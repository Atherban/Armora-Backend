import axios from "axios";
import {
  cache,
  now,
  CACHE_TTL_MS,
  extractDomainParts,
  updateStatus,
  SUSPICIOUS_TLDS,
  resolveDNS,
  detectUrlType,
  getTypeSpecificChecks,
  extractUrlDetails,
} from "../utils/scan.util.js";

const GOOGLE_SAFE_BROWSING_API_KEY = process.env.GSB_API_KEY || "";

export const scanUrl = async (req, res) => {
  const { url } = req.body;
  if (!url || typeof url !== "string") {
    return res.status(400).json({ error: "Missing or invalid url" });
  }

  let normalized = url.trim();
  if (!/^https?:\/\//i.test(normalized)) normalized = "http://" + normalized;

  const cacheEntry = cache.get(normalized);
  if (cacheEntry && cacheEntry.expiresAt > now()) {
    return res.json(cacheEntry.result);
  } else if (cacheEntry) {
    cache.delete(normalized);
  }

  // === Type detection ===
  const urlType = detectUrlType(normalized);
  const urlDetails = extractUrlDetails(normalized, urlType);

  const result = {
    url: normalized,
    status: "Safe",
    threatLevel: "None",
    confidence: 99,
    checks: {},
    urlType,
    urlDetails,
    riskFactors: [],
    recommendations: [],
    description: "URL analysis in progress.",
  };

  try {
    /* 1. DNS Check */
    const { hostname } = new URL(normalized);
    const dnsRes = await resolveDNS(hostname);
    if (!dnsRes.ok) {
      updateStatus(result, "Unsafe", "Unreachable Host", 60, "DNS");
      result.checks.dns = `DNS failed: ${dnsRes.error}`;
      result.riskFactors.push({
        factor: "DNS resolution failed",
        detail: `The domain could not be resolved. This may indicate a non-existent or malicious host.`,
      });
    } else {
      result.checks.dns = "Resolved OK";
    }

    /* 2. HTTPS / SSL Check */
    try {
      const httpsVersion = normalized.startsWith("https://")
        ? normalized
        : normalized.replace(/^http:\/\//i, "https://");

      const resp = await axios.get(httpsVersion, {
        timeout: 5000,
        maxRedirects: 3,
        validateStatus: () => true,
      });

      if (resp.status >= 400) {
        updateStatus(
          result,
          "Unsafe",
          `HTTP error ${resp.status}`,
          75,
          "HTTPS"
        );
        result.riskFactors.push({
          factor: `HTTP error ${resp.status}`,
          detail: `The server responded with an error code, which may indicate a compromised or inactive site.`,
        });
      } else {
        updateStatus(result, "Safe", "HTTPS OK", 99, "HTTPS");
      }
      result.checks.ssl = `HTTPS status ${resp.status}`;
    } catch (err) {
      updateStatus(result, "Unsafe", "HTTPS unreachable", 70, "HTTPS");
      result.checks.ssl = `HTTPS unreachable: ${err.message}`;
      result.riskFactors.push({
        factor: "HTTPS unreachable",
        detail: `Could not reach the site over HTTPS. This may indicate poor security or server issues.`,
      });
    }

    /* 3. TLD Heuristic */
    const { tld } = extractDomainParts(normalized);
    if (tld) {
      if (SUSPICIOUS_TLDS.includes(tld.toLowerCase())) {
        updateStatus(result, "Unsafe", `Suspicious TLD (.${tld})`, 75, "TLD");
        result.checks.tld = "Flagged TLD";
        result.riskFactors.push({
          factor: `Suspicious TLD: .${tld}`,
          detail: `The top-level domain is commonly associated with risky or fraudulent sites.`,
        });
      } else {
        result.checks.tld = `TLD .${tld} OK`;
      }
    }

    /* 4. Header & Content-Type */
    try {
      const headResp = await axios.get(normalized, {
        timeout: 5000,
        maxRedirects: 5,
        validateStatus: () => true,
      });
      const headers = headResp.headers || {};
      result.checks.headers = {
        status: headResp.status,
        contentType: headers["content-type"] || "unknown",
      };
      if (headResp.status >= 400) {
        updateStatus(
          result,
          "Unsafe",
          `HTTP error ${headResp.status}`,
          75,
          "Headers"
        );
        result.riskFactors.push({
          factor: `HTTP error ${headResp.status}`,
          detail: `The server responded with an error code, which may indicate a compromised or inactive site.`,
        });
      }
      if (headers["content-type"]?.includes("application/octet-stream")) {
        updateStatus(
          result,
          "Unsafe",
          "Binary download detected",
          80,
          "Headers"
        );
        result.riskFactors.push({
          factor: "Binary download detected",
          detail:
            "The URL serves a binary file, which may be unsafe or malicious.",
        });
      }
    } catch (hdrErr) {
      result.checks.headers = `Header check failed: ${hdrErr.message}`;
      result.riskFactors.push({
        factor: "Header check failed",
        detail: `Could not retrieve headers. This may indicate server misconfiguration or malicious intent.`,
      });
    }

    /* 5. Google Safe Browsing */
    if (GOOGLE_SAFE_BROWSING_API_KEY) {
      try {
        const gsbRes = await axios.post(
          `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${GOOGLE_SAFE_BROWSING_API_KEY}`,
          {
            client: { clientId: "armora-x", clientVersion: "1.0" },
            threatInfo: {
              threatTypes: [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION",
              ],
              platformTypes: ["ANY_PLATFORM"],
              threatEntryTypes: ["URL"],
              threatEntries: [{ url: normalized }],
            },
          }
        );
        if (gsbRes.data?.matches?.length) {
          updateStatus(
            result,
            "Unsafe",
            gsbRes.data.matches[0].threatType,
            90,
            "GoogleSB"
          );
          result.riskFactors.push({
            factor: gsbRes.data.matches[0].threatType,
            detail: "Google Safe Browsing flagged this URL as unsafe.",
          });
        }
        result.checks.google = "Checked via Google Safe Browsing";
      } catch (gsbErr) {
        result.checks.google = `GSB error: ${gsbErr.message}`;
        result.riskFactors.push({
          factor: "Google Safe Browsing error",
          detail: `Could not check with Google Safe Browsing: ${gsbErr.message}`,
        });
      }
    }

    // === Type-specific checks ===
    const typeChecks = await getTypeSpecificChecks(normalized, urlType);
    Object.assign(result.checks, typeChecks.checks);
    result.riskFactors.push(...typeChecks.riskFactors);
    result.recommendations.push(...typeChecks.recommendations);

    // Add a descriptive summary
    result.description = `URL type detected: ${urlType}. ${
      result.riskFactors.length
        ? "Potential risks found."
        : "No major risks detected."
    }`;

    // Severity level
    result.severity =
      result.status === "Unsafe"
        ? result.confidence >= 90
          ? "High"
          : result.confidence >= 75
          ? "Medium"
          : "Low"
        : "None";

    cache.set(normalized, { result, expiresAt: now() + CACHE_TTL_MS });

    return res.json(result);
  } catch (err) {
    console.error("Scan failed:", err);
    return res.status(500).json({ error: "Scan failed", details: err.message });
  }
};
