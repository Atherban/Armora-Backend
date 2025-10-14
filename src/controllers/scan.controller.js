import axios from "axios";
import {
  cache,
  now,
  CACHE_TTL_MS,
  extractDomainParts,
  updateStatus,
  SUSPICIOUS_TLDS,
  resolveDNS,
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

  const result = {
    url: normalized,
    status: "Safe",
    threatLevel: "None",
    confidence: 99,
    checks: {},
  };

  try {
    /* ✅ 1. DNS Check */
    const { hostname } = new URL(normalized);
    const dnsRes = await resolveDNS(hostname);
    if (!dnsRes.ok) {
      updateStatus(result, "Unsafe", "Unreachable Host", 60, "DNS");
      result.checks.dns = `DNS failed: ${dnsRes.error}`;
    } else {
      result.checks.dns = "Resolved OK";
    }

    /* ✅ 2. HTTPS / SSL Check */
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
      } else {
        updateStatus(result, "Safe", "HTTPS OK", 99, "HTTPS");
      }
      result.checks.ssl = `HTTPS status ${resp.status}`;
    } catch (err) {
      updateStatus(result, "Unsafe", "HTTPS unreachable", 70, "HTTPS");
      result.checks.ssl = `HTTPS unreachable: ${err.message}`;
    }

    /* ✅ 3. TLD Heuristic */
    const { tld } = extractDomainParts(normalized);
    if (tld) {
      if (SUSPICIOUS_TLDS.includes(tld.toLowerCase())) {
        updateStatus(result, "Unsafe", `Suspicious TLD (.${tld})`, 75, "TLD");
        result.checks.tld = "Flagged TLD";
      } else {
        result.checks.tld = `TLD .${tld} OK`;
      }
    }

    /* ✅ 4. Header & Content-Type */
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
      }
      if (headers["content-type"]?.includes("application/octet-stream")) {
        updateStatus(
          result,
          "Unsafe",
          "Binary download detected",
          80,
          "Headers"
        );
      }
    } catch (hdrErr) {
      result.checks.headers = `Header check failed: ${hdrErr.message}`;
    }

    /* ✅ 5. Google Safe Browsing */
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
        }
        result.checks.google = "Checked via Google Safe Browsing";
      } catch (gsbErr) {
        result.checks.google = `GSB error: ${gsbErr.message}`;
      }
    }

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

    ;
    return res.json(result);
  } catch (err) {
    console.error("Scan failed:", err);
    return res.status(500).json({ error: "Scan failed", details: err.message });
  }
};
