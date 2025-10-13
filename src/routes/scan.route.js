// backend/routes/scanRoute.js
import express from "express";
import axios from "axios";
import dns from "dns";
const dnsPromises = dns.promises;

const router = express.Router();
const GOOGLE_SAFE_BROWSING_API_KEY = process.env.GSB_API_KEY || "";

/* --- configuration / heuristics ----------------------------------------- */

const SUSPICIOUS_TLDS = [
  "xyz",
  "ru",
  "top",
  "click",
  "tk",
  "zip",
  "monster",
  "gq",
  "cf",
  "ml",
  "work",
  "loan",
  "download",
  "surf",
  "fit",
];

// simple in-memory cache: url -> { result, expiresAt }
const cache = new Map();
const CACHE_TTL_MS = 5 * 60 * 1000; // 5 minutes

/* --- helpers ------------------------------------------------------------ */

const extractDomainParts = (url) => {
  try {
    const u = new URL(url);
    const parts = u.hostname.split(".");
    return {
      domain: parts.slice(-2).join("."),
      tld: parts.pop(),
      hostname: u.hostname,
    };
  } catch {
    return { domain: "", tld: "", hostname: "" };
  }
};

const now = () => Date.now();

/**
 * updateStatus - update `result` with a new finding in a prioritized way
 * Rules:
 *  - If current status is Safe and newStatus is Unsafe => accept new (Unsafe wins)
 *  - If current status is Unsafe and newStatus is Safe => ignore (Unsafe wins)
 *  - If both Safe => keep the higher confidence (max)
 *  - If both Unsafe => keep the lower confidence (min) as it's more severe
 * Saves source that triggered the last update into result.checks.lastTriggered
 */
const updateStatus = (result, newStatus, newThreat, newConfidence, source) => {
  // default fields if missing
  if (!result.status) result.status = "Safe";
  if (typeof result.confidence !== "number") result.confidence = 99;

  if (result.status === newStatus) {
    if (newStatus === "Safe") {
      // keep the more confident Safe score
      if (newConfidence > result.confidence) {
        result.confidence = newConfidence;
        result.threatLevel = newThreat || result.threatLevel;
        result.checks.lastTriggered = source;
      }
    } else {
      // both Unsafe -> keep the lower (more severe) confidence
      if (newConfidence < result.confidence) {
        result.confidence = newConfidence;
        result.threatLevel = newThreat || result.threatLevel;
        result.checks.lastTriggered = source;
      }
    }
  } else {
    // statuses differ
    if (newStatus === "Unsafe" && result.status === "Safe") {
      // override Safe with Unsafe
      result.status = newStatus;
      result.threatLevel = newThreat;
      result.confidence = newConfidence;
      result.checks.lastTriggered = source;
    } else if (newStatus === "Safe" && result.status === "Unsafe") {
      // keep Unsafe (don't override)
      // optionally, if newConfidence is extremely high (>99) you might want to override
      // but keep current behaviour: Unsafe is stronger
    } else {
      // fallback: just set
      result.status = newStatus;
      result.threatLevel = newThreat;
      result.confidence = newConfidence;
      result.checks.lastTriggered = source;
    }
  }
};

/* --- main route --------------------------------------------------------- */

router.post("/", async (req, res) => {
  const { url } = req.body;
  if (!url || typeof url !== "string") {
    return res.status(400).json({ error: "Missing or invalid url" });
  }

  // Normalize input - keep behaviour of adding http:// if missing
  let normalized = url.trim();
  if (!/^https?:\/\//i.test(normalized)) normalized = "http://" + normalized;

  // Simple cache lookup
  const cacheEntry = cache.get(normalized);
  if (cacheEntry && cacheEntry.expiresAt > now()) {
    return res.json(cacheEntry.result);
  } else if (cacheEntry) {
    cache.delete(normalized);
  }

  // Initial optimistic result
  const result = {
    url: normalized,
    status: "Safe",
    threatLevel: "None",
    confidence: 99,
    checks: {},
  };

  try {
    /* 1️⃣ DNS check */
    try {
      const { hostname } = new URL(normalized);
      await dnsPromises.lookup(hostname);
      result.checks.dns = "Resolved OK";
    } catch (dnsErr) {
      updateStatus(result, "Unsafe", "Unreachable Host", 60, "DNS");
      result.checks.dns = `DNS lookup failed: ${dnsErr?.message || "error"}`;
      // continue — still run other checks for richer info
    }

    /* 2️⃣ HTTPS reachability / SSL behavior (use GET for best compatibility) */
    try {
      if (normalized.startsWith("https://")) {
        const resp = await axios.get(normalized, {
          timeout: 5000,
          maxRedirects: 3,
          validateStatus: () => true,
        });

        // Consider server error or >=400 as a problem
        if (resp.status >= 400) {
          updateStatus(
            result,
            "Unsafe",
            `HTTP error ${resp.status}`,
            75,
            "HTTPS"
          );
          result.checks.ssl = `HTTPS responded with ${resp.status}`;
        } else {
          // Positive signal: HTTPS responding
          updateStatus(result, "Safe", "HTTPS OK", 99, "HTTPS");
          result.checks.ssl = "Valid HTTPS response";
        }
      } else {
        // input was http:// — test https:// version
        const httpsVersion = normalized.replace(/^http:\/\//i, "https://");
        try {
          const resp = await axios.get(httpsVersion, {
            timeout: 5000,
            maxRedirects: 3,
            validateStatus: () => true,
          });

          if (resp.status >= 400) {
            updateStatus(
              result,
              "Unsafe",
              `HTTPS responded ${resp.status}`,
              75,
              "HTTPS"
            );
            result.checks.ssl = `HTTPS responded ${resp.status}`;
          } else {
            // HTTPS is available -> good signal
            updateStatus(
              result,
              "Safe",
              "Redirects to HTTPS / HTTPS available",
              95,
              "HTTPS"
            );
            result.checks.ssl = "Redirects to HTTPS (HTTPS available)";
          }
        } catch (httpsErr) {
          updateStatus(
            result,
            "Unsafe",
            "No SSL (HTTP only) or HTTPS unreachable",
            70,
            "HTTPS"
          );
          result.checks.ssl = `HTTPS unreachable: ${
            httpsErr?.message || "error"
          }`;
        }
      }
    } catch (sslErr) {
      updateStatus(
        result,
        "Unsafe",
        "Invalid or Missing SSL (request failed)",
        70,
        "HTTPS"
      );
      result.checks.ssl = `SSL check failed: ${sslErr?.message || "error"}`;
    }

    /* 3️⃣ TLD heuristic */
    const { tld } = extractDomainParts(normalized);
    if (tld) {
      if (SUSPICIOUS_TLDS.includes(tld.toLowerCase())) {
        updateStatus(result, "Unsafe", `Suspicious TLD (.${tld})`, 75, "TLD");
        result.checks.tld = "Flagged TLD";
      } else {
        result.checks.tld = `TLD .${tld} OK`;
      }
    } else {
      result.checks.tld = "TLD unknown";
    }

    /* 4️⃣ Header / redirect / content-type inspection (GET already performed above for SSL) */
    // We attempt a lightweight GET of the original normalized URL (if not already done)
    try {
      const headResp = await axios.get(normalized, {
        timeout: 5000,
        maxRedirects: 5,
        validateStatus: () => true,
      });

      const headers = headResp.headers || {};
      const statusCode = headResp.status;

      result.checks.headers = {
        status: statusCode,
        contentType: headers["content-type"] || "unknown",
        redirect: headers.location || null,
      };

      // HTTP error classification
      if (statusCode >= 400) {
        updateStatus(
          result,
          "Unsafe",
          `HTTP error ${statusCode}`,
          75,
          "Headers"
        );
      }

      // suspicious content types (binary downloads)
      if (headers["content-type"]?.includes("application/octet-stream")) {
        updateStatus(
          result,
          "Unsafe",
          "Potential download / binary content",
          80,
          "Headers"
        );
      }
    } catch (hdrErr) {
      // Non-fatal: just record the failure
      result.checks.headers = `Header check failed: ${
        hdrErr?.message || "error"
      }`;
    }

    /* 5️⃣ Google Safe Browsing API */
    if (GOOGLE_SAFE_BROWSING_API_KEY) {
      try {
        const gsbRes = await axios.post(
          `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${GOOGLE_SAFE_BROWSING_API_KEY}`,
          {
            client: { clientId: "armor-x", clientVersion: "1.0" },
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
          },
          { timeout: 10000 }
        );

        if (gsbRes.data?.matches && gsbRes.data.matches.length > 0) {
          // Google flags it — high confidence Unsafe
          updateStatus(
            result,
            "Unsafe",
            gsbRes.data.matches[0].threatType,
            90,
            "GoogleSB"
          );
        }
        result.checks.google = "GSB checked";
      } catch (gsbErr) {
        result.checks.google = `GSB check failed: ${
          gsbErr?.message || "error"
        }`;
      }
    } else {
      result.checks.google = "No GSB_API_KEY";
    }

    // Derive a simple severity label (optional)
    if (result.status === "Unsafe") {
      if (result.confidence >= 90) result.severity = "High";
      else if (result.confidence >= 75) result.severity = "Medium";
      else result.severity = "Low";
    } else {
      result.severity = "None";
    }

    // Persist to cache
    cache.set(normalized, { result, expiresAt: now() + CACHE_TTL_MS });

    // Log for debugging
    console.log(
      `[scan] ${normalized} => ${result.status} (${result.threatLevel}) [conf=${result.confidence}]`
    );

    return res.json(result);
  } catch (outerErr) {
    console.error("Scan failed:", outerErr);
    return res
      .status(500)
      .json({ error: "Scan failed", details: outerErr?.message || "error" });
  }
});

export default router;
