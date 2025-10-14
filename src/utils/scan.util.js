import dns from "dns";
const dnsPromises = dns.promises;

/* --- configuration / heuristics --- */
export const SUSPICIOUS_TLDS = [
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

export const CACHE_TTL_MS = 5 * 60 * 1000; // 5 minutes
export const cache = new Map();

export const now = () => Date.now();

export const extractDomainParts = (url) => {
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

export const updateStatus = (
  result,
  newStatus,
  newThreat,
  newConfidence,
  source
) => {
  if (!result.status) result.status = "Safe";
  if (typeof result.confidence !== "number") result.confidence = 99;

  if (result.status === newStatus) {
    if (newStatus === "Safe") {
      if (newConfidence > result.confidence) {
        result.confidence = newConfidence;
        result.threatLevel = newThreat || result.threatLevel;
        result.checks.lastTriggered = source;
      }
    } else {
      if (newConfidence < result.confidence) {
        result.confidence = newConfidence;
        result.threatLevel = newThreat || result.threatLevel;
        result.checks.lastTriggered = source;
      }
    }
  } else {
    if (newStatus === "Unsafe" && result.status === "Safe") {
      result.status = newStatus;
      result.threatLevel = newThreat;
      result.confidence = newConfidence;
      result.checks.lastTriggered = source;
    }
  }
};

export const resolveDNS = async (hostname) => {
  try {
    await dnsPromises.lookup(hostname);
    return { ok: true };
  } catch (err) {
    return { ok: false, error: err.message };
  }
};
