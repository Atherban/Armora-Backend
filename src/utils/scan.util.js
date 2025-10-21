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

// --- Type detection utility ---
export const detectUrlType = (url) => {
  // Add more patterns as needed
  const patterns = [
    {
      type: "payment",
      regex: /(paypal|stripe|paytm|razorpay|payment|checkout)/i,
    },
    {
      type: "banking",
      regex: /(bank|account|secure|login|verify|transaction)/i,
    },
    { type: "fraud", regex: /(phish|scam|malware|fraud|badsite|suspicious)/i },
    { type: "social", regex: /(facebook|twitter|instagram|linkedin|social)/i },
    { type: "file", regex: /(download|file|attachment|doc|pdf|exe|zip)/i },
    { type: "generic", regex: /.*/ },
  ];
  try {
    const u = new URL(url);
    for (const p of patterns) {
      if (p.regex.test(u.hostname + url)) return p.type;
    }
    return "generic";
  } catch {
    return "generic";
  }
};

// --- Modular type-specific checks ---
export const getTypeSpecificChecks = async (url, urlType) => {
  const checks = {};
  const riskFactors = [];
  const recommendations = [];
  try {
    switch (urlType) {
      case "payment":
        if (!/^https:/.test(url)) {
          riskFactors.push({
            factor: "Payment URL is not using HTTPS",
            detail:
              "Sensitive payment information may be exposed on non-secure connections.",
          });
          recommendations.push(
            "Never enter payment details on non-HTTPS sites."
          );
        }
        checks.payment = "Checked for HTTPS";
        break;
      case "banking":
        if (/login|verify|update/.test(url)) {
          riskFactors.push({
            factor: "Banking URL contains login/verify/update keywords",
            detail:
              "These keywords are often used in phishing attempts targeting banking users.",
          });
          recommendations.push(
            "Be cautious of banking URLs with login/verify/update."
          );
        }
        checks.banking = "Checked for suspicious keywords";
        break;
      case "fraud":
        riskFactors.push({
          factor: "Fraudulent pattern detected",
          detail: "URL matches known fraud or phishing patterns.",
        });
        recommendations.push(
          "Avoid interacting with suspicious or flagged domains."
        );
        checks.fraud = "Pattern matched for fraud";
        break;
      case "social":
        checks.social = "Social media URL detected";
        recommendations.push("Be cautious of phishing on social media links.");
        break;
      case "file":
        if (/\.exe|\.zip|\.pdf|\.doc/.test(url)) {
          riskFactors.push({
            factor: "File download detected",
            detail: "Downloaded files may contain malware or viruses.",
          });
          recommendations.push("Scan downloaded files for malware.");
        }
        checks.file = "File download pattern checked";
        break;
      default:
        checks.generic = "Generic URL type";
    }
  } catch (err) {
    riskFactors.push({
      factor: "Type-specific check error",
      detail: "Error occurred during type-specific analysis.",
    });
  }
  return { checks, riskFactors, recommendations };
};

// --- Extract essential details for each URL type ---
export const extractUrlDetails = (url, urlType) => {
  try {
    const u = new URL(url);
    switch (urlType) {
      case "payment":
      case "banking": {
        // Try to extract account holder or payee name from query params
        const params = u.searchParams;
        const accountHolder =
          params.get("name") ||
          params.get("account") ||
          params.get("payee") ||
          null;
        const accountNumber =
          params.get("acc") || params.get("accountNumber") || null;
        return {
          accountHolder: accountHolder || "Unknown",
          accountNumber: accountNumber || "Unknown",
          details: accountHolder
            ? `Account holder: ${accountHolder}`
            : "No account holder info found.",
        };
      }
      case "social": {
        // Try to extract profile name or user id
        const profile = u.pathname.split("/").filter(Boolean)[0] || null;
        return {
          profileName: profile || "Unknown",
          details: profile
            ? `Profile name: ${profile}`
            : "No profile info found.",
        };
      }
      case "file": {
        // Try to extract filename
        const filename = u.pathname.split("/").pop() || null;
        return {
          filename: filename || "Unknown",
          details: filename
            ? `Filename: ${filename}`
            : "No filename info found.",
        };
      }
      case "fraud": {
        // Extract suspicious keywords
        const suspicious = [
          "phish",
          "scam",
          "malware",
          "fraud",
          "badsite",
          "suspicious",
        ].filter((k) => url.includes(k));
        return {
          suspiciousKeywords: suspicious,
          details: suspicious.length
            ? `Suspicious keywords: ${suspicious.join(", ")}`
            : "No suspicious keywords found.",
        };
      }
      default:
        return { details: "No extra details for this URL type." };
    }
  } catch {
    return { details: "Failed to extract details." };
  }
};
