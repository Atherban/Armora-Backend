import dns from "dns";
import fetch from "node-fetch";
import { URL } from "url";
import whois from "whois-json";

export const handleQR = async (req, res) => {
  const { url } = req.body;

  if (!url) {
    return res.status(400).json({ error: "URL is required" });
  }

  try {
    const parsedUrl = new URL(url);
    const domain = parsedUrl.hostname;
    const protocol = parsedUrl.protocol.replace(":", "");

    // === 1. Check for suspicious patterns ===
    const suspiciousPatterns = [
      "free",
      "login",
      "verify",
      "update",
      "bank",
      "gift",
      "claim",
      "secure",
    ];

    const isSuspicious = suspiciousPatterns.some((word) =>
      domain.toLowerCase().includes(word)
    );

    // === 2. DNS Lookup ===
    let ipAddress = "N/A";
    try {
      const lookup = await new Promise((resolve, reject) =>
        dns.lookup(domain, (err, address) => {
          if (err) reject(err);
          else resolve(address);
        })
      );
      ipAddress = lookup;
    } catch (err) {
      ipAddress = "Unresolved";
    }

    // === 3. WHOIS lookup (for age + registrar) ===
    let whoisData = {};
    try {
      whoisData = await whois(domain);
    } catch {
      whoisData = { error: "WHOIS data unavailable" };
    }

    // === 4. SSL Certificate Check ===
    const sslValid = protocol === "https";

    // === 5. Phishing Domain Check (mocked or real API) ===
    const phishingDomains = ["phishy.com", "malicious.net", "badsite.org"];
    const isPhishing = phishingDomains.includes(domain.toLowerCase());

    // === 6. Fetch response headers (optional) ===
    let statusCode = null;
    try {
      const response = await fetch(url, { method: "HEAD", timeout: 5000 });
      statusCode = response.status;
    } catch {
      statusCode = "Unreachable";
    }

    // === 7. Risk Level Estimation ===
    let riskLevel = "Low";
    if (isPhishing || isSuspicious || statusCode === "Unreachable") {
      riskLevel = "High";
    } else if (!sslValid) {
      riskLevel = "Medium";
    }

    // === 8. Construct AI-style response object ===
    const analysis = {
      scannedUrl: url,
      domain,
      protocol,
      ipAddress,
      sslValid,
      riskLevel,
      isSuspicious,
      isPhishing,
      whois: {
        registrar: whoisData.registrar || "Unknown",
        creationDate: whoisData.creationDate || "Unknown",
        country: whoisData.country || "Unknown",
      },
      httpStatus: statusCode,
      recommendations: generateRecommendations(riskLevel),
      timestamp: new Date().toISOString(),
    };

    res.json(analysis);
  } catch (error) {
    console.error("QR Scan Error:", error);
    res.status(500).json({ error: "Failed to analyze QR URL" });
  }
};

// === Helper: Recommendations Generator ===
function generateRecommendations(risk) {
  switch (risk) {
    case "High":
      return [
        "Do not open this link on your primary device.",
        "Avoid entering personal or banking credentials.",
        "Scan the QR with a trusted security app.",
        "Report this domain if suspicious activity occurs.",
      ];
    case "Medium":
      return [
        "Check if the site uses HTTPS.",
        "Avoid downloading unknown files.",
        "Verify the sender/source of this QR code.",
      ];
    default:
      return [
        "This URL seems safe.",
        "Always ensure the domain matches official sources.",
      ];
  }
}
