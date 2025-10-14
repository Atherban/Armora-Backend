import os from "os";
import dns from "dns";
import axios from "axios";
const dnsPromises = dns.promises;

/**
 * Utility to measure DNS resolution time.
 */
const measureDnsLatency = async (hostname) => {
  const start = Date.now();
  try {
    await dnsPromises.lookup(hostname);
    const duration = Date.now() - start;
    return { ok: true, latencyMs: duration };
  } catch (err) {
    return { ok: false, latencyMs: null, error: err.message };
  }
};

/**
 * Determine if IP is private (local) or public.
 */
const isPrivateIp = (ip) => {
  if (!ip) return false;
  return (
    ip.startsWith("10.") ||
    ip.startsWith("192.168.") ||
    ip.startsWith("172.16.") ||
    ip.startsWith("172.17.") ||
    ip.startsWith("172.18.") ||
    ip.startsWith("172.19.") ||
    ip.startsWith("172.20.") ||
    ip.startsWith("172.21.") ||
    ip.startsWith("172.22.") ||
    ip.startsWith("172.23.") ||
    ip.startsWith("172.24.") ||
    ip.startsWith("172.25.") ||
    ip.startsWith("172.26.") ||
    ip.startsWith("172.27.") ||
    ip.startsWith("172.28.") ||
    ip.startsWith("172.29.") ||
    ip.startsWith("172.30.") ||
    ip.startsWith("172.31.")
  );
};

/**
 * 🧠 analyzeWifi – core controller
 */
export const analyzeWifi = async (req, res) => {
  const { ssid, ipAddress, isConnected, type, deviceInfo } = req.body;

  // initialize result structure
  const result = {
    ssid: ssid || "Unknown Network",
    ipAddress: ipAddress || "Unavailable",
    device: deviceInfo || os.hostname(),
    status: "Safe",
    threatLevel: "None",
    confidence: 99,
    severity: "None",
    metrics: {},
    recommendations: [],
    checks: {},
  };

  try {
    /** 1️⃣ Connection validation */
    if (!isConnected) {
      result.status = "Unsafe";
      result.threatLevel = "No active network connection";
      result.confidence = 60;
      result.recommendations.push("Connect to a secure Wi-Fi network.");
    } else if (type && type.toUpperCase() !== "WIFI") {
      result.status = "Unsafe";
      result.threatLevel = `Using ${type} network`;
      result.confidence = 70;
      result.recommendations.push("Switch to a trusted Wi-Fi connection.");
    }

    /** 2️⃣ DNS reachability test */
    const dnsCheck = await measureDnsLatency("google.com");
    if (dnsCheck.ok) {
      result.checks.dns = "Resolved successfully";
      result.metrics.dnsLatencyMs = dnsCheck.latencyMs;
    } else {
      result.checks.dns = `DNS resolution failed: ${dnsCheck.error}`;
      result.status = "Unsafe";
      result.threatLevel = "DNS resolution failed";
      result.confidence = 70;
      result.recommendations.push(
        "Check DNS settings or use a secure resolver (e.g., 1.1.1.1)."
      );
    }

    /** 3️⃣ IP validation */
    if (ipAddress && !isPrivateIp(ipAddress)) {
      result.status = "Unsafe";
      result.threatLevel = "Public IP Detected";
      result.confidence = Math.min(result.confidence, 75);
      result.recommendations.push(
        "You appear to be on a public network. Use a VPN for added security."
      );
    } else {
      result.checks.ipType = "Private (Local) IP";
    }

    /** 4️⃣ SSID heuristics */
    if (
      ssid?.toLowerCase().includes("public") ||
      ssid?.toLowerCase().includes("free") ||
      ssid?.toLowerCase().includes("open")
    ) {
      result.status = "Unsafe";
      result.threatLevel = "Public / Unsecured Wi-Fi";
      result.confidence = Math.min(result.confidence, 70);
      result.recommendations.push(
        "Avoid logging into sensitive accounts over public Wi-Fi."
      );
    }

    /** 5️⃣ Optional latency test */
    try {
      const start = Date.now();
      await axios.get("https://www.google.com/generate_204", { timeout: 5000 });
      const latency = Date.now() - start;
      result.metrics.internetLatencyMs = latency;
      if (latency > 300) {
        result.recommendations.push(
          "Network latency is high; consider switching Wi-Fi networks."
        );
      }
    } catch {
      result.status = "Unsafe";
      result.threatLevel = "No internet connectivity";
      result.confidence = 65;
      result.recommendations.push(
        "Check internet connection or router settings."
      );
    }

    /** 6️⃣ Severity calculation */
    if (result.status === "Unsafe") {
      if (result.confidence >= 90) result.severity = "High";
      else if (result.confidence >= 75) result.severity = "Medium";
      else result.severity = "Low";
    }
    return res.json(result);
  } catch (err) {
    console.error("❌ Wi-Fi analysis failed:", err);
    return res.status(500).json({
      error: "Wi-Fi analysis failed",
      details: err.message || "Unexpected error occurred",
    });
  }
};
