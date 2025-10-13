// backend/routes/wifiRoute.js
import express from "express";
import dns from "dns";
import axios from "axios";

const router = express.Router();

router.post("/", async (req, res) => {
  console.log(
    "🚀 Wi-Fi scan request received at",
    new Date().toLocaleTimeString()
  );
  console.log("📡 Incoming Wi-Fi data:", req.body);

  const { ssid, ipAddress, isConnected, type } = req.body;
  const result = {
    ssid,
    ipAddress,
    status: "Safe",
    threatLevel: "None",
    confidence: 99,
    recommendations: [],
  };

  try {
    // 1️⃣ Not connected or non-WiFi
    if (!isConnected || type !== "WIFI") {
      result.status = "Unsafe";
      result.threatLevel = "No Wi-Fi connection";
      result.confidence = 60;
      result.recommendations.push("Connect to a secure Wi-Fi network.");
    }

    // 2️⃣ Simple DNS check
    try {
      await dns.promises.lookup("google.com");
      result.checks = { dns: "Resolved OK" };
    } catch (err) {
      result.status = "Unsafe";
      result.threatLevel = "DNS resolution failed";
      result.confidence = 70;
      result.recommendations.push("Check your DNS configuration.");
    }

    // ✅ Respond immediately
    res.json(result);

    console.log(`✅ Scan processed for SSID: ${ssid}, IP: ${ipAddress}`);
  } catch (err) {
    console.error("❌ Wi-Fi scan failed:", err);
    res.status(500).json({ error: "Wi-Fi scan failed", details: err.message });
  }
});

export default router;
