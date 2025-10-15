import dns from "dns";
import net from "net";

export const analyzeDeviceSecurity = async (req, res) => {
  try {
    const { platform, osVersion, model, isEmulator, developerMode, userAgent } =
      req.body;

    let score = 10;

    const checks = {
      rooted: false,
      openPorts: [],
      threatLevel: "Low",
      details: "Device appears secure.",
      recommendations: [],
      platform: platform || "Unknown",
      osVersion: osVersion || "Unknown",
      model: model || "Unknown",
      isEmulator: !!isEmulator,
      developerMode: !!developerMode,
    };

    // 1️⃣ Root/Jailbreak detection
    if (/root|jailbreak|magisk|su/i.test(userAgent || "")) {
      checks.rooted = true;
      checks.threatLevel = "High";
      checks.details = "Root or jailbreak indicators detected.";
      checks.recommendations.push(
        "Avoid using rooted or jailbroken devices for sensitive operations."
      );
      score -= 3;
    }

    // 2️⃣ Open ports scan (localhost common ports)
    const commonPorts = [22, 80, 443, 8080, 3000, 5555];
    const openPortsList = [];

    const checkPort = (port) =>
      new Promise((resolve) => {
        const socket = new net.Socket();
        socket.setTimeout(400);
        socket.on("connect", () => {
          openPortsList.push(port);
          socket.destroy();
          resolve(true);
        });
        socket.on("timeout", () => {
          socket.destroy();
          resolve(false);
        });
        socket.on("error", () => resolve(false));
        socket.connect(port, "127.0.0.1");
      });

    await Promise.all(commonPorts.map(checkPort));
    checks.openPorts = openPortsList;

    if (openPortsList.length > 2) {
      checks.threatLevel = "Medium";
      checks.details = `${
        openPortsList.length
      } open ports detected: ${openPortsList.join(
        ", "
      )}. Review your active services.`;
      checks.recommendations.push(
        "Close unnecessary open ports to reduce attack surface."
      );
      score -= 2;
    }

    // 3️⃣ DNS Check
    try {
      await dns.promises.lookup("google.com");
    } catch (err) {
      score -= 1;
      checks.threatLevel = "Medium";
      checks.details += " DNS resolution issue detected.";
      checks.recommendations.push(
        "Check network connectivity and DNS settings."
      );
    }

    // 4️⃣ Threat Level adjustment based on score
    if (score >= 8) checks.threatLevel = "Low";
    else if (score >= 6) checks.threatLevel = "Medium";
    else checks.threatLevel = "High";

    // 🧮 Ensure score stays within 0–10
    score = Math.max(0, Math.min(score, 10));

    res.json({ score, checks });
  } catch (err) {
    res
      .status(500)
      .json({ error: "Security analysis failed", details: err.message });
  }
};
