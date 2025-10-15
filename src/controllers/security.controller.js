import dns from "dns";
import net from "net";

export const analyzeDeviceSecurity = async (req, res) => {
  try {
    const {
      platform,
      osVersion,
      model,
      isEmulator,
      developerMode,
      userAgent,
      usbDebugging,
      vpnActive,
    } = req.body;

    let score = 10;
    let riskPoints = 0;

    const checks = {
      rooted: false,
      openPorts: [],
      osOutdated: false,
      threatLevel: "Low",
      details: [],
      recommendations: [],
      platform: platform || "Unknown",
      osVersion: osVersion || "Unknown",
      model: model || "Unknown",
      isEmulator: !!isEmulator,
      developerMode: !!developerMode,
      usbDebugging: !!usbDebugging,
      vpnActive: !!vpnActive,
    };

    // 1 Root/Jailbreak detection
    if (/root|jailbreak|magisk|su/i.test(userAgent || "")) {
      checks.rooted = true;
      checks.details.push(
        "Root or jailbreak detected. High vulnerability risk."
      );
      riskPoints += 4;
    } else {
      checks.details.push("No root/jailbreak indicators found.");
    }

    // 2 Emulator / Developer Mode
    if (isEmulator) {
      checks.details.push("Device is an emulator. Security bypass possible.");
      riskPoints += 2;
    }
    if (developerMode) {
      checks.details.push(
        "Developer mode enabled. Sensitive data exposure possible."
      );
      riskPoints += 1;
    }

    // 3 USB Debugging
    if (usbDebugging) {
      checks.details.push("USB debugging active. Physical attacks possible.");
      riskPoints += 1;
    }

    // 4 Open ports scan
    const commonPorts = [22, 80, 443, 8080, 3000, 5555];
    const openPortsList = [];

    const checkPort = (port) =>
      new Promise((resolve) => {
        const socket = new net.Socket();
        socket.setTimeout(400);
        socket.on("connect", () => {
          openPortsList.push(port);
          socket.destroy();
          resolve();
        });
        socket.on("timeout", () => {
          socket.destroy();
          resolve();
        });
        socket.on("error", () => resolve());
        socket.connect(port, "127.0.0.1");
      });

    await Promise.all(commonPorts.map(checkPort));
    checks.openPorts = openPortsList;

    if (openPortsList.length > 0) {
      checks.details.push(`Open ports detected: ${openPortsList.join(", ")}.`);
      riskPoints += Math.min(openPortsList.length, 3);
    } else {
      checks.details.push("No common open ports detected.");
    }

    // 5 DNS / Network
    try {
      await dns.promises.lookup("google.com");
      checks.details.push("DNS resolution successful. Network is healthy.");
    } catch (err) {
      checks.details.push("DNS resolution failed. Check network security.");
      riskPoints += 1;
    }

    // 6 OS version check
    if (
      (platform.toLowerCase() === "android" && parseInt(osVersion) < 12) ||
      (platform.toLowerCase() === "ios" && parseInt(osVersion) < 16)
    ) {
      checks.osOutdated = true;
      checks.details.push(`OS version (${osVersion}) is outdated.`);
      riskPoints += 2;
    } else {
      checks.details.push("OS version is up-to-date.");
    }

    // 7 VPN / Network security
    if (!vpnActive) {
      checks.details.push("No VPN active. Network traffic may be exposed.");
      riskPoints += 1;
    } else {
      checks.details.push("VPN active. Network traffic is encrypted.");
    }

    // 8 Final score and threat level
    score = Math.max(0, 10 - riskPoints);

    if (score >= 8) checks.threatLevel = "Low";
    else if (score >= 5) checks.threatLevel = "Medium";
    else checks.threatLevel = "High";

    // 9 recommendations (max 6)
    const recommendations = [];
    if (checks.rooted || checks.osOutdated) {
      recommendations.push(
        "Use a secure, up-to-date OS and avoid rooted/jailbroken devices."
      );
    }
    if (isEmulator || developerMode || usbDebugging) {
      recommendations.push(
        "Disable developer features and USB debugging when not needed."
      );
    }
    if (openPortsList.length > 0) {
      recommendations.push("Close unnecessary open ports and use firewalls.");
    }
    if (!vpnActive) {
      recommendations.push("Use a VPN on public or untrusted networks.");
    }
    recommendations.push("Keep apps and OS updated regularly.");
    recommendations.push("Review installed apps and remove suspicious ones.");

    checks.recommendations = recommendations;

    // Combine details
    checks.details = checks.details.join(" ");

    res.json({ score, checks });
  } catch (err) {
    res.status(500).json({
      error: "Security analysis failed",
      details: err.message,
    });
  }
};
