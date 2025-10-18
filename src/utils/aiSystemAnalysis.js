// utils/systemAnalysis.js
import os from "os";

export const getSystemSecurityData = async () => {
  const networkInterfaces = os.networkInterfaces();
  const totalMemory = os.totalmem();
  const freeMemory = os.freemem();
  const memoryUsage = ((totalMemory - freeMemory) / totalMemory) * 100;

  const uptimeHours = (os.uptime() / 3600).toFixed(2);

  // Simulated detections
  const potentialThreats = [];
  if (memoryUsage > 85) {
    potentialThreats.push({
      name: "High Memory Usage",
      severity: "Medium",
      description: "System memory usage exceeds 85%, could affect performance.",
    });
  }

  if (uptimeHours > 120) {
    potentialThreats.push({
      name: "Long Uptime",
      severity: "Low",
      description:
        "Device hasn't been restarted for a while — regular reboots improve security.",
    });
  }

  return {
    system: os.type(),
    platform: os.platform(),
    release: os.release(),
    cpu: os.cpus()[0].model,
    memoryUsage: memoryUsage.toFixed(2),
    uptimeHours,
    threatsDetected: potentialThreats,
  };
};
