// services/ai.service.js
import { GoogleGenerativeAI } from "@google/generative-ai";
import dotenv from "dotenv";

dotenv.config();

const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY);

const clamp = (v, lo = 0, hi = 100) =>
  Math.max(lo, Math.min(hi, Math.round(v)));

const deriveVulnerability = (score) => {
  // score is 0..100
  if (score > 80) return "Safe";
  if (score > 60) return "Moderate";
  if (score > 40) return "Vulnerable";
  return "Critical";
};

export const analyzeWithAI = async (systemData, baseScore) => {
  const prompt = `
You are an advanced cybersecurity analyst AI.
You are provided with raw system diagnostic data:

System Type: ${systemData.system}
Platform: ${systemData.platform}
Release: ${systemData.release}
CPU: ${systemData.cpu}
Memory Usage: ${systemData.memoryUsage}%
Uptime: ${systemData.uptimeHours} hours
Potential Threats: ${
    systemData.threatsDetected.length
      ? JSON.stringify(systemData.threatsDetected)
      : "None"
  }

The system currently has a baseline score of ${baseScore}/100 based on heuristics.

Analyze this information and return a refined JSON response with:
{
  "aiScore": (integer, 0–100),
  "vulnerabilityLevel": "Safe" | "Moderate" | "Vulnerable" | "Critical",
  "summary": "2–3 sentence description of the system’s security health.",
  "recommendations": [
    { "title": "Recommendation title", "details": "Short practical advice." }
  ],
  "securityNews": [
    { "headline": "Recent cybersecurity news headline", "source": "Source name" }
  ]
}

Ensure valid JSON output only, no markdown.
`;

  try {
    const model = genAI.getGenerativeModel({ model: "gemini-2.5-flash" });
    const result = await model.generateContent(prompt);
    const text = result.response.text();

    let parsed = {};
    try {
      parsed = JSON.parse(text);
    } catch (parseErr) {
      // If AI returned something not strict JSON, fallback to empty parsed object
      console.warn("⚠️ AI returned non-JSON. Falling back to heuristics.");
      parsed = {};
    }

    // Prefer AI aiScore if present, otherwise use baseScore
    let aiScore =
      typeof parsed.aiScore === "number" ? parsed.aiScore : baseScore;

    // Reconcile heuristics: penalize aiScore slightly if there are detected threats
    const threatCount = Array.isArray(systemData.threatsDetected)
      ? systemData.threatsDetected.length
      : 0;

    // Apply small adjustments: each detected threat reduces score by 5 (configurable)
    aiScore -= threatCount * 5;

    // If memory usage very high (> 90) further reduce score
    const memUsage = parseFloat(systemData.memoryUsage || "0");
    if (!Number.isNaN(memUsage) && memUsage > 90) aiScore -= 8;

    // Clamp final score 0..100
    aiScore = clamp(aiScore);

    // If AI returned an explicit vulnerabilityLevel, we will still compute ours from aiScore
    const vulnerabilityLevel = deriveVulnerability(aiScore);

    // Ensure recommendations exist
    const recommendations =
      Array.isArray(parsed.recommendations) && parsed.recommendations.length
        ? parsed.recommendations
        : [
            {
              title: "Restart device regularly",
              details: "Short reboots reduce stale processes and memory leaks.",
            },
            {
              title: "Monitor memory usage",
              details:
                "Investigate high memory consumers and limit background apps.",
            },
            {
              title: "Install updates",
              details: "Keep OS and apps updated for latest security patches.",
            },
          ];

    // Normalize securityNews to predictable array of { headline, source }
    let securityNews = [];
    if (Array.isArray(parsed.securityNews) && parsed.securityNews.length) {
      securityNews = parsed.securityNews.map((n) => ({
        headline: n.headline || n.title || "Unknown headline",
        source: n.source || n.sourceName || "Unknown",
      }));
    } else if (
      parsed.securityNews &&
      Array.isArray(parsed.securityNews.articles)
    ) {
      securityNews = parsed.securityNews.articles.map((n) => ({
        headline: n.headline || n.title || "Unknown headline",
        source: n.source || n.sourceName || "Unknown",
      }));
    } else {
      // small curated fallback news items
      securityNews = [
        {
          headline: "AI tools now detect ransomware faster than ever",
          source: "Cybersecurity Today",
        },
        {
          headline:
            "Global organizations increase cybersecurity budgets by 30%",
          source: "TechRadar",
        },
      ];
    }

    // Final structured object returned to client
    return {
      aiScore, // 0..100
      vulnerabilityLevel,
      summary:
        parsed.summary ||
        `System security analyzed. Final computed score is ${aiScore}/100.`,
      recommendations,
      securityNews,
      systemData, // keep original data so frontend can show detected threats etc.
    };
  } catch (error) {
    console.error("⚠️ Gemini AI Fallback Triggered:", error.message);

    // On error use robust fallback and same normalized structure
    const threatCount = Array.isArray(systemData.threatsDetected)
      ? systemData.threatsDetected.length
      : 0;

    let fallbackScore = baseScore - threatCount * 5;
    const memUsage = parseFloat(systemData.memoryUsage || "0");
    if (!Number.isNaN(memUsage) && memUsage > 90) fallbackScore -= 8;
    fallbackScore = clamp(fallbackScore);

    return {
      aiScore: fallbackScore,
      vulnerabilityLevel:
        fallbackScore > 80
          ? "Safe"
          : fallbackScore > 60
          ? "Moderate"
          : fallbackScore > 40
          ? "Vulnerable"
          : "Critical",
      summary:
        "The AI service failed to respond; returning heuristic analysis based on system metrics.",
      recommendations: [
        {
          title: "Restart device regularly",
          details: "Prevents long uptime risks and refreshes processes.",
        },
        {
          title: "Monitor memory usage",
          details: "Avoid high memory consumption for better performance.",
        },
        {
          title: "Use a VPN",
          details: "Adds privacy and reduces data exposure risks.",
        },
      ],
      securityNews: [
        {
          headline: "AI tools now detect ransomware faster than ever",
          source: "Cybersecurity Today",
        },
      ],
      systemData,
    };
  }
};
