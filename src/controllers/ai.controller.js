// controllers/ai.controller.js
import { getSystemSecurityData } from "../utils/aiSystemAnalysis.js";
import { calculateBaseScore } from "../utils/aiScore.js";
import { analyzeWithAI } from "../services/ai.service.js";

export const getAISystemAnalysis = async (req, res) => {
  try {
    const systemData = await getSystemSecurityData();
    const baseScore = calculateBaseScore(systemData);

    const aiResponse = await analyzeWithAI(systemData, baseScore);

    res.status(200).json({
      baseScore,
      systemData,
      ...aiResponse,
      timestamp: new Date().toISOString(),
    });
  } catch (err) {
    console.error("❌ AI Security Analysis Error:", err.message);
    res.status(500).json({
      error: "Failed to analyze system security. Please try again.",
    });
  }
};
