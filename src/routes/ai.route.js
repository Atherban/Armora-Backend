// routes/ai.route.js
import express from "express";
import { getAISystemAnalysis } from "../controllers/ai.controller.js";
import { chatWithAI } from "../services/aiChat.service.js";

const router = express.Router();

// Analysis Route
router.get("/", getAISystemAnalysis);

// Chat route
router.post("/chat", async (req, res) => {
  const { analysisData, message } = req.body;
  if (!analysisData || !message) {
    return res.status(400).json({ error: "Missing analysisData or message" });
  }
  const result = await chatWithAI(analysisData, message);
  res.json(result);
});

export default router;
