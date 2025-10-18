// routes/ai.route.js
import express from "express";
import { getAISystemAnalysis } from "../controllers/ai.controller.js";

const router = express.Router();

router.get("/", getAISystemAnalysis);

export default router;
