// backend/routes/security.js
import express from "express";
import { analyzeDeviceSecurity } from "../controllers/security.controller.js";

const router = express.Router();

// POST endpoint that accepts device info from frontend
router.post("/analyze", analyzeDeviceSecurity);

export default router;
