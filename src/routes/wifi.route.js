import express from "express";
import { analyzeWifi } from "../controllers/wifi.controller.js";

const router = express.Router();

// POST /api/wifi-scan
router.post("/", analyzeWifi);

export default router;
