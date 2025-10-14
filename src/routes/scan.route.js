import express from "express";
import { scanUrl } from "../controllers/scan.controller.js";

const router = express.Router();

// POST /api/scan
router.post("/", scanUrl);

export default router;
