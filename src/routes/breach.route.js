import express from "express";
import { breachController } from "../controllers/breach.controller.js";

const router = express.Router();

// POST /api/breach
router.post("/check", breachController.checkBreaches);
router.get("/status", breachController.getServiceStatus);
router.post("/batch-check", breachController.batchCheckBreaches);

export default router;
