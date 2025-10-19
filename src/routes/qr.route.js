import express from "express";
import { handleQR } from "../controllers/qr.controller.js";

const router = express.Router();

router.post("/", handleQR);

export default router;
