import express from "express";
import limit from "express-rate-limit";
import "dotenv/config";
import cors from "cors";

import job from "./cron.js";

import authRoutes from "./routes/auth.route.js";
import scanRoute from "./routes/scan.route.js";
import wifiRoute from "./routes/wifi.route.js";
import securityRoutes from "./routes/security.route.js";
import aiRoute from "./routes/ai.route.js";
import qrRoute from "./routes/qr.route.js";
import breachRoutes from "./routes/breach.route.js";

const app = express();

const limiter = limit({
  windowMs: 1 * 60 * 1000, // 1 minutes
  max: 10, // Limit each IP to 10 requests per windowMs
  message: {
    success: false,
    message: "Too many requests from this IP, please try again after a minute",
  },
});

job.start();
app.use(cors());
app.use(express.json());
app.use(limiter);

//Auth Routes
app.use("/api/auth", authRoutes);

//QR scan Routes
app.use("/api/qr", qrRoute);

//Scan Site Route
app.use("/api/scan", scanRoute);

//Wifi Scan Route
app.use("/api/wifi-scan", wifiRoute);

//System Security Analysis Route
app.use("/api/security", securityRoutes);

// AI Route
app.use("/api/ai", aiRoute);

// BreachRoutes
app.use("/api/breach", breachRoutes);

export default app;
