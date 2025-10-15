import express from "express";
import "dotenv/config";
import cors from "cors";

import job from "./cron.js";

import authRoutes from "./routes/auth.route.js";
import scanRoute from "./routes/scan.route.js";
import wifiRoute from "./routes/wifi.route.js";
import securityRoutes from "./routes/security.route.js";

const app = express();

job.start();
app.use(cors());
app.use(express.json());

//Auth Routes
app.use("/api/auth", authRoutes);

//Scan Route
app.use("/api/scan", scanRoute);

//Wifi Scan Route
app.use("/api/wifi-scan", wifiRoute);

//System Security Analysis Route
app.use("/api/security", securityRoutes);

export default app;
