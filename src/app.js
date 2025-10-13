import express from "express";
import "dotenv/config";
import cors from "cors";

import authRoutes from "./routes/auth.route.js";
import scanRoute from "./routes/scan.route.js";
import wifiRoute from "./routes/wifi.route.js";

const app = express();

app.use(cors());
app.use(express.json());

//Auth Routes
app.use("/api/auth", authRoutes);

//Scan Route
app.use("/api/scan", scanRoute);

//Wifi Scan Route
app.use("/api/wifi-scan", wifiRoute);

export default app;
