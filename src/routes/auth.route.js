import express from "express";
import authController from "../controllers/auth.controller.js";

const router = express.Router();

//Auth Routes
router.post("/login", authController.loginController);
router.post("/register", authController.registerController);

export default router;
