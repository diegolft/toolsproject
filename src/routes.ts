import { Router } from "express";
import { register, login, profile } from "./users";
import { authMiddleware } from "./auth";

export const router = Router();

router.post('/register', register);
router.post('/login', login);
router.get('/profile', authMiddleware, profile);
