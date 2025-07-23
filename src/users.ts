import { Request, Response } from "express";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";

declare global {
  namespace Express {
    interface Request {
      user?: any;
    }
  }
}

const users:{username: string, password: string}[] = [];
const SECRET = "secret";

export const register = async (req: Request, res: Response) => {
    const { username, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    users.push({ username, password: hashedPassword });
    res.status(201).json({ message: "Usuário criado com sucesso" });
}

export const login = async (req: Request, res: Response) => {
    const { username, password } = req.body;
    const user = users.find((u) => u.username === username);
    if (!user) {
        return res.status(401).json({ message: "Usuário não encontrado" });
    }
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
        return res.status(401).json({ message: "Senha inválida" });
    }
    const token = jwt.sign({ username }, SECRET, { expiresIn: "1h" });
    res.json({ token });
}

export const profile = async (req: Request, res: Response) => {
    res.json({ message: "Perfil do usuário", user: req.user });
}