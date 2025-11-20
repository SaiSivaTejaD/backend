import express from "express";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import pool from "../db.js";

const router = express.Router();

// REGISTER
router.post("/register", async (req, res) => {
    try {
        const { email, password } = req.body;

        const [rows] = await pool.query("SELECT id FROM users WHERE email=?", [email]);
        if (rows.length > 0) return res.status(400).json({ message: "User already exists" });

        const hash = await bcrypt.hash(password, 10);

        await pool.query(
            "INSERT INTO users (email, password) VALUES (?, ?)",
            [email, hash]
        );

        res.json({ message: "Registered successfully" });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: "Server error" });
    }
});

// LOGIN
router.post("/login", async (req, res) => {
    try {
        const { userId, password } = req.body;

        const [rows] = await pool.query("SELECT * FROM users WHERE email=?", [userId]);
        if (rows.length === 0)
            return res.status(401).json({ message: "Invalid email or password" });

        const user = rows[0];
        console.log(user);
        const isMatch = password === user.password;
        if (!isMatch)
            return res.status(401).json({ message: "Invalid email or password" });

        const token = jwt.sign(
            { userId: user.id, email: user.email },
            process.env.JWT_SECRET,
            { expiresIn: "1h" }
        );

        res.json({ message: "Login successful", token });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: "Server error" });
    }
});

// Protected Route (GET /auth/me)
router.get("/members", async (req, res) => {
    try {
        const authHeader = req.headers.authorization;

        if (!authHeader?.startsWith("Bearer "))
            return res.status(401).json({ message: "Token missing" });

        const token = authHeader.split(" ")[1];
        const data = jwt.verify(token, process.env.JWT_SECRET);
        const [rows] = await pool.query("SELECT * FROM member");
        console.log(rows)

        res.json({ data: rows });
    } catch (err) {
        console.error(err);
        res.status(401).json({ message: "Invalid token" });
    }
});
router.post("/members", async (req, res) => {
    try {
        const authHeader = req.headers.authorization;

        if (!authHeader?.startsWith("Bearer "))
            return res.status(401).json({ message: "Token missing" });

        const token = authHeader.split(" ")[1];
        const data = jwt.verify(token, process.env.JWT_SECRET);
        let { name, email, phone, tier, join_date, password_hash } = req.body;
        await pool.query("INSERT INTO member (name,email,phone,tier,join_date,password_hash) VALUES (?,?,?,?,?,?)", [name, email, phone, tier, join_date, password_hash]);



        res.json({ data: "Member created successfully" });
    } catch (err) {
        console.error(err);
        res.status(401).json({ message: "Invalid token" });
    }
});

router.put("/members/:id", async (req, res) => {
    try {
        const authHeader = req.headers.authorization;

        if (!authHeader?.startsWith("Bearer "))
            return res.status(401).json({ message: "Token missing" });

        const token = authHeader.split(" ")[1];
        const data = jwt.verify(token, process.env.JWT_SECRET);
        const memberId = req.params.id;
        const { name, email, phone, tier } = req.body;
        await pool.query(
            "UPDATE member SET name=?, email=?, phone=?, tier=? WHERE member_id=?",
            [name, email, phone, tier, memberId]);

        res.json({ data: "Member updated successfully" });
    } catch (err) {
        console.error(err);
        res.status(401).json({ message: "Invalid token" });
    }
});

router.delete("/members/:id", async (req, res) => {
    try {
        const authHeader = req.headers.authorization;

        if (!authHeader?.startsWith("Bearer "))
            return res.status(401).json({ message: "Token missing" });

        const token = authHeader.split(" ")[1];
        const data = jwt.verify(token, process.env.JWT_SECRET);
        const memberId = +req.params.id;
        await pool.query(
            "DELETE FROM member WHERE member_id = ?",
            [memberId]);

        res.json({ data: "Member deleted successfully" });
    } catch (err) {
        console.error(err);
        res.status(401).json({ message: "Invalid token" });
    }
});

export default router;
