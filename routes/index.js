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
        const isMatch = password === user.password;
        if (!isMatch)
            return res.status(401).json({ message: "Invalid email or password" });

        const token = jwt.sign(
            { userId: user.id, email: user.email },
            process.env.JWT_SECRET,
            { expiresIn: "9h" }
        );

        res.json({ message: "Login successful", token });
    } catch (err) {
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

        res.json({ data: rows });
    } catch (err) {
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
        res.status(401).json({ message: "Invalid token" });
    }
});


router.get("/passes", async (req, res) => {
    try {
        const authHeader = req.headers.authorization;

        if (!authHeader?.startsWith("Bearer "))
            return res.status(401).json({ message: "Token missing" });

        const token = authHeader.split(" ")[1];
        const data = jwt.verify(token, process.env.JWT_SECRET);
        const [rows] = await pool.query("SELECT * FROM pass");

        res.json({ data: rows });
    } catch (err) {
        res.status(401).json({ message: "Invalid token" });
    }
});

router.post("/passes", async (req, res) => {
    try {
        const authHeader = req.headers.authorization;

        if (!authHeader?.startsWith("Bearer "))
            return res.status(401).json({ message: "Token missing" });

        const token = authHeader.split(" ")[1];
        const data = jwt.verify(token, process.env.JWT_SECRET);
        const { member_id, seat_id, start_ts, end_ts, price, status } = req.body
        const [seatRows] = await pool.query(
            "SELECT 1 FROM seat WHERE seat_id = ? LIMIT 1",
            [seat_id]
        );
        if (seatRows.length === 0) {
            return res.status(400).json({ message: "seat_id does not exist" });
        }

        const [memberRows] = await pool.query(
            "SELECT 1 FROM member WHERE member_id = ? LIMIT 1",
            [member_id]
        );
        if (memberRows.length === 0) {
            return res.status(400).json({ message: "member_id does not exist" });
        }

        const [result] = await pool.query(
            `INSERT INTO pass (member_id, seat_id, start_ts, end_ts, price, status)
   VALUES (?, ?, ?, ?, ?, ?)`,
            [member_id, seat_id, start_ts, end_ts, price, status]
        );


        res.json({ message: "Pass created", passId: result.insertId });
    } catch (err) {
        res.status(401).json({ message: "Invalid token" });
    }
});

router.put("/passes/:id", async (req, res) => {
    try {
        const authHeader = req.headers.authorization;

        if (!authHeader?.startsWith("Bearer ")) {
            return res.status(401).json({ message: "Token missing" });
        }

        const token = authHeader.split(" ")[1];
        const data = jwt.verify(token, process.env.JWT_SECRET);

        const passId = req.params.id;

        const { member_id, seat_id, start_ts, end_ts, price, status } = req.body;

        const [result] = await pool.query(
            `UPDATE pass SET member_id=?, seat_id=?, start_ts=?, end_ts=?, price=?, status=? 
             WHERE pass_id=?`,
            [member_id, seat_id, start_ts, end_ts, price, status, passId]
        );

        res.json({ message: "Pass updated", updatedRows: result.affectedRows });
    } catch (err) {
        res.status(401).json({ message: "Invalid token" });
    }
});

router.delete("/passes/:id", async (req, res) => {
    try {
        const authHeader = req.headers.authorization;

        if (!authHeader?.startsWith("Bearer ")) {
            return res.status(401).json({ message: "Token missing" });
        }

        const token = authHeader.split(" ")[1];
        jwt.verify(token, process.env.JWT_SECRET);

        const passId = req.params.id;

        const [result] = await pool.query(
            "DELETE FROM pass WHERE pass_id = ?",
            [passId]
        );

        if (result.affectedRows === 0) {
            return res.status(404).json({ message: "Pass not found" });
        }

        res.json({ message: "Pass deleted successfully" });
    } catch (err) {
        res.status(500).json({ message: "Server error" });
    }
});


router.get("/payments", async (req, res) => {
    try {
        const authHeader = req.headers.authorization;

        if (!authHeader?.startsWith("Bearer "))
            return res.status(401).json({ message: "Token missing" });

        const token = authHeader.split(" ")[1];
        const data = jwt.verify(token, process.env.JWT_SECRET);
        const [rows] = await pool.query("SELECT * FROM payment");

        res.json({ data: rows });
    } catch (err) {
        res.status(401).json({ message: "Invalid token" });
    }
});

router.get("/registrations", async (req, res) => {
    try {
        const authHeader = req.headers.authorization;

        if (!authHeader?.startsWith("Bearer "))
            return res.status(401).json({ message: "Token missing" });

        const token = authHeader.split(" ")[1];
        const data = jwt.verify(token, process.env.JWT_SECRET);
        const [rows] = await pool.query("SELECT * FROM registration");

        res.json({ data: rows });
    } catch (err) {
        res.status(401).json({ message: "Invalid token" });
    }
});

router.post('/registrations', async (req, res) => {
    try {
        const authHeader = req.headers.authorization;

        if (!authHeader?.startsWith("Bearer ")) {
            return res.status(401).json({ message: "Token missing" });
        }

        const token = authHeader.split(" ")[1];
        jwt.verify(token, process.env.JWT_SECRET);

        const { tourney_id, member_id, seed_no, result } = req.body;

        const [resultData] = await pool.query(
            "INSERT INTO registration (tourney_id, member_id, seed_no, result) VALUES (?, ?, ?, ?)",
            [tourney_id, member_id, seed_no, result]
        );

        // 👇 MUST send a response, otherwise request will hang forever
        res.json({
            message: "Registration created successfully",
            registration_id: resultData.insertId
        });

    } catch (err) {
        return res.status(500).json({ message: "Server error" });
    }
});

router.put("/registrations/:id", async (req, res) => {
    try {
        const authHeader = req.headers.authorization;
        if (!authHeader?.startsWith("Bearer ")) {
            return res.status(401).json({ message: "Token missing" });
        }

        const token = authHeader.split(" ")[1];
        // will throw if invalid
        jwt.verify(token, process.env.JWT_SECRET);

        const registrationId = req.params.id;
        const { tourney_id, member_id, seed_no, result } = req.body;

        // basic validation
        if (!tourney_id || !member_id) {
            return res.status(400).json({ message: "tourney_id and member_id are required" });
        }

        // ensure referenced member exists
        const [memberRows] = await pool.query(
            "SELECT 1 FROM member WHERE member_id = ? LIMIT 1",
            [member_id]
        );
        if (memberRows.length === 0) {
            return res.status(400).json({ message: "member_id does not exist" });
        }

        const [updateResult] = await pool.query(
            `UPDATE registration
       SET tourney_id = ?, member_id = ?, seed_no = ?, result = ?
       WHERE registration_id = ?`,
            [tourney_id, member_id, seed_no ?? null, result ?? null, registrationId]
        );

        if (updateResult.affectedRows === 0) {
            return res.status(404).json({ message: "Registration not found" });
        }

        return res.json({
            message: "Registration updated successfully",
            updatedRows: updateResult.affectedRows
        });
    } catch (err) {

        if (err.name === "JsonWebTokenError" || err.name === "TokenExpiredError") {
            return res.status(401).json({ message: "Invalid or expired token" });
        }

        if (err.code === "ER_NO_REFERENCED_ROW_2") {
            return res.status(400).json({ message: "Invalid foreign key value" });
        }

        return res.status(500).json({ message: "Server error" });
    }
});

router.delete("/registrations/:id", async (req, res) => {
    try {
        const authHeader = req.headers.authorization;

        if (!authHeader?.startsWith("Bearer ")) {
            return res.status(401).json({ message: "Token missing" });
        }

        const token = authHeader.split(" ")[1];
        jwt.verify(token, process.env.JWT_SECRET);

        const registrationId = req.params.id;

        const [result] = await pool.query(
            "DELETE FROM registration WHERE registration_id = ?",
            [registrationId]
        );

        if (result.affectedRows === 0) {
            return res.status(404).json({ message: "Registration not found" });
        }

        return res.json({
            message: "Registration deleted successfully",
            deletedRows: result.affectedRows,
        });
    } catch (err) {
        return res.status(500).json({ message: "Server error" });
    }
});



router.get("/seats", async (req, res) => {
    try {
        const authHeader = req.headers.authorization;

        if (!authHeader?.startsWith("Bearer "))
            return res.status(401).json({ message: "Token missing" });

        const token = authHeader.split(" ")[1];
        const data = jwt.verify(token, process.env.JWT_SECRET);
        const [rows] = await pool.query("SELECT * FROM seat");

        res.json({ data: rows });
    } catch (err) {
        res.status(401).json({ message: "Invalid token" });
    }
});

router.get("/sponsors", async (req, res) => {
    try {
        const authHeader = req.headers.authorization;

        if (!authHeader?.startsWith("Bearer "))
            return res.status(401).json({ message: "Token missing" });

        const token = authHeader.split(" ")[1];
        const data = jwt.verify(token, process.env.JWT_SECRET);
        const [rows] = await pool.query("SELECT * FROM sponsor");

        res.json({ data: rows });
    } catch (err) {
        res.status(401).json({ message: "Invalid token" });
    }
});

router.get("/tournaments", async (req, res) => {
    try {
        const authHeader = req.headers.authorization;

        if (!authHeader?.startsWith("Bearer "))
            return res.status(401).json({ message: "Token missing" });

        const token = authHeader.split(" ")[1];
        const data = jwt.verify(token, process.env.JWT_SECRET);
        const [rows] = await pool.query("SELECT * FROM tournament");

        res.json({ data: rows });
    } catch (err) {
        res.status(401).json({ message: "Invalid token" });
    }
});

export default router;
