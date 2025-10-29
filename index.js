import express from "express";
import bodyParser from "body-parser";
import { dirname } from "path";
import { fileURLToPath } from "url";
import dotenv from "dotenv";
import session from "express-session";
import connectPgSimple from "connect-pg-simple";
import bcrypt from "bcrypt";
import { Pool } from "pg";
import path from "path";
import cors from "cors"; //ช่วยแก้ปัญหา CORS error ที่เกิดเวลา frontend เรียก backend

dotenv.config();
const __dirname = dirname(fileURLToPath(import.meta.url));

const app = express();
app.use(cors());               // อนุญาตการเชื่อมต่อจาก frontend
app.use(express.json());       // เพื่อให้ express อ่าน req.body ที่เป็น JSON ได้
const port = process.env.PORT || 3000;

app.set("view engine", "ejs"); // บอก Express ว่าให้ใช้ EJS เป็น engine หลัก
app.set("views", path.join(__dirname, "views"));
// เชื่อมต่อ PostgreSQL
const pool = new Pool({
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DB_DATABASE,
  password: process.env.DB_PASSWORD,
  port: process.env.DB_PORT,
});

// ตรวจสอบการเชื่อมต่อฐานข้อมูล
pool.connect()
  .then(() => console.log("Connected to PostgreSQL"))
  .catch(err => console.error("Database connection error:", err));

const PgSession = connectPgSimple(session);
app.use(
  session({
    store: new PgSession({
      pool,
      tableName: "session",
      createTableIfMissing: true,
    }),
    secret: process.env.SESSION_SECRET || "dev-secret",
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: "lax",
      maxAge: 1000 * 60 * 60 * 24, // 1 วัน
    },
  })
);

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static(__dirname + "/public"));

// ดึง user จาก session
app.use((req, res, next) => {
  if (req.session && req.session.user) {
    req.user = req.session.user;
  }
  next();
});

// ฟังก์ชันเช็ค login และ role
function requireAuth(req, res, next) {
  if (!req.user) return res.redirect("/");
  next();
}

function requireRole(...roles) {
  return (req, res, next) => {
    if (!req.user) return res.status(401).send("Unauthorized");
    if (!roles.includes(req.user.role))
      return res.status(403).send("คุณไม่มีสิทธิ์เข้าหน้านี้");
    next();
  };
}

// หน้า login
app.get("/", (req, res) => {
  res.sendFile(__dirname + "/public/Home.html");
});

// สมัครสมาชิก (จาก sign_in.html)
app.post("/signup", async (req, res) => {
  const { username, surname, email, phone, password } = req.body;

  // แสดงค่าที่รับมาจาก form
  console.log("Received signup data:", username, surname, email, phone);

  try {
    const checkUser = await pool.query("SELECT * FROM users WHERE email = $1", [email]);
    if (checkUser.rows.length > 0) {
      console.log("Email already exists:", email); // แสดง log ถ้า email ซ้ำ
      return res.status(400).send("อีเมลนี้ถูกใช้ไปแล้ว");
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const result = await pool.query(
      `INSERT INTO users (displayname, surname, email, phone, password, role)
       VALUES ($1, $2, $3, $4, $5, 'Member') RETURNING userid`,
      [username, surname, email, phone, hashedPassword]
    );

    // แสดง user id ที่ insert ลงฐานข้อมูล
    console.log("Inserted user ID:", result.rows[0].userid);

    res.redirect("/log_in.html");
  } catch (err) {
    console.error("Signup error:", err); // แสดง error ถ้าเกิดปัญหา
    res.status(500).send("เกิดข้อผิดพลาดในการสมัครสมาชิก");
  }
});


// เข้าสู่ระบบ
app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  try {
    //ตรวจว่ามีผู้ใช้อีเมลนี้ไหม
    const result = await pool.query("SELECT * FROM users WHERE email = $1", [email]);

    if (result.rows.length === 0) {
      console.log("ไม่พบอีเมล:", email);
      return res.redirect("/log_in.html?error=" + encodeURIComponent("อีเมลหรือรหัสผ่านไม่ถูกต้อง"));
    }

    //ดึงข้อมูลผู้ใช้แถวแรก
    const user = result.rows[0];

    //ตรวจว่ามีรหัสผ่านใน DB จริงไหม
    if (!user.password) {
      console.log("ไม่พบรหัสผ่านในฐานข้อมูลสำหรับ:", email);
      return res.redirect("/log_in.html?error=" + encodeURIComponent("ข้อมูลผู้ใช้ไม่ถูกต้อง"));
    }

    //ตรวจสอบรหัสผ่าน
    const valid = await bcrypt.compare(password, user.password);
    console.log("Password valid?", valid);

    if (!valid) {
      console.log("รหัสผ่านไม่ถูกต้องสำหรับ:", email);
      return res.redirect("/log_in.html?error=" + encodeURIComponent("อีเมลหรือรหัสผ่านไม่ถูกต้อง"));
    }

    //ถ้าผ่านทุกอย่าง -> เก็บ session
    req.session.user = {
      id: user.userid,
      email: user.email,
      role: user.role,
      displayname: user.displayname,
      surname: user.surname
    };
    res.redirect("/Home.html");
  } catch (err) {
    console.error("Login Error:", err);
    res.redirect("/log_in.html?error=" + encodeURIComponent("เกิดข้อผิดพลาดจากเซิร์ฟเวอร์"));
  }
});

// reset-password
app.post("/reset-password", async (req, res) => {
  const { email, newPassword } = req.body;

  if (!email || !newPassword) {
    return res.status(400).send("กรุณากรอกอีเมลและรหัสผ่านใหม่");
  }

  try {
    const result = await pool.query("SELECT * FROM users WHERE email = $1", [email]);
    if (result.rows.length === 0) {
      return res.status(404).send("ไม่พบบัญชีนี้");
    }

    const hashed = await bcrypt.hash(newPassword, 10);

    await pool.query(
      "UPDATE users SET password = $1 WHERE email = $2",
      [hashed, email]
    );

    res.send("รีเซ็ตรหัสผ่านสำเร็จแล้ว");
  } catch (err) {
    console.error(err);
    res.status(500).send("เกิดข้อผิดพลาดในการรีเซ็ตรหัสผ่าน");
  }
}); 

// API คืนข้อมูลผู้ใช้ที่ login อยู่
app.get("/api/user", (req, res) => {
  if (req.session && req.session.user) {
    res.json(req.session.user);
  } else {
    res.status(401).json({ message: "ยังไม่ได้เข้าสู่ระบบ" });
  }
});

// logout
app.get("/logout", (req, res) => {
  req.session.destroy(err => {
    if (err) {
      console.error("Logout error:", err);
      return res.redirect("/Home.html");
    }
    res.clearCookie("connect.sid");
    res.redirect("/Home.html");
  });
});


// start server
app.listen(port, () => console.log(`Server running at http://localhost:${port}`));

function requireAdmin(req, res, next) {
  if (!req.user) return res.redirect("/log_in.html");
  if (req.user.role !== "Admin") return res.redirect("/Home.html");
  next();
}

function requireMember(req, res, next) {
  if (!req.user) return res.redirect("/log_in.html"); 
  if (req.user.role !== "Member") return res.redirect("/Home.html"); 
  next();
}

app.get("/Dash.html", requireAdmin, async (req, res) => {
    try {
        const user = req.user;
        
        // ดึงข้อมูลทั้งหมดจาก API ที่มีอยู่แล้ว (หรือโค้ด Query)
        const [totalRes, newRes, latestRes, weekRes] = await Promise.all([
            pool.query("SELECT COUNT(*) FROM users"),
            pool.query("SELECT COUNT(*) FROM users WHERE created_at::date = CURRENT_DATE"),
            pool.query("SELECT displayname, surname, email, created_at FROM users ORDER BY created_at DESC LIMIT 5"),
            pool.query(`
                SELECT to_char(created_at, 'YYYY-MM-DD') AS day, COUNT(*) AS count
                FROM users
                WHERE created_at >= CURRENT_DATE - INTERVAL '6 days'
                GROUP BY day
                ORDER BY day
            `)
        ]);

        // เตรียมข้อมูลสำหรับส่งไป EJS
        const totalMembers = parseInt(totalRes.rows[0].count);
        const newMembersToday = parseInt(newRes.rows[0].count);
        const latestMembers = latestRes.rows;
        const weekData = {
            labels: weekRes.rows.map(r => r.day),
            counts: weekRes.rows.map(r => parseInt(r.count))
        };

        // Render หน้า EJS
        res.render("Dash", {
            user: user,
            totalMembers: totalMembers,
            newMembersToday: newMembersToday,
            latestMembers: latestMembers,
            weekData: weekData
        });

    } catch (err) {
        console.error("Error rendering Dashboard:", err);
        res.status(500).send("ไม่สามารถโหลดหน้า Dashboard ได้");
    }
});

app.get("/Manage.html", requireAdmin, async (req, res) => {
    try {
        const user = req.user;
        
        // ดึงข้อมูลสมาชิกทั้งหมดในครั้งแรก
        const result = await pool.query(
            `SELECT userid AS id, displayname, surname, email, phone, role, created_at
            FROM users
            ORDER BY userid ASC`
        );
        const members = result.rows;

        // Render ไฟล์ views/Manage.ejs พร้อมส่งข้อมูล
        res.render("Manage", { 
            user: user,       
            members: members  
        });

    } catch (err) {
        console.error("Error rendering Manage page:", err);
        res.redirect("/Dash.html");
    }
});

app.get("/Mymember.html", requireMember, (req, res) => {
  res.sendFile(path.join(__dirname, "public", "Mymember.html"));
});

app.get("/api/admin/total-members", requireRole("Admin"), async (req, res) => {
  try {
    const result = await pool.query("SELECT COUNT(*) FROM users");
    res.json({ totalMembers: result.rows[0].count });
  } catch (err) {
    console.error("Error fetching total members:", err);
    res.status(500).json({ error: "เกิดข้อผิดพลาด" });
  }
});

// นับสมาชิกทั้งหมด
app.get("/api/admin/total-members", requireRole("Admin"), async (req, res) => {
  try {
    const result = await pool.query("SELECT COUNT(*) FROM users");
    res.json({ totalMembers: parseInt(result.rows[0].count) });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "เกิดข้อผิดพลาด" });
  }
});

// นับสมาชิกที่สมัครวันนี้
app.get("/api/admin/new-members-today", requireRole("Admin"), async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT COUNT(*) FROM users WHERE created_at::date = CURRENT_DATE"
    );
    res.json({ newMembersToday: parseInt(result.rows[0].count) });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "เกิดข้อผิดพลาด" });
  }
});

// สมาชิกล่าสุด 5 คน
app.get("/api/admin/latest-members", requireRole("Admin"), async (req, res) => {
  try {
    const result = await pool.query("SELECT displayname, surname, email, created_at FROM users ORDER BY created_at DESC LIMIT 5");
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json([]);
  }
});

// สมาชิกรายสัปดาห์ (7 วันล่าสุด)
app.get("/api/admin/members-week", requireRole("Admin"), async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT to_char(created_at, 'YYYY-MM-DD') AS day, COUNT(*) AS count
      FROM users
      WHERE created_at >= CURRENT_DATE - INTERVAL '6 days'
      GROUP BY day
      ORDER BY day
    `);
    const labels = result.rows.map(r => r.day);
    const counts = result.rows.map(r => parseInt(r.count));
    res.json({ labels, counts });
  } catch (err) {
    console.error(err);
    res.status(500).json({ labels: [], counts: [] });
  }
});

// ดึงรายชื่อสมาชิกทั้งหมด (เฉพาะแอดมิน)
app.get("/api/admin/members", async (req, res) => {
  try {
    if (!req.session?.user || req.session.user.role !== "Admin") {
      return res.status(403).json({ message: "forbidden" });
    }

    const search = req.query.search ? `%${req.query.search}%` : "%";

    const result = await pool.query(
      `SELECT userid AS id, displayname, surname, email, phone, role, created_at
       FROM users
       WHERE displayname ILIKE $1 OR email ILIKE $1
       ORDER BY userid ASC`,
      [search]
    );

    res.json(result.rows);
  } catch (err) {
    console.error("Error fetching members:", err);
    res.status(500).json({ message: "server error" });
  }
});

// อัปเดต role
app.put("/api/admin/update-role/:id", async (req, res) => {
  if (!req.session.user || req.session.user.role !== "Admin") {
    return res.status(403).json({ error: "forbidden" });
  }
  const { id } = req.params;
  const { role } = req.body;
  await pool.query("UPDATE users SET role = $1 WHERE userid = $2", [role, id]);
  res.json({ success: true });
});

// ลบสมาชิก
app.delete("/api/admin/delete-member/:id", async (req, res) => {
  if (!req.session.user || req.session.user.role !== "Admin") {
    return res.status(403).json({ error: "forbidden" });
  }
  const { id } = req.params;
  await pool.query("DELETE FROM users WHERE userid = $1", [id]);
  res.json({ success: true });
});

// บันทึกข้อมูลการชำระเงิน
app.post("/api/payment", async (req, res) => {
  const { fullname, email, package: pkg, card_number, expiry_date, cvv } = req.body;

  if (!fullname || !email || !pkg || !card_number || !expiry_date || !cvv) {
    return res.json({ success: false, message: "กรอกข้อมูลให้ครบถ้วน" });
  }

  try {
    // เริ่มลบข้อมูลเก่าของผู้ใช้ (ถ้ามี)
    await pool.query("DELETE FROM payments WHERE email = $1", [email]);

    // บันทึกข้อมูลใหม่
    const query = `
      INSERT INTO payments (fullname, email, package, card_number, expiry_date, cvv, payment_date)
      VALUES ($1, $2, $3, $4, $5, $6, NOW())
    `;
    await pool.query(query, [fullname, email, pkg, card_number, expiry_date, cvv]);

    res.json({ success: true });
  } catch (err) {
    console.error("Database Error:", err);
    res.json({ success: false, message: "ไม่สามารถบันทึกข้อมูลได้" });
  }
});

// ดึงข้อมูลสมาชิกของ user ที่ login
app.get("/api/membership/me", async (req, res) => {
  if (!req.session.user)
    return res.status(401).json({ message: "Unauthorized" });

  const email = req.session.user.email;

  try {
    const result = await pool.query(`
      SELECT
        fullname,
        package,
        payment_date
      FROM payments
      WHERE email = $1
      ORDER BY payment_date DESC
      LIMIT 1;
    `, [email]);

    if (result.rows.length === 0)
      return res.status(404).json({ message: "ไม่พบข้อมูลสมาชิก" });

    res.json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "เกิดข้อผิดพลาดจากเซิร์ฟเวอร์" });
  }
});

app.get("/admin/dashboard.html", requireAdmin, async (req, res) => {
    const user = req.user;

    const [totalRes, newRes, latestRes, weekRes] = await Promise.all([
        pool.query("SELECT COUNT(*) FROM users"),
        pool.query("SELECT COUNT(*) FROM users WHERE created_at::date = CURRENT_DATE"),
        pool.query("SELECT displayname, surname, email, created_at FROM users ORDER BY created_at DESC LIMIT 5"),
        pool.query(`
            SELECT to_char(created_at, 'YYYY-MM-DD') AS day, COUNT(*) AS count
            FROM users
            WHERE created_at >= CURRENT_DATE - INTERVAL '6 days'
            GROUP BY day
            ORDER BY day
        `)
    ]);

    res.render("Dash", {
        user,
        totalMembers: parseInt(totalRes.rows[0].count),
        newMembersToday: parseInt(newRes.rows[0].count),
        latestMembers: latestRes.rows,
        weekData: {
            labels: weekRes.rows.map(r => r.day),
            counts: weekRes.rows.map(r => parseInt(r.count))
        }
    });
});





