const express = require("express");
const cors = require("cors");
const path = require("path");
const sqlite3 = require("sqlite3").verbose();
const fs = require("fs");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { body, validationResult } = require("express-validator");
const multer = require("multer");

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || "dev_secret_change_me";

app.use(cors());
app.use(express.json({ limit: "2mb" }));
app.use(express.static(path.join(__dirname, "public")));
app.use('/uploads', express.static(path.join(__dirname, 'public', 'uploads')));

// --- SQLite connection ---
const db = new sqlite3.Database(path.join(__dirname, "ehr.db"), (err) => {
  if (err) console.error(err.message);
  else console.log("✅ Connected to SQLite database");
});

// --- Initialize schema (pragmatic: structured columns + JSON blobs for tabs) ---
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL CHECK(role IN ('admin','doctor','nurse')),
    created_at TEXT DEFAULT (datetime('now'))
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS patients (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT,
    dob TEXT,
    age INTEGER,
    gender TEXT,
    address TEXT,
    contact TEXT,
    patientStatus TEXT,
    roomNo TEXT,
    bedNo TEXT,
    physician TEXT,
    initialDiagnosis TEXT,
    info_json TEXT,
    id_json TEXT,
    history_json TEXT,
    assessment_json TEXT,
    labs_json TEXT,
    meds_json TEXT,
    vitals_json TEXT,
    nurse_json TEXT,
    doctor_json TEXT,
    plan_json TEXT,
    created_by TEXT,
    created_at TEXT DEFAULT (datetime('now')),
    updated_at TEXT DEFAULT (datetime('now'))
  )`);

  // Lightweight migration: add missing columns if upgrading from older schema
  const requiredPatientColumns = [
    'name','dob','age','gender','address','contact','patientStatus','roomNo','bedNo','physician','initialDiagnosis',
    'info_json','id_json','history_json','assessment_json','labs_json','meds_json','vitals_json','nurse_json','doctor_json','plan_json','created_by','created_at','updated_at'
  ];
  db.all("PRAGMA table_info(patients)", (err, rows) => {
    if (err || !Array.isArray(rows)) return;
    const have = new Set(rows.map(r => r.name));
    const adds = requiredPatientColumns.filter(c => !have.has(c));
    if (adds.length) {
      console.log('🔧 Migrating patients table, adding columns:', adds.join(', '));
      const addMap = {
        name: "TEXT", dob: "TEXT", age: "INTEGER", gender: "TEXT", address: "TEXT", contact: "TEXT", patientStatus: "TEXT", roomNo: "TEXT", bedNo: "TEXT", physician: "TEXT", initialDiagnosis: "TEXT",
        info_json: "TEXT", id_json: "TEXT", history_json: "TEXT", assessment_json: "TEXT", labs_json: "TEXT", meds_json: "TEXT", vitals_json: "TEXT", nurse_json: "TEXT", doctor_json: "TEXT", plan_json: "TEXT",
        created_by: "TEXT", created_at: "TEXT", updated_at: "TEXT"
      };
      db.serialize(() => {
        adds.forEach(col => {
          const type = addMap[col] || 'TEXT';
          db.run(`ALTER TABLE patients ADD COLUMN ${col} ${type}`);
        });
      });
    }
  });

  db.run(`CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_email TEXT,
    action TEXT,
    resource_type TEXT,
    resource_id INTEGER,
    details TEXT,
    created_at TEXT DEFAULT (datetime('now'))
  )`);

  // Seed default users if empty
  db.get("SELECT COUNT(*) AS c FROM users", (err, row) => {
    if (err) return console.error("Failed to count users", err);
    if (row && row.c === 0) {
      const seedUsers = [
        { email: "admin@example.com", role: "admin", password: "admin123" },
        { email: "doctor@example.com", role: "doctor", password: "doctor123" },
        { email: "nurse@example.com", role: "nurse", password: "nurse123" },
      ];
      const stmt = db.prepare("INSERT INTO users (email, password_hash, role) VALUES (?,?,?)");
      seedUsers.forEach(u => {
        const hash = bcrypt.hashSync(u.password, 10);
        stmt.run(u.email, hash, u.role);
      });
      stmt.finalize(() => console.log("✅ Seeded default users (admin/doctor/nurse)."));
    }
  });

  // Encounters (admissions/visits)
  db.run(`CREATE TABLE IF NOT EXISTS encounters (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    patient_id INTEGER NOT NULL,
    type TEXT, -- inpatient/outpatient/er
    status TEXT, -- active/discharged
    attending TEXT,
    location TEXT,
    start_at TEXT DEFAULT (datetime('now')),
    end_at TEXT,
    created_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY(patient_id) REFERENCES patients(id) ON DELETE CASCADE
  )`);

  // Vitals linked to encounters
  db.run(`CREATE TABLE IF NOT EXISTS vitals (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    encounter_id INTEGER NOT NULL,
    recorded_at TEXT DEFAULT (datetime('now')),
    by_user TEXT,
    temp TEXT, pulse TEXT, rr TEXT, bp TEXT, spo2 TEXT, pain TEXT,
    weight TEXT, height TEXT, bmi TEXT,
    note TEXT,
    FOREIGN KEY(encounter_id) REFERENCES encounters(id) ON DELETE CASCADE
  )`);

  // Med orders
  db.run(`CREATE TABLE IF NOT EXISTS medications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    encounter_id INTEGER NOT NULL,
    drug TEXT, dosage TEXT, route TEXT, frequency TEXT,
    ordered_by TEXT, administered_by TEXT,
    created_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY(encounter_id) REFERENCES encounters(id) ON DELETE CASCADE
  )`);

  // Allergies
  db.run(`CREATE TABLE IF NOT EXISTS allergies (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    patient_id INTEGER NOT NULL,
    substance TEXT, reaction TEXT, severity TEXT,
    noted_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY(patient_id) REFERENCES patients(id) ON DELETE CASCADE
  )`);

  // Labs
  db.run(`CREATE TABLE IF NOT EXISTS labs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    encounter_id INTEGER NOT NULL,
    test_name TEXT,
    result TEXT,
    units TEXT,
    reference_range TEXT,
    file_url TEXT,
    created_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY(encounter_id) REFERENCES encounters(id) ON DELETE CASCADE
  )`);

  // Notes (doctor/nurse)
  db.run(`CREATE TABLE IF NOT EXISTS notes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    encounter_id INTEGER NOT NULL,
    author_email TEXT,
    type TEXT, -- doctor|nurse
    content TEXT,
    created_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY(encounter_id) REFERENCES encounters(id) ON DELETE CASCADE
  )`);
});

// --- Helpers ---
function signToken(user) {
  return jwt.sign({ sub: user.id, email: user.email, role: user.role }, JWT_SECRET, { expiresIn: "12h" });
}

function authMiddleware(req, res, next) {
  const auth = req.headers.authorization || "";
  const token = auth.startsWith("Bearer ") ? auth.slice(7) : null;
  if (!token) return res.status(401).json({ error: "Missing token" });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch (e) {
    return res.status(401).json({ error: "Invalid token" });
  }
}

// --- File uploads (images/PDFs) ---
const uploadsDir = path.join(__dirname, 'public', 'uploads');
try { fs.mkdirSync(uploadsDir, { recursive: true }); } catch {}
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, uploadsDir);
  },
  filename: function (req, file, cb) {
    const safe = Date.now() + '-' + String(file.originalname || 'upload').replace(/\s+/g, '_').replace(/[^a-zA-Z0-9_\.-]/g, '');
    cb(null, safe);
  }
});
const upload = multer({
  storage,
  limits: { fileSize: 10 * 1024 * 1024 }, // 10MB
  fileFilter: (req, file, cb) => {
    const ok = file.mimetype?.startsWith('image/') || file.mimetype === 'application/pdf';
    if (!ok) return cb(new Error('Only images or PDF allowed'));
    cb(null, true);
  }
});

app.post('/api/uploads', authMiddleware, requireRole('admin','doctor','nurse'), upload.single('file'), (req, res) => {
  const f = req.file;
  if (!f) return res.status(400).json({ error: 'No file uploaded' });
  const url = `/uploads/${f.filename}`;
  res.json({ url, filename: f.filename, originalname: f.originalname, mimetype: f.mimetype, size: f.size });
});

function requireRole(...roles) {
  return (req, res, next) => {
    if (!req.user || !roles.includes(req.user.role)) return res.status(403).json({ error: "Forbidden" });
    next();
  };
}

function audit(userEmail, action, resourceType, resourceId, detailsObj = null) {
  const details = detailsObj ? JSON.stringify(detailsObj) : null;
  db.run(
    "INSERT INTO audit_logs (user_email, action, resource_type, resource_id, details) VALUES (?,?,?,?,?)",
    [userEmail || null, action, resourceType, resourceId || null, details],
  );
}

function mapPatientRow(row) {
  if (!row) return null;
  const parse = (t) => {
    try { return t ? JSON.parse(t) : null; } catch { return null; }
  };
  return {
    id: row.id,
    name: row.name,
    dob: row.dob,
    age: row.age,
    gender: row.gender,
    address: row.address,
    contact: row.contact,
    patientStatus: row.patientStatus,
    roomNo: row.roomNo,
    bedNo: row.bedNo,
    physician: row.physician,
    initialDiagnosis: row.initialDiagnosis,
    info: parse(row.info_json) || {},
    identification: parse(row.id_json) || {},
    history: parse(row.history_json) || {},
    assessment: parse(row.assessment_json) || {},
    labs: parse(row.labs_json) || {},
    meds: parse(row.meds_json) || {},
    vitals: parse(row.vitals_json) || [],
    nurse: parse(row.nurse_json) || {},
    doctor: parse(row.doctor_json) || {},
    plan: parse(row.plan_json) || {},
    created_by: row.created_by,
    created_at: row.created_at,
    updated_at: row.updated_at,
  };
}

// --- Auth routes ---
app.post(
  "/api/auth/login",
  body("email").isEmail(),
  body("password").isLength({ min: 4 }),
  (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });
    const { email, password } = req.body;
    db.get("SELECT * FROM users WHERE email = ?", [email], (err, user) => {
      if (err) return res.status(500).json({ error: err.message });
      if (!user) return res.status(401).json({ error: "Invalid credentials" });
      if (!bcrypt.compareSync(password, user.password_hash)) return res.status(401).json({ error: "Invalid credentials" });
      const token = signToken(user);
      res.json({ token, user: { id: user.id, email: user.email, role: user.role } });
    });
  }
);

app.get("/api/auth/me", authMiddleware, (req, res) => {
  res.json({ user: { email: req.user.email, role: req.user.role } });
});

// --- Patients: list with search & pagination ---
app.get("/api/patients", authMiddleware, (req, res) => {
  const { q = "", page = 1, limit = 20, sort = "updated_at_desc" } = req.query;
  const offset = (Number(page) - 1) * Number(limit);
  const like = `%${q}%`;
  const order = sort === "name_asc" ? "name COLLATE NOCASE ASC" : "datetime(updated_at) DESC";
  db.all(
    `SELECT * FROM patients 
     WHERE COALESCE(name,'') LIKE ? OR COALESCE(physician,'') LIKE ? OR COALESCE(roomNo,'') LIKE ?
     ORDER BY ${order} LIMIT ? OFFSET ?`,
    [like, like, like, Number(limit), offset],
    (err, rows) => {
      if (err) return res.status(500).json({ error: err.message });
      const data = rows.map(mapPatientRow);
      res.json({ data, page: Number(page), limit: Number(limit) });
    }
  );
});

// --- Encounters API ---
app.post("/api/patients/:id/encounters", authMiddleware, requireRole("admin", "doctor", "nurse"), (req, res) => {
  const patientId = Number(req.params.id);
  const { type = "outpatient", status = "active", attending = null, location = null, start_at = null } = req.body || {};
  db.run(
    `INSERT INTO encounters (patient_id, type, status, attending, location, start_at) VALUES (?,?,?,?,?,COALESCE(?, datetime('now')))` ,
    [patientId, type, status, attending, location, start_at],
    function (err) {
      if (err) return res.status(500).json({ error: err.message });
      audit(req.user.email, "create", "encounter", this.lastID, { patientId });
      db.get("SELECT * FROM encounters WHERE id = ?", [this.lastID], (e2, row) => {
        if (e2) return res.status(500).json({ error: e2.message });
        res.json({ encounter: row });
      });
    }
  );
});

app.get("/api/patients/:id/encounters", authMiddleware, (req, res) => {
  db.all("SELECT * FROM encounters WHERE patient_id = ? ORDER BY datetime(start_at) DESC", [req.params.id], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ data: rows });
  });
});

// --- Vitals API ---
app.post("/api/encounters/:id/vitals", authMiddleware, requireRole("admin", "doctor", "nurse"), (req, res) => {
  const encId = Number(req.params.id);
  const v = req.body || {};
  const recorded_at = v.recorded_at || null;
  db.run(
    `INSERT INTO vitals (encounter_id, recorded_at, by_user, temp, pulse, rr, bp, spo2, pain, weight, height, bmi, note)
     VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`,
    [encId, recorded_at, req.user.email, v.temp||null, v.pulse||null, v.rr||null, v.bp||null, v.spo2||null, v.pain||null, v.weight||null, v.height||null, v.bmi||null, v.note||null],
    function (err) {
      if (err) return res.status(500).json({ error: err.message });
      audit(req.user.email, "create", "vitals", this.lastID, { encId });
      db.get("SELECT * FROM vitals WHERE id = ?", [this.lastID], (e2, row) => {
        if (e2) return res.status(500).json({ error: e2.message });
        res.json({ vitals: row });
      });
    }
  );
});

app.get("/api/encounters/:id/vitals", authMiddleware, (req, res) => {
  db.all("SELECT * FROM vitals WHERE encounter_id = ? ORDER BY datetime(recorded_at) DESC, id DESC", [req.params.id], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ data: rows });
  });
});

// --- Labs API (text entries) ---
app.post("/api/encounters/:id/labs", authMiddleware, requireRole("admin", "doctor"), (req, res) => {
  const encId = Number(req.params.id);
  const { test_name, result, units, reference_range, file_url } = req.body || {};
  db.run(
    `INSERT INTO labs (encounter_id, test_name, result, units, reference_range, file_url) VALUES (?,?,?,?,?,?)`,
    [encId, test_name||null, result||null, units||null, reference_range||null, file_url||null],
    function (err) {
      if (err) return res.status(500).json({ error: err.message });
      audit(req.user.email, "create", "lab", this.lastID, { encId });
      db.get("SELECT * FROM labs WHERE id = ?", [this.lastID], (e2, row) => {
        if (e2) return res.status(500).json({ error: e2.message });
        res.json({ lab: row });
      });
    }
  );
});

app.get("/api/encounters/:id/labs", authMiddleware, (req, res) => {
  db.all("SELECT * FROM labs WHERE encounter_id = ? ORDER BY id DESC", [req.params.id], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ data: rows });
  });
});

// --- Notes API ---
app.post("/api/encounters/:id/notes", authMiddleware, requireRole("admin", "doctor", "nurse"), (req, res) => {
  const encId = Number(req.params.id);
  const { type = "nurse", content } = req.body || {};
  db.run(
    `INSERT INTO notes (encounter_id, author_email, type, content) VALUES (?,?,?,?)`,
    [encId, req.user.email, type, content||null],
    function (err) {
      if (err) return res.status(500).json({ error: err.message });
      audit(req.user.email, "create", "note", this.lastID, { encId, type });
      db.get("SELECT * FROM notes WHERE id = ?", [this.lastID], (e2, row) => {
        if (e2) return res.status(500).json({ error: e2.message });
        res.json({ note: row });
      });
    }
  );
});

app.get("/api/encounters/:id/notes", authMiddleware, (req, res) => {
  db.all("SELECT * FROM notes WHERE encounter_id = ? ORDER BY datetime(created_at) DESC", [req.params.id], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ data: rows });
  });
});

// --- Create new patient (from Info tab typically) ---
app.post(
  "/api/patients",
  authMiddleware,
  requireRole("admin", "doctor"),
  (req, res) => {
    const p = req.body || {};
    const info = p.info || p; // allow raw fields
    const name = info.name || null;
    if (!name) return res.status(400).json({ error: "Name is required" });
    const fields = [
      name,
      info.dob || null,
      info.age || null,
      info.gender || null,
      info.address || null,
      info.contact || null,
      info.patientStatus || null,
      info.roomNo || null,
      info.bedNo || null,
      info.physician || null,
      info.initialDiagnosis || null,
      JSON.stringify(info),
      null, null, null, null, null, null, JSON.stringify([]), null, null,
      req.user?.email || null
    ];
    db.run(
      `INSERT INTO patients 
        (name, dob, age, gender, address, contact, patientStatus, roomNo, bedNo, physician, initialDiagnosis, info_json, id_json, history_json, assessment_json, labs_json, meds_json, vitals_json, nurse_json, doctor_json, plan_json, created_by)
       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
      fields,
      function (err) {
        if (err) return res.status(500).json({ error: err.message });
        audit(req.user?.email, "create", "patient", this.lastID, { name });
        db.get("SELECT * FROM patients WHERE id = ?", [this.lastID], (e2, row) => {
          if (e2) return res.status(500).json({ error: e2.message });
          res.json({ patient: mapPatientRow(row) });
        });
      }
    );
  }
);

// --- Get single patient ---
app.get("/api/patients/:id", authMiddleware, (req, res) => {
  db.get("SELECT * FROM patients WHERE id = ?", [req.params.id], (err, row) => {
    if (err) return res.status(500).json({ error: err.message });
    if (!row) return res.status(404).json({ error: "Not found" });
    res.json({ patient: mapPatientRow(row) });
  });
});

// --- Update patient tab (merge into JSON blobs) ---
app.put("/api/patients/:id", authMiddleware, requireRole("admin", "doctor", "nurse"), (req, res) => {
  const id = req.params.id;
  const { tab, data } = req.body || {};
  if (!tab || typeof data !== "object") return res.status(400).json({ error: "tab and data required" });

  const allowedTabs = {
    info: "info_json",
    id: "id_json",
    history: "history_json",
    assessment: "assessment_json",
    labs: "labs_json",
    meds: "meds_json",
    vitals: "vitals_json",
    nurse: "nurse_json",
    doctor: "doctor_json",
    plan: "plan_json",
  };
  const col = allowedTabs[tab];
  if (!col) return res.status(400).json({ error: "Invalid tab" });

  // Role restrictions example: nurses cannot edit doctor tab
  if (tab === "doctor" && req.user.role === "nurse") return res.status(403).json({ error: "Forbidden for nurse" });

  // Special: also denormalize key fields for cards when updating info
  const setParts = [
    `${col} = ?`,
    `updated_at = datetime('now')`
  ];
  const params = [JSON.stringify(data)];
  if (tab === "info") {
    setParts.push("name = ?", "dob = ?", "age = ?", "gender = ?", "address = ?", "contact = ?", "patientStatus = ?", "roomNo = ?", "bedNo = ?", "physician = ?", "initialDiagnosis = ?");
    params.push(
      data.name || null,
      data.dob || null,
      data.age || null,
      data.gender || null,
      data.address || null,
      data.contact || null,
      data.patientStatus || null,
      data.roomNo || null,
      data.bedNo || null,
      data.physician || null,
      data.initialDiagnosis || null,
    );
  }
  params.push(id);

  const sql = `UPDATE patients SET ${setParts.join(", ")} WHERE id = ?`;
  db.run(sql, params, function (err) {
    if (err) return res.status(500).json({ error: err.message });
    if (this.changes === 0) return res.status(404).json({ error: "Not found" });
    audit(req.user.email, "update", "patient", id, { tab });
    db.get("SELECT * FROM patients WHERE id = ?", [id], (e2, row) => {
      if (e2) return res.status(500).json({ error: e2.message });
      res.json({ patient: mapPatientRow(row) });
    });
  });
});

// --- Delete patient ---
app.delete("/api/patients/:id", authMiddleware, requireRole("admin", "doctor"), (req, res) => {
  const id = req.params.id;
  db.run("DELETE FROM patients WHERE id = ?", [id], function (err) {
    if (err) return res.status(500).json({ error: err.message });
    if (this.changes === 0) return res.status(404).json({ error: "Not found" });
    audit(req.user.email, "delete", "patient", id, null);
    res.json({ message: "Patient deleted" });
  });
});

// --- Audit logs (admin only) ---
app.get("/api/audit", authMiddleware, requireRole("admin"), (req, res) => {
  db.all("SELECT * FROM audit_logs ORDER BY datetime(created_at) DESC LIMIT 500", [], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ data: rows });
  });
});

app.listen(PORT, () => {
  console.log(`✅ EHR API running at http://localhost:${PORT}`);
});

