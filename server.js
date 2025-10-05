const express = require('express');
const mysql = require('mysql2');
const bodyParser = require('body-parser');
const cors = require('cors');
const bcrypt = require('bcrypt');

const app = express();
app.use(cors());
app.use(bodyParser.json());

// MySQL connection
const db = mysql.createConnection({
  host: 'localhost',
  user: 'root',        // your MySQL username
  password: 'SriNi@',        // your MySQL password
  database: 'weshare'  // your DB name
});

db.connect(err => {
  if (err) throw err;
  console.log('MySQL Connected...');
});

app.post("/register",async (req, res) => {
    const { name, phone, address, role, email, password } = req.body;

  try{

    const hashedPassword = await bcrypt.hash(password, 10); // hash password
    const sql = "INSERT INTO users (email, name, phone, address, role, password) VALUES (?, ?, ?, ?, ?, ?)";
    db.query(sql, [email, name, phone, address, role, hashedPassword], (err, results) => {
        if (err) {
            if (err.code === "ER_DUP_ENTRY") {
                return res.status(400).send("Email already exists");
            }
            return res.status(500).send(err);
        }
        res.send("Registration successful!");
    });
  } catch(err){
    console.error(err);
    res.status(500).send("Error registering user");
  }
});


app.post("/login", (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ message: "Please provide email and password" });
  }

  const sql = "SELECT * FROM users WHERE email = ?";
  db.query(sql, [email], async (err, result) => {
    if (err) {
      console.error("❌ Error:", err);
      return res.status(500).json({ message: "Database error" });
    }

    if (result.length === 0) {
      return res.status(401).json({ message: "User not found" });
    }

    const user = result[0];
    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {
      return res.status(401).json({ message: "Invalid password" });
    }

    // ✅ Store email + hashed password in login table
    const logSql = "INSERT INTO login (email, password) VALUES (?, ?)";
    db.query(logSql, [email, user.password], (err2) => {
      if (err2) console.error("⚠️ Could not log login:", err2);
    });

    res.status(200).json({ message: "✅ Login successful", user: { email: user.email, role: user.role } });
  });
});

// Get dashboard stats (total donors, volunteers, organizations)
app.get("/admin/stats", (req, res) => {
  const sql = `
    SELECT 
      SUM(role='donor') AS donor,
      SUM(role='volunteer') AS volunteer,
      SUM(role='organization') AS organization
    FROM users;
  `;

  db.query(sql, (err, result) => {
    if (err) {
      console.error("Error fetching stats:", err);
      return res.status(500).json({ error: "Failed to fetch stats" });
    }
    res.json(result[0]);
  });
});

// Get users by role
app.get("/users", (req, res) => {
  const role = req.query.role;

  if (!role) {
    return res.status(400).json({ message: "Role parameter required" });
  }

  const sql = "SELECT email, name, phone, address, role FROM users WHERE role = ?";
  db.query(sql, [role], (err, result) => {
    if (err) {
      console.error("Error fetching users:", err);
      return res.status(500).json({ error: "Failed to fetch users" });
    }

    res.json(result);
  });
});

app.post("/api/events", (req, res) => {
  const {
    eventId,
    eventTitle,
    eventDesc,
    eventType,
    eventStartDate,
    eventEndDate,
    eventLocation,
    email
  } = req.body;

  if (!eventId || !eventTitle || !email) {
    return res.status(400).send("Missing required fields");
  }

  const sql = `
    INSERT INTO events 
      (event_id, title, description, event_type, start_date, end_date, location, email)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `;

  db.query(
    sql,
    [eventId, eventTitle, eventDesc, eventType, eventStartDate, eventEndDate, eventLocation, email],
    (err) => {
      if (err) {
        console.error(err);
        return res.status(500).send("Error storing event details");
      }
      res.send("Event stored successfully!");
    }
  );
});

app.post("/adm_register", async (req, res) => {
  const { admName } = req.body; // the code entered by admin

  if (!admName) {
    return res.status(400).send("Please enter Admin Code.");
  }

  // Get the stored hashed admin code from the database
  const query = "SELECT code_hash FROM admin_code LIMIT 1";
  db.query(query, async (err, results) => {
    if (err) {
      console.error(err);
      return res.status(500).send("Server error");
    }

    if (results.length === 0) {
      return res.status(500).send("No admin code found in DB.");
    }

    const storedHash = results[0].code_hash;

    try {
      // Compare the entered code with the hashed code
      const isMatch = await bcrypt.compare(admName, storedHash);

      if (isMatch) {
        // ✅ Admin entered the correct code
        return res.send("✅ Admin code verified successfully!");
      } else {
        // ❌ Admin code incorrect
        return res.status(401).send("❌ Wrong Admin Code! Please enter again.");
      }
    } catch (error) {
      console.error(error);
      return res.status(500).send("Error verifying admin code.");
    }
  });
});

app.listen(5000, () => {
  console.log('Server running on port 5000');
});
