const express = require("express");
const sqlite3 = require("sqlite3").verbose();
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");

const app = express();
const PORT = 4000; // tu backend correrá en http://localhost:4000
const SECRET_KEY = "clave_secreta_super_segura"; // cambia esto en producción

app.use(cors());
app.use(express.json());

// ==================== BASE DE DATOS ====================
const db = new sqlite3.Database("./banco.db", (err) => {
  if (err) console.error("Error al abrir la BD", err);
  else console.log("✅ Base de datos conectada");
});

// Crear tablas si no existen
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE,
      password TEXT
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS accounts (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER,
      balance REAL DEFAULT 1000,
      FOREIGN KEY(user_id) REFERENCES users(id)
  )`);
});

// ==================== RUTAS ====================

// Registro
app.post("/register", (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: "Usuario y contraseña requeridos" });
  }

  const hashedPassword = bcrypt.hashSync(password, 10);

  db.run(
    "INSERT INTO users (username, password) VALUES (?, ?)",
    [username, hashedPassword],
    function (err) {
      if (err) {
        return res.status(400).json({ error: "El usuario ya existe" });
      }

      // Crear cuenta con saldo inicial
      db.run("INSERT INTO accounts (user_id, balance) VALUES (?, ?)", [
        this.lastID,
        1000,
      ]);

      res.json({ message: "Usuario registrado correctamente" });
    }
  );
});

// Login
app.post("/login", (req, res) => {
  const { username, password } = req.body;

  db.get("SELECT * FROM users WHERE username = ?", [username], (err, user) => {
    if (!user) return res.status(400).json({ error: "Usuario no encontrado" });

    const isValid = bcrypt.compareSync(password, user.password);
    if (!isValid) return res.status(401).json({ error: "Contraseña incorrecta" });

    const token = jwt.sign({ id: user.id }, SECRET_KEY, { expiresIn: "1h" });

    res.json({ message: "Login exitoso", token });
  });
});

// Middleware para verificar token
function auth(req, res, next) {
  const header = req.headers["authorization"];
  if (!header) return res.status(403).json({ error: "Token requerido" });

  const token = header.split(" ")[1];
  jwt.verify(token, SECRET_KEY, (err, decoded) => {
    if (err) return res.status(403).json({ error: "Token inválido" });
    req.userId = decoded.id;
    next();
  });
}

// Consultar saldo
app.get("/balance", auth, (req, res) => {
  db.get("SELECT balance FROM accounts WHERE user_id = ?", [req.userId], (err, row) => {
    if (err) return res.status(500).json({ error: "Error en la BD" });
    res.json({ balance: row.balance });
  });
});

// ==================== INICIAR SERVIDOR ====================
app.listen(PORT, () => {
  console.log(`🚀 Servidor corriendo en http://localhost:${PORT}`);
});
