// app.js
const express = require("express");
const path = require("path");
const mqtt = require("mqtt");
const http = require("http");
const ejs = require("ejs");
const mysql = require("mysql");
const session = require("express-session");
const MySQLStore = require("express-mysql-session")(session);
const bodyParser = require("body-parser");

const app = express();
const server = http.createServer(app);
const io = require("socket.io")(server);
const PORT = 3001;

// ------------------- MYSQL -------------------
const db = mysql.createConnection({
  host: "localhost",
  user: "root",
  password: "",
  database: "proyecto",
});

db.connect((err) => {
  if (err) console.error("❌ Error al conectar a MySQL:", err);
  else console.log("✔️ Conectado a MySQL");
});

// ------------------- SESIONES PERSISTENTES -------------------
const sessionStore = new MySQLStore(
  {
    expiration: 7 * 24 * 60 * 60 * 1000, // 7 días
    createDatabaseTable: true,
  },
  db
);

app.use(
  session({
    key: "user_sid",
    secret: "clave_ultra_segura_persistente",
    store: sessionStore,
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 7 * 24 * 60 * 60 * 1000 },
  })
);

// ------------------- MIDDLEWARE -------------------
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

// ------------------- RUTAS ESTÁTICAS -------------------
app.use(express.static(path.join(__dirname, "public")));
app.use("/views", express.static(path.join(__dirname, "views")));
app.use("/protected", express.static(path.join(__dirname, "protected")));

// ------------------- MOTOR DE VISTAS -------------------
app.set("views", path.join(__dirname, "views"));
app.engine("html", ejs.renderFile);
app.set("view engine", "html");

// ------------------- MQTT + SOCKET.IO -------------------
const mqttClient = mqtt.connect("mqtt://broker.emqx.io:1883");

let lastData = { fuerza: 0, angulo: 0, emg: 0, tiempo: new Date() };
let releEstado = 0;
let calibOffsets = { fuerza: 0, angulo: 0, emg: 0 };

mqttClient.on("connect", () => {
  console.log("📡 Conectado a EMQX (mqtt)");
  mqttClient.subscribe(
    ["esp32_peso", "esp32_angulacion", "esp32_emg", "esp32_rele"],
    (err) => {
      if (!err) console.log("✔️ Suscrito a tópicos MQTT");
    }
  );
});

mqttClient.on("message", (topic, message) => {
  try {
    const payload = JSON.parse(message.toString());
    if (topic === "esp32_peso" && typeof payload.peso === "number")
      lastData.fuerza = payload.peso - (calibOffsets.fuerza || 0);
    if (topic === "esp32_angulacion" && typeof payload.angX === "number")
      lastData.angulo = payload.angX - (calibOffsets.angulo || 0);
    if (topic === "esp32_emg" && typeof payload.emg === "number")
      lastData.emg = payload.emg - (calibOffsets.emg || 0);
    if (topic === "esp32_rele" && typeof payload.estado === "number")
      releEstado = payload.estado;
  } catch (e) {
    console.error("❌ Error parseando MQTT message:", e.message);
  }
  lastData.tiempo = new Date().toLocaleTimeString();
  io.emit("datos_mqtt", { ...lastData, rele: releEstado });
});

io.on("connection", (socket) => {
  console.log("🔌 Cliente socket conectado:", socket.id);
  socket.emit("datos_mqtt", { ...lastData, rele: releEstado });
});

// ------------------- HELPER DE SESIÓN -------------------
function verifyToken(roles) {
  return (req, res, next) => {
    if (req.session && req.session.user) {
      const rolSesion = req.session.user.rol.trim().toUpperCase();
      const rolesPermitidos = roles.map((r) => r.trim().toUpperCase());
      if (rolesPermitidos.includes(rolSesion)) return next();
    }
    return res.status(403).send("Acceso denegado o sesión expirada");
  };
}

// ------------------- SESIÓN ACTUAL -------------------
app.get("/session", (req, res) => {
  if (req.session && req.session.user) {
    res.json({ email: req.session.user.email, rol: req.session.user.rol, nombre: req.session.user.nombre });
  } else {
    res.status(403).send("No hay sesión válida");
  }
});

// ------------------- RUTAS PRINCIPALES -------------------
app.get("/", (req, res) => res.redirect("/index.html"));
app.get("/login_rol.html", (req, res) => res.sendFile(path.join(__dirname, "views/login_rol.html")));
app.get("/index.html", (req, res) => res.sendFile(path.join(__dirname, "views/index.html")));
app.get("/health.html", (req, res) => res.sendFile(path.join(__dirname, "views/health.html")));
app.get("/medicine.html", (req, res) => res.sendFile(path.join(__dirname, "views/medicine.html")));
app.get("/mediciones.html", (req, res) => res.sendFile(path.join(__dirname, "views/mediciones.html")));

// ------------------- LOGIN PACIENTE -------------------
app.post("/login-paciente", (req, res) => {
  const { email, password } = req.body;
  const sql = "SELECT * FROM pacientes WHERE email = ? AND password = ?";
  db.query(sql, [email, password], (err, results) => {
    if (err) return res.redirect("/medicine.html?error=db");
    if (results.length > 0) {
      const paciente = results[0];
      req.session.userId = paciente.id;
      req.session.nombre = paciente.nombre;
      req.session.email = paciente.email;
      req.session.tipo = "PACIENTE";
      res.redirect("/health.html");
    } else {
      res.redirect("/medicine.html?error=credenciales");
    }
  });
});

// ------------------- LOGIN ROLES -------------------
app.post("/login-rol", (req, res) => {
  const { email, password } = req.body;
  const sql = "SELECT * FROM usuarios WHERE email=? AND password=? AND activo=1";
  db.query(sql, [email, password], (err, results) => {
    if (err) return res.status(500).send("Error en servidor");
    if (results.length === 0) return res.redirect("/login_rol.html?error=credenciales");

    const user = results[0];
    user.rol = (user.rol || "").trim().toUpperCase();
    req.session.user = user;

    switch (user.rol) {
      case "ADMIN":
        return res.redirect("/protected/dashboard_admin.html");
      case "PROFESIONAL":
        return res.redirect("/protected/dashboard_profesional.html");
      case "SERVICIO_TECNICO":
        return res.redirect("/protected/dashboard_tecnico.html");
      default:
        return res.redirect("/login_rol.html");
    }
  });
});

// ------------------- LOGOUT -------------------
app.get("/logout", (req, res) => {
  req.session.destroy(() => res.redirect("/login_rol.html"));
});

// ------------------- DASHBOARDS -------------------
app.get("/protected/dashboard_admin.html", verifyToken(["ADMIN"]), (req, res) =>
  res.sendFile(path.join(__dirname, "protected/dashboard_admin.html"))
);
app.get("/protected/dashboard_profesional.html", verifyToken(["PROFESIONAL"]), (req, res) =>
  res.sendFile(path.join(__dirname, "protected/dashboard_profesional.html"))
);
app.get("/protected/dashboard_tecnico.html", verifyToken(["SERVICIO_TECNICO"]), (req, res) =>
  res.sendFile(path.join(__dirname, "protected/dashboard_tecnico.html"))
);

// ------------------- API USUARIOS -------------------
app.get("/api/usuarios", verifyToken(["ADMIN", "PROFESIONAL"]), (req, res) => {
  db.query("SELECT id_usuario AS id, nombre, email, rol FROM usuarios WHERE activo=1", (err, results) => {
    if (err) return res.status(500).send("Error DB");
    res.json(results);
  });
});

app.post("/api/usuarios", verifyToken(["ADMIN"]), (req, res) => {
  const { nombre, email, password, rol } = req.body;
  if (!nombre || !email || !password || !rol) return res.status(400).send("Faltan datos");

  db.query("SELECT * FROM usuarios WHERE email=?", [email], (err, results) => {
    if (err) return res.status(500).send("Error DB");
    if (results.length > 0) return res.status(400).send("Correo ya registrado");

    db.query(
      "INSERT INTO usuarios (nombre, email, password, rol, activo, creado_en) VALUES (?, ?, ?, ?, 1, NOW())",
      [nombre, email, password, rol],
      (errInsert) => {
        if (errInsert) return res.status(500).send("Error creando usuario");
        res.send("Usuario creado");
      }
    );
  });
});

app.put("/api/usuarios/:id", verifyToken(["ADMIN"]), (req, res) => {
  const { nombre, email, rol } = req.body;
  const id = req.params.id;

  if (req.session.user.email === email) return res.status(403).send("No puedes modificar tu propia cuenta");

  db.query("UPDATE usuarios SET nombre=?, email=?, rol=? WHERE id_usuario=?", [nombre, email, rol, id], (err) => {
    if (err) return res.status(500).send("Error actualizando usuario");
    res.send("Usuario actualizado");
  });
});

app.delete("/api/usuarios/:id", verifyToken(["ADMIN"]), (req, res) => {
  const id = req.params.id;

  db.query("SELECT email FROM usuarios WHERE id_usuario=?", [id], (err, result) => {
    if (err) return res.status(500).send("Error DB");
    if (result.length && result[0].email === req.session.user.email) return res.status(403).send("No puedes eliminar tu propia cuenta");

    db.query("DELETE FROM usuarios WHERE id_usuario=?", [id], (errDel) => {
      if (errDel) return res.status(500).send("Error eliminando usuario");
      res.send("Usuario eliminado");
    });
  });
});

// ------------------- API REPORTES -------------------

// Listar reportes según rol
app.get("/api/reportes", verifyToken(["PROFESIONAL", "SERVICIO_TECNICO", "ADMIN"]), (req, res) => {
  const rol = req.session.user.rol.trim().toUpperCase();
  const nombreUsuario = req.session.user.nombre;
  let sql = "SELECT * FROM reportes";
  let params = [];

  if (rol === "PROFESIONAL") {
    sql += " WHERE usuario_emisor = ? AND rol_emisor = 'PROFESIONAL' ORDER BY fecha_creacion DESC";
    params = [nombreUsuario];
  } else if (rol === "SERVICIO_TECNICO") {
    sql += " WHERE estado = 'Pendiente' ORDER BY fecha_creacion ASC";
  } else {
    sql += " ORDER BY fecha_creacion DESC"; // Admin
  }

  db.query(sql, params, (err, results) => {
    if (err) return res.status(500).send("Error al obtener reportes");
    res.json(results);
  });
});

// Crear un reporte (solo profesional)
app.post("/api/reportes", verifyToken(["PROFESIONAL"]), (req, res) => {
  const { tipo, dispositivo, descripcion } = req.body;
  const nombreUsuario = req.session.user.nombre;
  const rolUsuario = req.session.user.rol;

  if (!tipo || !dispositivo || !descripcion) return res.status(400).send("Faltan campos obligatorios");

  const sql = `INSERT INTO reportes (usuario_emisor, rol_emisor, tipo, dispositivo, descripcion, estado)
               VALUES (?, ?, ?, ?, ?, 'Pendiente')`;

  db.query(sql, [nombreUsuario, rolUsuario, tipo, dispositivo, descripcion], (err) => {
    if (err) return res.status(500).send("Error al crear el reporte");
    res.send("Reporte creado correctamente");
  });
});

// Responder reporte (solo servicio técnico)
app.put("/api/reportes/:id", verifyToken(["SERVICIO_TECNICO"]), (req, res) => {
  const { respuesta, estado } = req.body;
  const nombreUsuario = req.session.user.nombre;
  const rolUsuario = req.session.user.rol;
  const id = req.params.id;

  const sql = `UPDATE reportes
               SET usuario_receptor = ?, rol_receptor = ?, respuesta = ?, estado = ?, fecha_respuesta = NOW()
               WHERE id = ? AND estado = 'Pendiente'`;

  db.query(sql, [nombreUsuario, rolUsuario, respuesta, estado || "Corregido", id], (err, result) => {
    if (err) return res.status(500).send("Error al actualizar reporte");
    if (result.affectedRows === 0) return res.status(404).send("Reporte no encontrado o ya corregido");
    res.send("Reporte actualizado correctamente");
  });
});

// ------------------- INICIO SERVIDOR -------------------
server.listen(PORT, () => {
  console.log(`🚀 Servidor corriendo en http://localhost:${PORT}`);
});
