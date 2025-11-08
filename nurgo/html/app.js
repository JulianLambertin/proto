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
const bcrypt = require("bcryptjs"); // ✅ IMPORTANTE
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
// ------------------ MQTT + SOCKET.IO -------------------
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
    res.json({
      email: req.session.user.email,
      rol: req.session.user.rol,
      nombre: req.session.user.nombre,
    });
  } else {
    res.status(403).send("No hay sesión válida");
  }
});
// ------------------- RUTAS PRINCIPALES -------------------
app.get("/", (req, res) => res.redirect("/index.html"));
app.get("/login_rol.html", (req, res) =>
  res.sendFile(path.join(__dirname, "views/login_rol.html"))
);
app.get("/index.html", (req, res) =>
  res.sendFile(path.join(__dirname, "views/index.html"))
);
app.get("/health.html", (req, res) =>
  res.sendFile(path.join(__dirname, "views/health.html"))
);
app.get("/medicine.html", (req, res) =>
  res.sendFile(path.join(__dirname, "views/medicine.html"))
);
app.get("/mediciones.html", (req, res) =>
  res.sendFile(path.join(__dirname, "views/mediciones.html"))
);
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
  const sql =
    "SELECT * FROM usuarios WHERE email=? AND password=? AND activo=1";
  db.query(sql, [email, password], (err, results) => {
    if (err) return res.status(500).send("Error en servidor");
    if (results.length === 0)
      return res.redirect("/login_rol.html?error=credenciales");
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
app.get(
  "/protected/dashboard_admin.html",
  verifyToken(["ADMIN"]),
  (req, res) =>
    res.sendFile(path.join(__dirname, "protected/dashboard_admin.html"))
);
app.get(
  "/protected/dashboard_profesional.html",
  verifyToken(["PROFESIONAL"]),
  (req, res) =>
    res.sendFile(path.join(__dirname, "protected/dashboard_profesional.html"))
);
app.get(
  "/protected/dashboard_tecnico.html",
  verifyToken(["SERVICIO_TECNICO"]),
  (req, res) =>
    res.sendFile(path.join(__dirname, "protected/dashboard_tecnico.html"))
);
// ------------------- API USUARIOS -------------------
app.get("/api/usuarios", verifyToken(["ADMIN", "PROFESIONAL"]), (req, res) => {
  db.query(
    "SELECT id_usuario AS id, nombre, email, rol FROM usuarios WHERE activo=1",
    (err, results) => {
      if (err) return res.status(500).send("Error DB");
      res.json(results);
    }
  );
});
// ------------------- API REPORTES -------------------
// ------------------- API REPORTES -------------------
app.get("/api/reportes", verifyToken(["PROFESIONAL", "SERVICIO_TECNICO", "ADMIN"]),
  (req, res) => {
    const rol = req.session.user.rol.trim().toUpperCase();
    const nombreUsuario = req.session.user.nombre;
    let sql = "SELECT * FROM reportes";
    let params = [];

    if (rol === "PROFESIONAL") {
      // El profesional solo ve los reportes que él emitió
      sql +=
        " WHERE usuario_emisor = ? AND rol_emisor = 'PROFESIONAL' ORDER BY fecha_creacion DESC";
      params = [nombreUsuario];
    } else if (rol === "SERVICIO_TECNICO") {
      // El técnico debe ver TODOS los reportes (pendientes y corregidos)
      // El filtrado a Pendientes y Corregidos se hará en el frontend.
      sql += " ORDER BY fecha_creacion DESC"; // <-- CORREGIDO: Trae todos
    } else {
      // Admin ve todos
      sql += " ORDER BY fecha_creacion DESC";
    }

    db.query(sql, params, (err, results) => {
      if (err) {
        console.error("❌ Error al obtener reportes:", err);
        return res.status(500).send("Error al obtener reportes");
      }
      res.json(results);
    });
  }
);
// Crear un reporte
app.post("/api/reportes", verifyToken(["PROFESIONAL"]), (req, res) => {
  const { tipo, dispositivo, descripcion } = req.body;
  const nombreUsuario = req.session.user.nombre;
  const rolUsuario = req.session.user.rol;
  if (!tipo || !dispositivo || !descripcion)
    return res.status(400).send("Faltan campos obligatorios");
  const sql = `INSERT INTO reportes (usuario_emisor, rol_emisor, tipo, dispositivo, descripcion, estado)
               VALUES (?, ?, ?, ?, ?, 'Pendiente')`;
  db.query(sql, [nombreUsuario, rolUsuario, tipo, dispositivo, descripcion], (err) => {
    if (err) return res.status(500).send("Error al crear el reporte");
    res.send("Reporte creado correctamente");
  });
});
// Cambiar estado del reporte
// Corregir reporte (guardar respuesta + marcar como corregido)
app.put("/api/reportes/:id/corregir", verifyToken(["SERVICIO_TECNICO"]), (req, res) => {
  const id = Number(req.params.id);
  const { respuesta } = req.body;
  if (!respuesta || !respuesta.trim()) {
    return res.status(400).send("Respuesta requerida");
  }

  const tecnicoNombre = req.session.user.nombre;
  const tecnicoRol = req.session.user.rol;

  const sql = `
    UPDATE reportes
    SET estado = 'Corregido',
        respuesta = ?,
        usuario_receptor = ?,
        rol_receptor = ?,
        fecha_respuesta = NOW()
    WHERE id = ?
  `;

  db.query(sql, [respuesta.trim(), tecnicoNombre, tecnicoRol, id], (err, result) => {
    if (err) {
      console.error("❌ Error al corregir reporte:", err);
      return res.status(500).send("Error al corregir reporte");
    }
    if (result.affectedRows === 0) {
      return res.status(404).send("Reporte no encontrado");
    }
    res.send("Reporte corregido y respuesta guardada");
  });
});




// ------------------- API PACIENTES -------------------
// Obtener pacientes del profesional logueado
app.get("/api/pacientes", verifyToken(["PROFESIONAL"]), (req, res) => {
  const profesionalId = req.session.user.id_usuario;
  const sql = "SELECT id_paciente, nombre, email FROM pacientes WHERE profesional_id = ?";
  db.query(sql, [profesionalId], (err, results) => {
    if (err) return res.status(500).json({ error: "Error al obtener pacientes" });
    res.json(results);
  });
});





// Crear paciente
app.post("/api/pacientes", verifyToken(["PROFESIONAL"]), (req, res) => {
  const { nombre, email, password } = req.body;
  const profesionalId = req.session.user.id_usuario; // ✅ usar el id del profesional
  if (!nombre || !email || !password)
    return res.status(400).send("Faltan campos obligatorios");

  const hashed = bcrypt.hashSync(password, 10);
  const sql = `INSERT INTO pacientes (nombre, email, password, profesional_id)
               VALUES (?, ?, ?, ?)`;
  db.query(sql, [nombre, email, hashed, profesionalId], (err) => {
    if (err) {
      console.error("❌ Error al crear paciente:", err);
      return res.status(500).send("Error al crear paciente");
    }
    res.json({ message: "✅ Paciente creado correctamente" });
  });
});

// Actualizar paciente
app.put("/api/pacientes/:id", verifyToken(["PROFESIONAL"]), (req, res) => {
  const id = req.params.id;
  const { nombre, email, password } = req.body;
  const profesionalId = req.session.user.id_usuario;

  let sql, params;
  if (password) {
    const hashed = bcrypt.hashSync(password, 10);
    sql = `UPDATE pacientes SET nombre=?, email=?, password=? 
           WHERE id_paciente=? AND profesional_id=?`;
    params = [nombre, email, hashed, id, profesionalId];
  } else {
    sql = `UPDATE pacientes SET nombre=?, email=? 
           WHERE id_paciente=? AND profesional_id=?`;
    params = [nombre, email, id, profesionalId];
  }

  db.query(sql, params, (err, result) => {
    if (err) return res.status(500).json({ error: "Error al actualizar paciente" });
    if (result.affectedRows === 0)
      return res.status(404).json({ error: "Paciente no encontrado" });
    res.json({ message: "Paciente actualizado correctamente" });
  });
});

// Eliminar paciente
app.delete("/api/pacientes/:id", verifyToken(["PROFESIONAL"]), (req, res) => {
  const id = req.params.id;
  const profesionalId = req.session.user.id_usuario; // ✅ usar id, no nombre

  const sql = "DELETE FROM pacientes WHERE id_paciente=? AND profesional_id=?";
  db.query(sql, [id, profesionalId], (err, result) => {
    if (err) {
      console.error("❌ Error al eliminar paciente:", err);
      return res.status(500).json({ error: "Error al eliminar paciente" });
    }
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: "Paciente no encontrado" });
    }
    res.json({ message: "Paciente eliminado correctamente" });
  });
});

// ------------------- INICIO SERVIDOR -------------------
server.listen(PORT, () => {
  console.log(`🚀 Servidor corriendo en http://localhost:${PORT}`);
});
