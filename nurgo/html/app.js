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
  const valor = parseFloat(message.toString());
  if (isNaN(valor)) return;

  switch (topic) {
    case "esp32_peso":
      lastData.fuerza = valor;
      break;
    case "esp32_angulacion":
      lastData.angulo = valor;
      break;
    case "esp32_emg":
      lastData.emg = valor;
      break;
    case "esp32_rele":
      releEstado = valor;
      break;
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
// ------------------- SESIÓN ACTUAL (MODIFICADA) -------------------
app.get("/session", (req, res) => {
  if (req.session && req.session.user) {
    const sessionData = req.session.user;

    res.json({
      id_usuario: sessionData.id_usuario,
      email: sessionData.email,
      rol: sessionData.rol,
      nombre: sessionData.nombre
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

  const sql = "SELECT * FROM pacientes WHERE email = ?";
  db.query(sql, [email], async (err, results) => {
    if (err) return res.redirect("/medicine.html?error=db");
    if (results.length === 0)
      return res.redirect("/medicine.html?error=credenciales");

    const paciente = results[0];

    // ✅ Comparar contraseña hasheada
    const passwordCorrecta = await bcrypt.compare(password, paciente.password);

    if (!passwordCorrecta)
      return res.redirect("/medicine.html?error=credenciales");

    // ✅ Guardar sesión
    req.session.user = {
      id_usuario: paciente.id_paciente, // Usar id_paciente como id_usuario para consistencia
      nombre: paciente.nombre,
      email: paciente.email,
      rol: "PACIENTE"
    };

    return res.redirect("/health.html");
  });
});

// ------------------- LOGIN ROLES -------------------
app.post("/login-rol", (req, res) => {
  const { email, password } = req.body;
  // La columna 'activo' es crucial para seguridad
  const sql =
    "SELECT id_usuario, nombre, email, rol, activo FROM usuarios WHERE email=? AND password=? AND activo=1";
  db.query(sql, [email, password], (err, results) => {
    if (err) return res.status(500).send("Error en servidor");
    if (results.length === 0)
      return res.redirect("/login_rol.html?error=credenciales");

    const user = results[0];
    user.rol = (user.rol || "").trim().toUpperCase();

    // Regenerar la sesión para seguridad
    req.session.regenerate((err) => {
      if (err) return res.status(500).send("Error de sesión");

      req.session.user = user;

      req.session.save((err) => {
        if (err) return res.status(500).send("Error de sesión");

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
    "SELECT id_usuario, nombre, email, rol FROM usuarios WHERE activo=1",
    (err, results) => {
      if (err) return res.status(500).send("Error DB");
      res.json(results);
    }
  );
});
// ------------------- API REPORTES (USANDO SOLO usuario_emisor) -------------------
app.get("/api/reportes", verifyToken(["PROFESIONAL", "SERVICIO_TECNICO", "ADMIN"]),
  (req, res) => {
    const rol = req.session.user.rol.trim().toUpperCase();
    const nombreUsuario = req.session.user.nombre;

    let sql = "SELECT * FROM reportes";
    let params = [];

    if (rol === "PROFESIONAL") {
      // Filtra por el nombre del usuario emisor
      sql += " WHERE usuario_emisor = ? ORDER BY fecha_creacion DESC";
      params = [nombreUsuario];
    } else {
      // Técnico y Admin ven todos
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

// Crear un reporte (USANDO SOLO usuario_emisor)
app.post("/api/reportes", verifyToken(["PROFESIONAL"]), (req, res) => {
  const { tipo, dispositivo, descripcion } = req.body;
  const nombreUsuario = req.session.user.nombre;
  const rolUsuario = req.session.user.rol;

  if (!tipo || !dispositivo || !descripcion)
    return res.status(400).send("Faltan campos obligatorios");

  // Solo usamos las columnas que existen
  const sql = `INSERT INTO reportes (usuario_emisor, rol_emisor, tipo, dispositivo, descripcion, estado, fecha_creacion)
                VALUES (?, ?, ?, ?, ?, 'Pendiente', NOW())`;

  db.query(sql, [nombreUsuario, rolUsuario, tipo, dispositivo, descripcion], (err) => {
    if (err) {
      console.error("Error al crear el reporte:", err);
      return res.status(500).send("Error al crear el reporte");
    }
    res.json({ message: "Reporte creado correctamente" });
  });
});

// Corregir reporte (mantenemos la lógica original para Técnico)
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
    res.json({ message: "Reporte corregido y respuesta guardada" });
  });
});

// ------------------- API MEDICIONES (Segura y Optimizada) -------------------
// Obtener mediciones del paciente. Solo para PROFESIONAL
app.get("/api/mediciones/paciente/:id", verifyToken(["PROFESIONAL"]), (req, res) => {
  const pacienteId = req.params.id;
  const profesionalId = req.session.user.id_usuario; // ID del profesional logueado

  // 1. Búsqueda principal: Usa JOIN para asegurar que el paciente pertenezca al profesional
  const sqlMediciones = `
        SELECT m.id_medicion, m.fuerza, m.angulacion, m.emg, m.fecha_medicion
        FROM mediciones m
        JOIN pacientes p ON m.id_paciente = p.id_paciente
        WHERE m.id_paciente = ? AND p.profesional_id = ?
        ORDER BY m.fecha_medicion DESC
    `;

  db.query(sqlMediciones, [pacienteId, profesionalId], (err, results) => {
    if (err) {
      console.error("Error al obtener mediciones con JOIN:", err);
      return res.status(500).send("Error en la base de datos");
    }

    if (results.length > 0) {
      return res.json(results);
    }

    // 2. Si no hay resultados, verificamos si es un intento de IDOR (o paciente sin mediciones)
    const sqlVerificacion = "SELECT id_paciente FROM pacientes WHERE id_paciente = ? AND profesional_id = ?";

    db.query(sqlVerificacion, [pacienteId, profesionalId], (errCheck, checkResult) => {
      if (errCheck) {
        console.error("Error de verificación:", errCheck);
        return res.status(500).send("Error en la base de datos");
      }

      if (checkResult.length === 0) {
        // Caso B: Paciente NO asignado. Es un intento de IDOR. Devolvemos 403.
        return res.status(403).send("No tienes permiso para ver a este paciente.");
      }

      // Caso C: Paciente asignado, pero sin mediciones. Devolvemos array vacío [].
      res.json([]);
    });
  });
});

// Obtener mediciones del paciente. Solo para PACIENTE logueado
app.get("/api/mediciones/mihistorial/:id", verifyToken(["PACIENTE"]), (req, res) => {
  const pacienteId = req.params.id;
  const sessionId = req.session.user.id_usuario; // ID del paciente logueado

  // Seguridad: Asegurar que el ID solicitado es el mismo que el de la sesión
  if (Number(pacienteId) !== Number(sessionId)) {
    return res.status(403).send("No tienes permiso para ver el historial de otro paciente.");
  }

  const sqlMediciones = `
        SELECT id_medicion, fuerza, angulacion, emg, fecha_medicion
        FROM mediciones
        WHERE id_paciente = ?
        ORDER BY fecha_medicion DESC
    `;

  db.query(sqlMediciones, [pacienteId], (err, results) => {
    if (err) {
      console.error("Error al obtener mediciones del paciente:", err);
      return res.status(500).send("Error en la base de datos");
    }
    res.json(results);
  });
});

// Registrar medición (Desde ESP32)
app.post("/api/medicion", (req, res) => {
  const { paciente_id, fuerza, angulacion, emg } = req.body;

  if (!paciente_id || fuerza === undefined || angulacion === undefined || emg === undefined) {
    return res.status(400).send("Faltan parámetros de medición");
  }

  const sql = `INSERT INTO mediciones (id_paciente, fuerza, angulacion, emg, fecha_medicion)
                 VALUES (?, ?, ?, ?, NOW())`;

  db.query(sql, [paciente_id, fuerza, angulacion, emg], (err) => {
    if (err) {
      console.error("Error al registrar medición:", err);
      return res.status(500).send("Error al guardar medición en DB");
    }
    res.send("Medición registrada");
  });
});

// API para Guardar Mediciones (desde health.html)
app.post("/api/guardar-mediciones", verifyToken(["PACIENTE"]), async (req, res) => {
  const pacienteId = req.session.user.id_usuario;
  const mediciones = req.body.mediciones; // Array de objetos {fuerza, angulacion, emg}

  if (!mediciones || !Array.isArray(mediciones) || mediciones.length === 0) {
    return res.status(400).json({ error: "No se proporcionaron mediciones válidas." });
  }

  // Preparar valores para inserción múltiple
  const values = mediciones.map(m => [
    pacienteId,
    m.fuerza,
    m.angulacion,
    m.emg,
    new Date().toISOString().slice(0, 19).replace('T', ' ') // Usar la hora de recepción
  ]);

  const sql = `INSERT INTO mediciones (id_paciente, fuerza, angulacion, emg, fecha_medicion) VALUES ?`;

  db.query(sql, [values], (err, result) => {
    if (err) {
      console.error("Error al guardar el lote de mediciones:", err);
      return res.status(500).json({ error: "Error de servidor al guardar mediciones." });
    }
    res.json({ message: `Lote de ${result.affectedRows} mediciones guardadas correctamente.` });
  });
});
// ------------------- API PACIENTES -------------------
// Obtener pacientes asignados al profesional logueado
app.get("/api/pacientes", verifyToken(["PROFESIONAL"]), (req, res) => {
  const profesionalId = req.session.user.id_usuario;
  const sql = "SELECT id_paciente, nombre, email FROM pacientes WHERE profesional_id = ?";
  db.query(sql, [profesionalId], (err, results) => {
    if (err) return res.status(500).send("Error DB");
    res.json(results);
  });
});

// Obtener nombre del paciente (para mediciones.html)
app.get("/api/pacientes/:id/nombre", verifyToken(["PROFESIONAL"]), (req, res) => {
  const pacienteId = req.params.id;
  const profesionalId = req.session.user.id_usuario;

  // Solo busca si el paciente está asignado a este profesional
  const sql = "SELECT nombre FROM pacientes WHERE id_paciente = ? AND profesional_id = ?";
  db.query(sql, [pacienteId, profesionalId], (err, results) => {
    if (err) {
      console.error("Error al obtener nombre:", err);
      return res.status(500).send("Error DB");
    }
    if (results.length === 0) {
      return res.status(404).send("Paciente no encontrado o no asignado");
    }
    res.json({ nombre: results[0].nombre });
  });
});

// Crear Paciente
app.post("/api/pacientes", verifyToken(["PROFESIONAL"]), async (req, res) => {
  const { nombre, email, password } = req.body;
  const profesionalId = req.session.user.id_usuario;

  if (!nombre || !email || !password) {
    return res.status(400).json({ error: "Faltan datos requeridos." });
  }

  try {
    // 1. Hash de la contraseña
    const hashedPassword = await bcrypt.hash(password, 10);

    // 2. Insertar paciente
    const sql = "INSERT INTO pacientes (nombre, email, password, profesional_id) VALUES (?, ?, ?, ?)";
    db.query(sql, [nombre, email, hashedPassword, profesionalId], (err, result) => {
      if (err) {
        if (err.code === 'ER_DUP_ENTRY') {
          return res.status(409).json({ error: "El email ya está registrado." });
        }
        console.error("Error al crear paciente:", err);
        return res.status(500).json({ error: "Error de servidor al crear paciente." });
      }
      res.status(201).json({ message: "Paciente creado correctamente", id: result.insertId });
    });
  } catch (e) {
    console.error("Error al hashear contraseña:", e);
    res.status(500).json({ error: "Error interno de servidor." });
  }
});

// Eliminar Paciente
app.delete("/api/pacientes/:id", verifyToken(["PROFESIONAL"]), (req, res) => {
  const pacienteId = req.params.id;
  const profesionalId = req.session.user.id_usuario;

  // Solo permite eliminar si el paciente está asignado a este profesional
  const sql = "DELETE FROM pacientes WHERE id_paciente = ? AND profesional_id = ?";
  db.query(sql, [pacienteId, profesionalId], (err, result) => {
    if (err) return res.status(500).send("Error DB");
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: "Paciente no encontrado o no asignado." });
    }
    res.send("Paciente eliminado");
  });
});

// Editar Paciente
app.put("/api/pacientes/:id", verifyToken(["PROFESIONAL"]), async (req, res) => {
  const pacienteId = req.params.id;
  const profesionalId = req.session.user.id_usuario;
  const { nombre, email, password } = req.body;

  let updateFields = [];
  let params = [];

  if (nombre) {
    updateFields.push("nombre = ?");
    params.push(nombre);
  }
  if (email) {
    updateFields.push("email = ?");
    params.push(email);
  }
  if (password && password.trim() !== "") {
    try {
      const hashedPassword = await bcrypt.hash(password.trim(), 10);
      updateFields.push("password = ?");
      params.push(hashedPassword);
    } catch (e) {
      return res.status(500).json({ error: "Error al hashear la nueva contraseña." });
    }
  }

  if (updateFields.length === 0) {
    return res.status(400).json({ error: "No hay campos para actualizar." });
  }

  params.push(pacienteId);
  params.push(profesionalId);

  // Solo permite editar si el paciente está asignado a este profesional
  const sql = `UPDATE pacientes SET ${updateFields.join(", ")} WHERE id_paciente = ? AND profesional_id = ?`;

  db.query(sql, params, (err, result) => {
    if (err) {
      if (err.code === 'ER_DUP_ENTRY') {
        return res.status(409).json({ error: "El email ya está registrado por otro usuario." });
      }
      console.error("Error al editar paciente:", err);
      return res.status(500).json({ error: "Error de servidor al editar paciente." });
    }
    if (result.affectedRows === 0 && result.changedRows === 0) {
      // Si el paciente existe pero no le pertenece al profesional, también devuelve 404/403
      return res.status(404).json({ error: "Paciente no encontrado o no asignado." });
    }
    res.send("Paciente actualizado");
  });
});
// ------------------- API ACTUADORES -------------------
app.post("/api/actuador/:nombre", verifyToken(["SERVICIO_TECNICO"]), (req, res) => {
  const { nombre } = req.params;
  const { estado } = req.body; // true = encender, false = apagar
  let comando = null;

  // Mapeo de actuadores a comandos numéricos
  if (nombre === "relay") comando = estado ? 1 : 2;
  else if (nombre === "buzzer") comando = estado ? 3 : 4;
  else if (nombre === "motor") comando = estado ? 5 : 6;

  if (comando === null)
    return res.status(400).send("Actuador no reconocido");

  try {
    mqttClient.publish("esp32_rele", comando.toString());
    console.log(`⚙️ Enviado comando MQTT ${comando} (${nombre} -> ${estado ? "ON" : "OFF"})`);
    res.send("Comando enviado");
  } catch (err) {
    console.error("Error enviando comando MQTT:", err);
    res.status(500).send("Error publicando comando MQTT");
  }
});



// ------------------- INICIO DE SERVIDOR -------------------
server.listen(PORT, () => {
  console.log(`🚀 Servidor en http://localhost:${PORT}`);
});