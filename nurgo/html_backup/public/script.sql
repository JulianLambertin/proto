-- ============================================
-- SCRIPT SQL - Estructura oficial
-- Base de datos: proyecto
-- ============================================

CREATE DATABASE IF NOT EXISTS proyecto
  CHARACTER SET utf8mb4
  COLLATE utf8mb4_general_ci;

USE proyecto;

-- ============================================
-- TABLA: usuarios
-- ============================================
CREATE TABLE IF NOT EXISTS usuarios (
  id_usuario INT(11) NOT NULL AUTO_INCREMENT,
  nombre VARCHAR(100) NOT NULL,
  email VARCHAR(100) NOT NULL UNIQUE,
  password VARCHAR(255) NOT NULL,
  rol ENUM('ADMIN','PROFESIONAL','SERVICIO_TECNICO') NOT NULL DEFAULT 'PROFESIONAL',
  activo TINYINT(1) DEFAULT 1,
  creado_en TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id_usuario)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ============================================
-- TABLA: pacientes
-- ============================================
CREATE TABLE IF NOT EXISTS pacientes (
  id_paciente INT(11) NOT NULL AUTO_INCREMENT,
  nombre VARCHAR(100) NOT NULL,
  email VARCHAR(100) NOT NULL UNIQUE,
  password VARCHAR(255) NOT NULL,
  PRIMARY KEY (id_paciente)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ============================================
-- TABLA: mediciones
-- ============================================
CREATE TABLE IF NOT EXISTS mediciones (
  id_medicion INT(11) NOT NULL AUTO_INCREMENT,
  id_paciente INT(11) NOT NULL,
  fuerza DECIMAL(10,2) DEFAULT NULL,
  angulacion DECIMAL(10,2) DEFAULT NULL,
  emg DECIMAL(10,2) DEFAULT NULL,
  fecha_medicion TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id_medicion),
  KEY fk_mediciones_paciente (id_paciente),
  CONSTRAINT fk_mediciones_paciente FOREIGN KEY (id_paciente)
    REFERENCES pacientes (id_paciente)
    ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ============================================
-- DATOS DE PRUEBA (opcional)
-- ============================================
/*
INSERT INTO usuarios (nombre, email, password, rol, activo)
VALUES
('Administrador', 'admin@demo.com', '1234', 'ADMIN', 1),
('Profesional Demo', 'prof@demo.com', '1234', 'PROFESIONAL', 1),
('Servicio Técnico', 'tec@demo.com', '1234', 'SERVICIO_TECNICO', 1);

INSERT INTO pacientes (nombre, email, password)
VALUES ('Paciente Demo', 'paciente@demo.com', '1234');

INSERT INTO mediciones (id_paciente, fuerza, angulacion, emg)
VALUES (1, 25.5, 45.3, 0.12);
*/






/*/ tabla de reportes */

CREATE TABLE reportes (
  id INT AUTO_INCREMENT PRIMARY KEY,
  usuario_emisor VARCHAR(100),   -- nombre de quien crea el reporte
  rol_emisor VARCHAR(50),        -- 'Profesional'
  usuario_receptor VARCHAR(100), -- nombre del técnico que responde (puede ser NULL al inicio)
  rol_receptor VARCHAR(50),      -- 'Servicio Técnico'
  tipo VARCHAR(20),              -- 'Sensor' o 'Actuador'
  dispositivo VARCHAR(100),      -- ej: 'Actuador Buzzer'
  descripcion TEXT,
  respuesta TEXT,
  estado ENUM('Pendiente', 'Corregido') DEFAULT 'Pendiente',
  fecha_creacion TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  fecha_respuesta TIMESTAMP NULL
);
