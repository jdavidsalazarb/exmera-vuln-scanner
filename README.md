# EXMERA Web Vulnerability Scanner - Escáner de Vulnerabilidades Web en Python

> **Herramienta Open-Source de Auditoría de Seguridad Web Automatizada y Escaneo Pasivo**  


[![Python Version](https://img.shields.io/badge/Python-3.8%2B-blue.svg?logo=python&logoColor=white)](https://www.python.org/)
[![Security Standard](https://img.shields.io/badge/OWASP-Top%2010%20Coverage-orange.svg)](https://owasp.org/)
[![Status](https://img.shields.io/badge/Status-Active%20%26%20Maintained-brightgreen.svg)]()

---

## 🔍 ¿Qué es EXMERA Vuln Scanner?

**EXMERA Web Vulnerability Scanner** es una herramienta de ciberseguridad open-source escrita en **Python**, diseñada específicamente para realizar escaneos pasivos y auditorías de seguridad web sin levantar sospechas en firewalls (WAF) ni afectar servidores de producción. 

Si buscas un **escáner de vulnerabilidades en Python** que sea rápido, ligero y 100% no invasivo, EXMERA es la solución ideal para analistas de seguridad, pentesters e integraciones en DevSecOps.

Analiza configuraciones de transporte, cabeceras HTTP recomendadas por **OWASP**, descubrimiento pasivo de rutas ocultas, fugas de información, políticas de acceso cross-origin (CORS) y vulnerabilidades conocidas en bibliotecas JavaScript de terceros.

Al finalizar la auditoría, genera un puntaje de seguridad (*Security Score*) ponderado de **0 a 100 (Grados A a F)** y un reporte en formato JSON.

---

## ⚙️ Módulos de Auditoría

La herramienta integra **8 módulos especializados**:

```
┌────────────────────────────────────────────────────────────────────────┐
│               EXMERA WEB VULNERABILITY SCANNER - MÓDULOS               │
├───────────────────┬────────────────────────────────────────────────────┤
│ 1. HTTP Headers   │ Audita HSTS, CSP, X-Frame-Options, Nosniff, etc.   │
│ 2. SSL/TLS        │ Evalúa versiones TLS, ciphers y días de expiración │
│ 3. Files Exposure │ Detecta .git, .env, backups y paneles expuestos    │
│ 4. Cookie Audit   │ Valida flags Secure, HttpOnly y SameSite           │
│ 5. CORS Analysis  │ Detecta comodines (*) y reflexión de orígenes      │
│ 6. HTML Leakage   │ Busca comentarios sensibles, API keys y falta SRI  │
│ 7. JS CVEs        │ Identifica bibliotecas vulnerables (DOMPurify, etc)│
│ 8. Misc & DNS     │ Verifica redirección HTTPS forzada y registros CAA │
└───────────────────┴────────────────────────────────────────────────────┘
```

---

## 🚀 Instalación Rápida

### 1. Clonar el repositorio
```bash
git clone https://github.com/jdavidsalazarb/exmera-vuln-scanner.git
cd exmera-vuln-scanner
```

### 2. Crear un entorno virtual (Recomendado)
```bash
# En Windows (PowerShell):
python -m venv .venv
.\.venv\Scripts\Activate.ps1

# En Linux / macOS:
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Instalar dependencias
```bash
pip install -r requirements.txt
```

---

## 💻 Guía de Uso

### Modo 1: Escaneo directo por línea de comandos
Pasa cualquier URL, dominio o dirección IP:

```bash
# Auditar un sitio web en producción
python exmera_vuln_scanner.py https://tu-sitio.com

# Auditar un entorno local de desarrollo
python exmera_vuln_scanner.py http://localhost:3000
```

### Modo 2: Modo Interactivo
Si ejecutas el script sin argumentos, te solicitará el objetivo en pantalla de forma interactiva:

```bash
python exmera_vuln_scanner.py
```

```text
╔══════════════════════════════════════════════════════════════╗
║             EXMERA Web Vulnerability Scanner                 ║
║       Auditor de Seguridad Web para Cualquier Dominio/Host   ║
║                                                              ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝

🎯 Ingresa la URL o host a auditar (ej: https://mi-sitio.com o localhost:3000):
```

---

## 📊 Ejemplo de Salida en Terminal

```text
╔══════════════════════════════════════════════════════════════╗
║             EXMERA Web Vulnerability Scanner                 ║
║       Auditoría de Seguridad Web Automatizada y Pasiva                          ║
╚══════════════════════════════════════════════════════════════╝

  🎯 Objetivo: https://ejemplo.com
  🕐 Inicio:   2026-10-04 12:00:00
  ⚙️  Módulos:  8 activos

Conectando al objetivo...
  ✓ Conexión exitosa: HTTP 200
  ✓ Tiempo de respuesta: 0.35s

[1/8] 🛡️  Auditando Encabezados de Seguridad HTTP...
  ✓ Strict-Transport-Security: max-age=31536000; includeSubDomains
  ✓ Content-Security-Policy: default-src 'self'...
  ✓ X-Content-Type-Options: nosniff
  ✓ X-Frame-Options: DENY
  ✓ Referrer-Policy: strict-origin-when-cross-origin

[2/8] 🔒 Auditando Configuración SSL/TLS...
  ✓ Protocolo: TLSv1.3
  ✓ Cipher Suite: TLS_AES_256_GCM_SHA384
  ✓ Protocolo seguro confirmado

═════════════════════════════════════════════════════════════════
  CALIFICACIÓN DE SEGURIDAD: A (95/100)
═════════════════════════════════════════════════════════════════
```

---

## 📄 Reporte JSON Generado

Cada ejecución guarda un archivo `audit_report_YYYYMMDD_HHMMSS.json` con la información detallada de cada hallazgo:

```json
{
  "metadata": {
    "tool": "EXMERA Web Vulnerability Scanner",
    "target": "https://ejemplo.com",
    "timestamp": "2026-10-04T12:00:15.123456",
    "duration_seconds": 1.4,
    "total_findings": 0,
    "score": 100,
    "grade": "A"
  },
  "summary": {
    "CRITICAL": 0,
    "HIGH": 0,
    "MEDIUM": 0,
    "LOW": 0,
    "INFO": 0
  },
  "findings": []
}
```

---


> **Aviso de Responsabilidad:** Esta herramienta fue creada exclusivamente con fines educativos, de auditoría defensiva y de fortalecimiento de postura de seguridad. El autor no se hace responsable del uso indebido fuera de entornos autorizados.

---

### 👤 Autor
* **Juan David Salazar**  
  GitHub: [@jdavidsalazarb](https://github.com/jdavidsalazarb)
