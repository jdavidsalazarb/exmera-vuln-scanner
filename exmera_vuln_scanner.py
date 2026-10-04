#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
╔══════════════════════════════════════════════════════════════╗
║             EXMERA Web Vulnerability Scanner                 ║
║       Auditor de Seguridad Web Automatizado y Pasivo         ║
║                                                              ║
║       Desarrollado por: Juan David Salazar                   ║
║       Licencia: MIT                                          ║
╚══════════════════════════════════════════════════════════════╝

Herramienta de auditoría de seguridad para aplicaciones web:
  - Encabezados de seguridad HTTP (HSTS, CSP, X-Frame-Options, etc.)
  - Configuración y vigencia SSL/TLS (Ciphers, Protocolos)
  - Detección de archivos sensibles y rutas de administración
  - Auditoría de atributos de seguridad en Cookies (Secure, HttpOnly, SameSite)
  - Políticas de intercambio de recursos de origen cruzado (CORS)
  - Análisis de fugas de información en HTML y comentarios
  - Verificación de bibliotecas JavaScript y detección de CVEs
  - Detección de integridad de recursos (SRI), redirecciones HTTP y registros CAA
"""

import os
import sys
import re
import ssl
import socket
import json
from datetime import datetime
from urllib.parse import urlparse
from collections import defaultdict

# Desactivar advertencias de certificados en inspección pasiva
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

try:
    import requests
    from bs4 import BeautifulSoup
except ImportError:
    print("\n[!] Error: Faltan dependencias necesarias.")
    print("[*] Instálalas ejecutando: pip install -r requirements.txt\n")
    sys.exit(1)


# ═══════════════════════════════════════════════════════════
# CONFIGURACIÓN DE COLORES Y ESTILOS
# ═══════════════════════════════════════════════════════════
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    END = '\033[0m'

C = Colors


# ═══════════════════════════════════════════════════════════
# ESTRUCTURA DE HALLAZGOS
# ═══════════════════════════════════════════════════════════
class Finding:
    def __init__(self, severity, category, title, description, recommendation=""):
        self.severity = severity  # CRITICAL, HIGH, MEDIUM, LOW, INFO
        self.category = category
        self.title = title
        self.description = description
        self.recommendation = recommendation
        self.timestamp = datetime.now().isoformat()

    def icon(self):
        icons = {
            'CRITICAL': '🔴',
            'HIGH': '🟠',
            'MEDIUM': '🟡',
            'LOW': '🔵',
            'INFO': '⚪'
        }
        return icons.get(self.severity, '⚪')

findings = []

def add_finding(severity, category, title, desc, rec=""):
    findings.append(Finding(severity, category, title, desc, rec))


# ═══════════════════════════════════════════════════════════
# MÓDULO 1: ENCABEZADOS DE SEGURIDAD HTTP
# ═══════════════════════════════════════════════════════════
def scan_security_headers(headers, url):
    print(f"\n{C.BOLD}{C.CYAN}[1/8] 🛡️  Auditando Encabezados de Seguridad HTTP...{C.END}")

    required_headers = {
        'Strict-Transport-Security': {
            'severity': 'HIGH',
            'desc': 'HSTS no está configurado. El sitio es vulnerable a ataques de downgrade SSL (SSLStrip).',
            'rec': 'Agregar header: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload'
        },
        'Content-Security-Policy': {
            'severity': 'HIGH',
            'desc': 'CSP no está configurado. El sitio es vulnerable a ataques XSS (Cross-Site Scripting) e inyección de contenido.',
            'rec': "Configurar una política CSP restrictiva (ejemplo: default-src 'self'; script-src 'self' cdn-urls; style-src 'self' 'unsafe-inline')"
        },
        'X-Content-Type-Options': {
            'severity': 'MEDIUM',
            'desc': 'X-Content-Type-Options no está configurado. El navegador podría interpretar archivos con un MIME type incorrecto (MIME sniffing).',
            'rec': 'Agregar header: X-Content-Type-Options: nosniff'
        },
        'X-Frame-Options': {
            'severity': 'MEDIUM',
            'desc': 'X-Frame-Options no está configurado. El sitio podría ser embebido en un iframe malicioso (Clickjacking).',
            'rec': "Agregar header: X-Frame-Options: DENY o SAMEORIGIN"
        },
        'Referrer-Policy': {
            'severity': 'LOW',
            'desc': 'Referrer-Policy no está configurado de forma óptima.',
            'rec': 'Agregar header: Referrer-Policy: strict-origin-when-cross-origin (o no-referrer)'
        },
        'Permissions-Policy': {
            'severity': 'LOW',
            'desc': 'Permissions-Policy no está configurado. Las APIs del navegador (cámara, micrófono, geolocalización) no están restringidas.',
            'rec': 'Agregar header: Permissions-Policy: camera=(), microphone=(), geolocation=()'
        },
        'X-XSS-Protection': {
            'severity': 'INFO',
            'desc': 'X-XSS-Protection no está presente. Aunque obsoleto en navegadores modernos, ayuda en clientes legacy.',
            'rec': 'Agregar header: X-XSS-Protection: 1; mode=block (para compatibilidad histórica)'
        }
    }

    # Normalizar cabeceras a minúsculas para comparación insensible a mayúsculas
    headers_lower = {k.lower(): (k, v) for k, v in headers.items()}

    for header_name, info in required_headers.items():
        if header_name.lower() in headers_lower:
            orig_name, val = headers_lower[header_name.lower()]
            print(f"  {C.GREEN}✓{C.END} {orig_name}: {C.DIM}{val[:60]}{C.END}")
        else:
            add_finding(info['severity'], 'Headers', f'{header_name} ausente', info['desc'], info['rec'])
            print(f"  {C.FAIL}✗{C.END} {header_name}: {C.FAIL}AUSENTE{C.END}")

    # Cabeceras que exponen información de infraestructura
    dangerous_headers = {
        'Server': 'Revela información del servidor web.',
        'X-Powered-By': 'Revela tecnologías del backend (ej: PHP, Express, ASP.NET).',
        'X-AspNet-Version': 'Revela la versión de ASP.NET.',
        'X-AspNetMvc-Version': 'Revela la versión de ASP.NET MVC.'
    }
    for header, desc in dangerous_headers.items():
        if header.lower() in headers_lower:
            orig_name, val = headers_lower[header.lower()]
            add_finding('LOW', 'Information Disclosure', f'Header {orig_name} expuesto',
                        f'{desc} Valor: "{val}"',
                        f'Eliminar o enmascarar el header {orig_name} en la configuración del servidor.')
            print(f"  {C.WARNING}⚠{C.END} {orig_name}: {C.WARNING}{val} (información expuesta){C.END}")


# ═══════════════════════════════════════════════════════════
# MÓDULO 2: SSL/TLS
# ═══════════════════════════════════════════════════════════
def scan_ssl(hostname):
    print(f"\n{C.BOLD}{C.CYAN}[2/8] 🔒 Auditando Configuración SSL/TLS...{C.END}")
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                protocol = ssock.version()
                cipher = ssock.cipher()

                print(f"  {C.GREEN}✓{C.END} Protocolo: {C.GREEN}{protocol}{C.END}")
                print(f"  {C.GREEN}✓{C.END} Cipher Suite: {C.DIM}{cipher[0]}{C.END}")

                # Verificar fecha de expiración
                not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                days_left = (not_after - datetime.now(not_after.tzinfo) if not_after.tzinfo else not_after - datetime.utcnow()).days
                print(f"  {C.GREEN}✓{C.END} Certificado expira: {cert['notAfter']} ({days_left} días restantes)")

                if days_left < 7:
                    add_finding('HIGH', 'SSL/TLS', 'Certificado SSL próximo a expirar',
                                f'El certificado SSL expira en {days_left} días ({cert["notAfter"]}).',
                                'Renovar el certificado SSL inmediatamente.')
                elif days_left < 20:
                    add_finding('MEDIUM', 'SSL/TLS', 'Certificado SSL expira pronto',
                                f'El certificado SSL expira en {days_left} días.',
                                'Verificar la renovación automática del certificado.')

                # Verificar protocolos obsoletos
                if protocol in ('TLSv1', 'TLSv1.1', 'SSLv3', 'SSLv2'):
                    add_finding('CRITICAL', 'SSL/TLS', f'Protocolo SSL/TLS inseguro: {protocol}',
                                f'El servidor soporta {protocol}, vulnerable a ataques conocidos (POODLE, BEAST).',
                                'Desactivar SSLv2, SSLv3, TLSv1 y TLSv1.1. Permitir únicamente TLSv1.2 y TLSv1.3.')
                else:
                    print(f"  {C.GREEN}✓{C.END} Protocolo seguro confirmado")

                # Nombres alternativos del sujeto (SANs)
                san = cert.get('subjectAltName', [])
                san_domains = [x[1] for x in san if x[0] == 'DNS']
                if san_domains:
                    print(f"  {C.GREEN}✓{C.END} SANs: {', '.join(san_domains[:4])}")

    except ssl.SSLError as e:
        add_finding('CRITICAL', 'SSL/TLS', 'Error SSL crítico',
                    f'No se pudo establecer conexión SSL segura: {str(e)}',
                    'Verificar la configuración de certificados SSL en el servidor.')
        print(f"  {C.FAIL}✗ Error SSL: {e}{C.END}")
    except socket.timeout:
        add_finding('MEDIUM', 'SSL/TLS', 'Timeout de conexión SSL',
                    'El servidor no respondió en 10 segundos a la conexión SSL.',
                    'Verificar la disponibilidad y latencia del servidor.')
        print(f"  {C.WARNING}⚠ Timeout al conectar{C.END}")
    except Exception as e:
        print(f"  {C.WARNING}⚠ No se pudo auditar SSL: {e}{C.END}")


# ═══════════════════════════════════════════════════════════
# MÓDULO 3: EXPOSICIÓN DE ARCHIVOS SENSIBLES
# ═══════════════════════════════════════════════════════════
def scan_sensitive_files(base_url):
    print(f"\n{C.BOLD}{C.CYAN}[3/8] 📁 Buscando Archivos Sensibles Expuestos...{C.END}")

    sensitive_paths = [
        ('.git/HEAD', 'CRITICAL', 'Repositorio Git expuesto', 'Un atacante puede descargar el historial y código fuente.'),
        ('.git/config', 'CRITICAL', 'Configuración Git expuesta', 'Puede revelar URLs de repos remotos y tokens.'),
        ('.env', 'CRITICAL', 'Archivo .env expuesto', 'Puede contener API keys, contraseñas de BD y secretos.'),
        ('.env.local', 'CRITICAL', 'Archivo .env.local expuesto', 'Puede contener secretos de entornos de desarrollo.'),
        ('wp-config.php', 'CRITICAL', 'WordPress config expuesto', 'Contiene credenciales directas de base de datos.'),
        ('.htaccess', 'MEDIUM', 'Archivo .htaccess expuesto', 'Puede revelar reglas internas de reescritura.'),
        ('web.config', 'MEDIUM', 'Archivo web.config expuesto', 'Puede revelar configuración interna de IIS.'),
        ('.DS_Store', 'LOW', 'Archivo .DS_Store expuesto', 'Puede revelar la estructura de directorios del sistema.'),
        ('package.json', 'LOW', 'package.json expuesto', 'Revela dependencias y posibles versiones desactualizadas.'),
        ('composer.json', 'LOW', 'composer.json expuesto', 'Revela dependencias de backend PHP.'),
        ('debug.log', 'HIGH', 'Log de debug expuesto', 'Puede contener stack traces y variables en memoria.'),
        ('error.log', 'HIGH', 'Log de errores expuesto', 'Puede contener rutas del sistema de archivos.'),
        ('.well-known/security.txt', 'INFO', 'security.txt encontrado', 'Buena práctica de divulgación responsable.'),
        ('crossdomain.xml', 'LOW', 'crossdomain.xml encontrado', 'Puede permitir acceso cross-domain permisivo.'),
        ('phpinfo.php', 'HIGH', 'phpinfo() expuesto', 'Revela toda la configuración y módulos del servidor PHP.'),
        ('admin/', 'MEDIUM', 'Panel admin accesible', 'El panel de administración no debería ser público.'),
        ('backup/', 'HIGH', 'Directorio de backups accesible', 'Puede contener copias de seguridad de datos.'),
        ('.gitignore', 'INFO', '.gitignore accesible', 'Revela convenciones de carpetas del proyecto.'),
        ('firebase.json', 'MEDIUM', 'firebase.json expuesto', 'Puede revelar configuración de Firebase.'),
        ('wrangler.toml', 'MEDIUM', 'wrangler.toml expuesto', 'Puede revelar configuración de Cloudflare Workers.')
    ]

    for path, severity, title, desc in sensitive_paths:
        try:
            url = f"{base_url.rstrip('/')}/{path}"
            resp = requests.get(url, timeout=5, allow_redirects=False,
                                headers={'User-Agent': 'Mozilla/5.0 (SecurityAudit/1.0)'})

            if resp.status_code == 200:
                body = resp.text[:500]
                content_type = resp.headers.get('Content-Type', '')

                # Descartar falsos positivos comunes en Single Page Applications (SPAs)
                if '<!DOCTYPE html>' in body or '<html' in body:
                    if len(resp.text) > 15000:
                        print(f"  {C.GREEN}✓{C.END} {path}: SPA fallback detectado (no expuesto)")
                        continue
                    if path.endswith(('.html', '.htm')):
                        pass
                    else:
                        print(f"  {C.GREEN}✓{C.END} {path}: SPA redirect (no expuesto)")
                        continue

                add_finding(severity, 'File Exposure', title,
                            f'{desc}\nURL: {url}\nContent-Type: {content_type}\nTamaño: {len(resp.text)} bytes',
                            f'Bloquear el acceso a /{path} en la configuración del servidor web.')
                print(f"  {C.FAIL}✗{C.END} {path}: {C.FAIL}EXPUESTO ({resp.status_code}){C.END}")
            else:
                print(f"  {C.GREEN}✓{C.END} {path}: {C.DIM}No accesible ({resp.status_code}){C.END}")
        except requests.exceptions.Timeout:
            print(f"  {C.DIM}  {path}: timeout{C.END}")
        except Exception:
            pass


# ═══════════════════════════════════════════════════════════
# MÓDULO 4: ANÁLISIS DE COOKIES
# ═══════════════════════════════════════════════════════════
def scan_cookies(response):
    print(f"\n{C.BOLD}{C.CYAN}[4/8] 🍪 Auditando Seguridad de Cookies...{C.END}")

    cookies = response.cookies
    if not cookies:
        print(f"  {C.GREEN}✓{C.END} No se detectaron cookies en la respuesta inicial.")
        return

    for cookie in cookies:
        issues = []
        name = cookie.name
        print(f"\n  Cookie: {C.BOLD}{name}{C.END}")

        if not cookie.secure:
            issues.append('Sin flag Secure')
            add_finding('MEDIUM', 'Cookies', f'Cookie "{name}" sin flag Secure',
                        'La cookie puede transmitirse sobre conexiones no cifradas (HTTP).',
                        f'Agregar flag Secure a la cookie "{name}".')

        if not cookie.has_nonstandard_attr('HttpOnly') and 'httponly' not in str(cookie).lower():
            issues.append('Sin flag HttpOnly')
            add_finding('MEDIUM', 'Cookies', f'Cookie "{name}" sin flag HttpOnly',
                        'La cookie es accesible desde scripts del cliente (vulnerable a robo vía XSS).',
                        f'Agregar flag HttpOnly a la cookie "{name}".')

        samesite = cookie.get_nonstandard_attr('SameSite') or ''
        if not samesite:
            issues.append('Sin SameSite')
            add_finding('LOW', 'Cookies', f'Cookie "{name}" sin atributo SameSite',
                        'La cookie podría ser enviada en peticiones cross-site (riesgo CSRF).',
                        f'Configurar SameSite=Lax o SameSite=Strict en la cookie "{name}".')

        if issues:
            print(f"    {C.WARNING}⚠ Advertencias: {', '.join(issues)}{C.END}")
        else:
            print(f"    {C.GREEN}✓ Configuración segura{C.END}")


# ═══════════════════════════════════════════════════════════
# MÓDULO 5: ANÁLISIS DE CORS
# ═══════════════════════════════════════════════════════════
def scan_cors(headers, url):
    print(f"\n{C.BOLD}{C.CYAN}[5/8] 🌐 Auditando Política CORS...{C.END}")

    acao = headers.get('Access-Control-Allow-Origin', '')
    acac = headers.get('Access-Control-Allow-Credentials', '')

    if acao == '*':
        if acac and acac.lower() == 'true':
            add_finding('CRITICAL', 'CORS', 'CORS Wildcard con Credenciales',
                        'Access-Control-Allow-Origin: * con Allow-Credentials: true permite a cualquier sitio leer respuestas autenticadas.',
                        'Restringir ACAO a dominios explícitos autorizados.')
            print(f"  {C.FAIL}✗ ACAO: * + Credentials: true → CRÍTICO{C.END}")
        else:
            add_finding('MEDIUM', 'CORS', 'CORS Wildcard (*)',
                        'Access-Control-Allow-Origin está configurado como "*", permitiendo peticiones desde cualquier origen.',
                        'Restringir a los dominios específicos que consuman el recurso.')
            print(f"  {C.WARNING}⚠{C.END} Access-Control-Allow-Origin: {C.WARNING}* (wildcard){C.END}")
    elif acao:
        print(f"  {C.GREEN}✓{C.END} ACAO: {acao}")
    else:
        print(f"  {C.GREEN}✓{C.END} Sin cabeceras CORS abiertas (cerrado por defecto).")

    # Prueba de reflexión de orígenes maliciosos
    try:
        test_origin = 'https://malicious-example.com'
        resp = requests.get(url, headers={'Origin': test_origin, 'User-Agent': 'SecurityAudit/1.0'}, timeout=5)
        reflected = resp.headers.get('Access-Control-Allow-Origin', '')
        if reflected == test_origin:
            add_finding('CRITICAL', 'CORS', 'CORS refleja origen arbitrario',
                        f'El servidor refleja el origen del atacante ({test_origin}) en la cabecera Access-Control-Allow-Origin.',
                        'No reflejar dinámicamente el header Origin. Utilizar una lista blanca estricta.')
            print(f"  {C.FAIL}✗ CORS refleja origen arbitrario → CRÍTICO{C.END}")
        else:
            print(f"  {C.GREEN}✓{C.END} No refleja orígenes arbitrarios.")
    except Exception:
        pass


# ═══════════════════════════════════════════════════════════
# MÓDULO 6: ANÁLISIS DEL HTML (FUGAS DE INFORMACIÓN)
# ═══════════════════════════════════════════════════════════
def scan_html_content(html, url):
    print(f"\n{C.BOLD}{C.CYAN}[6/8] 🔍 Analizando Fugas de Información en HTML...{C.END}")

    soup = BeautifulSoup(html, 'html.parser')

    # 1. Comentarios HTML sensibles
    comment_pattern = re.findall(r'<!--(.*?)-->', html, re.DOTALL)
    sensitive_comment_keywords = ['password', 'secret', 'key', 'token', 'admin', 'debug', 'TODO', 'FIXME', 'BUG', 'credential']
    for comment in comment_pattern:
        for keyword in sensitive_comment_keywords:
            if keyword.lower() in comment.lower():
                add_finding('LOW', 'Information Disclosure', 'Comentario HTML potencialmente sensible',
                            f'Se encontró la palabra "{keyword}" en un comentario HTML: {comment[:90]}...',
                            'Eliminar comentarios de depuración antes del despliegue en producción.')
                print(f"  {C.WARNING}⚠{C.END} Comentario con '{keyword}': {C.DIM}{comment[:60].strip()}...{C.END}")
                break

    # 2. Claves de API / Secretos en código HTML
    api_patterns = {
        'AWS Access Key': r'AKIA[0-9A-Z]{16}',
        'Private Key': r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----',
        'Generic Secret': r'(?:secret|password|passwd|pwd)\s*[:=]\s*["\'][^"\']{8,}["\']',
        'Firebase / Google API Key': r'AIza[0-9A-Za-z_-]{35}'
    }
    for name, pattern in api_patterns.items():
        matches = re.findall(pattern, html)
        if matches:
            if 'Firebase' in name or 'Google API' in name:
                print(f"  {C.CYAN}ℹ{C.END} {name} detectado (clave cliente de SPA - protegida por Security Rules)")
            else:
                add_finding('CRITICAL', 'Information Disclosure', f'{name} expuesta en HTML',
                            f'Se detectó una posible {name} en el código HTML de la respuesta.',
                            'Mover la clave al backend y no exponer credenciales privadas en el cliente.')
                print(f"  {C.FAIL}✗{C.END} {name}: {C.FAIL}EXPUESTA{C.END}")

    # 3. Scripts externos y Subresource Integrity (SRI)
    scripts = soup.find_all('script', src=True)
    external_domains = set()
    for script in scripts:
        src = script.get('src', '')
        if src.startswith('http'):
            domain = urlparse(src).netloc
            external_domains.add(domain)
            if not script.get('integrity'):
                if 'challenges.cloudflare.com' in src or 'recaptcha' in src:
                    # Scripts dinámicos autorizados que rotan por diseño
                    continue
                add_finding('LOW', 'Supply Chain', f'Script externo sin SRI: {domain}',
                            f'El script {src} no tiene atributo integrity (Subresource Integrity).',
                            'Agregar integrity="sha384-..." crossorigin="anonymous" para prevenir alteraciones en CDN.')

    if external_domains:
        print(f"  {C.CYAN}ℹ{C.END} Scripts externos: {', '.join(external_domains)}")

    # 4. Meta robots
    meta_robots = soup.find('meta', attrs={'name': 'robots'})
    if meta_robots:
        print(f"  {C.GREEN}✓{C.END} Meta robots: {meta_robots.get('content', '')}")

    print(f"  {C.GREEN}✓{C.END} Análisis HTML completado.")


# ═══════════════════════════════════════════════════════════
# MÓDULO 7: BIBLIOTECAS JS CON CVEs CONOCIDOS
# ═══════════════════════════════════════════════════════════
def scan_js_libraries(html, base_url):
    print(f"\n{C.BOLD}{C.CYAN}[7/8] 📦 Detectando Bibliotecas JS y CVEs Conocidos...{C.END}")

    known_vulns = {
        'jquery': {
            'pattern': r'jquery[.-]?v?(\d+\.\d+\.\d+)',
            'vulnerable_below': '3.5.0',
            'cve': 'CVE-2020-11022/11023 (XSS en $.html())',
        },
        'lodash': {
            'pattern': r'lodash[.-]?v?(\d+\.\d+\.\d+)',
            'vulnerable_below': '4.17.21',
            'cve': 'CVE-2021-23337 (Prototype Pollution)',
        },
        'angular': {
            'pattern': r'angular[.-]?v?(\d+\.\d+\.\d+)',
            'vulnerable_below': '1.8.0',
            'cve': 'Múltiples XSS en AngularJS < 1.8.0',
        },
        'bootstrap': {
            'pattern': r'bootstrap[.-]?v?(\d+\.\d+\.\d+)',
            'vulnerable_below': '5.2.0',
            'cve': 'CVE-2024-6531 (XSS)',
        },
        'dompurify': {
            'pattern': r'dompurify[/-]?v?(\d+\.\d+\.\d+)',
            'vulnerable_below': '3.0.6',
            'cve': 'CVE-2024-47875 (Bypass en versiones antiguas)',
        }
    }

    soup = BeautifulSoup(html, 'html.parser')
    scripts = soup.find_all('script', src=True)

    detected_any = False
    for script in scripts:
        src = script.get('src', '').lower()
        for lib, info in known_vulns.items():
            if lib in src:
                detected_any = True
                version_match = re.search(info['pattern'], src)
                if version_match:
                    version = version_match.group(1)
                    vuln_ver = info['vulnerable_below']
                    if tuple(map(int, version.split('.'))) < tuple(map(int, vuln_ver.split('.'))):
                        add_finding('HIGH', 'Dependencies', f'{lib} v{version} vulnerable',
                                    f'La versión {version} de {lib} tiene vulnerabilidades conocidas: {info["cve"]}.',
                                    f'Actualizar {lib} a la versión {vuln_ver} o superior.')
                        print(f"  {C.FAIL}✗{C.END} {lib} v{version}: {C.FAIL}VULNERABLE ({info['cve']}){C.END}")
                    else:
                        print(f"  {C.GREEN}✓{C.END} {lib} v{version}: Versión segura.")
                else:
                    print(f"  {C.CYAN}ℹ{C.END} {lib} detectado.")

    if not detected_any:
        print(f"  {C.GREEN}✓{C.END} No se detectaron bibliotecas obsoletas con CVEs en los tags script.")


# ═══════════════════════════════════════════════════════════
# MÓDULO 8: REDIRECCIONES Y MISCELÁNEOS
# ═══════════════════════════════════════════════════════════
def scan_misc(base_url, headers):
    print(f"\n{C.BOLD}{C.CYAN}[8/8] 🔧 Auditorías Misceláneas...{C.END}")

    # Redirección de HTTP a HTTPS
    try:
        http_url = base_url.replace('https://', 'http://')
        resp = requests.get(http_url, allow_redirects=False, timeout=5,
                            headers={'User-Agent': 'SecurityAudit/1.0'})
        if resp.status_code in (301, 302, 307, 308):
            location = resp.headers.get('Location', '')
            if 'https' in location:
                print(f"  {C.GREEN}✓{C.END} HTTP → HTTPS redirect activo ({resp.status_code})")
            else:
                print(f"  {C.WARNING}⚠{C.END} Redirect no apunta a HTTPS: {location}")
        else:
            add_finding('HIGH', 'Transport', 'Sin redirección HTTP a HTTPS',
                        'Las peticiones HTTP no son forzadas a HTTPS.',
                        'Configurar redirección 301 permanente a HTTPS en el servidor.')
            print(f"  {C.FAIL}✗{C.END} Sin redirección HTTP → HTTPS.")
    except Exception:
        print(f"  {C.DIM}  No se pudo verificar redirect HTTP.{C.END}")

    # Cabecera Cache-Control
    cc = headers.get('Cache-Control', '')
    if cc:
        print(f"  {C.GREEN}✓{C.END} Cache-Control: {C.DIM}{cc}{C.END}")
    else:
        add_finding('LOW', 'Caching', 'Sin Cache-Control',
                    'No hay header Cache-Control explícito.',
                    'Declarar Cache-Control adecuado según el tipo de recurso.')

    # Registros DNS CAA
    hostname = urlparse(base_url).netloc
    try:
        import subprocess
        result = subprocess.run(['nslookup', '-type=CAA', hostname], capture_output=True, text=True, timeout=8)
        if 'issue' in result.stdout.lower() or 'issuewild' in result.stdout.lower():
            print(f"  {C.GREEN}✓{C.END} Registros DNS CAA presentes.")
        else:
            add_finding('INFO', 'DNS', 'Sin registros DNS CAA',
                        'No se encontraron registros CAA que restrinjan qué CAs pueden emitir certificados.',
                        'Agregar registros DNS CAA para restringir la emisión no autorizada de certificados.')
            print(f"  {C.CYAN}ℹ{C.END} Sin registros DNS CAA.")
    except Exception:
        pass


# ═══════════════════════════════════════════════════════════
# GENERADOR DE REPORTE
# ═══════════════════════════════════════════════════════════
def generate_report(url, duration):
    severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4}
    sorted_findings = sorted(findings, key=lambda f: severity_order.get(f.severity, 5))

    counts = defaultdict(int)
    for f in findings:
        counts[f.severity] += 1

    print(f"\n{'═' * 65}")
    print(f"{C.BOLD}{C.CYAN}")
    print(f"  ╔══════════════════════════════════════════════════════════╗")
    print(f"  ║        REPORTE DE AUDITORÍA DE SEGURIDAD WEB           ║")
    print(f"  ║         Desarrollado por: Juan David Salazar           ║")
    print(f"  ╚══════════════════════════════════════════════════════════╝{C.END}")
    print(f"\n  🎯 Objetivo auditado: {C.BOLD}{url}{C.END}")
    print(f"  📅 Fecha: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  ⏱️  Duración: {duration:.1f} segundos")
    print(f"  📊 Total hallazgos: {len(findings)}")
    print(f"\n  {C.FAIL}🔴 CRITICAL: {counts['CRITICAL']}{C.END}  "
          f"{C.FAIL}🟠 HIGH: {counts['HIGH']}{C.END}  "
          f"{C.WARNING}🟡 MEDIUM: {counts['MEDIUM']}{C.END}  "
          f"{C.CYAN}🔵 LOW: {counts['LOW']}{C.END}  "
          f"{C.DIM}⚪ INFO: {counts['INFO']}{C.END}")

    score = 100 - (counts['CRITICAL'] * 25 + counts['HIGH'] * 15 + counts['MEDIUM'] * 8 + counts['LOW'] * 3 + counts['INFO'] * 1)
    score = max(0, score)

    if score >= 90: grade, grade_color = 'A', C.GREEN
    elif score >= 75: grade, grade_color = 'B', C.GREEN
    elif score >= 60: grade, grade_color = 'C', C.WARNING
    elif score >= 40: grade, grade_color = 'D', C.WARNING
    else: grade, grade_color = 'F', C.FAIL

    print(f"\n  {'─' * 55}")
    print(f"  {C.BOLD}  CALIFICACIÓN DE SEGURIDAD: {grade_color}{grade} ({score}/100){C.END}")
    print(f"  {'─' * 55}")

    if sorted_findings:
        print(f"\n  {C.BOLD}HALLAZGOS DETALLADOS:{C.END}")
        for f in sorted_findings:
            print(f"\n  {f.icon()} [{f.severity}] {C.BOLD}{f.title}{C.END}")
            print(f"     Categoría: {f.category}")
            for line in f.description.split('\n'):
                print(f"     {C.DIM}{line}{C.END}")
            if f.recommendation:
                print(f"     {C.GREEN}→ Recomendación: {f.recommendation}{C.END}")
    else:
        print(f"\n  {C.GREEN}  ¡Excelente! No se encontraron vulnerabilidades.{C.END}")

    print(f"\n{'═' * 65}")

    report_file = f'audit_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json'
    report_json = {
        'metadata': {
            'author': 'Juan David Salazar',
            'tool': 'EXMERA Web Vulnerability Scanner',
            'target': url,
            'timestamp': datetime.now().isoformat(),
            'duration_seconds': round(duration, 1),
            'total_findings': len(findings),
            'score': score,
            'grade': grade
        },
        'summary': dict(counts),
        'findings': [
            {
                'severity': f.severity,
                'category': f.category,
                'title': f.title,
                'description': f.description,
                'recommendation': f.recommendation,
                'timestamp': f.timestamp
            }
            for f in sorted_findings
        ]
    }

    with open(report_file, 'w', encoding='utf-8') as fp:
        json.dump(report_json, fp, indent=2, ensure_ascii=False)

    print(f"\n  {C.GREEN}📄 Reporte JSON guardado en: {os.path.abspath(report_file)}{C.END}\n")
    return report_json


# ═══════════════════════════════════════════════════════════
# ENTRADA PRINCIPAL
# ═══════════════════════════════════════════════════════════
def main():
    if len(sys.argv) > 1:
        url = sys.argv[1].strip('\'" ')
    else:
        print(f"""
{C.BOLD}{C.CYAN}╔══════════════════════════════════════════════════════════════╗
║             EXMERA Web Vulnerability Scanner                 ║
║       Auditor de Seguridad Web para Cualquier Dominio/Host   ║
║                                                              ║
║       Desarrollado por: Juan David Salazar                   ║
╚══════════════════════════════════════════════════════════════╝{C.END}
""")
        default_url = 'https://exmera.pages.dev/'
        try:
            prompt_text = f"🎯 Ingresa la URL o host a auditar (ej: https://mi-sitio.com o localhost:3000)\n   [Presiona ENTER para '{default_url}']: "
            user_input = input(prompt_text).strip('\'" ')
        except (EOFError, KeyboardInterrupt):
            user_input = ""
        url = user_input if user_input else default_url

    if not url.startswith('http://') and not url.startswith('https://'):
        if 'localhost' in url or '127.0.0.1' in url:
            url = 'http://' + url
        else:
            url = 'https://' + url

    parsed = urlparse(url)
    hostname = parsed.netloc.split(':')[0]

    print(f"""
{C.BOLD}{C.CYAN}
╔══════════════════════════════════════════════════════════════╗
║             EXMERA Web Vulnerability Scanner                 ║
║       Auditoría de Seguridad Web Automatizada y Pasiva       ║
║       Desarrollador: Juan David Salazar                      ║
╚══════════════════════════════════════════════════════════════╝{C.END}

  🎯 Objetivo: {C.BOLD}{url}{C.END}
  🕐 Inicio:   {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
  ⚙️  Módulos:  8 activos
""")

    start_time = datetime.now()

    try:
        print(f"{C.BOLD}Conectando al objetivo...{C.END}")
        response = requests.get(url, timeout=15,
                                headers={'User-Agent': 'Mozilla/5.0 (SecurityAudit/1.0)'},
                                allow_redirects=True)
        print(f"  {C.GREEN}✓{C.END} Conexión exitosa: HTTP {response.status_code}")
        print(f"  {C.GREEN}✓{C.END} Tiempo de respuesta: {response.elapsed.total_seconds():.2f}s")

        headers = response.headers
        html = response.text

        # Ejecución de los 8 módulos
        scan_security_headers(headers, url)
        scan_ssl(hostname)
        scan_sensitive_files(url)
        scan_cookies(response)
        scan_cors(headers, url)
        scan_html_content(html, url)
        scan_js_libraries(html, url)
        scan_misc(url, headers)

    except requests.exceptions.ConnectionError:
        print(f"\n{C.FAIL}✗ ERROR: No se pudo conectar a {url}{C.END}")
        sys.exit(1)
    except requests.exceptions.Timeout:
        print(f"\n{C.FAIL}✗ ERROR: Timeout al conectar a {url}{C.END}")
        sys.exit(1)

    duration = (datetime.now() - start_time).total_seconds()
    generate_report(url, duration)


if __name__ == '__main__':
    main()
