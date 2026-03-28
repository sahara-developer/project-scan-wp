# WP Recon

Scanner de reconocimiento web con enfoque en sitios WordPress. Detecta tecnologías, plugins, temas, usuarios y endpoints expuestos.

## ¿Qué hace?

**Detección general de tecnologías:**
- Servidor web (Nginx, Apache, LiteSpeed, IIS, Cloudflare)
- Lenguaje backend (PHP, ASP.NET, Express.js)
- CDN/Proxy/Hosting (Cloudflare, Vercel, AWS CloudFront)
- Frameworks y librerías JS/CSS (React, Vue, Angular, jQuery, Bootstrap, Tailwind, Next.js, etc.)
- CMS (WordPress, Joomla, Drupal, Shopify, Wix, Squarespace, Ghost, Hugo, Jekyll)
- Headers de seguridad (HSTS, CSP, X-Frame-Options, X-Content-Type-Options)

**Cuando detecta WordPress, profundiza con:**
- Versión de WordPress (meta generator, feed RSS, readme.html, wp-links-opml, parámetros `ver=`)
- Tema activo (slug, versión, autor, URI, descripción desde `style.css`)
- Plugins instalados (extracción del HTML + fuerza bruta contra ~50 plugins comunes vía `readme.txt` y directory probing)
- Usuarios (REST API `/wp-json/wp/v2/users` + enumeración por author archive `/?author=N`)
- Endpoints sensibles (debug.log, config backups, xmlrpc.php, install.php, setup-config.php)
- REST API discovery (namespaces, detección de plugins adicionales por namespace)

## Instalación

```bash
git clone https://github.com/sahara-developer/project-scan-wp.git
cd wp-recon
pip install -r requirements.txt
```

## Uso

### Modo interactivo

```bash
python3 wp_recon.py
```

Solicita la URL, tipo de escaneo (completo o rápido), hilos concurrentes y opción de exportar a JSON.

### Modo CLI

```bash
# Escaneo completo
python3 wp_recon.py https://example.com

# Escaneo rápido (sin fuerza bruta de plugins)
python3 wp_recon.py example.com --quick

# Con más hilos y exportar a JSON
python3 wp_recon.py example.com --threads 20 --json reporte.json
```

### Opciones

| Argumento | Descripción |
|---|---|
| `url` | Dominio o URL a escanear |
| `--quick`, `-q` | Escaneo rápido, omite fuerza bruta de plugins |
| `--json`, `-j` | Ruta para exportar resultados en JSON |
| `--threads`, `-t` | Hilos concurrentes (default: 10) |
| `--timeout` | Timeout por request en segundos (default: 10) |

## Ejemplo de salida

```
┌──────────────────────────────────────────────────┐
│ WP Recon — Resultados para https://example.com   │
└──────────────────────────────────────────────────┘

╭─ Información General ─╮
│ URL        example.com │
│ WordPress  Sí          │
│ Versión WP 6.5.2       │
╰────────────────────────╯

╭─ Tecnologías Detectadas ─╮
│ Nginx    1.24.0  Servidor │
│ PHP      8.2.18  Backend  │
│ jQuery          JS/CSS    │
╰───────────────────────────╯

╭─ Plugins Detectados (5) ─╮
│ wordfence    7.11.3       │
│ woocommerce  8.9.1        │
│ ...                       │
╰───────────────────────────╯
```

## Licencia

MIT
