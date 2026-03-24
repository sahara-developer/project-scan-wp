#!/usr/bin/env python3
"""
WP Recon - WordPress & Web Technology Scanner
==============================================
Herramienta de reconocimiento para identificar tecnologías web,
con enfoque especial en sitios WordPress.

Uso: python3 wp_recon.py <url> [opciones]

Requiere: pip install requests beautifulsoup4 rich
"""

import re
import sys
import json
import argparse
import concurrent.futures
from collections import Counter
from urllib.parse import urljoin
from typing import Optional

import requests
from bs4 import BeautifulSoup, Comment
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich import box

console = Console()

# ─── Configuración ───────────────────────────────────────────────────────────

DEFAULT_TIMEOUT = 10
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/120.0.0.0 Safari/537.36"
)

COMMON_WP_PLUGINS = [
    "akismet", "contact-form-7", "wordfence", "wordpress-seo",
    "elementor", "woocommerce", "jetpack", "wp-super-cache",
    "w3-total-cache", "all-in-one-seo-pack", "classic-editor",
    "wpforms-lite", "really-simple-ssl", "updraftplus",
    "duplicate-post", "redirection", "wp-mail-smtp",
    "google-analytics-for-wordpress", "litespeed-cache",
    "wp-fastest-cache", "sucuri-scanner", "better-wp-security",
    "limit-login-attempts", "regenerate-thumbnails", "tablepress",
    "advanced-custom-fields", "custom-post-type-ui", "ninja-forms",
    "bbpress", "buddypress", "easy-digital-downloads",
    "memberpress", "autoptimize", "insert-headers-and-footers",
    "all-in-one-wp-migration", "mailchimp-for-wp",
    "google-sitemap-generator", "wp-smushit",
    "shortpixel-image-optimiser", "imagify", "wp-optimize",
    "broken-link-checker", "simple-custom-css", "svg-support",
    "disable-comments", "tinymce-advanced", "cookie-notice",
    "gdpr-cookie-compliance", "revslider", "js_composer",
    "theme-my-login", "user-role-editor", "amp",
    "wordpress-popular-posts", "query-monitor", "debug-bar",
    "rankmath-seo",
]

COMMON_WP_THEMES = ['twentytwentyfive', 'twentytwentyfour', 'twentytwentythree', 'twentytwentytwo', 'twentytwentyone', 'twentytwenty', 'twentynineteen', 'twentyseventeen', 'twentysixteen', 'twentyfifteen', 'astra', 'oceanwp', 'generatepress', 'helloelementor', 'storefront', 'neve', 'hestia', 'kadence', 'blocksy', 'divi']

WP_ENDPOINTS = [
    "/wp-login.php",
    "/wp-admin/",
    "/wp-json/",
    "/wp-json/wp/v2/posts",
    "/wp-json/wp/v2/users",
    "/wp-json/wp/v2/pages",
    "/wp-json/wp/v2/categories",
    "/wp-json/wp/v2/tags",
    "/wp-json/wp/v2/media",
    "/wp-json/wp/v2/comments",
    "/xmlrpc.php",
    "/wp-cron.php",
    "/readme.html",
    "/license.txt",
    "/wp-includes/",
    "/wp-content/",
    "/wp-content/uploads/",
    "/wp-content/debug.log",
    "/wp-config.php.bak",
    "/wp-config.php.old",
    "/wp-config.txt",
    "/.wp-config.php.swp",
    "/wp-admin/install.php",
    "/wp-admin/setup-config.php",
    "/wp-trackback.php",
    "/wp-links-opml.php",
    "/wp-sitemap.xml",
    "/sitemap.xml",
    "/sitemap_index.xml",
    "/robots.txt",
    "/feed/",
    "/feed/rss/",
    "/feed/rss2/",
    "/feed/atom/",
    "/?author=1",
    "/wp-json/wp/v2/users/1",
]


# ─── Clase principal ─────────────────────────────────────────────────────────

class WPRecon:
    """Scanner de tecnologías web con enfoque en WordPress."""

    def __init__(self, url: str, timeout: int = DEFAULT_TIMEOUT, threads: int = 10):
        self.url = self._normalize_url(url)
        self.timeout = timeout
        self.threads = threads
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": USER_AGENT})
        self.session.verify = True
        self.results: dict = {
            "url": self.url,
            "is_wordpress": False,
            "version": None,
            "theme": None,
            "plugins": [],
            "endpoints": [],
            "users": [],
            "technologies": [],
            "headers": {},
            "meta_info": {},
        }

    @staticmethod
    def _normalize_url(url: str) -> str:
        url = url.strip().strip("/")
        # Quitar www. del inicio
        if url.lower().startswith("www."):
            url = url[4:]
        if url.lower().startswith("http://www."):
            url = "http://" + url[11:]
        elif url.lower().startswith("https://www."):
            url = "https://" + url[12:]
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        return url.rstrip("/")

    def _get(self, path: str = "", full_url: str = None, allow_redirects=True) -> Optional[requests.Response]:
        target = full_url if full_url else urljoin(self.url + "/", path.lstrip("/"))
        try:
            return self.session.get(target, timeout=self.timeout, allow_redirects=allow_redirects)
        except requests.RequestException:
            return None

    # ── Detección general de tecnologías ──────────────────────────────────

    def detect_technologies(self):
        """Analiza headers y HTML para detectar tecnologías generales."""
        resp = self._get()
        if not resp:
            console.print("[red]✗ No se pudo conectar al sitio[/red]")
            sys.exit(1)

        headers = dict(resp.headers)
        self.results["headers"] = {
            "server": headers.get("Server", "No expuesto"),
            "x-powered-by": headers.get("X-Powered-By", "No expuesto"),
            "x-generator": headers.get("X-Generator", "No expuesto"),
            "content-type": headers.get("Content-Type", ""),
            "x-frame-options": headers.get("X-Frame-Options", "No configurado"),
            "strict-transport-security": headers.get("Strict-Transport-Security", "No configurado"),
            "content-security-policy": headers.get("Content-Security-Policy", "No configurado"),
            "x-content-type-options": headers.get("X-Content-Type-Options", "No configurado"),
        }

        techs = []
        server = headers.get("Server", "").lower()
        powered = headers.get("X-Powered-By", "").lower()

        # Servidores web
        for name, pattern in [
            ("Nginx", "nginx"), ("Apache", "apache"), ("LiteSpeed", "litespeed"),
            ("IIS", "microsoft-iis"), ("Cloudflare", "cloudflare"),
        ]:
            if pattern in server:
                vm = re.search(rf"{pattern}[/ ]*([\d.]+)", server, re.I)
                techs.append({"name": name, "version": vm.group(1) if vm else "", "category": "Servidor Web"})

        # Lenguajes backend
        if "php" in powered:
            vm = re.search(r"php[/ ]*([\d.]+)", powered, re.I)
            techs.append({"name": "PHP", "version": vm.group(1) if vm else "", "category": "Backend"})
        if "asp.net" in powered:
            techs.append({"name": "ASP.NET", "version": "", "category": "Backend"})
        if "express" in powered:
            techs.append({"name": "Express.js", "version": "", "category": "Backend"})

        # CDN / Proxy / Hosting
        if "cloudflare" in str(headers.get("cf-ray", "")) or "cloudflare" in server:
            techs.append({"name": "Cloudflare", "version": "", "category": "CDN/Proxy"})
        if headers.get("x-vercel-id"):
            techs.append({"name": "Vercel", "version": "", "category": "Hosting"})
        if headers.get("x-amz-cf-id"):
            techs.append({"name": "AWS CloudFront", "version": "", "category": "CDN"})

        # Analizar HTML
        soup = BeautifulSoup(resp.text, "html.parser")

        # Meta generator
        gen_meta = soup.find("meta", attrs={"name": "generator"})
        if gen_meta and gen_meta.get("content"):
            gen = gen_meta["content"]
            self.results["meta_info"]["generator"] = gen
            if "wordpress" in gen.lower():
                self.results["is_wordpress"] = True
                vm = re.search(r"([\d.]+)", gen)
                if vm:
                    self.results["version"] = vm.group(1)
            for name, pattern in [
                ("Joomla", "joomla"), ("Drupal", "drupal"), ("Shopify", "shopify"),
                ("Wix", "wix"), ("Squarespace", "squarespace"), ("Ghost", "ghost"),
                ("Hugo", "hugo"), ("Jekyll", "jekyll"), ("Next.js", "next"),
            ]:
                if pattern in gen.lower():
                    techs.append({"name": name, "version": "", "category": "CMS/Framework"})

        # Detectar frameworks JS/CSS por scripts y links
        scripts = [s.get("src", "") for s in soup.find_all("script", src=True)]
        links = [l.get("href", "") for l in soup.find_all("link", href=True)]
        all_assets = " ".join(scripts + links)
        body_html = resp.text

        js_detections = [
            ("React", [r"react[.\-]", r"__NEXT_DATA__", r"_react"]),
            ("Vue.js", [r"vue[.\-]", r"__VUE__"]),
            ("Angular", [r"angular[.\-]", r"ng-version"]),
            ("jQuery", [r"jquery[.\-\d]"]),
            ("Bootstrap", [r"bootstrap[.\-]"]),
            ("Tailwind CSS", [r"tailwind"]),
            ("Svelte", [r"svelte"]),
            ("Nuxt.js", [r"nuxt", r"__NUXT__"]),
            ("Next.js", [r"_next/", r"__NEXT"]),
            ("Gatsby", [r"gatsby"]),
            ("Font Awesome", [r"font-awesome|fontawesome"]),
            ("Google Tag Manager", [r"googletagmanager"]),
            ("Google Analytics", [r"google-analytics|gtag|analytics\.js"]),
        ]

        for name, patterns in js_detections:
            for pat in patterns:
                if re.search(pat, all_assets, re.I) or re.search(pat, body_html, re.I):
                    techs.append({"name": name, "version": "", "category": "JS/CSS"})
                    break

        # WordPress en assets
        if "wp-content" in all_assets or "wp-includes" in all_assets:
            self.results["is_wordpress"] = True

        # Comentarios HTML
        for c in soup.find_all(string=lambda text: isinstance(text, Comment)):
            if "wordpress" in c.lower():
                self.results["is_wordpress"] = True

        self.results["technologies"] = techs

    # ── WordPress: Versión ────────────────────────────────────────────────

    def detect_wp_version(self):
        """Múltiples métodos para detectar la versión de WordPress."""
        if self.results["version"]:
            return

        # Feed RSS
        resp = self._get("/feed/")
        if resp and resp.status_code == 200:
            m = re.search(r"<generator>.*?wordpress.*?([\d.]+).*?</generator>", resp.text, re.I)
            if m:
                self.results["version"] = m.group(1)
                return

        # readme.html
        resp = self._get("/readme.html")
        if resp and resp.status_code == 200:
            m = re.search(r"Version\s+([\d.]+)", resp.text)
            if m:
                self.results["version"] = m.group(1)
                return

        # wp-links-opml.php
        resp = self._get("/wp-links-opml.php")
        if resp and resp.status_code == 200:
            m = re.search(r'generator="WordPress/([\d.]+)"', resp.text)
            if m:
                self.results["version"] = m.group(1)
                return

        # Hashes de archivos estáticos (ver= param)
        resp = self._get()
        if resp:
            matches = re.findall(r"ver=([\d.]+)", resp.text)
            if matches:
                most_common = Counter(matches).most_common(1)
                if most_common:
                    self.results["version"] = most_common[0][0] + " (probable)"

    # ── WordPress: Tema activo ────────────────────────────────────────────

    def detect_wp_theme(self):
        """Detecta el tema activo de WordPress."""
        resp = self._get()
        if not resp:
            return

        matches = re.findall(r"/wp-content/themes/([a-zA-Z0-9_-]+)/", resp.text)
        if not matches:
            return

        theme_slug = Counter(matches).most_common(1)[0][0]
        theme_info = {"name": theme_slug, "version": "", "author": "", "uri": ""}

        style_resp = self._get(f"/wp-content/themes/{theme_slug}/style.css")
        if style_resp and style_resp.status_code == 200:
            for field, pattern in [
                ("version", r"Version:\s*(.+)"),
                ("author", r"Author:\s*(.+)"),
                ("uri", r"Theme URI:\s*(.+)"),
                ("description", r"Description:\s*(.+)"),
            ]:
                m = re.search(pattern, style_resp.text, re.I)
                if m:
                    theme_info[field] = m.group(1).strip()

        self.results["theme"] = theme_info

    # ── WordPress: Plugins ────────────────────────────────────────────────

    def detect_wp_plugins(self):
        """Enumera plugins de WordPress por múltiples métodos."""
        found_plugins = {}

        # Método 1: Extraer del HTML de la página principal
        resp = self._get()
        if resp:
            for p in set(re.findall(r"/wp-content/plugins/([a-zA-Z0-9_-]+)/", resp.text)):
                found_plugins[p] = {"name": p, "version": "", "method": "HTML source"}

        # Método 2: Fuerza bruta contra plugins conocidos
        def check_plugin(slug):
            resp = self._get(f"/wp-content/plugins/{slug}/readme.txt")
            if resp and resp.status_code == 200 and "==" in resp.text:
                version = ""
                m = re.search(r"Stable tag:\s*([\d.]+)", resp.text, re.I)
                if m:
                    version = m.group(1)
                return slug, {"name": slug, "version": version, "method": "readme.txt"}
            dir_resp = self._get(f"/wp-content/plugins/{slug}/")
            if dir_resp and dir_resp.status_code in (200, 403):
                return slug, {"name": slug, "version": "", "method": "directory probe"}
            return None, None

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(check_plugin, s): s for s in COMMON_WP_PLUGINS}
            for future in concurrent.futures.as_completed(futures):
                slug, info = future.result()
                if slug and slug not in found_plugins:
                    found_plugins[slug] = info

        self.results["plugins"] = list(found_plugins.values())

    # ── WordPress: Usuarios ───────────────────────────────────────────────

    def enumerate_wp_users(self):
        """Enumera usuarios mediante la REST API y author archives."""
        users = []

        # REST API
        resp = self._get("/wp-json/wp/v2/users")
        if resp and resp.status_code == 200:
            try:
                for u in resp.json():
                    users.append({
                        "id": u.get("id"),
                        "name": u.get("name"),
                        "slug": u.get("slug"),
                        "description": u.get("description", "")[:80],
                        "method": "REST API",
                    })
            except (json.JSONDecodeError, TypeError):
                pass

        # Author enumeration (IDs 1-10)
        if not users:
            for uid in range(1, 11):
                resp = self._get(f"/?author={uid}", allow_redirects=True)
                if resp and resp.status_code == 200:
                    slug_match = re.search(r"/author/([^/]+)", resp.url)
                    if slug_match:
                        slug = slug_match.group(1)
                        if not any(u["slug"] == slug for u in users):
                            users.append({
                                "id": uid, "name": slug, "slug": slug,
                                "description": "", "method": "author archive",
                            })

        self.results["users"] = users

    # ── WordPress: Endpoints ──────────────────────────────────────────────

    def scan_endpoints(self):
        """Verifica la existencia de endpoints comunes."""
        endpoints = []

        def check_endpoint(path):
            resp = self._get(path, allow_redirects=False)
            if resp is None:
                return None
            status = resp.status_code
            if status in (200, 301, 302, 403):
                size = len(resp.content) if resp.content else 0
                redir = resp.headers.get("Location", "") if status in (301, 302) else ""
                note = ""
                if path == "/wp-content/debug.log" and status == 200 and size > 0:
                    note = "⚠ DEBUG LOG EXPUESTO"
                elif "config" in path and status == 200:
                    note = "⚠ POSIBLE CONFIG EXPUESTA"
                elif path == "/xmlrpc.php" and status == 200:
                    note = "⚠ XML-RPC habilitado"
                elif "install.php" in path and status == 200:
                    note = "⚠ Instalador accesible"
                elif "setup-config" in path and status == 200:
                    note = "⚠ Setup accesible"
                return {"path": path, "status": status, "size": size, "redirect": redir, "note": note}
            return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(check_endpoint, ep): ep for ep in WP_ENDPOINTS}
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    endpoints.append(result)

        endpoints.sort(key=lambda x: x["path"])
        self.results["endpoints"] = endpoints

    # ── REST API Discovery ────────────────────────────────────────────────

    def discover_rest_api(self):
        """Descubre namespaces y rutas disponibles en la REST API."""
        resp = self._get("/wp-json/")
        if not resp or resp.status_code != 200:
            return
        try:
            data = resp.json()
        except (json.JSONDecodeError, TypeError):
            return

        self.results["meta_info"]["site_name"] = data.get("name", "")
        self.results["meta_info"]["site_description"] = data.get("description", "")
        self.results["meta_info"]["wp_url"] = data.get("url", "")
        self.results["meta_info"]["timezone"] = data.get("timezone_string", "")
        namespaces = data.get("namespaces", [])
        self.results["meta_info"]["api_namespaces"] = namespaces

        ns_plugins = {
            "wc/": "WooCommerce", "jetpack": "Jetpack",
            "yoast": "Yoast SEO", "elementor": "Elementor",
            "contact-form-7": "Contact Form 7", "wpforms": "WPForms",
            "wordfence": "Wordfence", "redirection": "Redirection",
            "acf": "Advanced Custom Fields", "rankmath": "Rank Math",
            "bbpress": "bbPress", "buddypress": "BuddyPress",
            "tribe": "The Events Calendar",
        }
        existing = {p["name"].lower().replace(" ", "-") for p in self.results["plugins"]}
        for ns in namespaces:
            for key, name in ns_plugins.items():
                if key in ns.lower() and name.lower().replace(" ", "-") not in existing:
                    self.results["plugins"].append({
                        "name": name, "version": "", "method": f"REST namespace: {ns}",
                    })
                    existing.add(name.lower().replace(" ", "-"))

    # ── Ejecución completa ────────────────────────────────────────────────

    def run(self, full_scan: bool = True):
        """Ejecuta el escaneo completo."""
        with Progress(
            SpinnerColumn(), TextColumn("[bold blue]{task.description}"), console=console,
        ) as progress:
            task = progress.add_task("Detectando tecnologías...", total=None)
            self.detect_technologies()

            if self.results["is_wordpress"]:
                progress.update(task, description="WordPress detectado — obteniendo versión...")
                self.detect_wp_version()

                progress.update(task, description="Detectando tema activo...")
                self.detect_wp_theme()

                progress.update(task, description="Descubriendo REST API...")
                self.discover_rest_api()

                if full_scan:
                    progress.update(task, description="Enumerando plugins (puede tardar)...")
                    self.detect_wp_plugins()

                    progress.update(task, description="Enumerando usuarios...")
                    self.enumerate_wp_users()

                progress.update(task, description="Escaneando endpoints...")
                self.scan_endpoints()

            progress.update(task, description="[green]Escaneo completado ✓")

    # ── Salida formateada ─────────────────────────────────────────────────

    def print_results(self):
        """Imprime los resultados con formato rich."""
        r = self.results
        console.print()
        console.print(Panel.fit(
            f"[bold cyan]WP Recon[/bold cyan] — Resultados para [bold]{r['url']}[/bold]",
            border_style="cyan",
        ))

        # Info general
        tbl = Table(title="Información General", box=box.ROUNDED, show_header=False, border_style="blue")
        tbl.add_column("Campo", style="bold", width=25)
        tbl.add_column("Valor")
        tbl.add_row("URL", r["url"])
        tbl.add_row("WordPress", "[green]Sí[/green]" if r["is_wordpress"] else "[yellow]No detectado[/yellow]")
        if r["version"]:
            tbl.add_row("Versión WP", f"[bold]{r['version']}[/bold]")
        for key in ("site_name", "site_description", "generator", "timezone"):
            val = r["meta_info"].get(key)
            if val:
                tbl.add_row(key.replace("_", " ").title(), val)
        console.print(tbl)

        # Headers
        tbl = Table(title="Headers del Servidor", box=box.ROUNDED, show_header=False, border_style="blue")
        tbl.add_column("Header", style="bold", width=30)
        tbl.add_column("Valor")
        for key, val in r["headers"].items():
            style = "red" if val in ("No configurado", "No expuesto") else ""
            tbl.add_row(key, f"[{style}]{val}[/{style}]" if style else val)
        console.print(tbl)

        # Tecnologías
        if r["technologies"]:
            tbl = Table(title="Tecnologías Detectadas", box=box.ROUNDED, border_style="green")
            tbl.add_column("Tecnología", style="bold")
            tbl.add_column("Versión")
            tbl.add_column("Categoría", style="dim")
            seen = set()
            for t in r["technologies"]:
                if t["name"] not in seen:
                    seen.add(t["name"])
                    tbl.add_row(t["name"], t["version"] or "—", t["category"])
            console.print(tbl)

        # Tema
        if r["theme"]:
            t = r["theme"]
            tbl = Table(title="Tema Activo", box=box.ROUNDED, show_header=False, border_style="magenta")
            tbl.add_column("Campo", style="bold", width=20)
            tbl.add_column("Valor")
            tbl.add_row("Nombre", f"[bold]{t['name']}[/bold]")
            for f in ("version", "author", "uri", "description"):
                if t.get(f):
                    tbl.add_row(f.capitalize(), t[f])
            console.print(tbl)

        # Plugins
        if r["plugins"]:
            tbl = Table(title=f"Plugins Detectados ({len(r['plugins'])})", box=box.ROUNDED, border_style="yellow")
            tbl.add_column("#", style="dim", width=4)
            tbl.add_column("Plugin", style="bold")
            tbl.add_column("Versión")
            tbl.add_column("Método", style="dim")
            for i, p in enumerate(sorted(r["plugins"], key=lambda x: x["name"]), 1):
                tbl.add_row(str(i), p["name"], p["version"] or "—", p["method"])
            console.print(tbl)

        # Usuarios
        if r["users"]:
            tbl = Table(title="Usuarios Detectados", box=box.ROUNDED, border_style="red")
            tbl.add_column("ID", width=5)
            tbl.add_column("Nombre", style="bold")
            tbl.add_column("Slug")
            tbl.add_column("Método", style="dim")
            for u in r["users"]:
                tbl.add_row(str(u["id"]), u["name"], u["slug"], u["method"])
            console.print(tbl)

        # Endpoints
        if r["endpoints"]:
            tbl = Table(title="Endpoints Encontrados", box=box.ROUNDED, border_style="cyan")
            tbl.add_column("Path", style="bold")
            tbl.add_column("Status", width=8)
            tbl.add_column("Tamaño", width=10)
            tbl.add_column("Nota", style="bold red")
            for ep in r["endpoints"]:
                sc = "green" if ep["status"] == 200 else "yellow" if ep["status"] in (301, 302) else "red"
                size = f"{ep['size']:,} B" if ep["size"] else "—"
                tbl.add_row(ep["path"], f"[{sc}]{ep['status']}[/{sc}]", size, ep["note"])
            console.print(tbl)

        # API Namespaces
        ns = r["meta_info"].get("api_namespaces", [])
        if ns:
            tbl = Table(title="REST API Namespaces", box=box.ROUNDED, border_style="blue")
            tbl.add_column("Namespace")
            for n in sorted(ns):
                tbl.add_row(n)
            console.print(tbl)

        console.print()

    def export_json(self, filepath: str):
        """Exporta los resultados a un archivo JSON."""
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(self.results, f, indent=2, ensure_ascii=False)
        console.print(f"\n[green]✓ Resultados exportados a {filepath}[/green]")


# ─── CLI ──────────────────────────────────────────────────────────────────────

def interactive_menu():
    """Menú interactivo cuando se ejecuta sin argumentos."""
    console.print(Panel.fit(
        "[bold cyan]WP Recon[/bold cyan] — WordPress & Web Technology Scanner\n"
        "[dim]Herramienta de reconocimiento de tecnologías web[/dim]",
        border_style="cyan",
    ))
    console.print()

    # Pedir URL
    url = console.input("[bold green]🌐 Ingresa el dominio o URL a escanear:[/bold green] ").strip()
    if not url:
        console.print("[red]✗ Debes ingresar un dominio.[/red]")
        sys.exit(1)

    # Limpiar: quitar www. si lo puso, agregar https si falta
    url = url.strip("/")
    if url.startswith("www."):
        url = url[4:]
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    console.print()
    console.print("[bold yellow]Tipo de escaneo:[/bold yellow]")
    console.print("  [cyan]1[/cyan] — Completo (detecta plugins por fuerza bruta, más lento)")
    console.print("  [cyan]2[/cyan] — Rápido (solo lo visible en HTML y REST API)")
    console.print()
    scan_choice = console.input("[bold green]Elige [1/2] (default: 1):[/bold green] ").strip()
    full_scan = scan_choice != "2"

    console.print()
    threads_input = console.input("[bold green]Hilos concurrentes [1-50] (default: 10):[/bold green] ").strip()
    try:
        threads = max(1, min(50, int(threads_input))) if threads_input else 10
    except ValueError:
        threads = 10

    console.print()
    export_input = console.input("[bold green]¿Exportar a JSON? Escribe la ruta o deja vacío para no:[/bold green] ").strip()

    console.print()

    # Ejecutar
    scanner = WPRecon(url, timeout=DEFAULT_TIMEOUT, threads=threads)
    scanner.run(full_scan=full_scan)
    scanner.print_results()

    if export_input:
        scanner.export_json(export_input)

    # Preguntar si quiere escanear otro
    console.print()
    again = console.input("[bold green]¿Escanear otro sitio? [s/N]:[/bold green] ").strip().lower()
    if again in ("s", "si", "sí", "y", "yes"):
        console.print()
        interactive_menu()


def main():
    # Si se pasan argumentos, modo CLI clásico; si no, interactivo
    if len(sys.argv) > 1:
        parser = argparse.ArgumentParser(
            description="WP Recon — Scanner de tecnologías web con enfoque WordPress",
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
Ejemplos:
  python3 wp_recon.py https://example.com
  python3 wp_recon.py example.com --quick
  python3 wp_recon.py example.com --threads 20 --json report.json
            """,
        )
        parser.add_argument("url", help="URL del sitio web a escanear")
        parser.add_argument("--quick", "-q", action="store_true",
                            help="Escaneo rápido (sin fuerza bruta de plugins)")
        parser.add_argument("--json", "-j", metavar="FILE",
                            help="Exportar resultados a archivo JSON")
        parser.add_argument("--threads", "-t", type=int, default=10,
                            help="Hilos concurrentes (default: 10)")
        parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT,
                            help=f"Timeout en segundos (default: {DEFAULT_TIMEOUT})")

        args = parser.parse_args()

        console.print(Panel.fit(
            "[bold cyan]WP Recon[/bold cyan] — WordPress & Web Technology Scanner\n"
            "[dim]Herramienta de reconocimiento de tecnologías web[/dim]",
            border_style="cyan",
        ))

        scanner = WPRecon(args.url, timeout=args.timeout, threads=args.threads)
        scanner.run(full_scan=not args.quick)
        scanner.print_results()

        if args.json:
            scanner.export_json(args.json)
    else:
        interactive_menu()


if __name__ == "__main__":
    main()
