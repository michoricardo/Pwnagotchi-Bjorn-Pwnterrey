"""""
upload_pcap.py — Sube archivos PCAP a wpa-sec.stanev.org y correlaciona los resultados.

============================  REQUISITOS  ============================
  pip install requests

============================  TU API KEY  ============================
  Para obtener tu clave:
    1. Ve a https://wpa-sec.stanev.org
    2. Inicia sesión o regístrate.
    3. Tu clave es el valor de la cookie 'key' (también visible en el perfil).

============================  EJEMPLOS DE USO  ======================

  # Subir todos los archivos .pcap de una carpeta:
  python upload_pcap.py --key TU_CLAVE upload --folder C:\ruta\a\pcaps

  # Ver redes crackeadas y correlacionar con tus archivos locales:
  python upload_pcap.py --key TU_CLAVE results --folder C:\ruta\a\pcaps

  # Subir archivos Y mostrar resultados al terminar:
  python upload_pcap.py --key TU_CLAVE upload --folder C:\ruta\a\pcaps --results

  # Hacer una prueba sin subir nada (solo muestra qué subiría):
  python upload_pcap.py --key TU_CLAVE upload --folder C:\ruta\a\pcaps --dry-run

============================  OPCIONES PRINCIPALES  =================
  --delay SEGUNDOS    Espera entre subidas (por defecto: 5 s). Auméntalo si
                      quieres ser más respetuoso con el servidor.
  --dry-run           Simula la subida sin enviar nada.
  --state ARCHIVO     JSON donde se guardan los archivos ya subidos
                      (por defecto: uploaded.json). Permite reanudar si se
                      interrumpe el proceso.

============================  CORRELACIÓN  ==========================
  El script extrae el BSSID del nombre del archivo
  (ej. MIGARZASADA_0019be81fad9.pcap → 00:19:be:81:fa:d9)
  y lo compara con los resultados de ?my_nets para mostrarte
  directamente qué contraseña se encontró para cada captura.
"""

import argparse
import json
import os
import re
import sys
import time
from pathlib import Path

import requests

BASE_URL = "https://wpa-sec.stanev.org"
SUBMIT_URL = f"{BASE_URL}/?submit"
MY_NETS_URL = f"{BASE_URL}/?my_nets"

HEADERS = {
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Origin": BASE_URL,
    "Referer": SUBMIT_URL,
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36"
    ),
}

# ── Filename parsing ───────────────────────────────────────────────────────────
# Expected pattern:  <ESSID>_<BSSID_no_colons>.pcap
# Example:           1930GARZASADA_0019be81fad9.pcap  →  00:19:be:81:fa:d9
BSSID_RE = re.compile(r"_([0-9a-fA-F]{12})\.pcap$", re.IGNORECASE)


def parse_bssid_from_filename(filename: str) -> str | None:
    """Return colon-separated BSSID from a filename, or None if not found."""
    m = BSSID_RE.search(filename)
    if not m:
        return None
    raw = m.group(1).lower()
    return ":".join(raw[i : i + 2] for i in range(0, 12, 2))


def parse_essid_from_filename(filename: str) -> str | None:
    """Return the ESSID portion of the filename (everything before the last '_BSSID')."""
    stem = Path(filename).stem
    idx = stem.rfind("_")
    if idx == -1:
        return None
    candidate = stem[idx + 1 :]
    if re.fullmatch(r"[0-9a-fA-F]{12}", candidate):
        return stem[:idx]
    return None


# ── State helpers ──────────────────────────────────────────────────────────────

def load_state(path: str) -> set:
    """Return set of already-uploaded filenames."""
    if not os.path.exists(path):
        return set()
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return set(data.get("uploaded", []))
    except (json.JSONDecodeError, KeyError):
        return set()


def save_state(path: str, uploaded: set) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump({"uploaded": sorted(uploaded)}, f, indent=2)


# ── Upload ─────────────────────────────────────────────────────────────────────

def upload_file(session: requests.Session, pcap_path: Path, dry_run: bool) -> bool:
    """Upload a single PCAP file. Returns True on success."""
    if dry_run:
        print(f"  [simulación] Se subiría: {pcap_path.name}")
        return True

    try:
        with open(pcap_path, "rb") as fh:
            files = {"webfile": (pcap_path.name, fh, "application/octet-stream")}
            resp = session.post(SUBMIT_URL, files=files, headers=HEADERS, timeout=60)

        if resp.status_code == 200:
            # The site returns 200 even on errors; check for known error strings
            body = resp.text.lower()
            if "error" in body and "upload" in body:
                print(f"  [AVISO] El servidor reportó un error con {pcap_path.name}")
                print(f"          Fragmento de respuesta: {resp.text[:300]}")
                return False
            print(f"  [OK] Subido: {pcap_path.name}")
            return True
        else:
            print(f"  [FALLO] HTTP {resp.status_code} para {pcap_path.name}")
            return False

    except requests.RequestException as exc:
        print(f"  [ERROR] {pcap_path.name}: {exc}")
        return False


def cmd_upload(args: argparse.Namespace) -> None:
    folder = Path(args.folder)
    if not folder.is_dir():
        sys.exit(f"Carpeta no encontrada: {folder}")

    pcap_files = sorted(folder.glob("*.pcap"))
    if not pcap_files:
        sys.exit(f"No se encontraron archivos .pcap en: {folder}")

    uploaded = load_state(args.state)
    pending = [p for p in pcap_files if p.name not in uploaded]

    print(f"Se encontraron {len(pcap_files)} archivo(s) .pcap, {len(pending)} pendiente(s) de subir.")

    if not pending:
        print("No hay nada que hacer — todos los archivos ya fueron subidos.")
        if args.results:
            cmd_results(args)
        return

    session = requests.Session()
    session.cookies.set("key", args.key, domain="wpa-sec.stanev.org")

    for i, pcap_path in enumerate(pending):
        print(f"[{i + 1}/{len(pending)}] {pcap_path.name}")
        ok = upload_file(session, pcap_path, args.dry_run)
        if ok and not args.dry_run:
            uploaded.add(pcap_path.name)
            save_state(args.state, uploaded)

        if i < len(pending) - 1:
            print(f"  Esperando {args.delay}s antes de la siguiente subida…")
            time.sleep(args.delay)

    print(f"\nListo. {len(uploaded)} archivo(s) registrado(s) como subidos.")

    if args.results:
        cmd_results(args)


# ── Results / correlation ──────────────────────────────────────────────────────

def fetch_my_nets(session: requests.Session) -> list[dict]:
    """
    Download ?my_nets and parse it.
    The endpoint returns CSV-like lines:
        BSSID,ESSID,password[,...]
    Lines starting with '#' are comments.
    """
    try:
        resp = session.get(MY_NETS_URL, headers=HEADERS, timeout=30)
        resp.raise_for_status()
    except requests.RequestException as exc:
        sys.exit(f"Could not fetch {MY_NETS_URL}: {exc}")

    nets = []
    for raw_line in resp.text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(":")
        # Format observed: xx:xx:xx:xx:xx:xx:ESSID:password
        # (6 MAC octets + essid + password = 8 colon-separated tokens minimum)
        if len(parts) >= 8:
            bssid = ":".join(parts[:6]).lower()
            essid = ":".join(parts[6:-1])  # ESSID may contain colons
            password = parts[-1]
            nets.append({"bssid": bssid, "essid": essid, "password": password})
    return nets


def cmd_results(args: argparse.Namespace) -> None:
    folder = Path(args.folder)
    pcap_files = sorted(folder.glob("*.pcap")) if folder.is_dir() else []

    session = requests.Session()
    session.cookies.set("key", args.key, domain="wpa-sec.stanev.org")

    print(f"\nDescargando redes crackeadas desde {MY_NETS_URL} …")
    nets = fetch_my_nets(session)
    print(f"  {len(nets)} red(es) crackeada(s) encontrada(s).")

    if not nets:
        print("Todavía no hay resultados disponibles.")
        return

    # Build lookup: bssid → net
    by_bssid = {n["bssid"]: n for n in nets}

    print("\n── Correlación con archivos PCAP locales ─────────────────────────────────")
    matched = 0
    for pcap_path in pcap_files:
        bssid = parse_bssid_from_filename(pcap_path.name)
        if bssid is None:
            print(f"  [OMITIDO] No se puede extraer el BSSID de: {pcap_path.name}")
            continue
        net = by_bssid.get(bssid)
        if net:
            matched += 1
            print(
                f"  [ENCONTRADO] {pcap_path.name}\n"
                f"               BSSID:      {net['bssid']}\n"
                f"               ESSID:      {net['essid']}\n"
                f"               Contraseña: {net['password']}"
            )
        else:
            print(f"  [PENDIENTE] {pcap_path.name}  (BSSID {bssid} — aún no crackeado)")

    print(f"\n{matched}/{len(pcap_files)} archivo(s) coincidieron con una red crackeada.")

    # Mostrar redes crackeadas que no tienen archivo local
    local_bssids = {
        parse_bssid_from_filename(p.name)
        for p in pcap_files
        if parse_bssid_from_filename(p.name)
    }
    orphans = [n for n in nets if n["bssid"] not in local_bssids]
    if orphans:
        print(f"\n── {len(orphans)} red(es) crackeada(s) sin archivo local ──────────────")
        for n in orphans:
            print(f"  {n['bssid']}  ESSID={n['essid']}  contraseña={n['password']}")


# ── CLI ────────────────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Sube archivos PCAP a wpa-sec.stanev.org y correlaciona los resultados.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--key",
        required=True,
        help="Tu clave de API de wpa-sec (valor de la cookie 'key').",
    )

    sub = parser.add_subparsers(dest="command", required=True)

    # sub-comando upload
    p_upload = sub.add_parser("upload", help="Sube archivos .pcap desde una carpeta.")
    p_upload.add_argument("--folder", default=".", help="Carpeta con los archivos .pcap.")
    p_upload.add_argument(
        "--delay",
        type=float,
        default=5.0,
        help="Segundos de espera entre subidas (por defecto: 5).",
    )
    p_upload.add_argument(
        "--state",
        default="uploaded.json",
        help="Archivo JSON donde se registran los archivos ya subidos (por defecto: uploaded.json).",
    )
    p_upload.add_argument(
        "--dry-run",
        action="store_true",
        help="Simula la subida sin enviar ningún archivo.",
    )
    p_upload.add_argument(
        "--results",
        action="store_true",
        help="Al terminar de subir, descarga y correlaciona los resultados crackeados.",
    )

    # sub-comando results
    p_results = sub.add_parser(
        "results", help="Descarga las redes crackeadas y las cruza con tus archivos locales."
    )
    p_results.add_argument("--folder", default=".", help="Carpeta con los archivos .pcap.")

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if args.command == "upload":
        cmd_upload(args)
    elif args.command == "results":
        cmd_results(args)


if __name__ == "__main__":
    main()
