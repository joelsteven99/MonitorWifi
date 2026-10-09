#!/usr/bin/env python3
import argparse, errno, ipaddress, re, socket, subprocess, sys, time
from concurrent.futures import ThreadPoolExecutor
PUERTOS = (80, 443, 22, 445, 139, 8080, 62078)
MAX_HOSTS = 4096

parser = argparse.ArgumentParser(description="Lista IPs conectadas a una red")
parser.add_argument("-IP", dest="red", metavar="RED",
                    help="red a escanear en formato CIDR, ej: 192.168.1.0/24")
parser.add_argument("-ip", dest="local", action="store_true",
                    help="escanear la red a la que estás conectado")
parser.add_argument("-t", "--hilos", type=int, default=100,
                    help="hilos en paralelo (por defecto 100)")
args = parser.parse_args()

if not args.red and not args.local:parser.print_help();sys.exit(1)

def ip_local():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("10.255.255.255", 1))
        return s.getsockname()[0]
    except OSError:return None
    finally:s.close()

def red_local():
    """Devuelve (red, ip_local) de la red actual. Si no se detecta el prefijo, usa /24."""
    ip = ip_local()
    if not ip:print("[!] No se pudo detectar tu IP local. ¿Estás conectado a una red?");sys.exit(1)
    prefijo = 24
    try:
        salida = subprocess.run(["ip", "-4", "-o", "addr", "show"],capture_output=True, text=True, timeout=5).stdout
        m = re.search(rf"inet {re.escape(ip)}/(\d+)", salida)
        if m:prefijo = int(m.group(1))
    except (FileNotFoundError, subprocess.TimeoutExpired):pass
    if prefijo < 24:print(f"[*] Tu red es /{prefijo}; se limitará a /24 alrededor de {ip}");prefijo = 24
    return ipaddress.ip_network(f"{ip}/{prefijo}", strict=False), ip

def leer_arp():
    tabla = {}
    try:
        with open("/proc/net/arp") as f:
            next(f)
            for linea in f:
                c = linea.split()
                if len(c) >= 4 and c[3] != "00:00:00:00:00:00":tabla[c[0]] = c[3]
    except OSError:pass
    if not tabla:
        try:
            salida = subprocess.run(["ip", "neigh"], capture_output=True,text=True, timeout=5).stdout
            for m in re.finditer(r"^(\d+\.\d+\.\d+\.\d+).*lladdr ([0-9a-f:]{17})",salida, re.M):tabla[m.group(1)] = m.group(2)
        except (FileNotFoundError, subprocess.TimeoutExpired):pass
    return tabla

def esta_vivo(ip):
    ip = str(ip)
    try:
        r = subprocess.run(["ping", "-c", "1", "-W", "1", ip],capture_output=True, timeout=3)
        if r.returncode == 0:return True
    except (FileNotFoundError, subprocess.TimeoutExpired):pass
    for puerto in PUERTOS:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.4)
        try:
            if s.connect_ex((ip, puerto)) in (0, errno.ECONNREFUSED):return True
        except OSError:pass
        finally:s.close()
    return False

def escanear_red(red, propia=None):
    hosts = [red.network_address] if red.num_addresses == 1 else list(red.hosts())
    if len(hosts) > MAX_HOSTS:print(f"[!] Red demasiado grande ({len(hosts)} hosts). Máximo: {MAX_HOSTS}.");return
    print(f"[*] Escaneando {red} ({len(hosts)} direcciones)...")
    t0 = time.time()
    with ThreadPoolExecutor(max_workers=args.hilos) as pool:estados = list(pool.map(esta_vivo, hosts))
    vivos = {str(h) for h, ok in zip(hosts, estados) if ok}
    if propia and ipaddress.ip_address(propia) in red:vivos.add(propia)
    arp = leer_arp()
    print(f"\nIPs activas en {red}:")
    print(f"{'IP':<16} {'MAC':<18} Nota")
    print("-" * 44)
    for ip in sorted(vivos, key=lambda x: ipaddress.ip_address(x)):
        nota = "(este dispositivo)" if ip == propia else ""
        print(f"{ip:<16} {arp.get(ip, '-'):<18} {nota}")
    print(f"\n[*] {len(vivos)} dispositivos activos | {time.time() - t0:.1f}s\n")

try:
    if args.local:
        red, propia = red_local()
        escanear_red(red, propia)
    if args.red:
        try:escanear_red(ipaddress.ip_network(args.red, strict=False))
        except ValueError:print(f"[!] Red inválida: {args.red} (usa formato CIDR, ej: 192.168.1.0/24)");sys.exit(1)
except KeyboardInterrupt:print("\n[!] Escaneo interrumpido por el usuario.")
