import errno, ipaddress, json, re, socket, subprocess, time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path

PUERTOS = (80, 443, 22, 445, 139, 8080, 62078)
MAX_HOSTS = 4096
base = Path(__file__).resolve().parent

config = {
    "hilos": 100,
    "archivo": str(base / "IPsActivas.json"),
}

resultados = {"fecha": None, "red": None, "propia": None, "ips": [], "arp": {}}

def IpLocal():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:s.connect(("10.255.255.255", 1));return s.getsockname()[0]
    except OSError:return None
    finally:s.close()

def RedLocal():
    ip = IpLocal()
    if not ip:print("[!] No se pudo detectar tu IP local. ¿Estás conectado a una red?");return None
    prefijo = 24
    try:
        salida = subprocess.run(["ip", "-4", "-o", "addr", "show"],capture_output=True, text=True, timeout=5).stdout
        m = re.search(rf"inet {re.escape(ip)}/(\d+)", salida)
        if m:prefijo = int(m.group(1))
    except (FileNotFoundError, subprocess.TimeoutExpired):pass
    if prefijo < 24:print(f"[*] Tu red es /{prefijo}; se limitará a /24 alrededor de {ip}");prefijo = 24
    return ipaddress.ip_network(f"{ip}/{prefijo}", strict=False), ip

def LeerArp():
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

def EstaVivo(ip):
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

def MostrarResultados():
    if not resultados["ips"]:print("\n[!] Aún no hay resultados. Ejecuta un escaneo primero.");return
    print(f"\nIPs activas en {resultados['red']} ({resultados['fecha']}):")
    print(f"{'IP':<16} {'MAC':<18} Nota")
    print("-" * 44)
    for ip in resultados["ips"]:
        nota = "(este dispositivo)" if ip == resultados["propia"] else ""
        print(f"{ip:<16} {resultados['arp'].get(ip, '-'):<18} {nota}")
    print(f"\n[*] {len(resultados['ips'])} dispositivos activos")

def EscanearRed(red, propia=None):
    hosts = [red.network_address] if red.num_addresses == 1 else list(red.hosts())
    if len(hosts) > MAX_HOSTS:print(f"[!] Red demasiado grande ({len(hosts)} hosts). Máximo: {MAX_HOSTS}.");return
    print(f"[*] Escaneando {red} ({len(hosts)} direcciones)...")
    t0 = time.time()
    with ThreadPoolExecutor(max_workers=config["hilos"]) as pool:estados = list(pool.map(EstaVivo, hosts))
    vivos = {str(h) for h, ok in zip(hosts, estados) if ok}
    if propia and ipaddress.ip_address(propia) in red:vivos.add(propia)
    resultados["fecha"] = datetime.now().isoformat(timespec="seconds")
    resultados["red"] = str(red)
    resultados["propia"] = propia
    resultados["arp"] = LeerArp()
    resultados["ips"] = sorted(vivos, key=ipaddress.ip_address)
    MostrarResultados()
    print(f"[*] Tiempo: {time.time() - t0:.1f}s")

def EscanearActual():
    datos = RedLocal()
    if datos:EscanearRed(datos[0], datos[1])

def EscanearEspecifica():
    texto = input("Red a escanear (CIDR, ej: 192.168.1.0/24): ").strip()
    try:red = ipaddress.ip_network(texto, strict=False)
    except ValueError:print(f"[!] Red inválida: '{texto}' (usa formato CIDR, ej: 192.168.1.0/24)");return
    EscanearRed(red)

def CambiarHilos():
    texto = input(f"Hilos en paralelo [{config['hilos']}]: ").strip()
    if not texto:return
    if not texto.isdigit() or not 1 <= int(texto) <= 500:print("[!] Ingresa un número entre 1 y 500.");return
    config["hilos"] = int(texto)
    print(f"[✓] Hilos configurados: {config['hilos']}")

def CambiarArchivo():
    ruta = input(f"Archivo JSON de salida [{config['archivo']}]: ").strip()
    if not ruta:return
    if not ruta.lower().endswith(".json"):ruta += ".json"
    config["archivo"] = ruta
    print(f"[✓] Archivo configurado: {ruta}")

def ConfirmarSobrescritura(ruta):
    if not Path(ruta).exists():return True
    return input(f"[?] '{ruta}' ya existe. ¿Sobrescribir? (s/N): ").strip().lower() == "s"

def EscribirJson(ruta, datos):
    if not ConfirmarSobrescritura(ruta):print("[*] Guardado cancelado.");return
    try:
        Path(ruta).write_text(json.dumps(datos, indent=4, ensure_ascii=False),encoding="utf-8")
        print(f"[✓] Archivo guardado en: {ruta}")
    except OSError as e:print(f"[!] No se pudo guardar el archivo: {e}")

def GuardarMonitor():
    if not resultados["ips"]:print("[!] Aún no hay resultados. Ejecuta un escaneo primero.");return
    EscribirJson(config["archivo"], list(resultados["ips"]))
    print("[i] Revisa la lista antes de usarla como IPs permitidas: todo lo que esté conectado ahora quedaría autorizado.")

def GuardarDetallado():
    if not resultados["ips"]:print("[!] Aún no hay resultados. Ejecuta un escaneo primero.");return
    destino = str(Path(config["archivo"]).with_name(Path(config["archivo"]).stem + "_detalle.json"))
    datos = {
        "fecha": resultados["fecha"],
        "red": resultados["red"],
        "total": len(resultados["ips"]),
        "dispositivos": [
            {
                "ip": ip,
                "mac": resultados["arp"].get(ip),
                "nota": "este dispositivo" if ip == resultados["propia"] else "",
            }
            for ip in resultados["ips"]
        ],
    }
    EscribirJson(destino, datos)


while True:
    print("\n" + "=" * 46)
    print("        SCAN DE IPs EN LA RED")
    print("=" * 46)
    print(f"  Hilos   : {config['hilos']}")
    print(f"  Archivo : {config['archivo']}")
    print(f"  Última  : {resultados['red'] or '(sin escaneos)'}"
          f"{' - ' + str(len(resultados['ips'])) + ' IPs' if resultados['ips'] else ''}")
    print("-" * 46)
    print("  1. Escanear la red a la que estoy conectado")
    print("  2. Escanear una red específica")
    print("  3. Ver últimos resultados")
    print("  4. Guardar JSON para el monitor (lista de IPs)")
    print("  5. Guardar JSON detallado (IP, MAC, nota)")
    print("  6. Cambiar hilos")
    print("  7. Cambiar archivo de salida")
    print("  0. Salir")
    print("=" * 46)

    try:opcion = input("Selecciona una opción: ").strip()
    except (EOFError, KeyboardInterrupt):print("\n[!] Operación cancelada.");print("\nHasta luego.");break

    match opcion:
        case "1":EscanearActual()
        case "2":EscanearEspecifica()
        case "3":MostrarResultados()
        case "4":GuardarMonitor()
        case "5":GuardarDetallado()
        case "6":CambiarHilos()
        case "7":CambiarArchivo()
        case "0":print("Hasta luego.");break
        case _:print("[!] Opción no válida.")
