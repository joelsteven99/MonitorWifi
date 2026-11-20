import ast, ipaddress, json, sys
from datetime import datetime
from pathlib import Path

try:import nmap
except ImportError:sys.exit("Error: falta python-nmap. Instala con: pip install python-nmap")

base = Path(__file__).resolve().parent

config = {
    "red": "000.000.00.0/24",
    "archivo": str(base / "IPermitidas.json"),
    "salida": None,
}

def Ordenar(ips):return sorted(ips, key=ipaddress.ip_address)

def Pedir(texto, defecto):entrada = input(f"{texto} [{defecto}]: ").strip();return entrada or defecto

def CargarPermitidas(ruta):
    try:texto = Path(ruta).read_text(encoding="utf-8")
    except FileNotFoundError:print(f"[!] No se encontró el archivo '{ruta}'.");return None

    try:datos = json.loads(texto)
    except json.JSONDecodeError:
        try:datos = ast.literal_eval(texto)
        except (ValueError, SyntaxError):print(f"[!] '{ruta}' no tiene un formato de lista válido.");return None

    if not isinstance(datos, list):print("[!] El archivo debe contener una lista de IPs.");return None

    permitidas = set()
    for ip in datos:
        try:permitidas.add(str(ipaddress.ip_address(str(ip).strip())))
        except ValueError:print(f"[?] IP inválida ignorada: {ip}")
    return permitidas

def ConfigurarRed():
    red = Pedir("Red a escanear (CIDR)", config["red"])
    try:ipaddress.ip_network(red, strict=False)
    except ValueError:print(f"[!] Red inválida: '{red}'. Se mantiene {config['red']}.");return
    config["red"] = red
    print(f"[✓] Red configurada: {red}")

def ConfigurarArchivo():
    ruta = Pedir("Archivo JSON de IPs permitidas", config["archivo"])
    if not Path(ruta).is_file():print(f"[!] No se encontró '{ruta}'. Se mantiene {config['archivo']}.");return
    config["archivo"] = ruta
    print(f"[✓] Archivo configurado: {ruta}")

def ConfigurarSalida():
    ruta = input("Archivo de reporte JSON (vacío = no guardar): ").strip()
    config["salida"] = ruta or None
    if ruta:print(f"[✓] El reporte se guardará en: {ruta}")
    else:print("[✓] No se guardará reporte.")

def VerPermitidas():
    permitidas = CargarPermitidas(config["archivo"])
    if permitidas is None:return
    print(f"\nIPs permitidas ({len(permitidas)}):")
    for ip in Ordenar(permitidas):print(f"  - {ip}")

def Escanear():
    permitidas = CargarPermitidas(config["archivo"])
    if permitidas is None:return

    print(f"\nEscaneando red: {config['red']}")
    print(f"IPs permitidas: {len(permitidas)}")

    nm = nmap.PortScanner()
    try:nm.scan(hosts=config["red"], arguments="-sn")
    except nmap.PortScannerError as e:print(f"[!] Error de nmap: {e}\n    Instálalo con: pkg install nmap");return

    activos = {h: nm[h].hostname() for h in nm.all_hosts()}
    conectadas = set(activos)

    autorizadas = conectadas & permitidas
    denegadas = conectadas - permitidas
    ausentes = permitidas - conectadas

    def Etiqueta(ip):return f"{ip} ({activos[ip]})" if activos.get(ip) else ip

    print("\nIPs Permitidas:")
    for ip in Ordenar(autorizadas):print(f"[+] {Etiqueta(ip)}: IP Permitida")

    print("\nIPs Denegadas:")
    if denegadas:
        for ip in Ordenar(denegadas):print(f"[!] {Etiqueta(ip)}: IP Denegada")
    else:print("[✓] No se detectaron dispositivos no autorizados")

    if ausentes:
        print("\nPermitidas que no respondieron:")
        for ip in Ordenar(ausentes):print(f"[-] {ip}")

    if config["salida"]:
        reporte = {
            "fecha": datetime.now().isoformat(timespec="seconds"),
            "red": config["red"],
            "permitidas": Ordenar(autorizadas),
            "denegadas": Ordenar(denegadas),
            "ausentes": Ordenar(ausentes),
        }
        Path(config["salida"]).write_text(json.dumps(reporte, indent=4, ensure_ascii=False), encoding="utf-8")
        print(f"\nReporte guardado en: {config['salida']}")

while True:
    print("\n" + "=" * 46)
    print(" MONITOR WIFI")
    print("=" * 46)
    print(f"  Red     : {config['red']}")
    print(f"  Archivo : {config['archivo']}")
    print(f"  Reporte : {config['salida'] or '(no se guarda)'}")
    print("-" * 46)
    print("  1. Cambiar red a escanear")
    print("  2. Cambiar archivo de IPs permitidas")
    print("  3. Configurar archivo de reporte")
    print("  4. Ver IPs permitidas cargadas")
    print("  5. Ejecutar escaneo")
    print("  0. Salir")
    print("=" * 46)

    try:opcion = input("Selecciona una opción: ").strip()
    except (EOFError, KeyboardInterrupt):print("\nHasta luego.");break
    match opcion:
        case 1:ConfigurarRed()
        case 2:ConfigurarArchivo()
        case 3:ConfigurarSalida()
        case 4:VerPermitidas()
        case 5:Escanear()
        case 0:print("Hasta luego.");break
        case _:print("[!] Opción no válida.")
