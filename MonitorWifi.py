#!/usr/bin/env python3
import argparse
import ast
import ipaddress
import json
import sys
from datetime import datetime
from pathlib import Path

try:import nmap
except ImportError:sys.exit("Error: falta python-nmap. Instala con: pip install python-nmap")

def ordenar(ips):return sorted(ips, key=ipaddress.ip_address)

base = Path(__file__).resolve().parent
parser = argparse.ArgumentParser(description="Detector de IPs no autorizadas en la red")
parser.add_argument("-r", "--red", default="192.168.20.0/24",help="red a escanear (por defecto 192.168.20.0/24)")
parser.add_argument("-f", "--archivo", default=str(base / "IPermitidas.json"),help="archivo JSON con las IPs permitidas")
parser.add_argument("-o", "--salida", help="guardar el reporte en un archivo JSON")
args = parser.parse_args()

try:ipaddress.ip_network(args.red, strict=False)
except ValueError:sys.exit(f"Error: red inválida '{args.red}'.")

try:texto = Path(args.archivo).read_text(encoding="utf-8")
except FileNotFoundError:sys.exit(f"Error: no se encontró el archivo '{args.archivo}'.")

try:datos = json.loads(texto)
except json.JSONDecodeError:
    try:datos = ast.literal_eval(texto)
    except (ValueError, SyntaxError):sys.exit(f"Error: '{args.archivo}' no tiene un formato de lista válido.")

if not isinstance(datos, list):sys.exit("Error: el archivo debe contener una lista de IPs.")

permitidas = set()
for ip in datos:
    try:permitidas.add(str(ipaddress.ip_address(str(ip).strip())))
    except ValueError:print(f"[?] IP inválida ignorada: {ip}")

print(f"\nEscaneando red: {args.red}")
print(f"IPs permitidas: {len(permitidas)}")

nm = nmap.PortScanner()
try:nm.scan(hosts=args.red, arguments="-sn")
except nmap.PortScannerError as e:sys.exit(f"Error de nmap: {e}\nInstálalo con: pkg install nmap")

activos = {h: nm[h].hostname() for h in nm.all_hosts()}
conectadas = set(activos)

autorizadas = conectadas & permitidas
denegadas = conectadas - permitidas
ausentes = permitidas - conectadas

def etiqueta(ip):return f"{ip} ({activos[ip]})" if activos.get(ip) else ip

print("\nIPs Permitidas:")
for ip in ordenar(autorizadas):print(f"[+] {etiqueta(ip)}: IP Permitida")

print("\nIPs Denegadas:")
if denegadas:
    for ip in ordenar(denegadas):print(f"[!] {etiqueta(ip)}: IP Denegada")
else:print("[✓] No se detectaron dispositivos no autorizados")

if ausentes:
    print("\nPermitidas que no respondieron:")
    for ip in ordenar(ausentes):print(f"[-] {ip}")

if args.salida:
    reporte = {
        "fecha": datetime.now().isoformat(timespec="seconds"),
        "red": args.red,
        "permitidas": ordenar(autorizadas),
        "denegadas": ordenar(denegadas),
        "ausentes": ordenar(ausentes),
    }
    Path(args.salida).write_text(json.dumps(reporte, indent=4, ensure_ascii=False), encoding="utf-8")
    print(f"\nReporte guardado en: {args.salida}")
