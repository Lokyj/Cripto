#!/usr/bin/env python3
import sys
from scapy.all import rdpcap, ICMP, Raw

FRECUENCIAS_ES = {
    'e': 13.68, 'a': 12.53, 'o': 8.68, 's': 7.98, 'r': 6.87,
    'n': 6.71,  'i': 6.25,  'd': 5.86, 'l': 4.97, 'c': 4.68,
    't': 4.63,  'u': 3.93,  'm': 3.15, 'p': 2.51, 'b': 1.42,
    'g': 1.01,  'v': 0.90,  'y': 0.90, 'q': 0.88, 'h': 0.70,
    'f': 0.69,  'z': 0.52,  'j': 0.44, 'x': 0.22, 'k': 0.02, 'w': 0.01
}

COLOR_VERDE = "\033[1;32m"
COLOR_RESET = "\033[0m"

def puntuar_texto(texto):
    return sum(FRECUENCIAS_ES.get(c, 0.0) for c in texto.lower())

def descifrar_cesar(texto, desplazamiento):
    res = []
    for c in texto:
        if 'a' <= c <= 'z':
            res.append(chr((ord(c) - ord('a') - desplazamiento) % 26 + ord('a')))
        elif 'A' <= c <= 'Z':
            res.append(chr((ord(c) - ord('A') - desplazamiento) % 26 + ord('A')))
        else:
            res.append(c)
    return "".join(res)

if len(sys.argv) < 2:
    print(f"Uso: python3 {sys.argv[0]} <archivo.pcap>")
    sys.exit(1)

paquetes = rdpcap(sys.argv[1])
mensajes_por_id = {}

for pkt in paquetes:
    if pkt.haslayer(ICMP) and pkt[ICMP].type == 8 and pkt.haslayer(Raw):
        payload = pkt[Raw].load
        
        # El caracter está en el offset 8 (inicio del campo 'Data (48 bytes)')
        if len(payload) > 8:
            icmp_id = pkt[ICMP].id
            seq = pkt[ICMP].seq
            char = chr(payload[8])
            
            if icmp_id not in mensajes_por_id:
                mensajes_por_id[icmp_id] = {}
            
            mensajes_por_id[icmp_id][seq] = char

for icmp_id, seq_dict in mensajes_por_id.items():
    mensaje_crudo = "".join(seq_dict[seq] for seq in sorted(seq_dict.keys()))
    
    variantes = [
        (rot, descifrar_cesar(mensaje_crudo, rot), puntuar_texto(descifrar_cesar(mensaje_crudo, rot)))
        for rot in range(26)
    ]
    mejor_rot, _, _ = max(variantes, key=lambda x: x[2])
    
    print("=" * 65)
    print(f"[ID ICMP: 0x{icmp_id:04x}] Capturado: '{mensaje_crudo}'")
    print("=" * 65)
    for rot, candidato, _ in variantes:
        if rot == mejor_rot:
            print(f"{COLOR_VERDE}ROT-{rot:<2} | {candidato} <-- [MÁS PROBABLE]{COLOR_RESET}")
        else:
            print(f"ROT-{rot:<2} | {candidato}")
    print()
