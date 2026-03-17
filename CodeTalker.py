import socket
import struct
import time
import os
import sys

ICMP_ECHO_REQUEST = 8

def checksum(data):
    s = 0
    for i in range(0, len(data), 2):
        part = data[i] + (data[i+1] << 8) if i+1 < len(data) else data[i]
        s += part
    s = (s >> 16) + (s & 0xffff)
    s += (s >> 16)
    return ~s & 0xffff

def create_packet(seq, char):
    pid = os.getpid() & 0xFFFF
    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, 0, pid, seq)
    data = char.encode('utf-8')

    chksum = checksum(header + data)
    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, socket.htons(chksum), pid, seq)
    
    return header + data

def send_string_icmp(dest_ip, message, delay=0.5):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    except PermissionError:
        print("Necesitas ejecutar como root/administrador.")
        return

    for seq, char in enumerate(message):
        packet = create_packet(seq, char)
        sock.sendto(packet, (dest_ip, 1))
        print(f"Enviado: '{char}' (seq={seq})")
        time.sleep(delay)

    sock.close()

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print(f"Uso: sudo python3 {sys.argv[0]} <IP_DESTINO> <MENSAJE>")
        sys.exit(1)

    destino = sys.argv[1]
    mensaje = sys.argv[2]

    send_string_icmp(destino, mensaje)