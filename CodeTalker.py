from scapy.all import *
import sys

def send_icmp_packets(message, target_ip):
    for char in message:
        # Codificar el carácter como un byte (ASCII)
        packet = IP(dst=target_ip) / ICMP() / Raw(load=bytes([ord(char)]))
        # Enviar el paquete
        send(packet)
        print(f"Enviando paquete con el carácter: {char}")

if __name__ == "__main__":
    # Obtener la dirección IP del destino y el mensaje a enviar desde la consola
    if len(sys.argv) != 3:
        print("Uso: python3 send_icmp.py <dirección IP> <mensaje>")
        sys.exit(1)

    target_ip = sys.argv[1]
    message = sys.argv[2]

    send_icmp_packets(message, target_ip)