from scapy.all import *
import sys
import time
import random

def send_icmp_packets(message, target_ip):
    # Datos personalizados ajustados a 55 bytes
    custom_ping_data = bytes([
        0x52, 0x54, 0x00, 0x12, 0x35, 0x02, 0x08, 0x00, 0x27, 0x7e, 
        0xd3, 0xe8, 0x08, 0x45, 0x00, 0x00, 0x01, 0x00, 0x00, 0x40, 
        0x01, 0xe7, 0xd3, 0x0a, 0x02, 0x00, 0x08, 0x08, 0x00, 0x66, 
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 
        0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 
        0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d,
        0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37
    ])

    # Tomamos los últimos 24 bytes y los primeros 31 bytes
    custom_ping_data = custom_ping_data[:31] + custom_ping_data[-24:]

    # Enviar los paquetes ICMP, uno por cada carácter del mensaje
    for char in message:
        # Crear el paquete ICMP con los datos personalizados + el carácter del mensaje
        packet_data = bytes([ord(char)]) + custom_ping_data  # Concatenar char a los datos personalizados del ping
        
        # Crear el paquete ICMP con el identificador y secuencia apropiados
        packet = IP(dst=target_ip) / ICMP(id=random.randint(0, 65535), seq=random.randint(0, 65535)) / Raw(load=packet_data)
        
        # Enviar el paquete
        send(packet)
        print(f"Enviando paquete con el carácter: {char}")
        
        # Esperar un pequeño intervalo antes de enviar el siguiente paquete (para evitar enviar demasiado rápido)
        time.sleep(0.1)

if __name__ == "__main__":
    # Obtener la dirección IP del destino y el mensaje desde la consola
    if len(sys.argv) != 3:
        print("Uso: python3 CodeTalker.py <dirección IP> <mensaje>")
        sys.exit(1)

    target_ip = sys.argv[1]
    message = sys.argv[2]

    send_icmp_packets(message, target_ip)