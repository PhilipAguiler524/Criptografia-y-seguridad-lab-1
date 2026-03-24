from scapy.all import *
import sys
import string
from collections import Counter
from colorama import Fore, init

# Función para aplicar el cifrado César
def cesar_cipher(text, shift):
    result = []
    for char in text:
        if char.isalpha():
            # Determinar si es mayúscula o minúscula
            start = ord('A') if char.isupper() else ord('a')
            # Aplicar el desplazamiento
            new_char = chr(start + (ord(char) - start + shift) % 26)
            result.append(new_char)
        else:
            # Si no es letra, no se cambia
            result.append(char)
    return ''.join(result)

# Función para evaluar si una palabra es válida
def is_valid_word(word, valid_words):
    return word.lower() in valid_words

# Función para procesar el pcap y reconstruir el mensaje
def process_pcap(file_name):
    packets = rdpcap(file_name)
    original_message = []

    for packet in packets:
        if packet.haslayer(ICMP) and packet[ICMP].type == 8:  # ICMP Echo Request
            payload = packet[Raw].load
            message_char = chr(payload[0])
            original_message.append(message_char)

    return ''.join(original_message)

# Función para analizar todos los desplazamientos posibles y marcar el más probable
def analyze_cesar_shifts(original_message, valid_words_es, valid_words_en):
    best_shift = -1
    best_score = -1
    best_message = ""

    # Probar todos los desplazamientos posibles
    for shift in range(26):
        shifted_message = cesar_cipher(original_message, shift)

        # Dividir el mensaje en palabras y contar cuántas son válidas
        words = shifted_message.split()
        valid_words_count = sum(is_valid_word(word, valid_words_es) or is_valid_word(word, valid_words_en) for word in words)

        # Comparar y mantener el mejor desplazamiento
        if valid_words_count > best_score:
            best_score = valid_words_count
            best_shift = shift
            best_message = shifted_message

    # Imprimir los resultados
    for shift in range(26):
        shifted_message = cesar_cipher(original_message, shift)
        if shift == best_shift:
            print(f"{Fore.GREEN}Shift {shift}: {shifted_message}{Fore.RESET}")
        else:
            print(f"Shift {shift}: {shifted_message}")

    print("\nMejor mensaje encontrado:")
    print(f"{Fore.GREEN}{best_message}{Fore.RESET} con el desplazamiento de {best_shift}")

# Cargar las palabras válidas en español e inglés
def load_valid_words():
    # Se pueden cargar desde un archivo o usar listas predefinidas
    # Aquí cargamos algunas palabras comunes en ambos idiomas como ejemplo
    valid_words_es = {"hola", "este", "es", "un", "mensaje", "original", "palabra", "español"}
    valid_words_en = {"hello", "this", "is", "a", "message", "original", "word", "english", "high", "light", "highlight"}
    return valid_words_es, valid_words_en

if __name__ == "__main__":
    # Inicializar colorama
    init(autoreset=True)

    if len(sys.argv) != 2:
        print("Uso: python3 read_pcap.py <archivo.pcapng>")
        sys.exit(1)

    file_name = sys.argv[1]

    # Procesar el archivo pcapng y obtener el mensaje original
    original_message = process_pcap(file_name)
    print(f"Mensaje original: {original_message}\n")

    # Cargar las palabras válidas en español e inglés
    valid_words_es, valid_words_en = load_valid_words()

    # Analizar todos los desplazamientos posibles con el Cifrado César
    analyze_cesar_shifts(original_message, valid_words_es, valid_words_en)