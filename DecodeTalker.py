from scapy.all import *
import sys
from colorama import Fore, Style

# Función para descifrar el mensaje con el algoritmo César
def caesar_cipher(text, shift):
    result = []
    for char in text:
        if char.isalpha():  # Solo cifrar letras
            shift_base = 65 if char.isupper() else 97
            result.append(chr((ord(char) - shift_base + shift) % 26 + shift_base))
        else:
            result.append(char)
    return ''.join(result)

# Función para verificar si una palabra tiene sentido en inglés (usando un enfoque simple)
def is_valid_word(word):
    # Lista muy simple de palabras comunes en inglés
    common_words = [
        "the", "be", "to", "of", "and", "a", "in", "that", "have", "I", "it", "for", 
        "not", "on", "with", "he", "as", "you", "do", "at", "this", "but", "his", 
        "by", "from", "they", "we", "say", "her", "she", "or", "an", "will", "my", 
        "one", "all", "would", "there", "their", "what", "so", "up", "out", "if", 
        "about", "who", "get", "which", "go", "me", "when", "make", "can", "like", 
        "time", "no", "just", "him", "know", "take", "people", "into", "year", "your", 
        "good", "some", "could", "them", "see", "other", "than", "then", "now", "look", 
        "only", "come", "its", "over", "think", "also", "back", "after", "use", "two", 
        "how", "our", "work", "first", "well", "way", "even", "new", "want", "because", "highlight"
    ]
    return word.lower() in common_words

# Función para extraer datos ICMP
def extract_icmp_data(pcap_file):
    # Abrir el archivo pcapng
    packets = rdpcap(pcap_file)

    # Lista para almacenar los caracteres que se extraerán
    extracted_chars = []

    # Filtrar los paquetes ICMP (echo request)
    for pkt in packets:
        if ICMP in pkt and pkt[ICMP].type == 8:  # ICMP Echo Request
            # Extraer los datos del paquete ICMP
            raw_data = pkt[Raw].load
            
            # El primer byte ahora es el carácter, así que lo extraemos directamente
            if raw_data:
                message_char = raw_data[0:1]  # El primer byte es el carácter
                extracted_chars.append(message_char.decode(errors='ignore'))
    
    # Reconstruir el mensaje original
    reconstructed_message = ''.join(extracted_chars)
    return reconstructed_message

# Función para descifrar y mostrar las posibles combinaciones del mensaje
def show_possible_decryptions(message):
    print("\nPossible Caesar Cipher Decodings:")
    best_score = -1
    best_message = ""
    
    # Intentar todas las combinaciones de desplazamiento de 1 a 25
    for shift in range(1, 26):
        decrypted_message = caesar_cipher(message, shift)
        words = decrypted_message.split()
        
        # Calcular el puntaje de la validez del mensaje (contando palabras válidas)
        score = sum([is_valid_word(word) for word in words])
        
        # Si es la mejor opción (más palabras válidas), marcarla como la mejor opción
        if score > best_score:
            best_score = score
            best_message = decrypted_message
            best_shift = shift

        # Mostrar el mensaje descifrado con la combinación actual
        if score == best_score:
            # Resaltar la opción más probable en verde
            if shift == best_shift:
                print(Fore.GREEN + f"Shift {shift}: {decrypted_message}" + Style.RESET_ALL)
            else:
                print(f"Shift {shift}: {decrypted_message}")
        else:
            print(f"Shift {shift}: {decrypted_message}")
    
    return best_message, best_shift

if __name__ == "__main__":
    # Verificar que el archivo pcapng es pasado como argumento
    if len(sys.argv) != 2:
        print("Usage: python3 DecodeTalker.py <file.pcapng>")
        sys.exit(1)

    pcap_file = sys.argv[1]
    
    # Extraer el mensaje de los paquetes ICMP
    message = extract_icmp_data(pcap_file)
    
    print("Reconstructed message:")
    print(message)

    # Mostrar todas las posibles combinaciones de descifrado César y resaltar la opción más probable
    best_message, best_shift = show_possible_decryptions(message)

    print("\nMost probable decoded message:")
    print(Fore.GREEN + f"Shift {best_shift}: {best_message}" + Style.RESET_ALL)