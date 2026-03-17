import sys
import unicodedata

def normalizar_texto(texto):
    # Elimina tildes y convierte a minúsculas
    texto = texto.lower()
    texto = unicodedata.normalize('NFD', texto)
    texto = texto.encode('ascii', 'ignore').decode("utf-8")
    # Reemplaza 'ñ' por 'n'
    texto = texto.replace('ñ', 'n')
    return texto

def cifrar_cesar(texto, desplazamiento):
    texto_cifrado = ""

    for char in texto:
        if char.isalpha():
            nuevo_char = chr((ord(char) - ord('a') + desplazamiento) % 26 + ord('a'))
            texto_cifrado += nuevo_char
        else:
            texto_cifrado += char

    return texto_cifrado

# Verificar argumentos
if len(sys.argv) != 3:
    print("Uso: sudo python3 cesar.py \"<texto a cifrar>\" <desplazamiento>")
    sys.exit(1)

texto_entrada = sys.argv[1]
desplazamiento = int(sys.argv[2])

# Normalizar texto
texto_normalizado = normalizar_texto(texto_entrada)

# Cifrar
texto_cifrado = cifrar_cesar(texto_normalizado, desplazamiento)

# Imprimir resultado
print(texto_cifrado)

