def cifrado_cesar(texto, desplazamiento):
    resultado = ""
    
    for char in texto:
        # Verificar si el carácter es una letra
        if char.isalpha():
            # Determinar el rango del carácter (mayúscula o minúscula)
            start = ord('A') if char.isupper() else ord('a')
            # Aplicar el desplazamiento, asegurándose de que vuelva al inicio si excede el rango
            resultado += chr((ord(char) - start + desplazamiento) % 26 + start)
        else:
            # Si no es una letra, añadirlo sin cambios (espacios, puntuación, etc.)
            resultado += char
            
    return resultado

# Solicitar input al usuario
texto_usuario = input("Ingresa el texto a cifrar: ")
desplazamiento_usuario = int(input("Ingresa el desplazamiento (número entero): "))

# Llamar a la función para cifrar el texto
texto_cifrado = cifrado_cesar(texto_usuario, desplazamiento_usuario)

# Mostrar el resultado
print("Texto cifrado:", texto_cifrado)