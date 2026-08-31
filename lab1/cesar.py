import sys

def cifrado_cesar(texto, rotacion):
    resultado = ""
    
    for caracter in texto:
        if caracter.isalpha():
            base = ord('A') if caracter.isupper() else ord('a')
            nuevo_caracter = chr((ord(caracter) - base + rotacion) % 26 + base)
            resultado += nuevo_caracter
        else:
            resultado += caracter
            
    return resultado

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print('Uso: python cesar.py "texto a cifrar" <numero_rotacion>')
        sys.exit(1)

    texto_original = sys.argv[1]

    try:
        rotacion = int(sys.argv[2])
    except ValueError:
        print("Error: El segundo parámetro (corrimiento) debe ser un número entero.")
        sys.exit(1)

    texto_cifrado = cifrado_cesar(texto_original, rotacion)
    
    print(texto_cifrado)

