import cryptography
from cryptography.fernet import Fernet


# generar key solamente en un archivo
def generateKeyWithoutPassword(keyName):
    key = Fernet.generate_key()
    print("\nLLave generada: " + keyName + ".key")

    file = open(keyName  + ".key", 'wb') #wb = write bytes
    file.write(key)
    file.close()

def readKeyFile(keyName):
    # Get the key from the file
    file = open(keyName, 'rb')
    key = file.read()
    file.close()

    return key

def encryptionMethod(file2encrypt, llave):
    #  Open the file to encrypt
    with open(file2encrypt, 'rb') as f:
        data = f.read()
        f.close()
    key = readKeyFile(llave)
    fernet = Fernet(key)
    encrypted = fernet.encrypt(data)
    # Write the encrypted file
    with open(file2encrypt , 'wb') as f:
        f.write(encrypted)
        f.close()

def decryptionMethod(file2decrypt,llave):
    #  Open the file to decrypt
    with open(file2decrypt, 'rb') as f:
        data = f.read()
        f.close()
    key = readKeyFile(llave)
    fernet = Fernet(key)
    decrypted = fernet.decrypt(data)

    # Open the decrypted file
    with open(file2decrypt, 'wb') as f:
        f.write(decrypted)
        f.close()

def menu():
    print("############### BIENVENID@ ###############")
    print("Elija la opción deseada:")
    print("\t 1 - Encriptacion Simetrica")
    print("\t 2 - Desencriptacion Simetrica")
    print("\t 3 - Encriptacion Asimetrica")
    print("\t 4 - Desencriptacion Asimetrica")
    print("\t 5 - Cifrado por Matrices")
    print("\t 6 - Cifrado por Matrices")
    selection = input("\n -->: ")
    return int(selection)
def main():
    opt  = menu()
    if opt == 1:
        try:
            name = input("\nIngrese nombre de su nueva llave secreta: " )
            generateKeyWithoutPassword(name)
            file = input("\nIngrese el nombre del archivo a encriptar incluyendo la extension: ")
            key = input("\nIngrese el nombre de su llave incluyendo la extension: ")
            encryptionMethod(file,key)
            print("\nArchivo encriptado satisfactoriamente.")
        except ValueError as e:
            print(e)
    if opt == 2:
        try:
            file = input("\nIngrese el nombre del archivo a desencriptar incluyendo la extension: ")
            key = input("\nIngrese el nombre de su llave incluyendo la extension: ")
            decryptionMethod(file,key)
            print("\nArchivo desencriptado satisfactoriamente.")

        except ValueError as e:
            print(e)

    return True
if __name__ == '__main__':
    ok = True
    while ok:
        ok = main()
