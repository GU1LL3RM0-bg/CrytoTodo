import cryptography
from cryptography.fernet import Fernet

from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
import base64


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
    print("\n############### BIENVENID@ ###############\n")
    print("Elija la opción deseada:")
    print("\t 1 - Encriptacion Simetrica")
    print("\t 2 - Desencriptacion Simetrica")
    print("\t 3 - Encriptacion Asimetrica")
    print("\t 4 - Desencriptacion Asimetrica")
    print("\t 5 - Cifrado por Matrices")
    print("\t 6 - Cifrado por Matrices")
    selection = input("\n -->: ")
    return int(selection)

def generatePublicAndPrivateKeys():
    # Generates RSA Encryption + Decryption keys / Public + Private keys
    key = RSA.generate(2048)

    private_key = key.export_key()
    with open('private.pem', 'wb') as f:
        f.write(private_key)
        f.close()

    public_key = key.publickey().export_key()
    with open('public.pem', 'wb') as f:
        f.write(public_key)
        f.close()


def encryptionMethodAsymetric(fileName):
    try:
        with open(fileName, 'rb') as fn:
            archivo = fn.read()

        with open(fileName, 'wb') as f:
            # Public RSA key
            public_key = RSA.import_key(open('public.pem').read())
            # Public encrypter object
            public_crypter =  PKCS1_OAEP.new(public_key)
            # Encrypted fernet key
            file_encrypted = public_crypter.encrypt(archivo)
            # Write encrypted fernet key to file
            f.write(file_encrypted)
            f.close()
        print("Archivo encriptado exitosamente. Protege la llave privada private.pem !!")
    except ValueError as e:
        print("Error técnico." + str(e))

def decryptionMethodAsymetric(file, llave):
    try:
        with open(file, 'rb') as f:
            archivo_encriptado = f.read()
        # Private RSA key
        private_key = RSA.import_key(open(llave).read())
        # Private decrypter
        private_crypter = PKCS1_OAEP.new(private_key)
        # Decrypted session key
        archivo_desencriptado = private_crypter.decrypt(archivo_encriptado)
        with open(file, 'wb') as f:
            f.write(archivo_desencriptado)

        print('Archivo desencriptado exitosamente!')
    except ValueError as e:
        print("Error Tecnico: " + str(e))

def main():
    opt  = menu()
    if opt == 1:
        try:
            si_no = input("\nDesea generar una llave nueva?... escriba si o no: ")
            if si_no == "si":
                name = input("\nIngrese nombre de su nueva llave secreta: " )
                generateKeyWithoutPassword(name)
            else:
                print("\n")
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

    if opt == 3:
        try:
            file = input("\nIngrese el nombre del archivo a encriptar incluyendo la extension: ")
            generatePublicAndPrivateKeys()
            encryptionMethodAsymetric(file)
        except ValueError as e:
            print(e)
    if opt == 4:
        try:
            file = input("\nIngrese el nombre del archivo a desencriptar incluyendo la extension: ")
            llave = input("\nIngrese la llave privada para desencriptar el archivo incluyendo la extension: ")
            decryptionMethodAsymetric(file, llave)
        except ValueError as e:
            print(e)
    return True
if __name__ == '__main__':
    ok = True
    while ok:
        ok = main()
