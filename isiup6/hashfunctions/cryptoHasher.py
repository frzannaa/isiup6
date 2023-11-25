from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
import bcrypt
from os import path
import os
import ast

class Hasher():

    def __init__(self) -> None:
        self.nonce = b"\x00" * 16

    def pad_block(self, data):
        if(len(data) % 8 != 0):
            data += b"\x00" * (8 - len(data) % 8)
        return data
    
    def get128BitKey(self, key):
        if len(key) < 16:
            key = key + '0' * (16 - len(key))
        elif len(key) > 16:
            key = key[-16:]
        return key.encode('utf-8')

    def deleteFile(self, fpath, ext):
        old_path = path.splitext(fpath)[0] + ext
        print("Old Path: ", old_path)
        if path.exists(old_path):
            print("Deleting file: ", old_path)
            os.remove(old_path)
        else:
            print("The file does not exist")
    
    def encryptFile(self, fpath, algo, key = '1234567890123456'):
        # get file directiory without the extension
        key = self.get128BitKey(key)
        encrypted_path = path.splitext(fpath)[0] + ".enc"
        print("Encrypted Path: ", encrypted_path)
        with open(fpath, "rb") as f:
            data = f.read()
        if(algo == "DES"):
            encrypted = self.DES_Encrypt(key, data)
            self.saveFile(encrypted_path, encrypted)
            return encrypted_path
        elif(algo == "AES"):
            encrypted = self.AES_Encrypt(key, data)
            self.saveFile(encrypted_path, encrypted)
            return encrypted_path
        elif(algo == "ARC4"):
            encrypted = self.ARC4_Encrypt(key, data)
            self.saveFile(encrypted_path, encrypted)
            return encrypted_path
        else:
            return None
    
    def decryptFile(self, fpath, algo, filetype,  key = '1234567890123456'):
        key = self.get128BitKey(key)

        decrypted_path = path.splitext(fpath)[0] + filetype
        with open(fpath, "rb") as f:
            data = f.read()
        if(algo == "DES"):
            decryped = self.DES_Decrypt(key, data)
            # self.saveFile(decrypted_path, decryped)
            return decryped, decrypted_path
        elif(algo == "AES"):
            decryped = self.AES_Decrypt(key, data)
            # self.saveFile(decrypted_path, decryped)
            return decryped, decrypted_path
        elif(algo == "ARC4"):
            decryped = self.ARC4_Decrypt(key, data)
            # self.saveFile(decrypted_path, decryped)
            return decryped, decrypted_path
        else:
            return None
        
    def encryptText(self, text, algo, key = '1234567890123456'):
        key = self.get128BitKey(key)
        text = text.encode('utf-8')
        if(algo == "DES"):
            encrypted = self.DES_Encrypt(key, text)
            return encrypted
        elif(algo == "AES"):
            encrypted = self.AES_Encrypt(key, text)
            return encrypted
        elif(algo == "ARC4"):
            encrypted = self.ARC4_Encrypt(key, text)
            return encrypted
        else:
            return None
    
    def decryptText(self, text, algo, key = '1234567890123456'):
        key = self.get128BitKey(key)
        text = ast.literal_eval(text)
        if(algo == "DES"):
            decryped = self.DES_Decrypt(key, text)
            return decryped.decode('utf-8')
        elif(algo == "AES"):
            decryped = self.AES_Decrypt(key, text)
            return decryped.decode('utf-8')
        elif(algo == "ARC4"):
            decryped = self.ARC4_Decrypt(key, text)
            return decryped.decode('utf-8')
        else:
            return None

        
    def saveFile(self, path, data):
        with open(path, "wb") as f:
            f.write(data)

    def Hash_Password(self, password):
        hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
        print(hashed)
        return hashed
    
    def Check_Password(self, password, hashed):
        return bcrypt.checkpw(password.encode(), hashed)


    def DES_Encrypt(self, key, data):
        nonce = b"\x00" * 8
        cipher = Cipher(algorithms.TripleDES(key), modes.CBC(nonce))
        encryptor = cipher.encryptor()
        return encryptor.update(self.pad_block(data)) + encryptor.finalize()

    def DES_Decrypt(self, key, data):
        nonce = b"\x00" * 8
        cipher = Cipher(algorithms.TripleDES(key), modes.CBC(nonce))
        decryptor = cipher.decryptor()
        data = decryptor.update(data) + decryptor.finalize()
        return data.rstrip(b"\x00") 

    def AES_Encrypt(self, key, data):
        cipher = Cipher(algorithms.AES(key), modes.CTR(self.nonce))
        encryptor = cipher.encryptor()
        return encryptor.update(self. pad_block(data)) + encryptor.finalize()

    def AES_Decrypt(self, key, data):
        cipher = Cipher(algorithms.AES(key), modes.CTR(self.nonce))
        decryptor = cipher.decryptor()
        data = decryptor.update(data) + decryptor.finalize()
        return data.rstrip(b"\x00")

    def ARC4_Encrypt(self, key, data):
        cipher = Cipher(algorithms.ARC4(key), None)
        encryptor = cipher.encryptor()
        return encryptor.update(self.pad_block(data)) + encryptor.finalize()

    def ARC4_Decrypt(self, key, data):
        cipher = Cipher(algorithms.ARC4(key), None)
        decryptor = cipher.decryptor()
        data = decryptor.update(data) + decryptor.finalize()
        return data.rstrip(b"\x00")
    
    def RSA_Generate_Key(self):
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = private_key.public_key()
        return private_key, public_key

    def RSA_Encrypt(self, key, data):
        return key.encrypt(data, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    
    def RSA_Decrypt(self, key, data):
        return key.decrypt(data, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    

