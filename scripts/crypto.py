import os
import logging
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization, asymmetric, hashes, padding

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


class Cryptography:
    def __init__(self, symmetric_key_path: str, public_key_path: str, private_key_path: str) -> None:
        self.symmetric_key_path = symmetric_key_path
        self.public_key_path = public_key_path
        self.private_key_path = private_key_path
    
    def generate_symmetric_key(self) -> None:
        """
            Генерация ключа для симметричного алгоритма.
            :return: None
        """
        symmetric_key = os.urandom(16)


    def generate_assymetric_key(self) -> None:
        """
        Генерация ключа для ассиметричного алгоритма.
        :return: None
        """
        private_key = asymmetric.rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        public_key = private_key.public_key()

    def serealization_assymetric_keys(self,private_key, public_key) -> None:
        private_key_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        public_key_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    
    def write_key_bytes(self, public_key_bytes, private_key_bytes) -> None:
        try:
            with open(self.public_key_path, 'wb') as f:
                f.write(public_key_bytes)
        except Exception as e:
            logging.error(e)
        try:
            with open(self.private_key_path, 'wb') as f:
                f.write(private_key_bytes)
        except Exception as e:
            logging.error(e)
        
    def read_key(self):
        try:
            with open(self.symmetric_key_path, 'rb') as f:
                encrypted_symmetric_key = f.read()
        except Exception as e:
            logging.error(e)    
        
    def symmetric_key_encription(self,public_key, symmetric_key) -> None:   
        encrypted_symmetric_key = public_key.encrypt(
            symmetric_key,
            asymmetric.padding.OAEP(
                mgf=asymmetric.padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        try:
            with open(self.symmetric_key_path, 'wb') as f:
                f.write(encrypted_symmetric_key)
        except Exception as e:
            logging.error(e)



    def encrypt_data(self,encrypted_symmetric_key: str) -> None:
        """
            2 пункт л.р - Шифрование данных
            2.1. Расшифровать ключ симметричного шифрования закрытым ключом.
            2.2. Зашифровать данные симметричным алгоритмом.
            :return: None
        """
        try:
            with open(self.private_key_path, 'rb') as f:
                private_key = serialization.load_pem_private_key(
                    f.read(),
                    password=None
                )
        except Exception as e:
            logging.error(e)
        symmetric_key = private_key.decrypt(
            encrypted_symmetric_key,
            asymmetric.padding.OAEP(
                mgf=asymmetric.padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        padder = padding.PKCS7(128).padder()
        padded_text = padder.update(data) + padder.finalize()
        iv = os.urandom(16)
        cipher = Cipher(algorithms.SEED(symmetric_key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        data = encryptor.update(padded_text) + encryptor.finalize()
        data = iv + data

    def read_file(self, input_file_path: str ) -> None:
        try:
            with open(input_file_path, 'rb') as f:
                data = f.read()
        except Exception as e:
            logging.error(e)
       
    
    def write_file(self, output_file_path, data):
        try:
            with open(output_file_path, 'wb') as f:
                f.write(data)
        except Exception as e:
            logging.error(e)
    def decrypt_data(self, encrypted_symmetric_key: str) -> None:
        """
            3 пункт л.р - Расшифровка данных
            3.1. Считать зашифрованный ключ симметричного шифрования из файла.
            3.2. Расшифровать ключ симметричного шифрования закрытым ключом.
            3.4. Расшифровать данные симметричным алгоритмом.
            :return: None
        """

        try:
            with open(self.private_key_path, 'rb') as f:
                private_key = serialization.load_pem_private_key(
                    f.read(),
                    password=None
                )
        except Exception as e:
            logging.error(e)
        symmetric_key = private_key.decrypt(
            encrypted_symmetric_key,
            asymmetric.padding.OAEP(
                mgf=asymmetric.padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        iv = data[:16]
        data = data[16:]
        cipher = Cipher(algorithms.SEED(symmetric_key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        data = decryptor.update(data) + decryptor.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        data = unpadder.update(data) + unpadder.finalize()
        
        