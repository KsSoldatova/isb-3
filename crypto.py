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

    def generate_keys(self) -> None:
        # Генерация ключа для симметричного алгоритма
        symmetric_key = os.urandom(16)
        # Генерация ключей для ассиметричного алгоритма
        private_key = asymmetric.rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        public_key = private_key.public_key()
        # Сериализация ассиметричных ключей
        private_key_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        public_key_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
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
        # Шифрование ключа симметричного шифрования открытым ключом и сохранение по указанному пути
        encrypted_symmetric_key = public_key.encrypt(
            symmetric_key,
            asymmetric.padding.OAEP(
                mgf=asymmetric.padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        try:
            # Запись зашифрованного ключа в файл
            with open(self.symmetric_key_path, 'wb') as f:
                f.write(encrypted_symmetric_key)
        except Exception as e:
            logging.error(e)

    def encrypt_data(self, input_file_path: str, output_file_path: str) -> None:
        # Считывание зашифрованного ключа симметричного шифрования из файла
        try:
            with open(self.symmetric_key_path, 'rb') as f:
                encrypted_symmetric_key = f.read()
        except Exception as e:
            logging.error(e)
        # Расшифровка ключа симметричного шифрования закрытым ключом
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
        # Чтение данных из файла
        try:
            with open(input_file_path, 'rb') as f:
                data = f.read()
        except Exception as e:
            logging.error(e)

        padder = padding.PKCS7(128).padder()
        padded_text = padder.update(data) + padder.finalize()
        iv = os.urandom(16)
        cipher = Cipher(algorithms.SEED(symmetric_key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(padded_text) + encryptor.finalize()
        encrypted_data = iv + encrypted_data
        # Сохранение зашифрованных данных в файл
        try:
            with open(output_file_path, 'wb') as f:
                f.write(encrypted_data)
        except Exception as e:
            logging.error(e)

    def decrypt_data(self, input_file_path: str, output_file_path: str) -> None:
        # Считывание зашифрованного ключа симметричного шифрования из файла
        try:
            with open(self.symmetric_key_path, 'rb') as f:
                encrypted_symmetric_key = f.read()
        except Exception as e:
            logging.error(e)
        # Расшифровка ключа симметричного шифрования закрытым ключом
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
        # Чтение зашифрованных данных из файла
        try:
            with open(input_file_path, 'rb') as f:
                encrypted_data = f.read()
        except Exception as e:
            logging.error(e)
        # Расшифровка данных симметричным алгоритмом
        iv = encrypted_data[:16]
        encrypted_data = encrypted_data[16:]
        cipher = Cipher(algorithms.SEED(symmetric_key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        data = decryptor.update(encrypted_data) + decryptor.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        data = unpadder.update(data) + unpadder.finalize()
        try:
            with open(output_file_path, 'wb') as f:
                f.write(data)
        except Exception as e:
            logging.error(e)