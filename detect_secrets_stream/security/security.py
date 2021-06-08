import os

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import asymmetric
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import algorithms
from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers import modes


class Encryptor:
    def __init__(self, key_filename=os.getenv('GD_PUB_KEY_FILENAME')):
        if not os.path.isfile(key_filename):
            raise Exception(f'key_filename={key_filename} is not a regualar file')
        self._key_filename = key_filename
        self._encryptor = None

    def get_encryptor(self):
        if not self._encryptor:
            key_file = open(self._key_filename, 'rb')
            self._encryptor = serialization.load_pem_public_key(
                key_file.read(),
                backend=default_backend(),
            )

        return self._encryptor

    def encrypt(self, text: str) -> bytes:
        '''
        Asymmetric encryption with cryptography library
        '''
        if type(text) is not str:
            return None

        ciphertext = self.get_encryptor().encrypt(
            str.encode(text),
            asymmetric.padding.OAEP(
                mgf=asymmetric.padding.MGF1(algorithm=hashes.SHA1()),
                algorithm=hashes.SHA1(),
                label=None,
            ),
        )

        return ciphertext


class Decryptor:
    def __init__(self, key_filename=os.getenv('GD_PRI_KEY_FILENAME')):
        if not os.path.isfile(key_filename):
            raise Exception(f'key_filename={key_filename} is not a regualar file')

        self._key_filename = key_filename
        self._decryptor = None

    def get_decryptor(self):
        if not self._decryptor:
            key_file = open(self._key_filename, 'rb')
            self._decryptor = serialization.load_pem_private_key(
                key_file.read(),
                password=None,
                backend=default_backend(),
            )

        return self._decryptor

    def decrypt(self, encrypted_text) -> str:
        '''
        Asymmetric decryption with cryptography library
        '''
        if encrypted_text is None:
            return None

        if type(encrypted_text) is bytes:
            bytes_encrypted_text = encrypted_text
        else:
            bytes_encrypted_text = bytes(encrypted_text)

        decrypted_byte_text = self.get_decryptor().decrypt(
            bytes_encrypted_text,
            asymmetric.padding.OAEP(
                mgf=asymmetric.padding.MGF1(algorithm=hashes.SHA1()),
                algorithm=hashes.SHA1(),
                label=None,
            ),
        )

        return bytes.decode(decrypted_byte_text)


class DeterministicCryptor:
    def __init__(self, de_key_filename=os.getenv('GD_DC_KEY_FILENAME'), de_iv_filename=os.getenv('GD_DC_IV_FILENAME')):
        '''
        A symmetric encryptor which use AES encryption with CBC mode. Based on the doc
        https://cryptography.io/en/latest/hazmat/primitives/symmetric-encryption/#cryptography.hazmat.primitives.ciphers.modes.CBC
        padding is required for CBC mode, so padding was added before encryption and unpadding after decryption.

        de_key_filename - deterministic encryption key file which contains 256 bits of random data
        de_iv_filename - deterministic encryption initialization vector file which contains 128 bits of random data.
                        Using a static IV makes sure we will have determinstic encryption result.
                        It is less secure than random IV each time.
        '''
        if not os.path.isfile(de_key_filename):
            raise Exception(f'de_key_filename={de_key_filename} is not a regualar file')

        if not os.path.isfile(de_iv_filename):
            raise Exception(f'de_iv_filename={de_iv_filename} is not a regualar file')

        de_key = open(de_key_filename, 'rb').read()
        de_iv = open(de_iv_filename, 'rb').read()
        self.cipher = Cipher(algorithms.AES(de_key), modes.CBC(de_iv), backend=default_backend())

    def padding(self, bytes_data) -> bytes:
        padder = padding.PKCS7(256).padder()
        padded_data = padder.update(bytes_data)
        padded_data += padder.finalize()

        return padded_data

    def unpadding(self, padded_bytes_data) -> bytes:
        unpadder = padding.PKCS7(256).unpadder()
        data = unpadder.update(padded_bytes_data)
        data += unpadder.finalize()

        return data

    def decrypt(self, encrypted_text) -> str:
        '''
        Symmetric decryption with cryptography library
        '''
        decryptor = self.cipher.decryptor()

        if encrypted_text is None:
            return None

        if type(encrypted_text) is bytes:
            bytes_encrypted_text = encrypted_text
        else:
            bytes_encrypted_text = bytes(encrypted_text)

        decrypted_byte_text = decryptor.update(bytes_encrypted_text) + decryptor.finalize()
        decrypted_byte_text = self.unpadding(decrypted_byte_text)

        return bytes.decode(decrypted_byte_text)

    def encrypt(self, text: str) -> bytes:
        '''
        Symmetric encryption with cryptography library
        '''
        encryptor = self.cipher.encryptor()

        if type(text) is not str:
            return None

        data = self.padding(str.encode(text))
        ciphertext = encryptor.update(data) + encryptor.finalize()

        return ciphertext
