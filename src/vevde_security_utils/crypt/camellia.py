from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


class Camellia:
    def __init__(self, key: bytes, iv: bytes, backend):
        self._cipher = Cipher(algorithms.Camellia(key), modes.CBC(iv), backend=backend)

    def encrypt(self, plaintext: bytes):
        padder = padding.PKCS7(algorithms.Camellia.block_size).padder()
        padded = padder.update(plaintext) + padder.finalize()
        cip = self._cipher.encryptor()
        return cip.update(padded) + cip.finalize()

    def decrypt(self, ciphertext: bytes):
        cip = self._cipher.decryptor()
        padded = cip.update(ciphertext) + cip.finalize()
        unpadder = padding.PKCS7(algorithms.Camellia.block_size).unpadder()
        return unpadder.update(padded) + unpadder.finalize()


def camellia_crypt(msg: bytes, key: bytes, iv: bytes, encrypt: bool = True):
    cipher = Camellia(key, iv, default_backend())

    if encrypt:
        return cipher.encrypt(msg)
    else:
        return cipher.decrypt(msg)
