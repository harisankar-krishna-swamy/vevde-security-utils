from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


class AES:
    def __init__(self, key: bytes, iv: bytes, backend):
        self._cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)

    def encrypt(self, plaintext: bytes):
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded = padder.update(plaintext) + padder.finalize()
        cip = self._cipher.encryptor()
        return cip.update(padded) + cip.finalize()

    def decrypt(self, ciphertext: bytes):
        cip = self._cipher.decryptor()
        padded = cip.update(ciphertext) + cip.finalize()
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        return unpadder.update(padded) + unpadder.finalize()


def aes_crypt(msg: bytes, key: bytes, iv: bytes, encrypt: bool = True):
    cipher = AES(key, iv, default_backend())

    if encrypt:
        return cipher.encrypt(msg)
    else:
        return cipher.decrypt(msg)
