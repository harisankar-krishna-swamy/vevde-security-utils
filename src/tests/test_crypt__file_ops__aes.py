import os
from time import time
from unittest import TestCase

from cryptography.hazmat.backends import default_backend
from ddt import data, ddt, unpack

from vevde_security_utils.crypt.aes import AES
from vevde_security_utils.crypt.file_ops import dec_file, enc_file


@ddt
class TestAESCryptFileOps(TestCase):
    def setUp(self):
        self.file = './tests/random-data.txt'
        key, iv, backend = (os.urandom(32), os.urandom(16), default_backend())

        self.aes_enc = AES(key, iv, backend)
        self.aes_dec = AES(key, iv, backend)

    def __assert_hashes(self, hash_before, hash_after):
        print("Hashes")
        print(f'hash_before: {hash_before}')
        print(f'hash_after: {hash_after}')

        self.assertEqual(
            hash_before,
            hash_after,
            f'Hash mismatch on encrypt/decrypt for {self.__class__.__name__}',
        )

    @data((1024,), (2048,), (3072,), (4096,))
    @unpack
    def test_AES__encrypt_decrypt_file__read_chunk_size(self, read_chunk_size=1024):
        start = time()
        hash_before = enc_file(
            self.aes_enc,
            infile=self.file,
            outfile=f'/tmp/{self.__class__.__name__}.enc',
            read_chunk_size=read_chunk_size,
        )
        hash_after = dec_file(
            self.aes_dec,
            infile=f'/tmp/{self.__class__.__name__}.enc',
            outfile=f'/tmp/{self.__class__.__name__}.dec',
            read_chunk_size=read_chunk_size,
            cipher_block_size=16,
        )

        self.__assert_hashes(hash_before, hash_after)

        end = time()
        print(f'{self.__class__.__name__}: End: Elasped - {(end - start)} seconds')
