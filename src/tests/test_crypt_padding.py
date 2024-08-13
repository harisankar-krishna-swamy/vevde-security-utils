from unittest import TestCase

from ddt import data, ddt, unpack

from vevde_security_utils.crypt.aes import aes_crypt
from vevde_security_utils.crypt.camellia import camellia_crypt
from vevde_security_utils.crypt.padding import pad, unpad
from vevde_security_utils.crypt.settings import CIPHER_AES_256, CIPHER_CAMELLIA_256

cipher_crypt_map = {CIPHER_AES_256: aes_crypt, CIPHER_CAMELLIA_256: camellia_crypt}


@ddt
class TestPadding(TestCase):

    test_data = (
        (0,),
        (8,),
        (16,),
        (32,),
        (64,),
        (128,),
    )

    @data(*test_data)
    @unpack
    def test_padding(self, block_size=16):
        data = b'test_data'
        block_size = 8
        padded = pad(data, block_size)
        unpadded = unpad(padded)
        self.assertEqual(data, unpadded, f'Padding error with block_size {block_size}')
