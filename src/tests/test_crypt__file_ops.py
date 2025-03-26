from unittest import TestCase

from vevde_security_utils.crypt.file_ops import dec_file, enc_file


class UnsupportedCipher:
    pass


class TestCryptFileOps(TestCase):
    def setUp(self):
        self.file = './tests/random-data.txt'

    def test_enc_file__unsupported_cipher(self):

        with self.assertRaises(
            TypeError,
            msg='File encryption with unsupported ciphers must raise ValueError',
        ):
            _ = enc_file(
                UnsupportedCipher(),
                infile=self.file,
                outfile=f'/tmp/{self.__class__.__name__}.enc',
                read_chunk_size=1024,
            )

    def test_dec_file__unsupported_cipher(self):

        with self.assertRaises(
            TypeError,
            msg='File encryption with unsupported ciphers must raise ValueError',
        ):
            _ = dec_file(
                UnsupportedCipher(),
                infile=f'/tmp/{self.__class__.__name__}.enc',
                outfile=f'/tmp/{self.__class__.__name__}.dec',
                read_chunk_size=1024,
                cipher_block_size=16,
            )
