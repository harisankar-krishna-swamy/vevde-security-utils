import hashlib
from typing import Union

from vevde_security_utils.crypt.aes import AES
from vevde_security_utils.crypt.camellia import Camellia


def enc_file(
    cipher: Union[AES, Camellia], infile: str, outfile: str, read_chunk_size: int
):
    """
    Encrypts file contents and return SHA-512

    @param cipher: an instance of AES or Camellia
    @param infile: absolute path name of input file (string)
    @param outfile: absolute path name of output encrypted file (string)
    @param read_chunk_size: file read chunk size (calling app code must remember and provide this to decrypt)

    @return: SHA-512 of file contents
    """
    if type(cipher) not in (AES, Camellia):
        raise TypeError(f'cipher {type(cipher)} not supported')

    with open(infile, 'rb') as ifl, open(outfile, 'wb') as of:
        hasher = hashlib.sha512()
        while True:
            d = ifl.read(read_chunk_size)
            hasher.update(d)
            if not d:
                break
            r = cipher.encrypt(d)
            of.write(r)

        return hasher.hexdigest()


def dec_file(
    cipher: Union[AES, Camellia],
    infile: str,
    outfile: str,
    read_chunk_size: int,
    cipher_block_size: int,
):
    """
    Decrypts file contents and return SHA-512 of decrypted content

    @param cipher: an instance of AES or Camellia
    @param infile: absolute path name of input file (string)
    @param outfile: absolute path name of output encrypted file (string)
    @param read_chunk_size: file read chunk size (must be same as value used to encrypt infile)
    @param cipher_block_size: block size of cipher in bytes (16 for AES and Camellia)

    @return: SHA-512 of file contents
    """

    if type(cipher) not in (AES, Camellia):
        raise TypeError(f'cipher {type(cipher)} not supported')

    with open(infile, 'rb') as ifl, open(outfile, 'wb') as of:
        decipher_block_size = (
            read_chunk_size + cipher_block_size - read_chunk_size % cipher_block_size
        )
        hasher = hashlib.sha512()
        while True:
            d = ifl.read(decipher_block_size)
            if not d:
                break
            r = cipher.decrypt(d)
            hasher.update(r)
            of.write(r)

    return hasher.hexdigest()
