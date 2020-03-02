"""
Created: Mar. 1, 2020
Updated:

Author: Suleyman

=== DETAILS ===
This file houses the RSA key that either a client or server can use to encrypt, decrypt messages with.
"""

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from re import findall


class PublicKey(object):
    """
    Public key that is provided by a handshake with an unknown endpoint
    """
    def __init__(self, raw_data):
        try:
            # Try to parse data
            parsed_data = findall(r"(n{.*})(e{.*})", raw_data)[0]
            n = parsed_data[0]
            e = parsed_data[1]
            print('Parsed raw data successfully')

            self.rsa = RSA.construct((n, e))
            self.cipher = PKCS1_OAEP.new(self.rsa)
            print('Created Public RSA key successfully')

            print('Public Key created!')

        except Exception as e:
            print('CRITICAL ERROR: Could not resolve public key from raw data!')
            raise e

    def encrypt(self, msg):
        """
        This method will encrypt a message using the public key and can only be decrypted by the private key
        :param msg: String plain-text message
        :return: bytestream of the encrypted message
        """
        try:
            return self.cipher.encrypt(msg.encode('utf-8'))
        except AttributeError or UnicodeEncodeError:
            print('WARNING: Could not encode message, encrypting raw data!')
            return self.cipher.encrypt(msg)

    def decrypt(self, msg):
        """
        TODO: THIS DOES NOT WORK!!
        This method will decrypt a message using the public key. It is meant to decode messages that were encrypted
            using the private key.
        :param msg: Encrypted bytestream
        :return: Plain-text message
        """
        raise NotImplementedError
        # decrypted = None
        # try:
        #     decrypted = self.cipher.decrypt(msg)
        #     return decrypted.decode('utf-8')
        # except AttributeError or UnicodeDecodeError:
        #     print('WARNING: Could not decode message, returning raw data!')
        #     return decrypted


class PrivateKey(object):
    """
    Main Key object that Client and Server objects can use to create their RSA public and private keys as well as
    encrypt and decrypt messages using their public and/or private keys
    """
    def __init__(self, bit_level=None):
        print('Initializing RSA encryption...')
        self.bit_level = 2048 if bit_level is None else bit_level
        print(f'Bit level: {self.bit_level}')
        self.e = 23981519

        print('Generating new RSA keys...')
        self.rsa = RSA.generate(self.bit_level, e=self.e)
        # rsa_components (tuple):
        #     A tuple of integers, with at least 2 and no
        #     more than 6 items. The items come in the following order:
        #
        #     1. RSA modulus *n*.
        #     2. Public exponent *e*.
        #     3. Private exponent *d*.
        #        Only required if the key is private.
        #     4. First factor of *n* (*p*).
        #        Optional, but the other factor *q* must also be present.
        #     5. Second factor of *n* (*q*). Optional.
        #     6. CRT coefficient *q*, that is :math:`p^{-1} \text{mod }q`. Optional.
        # 'n', 'e', 'd', 'p', 'q', 'u'
        self.neg_rsa = RSA.construct((self.rsa.n, self.rsa.d, self.rsa.e, self.rsa.p, self.rsa.q, self.rsa.u))

        print('Creating ciphers...')
        self.cipher = PKCS1_OAEP.new(self.rsa)
        self.neg_cipher = PKCS1_OAEP.new(self.neg_rsa)

        print('Private Key generated!')

    def public_encrypt(self, msg):
        """
        This method will encrypt a message using the public key and can only be decrypted by the private key
        :param msg: String plain-text message
        :return: bytestream of the encrypted message
        """
        try:
            return self.cipher.encrypt(msg.encode('utf-8'))
        except AttributeError or UnicodeEncodeError:
            print('WARNING: Could not encode message, encrypting raw data!')
            return self.cipher.encrypt(msg)

    def private_encrypt(self, msg):
        """
        This method will encrypt a message using the private key and can only be decrypted by the public key
        :param msg: String plain-text message
        :return: bytestream of the encrypted message
        """
        try:
            return self.neg_cipher.encrypt(msg.encode('utf-8'))
        except AttributeError or UnicodeEncodeError:
            print('WARNING: Could not encode message, encrypting raw data!')
            return self.neg_cipher.encrypt(msg)

    def private_decrypt(self, msg):
        """
        This method will decrypt a message using the private key. It is meant to decode messages that were encrypted
            using the public key.
        :param msg: Encrypted bytestream
        :return: Plain-text message
        """
        decrypted = None
        try:
            decrypted = self.cipher.decrypt(msg)
            return decrypted.decode('utf-8')
        except AttributeError or UnicodeDecodeError:
            print('WARNING: Could not decode message, returning raw data!')
            return decrypted

    def public_decrypt(self, msg):
        """
        This method will decrypt a message using the public key. It is meant to decode messages that were encrypted
            using the private key.
        :param msg: Encrypted bytestream
        :return: Plain-text message
        """
        decrypted = None
        try:
            decrypted = self.neg_cipher.decrypt(msg)
            return decrypted.decode('utf-8')
        except AttributeError or UnicodeDecodeError:
            print('WARNING: Could not decode message, returning raw data!')
            return decrypted
