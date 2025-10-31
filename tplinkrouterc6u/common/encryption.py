from base64 import b64encode, b64decode
from Crypto.PublicKey.RSA import construct
from Crypto.Cipher import PKCS1_v1_5
from binascii import b2a_hex, hexlify
from Crypto.Cipher import AES
from Crypto import Random
from Crypto.PublicKey import RSA
from Crypto.Util.number import bytes_to_long, long_to_bytes
from Crypto.Util.Padding import pad, unpad
from time import time
from random import randint
from Crypto.Random import get_random_bytes

class EncryptionWrapper:
    def __init__(self) -> None:
        self._iv = b2a_hex(Random.get_random_bytes(8))
        self._key = b2a_hex(Random.get_random_bytes(8))

    def aes_encrypt(self, raw: str) -> str:
        raw = self._pad(raw)
        cipher = AES.new(self._key, AES.MODE_CBC, self._iv)
        return b64encode(cipher.encrypt(raw.encode())).decode()

    def aes_decrypt(self, enc: str):
        enc = b64decode(enc)
        cipher = AES.new(self._key, AES.MODE_CBC, self._iv)
        decrypted = cipher.decrypt(enc)
        result = self._unpad(decrypted)
        return result.decode()

    @staticmethod
    def rsa_encrypt(data: str, nn: str, ee: str) -> str:
        e = int(ee, 16)
        n = int(nn, 16)

        key = construct((n, e))
        cipher = PKCS1_v1_5.new(key)

        result = cipher.encrypt(data.encode())
        return b2a_hex(result).decode()

    def get_signature(self, seq: int, is_login: bool, hash: str, nn: str, ee: str) -> str:
        if is_login:
            s = '{}&h={}&s={}'.format(self._get_aes_string(), hash, seq)
        else:
            s = 'h={}&s={}'.format(hash, seq)

        sign = ''
        pos = 0

        while pos < len(s):
            sign = sign + self.rsa_encrypt(s[pos:pos + 53], nn, ee)
            pos = pos + 53

        return sign

    def _pad(self, s: str) -> str:
        return s + (AES.block_size - len(s) % AES.block_size) * chr(AES.block_size - len(s) % AES.block_size)

    @staticmethod
    def _unpad(s):
        return s[:-ord(s[len(s) - 1:])]

    def _get_aes_string(self) -> str:
        return 'k={}&i={}'.format(self._key.decode(), self._iv.decode())

    @staticmethod
    def encrypt_password_C1200(password: str, nn: str, ee: str) -> str:
        n = int(nn, 16)
        e = int(ee, 16)
        key = RSA.construct((n, e))

        modulus_byte_length = (key.size_in_bits() + 7) // 8
        password_bytes = password.encode('utf-8')
        if len(password_bytes) > modulus_byte_length:
            raise ValueError("Password too long for the RSA key size.")

        padded_password = password_bytes.ljust(modulus_byte_length, b'\x00')
        message_int = bytes_to_long(padded_password)
        encrypted_int = pow(message_int, e, n)
        encrypted_hex = format(encrypted_int, 'x').zfill(256)

        return encrypted_hex


class EncryptionWrapperMR:
    RSA_USE_PKCS_V1_5 = False
    AES_KEY_LEN = 16  # 128-bit AES
    AES_IV_LEN = 12  # GCM uses 96-bit IV, not 16!

    def __init__(self):
        self.key_bytes = get_random_bytes(self.AES_KEY_LEN)
        self.iv_bytes = get_random_bytes(self.AES_IV_LEN)

        self.key = b64encode(self.key_bytes).decode()
        self.iv = b64encode(self.iv_bytes).decode()

    def aes_encrypt(self, raw: str) -> tuple[str, str]:
        cipher = AES.new(self.key_bytes, AES.MODE_GCM, nonce=self.iv_bytes)
        ciphertext, tag = cipher.encrypt_and_digest(raw.encode('utf-8'))
        return (
            b64encode(ciphertext).decode(),  # router expects b64 ciphertext
            b64encode(tag).decode()  # router expects b64 tag
        )

    def aes_decrypt(self, combined_b64: str):
        # split into ciphertext_b64 and tag_b64 at the FIRST '=' only
        tag_b64 = combined_b64[-24:]  # last 24 characters
        ciphertext_b64 = combined_b64[:-24]
        ciphertext = b64decode(ciphertext_b64)
        tag = b64decode(tag_b64)
        cipher = AES.new(self.key_bytes, AES.MODE_GCM, nonce=self.iv_bytes)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        return plaintext.decode('utf8')

    def get_signature(self, seq: int, is_login: bool, hash: str, nn: str, ee: str) -> str:
        if is_login:
            # on login we also send our AES key, which is subsequently
            # used for E2E encrypted communication
            sign_data = f"key={self.key}&iv={self.iv}&h={hash}&s={seq}"
        else:
            sign_data = f"h={hash}&s={seq}"
        # set step based on whether PKCS padding is used
        rsa_byte_len = len(nn) // 2  # hexlen / 2 * 8 / 8
        step = (rsa_byte_len - 11) if self.RSA_USE_PKCS_V1_5 else rsa_byte_len

        # encrypt the signature using the RSA public key
        rsa_key = self._make_rsa_pub_key(nn, ee)

        # make the PKCS#1 v1.5 cipher
        if self.RSA_USE_PKCS_V1_5:
            rsa = PKCS1_v1_5.new(rsa_key)

        signature = ''
        pos = 0

        while pos < len(sign_data):
            sign_data_bin = sign_data[pos: pos + step].encode('utf8')

            if self.RSA_USE_PKCS_V1_5:
                # encrypt using the PKCS#1 v1.5 padding
                enc = rsa.encrypt(sign_data_bin)
            else:
                # encrypt using NOPADDING
                # ... pad the end with zero bytes
                while len(sign_data_bin) < step:
                    sign_data_bin = sign_data_bin + b'\0'

                # step 3a (OS2IP)
                em_int = bytes_to_long(sign_data_bin)

                # step 3b (RSAEP)
                m_int = rsa_key._encrypt(em_int)

                # step 3c (I2OSP)
                enc = long_to_bytes(m_int, 1)

            # hexlify to string
            enc_str = hexlify(enc).decode('utf8')

            # pad the start with '0' hex char
            while len(enc_str) < rsa_byte_len * 2:
                enc_str = '0' + enc_str

            signature += enc_str
            pos = pos + step

        return signature

    def _make_aes_cipher(self) -> AES:
        return AES.new(self._key.encode('utf8'), AES.MODE_CBC, iv=self._iv.encode('utf8'))

    @staticmethod
    def _make_rsa_pub_key(nn: str, ee: str):
        '''
        Makes a new RSA pub key from tuple (n, e)
        '''
        n = int('0x' + nn, 16)
        e = int('0x' + ee, 16)
        return RSA.construct((n, e))
