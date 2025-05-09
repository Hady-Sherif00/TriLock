from input import Converter
from autokey import AutokeyCipher
from rsa import RSA
from aes import AES

rsa = RSA()
aes = AES()
ak = AutokeyCipher()

plain_text = Converter.get_input()
plain_hex = Converter.txt2hex(plain_text)

ak_key = ak.generate_random_key()
ak_encrypt = ak.encrypt_hex(plain_hex, ak_key)

aes_key = aes.generate_random_key(128)
aes_encrypt = aes.encrypt(ak_encrypt, aes_key)

aes_dec = Converter.hex2dec(aes_encrypt.hex().upper())
rsa_encrypt = rsa.encrypt(aes_dec)

cipher_text = Converter.dec2hex(rsa_encrypt)
print(f"Cipher text: {cipher_text}")


rsa_decrypt = rsa.decrypt(rsa_encrypt)

rsa_hex = Converter.dec2hex(rsa_decrypt)
aes_decrypt = aes.decrypt(rsa_hex, aes_key)

ak_decrypt = ak.decrypt_hex(aes_decrypt, ak_key)

decrypted_text = Converter.hex2txt(ak_decrypt)
print(f"Decrypted Text: {decrypted_text}")