from input import Converter
from autokey import AutokeyCipher
from rsa import RSA
from aes import AES

rsa = RSA()
aes = AES()
ak = AutokeyCipher()

def encrypt_file(input_path, out_cipher_path, out_rsa_key_path, out_autokey_path):
    with open(input_path, "r", encoding="utf-8") as f:
        plain_text = f.read()

    # Hybrid encryption
    ak_key = ak.generate_random_key()
    ak_encrypted = ak.encrypt(plain_text, ak_key)

    aes_key = aes.generate_random_key()
    aes_encrypted = aes.encrypt(ak_encrypted, aes_key)

    aes_key_dec = Converter.hex2dec(aes_key)
    rsa_encrypted_key = rsa.encrypt(aes_key_dec)

    # Save outputs
    with open(out_cipher_path, "w") as f:
        f.write(aes_encrypted.hex().upper())

    with open(out_rsa_key_path, "w") as f:
        f.write(str(rsa_encrypted_key))

    with open(out_autokey_path, "w") as f:
        f.write(ak_key)

    print("[+] File encrypted successfully.")



def decrypt_file(cipher_path, rsa_key_path, ak_key_path, out_path):
    # Load RSA-encrypted AES key
    with open(rsa_key_path, "r") as f:
        rsa_encrypted_key = int(f.read().strip())

    aes_key_dec = rsa.decrypt(rsa_encrypted_key)
    aes_key = Converter.dec2hex(aes_key_dec)

    # Load ciphertext
    with open(cipher_path, "r") as f:
        aes_encrypted_hex = f.read().strip()
        aes_encrypted = bytes.fromhex(aes_encrypted_hex)

    aes_decrypted_raw = aes.decrypt(aes_encrypted, aes_key)

    if isinstance(aes_decrypted_raw, (bytes, bytearray)):
        try:
            aes_decrypted = aes_decrypted_raw.decode('utf-8')
        except UnicodeDecodeError:
            print("[ERROR] AES output is not valid UTF-8.")
            return
    else:
        aes_decrypted = aes_decrypted_raw

    # Load Autokey key
    with open(ak_key_path, "r") as f:
        ak_key = f.read().strip()

    final_plaintext = ak.decrypt(aes_decrypted, ak_key)

    with open(out_path, "w", encoding="utf-8") as f:
        f.write(final_plaintext)

    print("[+] File decrypted successfully.")

if __name__ == "__main__":
    # Encrypt a file
    encrypt_file("input.txt", "ciphertext.bin", "rsa_key.enc", "autokey.txt")

    # Decrypt the result
    decrypt_file("ciphertext.bin", "rsa_key.enc", "autokey.txt", "decrypted.txt")