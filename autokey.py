import random
from input import Converter

class AutokeyCipher:
    def __init__(self):
        self.LETTERS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    
    def generate_random_key(self):
        return random.choice(self.LETTERS)
    
    def encrypt(self, plaintext, key):
        if not key:
            raise ValueError("Key must have at least one character")

        key = key[0].upper()
        
        result = ""
        processed_count = 0 
        
        for i in range(len(plaintext)):
            char = plaintext[i]
            
            if char.isalpha():

                if processed_count == 0:
                    shift = ord(key) - 65
                else:
                    prev_idx = i - 1
                    while prev_idx >= 0:
                        if plaintext[prev_idx].isalpha():
                            break
                        prev_idx -= 1
                    prev_char = plaintext[prev_idx].upper()
                    shift = ord(prev_char) - 65

                if char.isupper():
                    result += chr((ord(char) + shift - 65) % 26 + 65)
                else:
                    result += chr((ord(char) + shift - 97) % 26 + 97)

                processed_count += 1
            else:
                result += char
        
        return result
    
    def decrypt(self, ciphertext, key):
        key = key[0].upper()
        
        result = ""
        processed_count = 0
        
        for i in range(len(ciphertext)):
            char = ciphertext[i]

            if char.isalpha():
                
                if processed_count == 0:
                    shift = ord(key) - 65
                else:
                    prev_idx = len(result) - 1
                    while prev_idx >= 0:
                        if result[prev_idx].isalpha():
                            break
                        prev_idx -= 1

                    prev_char = result[prev_idx].upper()
                    shift = ord(prev_char) - 65
                
                if char.isupper():
                    result += chr((ord(char) - shift - 65) % 26 + 65)
                else:
                    result += chr((ord(char) - shift - 97) % 26 + 97)
                
                processed_count += 1
            else:
                result += char
        
        return result
    
    def encrypt_hex(self, hex_string, key):
        text = Converter.hex2txt(hex_string)

        encrypted_text = self.encrypt(text, key)

        return Converter.txt2hex(encrypted_text)
    
    def decrypt_hex(self, hex_string, key):
        text = Converter.hex2txt(hex_string)

        decrypted_text = self.decrypt(text, key)

        return Converter.txt2hex(decrypted_text)