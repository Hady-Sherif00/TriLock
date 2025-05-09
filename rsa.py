import random
from input import Converter

class RSA:
    def __init__(self, key_size=1024):
        self.key_size = key_size

        self.p = self.generate_large_prime(key_size // 2)
        self.q = self.generate_large_prime(key_size // 2)

        self.e = 65537

        self.public_key, self.private_key, self.n = self.generateKeys()
        
    def is_probably_prime(self, n, k=40):
        if n == 2 or n == 3:
            return True
        if n <= 1 or n % 2 == 0:
            return False

        r, d = 0, n - 1
        while d % 2 == 0:
            r += 1
            d //= 2

        for _ in range(k):
            a = random.randint(2, n - 2)
            x = pow(a, d, n)
            if x == 1 or x == n - 1:
                continue
            for _ in range(r - 1):
                x = pow(x, 2, n)
                if x == n - 1:
                    break
            else:
                return False
        return True
        
    def generate_large_prime(self, bits):
        while True:
            prime_candidate = random.getrandbits(bits)
            prime_candidate |= (1 << bits - 1) | 1 
            if self.is_probably_prime(prime_candidate):
                return prime_candidate
    
    def power(self, base, expo, m):
        return pow(base, expo, m)
    
    def modInverse(self, e, phi):
        def extended_gcd(a, b):
            if a == 0:
                return b, 0, 1
            else:
                gcd, x, y = extended_gcd(b % a, a)
                return gcd, y - (b // a) * x, x
                
        gcd, x, y = extended_gcd(e, phi)
        if gcd != 1:
            raise ValueError("Modular inverse does not exist")
        else:
            return x % phi
    
    def gcd(self, a, b):
        while b != 0:
            a, b = b, a % b
        return a
    
    def generateKeys(self):
        n = self.p * self.q
        phi = (self.p - 1) * (self.q - 1)

        if self.gcd(self.e, phi) != 1:
            raise ValueError(f"e={self.e} and phi={phi} are not coprime")
        
        d = self.modInverse(self.e, phi)
        
        return self.e, d, n
    
    def encrypt(self, m, e=None, n=None):
        if e is None:
            e = self.public_key
        if n is None:
            n = self.n
            
        if m >= n:
            raise ValueError(f"Message ({m}) must be smaller than n ({n})")
            
        return self.power(m, e, n)
    
    def decrypt(self, c, d=None, n=None):
        if d is None:
            d = self.private_key
        if n is None:
            n = self.n
            
        return self.power(c, d, n)
    
    def encrypt_text(self, text):
        m = Converter.txt2dec(text)

        if m >= self.n:
            raise ValueError(f"Message too large for current key size. Use a larger key.")

        return self.encrypt(m)
    
    def decrypt_to_text(self, c):
        m = self.decrypt(c)

        hex_str = Converter.dec2hex(m)
        return Converter.hex2txt(hex_str)