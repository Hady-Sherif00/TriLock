import secrets

class AES:
    def __init__(self):
        self.sbox = [
            0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
            0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
            0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
            0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
            0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
            0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
            0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
            0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
            0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
            0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
            0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
            0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
            0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
            0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
            0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
            0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
        ]
        
        self.inv_sbox = [
            0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
            0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
            0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
            0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
            0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
            0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
            0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
            0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
            0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
            0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
            0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
            0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
            0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
            0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
            0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
            0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
        ]
        
        self.rcon = [
            0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36,
            0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6
        ]
        
        self.num_rounds = 10
    
    def sub_bytes(self, state):
        for i in range(4):
            for j in range(4):
                state[i][j] = self.sbox[state[i][j]]
        return state
    
    def inv_sub_bytes(self, state):
        for i in range(4):
            for j in range(4):
                state[i][j] = self.inv_sbox[state[i][j]]
        return state
    
    def shift_rows(self, state):
        state[1] = state[1][1:] + state[1][:1]

        state[2] = state[2][2:] + state[2][:2]

        state[3] = state[3][3:] + state[3][:3]
        return state
    
    def inv_shift_rows(self, state):
        state[1] = state[1][-1:] + state[1][:-1]

        state[2] = state[2][-2:] + state[2][:-2]

        state[3] = state[3][-3:] + state[3][:-3]
        return state
    
    def galois_multiply(self, a, b):
        p = 0
        for i in range(8):
            if b & 1:
                p ^= a
            hi_bit_set = a & 0x80
            a <<= 1
            if hi_bit_set:
                a ^= 0x1b 
            b >>= 1
        return p & 0xff
    
    def mix_columns(self, state):
        for i in range(4):
            s0 = state[0][i]
            s1 = state[1][i]
            s2 = state[2][i]
            s3 = state[3][i]
            
            state[0][i] = self.galois_multiply(0x02, s0) ^ self.galois_multiply(0x03, s1) ^ s2 ^ s3
            state[1][i] = s0 ^ self.galois_multiply(0x02, s1) ^ self.galois_multiply(0x03, s2) ^ s3
            state[2][i] = s0 ^ s1 ^ self.galois_multiply(0x02, s2) ^ self.galois_multiply(0x03, s3)
            state[3][i] = self.galois_multiply(0x03, s0) ^ s1 ^ s2 ^ self.galois_multiply(0x02, s3)
        return state
    
    def inv_mix_columns(self, state):
        for i in range(4):
            s0 = state[0][i]
            s1 = state[1][i]
            s2 = state[2][i]
            s3 = state[3][i]
            
            state[0][i] = self.galois_multiply(0x0e, s0) ^ self.galois_multiply(0x0b, s1) ^ self.galois_multiply(0x0d, s2) ^ self.galois_multiply(0x09, s3)
            state[1][i] = self.galois_multiply(0x09, s0) ^ self.galois_multiply(0x0e, s1) ^ self.galois_multiply(0x0b, s2) ^ self.galois_multiply(0x0d, s3)
            state[2][i] = self.galois_multiply(0x0d, s0) ^ self.galois_multiply(0x09, s1) ^ self.galois_multiply(0x0e, s2) ^ self.galois_multiply(0x0b, s3)
            state[3][i] = self.galois_multiply(0x0b, s0) ^ self.galois_multiply(0x0d, s1) ^ self.galois_multiply(0x09, s2) ^ self.galois_multiply(0x0e, s3)
        return state
    
    def add_round_key(self, state, round_key):
        for i in range(4):
            for j in range(4):
                state[i][j] ^= round_key[i][j]
        return state
    
    def expand_key(self, key):
        key_bytes = bytes.fromhex(key) if isinstance(key, str) else key
        if len(key_bytes) < 16:
            key_bytes = key_bytes.ljust(16, b'\0')
        elif len(key_bytes) > 16:
            key_bytes = key_bytes[:16]

        key_words = [0] * 44 
        for i in range(4):
            key_words[i] = (key_bytes[4*i] << 24) | (key_bytes[4*i+1] << 16) | (key_bytes[4*i+2] << 8) | key_bytes[4*i+3]

        for i in range(4, 44):
            temp = key_words[i-1]
            if i % 4 == 0:
                temp = ((temp << 8) | (temp >> 24)) & 0xFFFFFFFF

                temp = (self.sbox[(temp >> 24) & 0xFF] << 24) | \
                       (self.sbox[(temp >> 16) & 0xFF] << 16) | \
                       (self.sbox[(temp >> 8) & 0xFF] << 8) | \
                       self.sbox[temp & 0xFF]
                
                temp ^= self.rcon[i // 4 - 1] << 24

            key_words[i] = key_words[i-4] ^ temp

        round_keys = []
        for r in range(self.num_rounds + 1):
            round_key = [[0 for _ in range(4)] for _ in range(4)]
            for j in range(4):
                word = key_words[r*4 + j]
                for i in range(4):
                    round_key[i][j] = (word >> (24 - 8*i)) & 0xFF
            round_keys.append(round_key)
        
        return round_keys
    
    def bytes_to_state(self, data):
        state = [[0 for _ in range(4)] for _ in range(4)]
        for j in range(4):
            for i in range(4):
                state[i][j] = data[i + 4*j]
        return state
    
    def state_to_bytes(self, state):
        output = bytearray(16)
        for j in range(4):
            for i in range(4):
                output[i + 4*j] = state[i][j]
        return output
    
    def pad_data(self, data):
        if isinstance(data, str):
            data = data.encode('utf-8')
        
        padding_length = 16 - (len(data) % 16)
        padding = bytes([padding_length] * padding_length)
        return data + padding
    
    def unpad_data(self, data):
        padding_length = data[-1]
        if padding_length > 16:
            return data 
        
        for i in range(1, padding_length + 1):
            if data[-i] != padding_length:
                return data
                
        return data[:-padding_length]
    
    def encrypt_block(self, block, round_keys):
        state = self.bytes_to_state(block)

        state = self.add_round_key(state, round_keys[0])

        for r in range(1, self.num_rounds):
            state = self.sub_bytes(state)
            state = self.shift_rows(state)
            state = self.mix_columns(state)
            state = self.add_round_key(state, round_keys[r])

        state = self.sub_bytes(state)
        state = self.shift_rows(state)
        state = self.add_round_key(state, round_keys[self.num_rounds])
        
        return self.state_to_bytes(state)
    
    def decrypt_block(self, block, round_keys):
        state = self.bytes_to_state(block)

        state = self.add_round_key(state, round_keys[self.num_rounds])
        state = self.inv_shift_rows(state)
        state = self.inv_sub_bytes(state)

        for r in range(self.num_rounds - 1, 0, -1):
            state = self.add_round_key(state, round_keys[r])
            state = self.inv_mix_columns(state)
            state = self.inv_shift_rows(state)
            state = self.inv_sub_bytes(state)

        state = self.add_round_key(state, round_keys[0])
        
        return self.state_to_bytes(state)
    
    def encrypt(self, plaintext, key):
        plaintext_bytes = self.pad_data(plaintext)

        round_keys = self.expand_key(key)

        ciphertext = bytearray()
        for i in range(0, len(plaintext_bytes), 16):
            block = plaintext_bytes[i:i+16]
            encrypted_block = self.encrypt_block(block, round_keys)
            ciphertext.extend(encrypted_block)
            
        return ciphertext
    
    def decrypt(self, ciphertext, key):
        if isinstance(ciphertext, str):
            try:
                ciphertext = bytes.fromhex(ciphertext)
            except ValueError:
                ciphertext = ciphertext.encode('utf-8')

        round_keys = self.expand_key(key)

        plaintext = bytearray()
        for i in range(0, len(ciphertext), 16):
            block = ciphertext[i:i+16]
            decrypted_block = self.decrypt_block(block, round_keys)
            plaintext.extend(decrypted_block)

        unpadded = self.unpad_data(plaintext)

        try:
            return unpadded.decode('utf-8')
        except UnicodeDecodeError:
            return unpadded

    @staticmethod
    def generate_random_key(key_size=128):
        if key_size not in [128, 192, 256]:
            raise ValueError("Key size must be 128, 192, or 256 bits")

        bytes_needed = key_size // 8

        random_bytes = secrets.token_bytes(bytes_needed)

        return random_bytes.hex().upper()