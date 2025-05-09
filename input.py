class Converter:

    @staticmethod
    def get_input():
        user_input = input("Enter the plaintext: ")
        return user_input
    
    @staticmethod
    def txt2hex(text):
        return text.encode('utf-8').hex().upper()

    @staticmethod
    def hex2txt(hex_str):
        try:
            return bytes.fromhex(hex_str).decode('utf-8')
        except:
            return "[Non-decodable data]"

    @staticmethod
    def hex2dec(hex_str):
        hex_str = hex_str.upper()
        return int(hex_str, 16)
    
    @staticmethod
    def dec2hex(decimal):
        return format(decimal, 'X')