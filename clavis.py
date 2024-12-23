import base64
from colorama import Fore, Style, init


init(autoreset=True)

def encode_to_base64(plain_text):
    try:
        encoded_bytes = base64.b64encode(plain_text.encode('utf-8'))
        encoded_string = encoded_bytes.decode('utf-8')
        return encoded_string
    except Exception as e:
        return f"Bir hata oluştu: {e}"

def decode_base64(encoded_string):
    try:
        decoded_bytes = base64.b64decode(encoded_string)
        decoded_string = decoded_bytes.decode('utf-8')
        return decoded_string
    except Exception as e:
        return f"Bir hata oluştu: {e}"

def caesar_cipher(text, shift, mode='encode'):
    result = ""
    for char in text:
        if char.isalpha():
            start = ord('a') if char.islower() else ord('A')
            offset = ord(char) - start
            if mode == 'encode':
                result += chr((offset + shift) % 26 + start)
            elif mode == 'decode':
                result += chr((offset - shift) % 26 + start)
        else:
            result += char
    return result

def brute_force_caesar(text):
    print(f"{Fore.YELLOW}{Style.BRIGHT}Bruteforce Çözüm (1-26 kaydırma):\n")
    for shift in range(1, 27):
        decoded_text = caesar_cipher(text, shift, mode='decode')
        print(f"Kaydırma {shift}: {decoded_text}")

def xor_cipher(text, key, mode='encode'):
    result = ""
    for i in range(len(text)):
        result += chr(ord(text[i]) ^ key)  
    return result

def brute_force_xor(text):
    print(f"{Fore.YELLOW}{Style.BRIGHT}Bruteforce XOR Çözümü (Anahtar 0-255 arası):\n")
    for key in range(256):
        decoded_text = xor_cipher(text, key, mode='decode')
        print(f"Anahtar {key}: {decoded_text}")

def encode_to_hex(plain_text):
    try:
        hex_string = plain_text.encode('utf-8').hex()
        return hex_string
    except Exception as e:
        return f"Bir hata oluştu: {e}"

def decode_from_hex(hex_string):
    try:
        decoded_string = bytes.fromhex(hex_string).decode('utf-8')
        return decoded_string
    except Exception as e:
        return f"Bir hata oluştu: {e}"

def print_header():
    
    print(f"{Fore.GREEN}{Style.BRIGHT}===================================")
    print(f"{Fore.GREEN}{Style.BRIGHT}              CLAVİS              |")
    print(f"{Fore.GREEN}{Style.BRIGHT}          **************          |")
    print(f"{Fore.GREEN}{Style.BRIGHT}       github.com/SametAkilli     |")
    print(f"{Fore.GREEN}{Style.BRIGHT}===================================\n\n\n")

def print_footer():
    
    print(f"{Fore.RED}{Style.BRIGHT}===================================")
    print(f"{Fore.RED}{Style.BRIGHT}   Programdan çıkılıyor...        ")
    print(f"{Fore.RED}{Style.BRIGHT}===================================")

def print_invalid_choice():
    
    print(f"{Fore.YELLOW}{Style.BRIGHT}===================================")
    print(f"{Fore.YELLOW}{Style.BRIGHT}  Geçersiz seçim! Lütfen '1', '2' veya '0' yazın. ")
    print(f"{Fore.YELLOW}{Style.BRIGHT}===================================\n\n\n")

def safe_int_input(prompt):
    
    while True:
        try:
            return int(input(prompt))
        except ValueError:
            print(f"{Fore.RED}{Style.BRIGHT}Geçersiz bir sayı girdiniz, lütfen tekrar deneyin.")

if __name__ == "__main__":
    while True:
        print_header()  

        print(f"{Fore.GREEN}{Style.BRIGHT}Ana Menü:")
        print(f"{Fore.CYAN}1. Base64 (Encode/Decode)")
        print(f"{Fore.CYAN}2. Caesar Cipher (Encode/Decode)")
        print(f"{Fore.CYAN}3. XOR (Encode/Decode/Bruteforce)")
        print(f"{Fore.CYAN}4. Hex (Encode/Decode)")
        print(f"{Fore.CYAN}0. Çıkış\n")

        choice = input("Seçiminizi yapın (1/2/3/4/0): ").strip()

        if choice == "1":
            
            while True:
                print(f"{Fore.RED}{Style.BRIGHT}Base64 Seçenekleri:")
                print(f"{Fore.CYAN}1. Encode (Base64 ile kodla)")
                print(f"{Fore.CYAN}2. Decode (Base64 çöz)")
                print(f"{Fore.CYAN}0. Ana Menüye Dön")

                base64_choice = input("Seçiminizi yapın (1/2/0): ").strip()

                if base64_choice == "1":
                    text = input(f"{Fore.GREEN}{Style.BRIGHT}Base64 ile encode edilecek metni girin: ")
                    encoded = encode_to_base64(text)
                    print(f"{Fore.GREEN}{Style.BRIGHT}===================================")
                    print(f"{Fore.GREEN}{Style.BRIGHT}Encoded metin: {encoded}")
                    print(f"{Fore.GREEN}{Style.BRIGHT}===================================\n")
                elif base64_choice == "2":
                    encoded = input(f"{Fore.BLUE}{Style.BRIGHT}Base64 ile encode edilmiş metni girin: ")
                    decoded = decode_base64(encoded)
                    print(f"{Fore.BLUE}{Style.BRIGHT}===================================")
                    print(f"{Fore.BLUE}{Style.BRIGHT}Çözülmüş metin: {decoded}")
                    print(f"{Fore.BLUE}{Style.BRIGHT}===================================\n")
                elif base64_choice == "0":
                    break  
                else:
                    print_invalid_choice()

        elif choice == "2":
            
            while True:
                print(f"{Fore.RED}{Style.BRIGHT}Caesar Cipher Seçenekleri:")
                print(f"{Fore.CYAN}1. Encode (Şifrele)")
                print(f"{Fore.CYAN}2. Decode (Çöz)")
                print(f"{Fore.CYAN}3. Bruteforce (Tüm Kaydırmalar)")
                print(f"{Fore.CYAN}0. Ana Menüye Dön")

                caesar_choice = input("Seçiminizi yapın (1/2/3/0): ").strip()

                if caesar_choice == "1":
                    text = input(f"{Fore.GREEN}{Style.BRIGHT}Şifrelenecek metni girin: ")
                    shift = safe_int_input(f"{Fore.GREEN}{Style.BRIGHT}Kaydırma değerini girin: ")
                    encoded = caesar_cipher(text, shift, mode='encode')
                    print(f"{Fore.GREEN}{Style.BRIGHT}===================================")
                    print(f"{Fore.GREEN}{Style.BRIGHT}Şifrelenmiş metin: {encoded}")
                    print(f"{Fore.GREEN}{Style.BRIGHT}===================================\n")
                elif caesar_choice == "2":
                    text = input(f"{Fore.BLUE}{Style.BRIGHT}Çözülmesi istenen şifreli metni girin: ")
                    shift = safe_int_input(f"{Fore.BLUE}{Style.BRIGHT}Kaydırma değerini girin: ")
                    decoded = caesar_cipher(text, shift, mode='decode')
                    print(f"{Fore.BLUE}{Style.BRIGHT}===================================")
                    print(f"{Fore.BLUE}{Style.BRIGHT}Çözülmüş metin: {decoded}")
                    print(f"{Fore.BLUE}{Style.BRIGHT}===================================\n")
                elif caesar_choice == "3":
                    text = input(f"{Fore.YELLOW}{Style.BRIGHT}Bruteforce ile çözülecek şifreli metni girin: ")
                    brute_force_caesar(text)
                elif caesar_choice == "0":
                    break  
                else:
                    print_invalid_choice()

        elif choice == "3":
            
            while True:
                print(f"{Fore.CYAN}{Style.BRIGHT}XOR Seçenekleri:")
                print(f"{Fore.CYAN}1. Encode (Şifrele)")
                print(f"{Fore.CYAN}2. Decode (Çöz)")
                print(f"{Fore.CYAN}3. Bruteforce (Anahtar 0-255)")
                print(f"{Fore.CYAN}0. Ana Menüye Dön")

                xor_choice = input("Seçiminizi yapın (1/2/3/0): ").strip()

                if xor_choice == "1":
                    text = input(f"{Fore.GREEN}{Style.BRIGHT}XOR ile şifrelenecek metni girin: ")
                    key = safe_int_input(f"{Fore.GREEN}{Style.BRIGHT}Anahtar (0-255) girin: ")
                    encoded = xor_cipher(text, key, mode='encode')
                    print(f"{Fore.GREEN}{Style.BRIGHT}===================================")
                    print(f"{Fore.GREEN}{Style.BRIGHT}Şifrelenmiş metin: {encoded}")
                    print(f"{Fore.GREEN}{Style.BRIGHT}===================================\n")
                elif xor_choice == "2":
                    text = input(f"{Fore.BLUE}{Style.BRIGHT}Çözülmesi istenen şifreli metni girin: ")
                    key = safe_int_input(f"{Fore.BLUE}{Style.BRIGHT}Anahtar (0-255) girin: ")
                    decoded = xor_cipher(text, key, mode='decode')
                    print(f"{Fore.BLUE}{Style.BRIGHT}===================================")
                    print(f"{Fore.BLUE}{Style.BRIGHT}Çözülmüş metin: {decoded}")
                    print(f"{Fore.BLUE}{Style.BRIGHT}===================================\n")
                elif xor_choice == "3":
                    text = input(f"{Fore.YELLOW}{Style.BRIGHT}Bruteforce ile çözülecek XOR şifreli metni girin: ")
                    brute_force_xor(text)
                elif xor_choice == "0":
                    break  
                else:
                    print_invalid_choice()

        elif choice == "4":
            
            while True:
                print(f"{Fore.CYAN}{Style.BRIGHT}Hex Seçenekleri:")
                print(f"{Fore.CYAN}1. Encode (Hex ile kodla)")
                print(f"{Fore.CYAN}2. Decode (Hex çöz)")
                print(f"{Fore.CYAN}0. Ana Menüye Dön")

                hex_choice = input("Seçiminizi yapın (1/2/0): ").strip()

                if hex_choice == "1":
                    text = input(f"{Fore.GREEN}{Style.BRIGHT}Hex ile encode edilecek metni girin: ")
                    encoded = encode_to_hex(text)
                    print(f"{Fore.GREEN}{Style.BRIGHT}===================================")
                    print(f"{Fore.GREEN}{Style.BRIGHT}Encoded metin (Hex): {encoded}")
                    print(f"{Fore.GREEN}{Style.BRIGHT}===================================\n")
                elif hex_choice == "2":
                    hex_string = input(f"{Fore.BLUE}{Style.BRIGHT}Hex ile encode edilmiş metni girin: ")
                    decoded = decode_from_hex(hex_string)
                    print(f"{Fore.BLUE}{Style.BRIGHT}===================================")
                    print(f"{Fore.BLUE}{Style.BRIGHT}Çözülmüş metin: {decoded}")
                    print(f"{Fore.BLUE}{Style.BRIGHT}===================================\n")
                elif hex_choice == "0":
                    break  
                else:
                    print_invalid_choice()

        elif choice == "0":
            print_footer()  
            break
        else:
            print_invalid_choice()  
