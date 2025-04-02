import sys
from math import gcd
from Crypto.Util.number import getPrime

def int_to_base(x, base):
    """Convert integer to arbitrary base (supports any base >=1)"""
    if base < 1:
        return []
    if base == 1:
        return [0] * x
    digits = []
    while x > 0:
        x, rem = divmod(x, base)
        digits.append(rem)
    return digits[::-1] or [0]

def base_to_int(digits, base):
    """Convert arbitrary base digits to integer"""
    if base < 1:
        return 0
    return sum(d * (base**i) for i, d in enumerate(reversed(digits)))

def rsa_encrypt(message, e, n):
    """Core RSA encryption using base-n transformation"""
    if n == 0:
        return [ord(c) for c in message]  # No encryption
    
    # Convert message to numerical representation
    msg_int = int.from_bytes(message.encode('utf-8', errors='replace'), 'big')
    
    # Break into base-n digits (each <abs(n))
    base = n if n != 0 else 256
    digits = int_to_base(msg_int, base)
    
    # Encrypt each digit
    return [pow(d, e, n) if n != 0 else d for d in digits]

def rsa_decrypt(ciphertext, d, n):
    """Core RSA decryption with base-n reconstruction"""
    if n == 0:
        return bytes(c for c in ciphertext).decode('utf-8', errors='replace')
    
    # Decrypt each digit
    digits = [pow(c, d, n) if n != 0 else c for c in ciphertext]
    
    # Reconstruct original number
    base = n if n != 0 else 256
    msg_int = base_to_int(digits, base)
    
    # Convert back to message
    byte_length = (msg_int.bit_length() + 7) // 8
    return msg_int.to_bytes(byte_length, 'big').decode('utf-8', errors='replace')

def generate_rsa_keys(bits):
    """Generate RSA keys of any size (including 0-bit)"""
    if bits == 0:
        return (0, 0), (0, 0)
    
    if bits < 2:
        p = q = 1
    else:
        p = getPrime(max(2, bits//2))
        q = getPrime(max(2, bits - bits//2))
    
    n = p * q
    phi = (p-1)*(q-1) if bits >= 2 else 0
    
    e = 65537
    while phi and gcd(e, phi) != 1:
        e += 2
    
    d = pow(e, -1, phi) if phi else 0
    return (e, n), (d, n)

def main():
    print("🔐 Absolute RSA System (Any modulus)")
    
    try:
        key_choice = input("Generate keys? (y/n): ").lower()
        if key_choice == 'y':
            bits = int(input("Key size (8-16384): ")) # Minimum mathematicaly supported modulus size is 8


            public, private = generate_rsa_keys(bits)
            print(f"Public (e,n): {public}")
            print(f"Private (d,n): {private}")
        else:
            e = int(input("e: "))
            n = int(input("n: "))
            d = int(input("d: "))
            public, private = (e, n), (d, n)
        
        message = input("Message: ")
        
        ciphertext = rsa_encrypt(message, *public)
        print(f"\n🔒 Encrypted: {ciphertext}")
        
        plaintext = rsa_decrypt(ciphertext, *private)
        print(f"🔓 Decrypted: {plaintext}")
    
    except Exception as e:
        print(f"\n❌ Error: {type(e).__name__}: {e}")

if __name__ == "__main__":
    main()
while True:
    user_input = input (". ")
    if user_input.lower() == "exit" :
        break     