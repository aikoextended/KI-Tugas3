def gcd(a, b):
    """Menghitung Greatest Common Divisor"""
    while b:
        a, b = b, a % b
    return a

def extended_gcd(a, b):
    """Extended Euclidean Algorithm"""
    if a == 0:
        return b, 0, 1
    gcd_val, x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return gcd_val, x, y

def mod_inverse(e, phi):
    """Menghitung modular multiplicative inverse"""
    gcd_val, x, _ = extended_gcd(e, phi)
    if gcd_val != 1:
        raise Exception("Modular inverse tidak ada")
    return x % phi

def is_prime(n):
    """Cek apakah bilangan prima"""
    if n < 2:
        return False
    if n == 2:
        return True
    if n % 2 == 0:
        return False
    for i in range(3, int(n**0.5) + 1, 2):
        if n % i == 0:
            return False
    return True

def generate_keypair(p, q):
    """Generate RSA key pair dari dua bilangan prima"""
    if not (is_prime(p) and is_prime(q)):
        raise ValueError("Kedua bilangan harus prima")
    if p == q:
        raise ValueError("p dan q tidak boleh sama")
    
    n = p * q
    phi = (p - 1) * (q - 1)
    
    # Pilih e (gunakan 65537 yang umum digunakan)
    e = 65537
    if gcd(e, phi) != 1:
        # Jika tidak cocok, cari e yang cocok
        e = 3
        while gcd(e, phi) != 1:
            e += 2
    
    d = mod_inverse(e, phi)
    
    # Public key: (e, n), Private key: (d, n)
    return ((e, n), (d, n))

def string_to_int(text):
    """Convert string ke integer - MENDUKUNG STRING PANJANG"""
    # Convert setiap karakter ke ASCII dan gabungkan
    result = 0
    for char in text:
        result = (result << 8) + ord(char)
    return result

def int_to_string(num):
    """Convert integer ke string - MENDUKUNG STRING PANJANG"""
    if num == 0:
        return ""
    
    result = ""
    while num > 0:
        result = chr(num & 0xFF) + result
        num = num >> 8
    return result

def encrypt(public_key, plaintext):
    """Enkripsi menggunakan public key - MENDUKUNG STRING PANJANG"""
    e, n = public_key
    
    # Convert plaintext to integer
    plaintext_int = string_to_int(plaintext)
    
    if plaintext_int >= n:
        raise ValueError(f"Plaintext terlalu panjang untuk key ini. Plaintext: {plaintext_int}, n: {n}")
    
    # Encrypt
    ciphertext_int = pow(plaintext_int, e, n)
    return ciphertext_int

def decrypt(private_key, ciphertext_int):
    """Dekripsi menggunakan private key - MENDUKUNG STRING PANJANG"""
    d, n = private_key
    
    # Decrypt
    plaintext_int = pow(ciphertext_int, d, n)
    
    # Convert back to string
    plaintext = int_to_string(plaintext_int)
    return plaintext

def parse_public_key(key_string):
    """Parse public key dari string format 'e,n'"""
    parts = key_string.strip().split(',')
    if len(parts) != 2:
        raise ValueError("Format public key salah")
    e = int(parts[0])
    n = int(parts[1])
    return (e, n)

def parse_private_key(key_string):
    """Parse private key dari string format 'd,n'"""
    parts = key_string.strip().split(',')
    if len(parts) != 2:
        raise ValueError("Format private key salah")
    d = int(parts[0])
    n = int(parts[1])
    return (d, n)

def format_public_key(public_key):
    """Format public key ke string 'e,n'"""
    e, n = public_key
    return f"{e},{n}"

def format_private_key(private_key):
    """Format private key ke string 'd,n'"""
    d, n = private_key
    return f"{d},{n}"
