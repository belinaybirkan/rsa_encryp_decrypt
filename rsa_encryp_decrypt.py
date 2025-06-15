import math
import json



def is_prime(n):
    if n < 2: return False
    for i in range(2, int(math.sqrt(n)) + 1):
        if n % i == 0: return False
    return True

def extended_gcd(a, b):
    if b == 0:
        return a, 1, 0
    else:
        g, x1, y1 = extended_gcd(b, a % b)
        x, y = y1, x1 - (a // b) * y1
        return g, x, y

def mod_inverse(e, phi):
    g, x, _ = extended_gcd(e, phi)
    if g != 1:
        raise Exception("Modular inverse does not exist.")
    return x % phi

def string_to_int(s):
    return int.from_bytes(s.encode('utf-8'), 'big')

def int_to_string(i):
    return i.to_bytes((i.bit_length() + 7) // 8, 'big').decode('utf-8')


# RSA Functions


def encrypt(x, e, n):
    return pow(x, e, n)

def decrypt(y, d, n):
    return pow(y, d, n)

def factor_n(n):
    for i in range(2, 1001):
        if n % i == 0 and is_prime(i):
            q = n // i
            if is_prime(q) and q <= 1000:
                return i, q
    raise ValueError("n cannot be factored into two primes <= 1000.")

def save_to_file(filename, data):
    with open(filename, 'w') as f:
        json.dump(data, f)

def load_from_file(filename):
    with open(filename, 'r') as f:
        return json.load(f)

#main
def main():
    print("RSA Encryption/Decryption System (No crypto library)")
    mode = input("Choose mode: (1) Encrypt, (2) Decrypt: ").strip()

    if mode == "1":
        p = int(input("Enter prime p (<=1000): "))
        q = int(input("Enter prime q (<=1000): "))
        plaintext = input("Enter plaintext (as string): ")

        if not (is_prime(p) and is_prime(q)):
            print("Both p and q must be prime.")
            return

        n = p * q
        phi_n = (p - 1) * (q - 1)

        # Select public exponent e
        e = 65537
        if math.gcd(e, phi_n) != 1:
            for i in range(3, phi_n, 2):
                if math.gcd(i, phi_n) == 1:
                    e = i
                    break

        x = string_to_int(plaintext)
        y = encrypt(x, e, n)

        print(f"Ciphertext (as integer): {y}")
        save_to_file("rsa_data.json", {"y": y, "n": n, "e": e})
        print("Data saved to rsa_data.json")

    elif mode == "2":
        data = load_from_file("rsa_data.json")
        y, n, e = data["y"], data["n"], data["e"]

        print(f"Loaded ciphertext: {y}")
        print(f"Public key (n={n}, e={e})")

        p, q = factor_n(n)
        print(f"Factors found: p={p}, q={q}")

        phi_n = (p - 1) * (q - 1)
        d = mod_inverse(e, phi_n)

        x = decrypt(y, d, n)
        plaintext = int_to_string(x)
        print(f"Decrypted plaintext: {plaintext}")

    else:
        print("Invalid mode.")

if __name__ == "__main__":
    main()

