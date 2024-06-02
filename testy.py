from rsa import *
from md4 import *


def empty():
    md4 = MD4(b"")
    assert md4.get_hash() == 0x31D6CFE0D16AE931B73C59D7E0C089C0


def cyclic_shift():
    result = MD4._MD4__cyclic_shift(0b1100, 1, 4)
    assert result == 0b1001


def empty_file():
    md4 = MD4.from_file("empty.txt")
    assert md4.get_hash() == 0x31D6CFE0D16AE931B73C59D7E0C089C0


def test_file():
    md4 = MD4.from_file("test.txt")
    assert md4.get_hash() == 0xD35A25D76A6EDCB5D7E5BBCECF3D6EE5


def string():
    md4 = MD4.from_string("asfubvibjbk")
    assert md4.get_hash() == 0x10BAE3F2F1E94879F09AEEAAF5718C73


def test_generate_large_prime():
    rsa = RSA()
    prime = rsa.generate_large_prime(2048)
    assert is_prime(prime)


def test_encrypt_decrypt():
    rsa = RSA()
    plaintext = 123456789
    public_key, private_key = rsa.get_keys()
    ciphertext = RSA.encrypt(plaintext, public_key)
    decrypted_text = RSA.decrypt(ciphertext, private_key)
    assert decrypted_text == plaintext


def test_extended_gcd():
    a, b = 123, 456
    gcd, x, y = RSA.extended_gcd(a, b)
    assert gcd == 3
    assert a * x + b * y == gcd


def test_solve_dio_equation():
    rsa = RSA()
    b = rsa.solve_dio_equation()
    assert b == rsa.private_key[1]


def test_encrypt_message():
    N = 987654321
    e = 65537
    plaintext = 123456789
    ciphertext = RSA.encrypt_message(plaintext, N, e)
    assert ciphertext == 179832234


def test_decrypt_message():
    N = 987654321
    d = 123456789
    ciphertext = 179832234
    plaintext = RSA.decrypt_message(ciphertext, N, d)
    assert plaintext == 123456789


def is_prime(n):
    if n <= 1:
        return False
    for i in range(2, int(n**0.5) + 1):
        if n % i == 0:
            return False
    return True
