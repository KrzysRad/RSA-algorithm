import random
import pickle


class RSA:
    __e: int = 65537

    @staticmethod
    def generate_large_prime(n):
        # Generate a large prime number of n bits using the Miller-Rabin primality test
        first_primes_list = [
            2,
            3,
            5,
            7,
            11,
            13,
            17,
            19,
            23,
            29,
            31,
            37,
            41,
            43,
            47,
            53,
            59,
            61,
            67,
            71,
            73,
            79,
            83,
            89,
            97,
            101,
            103,
            107,
            109,
            113,
            127,
            131,
            137,
            139,
            149,
            151,
            157,
            163,
            167,
            173,
            179,
            181,
            191,
            193,
            197,
            199,
            211,
            223,
            227,
            229,
            233,
            239,
            241,
            251,
            257,
            263,
            269,
            271,
            277,
            281,
            283,
            293,
            307,
            311,
            313,
            317,
            331,
            337,
            347,
            349,
            353,
            359,
            367,
            373,
            379,
            383,
            389,
            397,
            401,
            409,
            419,
            421,
            431,
            433,
            439,
            443,
            449,
            457,
            461,
            463,
            467,
            479,
            487,
            491,
            499,
        ]

        def nBitRandom(n):
            return random.randrange(2 ** (n - 1) + 1, 2**n - 1)

        def get_low_level_prime(n):
            # Generate a prime candidate divisible by first primes
            while True:
                # Obtain a random number
                num = nBitRandom(n)

                # Test divisibility by pre-generated primes
                for divisor in first_primes_list:
                    if num % divisor == 0 and divisor**2 <= num:
                        break
                else:
                    return num

        def is_miller_rabin_passed(mrc):
            # Run 20 iterations of Rabin Miller Primality test
            maxDivisionsByTwo = 0
            n = mrc - 1
            while n % 2 == 0:
                n >>= 1
                maxDivisionsByTwo += 1
            assert 2**maxDivisionsByTwo * n == mrc - 1

            def trialComposite(round_tester):
                if pow(round_tester, n, mrc) == 1:
                    return False
                for i in range(maxDivisionsByTwo):
                    if pow(round_tester, 2**i * n, mrc) == mrc - 1:
                        return False
                return True

            # Set number of trials here
            numberOfRabinTrials = 20
            for i in range(numberOfRabinTrials):
                round_tester = random.randrange(2, mrc)
                if trialComposite(round_tester):
                    return False
            return True

        while True:
            prime_candidate = get_low_level_prime(n)
            if not is_miller_rabin_passed(prime_candidate):
                continue
            else:
                return prime_candidate

    def __init__(self):
        self.p = RSA.generate_large_prime(2048)
        self.q = RSA.generate_large_prime(2048)
        self.private_key = None
        self.public_key = None

    @staticmethod
    def encrypt(plaintext, public_key):
        N, e = public_key
        ciphertext = RSA.encrypt_message(plaintext, N, e)
        return ciphertext

    @staticmethod
    def decrypt(ciphertext, private_key):
        N, d = private_key
        plaintext = RSA.decrypt_message(ciphertext, N, d)
        return plaintext

    def gen_keys(self):
        self.public_key = Key((self.p * self.q, RSA.__e))
        self.private_key = Key((self.p * self.q, RSA.solve_dio_equation(self)))

    @staticmethod
    def extended_gcd(a, b):
        if b == 0:
            return a, 1, 0
        gcd, x1, y1 = RSA.extended_gcd(b, a % b)
        x = y1
        y = x1 - (a // b) * y1
        return gcd, x, y

    def solve_dio_equation(self):
        a = 0
        b = 0

        gcd, x, y = RSA.extended_gcd(self.__e, (self.p - 1) * (self.q - 1))

        if gcd == 1:
            a = x
            b = y

        return b

    def print_keys(self):
        print(f"{self.p}\n\n{self.q}\n\n{self.public_key}\n\n{self.private_key}")

    def get_keys(self):
        return self.public_key, self.private_key

    def save_keys(self, path):
        pickle.dump(self.public_key, open(path + "/public_key", "wb"))
        pickle.dump(self.private_key, open(path + "/private_key", "wb"))

    # def load_keys(self, path):
    #     public_key = open(path + "/public_key", "rb")
    #     private_key = open(path + "/private_key", "rb")

    #     self.public_key = pickle.load(public_key)
    #     self.private_key = pickle.load(private_key)

    #     if not isinstance (self.public_key, Key) or not isinstance(self.private_key, Key):
    #         raise TypeError("Keys are not of type Key")
    #     return self.public_key, self.private_key
    
    @staticmethod
    def encrypt_message(m, N, e):
        c = pow(m, e, N) % N
        return c

    @staticmethod
    def decrypt_message(c, N, d):
        m = pow(c, d, N) % N
        return m


class Key:
    def __init__(self, key):
        self.key = key

    def get_key(self):
        return self.key


rsa = RSA()
rsa.gen_keys()
# rsa.print_keys()
