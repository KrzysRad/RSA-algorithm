import struct

# MD class for hashing a message

class MD4:
    # size of a message section in bits

    __block_size: int = 512

    # mask for bit truncation

    __mask: int = 0xFFFFFFFF

    # helper functions for the hashing process

    @staticmethod
    def __F(x: int, y: int, z: int) -> int:
        return (x & y) | ((~x) & z)

    @staticmethod
    def __G(x: int, y: int, z: int) -> int:
        return (x & y) | (y & z) | (x & z)

    @staticmethod
    def __H(x: int, y: int, z: int) -> int:
        return x ^ y ^ z

    # hash variables

    __f_values: list = [__F.__get__(object), __G.__get__(object), __H.__get__(object)]
    __y_values: list[int] = [0, 1518500249, 1859775393]
    __z_values: list[int] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
        0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15,
        0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15,
    ]
    __w_values: list[int] = [
        3, 7, 11, 19, 3, 7, 11, 19, 3, 7, 11, 19, 3, 7, 11, 19,
        3, 5, 9, 13, 3, 5, 9, 13, 3, 5, 9, 13, 3, 5, 9, 13,
        3, 9, 11, 15, 3, 9, 11, 15, 3, 9, 11, 15, 3, 9, 11, 15,
    ]

    # default constructor; input should be encoded as a bytes object

    def __init__(self, x: bytes):

        self.__hash_hex = None

        # assign the message to an object variable

        if isinstance(x, bytes):
            self.__message = x
        elif x is None:
            self.__message = b""
        else:
            raise TypeError("the argument must be a bytes object")

        # message padding
        
        # store the original message length in bits
        message_len = len(self.__message) * 8

        # append a byte with the first bit 1, the rest 0
        self.__message += b"\x80"

        # append zeros until len divisible by 512 bits
        self.__message += b"\x00" * (-(len(self.__message) + 8) % 64)

        # append length of the message in little endian
        self.__message += struct.pack("<Q", message_len)

    @classmethod
    def from_string(cls, x: str):
        return cls(x.encode("utf-8"))

    @classmethod
    def from_file(cls, x):
        with open(f"{x}", "r") as file:
#            s = file.read().rstrip("\n")
            s = file.read()
        return cls(s.encode("utf-8"))

    def get_hash(self) -> int:

        # if hashed already, just return the value

        if self.__hash_hex != None:
            return int(self.__hash_hex, 16)

        # split the message into chunks

        chunks = [self.__message[i : i + 64] for i in range(0, len(self.__message), 64)]

        # current state

        state = (0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476)

        # compute 3 full rounds for each message chunk

        for chunk in chunks:
            A, B, C, D = state

            # unpack the message into 16 32-bit little-endian values

            X = struct.unpack("<16I", chunk)

            # perform the 3 full rounds

            for j in range(48):

                # read round variables

                f = MD4.__f_values[j // 16]
                z = MD4.__z_values[j]
                x = X[z]
                y = MD4.__y_values[j // 16]
                w = MD4.__w_values[j]

                # calculate new state

                AA = D
                BB = A + f(B, C, D) + x + y
                BB &= MD4.__mask
                BB = MD4.__cyclic_shift(BB, w, 32)
                CC = B
                DD = C

                # replace old state with the new one

                A = AA
                B = BB
                C = CC
                D = DD

            # compute final state

            state = tuple((new_state + old_state) & MD4.__mask for new_state, old_state in zip((A, B, C, D), state))

        hash_bytes = struct.pack("<4I", *state)
        hash_hex = "".join(f"{value:02x}" for value in hash_bytes)
        self.__hash_hex = hash_hex
        return int(hash_hex, 16)

    # cyclic shift left implementation

    @staticmethod
    def __cyclic_shift(n: int, d: int, N: int) -> int:
        return ((n << d) % (1 << N)) | (n >> (N - d))

    def __str__(self):
        return self.__hash_hex

# testing

if __name__ == "__main__":
    h = "aaa.txt"
    h = MD4(bytes("Ala ma kota", encoding = "utf-8"))
    h = MD4.from_file("Ala.txt")
    h = MD4(bytes("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", encoding = "utf-8"))
    print(h._MD4__message)
    print(h.get_hash())
    print(h.get_hash())
    print(str(h))

