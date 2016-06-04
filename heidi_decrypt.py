from itertools import izip_longest


def grouper(n, iterable, padvalue=None):
    "grouper(3, 'abcdefg', 'x') --> ('a','b','c'), ('d','e','f'), ('g','x','x')"
    return izip_longest(*[iter(iterable)] * n, fillvalue=padvalue)


def decrypt(s):
    def bytehandler(x):
        """ handles a pair of hex nibbles i.e. ("A", "0") """
        nr = int("".join(x), 16) - int(s[-1], 16)
        if nr < 0: nr += 255
        return chr(nr)

    return "".join(
        map(
            bytehandler,
            grouper(2, s[:-1]) # group all nibbles except the last into pairs
        )
    )


str1 = "7A6B797A6"
print(decrypt(str1))