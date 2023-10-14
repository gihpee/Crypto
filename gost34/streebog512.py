from gost34.streebog import GOST34112012
from gost34.pbkdf2 import pbkdf2 as pbkdf2_base
import binascii


class streebog512(GOST34112012):
    def __init__(self, data=b""):
        data = data[::-1]
        super(streebog512, self).__init__(data, digest_size=64)


def new(data=b""):
    return streebog512(data)


def pbkdf2(password, salt, iterations, dklen):
    return pbkdf2_base(streebog512, password, salt, iterations, dklen)

