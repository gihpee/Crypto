from gost34.streebog import GOST34112012
import binascii


class streebog256(GOST34112012):
    def __init__(self, data=b""):
        data = data[::-1]
        super(streebog256, self).__init__(data, digest_size=32)


def new(data=b""):
    return streebog256(data)
