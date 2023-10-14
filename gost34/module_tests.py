import unittest
import binascii
from unittest import TestCase
from gost34.grasshopper import grasshopper
from gost34.magma import magma
from gost34.streebog256 import streebog256
from gost34.streebog512 import streebog512
from gost34.gost3410 import DSGOST
from gost34.ec import ECPoint


def to_hex_list(a):
    return list(binascii.unhexlify(a))


class TestModuleMethods(unittest.TestCase):

    def test_grasshopper_encryption(self):
        a = to_hex_list('1122334455667700ffeeddccbbaa9988')
        k = to_hex_list('8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef')

        gost = grasshopper(k)
        c = gost.encryption(a)
        assert binascii.hexlify(bytearray(c)), b'7f679d90bebc24305a468d42b9d4edcd'

    def test_grasshopper_decryption(self):
        a = to_hex_list('1122334455667700ffeeddccbbaa9988')
        k = to_hex_list('8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef')

        gost = grasshopper(k)
        c = gost.encryption(a)
        d = gost.decryption(c)

        assert binascii.hexlify(bytearray(d)) == b'1122334455667700ffeeddccbbaa9988'

    def test_magma_encryption(self):
        a = to_hex_list('fedcba9876543210')
        k = binascii.unhexlify('ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff')

        gost = magma(k)
        c = gost.encrypt(a)
        assert binascii.hexlify(bytearray(c)), b'4ee901e5c2d8ca3d'

    def test_magma_decryption(self):
        a = to_hex_list('fedcba9876543210')
        k = binascii.unhexlify('ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff')

        gost = magma(k)
        c = gost.encrypt(a)
        d = gost.decrypt(c)
        assert binascii.hexlify(bytearray(d)), b'fedcba9876543210'
        
    def test_streebog_256_1(self):
        a = '323130393837363534333231303938373635343332313039383736353433323130393837363534333231303938373635343332313039383736353433323130'
        hsh = b'00557be5e584fd52a449b16b0251d05d27f94ab76cbaa6da890b59d8ef1e159d'
        
        gost = streebog256(binascii.unhexlify(a))
        
        assert gost.digest(), binascii.unhexlify(hsh)
        
    def test_streebog_256_2(self):
        a = 'fbe2e5f0eee3c820fbeafaebef20fffbf0e1e0f0f520e0ed20e8ece0ebe5f0f2f120fff0eeec20f120faf2fee5e2202ce8f6f3ede220e8e6eee1e8f0f2d1202ce8f0f2e5e220e5d1'
        hsh = b'508f7e553c06501d749a66fc28c6cac0b005746d97537fa85d9e40904efed29d'
        
        gost = streebog256(binascii.unhexlify(a))
        
        assert gost.digest(), binascii.unhexlify(hsh)
        
    def test_streebog_512_1(self):
        a = '323130393837363534333231303938373635343332313039383736353433323130393837363534333231303938373635343332313039383736353433323130'
        hsh = b'486f64c1917879417fef082b3381a4e211c324f074654c38823a7b76f830ad00fa1fbae42b1285c0352f227524bc9ab16254288dd6863dccd5b9f54a1ad0541b'
        
        gost = streebog512(binascii.unhexlify(a))
        
        assert gost.digest(), binascii.unhexlify(hsh)
        
    def test_streebog_512_2(self):
        a = 'fbe2e5f0eee3c820fbeafaebef20fffbf0e1e0f0f520e0ed20e8ece0ebe5f0f2f120fff0eeec20f120faf2fee5e2202ce8f6f3ede220e8e6eee1e8f0f2d1202ce8f0f2e5e220e5d1'
        hsh = b'28fbc9bada033b1460642bdcddb90c3fb3e56c497ccd0f62b8a2ad4935e85f037613966de4ee00531ae60f3b5a47f8dae06915d5f2f194996fcabf2622e6881e'
        
        gost = streebog512(binascii.unhexlify(a))
        
        assert gost.digest(), binascii.unhexlify(hsh)

    def test_gost_sign(self):
        p = 57896044618658097711785492504343953926634992332820282019728792003956564821041
        a = 7
        b = 43308876546767276905765904595650931995942111794451039583252968842033849580414
        x = 2
        y = 4018974056539037503335449422937059775635739389905545080690979365213431566280
        q = 57896044618658097711785492504343953927082934583725450622380973592137631069619
        gost = DSGOST(p, a, b, q, x, y)
        key = 55441196065363246126355624130324183196576709222340016572108097750006097525544
        message = 20798893674476452017134061561508270130637142515379653289952617252661468872421
        k = 53854137677348463731403841147996619241504003434302020712960838528893196233395
        sign = gost.sign(message, key, k)
        expected = (29700980915817952874371204983938256990422752107994319651632687982059210933395,
                    574973400270084654178925310019147038455227042649098563933718999175515839552)
        assert sign == expected

    def test_gost_verify(self):
        p = 57896044618658097711785492504343953926634992332820282019728792003956564821041
        a = 7
        b = 43308876546767276905765904595650931995942111794451039583252968842033849580414
        x = 2
        y = 4018974056539037503335449422937059775635739389905545080690979365213431566280
        q = 57896044618658097711785492504343953927082934583725450622380973592137631069619
        gost = DSGOST(p, a, b, q, x, y)
        message = 20798893674476452017134061561508270130637142515379653289952617252661468872421
        sign = (29700980915817952874371204983938256990422752107994319651632687982059210933395,
                574973400270084654178925310019147038455227042649098563933718999175515839552)
        q_x = 57520216126176808443631405023338071176630104906313632182896741342206604859403
        q_y = 17614944419213781543809391949654080031942662045363639260709847859438286763994
        public_key = ECPoint(q_x, q_y, a, b, p)
        assert gost.verify(message, sign, public_key) == True


