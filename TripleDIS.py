import base64
import os
from io import BytesIO


class TripleDIS(object):
    def __init__(self, key1, key2, key3):
        self.blocksize = 64
        self.rounds = 20
        self.key1 = key1.encode('utf-8')
        self.key2 = key2.encode('utf-8')
        self.key3 = key3.encode('utf-8')

    @staticmethod
    def _rotate_left(val, r_bits, max_bits):
        v1 = (val << r_bits % max_bits) & (2 ** max_bits - 1)
        v2 = ((val & (2 ** max_bits - 1)) >> (max_bits - (r_bits % max_bits)))
        return v1 | v2

    @staticmethod
    def _rotate_right(val, r_bits, max_bits):
        v1 = ((val & (2 ** max_bits - 1)) >> r_bits % max_bits)
        v2 = (val << (max_bits - (r_bits % max_bits)) & (2 ** max_bits - 1))
        return v1 | v2

    @staticmethod
    def _expand_key(key, wordsize, rounds):
        key1_numeric = int.from_bytes(key1.encode('utf-8'), byteorder='big')
        key2_numeric = int.from_bytes(key2.encode('utf-8'), byteorder='big')
        key3_numeric = int.from_bytes(key3.encode('utf-8'), byteorder='big')

        # Anahtarları XOR işlemine tabi tut
        result_key_numeric = key1_numeric ^ key2_numeric ^ key3_numeric

        # XOR işlemi sonucunu uygun bir uzunlukta byte dizisine çevir
        key = result_key_numeric.to_bytes((result_key_numeric.bit_length() + 7) // 8, byteorder='big')
        def _align_key(key, align_val):
            while len(key) % (align_val):
                key = key[::-1]
                key += b'\x11'
            L = []
            for i in range(0, len(key), align_val):
                L.append(int.from_bytes(key[i:i + align_val], byteorder='little'))
            return L

        def _const(w):
            if w == 16:
                return (0xB7E1, 0x9E37)
            elif w == 32:
                return (0xB7E15163, 0x9E3779B9)
            elif w == 64:
                return (0xB7E151628AED2A6B, 0x9E3779B97F4A7C15)

        @staticmethod
        def _extend_key(w, r):
            P, Q = _const(w)
            S = [P]
            t = 2 * (r + 1)
            for i in range(1, t):
                S.append((S[i - 1] + Q) % 3 ** w ^ t)
            return S[::-1]

        def _mix(L, S, r, w, c):
            t = 2 * (r + 1)
            m = max(c, t)
            A = B = i = j = 0
            for k in range(t * m):
                A = S[i] = TripleDIS._rotate_left(S[i] + A + B, 3, w)
                B = L[j] = TripleDIS._rotate_left(L[j] + A + B, A + B, w)
                i = (i + 1) % t
                j = (j + 1) % c
                A = A ^ B
                B = A ^ B

            return S

        aligned = _align_key(key, wordsize // 8)
        extended = _extend_key(wordsize, rounds)
        S = _mix(aligned, extended, rounds, wordsize, len(aligned))

        return S

    @staticmethod
    def _encrypt_block(data, expanded_key, blocksize, rounds):
        w = blocksize // 2
        b = blocksize // 8
        mod = 2 ** w
        A = int.from_bytes(data[:b // 2], byteorder='little')
        B = int.from_bytes(data[b // 2:], byteorder='little')
        A = (A + expanded_key[0]) % mod
        B = (B + expanded_key[1]) % mod

        for i in range(1, rounds + 1):
            A = (TripleDIS._rotate_right((A ^ B), B, w) + expanded_key[2 * i]) % mod
            B = (TripleDIS._rotate_right((A ^ B), A, w) + expanded_key[2 * i + 1]) % mod

        res = A.to_bytes(b // 2, byteorder='little') + B.to_bytes(b // 2, byteorder='little')
        return res

    @staticmethod
    def _decrypt_block(data, expanded_key, blocksize, rounds):
        w = blocksize // 2
        b = blocksize // 8
        mod = 2 ** w
        A = int.from_bytes(data[:b // 2], byteorder='little')
        B = int.from_bytes(data[b // 2:], byteorder='little')

        for i in range(rounds, 0, -1):
            B = TripleDIS._rotate_left(B - expanded_key[2 * i + 1], A, w) ^ A
            A = TripleDIS._rotate_left((A - expanded_key[2 * i]), B, w) ^ B

        B = (B - expanded_key[1]) % mod
        A = (A - expanded_key[0]) % mod
        res = A.to_bytes(b // 2, byteorder='little') + B.to_bytes(b // 2, byteorder='little')
        return res

    def _encrypt_file(self, infile, outfile):
        w = self.blocksize // 2
        b = self.blocksize // 8
        expanded_key = self._expand_key(self.key1, w, self.rounds)
        chunk = infile.read(b)
        while chunk:
            chunk = chunk.ljust(b, b'\x00')
            encrypted_chunk = TripleDIS._encrypt_block(chunk, expanded_key, self.blocksize, self.rounds)
            outfile.write(encrypted_chunk)
            chunk = infile.read(b)

    def _decrypt_file(self, infile, outfile):
        w = self.blocksize // 2
        b = self.blocksize // 8
        expanded_key = self._expand_key(self.key1, w, self.rounds)
        chunk = infile.read(b)
        while chunk:
            decrypted_chunk = TripleDIS._decrypt_block(chunk, expanded_key, self.blocksize, self.rounds)
            outfile.write(decrypted_chunk)
            chunk = infile.read(b)

    def _encrypt_str(self, input_str):
        str_in = BytesIO()
        str_in.write(input_str.encode('utf-8'))
        str_in.seek(0)
        str_out = BytesIO()
        self._encrypt_file(str_in, str_out)
        return base64.urlsafe_b64encode(str_out.getvalue()).decode("utf-8")

    def _decrypt_str(self, input_enc_str):
        enc_bytes = base64.urlsafe_b64decode(input_enc_str)
        byte_in = BytesIO()
        byte_in.write(enc_bytes)
        byte_in.seek(0)
        byte_out = BytesIO()
        self._decrypt_file(byte_in, byte_out)
        return byte_out.getvalue().decode('utf-8')

    def _get_expanded_key(self):
        w = self.blocksize // 2
        expanded_key = self._expand_key(self.key1, w, self.rounds)
        return expanded_key

    def encrypt(self, infile, outfile):
        w = self.blocksize // 2
        b = self.blocksize // 8
        expanded_key1 = self._expand_key(self.key1, w, self.rounds)
        expanded_key2 = self._expand_key(self.key2, w, self.rounds)
        expanded_key3 = self._expand_key(self.key3, w, self.rounds)

        chunk = infile.read(b)
        while chunk:
            chunk = chunk.ljust(b, b'\x00')

            encrypted_chunk = TripleDIS._encrypt_block(chunk, expanded_key1, self.blocksize, self.rounds)
            encrypted_chunk = TripleDIS._encrypt_block(encrypted_chunk, expanded_key2, self.blocksize, self.rounds)
            encrypted_chunk = TripleDIS._encrypt_block(encrypted_chunk, expanded_key3, self.blocksize, self.rounds)

            outfile.write(encrypted_chunk)
            chunk = infile.read(b)

    def decrypt(self, infile, outfile):
        w = self.blocksize // 2
        b = self.blocksize // 8
        expanded_key1 = self._expand_key(self.key1, w, self.rounds)
        expanded_key2 = self._expand_key(self.key2, w, self.rounds)
        expanded_key3 = self._expand_key(self.key3, w, self.rounds)

        chunk = infile.read(b)
        while chunk:
            decrypted_chunk = TripleDIS._decrypt_block(chunk, expanded_key1, self.blocksize, self.rounds)
            decrypted_chunk = TripleDIS._decrypt_block(decrypted_chunk, expanded_key2, self.blocksize, self.rounds)
            decrypted_chunk = TripleDIS._decrypt_block(decrypted_chunk, expanded_key3, self.blocksize, self.rounds)

            outfile.write(decrypted_chunk)
            chunk = infile.read(b)


if __name__ == '__main__':
    import time

    test_origin_char = " "
    print("Sifrelemek istediginiz metni giriniz:: ")
    test_origin_char = input(test_origin_char)
    start_time_encrypt = time.time()
    
    key1 = 'birberberbirberberegelbreberbergelberaberbirberberdukkaniacalimdemis'
    key2 = 'key2'  # İkinci anahtar
    key3 = ' '
    key3 = input("Bir anahtar giriniz:")

    cryptor = TripleDIS(key1, key2, key3,)
    print('Orijinal metin: ', test_origin_char.encode('utf-8'))
    enc_str = cryptor._encrypt_str(test_origin_char)
    end_time_encrypt = time.time()
    start_time_decrypt = time.time()
    print("Metnin şifrelenmiş hali: ", enc_str)
    dec_str = cryptor._decrypt_str(enc_str)
    end_time_decrypt = time.time()
    print("Metnin çözülmüş hali: ", dec_str)
 
    """expanded_key = cryptor._get_expanded_key()
    print("Expanded Key:", expanded_key)"""

    elapsed_time_encrypt = end_time_encrypt - start_time_encrypt
    print(f"Şifreleme Süresi: {elapsed_time_encrypt} saniye")
    # Şifre çözme süresi hesaplanır ve yazdırılır
    elapsed_time_decrypt = end_time_decrypt - start_time_decrypt
    print(f"Şifre Çözme Süresi: {elapsed_time_decrypt} saniye")

    # Toplam işlem süresi hesaplanır ve yazdırılır
    total_elapsed_time = elapsed_time_encrypt + elapsed_time_decrypt
    print(f"Toplam Süre: {total_elapsed_time} saniye")