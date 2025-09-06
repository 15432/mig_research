import os, sys
import random
from binascii import unhexlify as uhx, hexlify as hx
from Crypto.Cipher import AES
from Crypto.Util import Counter
import struct

if sys.version_info[0] == 3:
    _ord = lambda x: x
    _chr = lambda x: bytes([x])
else:
    _ord = ord
    _chr = chr

tea_key = uhx("ECC9BDEA1EE73E55BDE80FA94FF62C50")

aes_key_0 = uhx("1CEE98758A99C3865DE3C29DE1FA02C58937A3555D392C5CB41BB204E292D27F")
aes_key_1 = uhx("0000000000000000000000000000000000000000000000000000000000000000")
aes_key_2 = uhx("84D04BB2454E9756D7702C723EA6CAD85D7B6AC32E86EB7130DE692F058C8DDE")
aes_key_3 = uhx("B5E32BE20C114C1D7D63ABAD8154C61783C3186FED4E69920BCDDE477D91BF1B")
aes_key_4 = uhx("DC7BF19B5354CD75F1E96E33313CA8434ECB24035238651DE69F0A71DFC313D8")
aes_key_5 = uhx("8BA3ABFC061D38C4B3DDAE99A532641A819E0484DF18FE9A941BAD9026E1FEDC")
aes_key_6 = uhx("8EF150FE1B869E80FF8967B25E7BF25F28272E4BBB7FAE3957E44FA7EA2D81DA")
aes_key_7 = uhx("F7F54D5B996124FF9E37D84855B54CC20BCEC09C10A0978BAE2CF590039902F0")
aes_keys = [aes_key_0, aes_key_1, aes_key_2, aes_key_3, aes_key_4, aes_key_5, aes_key_6, aes_key_7]

def u32(x):
    return (x & 0xFFFFFFFF)
    
def lsl(val, n):
    return u32(u32(val) << n)

def lsr(val, n):
    return u32(u32(val) >> n)

def xor(s1, s2):
    return b''.join(_chr(_ord(a) ^ _ord(b)) for a,b in zip(s1,s2))

def aes_ecb_enc(buf, key):
    return AES.new(key, AES.MODE_ECB).encrypt(buf)

def aes_ecb_dec(buf, key):
    return AES.new(key, AES.MODE_ECB).decrypt(buf)

def tea_encrypt(block, key):
    (sum, delta) = 0, 0x9E3779B9
    key, (v0, v1) = struct.unpack("<4L", key), struct.unpack("<2L", block)
    for _ in range(32):
        sum = (sum + delta) & 0xFFFFFFFF
        v0 = (v0 + (((v1 << 4) + key[0]) ^ (v1 + sum) ^ ((v1 >> 5) + key[1]))) & 0xFFFFFFFF
        v1 = (v1 + (((v0 << 4) + key[2]) ^ (v0 + sum) ^ ((v0 >> 5) + key[3]))) & 0xFFFFFFFF
    return struct.pack("<2L", v0, v1)
    
def tea_decrypt(block, key):
    (sum, delta) = 0xC6EF3720, 0x9E3779B9 
    key, (v0, v1) = struct.unpack("<4L", key), struct.unpack("<2L", block)
    for _ in range(32):
        v1 = (v1 - (((v0 << 4) + key[2]) ^ (v0 + sum) ^ ((v0 >> 5) + key[3]))) & 0xFFFFFFFF
        v0 = (v0 - (((v1 << 4) + key[0]) ^ (v1 + sum) ^ ((v1 >> 5) + key[1]))) & 0xFFFFFFFF
        sum = (sum - delta) & 0xFFFFFFFF
    return struct.pack("<2L", v0, v1)

def advance_xor_stream(stream):
    stream_words = struct.unpack("<10I", stream)
    
    stream_adv_words = [0]*10
    for i in range(10):
        stream_adv_words[i] = stream_words[i]
        
    tmp_var_0 = stream_adv_words[1]
    tmp_var_1 = stream_adv_words[4]
    tmp_var_2 = stream_adv_words[5]
    tmp_var_3 = stream_adv_words[6]
    tmp_var_4 = stream_adv_words[7]
    tmp_var_5 = stream_adv_words[8]
    tmp_var_6 = stream_adv_words[9]
    tmp_var_7 = stream_adv_words[0]
    tmp_var_8 = stream_adv_words[2]
    tmp_var_9 = stream_adv_words[3]
    tmp_var_10 = 0xFFFFFFFF
    
    for counter in range(0x4, 0xC):
        tmp_var_11 = tmp_var_7
        tmp_var_12 = counter
        tmp_var_13 = (tmp_var_11 ^ tmp_var_5)
        tmp_var_14 = lsl(tmp_var_12, 0x4)
        tmp_var_11 = 0xF0
        tmp_var_14 = (tmp_var_11 - tmp_var_14)
        tmp_var_11 = tmp_var_8
        tmp_var_14 = (tmp_var_14 | tmp_var_12)
        tmp_var_15 = (tmp_var_0 ^ tmp_var_6)
        tmp_var_12 = (tmp_var_14 >> 0x1F)
        tmp_var_14 = (tmp_var_14 ^ tmp_var_11)
        tmp_var_11 = tmp_var_9
        tmp_var_1 = (tmp_var_14 ^ tmp_var_1)
        tmp_var_14 = (tmp_var_10 ^ tmp_var_15)
        tmp_var_16 = tmp_var_14
        tmp_var_12 = (tmp_var_12 ^ tmp_var_11)
        tmp_var_14 = tmp_var_9
        tmp_var_2 = (tmp_var_12 ^ tmp_var_2)
        tmp_var_11 = tmp_var_8
        tmp_var_0 = (tmp_var_10 ^ tmp_var_14)
        tmp_var_14 = (tmp_var_10 ^ tmp_var_2)
        tmp_var_5 = (tmp_var_5 ^ tmp_var_3)
        tmp_var_12 = (tmp_var_10 ^ tmp_var_13)
        tmp_var_17 = tmp_var_14
        tmp_var_14 = (tmp_var_10 ^ tmp_var_4)
        tmp_var_6 = (tmp_var_6 ^ tmp_var_4)
        tmp_var_18 = tmp_var_12
        tmp_var_19 = tmp_var_14
        tmp_var_12 = (tmp_var_10 ^ tmp_var_11)
        tmp_var_14 = (tmp_var_10 ^ tmp_var_5)
        tmp_var_11 = (tmp_var_10 ^ tmp_var_1)
        tmp_var_7 = tmp_var_11
        tmp_var_20 = tmp_var_14
        tmp_var_11 = (tmp_var_10 ^ tmp_var_3)
        tmp_var_14 = (tmp_var_10 ^ tmp_var_6)
        tmp_var_21 = tmp_var_14
        tmp_var_11 = (tmp_var_5 & tmp_var_11)
        tmp_var_14 = tmp_var_19
        tmp_var_12 = (tmp_var_1 & tmp_var_12)
        tmp_var_1 = (tmp_var_11 ^ tmp_var_1)
        tmp_var_11 = tmp_var_20
        tmp_var_14 = (tmp_var_6 & tmp_var_14)
        tmp_var_12 = (tmp_var_12 ^ tmp_var_13)
        tmp_var_0 = (tmp_var_2 & tmp_var_0)
        tmp_var_2 = (tmp_var_14 ^ tmp_var_2)
        tmp_var_14 = (tmp_var_13 & tmp_var_11)
        tmp_var_13 = tmp_var_21
        tmp_var_14 = (tmp_var_14 ^ tmp_var_3)
        tmp_var_11 = tmp_var_18
        tmp_var_0 = (tmp_var_0 ^ tmp_var_15)
        tmp_var_19 = tmp_var_14
        tmp_var_15 = (tmp_var_15 & tmp_var_13)
        tmp_var_14 = tmp_var_8
        tmp_var_15 = (tmp_var_15 ^ tmp_var_4)
        tmp_var_21 = tmp_var_15
        tmp_var_13 = (tmp_var_11 & tmp_var_14)
        tmp_var_15 = tmp_var_16
        tmp_var_14 = tmp_var_9
        tmp_var_13 = (tmp_var_13 ^ tmp_var_5)
        tmp_var_11 = (tmp_var_15 & tmp_var_14)
        tmp_var_18 = tmp_var_13
        tmp_var_15 = tmp_var_7
        tmp_var_13 = tmp_var_17
        tmp_var_3 = (tmp_var_15 & tmp_var_3)
        tmp_var_5 = (tmp_var_13 & tmp_var_4)
        tmp_var_15 = tmp_var_9
        tmp_var_5 = (tmp_var_5 ^ tmp_var_0)
        tmp_var_5 = (tmp_var_5 ^ tmp_var_15)
        tmp_var_13 = tmp_var_18
        tmp_var_15 = tmp_var_21
        tmp_var_11 = (tmp_var_11 ^ tmp_var_6)
        tmp_var_14 = tmp_var_8
        tmp_var_0 = (tmp_var_0 ^ tmp_var_11)
        tmp_var_3 = (tmp_var_3 ^ tmp_var_12)
        tmp_var_15 = (tmp_var_2 ^ tmp_var_15)
        tmp_var_12 = (tmp_var_12 ^ tmp_var_13)
        tmp_var_6 = (tmp_var_3 ^ tmp_var_14)
        tmp_var_13 = lsl(tmp_var_0, 0xD)
        tmp_var_3 = tmp_var_19
        tmp_var_16 = tmp_var_15
        tmp_var_15 = lsr(tmp_var_12, 0x13)
        tmp_var_15 = (tmp_var_13 | tmp_var_15)
        tmp_var_14 = (tmp_var_1 ^ tmp_var_3)
        tmp_var_9 = tmp_var_15
        tmp_var_3 = lsl(tmp_var_12, 0xD)
        tmp_var_15 = lsr(tmp_var_0, 0x13)
        tmp_var_15 = (tmp_var_3 | tmp_var_15)
        tmp_var_7 = tmp_var_15
        tmp_var_4 = lsl(tmp_var_0, 0x4)
        tmp_var_15 = lsr(tmp_var_12, 0x1C)
        tmp_var_4 = (tmp_var_4 | tmp_var_15)
        tmp_var_3 = lsr(tmp_var_0, 0x1C)
        tmp_var_15 = lsl(tmp_var_12, 0x4)
        tmp_var_15 = (tmp_var_15 | tmp_var_3)
        tmp_var_3 = tmp_var_9
        tmp_var_1 = (tmp_var_10 ^ tmp_var_1)
        tmp_var_13 = (tmp_var_3 ^ tmp_var_4)
        tmp_var_3 = tmp_var_7
        tmp_var_13 = (tmp_var_12 ^ tmp_var_13)
        tmp_var_15 = (tmp_var_3 ^ tmp_var_15)
        tmp_var_12 = lsl(tmp_var_5, 0x3)
        tmp_var_0 = (tmp_var_0 ^ tmp_var_15)
        tmp_var_15 = lsr(tmp_var_6, 0x1D)
        tmp_var_12 = (tmp_var_15 | tmp_var_12)
        tmp_var_3 = lsr(tmp_var_5, 0x1D)
        tmp_var_15 = lsl(tmp_var_6, 0x3)
        tmp_var_3 = (tmp_var_3 | tmp_var_15)
        tmp_var_7 = tmp_var_13
        tmp_var_15 = lsl(tmp_var_5, 0x19)
        tmp_var_13 = lsr(tmp_var_6, 0x7)
        tmp_var_13 = (tmp_var_13 | tmp_var_15)
        tmp_var_4 = lsl(tmp_var_6, 0x19)
        tmp_var_15 = lsr(tmp_var_5, 0x7)
        tmp_var_15 = (tmp_var_15 | tmp_var_4)
        tmp_var_12 = (tmp_var_12 ^ tmp_var_13)
        tmp_var_2 = (tmp_var_10 ^ tmp_var_2)
        tmp_var_12 = (tmp_var_5 ^ tmp_var_12)
        tmp_var_15 = (tmp_var_3 ^ tmp_var_15)
        tmp_var_15 = (tmp_var_6 ^ tmp_var_15)
        tmp_var_13 = lsl(tmp_var_2, 0x1F)
        tmp_var_9 = tmp_var_12
        tmp_var_12 = lsr(tmp_var_1, 0x1)
        tmp_var_13 = (tmp_var_13 | tmp_var_12)
        tmp_var_8 = tmp_var_15
        tmp_var_12 = lsr(tmp_var_2, 0x1)
        tmp_var_15 = lsl(tmp_var_1, 0x1F)
        tmp_var_3 = (tmp_var_15 | tmp_var_12)
        tmp_var_15 = lsl(tmp_var_2, 0x1A)
        tmp_var_12 = lsr(tmp_var_1, 0x6)
        tmp_var_6 = lsr(tmp_var_2, 0x6)
        tmp_var_12 = (tmp_var_15 | tmp_var_12)
        tmp_var_15 = lsl(tmp_var_1, 0x1A)
        tmp_var_5 = tmp_var_16
        tmp_var_15 = (tmp_var_15 | tmp_var_6)
        tmp_var_12 = (tmp_var_13 ^ tmp_var_12)
        tmp_var_15 = (tmp_var_3 ^ tmp_var_15)
        tmp_var_1 = (tmp_var_1 ^ tmp_var_12)
        tmp_var_2 = (tmp_var_2 ^ tmp_var_15)
        tmp_var_12 = lsr(tmp_var_14, 0xA)
        tmp_var_15 = lsl(tmp_var_5, 0x16)
        tmp_var_15 = (tmp_var_15 | tmp_var_12)
        tmp_var_4 = lsl(tmp_var_14, 0x16)
        tmp_var_12 = lsr(tmp_var_5, 0xA)
        tmp_var_4 = (tmp_var_4 | tmp_var_12)
        tmp_var_3 = lsl(tmp_var_5, 0xF)
        tmp_var_12 = lsr(tmp_var_14, 0x11)
        tmp_var_3 = (tmp_var_3 | tmp_var_12)
        tmp_var_3 = (tmp_var_15 ^ tmp_var_3)
        tmp_var_13 = lsr(tmp_var_5, 0x11)
        tmp_var_12 = lsl(tmp_var_14, 0xF)
        tmp_var_3 = (tmp_var_14 ^ tmp_var_3)
        tmp_var_14 = tmp_var_18
        tmp_var_12 = (tmp_var_12 | tmp_var_13)
        tmp_var_4 = (tmp_var_4 ^ tmp_var_12)
        tmp_var_15 = lsl(tmp_var_11, 0x19)
        tmp_var_12 = lsr(tmp_var_14, 0x7)
        tmp_var_15 = (tmp_var_15 | tmp_var_12)
        tmp_var_6 = lsl(tmp_var_14, 0x19)
        tmp_var_12 = lsr(tmp_var_11, 0x7)
        tmp_var_6 = (tmp_var_6 | tmp_var_12)
        tmp_var_4 = (tmp_var_5 ^ tmp_var_4)
        tmp_var_12 = lsl(tmp_var_11, 0x17)
        tmp_var_5 = tmp_var_18
        tmp_var_14 = lsr(tmp_var_14, 0x9)
        tmp_var_14 = (tmp_var_14 | tmp_var_12)
        tmp_var_13 = lsl(tmp_var_5, 0x17)
        tmp_var_6 = (tmp_var_6 ^ tmp_var_14)
        tmp_var_12 = lsr(tmp_var_11, 0x9)
        tmp_var_12 = (tmp_var_12 | tmp_var_13)
        tmp_var_5 = (tmp_var_15 ^ tmp_var_12)
        tmp_var_12 = tmp_var_18
        tmp_var_5 = (tmp_var_12 ^ tmp_var_5)
        tmp_var_6 = (tmp_var_11 ^ tmp_var_6)
    
    stream_adv_words[0] = tmp_var_7
    stream_adv_words[1] = tmp_var_0
    stream_adv_words[2] = tmp_var_8
    stream_adv_words[3] = tmp_var_9
    stream_adv_words[4] = tmp_var_1
    stream_adv_words[5] = tmp_var_2
    stream_adv_words[6] = tmp_var_3
    stream_adv_words[7] = tmp_var_4
    stream_adv_words[8] = tmp_var_5
    stream_adv_words[9] = tmp_var_6
    
    stream_adv = b''
    for i in range(10):
        stream_adv += struct.pack("<I", stream_adv_words[i])

    return stream_adv

def generate_xor_stream(seed):
    seed_words = struct.unpack("<20I", seed)
    
    rand_0_0 = random.getrandbits(32)
    rand_0_1 = random.getrandbits(32)
    rand_1_0 = random.getrandbits(32)
    rand_1_1 = random.getrandbits(32)
    rand_2_0 = random.getrandbits(32)
    rand_2_1 = random.getrandbits(32)
    rand_3_0 = random.getrandbits(32)
    rand_3_1 = random.getrandbits(32)
    rand_4_0 = random.getrandbits(32)
    rand_4_1 = random.getrandbits(32)
    
    stream_words = [0]*20
    for i in range(20):
        stream_words[i] = seed_words[i]
        
    for counter in range(0xC):
        tmp_var_0 = stream_words[16]
        tmp_var_1 = stream_words[0]
        tmp_var_2 = stream_words[18]
        tmp_var_1 = (tmp_var_1 ^ tmp_var_0)
        tmp_var_3 = tmp_var_1
        stream_words[0] = tmp_var_1
        tmp_var_1 = stream_words[2]
        tmp_var_4 = stream_words[17]
        tmp_var_1 = (tmp_var_1 ^ tmp_var_2)
        tmp_var_5 = stream_words[1]
        tmp_var_6 = tmp_var_1
        stream_words[2] = tmp_var_1
        tmp_var_1 = stream_words[12]
        tmp_var_5 = (tmp_var_5 ^ tmp_var_4)
        tmp_var_1 = (tmp_var_1 ^ tmp_var_0)
        tmp_var_7 = stream_words[19]
        tmp_var_8 = tmp_var_5
        stream_words[1] = tmp_var_5
        stream_words[16] = tmp_var_1
        tmp_var_5 = stream_words[3]
        tmp_var_1 = stream_words[14]
        tmp_var_5 = (tmp_var_5 ^ tmp_var_7)
        tmp_var_1 = (tmp_var_1 ^ tmp_var_2)
        tmp_var_9 = stream_words[13]
        tmp_var_2 = stream_words[15]
        tmp_var_10 = tmp_var_5
        stream_words[3] = tmp_var_5
        tmp_var_5 = counter
        tmp_var_9 = (tmp_var_9 ^ tmp_var_4)
        tmp_var_2 = (tmp_var_2 ^ tmp_var_7)
        tmp_var_11 = stream_words[8]
        tmp_var_7 = 0xF0
        stream_words[17] = tmp_var_9
        stream_words[19] = tmp_var_2
        tmp_var_9 = stream_words[4]
        tmp_var_2 = lsl(tmp_var_5, 0x4)
        tmp_var_12 = stream_words[9]
        tmp_var_2 = (tmp_var_7 - tmp_var_2)
        stream_words[18] = tmp_var_1
        tmp_var_1 = stream_words[5]
        tmp_var_11 = (tmp_var_11 ^ tmp_var_9)
        tmp_var_2 = (tmp_var_2 | tmp_var_5)
        tmp_var_5 = (tmp_var_2 >> 0x1F)
        tmp_var_12 = (tmp_var_12 ^ tmp_var_1)
        tmp_var_2 = (tmp_var_2 ^ tmp_var_11)
        stream_words[8] = tmp_var_2
        tmp_var_2 = (tmp_var_5 ^ tmp_var_12)
        stream_words[9] = tmp_var_2
        tmp_var_2 = stream_words[10]
        tmp_var_5 = stream_words[6]
        tmp_var_11 = tmp_var_8
        tmp_var_2 = (tmp_var_2 ^ tmp_var_5)
        stream_words[10] = tmp_var_2
        tmp_var_5 = stream_words[7]
        tmp_var_2 = stream_words[11]
        tmp_var_2 = (tmp_var_2 ^ tmp_var_5)
        tmp_var_5 = tmp_var_3
        stream_words[11] = tmp_var_2
        tmp_var_2 = 0xFFFFFFFF
        tmp_var_12 = (tmp_var_2 ^ tmp_var_5)
        tmp_var_5 = (tmp_var_2 ^ tmp_var_11)
        tmp_var_9 = (tmp_var_12 & tmp_var_9)
        tmp_var_5 = (tmp_var_5 & tmp_var_1)
        tmp_var_13 = tmp_var_9
        tmp_var_14 = tmp_var_5
        tmp_var_4 = rand_0_0
        tmp_var_0 = rand_0_1
        tmp_var_7 = stream_words[0]
        tmp_var_9 = stream_words[6]
        tmp_var_11 = stream_words[1]
        tmp_var_12 = (tmp_var_2 ^ tmp_var_7)
        tmp_var_1 = stream_words[7]
        tmp_var_15 = tmp_var_4
        tmp_var_4 = (tmp_var_12 & tmp_var_9)
        tmp_var_12 = stream_words[4]
        tmp_var_5 = (tmp_var_2 ^ tmp_var_11)
        tmp_var_16 = tmp_var_4
        tmp_var_4 = stream_words[2]
        tmp_var_5 = (tmp_var_5 & tmp_var_1)
        tmp_var_9 = (tmp_var_9 ^ tmp_var_12)
        tmp_var_9 = (tmp_var_4 & tmp_var_9)
        tmp_var_17 = tmp_var_5
        tmp_var_5 = stream_words[5]
        tmp_var_18 = tmp_var_9
        tmp_var_9 = stream_words[3]
        tmp_var_1 = (tmp_var_1 ^ tmp_var_5)
        tmp_var_1 = (tmp_var_9 & tmp_var_1)
        tmp_var_19 = tmp_var_1
        tmp_var_1 = stream_words[8]
        tmp_var_12 = (tmp_var_2 ^ tmp_var_12)
        tmp_var_12 = (tmp_var_1 & tmp_var_12)
        tmp_var_1 = stream_words[9]
        tmp_var_5 = (tmp_var_2 ^ tmp_var_5)
        tmp_var_5 = (tmp_var_1 & tmp_var_5)
        tmp_var_12 = (tmp_var_12 ^ tmp_var_7)
        tmp_var_5 = (tmp_var_5 ^ tmp_var_11)
        stream_words[0] = tmp_var_12
        stream_words[1] = tmp_var_5
        tmp_var_20 = tmp_var_0
        tmp_var_4 = rand_1_0
        tmp_var_0 = rand_1_1
        tmp_var_1 = stream_words[0]
        tmp_var_21 = stream_words[11]
        tmp_var_1 = (tmp_var_1 ^ tmp_var_4)
        stream_words[0] = tmp_var_1
        tmp_var_1 = stream_words[1]
        tmp_var_5 = stream_words[9]
        tmp_var_22 = stream_words[5]
        tmp_var_1 = (tmp_var_1 ^ tmp_var_0)
        tmp_var_11 = stream_words[7]
        stream_words[1] = tmp_var_1
        tmp_var_1 = (tmp_var_21 ^ tmp_var_5)
        tmp_var_11 = (tmp_var_11 & tmp_var_1)
        tmp_var_1 = (tmp_var_2 ^ tmp_var_22)
        tmp_var_1 = (tmp_var_1 & tmp_var_21)
        tmp_var_1 = (tmp_var_11 ^ tmp_var_1)
        tmp_var_11 = stream_words[3]
        tmp_var_23 = stream_words[10]
        tmp_var_12 = stream_words[8]
        tmp_var_24 = stream_words[4]
        tmp_var_1 = (tmp_var_11 ^ tmp_var_1)
        tmp_var_7 = stream_words[6]
        tmp_var_9 = (tmp_var_23 ^ tmp_var_12)
        tmp_var_1 = (tmp_var_1 ^ tmp_var_0)
        tmp_var_7 = (tmp_var_7 & tmp_var_9)
        stream_words[3] = tmp_var_1
        tmp_var_9 = (tmp_var_2 ^ tmp_var_24)
        tmp_var_1 = stream_words[12]
        tmp_var_9 = (tmp_var_9 & tmp_var_23)
        tmp_var_12 = (tmp_var_2 ^ tmp_var_12)
        tmp_var_9 = (tmp_var_7 ^ tmp_var_9)
        tmp_var_12 = (tmp_var_1 & tmp_var_12)
        tmp_var_7 = stream_words[2]
        tmp_var_1 = stream_words[13]
        tmp_var_5 = (tmp_var_2 ^ tmp_var_5)
        tmp_var_9 = (tmp_var_7 ^ tmp_var_9)
        tmp_var_5 = (tmp_var_1 & tmp_var_5)
        tmp_var_12 = (tmp_var_12 ^ tmp_var_24)
        tmp_var_5 = (tmp_var_5 ^ tmp_var_22)
        tmp_var_9 = (tmp_var_9 ^ tmp_var_4)
        stream_words[2] = tmp_var_9
        stream_words[4] = tmp_var_12
        stream_words[5] = tmp_var_5
        tmp_var_4 = rand_2_0
        tmp_var_0 = rand_2_1
        tmp_var_1 = stream_words[4]
        tmp_var_23 = stream_words[14]
        tmp_var_12 = stream_words[12]
        tmp_var_24 = stream_words[8]
        tmp_var_1 = (tmp_var_1 ^ tmp_var_4)
        tmp_var_7 = stream_words[10]
        tmp_var_9 = (tmp_var_23 ^ tmp_var_12)
        stream_words[4] = tmp_var_1
        tmp_var_1 = stream_words[5]
        tmp_var_21 = stream_words[15]
        tmp_var_5 = stream_words[13]
        tmp_var_7 = (tmp_var_7 & tmp_var_9)
        tmp_var_9 = (tmp_var_2 ^ tmp_var_24)
        tmp_var_22 = stream_words[9]
        tmp_var_1 = (tmp_var_1 ^ tmp_var_0)
        tmp_var_9 = (tmp_var_9 & tmp_var_23)
        tmp_var_11 = stream_words[11]
        stream_words[5] = tmp_var_1
        tmp_var_9 = (tmp_var_7 ^ tmp_var_9)
        tmp_var_1 = (tmp_var_21 ^ tmp_var_5)
        tmp_var_7 = stream_words[6]
        tmp_var_11 = (tmp_var_11 & tmp_var_1)
        tmp_var_1 = (tmp_var_2 ^ tmp_var_22)
        tmp_var_1 = (tmp_var_1 & tmp_var_21)
        tmp_var_9 = (tmp_var_7 ^ tmp_var_9)
        tmp_var_7 = stream_words[7]
        tmp_var_1 = (tmp_var_11 ^ tmp_var_1)
        tmp_var_1 = (tmp_var_7 ^ tmp_var_1)
        tmp_var_1 = (tmp_var_1 ^ tmp_var_0)
        stream_words[7] = tmp_var_1
        tmp_var_1 = stream_words[16]
        tmp_var_12 = (tmp_var_2 ^ tmp_var_12)
        tmp_var_12 = (tmp_var_1 & tmp_var_12)
        tmp_var_1 = stream_words[17]
        tmp_var_5 = (tmp_var_2 ^ tmp_var_5)
        tmp_var_5 = (tmp_var_1 & tmp_var_5)
        tmp_var_12 = (tmp_var_12 ^ tmp_var_24)
        tmp_var_5 = (tmp_var_5 ^ tmp_var_22)
        tmp_var_9 = (tmp_var_9 ^ tmp_var_4)
        stream_words[6] = tmp_var_9
        stream_words[8] = tmp_var_12
        stream_words[9] = tmp_var_5
        tmp_var_4 = rand_3_0
        tmp_var_0 = rand_3_1
        tmp_var_1 = stream_words[8]
        tmp_var_21 = stream_words[19]
        tmp_var_1 = (tmp_var_1 ^ tmp_var_4)
        stream_words[8] = tmp_var_1
        tmp_var_1 = stream_words[9]
        tmp_var_22 = stream_words[13]
        tmp_var_1 = (tmp_var_1 ^ tmp_var_0)
        stream_words[9] = tmp_var_1
        tmp_var_1 = stream_words[17]
        tmp_var_11 = stream_words[15]
        tmp_var_5 = (tmp_var_21 ^ tmp_var_1)
        tmp_var_23 = stream_words[18]
        tmp_var_9 = stream_words[16]
        tmp_var_24 = stream_words[12]
        tmp_var_11 = (tmp_var_11 & tmp_var_5)
        tmp_var_7 = stream_words[14]
        tmp_var_5 = (tmp_var_2 ^ tmp_var_22)
        tmp_var_12 = (tmp_var_23 ^ tmp_var_9)
        tmp_var_5 = (tmp_var_5 & tmp_var_21)
        tmp_var_7 = (tmp_var_7 & tmp_var_12)
        tmp_var_5 = (tmp_var_11 ^ tmp_var_5)
        tmp_var_12 = (tmp_var_2 ^ tmp_var_24)
        tmp_var_11 = stream_words[11]
        tmp_var_12 = (tmp_var_12 & tmp_var_23)
        tmp_var_5 = (tmp_var_11 ^ tmp_var_5)
        tmp_var_12 = (tmp_var_7 ^ tmp_var_12)
        tmp_var_7 = stream_words[10]
        tmp_var_5 = (tmp_var_5 ^ tmp_var_0)
        tmp_var_12 = (tmp_var_7 ^ tmp_var_12)
        stream_words[11] = tmp_var_5
        tmp_var_7 = tmp_var_3
        tmp_var_5 = tmp_var_8
        tmp_var_9 = (tmp_var_2 ^ tmp_var_9)
        tmp_var_1 = (tmp_var_2 ^ tmp_var_1)
        tmp_var_9 = (tmp_var_9 & tmp_var_7)
        tmp_var_1 = (tmp_var_1 & tmp_var_5)
        tmp_var_9 = (tmp_var_9 ^ tmp_var_24)
        tmp_var_1 = (tmp_var_1 ^ tmp_var_22)
        tmp_var_12 = (tmp_var_12 ^ tmp_var_4)
        stream_words[10] = tmp_var_12
        stream_words[12] = tmp_var_9
        stream_words[13] = tmp_var_1
        tmp_var_4 = rand_4_0
        tmp_var_0 = rand_4_1
        tmp_var_11 = tmp_var_13
        tmp_var_7 = stream_words[16]
        tmp_var_5 = tmp_var_14
        tmp_var_9 = (tmp_var_11 ^ tmp_var_7)
        tmp_var_7 = tmp_var_15
        tmp_var_11 = stream_words[17]
        tmp_var_9 = (tmp_var_9 ^ tmp_var_7)
        tmp_var_1 = (tmp_var_5 ^ tmp_var_11)
        tmp_var_25 = tmp_var_9
        tmp_var_5 = tmp_var_16
        tmp_var_11 = tmp_var_18
        tmp_var_9 = tmp_var_20
        tmp_var_7 = tmp_var_17
        tmp_var_1 = (tmp_var_1 ^ tmp_var_9)
        tmp_var_9 = (tmp_var_5 ^ tmp_var_11)
        tmp_var_5 = tmp_var_19
        tmp_var_11 = stream_words[18]
        tmp_var_13 = tmp_var_1
        tmp_var_1 = (tmp_var_7 ^ tmp_var_5)
        tmp_var_7 = stream_words[19]
        tmp_var_9 = (tmp_var_9 ^ tmp_var_11)
        tmp_var_11 = tmp_var_20
        tmp_var_1 = (tmp_var_1 ^ tmp_var_7)
        tmp_var_21 = (tmp_var_1 ^ tmp_var_11)
        tmp_var_24 = stream_words[0]
        tmp_var_1 = stream_words[4]
        tmp_var_22 = stream_words[1]
        tmp_var_1 = (tmp_var_1 ^ tmp_var_24)
        tmp_var_14 = tmp_var_1
        tmp_var_1 = stream_words[5]
        tmp_var_7 = stream_words[2]
        tmp_var_1 = (tmp_var_1 ^ tmp_var_22)
        tmp_var_16 = tmp_var_1
        tmp_var_1 = stream_words[6]
        tmp_var_5 = tmp_var_15
        tmp_var_1 = (tmp_var_1 ^ tmp_var_7)
        tmp_var_11 = stream_words[3]
        tmp_var_17 = tmp_var_1
        tmp_var_1 = stream_words[7]
        tmp_var_23 = (tmp_var_9 ^ tmp_var_5)
        tmp_var_9 = tmp_var_13
        tmp_var_1 = (tmp_var_1 ^ tmp_var_11)
        tmp_var_22 = (tmp_var_9 ^ tmp_var_22)
        tmp_var_5 = stream_words[8]
        tmp_var_18 = tmp_var_1
        tmp_var_9 = stream_words[12]
        tmp_var_1 = tmp_var_25
        tmp_var_9 = (tmp_var_9 ^ tmp_var_5)
        tmp_var_24 = (tmp_var_1 ^ tmp_var_24)
        tmp_var_1 = stream_words[13]
        tmp_var_5 = stream_words[9]
        tmp_var_9 = (tmp_var_9 ^ tmp_var_4)
        tmp_var_1 = (tmp_var_1 ^ tmp_var_5)
        tmp_var_19 = tmp_var_9
        tmp_var_5 = stream_words[11]
        tmp_var_9 = stream_words[15]
        tmp_var_1 = (tmp_var_1 ^ tmp_var_0)
        tmp_var_9 = (tmp_var_9 ^ tmp_var_5)
        tmp_var_15 = tmp_var_9
        tmp_var_5 = stream_words[17]
        tmp_var_9 = stream_words[16]
        tmp_var_26 = tmp_var_1
        tmp_var_12 = stream_words[14]
        tmp_var_1 = stream_words[10]
        tmp_var_7 = (tmp_var_23 ^ tmp_var_7)
        tmp_var_12 = (tmp_var_12 ^ tmp_var_1)
        tmp_var_1 = (tmp_var_2 ^ tmp_var_9)
        tmp_var_9 = (tmp_var_2 ^ tmp_var_5)
        tmp_var_5 = tmp_var_6
        tmp_var_11 = (tmp_var_21 ^ tmp_var_11)
        tmp_var_1 = (tmp_var_1 & tmp_var_5)
        tmp_var_5 = tmp_var_10
        tmp_var_12 = (tmp_var_12 ^ tmp_var_1)
        tmp_var_1 = tmp_var_15
        tmp_var_9 = (tmp_var_9 & tmp_var_5)
        tmp_var_9 = (tmp_var_1 ^ tmp_var_9)
        tmp_var_15 = tmp_var_9
        tmp_var_5 = stream_words[18]
        tmp_var_9 = tmp_var_3
        tmp_var_1 = (tmp_var_9 & tmp_var_5)
        tmp_var_9 = tmp_var_8
        tmp_var_5 = stream_words[19]
        tmp_var_9 = (tmp_var_9 & tmp_var_5)
        tmp_var_5 = (tmp_var_12 ^ tmp_var_1)
        tmp_var_1 = tmp_var_15
        tmp_var_1 = (tmp_var_1 ^ tmp_var_9)
        tmp_var_3 = tmp_var_1
        tmp_var_9 = tmp_var_6
        tmp_var_1 = stream_words[18]
        tmp_var_12 = (tmp_var_9 & tmp_var_1)
        tmp_var_1 = stream_words[19]
        tmp_var_9 = tmp_var_10
        tmp_var_9 = (tmp_var_9 & tmp_var_1)
        tmp_var_1 = (tmp_var_5 ^ tmp_var_12)
        tmp_var_5 = tmp_var_3
        tmp_var_1 = (tmp_var_1 ^ tmp_var_4)
        tmp_var_12 = (tmp_var_5 ^ tmp_var_9)
        tmp_var_4 = stream_words[8]
        tmp_var_9 = stream_words[9]
        tmp_var_0 = (tmp_var_12 ^ tmp_var_0)
        tmp_var_3 = tmp_var_1
        tmp_var_8 = tmp_var_0
        tmp_var_1 = (tmp_var_2 ^ tmp_var_4)
        tmp_var_0 = lsl(tmp_var_22, 0xD)
        tmp_var_2 = (tmp_var_2 ^ tmp_var_9)
        tmp_var_9 = lsr(tmp_var_24, 0x13)
        tmp_var_0 = (tmp_var_0 | tmp_var_9)
        tmp_var_4 = lsl(tmp_var_24, 0xD)
        tmp_var_9 = lsr(tmp_var_22, 0x13)
        tmp_var_4 = (tmp_var_4 | tmp_var_9)
        tmp_var_5 = lsl(tmp_var_22, 0x4)
        tmp_var_9 = lsr(tmp_var_24, 0x1C)
        tmp_var_5 = (tmp_var_5 | tmp_var_9)
        tmp_var_12 = lsr(tmp_var_22, 0x1C)
        tmp_var_9 = lsl(tmp_var_24, 0x4)
        tmp_var_9 = (tmp_var_9 | tmp_var_12)
        tmp_var_9 = (tmp_var_4 ^ tmp_var_9)
        tmp_var_9 = (tmp_var_9 ^ tmp_var_22)
        tmp_var_0 = (tmp_var_0 ^ tmp_var_5)
        stream_words[1] = tmp_var_9
        tmp_var_5 = lsl(tmp_var_11, 0xD)
        tmp_var_9 = lsr(tmp_var_7, 0x13)
        tmp_var_12 = lsl(tmp_var_7, 0xD)
        tmp_var_5 = (tmp_var_5 | tmp_var_9)
        tmp_var_9 = lsr(tmp_var_11, 0x13)
        tmp_var_9 = (tmp_var_12 | tmp_var_9)
        tmp_var_0 = (tmp_var_0 ^ tmp_var_24)
        tmp_var_12 = lsr(tmp_var_7, 0x1C)
        tmp_var_4 = lsl(tmp_var_11, 0x4)
        tmp_var_4 = (tmp_var_4 | tmp_var_12)
        stream_words[0] = tmp_var_0
        tmp_var_12 = lsl(tmp_var_7, 0x4)
        tmp_var_0 =  lsr(tmp_var_11, 0x1C)
        tmp_var_12 = (tmp_var_12 | tmp_var_0)
        tmp_var_5 = (tmp_var_5 ^ tmp_var_4)
        tmp_var_5 = (tmp_var_5 ^ tmp_var_7)
        tmp_var_12 = (tmp_var_9 ^ tmp_var_12)
        stream_words[2] = tmp_var_5
        tmp_var_12 = (tmp_var_12 ^ tmp_var_11)
        tmp_var_7 = tmp_var_16
        tmp_var_11 = tmp_var_14
        tmp_var_9 = lsl(tmp_var_7, 0x3)
        tmp_var_5 = lsr(tmp_var_11, 0x1D)
        tmp_var_4 = tmp_var_14
        stream_words[3] = tmp_var_12
        tmp_var_9 = (tmp_var_5 | tmp_var_9)
        tmp_var_12 = lsr(tmp_var_7, 0x1D)
        tmp_var_5 = lsl(tmp_var_11, 0x3)
        tmp_var_5 = (tmp_var_12 | tmp_var_5)
        tmp_var_11 = lsr(tmp_var_11, 0x7)
        tmp_var_12 = lsl(tmp_var_7, 0x19)
        tmp_var_12 = (tmp_var_11 | tmp_var_12)
        tmp_var_11 = lsr(tmp_var_7, 0x7)
        tmp_var_7 = lsl(tmp_var_4, 0x19)
        tmp_var_11 = (tmp_var_11 | tmp_var_7)
        tmp_var_11 = (tmp_var_5 ^ tmp_var_11)
        tmp_var_11 = (tmp_var_11 ^ tmp_var_4)
        tmp_var_5 = tmp_var_16
        tmp_var_7 = tmp_var_18
        tmp_var_9 = (tmp_var_9 ^ tmp_var_12)
        stream_words[4] = tmp_var_11
        tmp_var_11 = tmp_var_17
        tmp_var_9 = (tmp_var_9 ^ tmp_var_5)
        stream_words[5] = tmp_var_9
        tmp_var_5 = lsr(tmp_var_11, 0x1D)
        tmp_var_9 = lsl(tmp_var_7, 0x3)
        tmp_var_4 = tmp_var_17
        tmp_var_12 = lsr(tmp_var_7, 0x1D)
        tmp_var_9 = (tmp_var_5 | tmp_var_9)
        tmp_var_5 = lsl(tmp_var_11, 0x3)
        tmp_var_5 = (tmp_var_12 | tmp_var_5)
        tmp_var_11 = lsr(tmp_var_11, 0x7)
        tmp_var_12 = lsl(tmp_var_7, 0x19)
        tmp_var_12 = (tmp_var_11 | tmp_var_12)
        tmp_var_11 = lsr(tmp_var_7, 0x7)
        tmp_var_7 = lsl(tmp_var_4, 0x19)
        tmp_var_11 = (tmp_var_11 | tmp_var_7)
        tmp_var_11 = (tmp_var_5 ^ tmp_var_11)
        tmp_var_5 = tmp_var_18
        tmp_var_9 = (tmp_var_9 ^ tmp_var_12)
        tmp_var_9 = (tmp_var_9 ^ tmp_var_5)
        stream_words[7] = tmp_var_9
        tmp_var_5 = lsl(tmp_var_2, 0x1F)
        tmp_var_9 = lsr(tmp_var_1, 0x1)
        tmp_var_11 = (tmp_var_11 ^ tmp_var_4)
        tmp_var_12 = lsl(tmp_var_1, 0x1F)
        tmp_var_5 = (tmp_var_5 | tmp_var_9)
        tmp_var_9 = lsr(tmp_var_2, 0x1)
        tmp_var_9 = (tmp_var_12 | tmp_var_9)
        stream_words[6] = tmp_var_11
        tmp_var_12 = lsr(tmp_var_1, 0x6)
        tmp_var_11 = lsl(tmp_var_2, 0x1A)
        tmp_var_11 = (tmp_var_11 | tmp_var_12)
        tmp_var_7 = lsr(tmp_var_2, 0x6)
        tmp_var_12 = lsl(tmp_var_1, 0x1A)
        tmp_var_12 = (tmp_var_12 | tmp_var_7)
        tmp_var_12 = (tmp_var_9 ^ tmp_var_12)
        tmp_var_7 = stream_words[10]
        tmp_var_5 = (tmp_var_5 ^ tmp_var_11)
        tmp_var_11 = stream_words[11]
        tmp_var_2 = (tmp_var_12 ^ tmp_var_2)
        tmp_var_5 = (tmp_var_5 ^ tmp_var_1)
        stream_words[9] = tmp_var_2
        tmp_var_1 = lsl(tmp_var_11, 0x1F)
        tmp_var_2 = lsr(tmp_var_7, 0x1)
        tmp_var_9 = lsl(tmp_var_7, 0x1F)
        tmp_var_1 = (tmp_var_1 | tmp_var_2)
        tmp_var_2 = lsr(tmp_var_11, 0x1)
        tmp_var_2 = (tmp_var_9 | tmp_var_2)
        stream_words[8] = tmp_var_5
        tmp_var_9 = lsr(tmp_var_7, 0x6)
        tmp_var_5 = lsl(tmp_var_11, 0x1A)
        tmp_var_5 = (tmp_var_5 | tmp_var_9)
        tmp_var_1 = (tmp_var_1 ^ tmp_var_5)
        tmp_var_12 = lsr(tmp_var_11, 0x6)
        tmp_var_1 = (tmp_var_1 ^ tmp_var_7)
        tmp_var_9 = lsl(tmp_var_7, 0x1A)
        tmp_var_4 = tmp_var_26
        tmp_var_9 = (tmp_var_9 | tmp_var_12)
        stream_words[10] = tmp_var_1
        tmp_var_1 = tmp_var_19
        tmp_var_9 = (tmp_var_2 ^ tmp_var_9)
        tmp_var_9 = (tmp_var_9 ^ tmp_var_11)
        tmp_var_2 = lsr(tmp_var_1, 0xA)
        tmp_var_11 = tmp_var_19
        tmp_var_5 = lsl(tmp_var_4, 0x16)
        tmp_var_5 = (tmp_var_5 | tmp_var_2)
        tmp_var_1 = lsl(tmp_var_1, 0x16)
        tmp_var_2 = lsr(tmp_var_4, 0xA)
        tmp_var_2 = (tmp_var_1 | tmp_var_2)
        stream_words[11] = tmp_var_9
        tmp_var_1 = lsr(tmp_var_11, 0x11)
        tmp_var_9 = lsl(tmp_var_4, 0xF)
        tmp_var_12 = lsr(tmp_var_4, 0x11)
        tmp_var_9 = (tmp_var_9 | tmp_var_1)
        tmp_var_1 = lsl(tmp_var_11, 0xF)
        tmp_var_1 = (tmp_var_1 | tmp_var_12)
        tmp_var_1 = (tmp_var_2 ^ tmp_var_1)
        tmp_var_7 = tmp_var_8
        tmp_var_1 = (tmp_var_1 ^ tmp_var_4)
        tmp_var_9 = (tmp_var_5 ^ tmp_var_9)
        tmp_var_4 = tmp_var_3
        tmp_var_9 = (tmp_var_9 ^ tmp_var_11)
        tmp_var_2 = lsr(tmp_var_4, 0xA)
        stream_words[12] = tmp_var_9
        stream_words[13] = tmp_var_1
        tmp_var_9 = tmp_var_3
        tmp_var_1 = lsl(tmp_var_7, 0x16)
        tmp_var_1 = (tmp_var_1 | tmp_var_2)
        tmp_var_0 = lsl(tmp_var_4, 0x16)
        tmp_var_2 = lsr(tmp_var_7, 0xA)
        tmp_var_0 = (tmp_var_0 | tmp_var_2)
        tmp_var_4 = lsl(tmp_var_7, 0xF)
        tmp_var_2 = lsr(tmp_var_9, 0x11)
        tmp_var_4 = (tmp_var_4 | tmp_var_2)
        tmp_var_5 = lsl(tmp_var_9, 0xF)
        tmp_var_2 = lsr(tmp_var_7, 0x11)
        tmp_var_5 = (tmp_var_5 | tmp_var_2)
        tmp_var_11 = tmp_var_25
        tmp_var_0 = (tmp_var_0 ^ tmp_var_5)
        tmp_var_1 = (tmp_var_1 ^ tmp_var_4)
        tmp_var_5 = tmp_var_13
        tmp_var_1 = (tmp_var_1 ^ tmp_var_9)
        stream_words[14] = tmp_var_1
        tmp_var_2 = lsr(tmp_var_11, 0x7)
        tmp_var_1 = lsl(tmp_var_5, 0x19)
        tmp_var_0 = (tmp_var_0 ^ tmp_var_7)
        tmp_var_1 = (tmp_var_1 | tmp_var_2)
        tmp_var_7 = tmp_var_13
        tmp_var_9 = lsl(tmp_var_11, 0x19)
        tmp_var_2 = lsr(tmp_var_5, 0x7)
        tmp_var_2 = (tmp_var_9 | tmp_var_2)
        tmp_var_5 = lsl(tmp_var_5, 0x17)
        tmp_var_9 = lsr(tmp_var_11, 0x9)
        tmp_var_9 = (tmp_var_9 | tmp_var_5)
        tmp_var_12 = lsl(tmp_var_11, 0x17)
        tmp_var_5 = lsr(tmp_var_7, 0x9)
        tmp_var_5 = (tmp_var_5 | tmp_var_12)
        tmp_var_1 = (tmp_var_1 ^ tmp_var_5)
        tmp_var_2 = (tmp_var_2 ^ tmp_var_9)
        tmp_var_1 = (tmp_var_1 ^ tmp_var_11)
        tmp_var_2 = (tmp_var_2 ^ tmp_var_7)
        stream_words[15] = tmp_var_0
        stream_words[16] = tmp_var_1
        stream_words[17] = tmp_var_2
        tmp_var_1 = lsl(tmp_var_21, 0x19)
        tmp_var_2 = lsr(tmp_var_23, 0x7)
        tmp_var_1 = (tmp_var_1 | tmp_var_2)
        tmp_var_9 = lsr(tmp_var_21, 0x7)
        tmp_var_2 = lsl(tmp_var_23, 0x19)
        tmp_var_2 = (tmp_var_2 | tmp_var_9)
        tmp_var_5 = lsl(tmp_var_21, 0x17)
        tmp_var_9 = lsr(tmp_var_23, 0x9)
        tmp_var_9 = (tmp_var_9 | tmp_var_5)
        tmp_var_2 = (tmp_var_2 ^ tmp_var_9)
        tmp_var_2 = (tmp_var_2 ^ tmp_var_21)
        tmp_var_5 = lsr(tmp_var_21, 0x9)
        tmp_var_12 = lsl(tmp_var_23, 0x17)
        tmp_var_5 = (tmp_var_5 | tmp_var_12)
        stream_words[19] = tmp_var_2
        tmp_var_1 = (tmp_var_1 ^ tmp_var_5)
        tmp_var_1 = (tmp_var_1 ^ tmp_var_23)
        stream_words[18] = tmp_var_1
    
    stream = b''
    for i in range(20):
        stream += struct.pack("<I", stream_words[i])
        
    return stream
    
def deobfuscate_firmware(data, rng_seed, fw_seed, header_seed):    
    rng_seed_words = struct.unpack("<2I", rng_seed)
    fw_seed_words = struct.unpack("<4I", fw_seed)
    header_seed_words = struct.unpack("<4I", header_seed)
    
    rand_0_0 = random.getrandbits(32)
    rand_0_1 = random.getrandbits(32)
    rand_1_0 = random.getrandbits(32)
    rand_1_1 = random.getrandbits(32)
    rand_2_0 = random.getrandbits(32)
    rand_2_1 = random.getrandbits(32)
    rand_3_0 = random.getrandbits(32)
    rand_3_1 = random.getrandbits(32)
    rand_4_0 = random.getrandbits(32)
    rand_4_1 = random.getrandbits(32)
    
    rand_seed_words = [0]*20
    rand_seed_words[0] = (rand_0_0 ^ rng_seed_words[0])
    rand_seed_words[1] = (rand_0_1 ^ rng_seed_words[1])
    rand_seed_words[2] = rand_0_0
    rand_seed_words[3] = rand_0_1
    rand_seed_words[4] = (rand_1_0 ^ fw_seed_words[0])
    rand_seed_words[5] = (rand_1_1 ^ fw_seed_words[1])
    rand_seed_words[6] = rand_1_0
    rand_seed_words[7] = rand_1_1
    rand_seed_words[8] = (rand_2_0 ^ fw_seed_words[2])
    rand_seed_words[9] = (rand_2_1 ^ fw_seed_words[3])
    rand_seed_words[10] = rand_2_0
    rand_seed_words[11] = rand_2_1
    rand_seed_words[12] = (rand_3_0 ^ header_seed_words[0])
    rand_seed_words[13] = (rand_3_1 ^ header_seed_words[1])
    rand_seed_words[14] = rand_3_0
    rand_seed_words[15] = rand_3_1
    rand_seed_words[16] = (rand_4_0 ^ header_seed_words[2])
    rand_seed_words[17] = (rand_4_1 ^ header_seed_words[3])
    rand_seed_words[18] = rand_4_0
    rand_seed_words[19] = rand_4_1
    
    rand_seed = b''
    for i in range(20):
        rand_seed += struct.pack("<I", rand_seed_words[i])
     
    rand_stream = generate_xor_stream(rand_seed)
      
    rand_stream_words = [0]*20
    for i in range(20):
        rand_stream_words[i] = struct.unpack("<20I", rand_stream)[i]
    
    xor_stream_words = [0]*10
    xor_stream_words[0] = rand_stream_words[0] ^ rand_stream_words[2]
    xor_stream_words[1] = rand_stream_words[1] ^ rand_stream_words[3]
    xor_stream_words[2] = rand_stream_words[4] ^ rand_stream_words[6]
    xor_stream_words[3] = rand_stream_words[5] ^ rand_stream_words[7]
    xor_stream_words[4] = rand_stream_words[8] ^ rand_stream_words[10]
    xor_stream_words[5] = rand_stream_words[9] ^ rand_stream_words[11]
    xor_stream_words[6] = rand_stream_words[12] ^ rand_stream_words[14]
    xor_stream_words[7] = rand_stream_words[13] ^ rand_stream_words[15]
    xor_stream_words[8] = rand_stream_words[16] ^ rand_stream_words[18]
    xor_stream_words[9] = rand_stream_words[17] ^ rand_stream_words[19]
    
    xor_stream = b''
    for i in range(10):
        xor_stream += struct.pack("<I", xor_stream_words[i])
    
    dec_data = b''
    data_size_left = (0x10 - (len(data) % 0x10)) % 0x10
    data_size_align = len(data) - data_size_left
    for i in range(0, data_size_align, 0x10):
        dec_data += xor(data[i:i+0x10], xor_stream[0:0x10])
        xor_stream = advance_xor_stream(data[i:i+0x10] + xor_stream[0x10:])
        
    for i in range(data_size_left):
        dec_data += xor(data[data_size_align+i], xor_stream[i])
    
    return dec_data    
    
def decrypt_update(data):
    dec_data = b''
    block_seed = 0
    for i in range(len(data)//8):
        block_iv = tea_encrypt(struct.pack("<2L", i, block_seed), tea_key)
        block_key = block_iv + tea_key[8:12] + tea_key[12:16]
        block_dec = tea_decrypt(data[i*8:i*8+8], block_key)
        block_seed ^= (struct.unpack("<L", block_dec[0:4])[0] ^ struct.unpack("<L", block_dec[4:8])[0])
        dec_data += block_dec
    return dec_data
    
def decrypt_firmware(data):
    fw_header = data[0:0x1000]
    fw_secure_boot_sig_block = data[0x1000:0x2000]
    
    fw_version = fw_header[0:0x20]
    fw_dec_hash = fw_header[0x20:0x40]
    fw_enc_hash = fw_header[0x40:0x60]
    fw_entry_addr = struct.unpack("<I", fw_header[0x60:0x64])[0]
    fw_num_sections = struct.unpack("<I", fw_header[0x64:0x68])[0]
    fw_rand_0 = struct.unpack("<I", fw_header[0x68:0x6C])[0]
    fw_rand_1 = struct.unpack("<I", fw_header[0x6C:0x70])[0]
    fw_rand_2 = struct.unpack("<I", fw_header[0x70:0x74])[0]
    fw_rand_3 = struct.unpack("<I", fw_header[0x74:0x78])[0]
    fw_key_idx = struct.unpack("<B", fw_header[0x78:0x79])[0]
    fw_reserved_0 = struct.unpack("<B", fw_header[0x79:0x7A])[0]
    fw_flags = struct.unpack("<B", fw_header[0x7A:0x7B])[0]
    fw_reserved_1 = struct.unpack("<B", fw_header[0x7B:0x7C])[0]
    fw_size = struct.unpack("<I", fw_header[0x7C:0x80])[0]
    
    fw_key = aes_keys[fw_key_idx][0:0x10]
    fw_seed = aes_keys[fw_key_idx][0x10:0x20]
    rng_seed = struct.pack("<2I", 0x49A159CD, 0xC222A9C9)
    header_seed = struct.pack("<4I", fw_rand_0, fw_rand_1, fw_rand_2, fw_rand_3)
    
    print("Firmware version: {}".format(fw_version.decode("utf-8")))
    
    fw_data = b''
    for i in range(fw_num_sections):
        fw_section_offset = struct.unpack("<I", fw_header[0x80+i*0xC:0x84+i*0xC])[0]
        fw_section_addr = struct.unpack("<I", fw_header[0x84+i*0xC:0x88+i*0xC])[0]
        fw_section_size = struct.unpack("<I", fw_header[0x88+i*0xC:0x8C+i*0xC])[0]
        
        print("Firmware section #{}: offset=0x{:08X}, address=0x{:08X}, size=0x{:08X}".format(i, fw_section_offset, fw_section_addr, fw_section_size))
    
        fw_dec_data = aes_ecb_dec(data[fw_section_offset:fw_section_offset+fw_section_size], fw_key)
        fw_data += deobfuscate_firmware(fw_dec_data, rng_seed, fw_seed, header_seed)

    return fw_data

with open("update.s2", "rb") as in_file:
    with open("update_dec.bin", "wb") as out_file:
        out_file.write(decrypt_update(in_file.read()))

with open("update_dec.bin", "rb") as in_file:
    with open("firmware.bin", "wb") as out_file:
        out_file.write(decrypt_firmware(in_file.read()))
