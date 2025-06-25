from aes_implementation import *
import os
from Crypto.Cipher import AES
from intermediates import *

# Generating plaintext and key
key = os.urandom(16)
plaintext = os.urandom(16)

print_round_keys(key)

print("Plaintext:", plaintext)
print("Converted hexadecimal plaintext:", plaintext.hex())

intermediate_ciphertext = intermediate_AES_encrypt(plaintext, key)

# ENCRYPTION TEST
# Encrypt using AES implementation
my_cipher = AES_encrypt(plaintext, key)
ciphertext = AES_encrypt(plaintext, key)

# Encrypt using PyCryptodome
aes = AES.new(key, AES.MODE_ECB)
ref_cipher = aes.encrypt(plaintext)

print("AES_encrypt ciphertext:", ciphertext.hex()) 
print("PyCryptodome ciphertext:", ref_cipher.hex())
print("Match:", ciphertext == ref_cipher == intermediate_ciphertext)


intermediate_plaintext = intermediate_AES_decrypt(ciphertext, key)
print("Intermediate plaintext:", intermediate_plaintext.hex())

# DECRYPTION TEST
my_plain = AES_decrypt(ciphertext, key)
ref_plain = aes.decrypt(ciphertext)

print("AES_decrypt plaintext:", my_plain.hex()) 
print("PyCryptodome plaintext:", ref_plain.hex())
print("Match:", my_plain == ref_plain == plaintext == intermediate_plaintext)