# AES-128 Encryption/Decryption in Python (Manual Implementation)

This project implements the AES-128 encryption and decryption algorithm entirely from scratch in Python, based on the FIPS-197 standard. All core cryptographic operations—including key expansion, SubBytes, ShiftRows, MixColumns, and AddRoundKey — are implemented manually without relying on external libraries.

PyCryptodome is used only for testing and validation, to ensure the correctness of the manual implementation.

# Features
- AES-128 block encryption and decryption
- Manual implementation of:
  - SubBytes / InvSubBytes
  - ShiftRows / InvShiftRows
  - MixColumns / InvMixColumns
  - AddRoundKey
  - Key expansion
- Verified for correctness using PyCryptodome
- Clean, modular Python structure with reusable components

# Usage
```bash
$ python implementation_test.py
```
Example (in code:)
```python
from aes_implementation import *

key = b'\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c'
plaintext = b'\x32\x43\xf6\xa8\x88\x5a\x30\x8d\x31\x31\x98\xa2\xe0\x37\x07\x34'

ciphertext = AES_encrypt(plaintext, key)
decrypted = AES_decrypt(ciphertext, key)

assert decrypted == plaintext
```
