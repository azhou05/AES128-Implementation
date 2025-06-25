from Crypto.Cipher import AES
from aes_implementation import *

def print_state(round_num, step_name, state):
    print(f"{step_name} round {round_num}:")
    for row in state:
        print(' '.join(f"{byte:02x}" for byte in row))
    print()

def print_round_keys(key):
    round_keys = key_expansion(key)

    print("\nAES-128 Round Keys:")
    print(f"Main Key: {key.hex()}\n")

    for i in range(11):  # 11 round keys (0-10)
        start_idx = i * 4
        round_key_words = round_keys[start_idx : start_idx + 4]
        
        print(f"Round {i} Key:")
        # Print as 4 words (32-bit each)
        for j, word in enumerate(round_key_words):
            print(f"  w[{start_idx + j}] = {word:08x}")
        
        # Print as 16 bytes (4x4 matrix)
        round_key_bytes = b''.join(word.to_bytes(4, 'big') for word in round_key_words)
        print("  Bytes:")
        for row in range(4):
            print("   ", end="")
            for col in range(4):
                print(f" {round_key_bytes[row + 4*col]:02x}", end="")
            print()
        print()

def intermediate_AES_encrypt(plaintext, key):
    state = bytes_to_state(plaintext)
    round_keys = key_expansion(key)

    print_state(0, "Initial state,", state)

    # Initial Round (AddRoundKey only)
    add_round_key(state, round_keys[0:4])
    print_state(0, "After AddRoundKey,", state)

    # Printing all transformations for 1st main round
    r = 1
    sub_bytes(state)
    print_state(r, "After SubBytes,", state)

    shift_rows(state)
    print_state(r, "After ShiftRows,", state)
    
    mix_columns(state)
    print_state(r, "After MixColumns,", state)

    add_round_key(state, round_keys[r*4:(r+1)*4])
    print_state(r, "After AddRoundKey,", state)


    # Other 8 main round outputs
    for r in range(2, 10):
        sub_bytes(state)
        shift_rows(state)
        mix_columns(state)
        add_round_key(state, round_keys[r*4:(r+1)*4])
        print_state(r, "After", state)

    # Final Round (No MixColumns)
    sub_bytes(state)
    shift_rows(state)
    add_round_key(state, round_keys[40:44])
    print_state(10, "After", state)

    return(state_to_bytes(state))

def intermediate_AES_decrypt(ciphertext, key):
    state = bytes_to_state(ciphertext)
    round_keys = key_expansion(key)

    # Initial Round (AddRoundKey only)
    add_round_key(state, round_keys[40:44])
    print_state(0, "After AddRoundKey,", state)

    # Printing all transformations for 1st main round
    r = 9
    round = 10 - r
    inv_shift_rows(state)
    print_state(round, "After ShiftRows,", state)

    inv_sub_bytes(state)
    print_state(round, "After SubBytes,", state)

    add_round_key(state, round_keys[r*4:(r+1)*4])
    print_state(round, "After AddRoundKey,", state)

    inv_mix_columns(state)
    print_state(round, "After MixColumns,", state)

    # Other 8 main round outputs
    for r in range(8, 0, -1):
        inv_shift_rows(state)
        inv_sub_bytes(state)
        add_round_key(state, round_keys[r*4:(r+1)*4])
        inv_mix_columns(state)
        print_state(10 - r, "After", state)

    # Final Round (No MixColumns)
    inv_shift_rows(state)
    inv_sub_bytes(state) 
    add_round_key(state, round_keys[0:4])
    print_state(10, "After", state)

    return state_to_bytes(state)