from encrypt_transform_funcs import *
from decrypt_transform_funcs import *

# AES encryption
def AES_encrypt(plaintext, key):
    state = bytes_to_state(plaintext)
    round_keys = key_expansion(key)

    # Initial round: add round key
    add_round_key(state, round_keys[0:4])

    # 9 main rounds
    for r in range(1, 10):
        sub_bytes(state)
        shift_rows(state)
        mix_columns(state)
        add_round_key(state, round_keys[r*4:(r+1)*4])

    # Final round (no mix columns)
    sub_bytes(state)
    shift_rows(state)
    add_round_key(state, round_keys[40:44])

    return state_to_bytes(state)
    
def AES_decrypt(ciphertext, key):

    state = bytes_to_state(ciphertext)
    round_keys = key_expansion(key)

    # Initial AddRoundKey with last round key
    add_round_key(state, round_keys[40:44])

    # 9 main rounds
    for r in range(9, 0, -1):
        inv_shift_rows(state)
        inv_sub_bytes(state)
        add_round_key(state, round_keys[r*4:(r+1)*4])
        inv_mix_columns(state)

    # Final round (no inv_mix_columns)
    inv_shift_rows(state)
    inv_sub_bytes(state)
    add_round_key(state, round_keys[0:4])

    return state_to_bytes(state)

