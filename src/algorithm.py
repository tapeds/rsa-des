from constants import pc1_table, pc2_table, shift_positions, ip_table, ip_inv_table, expansion_table, p_table, s_boxes

sub_keys = []


def validate_key_input(key):
    if isinstance(key, str):
        key = key.encode()  # Convert string to bytes
    if not isinstance(key, (bytes, bytearray)):
        raise TypeError("Key must be a bytes-like object or string.")
    if len(key) != 8:
        raise ValueError("Key must be exactly 8 bytes (64 bits).")
    return key


def text_to_bin(text):
    if isinstance(text, str):
        text = text.encode()  # Convert string to bytes
    return ''.join(format(byte, '08b') for byte in text)


def bin_to_text(binary_string):
    length = len(binary_string)
    binary_string = binary_string[:length -
                                  (length % 8)]  # Trim to multiple of 8
    chars = [int(binary_string[i:i + 8], 2)
             for i in range(0, len(binary_string), 8)]
    return bytes(chars).decode('utf-8', errors='ignore')  # Safely decode


def pc1_conversion(binary_key):
    temp_list = [int(x) for x in binary_key]
    return [temp_list[i - 1] for i in pc1_table]


def shift_left(bits, shift_value):
    return bits[shift_value:] + bits[:shift_value]


def generate_subkeys(left, right):
    for round_count in range(1, 17):
        shift_value = 1 if round_count in shift_positions else 2
        left = shift_left(left, shift_value)
        right = shift_left(right, shift_value)
        merged_bits = left + right
        sub_key = [merged_bits[i - 1] for i in pc2_table]
        sub_keys.append(sub_key)


def key_setup(key):
    key = validate_key_input(key)
    binary_key = text_to_bin(key)
    initial_key = pc1_conversion(binary_key)
    left_bits = initial_key[:28]
    right_bits = initial_key[28:]
    generate_subkeys(left_bits, right_bits)


def initial_permutation(bits):
    return [int(bits[i - 1]) for i in ip_table]


def expansion_box(right_half):
    return [right_half[i - 1] for i in expansion_table]


def xor_with_key(expanded, key_index):
    return [expanded[i] ^ sub_keys[key_index][i] for i in range(len(expanded))]


def s_box_substitution(bits):
    result = ''
    for i in range(8):
        block = bits[i * 6:(i + 1) * 6]
        row = int(f"{block[0]}{block[5]}", 2)
        col = int(''.join(map(str, block[1:5])), 2)
        val = s_boxes[i][row][col]
        bin_val = format(val, '04b')
        result += bin_val
    return [int(bit) for bit in result]


def permutation(sbox_output):
    return [sbox_output[i - 1] for i in p_table]


def des_round(left, right, round_number):
    expanded_right = expansion_box(right)
    xor_result = xor_with_key(expanded_right, round_number)
    sbox_output = s_box_substitution(xor_result)
    p_result = permutation(sbox_output)
    new_right = [left[i] ^ p_result[i] for i in range(len(left))]
    return right, new_right


def final_permutation(bits):
    return [bits[i - 1] for i in ip_inv_table]


def des_encrypt(plaintext, key):
    key_setup(key)
    padded_plaintext = plaintext.ljust((len(plaintext) + 7) // 8 * 8, '\x00')
    ciphertext = ""

    for i in range(0, len(padded_plaintext), 8):
        block = padded_plaintext[i:i+8]
        binary_plaintext = text_to_bin(block)

        if len(binary_plaintext) < 64:
            binary_plaintext = binary_plaintext.ljust(64, '0')
        else:
            binary_plaintext = binary_plaintext[:64]

        permuted_bits = initial_permutation(binary_plaintext)
        left_half = permuted_bits[:32]
        right_half = permuted_bits[32:]

        for round_number in range(16):
            left_half, right_half = des_round(
                left_half, right_half, round_number)

        final_bits = right_half + left_half
        final_permuted_bits = final_permutation(final_bits)
        binary_result = ''.join(map(str, final_permuted_bits))

        block_hex_result = hex(int(binary_result, 2))[2:].upper().zfill(16)
        ciphertext += block_hex_result

    return ciphertext


def des_decrypt(ciphertext, key):
    key_setup(key)
    plaintext = ""

    for i in range(0, len(ciphertext), 16):
        block_hex = ciphertext[i:i+16]
        binary_ciphertext = bin(int(block_hex, 16))[2:].zfill(64)
        permuted_bits = initial_permutation(binary_ciphertext)
        left_half = permuted_bits[:32]
        right_half = permuted_bits[32:]

        for round_number in reversed(range(16)):
            left_half, right_half = des_round(
                left_half, right_half, round_number)

        final_bits = right_half + left_half
        final_permuted_bits = final_permutation(final_bits)
        binary_result = ''.join(map(str, final_permuted_bits))

        block_plaintext = bin_to_text(binary_result)
        plaintext += block_plaintext

    return plaintext.strip('\x00')
