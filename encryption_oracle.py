from encryption_oracle import aes_encrypt

def generate_guess_message_data(message_guess, message_iv, next_iv, block_size):
    message_guess_data = message_guess.encode('utf-8')
    xor_data1 = bytes(a ^ b for a, b in zip(message_iv, next_iv))
    msg_block1 = message_guess_data[:block_size]
    first_block_data = bytes(a ^ b for a, b in zip(xor_data1, msg_block1))
    return first_block_data + message_guess_data[block_size:]

def pick_msg_to_send(recovered_string, block_size):
    header = "MSG="
    known_char_count = len(header) + len(recovered_string)
    blocks_filled = known_char_count // block_size
    xpad_len = blocks_filled * block_size + block_size - len(header) - len(recovered_string) - 1
    return 'x' * xpad_len

def pick_msg_to_guess(recovered_string, guess_char, block_size):
    header = "MSG="
    known_char_count = len(header) + len(recovered_string)
    blocks_filled = known_char_count // block_size
    xpad_len = blocks_filled * block_size + block_size - len(header) - len(recovered_string) - 1
    return header + 'x' * xpad_len + recovered_string + guess_char

def predict_iv(iteration):
    return bytes([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]) + iteration.to_bytes(8, 'big')

def xor_array(array1, array2):
    if len(array1) == len(array2):
        return bytes(a ^ b for a, b in zip(array1, array2))
    raise ValueError()

def get_printable_character_collection():
    return [chr(i) for i in range(0, 127) if chr(i).isprintable()]

def main():
    block_size = 16
    encryption_iteration = 0
    recovered_string = ''

    # Modify the IV and encrypted_data below with your values
    init_vector = bytes.fromhex("cf8fe08eaf106df86e9b0d28e33ff97a")
    encrypted_data = bytes.fromhex("4bb3cc4c7b0a856fa5e92f60013c821d185a8d16cd431479d2a277fc330d31b9138332814b8e94414ba9ec6ea560182d")

    while True:
        message = pick_msg_to_send(recovered_string, block_size)
        encrypted_message_data = init_vector + encrypted_data
        init_vector = encrypted_message_data[:block_size]
        encrypted_data = encrypted_message_data[block_size:]
        encryption_iteration += 1

        found_char = chr(0)
        success = False
        print("Brute-forcing next character...")

        for try_char in get_printable_character_collection():
            msg_guess = pick_msg_to_guess(recovered_string, try_char, block_size)
            predicted_iv = predict_iv(encryption_iteration)
            guess_msg_data = generate_guess_message_data(msg_guess, init_vector, predicted_iv, block_size)
            encrypted_guess_data = aes_encrypt(guess_msg_data)[block_size:]
            encryption_iteration += 1

            if encrypted_data[:len(msg_guess)] == encrypted_guess_data[:len(msg_guess)]:
                found_char = try_char
                success = True
                break

        if success:
            recovered_string += found_char
            print("Recovered String Update:", recovered_string)
        else:
            break

    print("Recovered String Result:", recovered_string)

if __name__ == '__main__':
    main()