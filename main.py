import os
import sys
import base64
import json
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad


KEY_STATISTIC = b"crst1\0\0\0"
KEY_DEFAULT = b"iambo\0\0\0"
IV = b"Ahbool\0\0"
KEY_XOR = bytes([115, 108, 99, 122, 125, 103, 117, 99, 127, 87, 109, 108, 107, 74, 95])


def xor_cipher(data, key):
    """Applies XOR cipher to the data."""
    return bytes([b ^ key[i % len(key)] for i, b in enumerate(data)])


def decrypt_des(data, key, iv):
    """Decrypts DES encrypted data."""
    try:
        cipher = DES.new(key, DES.MODE_CBC, iv)
        decoded_data = base64.b64decode(data)
        decrypted_data = cipher.decrypt(decoded_data)
        return unpad(decrypted_data, DES.block_size)
    except (ValueError, KeyError) as e:
        print(f"Error decrypting with DES: {e}")
        return None


def encrypt_des(data, key, iv):
    """Encrypts data using DES."""
    cipher = DES.new(key, DES.MODE_CBC, iv)
    padded_data = pad(data, DES.block_size)
    encrypted_data = cipher.encrypt(padded_data)
    return base64.b64encode(encrypted_data)


def get_file_handler(filename):
    """Determines the correct handler based on filename."""
    if filename.startswith("statistic"):
        return "des", KEY_STATISTIC
    if filename == "game.data":
        return "xor", KEY_XOR

    return "des", KEY_DEFAULT


def decode_file(filepath):
    """Decodes a single .data file."""
    filename = os.path.basename(filepath)
    print(f"Decoding {filename}...")

    clean_filename = filename.split("_")[0] + ".data"
    if "item_data" in filename:
        clean_filename = "item_data.data"

    handler_type, key = get_file_handler(clean_filename)

    with open(filepath, "rb") as f:
        content = f.read()

    if handler_type == "des":
        decrypted_content = decrypt_des(content, key, IV)
    elif handler_type == "xor":
        decrypted_content = xor_cipher(content, key)
    else:
        print(f"No handler found for {filename}")
        return

    if decrypted_content:
        try:
            json_obj = json.loads(decrypted_content)
            pretty_json = json.dumps(json_obj, indent=4, sort_keys=True)
            output_filename = os.path.splitext(filepath)[0] + ".json"
            with open(output_filename, "w") as f:
                f.write(pretty_json)
            print(f"Successfully decoded and saved to {output_filename}")
        except json.JSONDecodeError:
            print("Failed to decode JSON from decrypted content.")
        except Exception as e:
            print(f"An error occurred during file writing: {e}")


def encode_file(filepath, original_data_filename):
    """Encodes a single .json file to .data."""
    filename = os.path.basename(filepath)
    print(f"Encoding {filename}...")

    output_dir = "output"
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    output_filename = os.path.join(output_dir, original_data_filename)

    clean_filename = original_data_filename.split("_")[0] + ".data"
    if "item_data" in clean_filename:
        clean_filename = "item_data.data"

    handler_type, key = get_file_handler(clean_filename)

    with open(filepath, "r") as f:
        content_str = f.read()
        content = json.dumps(json.loads(content_str), separators=(",", ":")).encode(
            "utf-8"
        )

    if handler_type == "des":
        encrypted_content = encrypt_des(content, key, IV)
    elif handler_type == "xor":
        encrypted_content = xor_cipher(content, key)
    else:
        print(f"No handler found for {filename}")
        return

    if encrypted_content:
        with open(output_filename, "wb") as f:
            f.write(encrypted_content)
        print(f"Successfully encoded and saved to {output_filename}")


def main():
    if len(sys.argv) != 2 or sys.argv[1] not in ["encode", "decode"]:
        print("Usage: python main.py [encode|decode]")
        sys.exit(1)

    mode = sys.argv[1]
    files_processed = 0

    if mode == "decode":
        for file in os.listdir("."):
            if file.endswith(".data"):
                decode_file(file)
                files_processed += 1
    elif mode == "encode":
        data_files = [f for f in os.listdir(".") if f.endswith(".data")]
        if not data_files:
            print("No .data files found to use as a reference for encoding.")
            sys.exit(1)

        reference_data_file = data_files[0]

        for file in os.listdir("."):
            if file.endswith(".json"):
                encode_file(file, reference_data_file)
                files_processed += 1

    if files_processed == 0:
        if mode == "decode":
            print("No .data files found in the current directory.")
        else:
            print("No .json files found in the current directory.")


if __name__ == "__main__":
    main()
