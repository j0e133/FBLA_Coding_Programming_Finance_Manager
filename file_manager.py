# builtin imports
from typing import Optional

# 3rd party imports
import zlib

# local imports
from encryption import encrypt, decrypt



def compress(text: str, compression: int = 6) -> bytes:
    '''
    Compresses a string of text.

    `compression` is the level of compression to use. Should be 0-9. Higher numbers compress more, but are slower.
    '''

    text_data = text.encode('utf-8')

    compressed_data = zlib.compress(text_data, level=compression)

    return compressed_data



def decompress(compressed_data: bytes) -> str:
    '''
    Decompresses bytes.
    '''

    decompressed_data = zlib.decompress(compressed_data)

    text = decompressed_data.decode('utf-8')

    return text



def save(text: str, filename: str, encryption_password: Optional[str] = None, compression: int = 6) -> None:
    '''
    Saves text to a file. The file should be binary. Use `save_plaintext` for .txt files.

    `encryption_password` is the optional encryption password to use. Leave as `None` for no encryption.

    `compression` is the level of compression to use. Should be 0-9. Higher numbers compress more, but are slower.
    '''

    compressed_data = compress(text, compression)

    if encryption_password:
        save_data = encrypt(compressed_data, encryption_password)

    else:
        save_data = compressed_data

    with open(filename, 'wb') as f:
        f.write(save_data)

    return None



def save_plaintext(text: str, filename: str) -> None:
    '''
    Saves text to a plaintext file.
    '''

    with open(filename, 'w') as f:
        f.write(text)

    return None



def load(filename: str, decryption_password: Optional[str] = None) -> str:
    '''
    Loads text from a file. The file should be in binary. Use `load_plaintext` for .txt files.

    `decryption_password` should be the same as the password used to encrypt the data originally.
    '''

    with open(filename, 'rb') as f:
        file_data = f.read()

    if decryption_password:
        compressed_data = decrypt(file_data, decryption_password)

    else:
        compressed_data = file_data

    text = decompress(compressed_data)

    return text



def load_plaintext(filename: str) -> str:
    '''
    Loads text from a plaintext file.
    '''

    with open(filename, 'r') as f:
        text = f.read()

    return text



if __name__ == '__main__':
    while True:
        mode = input('Mode?: ')

        match mode:
            case 'save':
                filename = input('Save to?: ')
                password = input('Password?: ')

                text = load_plaintext('bible.txt')

                save(text, filename, password)

            case 'load':
                filename = input('Load from?: ')
                password = input('Password?: ')

                text = load(filename, password)

                print(text[-500:])

            case 'exit':
                exit()

            case _:
                print('Unknown mode. Should be "save," "load," or "exit"')

