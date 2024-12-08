from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.hashes import SHA256
import os

# Fungsi untuk menghasilkan kunci AES
def generate_key(password: str, salt: bytes):
    kdf = PBKDF2HMAC(
        algorithm=SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

# Fungsi enkripsi file
def encrypt_file(input_file: str, output_file: str, password: str):
    salt = os.urandom(16)
    key = generate_key(password, salt)
    iv = os.urandom(16)

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(algorithms.AES.block_size).padder()

    with open(input_file, 'rb') as f:
        data = f.read()

    padded_data = padder.update(data) + padder.finalize()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    with open(output_file, 'wb') as f:
        f.write(salt + iv + encrypted_data)

# Fungsi dekripsi file
def decrypt_file(input_file: str, output_file: str, password: str):
    with open(input_file, 'rb') as f:
        salt = f.read(16)
        iv = f.read(16)
        encrypted_data = f.read()

    key = generate_key(password, salt)

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()

    decrypted_padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
    decrypted_data = unpadder.update(decrypted_padded_data) + unpadder.finalize()

    with open(output_file, 'wb') as f:
        f.write(decrypted_data)

# Fungsi utama
def main():
    print("==== AES File Encryption/Decryption ====")
    print("Pilih operasi:")
    print("1. Enkripsi File")
    print("2. Dekripsi File")
    
    choice = input("Masukkan pilihan (1/2): ").strip()

    if choice not in ['1', '2']:
        print("Pilihan tidak valid. Program selesai.")
        return

    input_file = input("Masukkan nama file input (dengan path): ").strip()
    output_file = input("Masukkan nama file output (dengan path): ").strip()
    password = input("Masukkan password: ").strip()

    if not os.path.exists(input_file):
        print("File input tidak ditemukan. Program selesai.")
        return

    try:
        if choice == '1':
            encrypt_file(input_file, output_file, password)
            print(f"File berhasil dienkripsi! Output: {output_file}")
        elif choice == '2':
            decrypt_file(input_file, output_file, password)
            print(f"File berhasil didekripsi! Output: {output_file}")
    except Exception as e:
        print(f"Terjadi kesalahan: {e}")

if __name__ == "__main__":
    main()
