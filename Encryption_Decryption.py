from Crypto.Cipher import AES, DES, DES3, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import sys
import time

def encrypt_decrypt_des(file, encrypt_time, decrypt_time):
    key = get_random_bytes(8)
    iv = get_random_bytes(8)

    start = time.time()
    cipher = DES.new(key, DES.MODE_OFB, iv=iv)
    file_padded = pad(file, DES.block_size)
    cipher_text = cipher.encrypt(file_padded)
    end = time.time()
    encrypt_time.append(end-start)

    start = time.time()
    decipher = DES.new(key, DES.MODE_OFB, iv=iv)
    decipher.decrypt(cipher_text)
    end = time.time()
    decrypt_time.append(end-start)

def encrypt_decrypt_des3(file, encrypt_time, decrypt_time):
    while True:
        try: 
            key = DES3.adjust_key_parity(get_random_bytes(24))

            break
        except ValueError:
            pass
    
    start = time.time()
    cipher = DES3.new(key, DES3.MODE_CFB)
    file_padded = pad(file, DES3.block_size)
    cipher_text = cipher.encrypt(file_padded)
    end = time.time()
    encrypt_time.append(end-start)

    start = time.time()
    decipher = DES3.new(key, DES3.MODE_CFB)
    decipher.decrypt(cipher_text)
    end = time.time()
    decrypt_time.append(end-start)

def encrypt_decrypt_aes(file, encrypt_time, decrypt_time):
    key = get_random_bytes(16)
    
    start = time.time()
    cipher = AES.new(key, AES.MODE_CBC)
    file_padded = pad(file, AES.block_size)
    cipher_text = cipher.encrypt(file_padded)
    end = time.time()
    encrypt_time.append(end-start)

    start = time.time()
    decipher = AES.new(key, AES.MODE_CBC)
    decipher.decrypt(cipher_text)
    end = time.time()
    decrypt_time.append(end-start)
    
def encrypt_decrypt_rsa(file, encrypt_time, decrypt_time):
    key = RSA.import_key(open('myprivatekey.pem').read())
    
    start = time.time()
    cipher = PKCS1_OAEP.new(key)
    cipher_text = cipher.encrypt(file)
    end = time.time()
    encrypt_time.append(end-start)

    start = time.time()
    decipher = PKCS1_OAEP.new(key)
    decipher.decrypt(cipher_text)
    end = time.time()
    decrypt_time.append(end-start)

if __name__=="__main__":
    file_sizes = {
        "51KB": "length_51kb.txt",
        "1MB": "length_1mb.txt",
        "2MB": "length_3mb.txt",
    }
    
    for i in file_sizes:
        file_path = file_sizes[i]
        file = open(file_path, "rb")
        file_content = file.read()

        des_time_stamp = []
        des_encrypt_time = []
        des_decrypt_time = []
        for j in range(100):
            start = time.time()
            encrypt_decrypt_des(file_content, des_encrypt_time, des_decrypt_time)
            end = time.time()
            des_time_stamp.append(end-start)

        des_avg_time = 0
        des_encrypt_avg_time = 0
        des_decrypt_avg_time = 0
        for j in range(len(des_time_stamp)):
            des_avg_time += des_time_stamp[j]
            des_encrypt_avg_time += des_encrypt_time[j]
            des_decrypt_avg_time += des_decrypt_time[j]
        des_avg_time = des_avg_time / len(des_time_stamp)
        des_encrypt_avg_time = des_encrypt_avg_time / len(des_encrypt_time)
        des_decrypt_avg_time = des_decrypt_avg_time / len(des_decrypt_time)


        file.close()

        print(f"DES Average Time ({i}): {des_avg_time * 100} seconds")
        print(f"\tDES Encrypt Average Time ({i}): {des_encrypt_avg_time * 100} seconds")
        print(f"\tDES Decrypt Average Time ({i}): {des_decrypt_avg_time * 100} seconds")

    for i in file_sizes:
        file_path = file_sizes[i]
        file = open(file_path, "rb")
        file_content = file.read()
        
        des3_time_stamp = []
        des3_encrypt_time = []
        des3_decrypt_time = []
        for j in range(100):
            start = time.time()
            encrypt_decrypt_des3(file_content, des3_encrypt_time, des3_decrypt_time)
            end = time.time()
            des3_time_stamp.append(end-start)

        des3_avg_time = 0
        des3_avg_encrypt_time = 0
        des3_avg_decrypt_time = 0
        for j in range(len(des3_time_stamp)):
            des3_avg_time += des3_time_stamp[j]
            des3_avg_encrypt_time += des3_encrypt_time[j]
            des3_avg_decrypt_time += des3_decrypt_time[j]
        des3_avg_time = des3_avg_time / len(des3_time_stamp)
        des3_avg_encrypt_time = des3_avg_encrypt_time / len(des3_encrypt_time)
        des3_avg_decrypt_time = des3_avg_decrypt_time / len(des3_decrypt_time)

        file.close()

        print(f"3DES Average Time ({i}): {des3_avg_time * 100} seconds")
        print(f"\t3DES Encrpyt Average Time ({i}): {des3_avg_encrypt_time * 100} seconds")
        print(f"\t3DES Decrpyt Average Time ({i}): {des3_avg_decrypt_time * 100} seconds")

    for i in file_sizes:
        file_path = file_sizes[i]
        file = open(file_path, "rb")
        file_content = file.read()

        aes_time_stamp = []
        aes_encrypt_time = []
        aes_decrypt_time = []
        for j in range(100):
            start = time.time()
            encrypt_decrypt_aes(file_content, aes_encrypt_time, aes_decrypt_time)
            end = time.time()
            aes_time_stamp.append(end-start)

        aes_avg_time = 0
        aes_avg_encrypt_time = 0
        aes_avg_decrypt_time = 0
        for j in range(len(aes_time_stamp)):
            aes_avg_time += aes_time_stamp[j]
            aes_avg_encrypt_time += aes_encrypt_time[j]
            aes_avg_decrypt_time += aes_decrypt_time[j]
        aes_avg_time = aes_avg_time / len(aes_time_stamp)
        aes_avg_encrypt_time = aes_avg_encrypt_time / len(aes_encrypt_time)
        aes_avg_decrypt_time = aes_avg_decrypt_time / len(aes_decrypt_time)

        file.close()

        print(f"AES Average Time ({i}): {aes_avg_time * 100} seconds")
        print(f"\tAES Encrypt Average Time ({i}): {aes_avg_encrypt_time * 100} seconds")
        print(f"\tAES Decrypt Average Time ({i}): {aes_avg_decrypt_time * 100} seconds")

    key = RSA.generate(3072)
    pwd = b'secret'
    with open("myprivatekey.pem", "wb") as f:
        data = key.export_key(passphrase=pwd,
                              pkcs=8,protection='PBKDF2WithHMAC-SHA512AndAES256-CBC',
                              prot_params={'iteration_count':131072})
        f.write(data)

    for i in file_sizes:
        file_path = file_sizes[i]
        file = open(file_path, "rb")
        file_content = file.read()

        rsa_time_stamp = []
        rsa_encrypt_time = []
        rsa_decrypt_time = []
        for j in range(100):
            start = time.time()
            encrypt_decrypt_aes(file_content, rsa_encrypt_time, rsa_decrypt_time)
            end = time.time()
            rsa_time_stamp.append(end-start)

        rsa_avg_time = 0
        rsa_avg_encrypt_time = 0
        rsa_avg_decrypt_time = 0
        for j in range(len(rsa_time_stamp)):
            rsa_avg_time += rsa_time_stamp[j]
            rsa_avg_encrypt_time += rsa_encrypt_time[j]
            rsa_avg_decrypt_time += rsa_decrypt_time[j]
        rsa_avg_time = rsa_avg_time / len(rsa_time_stamp)
        rsa_avg_encrypt_time = rsa_avg_encrypt_time / len(rsa_encrypt_time)
        rsa_avg_decrypt_time = rsa_avg_decrypt_time / len(rsa_decrypt_time)

        file.close()

        print(f"RSA Average Time ({i}): {rsa_avg_time * 100} seconds")
        print(f"\tRSA Encrypt Average Time ({i}): {rsa_avg_encrypt_time * 100} seconds")
        print(f"\tRSA Decrypt Average Time ({i}): {rsa_avg_decrypt_time * 100} seconds")

