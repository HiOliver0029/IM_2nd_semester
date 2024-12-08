from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import os
import winreg

# 生成 AES 金鑰（32 bytes 用來解密 tw-100a-a00-e14d9.tmp 和 tw-100b-a00-e14d9.tmp）
def generate_key():
    return os.urandom(32)

# 使用 PKCS7 填充
def pad_data(data):
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(data) + padder.finalize()
    return padded_data

# 去除 PKCS7 填充
def unpad_data(padded_data):
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    data = unpadder.update(padded_data) + unpadder.finalize()
    return data

def get_machine_guid():
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Cryptography")
        guid, _ = winreg.QueryValueEx(key, "MachineGuid")
        return guid
    except Exception as e:
        print(f"Error retrieving MachineGuid: {str(e)}")
        return None

# 使用 AES-CBC 模式加密 payload
def encrypt_payload(key, plaintext):
    iv = os.urandom(16)  # 16 bytes IV for AES-CBC

    # 取得 MachineGuid 並將其加入訊息中
    # machine_guid = get_machine_guid()
    # if machine_guid:
    #     machine_guid_bytes = machine_guid.encode('utf-8')
    # else:
    #     machine_guid_bytes = b'\x00' * 16  # 如果沒有取到，使用 16 個 0 bytes
    
    # plaintext_guid = plaintext + machine_guid_bytes # 把guid加到最後面
    # padded_plaintext = pad_data(plaintext_guid)  # 填充明文
    padded_plaintext = pad_data(plaintext)  # 填充明文
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()

    return iv + ciphertext 

# 使用 AES-CBC 模式解密 payload
def decrypt_payload(key, ciphertext):
    iv = ciphertext[:16]  # 提取前16 bytes作為IV
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext[16:]) + decryptor.finalize()
    plaintext = unpad_data(padded_plaintext)  # 去除填充
    return plaintext

# 寫入 tw-100a-a00-e14d9.tmp 的模擬惡意載荷 (讀取 signBT.py)
def write_encrypted_payload(filename, key, payload_file):
    # 這是模擬的惡意載荷，實際攻擊中會是二進制惡意程式
    # payload = b"Simulated malicious payload"
    with open(payload_file, 'rb') as f:
        payload = f.read()  # 讀取 signBT.py 的內容
    encrypted_payload = encrypt_payload(key, payload)
    with open(filename, 'wb') as f:
        f.write(key) # 把 key 當作前 32 bytes 存入檔案
        f.write(encrypted_payload)

# 寫入 tw-100b-a00-e14d9.tmp 的設定檔
def write_encrypted_config(filename, key):
    # 這裡的模擬設定檔包含 C2 伺服器地址等
    config_data = b"DNS1: 221.141.3.76 (theorigin.co.kr), DNS2: 221.156.137.137 (ictm.or.kr), DNS3: 121.78.116.216 (ucware.net), sleep_interval: 10"
    encrypted_config = encrypt_payload(key, config_data)
    with open(filename, 'wb') as f:
        f.write(encrypted_config)

# 模擬實作，生成惡意載荷和設定檔
def simulate_files():
    key = generate_key()  # 生成32 bytes AES 金鑰
    write_encrypted_payload("tw-100a-a00-e14d9.tmp", key, "signBT.py")  # 使用 signBT.py 作為載荷
    write_encrypted_config("tw-100b-a00-e14d9.tmp", key)
    print("Files generated: tw-100a-a00-e14d9.tmp and tw-100b-a00-e14d9.tmp")
    return key

# 測試解密
def test_decrypt_files(key):
    # 解密載荷
    with open("tw-100a-a00-e14d9.tmp", 'rb') as f:
        encrypted_payload = f.read()
    # print("Encrypted Payload: ", encrypted_payload)
    decrypted_payload = decrypt_payload(key, encrypted_payload)
    print("Decrypted Payload: ", decrypted_payload, '\n')

    # 解密設定檔
    with open("tw-100b-a00-e14d9.tmp", 'rb') as f:
        encrypted_config = f.read()
    # print("Encrypted Config: ", encrypted_payload)
    decrypted_config = decrypt_payload(key, encrypted_config)
    print("Decrypted Config: ", decrypted_config)


# 執行模擬生成與解密
if __name__ == "__main__":
    aes_key = simulate_files()  # 生成檔案
    test_decrypt_files(aes_key)  # 解密並展示內容
