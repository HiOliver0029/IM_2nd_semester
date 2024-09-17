from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

# 1. 準備密鑰和資料
key = get_random_bytes(16)  # 128 位元密鑰
data = b"This message is what we want to encrypt." #b指的是byte格式的字串，而非str

# 2. 加密 (AES-128 CBC 模式)
cipher = AES.new(key, AES.MODE_CBC)
print(f"cipher: {cipher}")
ciphertext = cipher.encrypt(pad(data, AES.block_size))
# print(cipher.iv)
# print(cipher.iv)

# 3. 解密
decipher = AES.new(key, AES.MODE_CBC, cipher.iv)
print(type(cipher.iv))
plaintext = unpad(decipher.decrypt(ciphertext), AES.block_size)

# 4. 顯示結果
print("原始資料:", data.decode('utf-8'))
print("加密後密文:", ciphertext)
print("解密後明文:", plaintext.decode('utf-8'))

# 實作步驟解說：
# 密鑰生成：透過 get_random_bytes(16) 生成一個隨機 16 位元組的密鑰，用來加密和解密。
# 加密：首先進行資料填充，確保資料長度是 128 位元的倍數，然後使用 AES CBC 模式加密。
# 解密：使用相同的密鑰進行解密，最後去除填充還原原始資料。