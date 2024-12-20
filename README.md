### 專案簡介
這份專案聚焦在研析與演練進階持續性威脅組織（APT）的一個 attack campaign，名為 A cascade of compromise:
Unveiling Lazarus new campaign，是北韓駭客組織 Lazarus 透過一個合法用來加密 web communication 的安全軟體的漏洞部屬名為 signBT 的惡意軟體，在其攻擊生命週期裡包含若干攻擊腳本的執行。

藉由研讀過去曾發生的 APT Attack Campaign‘s CTI（Cyber Threat Intelligence）文件，了解各攻擊階段所採用的攻擊戰略與手法，實作各攻擊階段所使用的程式與各項工具以重建攻擊事件，依據內容盡可能復刻原攻擊流程 （Attack Life Cycle）。旨在將 APT 攻擊生命週期中所使用的攻擊腳本，以 abilities 的形式完整建構並貢獻至 CALDERA 平台，擴增 APT 攻擊模擬攻防的武器庫。

### 操作說明
#### C2_server
內含 `C2_server.py` 檔案，用於 attacker 端發送指令並接收 `signBT` 回傳的 victim 相關資訊，以 `python C2_server.py` 執行即可。

#### signBT
`signBT.py` 檔案是會被置於 victim 端的惡意 payload，部署後可透過 `python signBT.py` 執行，就會跟 C2 server 進行傳訊，另外為了不在 victim 端留下足跡，亦可透過 `signBT.cpp` 去讀取 `signBT.py` 檔案的方式執行 signBT，需要先 `sudo apt-get install python3-dev`，接著編譯檔案 `g++ -o signBT signBT.cpp -lssl -lcrypto` 然後執行 `.\signBT.exe`。  

#### AESdecrypt,encrypt,100a,100b 
需先安裝 openssl 與 cyptography 套件，指令為 `sudo apt-get install openssl` 和 `pip install cryptography`，windows 版本 openssl 請[點此安裝](https://slproweb.com/products/Win32OpenSSL.html)。  

`encrypt.cpp` 可以用來加密檔案，編譯指令為 `g++ -o en encrypt.cpp -lssl -lcrypto` 然後把自行製作完的 `signBT` 跟 `config` 檔案放在同一層目錄下並執行 `.\en.exe`。  
加密後會產生 `tw-100a-a00-e14d9.tmp` 和 `tw-100b-a00-e14d9.tmp` 二份加密過的檔案。    
`decrypt.cpp` 可以用來解密 `tw-100a-a00-e14d9.tmp` 和 `tw-100b-a00-e14d9.tmp` 檔案，編譯指令為 `g++ -o de decrypt.cpp -lssl -lcrypto` 然後執行 `.\de.exe`，就會生成解密後的檔案。    
此外 `make100a,100b.py` 同樣可以用來加解密，但它是以 `python` 實作，以 `python make100a,100b.py` 執行即可。    
`AES_example.py` 則是一份用於解釋 AES 運作原理的簡化過的檔案，由於上述加解密利用 AES 進行加解密，因此透過這份檔案可以更清楚此函式庫的運作方式，以 `python AES_example.py` 執行即可。  

#### machineGUID
`guid.exe` 會讀取當前系統的 guid 並與給定的 guid 比對，如果一致才會繼續進行後續流程。編譯方式為 `g++ -o guid guid.cpp`，產生 guid.exe 後將給定的 guid 放入同一層目錄，執行 `.\guid.exe` 即可進行比對。

#### configData
因為 report 中提到 signBT 會蒐集 victim 的 config data，因此我們實作 `config_data.ps1`，內含一些可取得詳細 victim config data 的指令，執行檔案後可以取得以下資訊：
- 系統硬體資訊：處理器、內存、磁碟空間、BIOS 版本等。
- 操作系統資訊：操作系統版本、系統啟動時間等。
- 網路配置：IP 地址、網卡資訊、DNS 配置等。
- 安裝的軟體與服務：系統中已安裝的應用程序和運行的服務。
- 用戶帳戶與權限：當前用戶、系統中的用戶帳戶等。
