# 將結果保存到指定的路徑
$outputPath = "$env:USERPROFILE\system_configuration_report.txt"

# 系統硬體資訊
$cpuInfo = Get-CimInstance -ClassName Win32_Processor
$memoryInfo = Get-CimInstance -ClassName Win32_PhysicalMemory
$diskInfo = Get-CimInstance -ClassName Win32_LogicalDisk
$biosInfo = Get-CimInstance -ClassName Win32_BIOS

# 操作系統資訊
$osInfo = Get-CimInstance -ClassName Win32_OperatingSystem
$lastBoot = $osInfo.LastBootUpTime

# 網路配置
$ipAddresses = Get-NetIPAddress
$netAdapters = Get-NetAdapter
$dnsServers = Get-DnsClientServerAddress

# 安裝的軟體與更新
$installedSoftware = Get-WmiObject -Class Win32_Product | Select-Object Name, Version
$installedUpdates = Get-HotFix

# 用戶賬戶
$currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
$localUsers = Get-LocalUser

# 組合報告
$report = @"
--- System Configuration Report ---
Generated on: $(Get-Date)

--- Hardware Information ---
CPU: $cpuInfo
Memory: $memoryInfo
Disk: $diskInfo
BIOS: $biosInfo

--- Operating System Information ---
OS: $osInfo
Last Boot Time: $lastBoot

--- Network Configuration ---
IP Addresses: $ipAddresses
Network Adapters: $netAdapters
DNS Servers: $dnsServers

--- Installed Software ---
$($installedSoftware | Format-Table | Out-String)

--- Installed Updates ---
$($installedUpdates | Format-Table | Out-String)

--- User Accounts ---
Current User: $currentUser
Local Users: $($localUsers | Format-Table | Out-String)

"@

# 將報告寫入到檔案
$report | Out-File -FilePath $outputPath

Write-Host "System configuration report generated at $outputPath"
