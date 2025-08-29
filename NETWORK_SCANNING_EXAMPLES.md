# 網絡掃描範例 - Trae AI + Metasploit MCP

本文檔展示如何透過 Trae AI 使用 Metasploit 的 auxiliary/scanner 模組進行網絡掃描。

## 基礎端口掃描

### 1. TCP 端口掃描

**用戶提問：**
```
幫我掃描 192.168.1.100 的常見端口
```

**Trae AI 操作流程：**
1. 選擇模組：`auxiliary/scanner/portscan/tcp`
2. 設置目標：`set RHOSTS 192.168.1.100`
3. 設置端口範圍：`set PORTS 1-1000`
4. 執行掃描：`run`

**預期結果：**
```
[+] 192.168.1.100:22 - TCP OPEN
[+] 192.168.1.100:80 - TCP OPEN
[+] 192.168.1.100:443 - TCP OPEN
[+] 192.168.1.100:3389 - TCP OPEN
```

### 2. SYN 掃描（隱蔽掃描）

**用戶提問：**
```
對 192.168.1.0/24 網段進行隱蔽的 SYN 掃描
```

**Trae AI 操作流程：**
1. 選擇模組：`auxiliary/scanner/portscan/syn`
2. 設置目標網段：`set RHOSTS 192.168.1.0/24`
3. 設置常見端口：`set PORTS 21,22,23,25,53,80,110,443,993,995`
4. 設置線程：`set THREADS 50`
5. 執行掃描：`run`

## 服務識別掃描

### 3. SSH 服務掃描

**用戶提問：**
```
掃描目標網段的 SSH 服務版本信息
```

**Trae AI 操作流程：**
1. 選擇模組：`auxiliary/scanner/ssh/ssh_version`
2. 設置目標：`set RHOSTS 192.168.1.0/24`
3. 設置超時：`set TIMEOUT 30`
4. 執行掃描：`run`

**預期結果：**
```
[+] 192.168.1.10:22 SSH server version: SSH-2.0-OpenSSH_7.4
[+] 192.168.1.20:22 SSH server version: SSH-2.0-OpenSSH_8.0
```

### 4. HTTP 服務掃描

**用戶提問：**
```
識別目標的 Web 服務器類型和版本
```

**Trae AI 操作流程：**
1. 選擇模組：`auxiliary/scanner/http/http_version`
2. 設置目標：`set RHOSTS 192.168.1.100`
3. 設置端口：`set RPORT 80,443,8080,8443`
4. 執行掃描：`run`

**預期結果：**
```
[+] 192.168.1.100:80 Apache/2.4.41 (Ubuntu)
[+] 192.168.1.100:443 nginx/1.18.0
```

### 5. SMB 服務掃描

**用戶提問：**
```
掃描 Windows 主機的 SMB 共享信息
```

**Trae AI 操作流程：**
1. SMB 版本掃描：`auxiliary/scanner/smb/smb_version`
2. SMB 共享枚舉：`auxiliary/scanner/smb/smb_enumshares`
3. 設置目標：`set RHOSTS 192.168.1.0/24`
4. 執行掃描：`run`

## 漏洞掃描

### 6. SMB 漏洞掃描

**用戶提問：**
```
檢查目標是否存在 MS17-010 (EternalBlue) 漏洞
```

**Trae AI 操作流程：**
1. 選擇模組：`auxiliary/scanner/smb/smb_ms17_010`
2. 設置目標：`set RHOSTS 192.168.1.0/24`
3. 執行掃描：`run`

**預期結果：**
```
[+] 192.168.1.50 - Host is likely VULNERABLE to MS17-010!
[*] 192.168.1.51 - Host does NOT appear vulnerable.
```

### 7. SSL/TLS 漏洞掃描

**用戶提問：**
```
檢查 HTTPS 服務的 SSL 配置和已知漏洞
```

**Trae AI 操作流程：**
1. SSL 版本掃描：`auxiliary/scanner/ssl/ssl_version`
2. Heartbleed 檢測：`auxiliary/scanner/ssl/openssl_heartbleed`
3. 設置目標：`set RHOSTS 192.168.1.100`
4. 設置端口：`set RPORT 443`

## 數據庫掃描

### 8. MySQL 掃描

**用戶提問：**
```
掃描 MySQL 數據庫服務並嘗試弱密碼
```

**Trae AI 操作流程：**
1. MySQL 版本掃描：`auxiliary/scanner/mysql/mysql_version`
2. MySQL 登錄嘗試：`auxiliary/scanner/mysql/mysql_login`
3. 設置用戶名字典：`set USER_FILE /usr/share/metasploit-framework/data/wordlists/common_users.txt`
4. 設置密碼字典：`set PASS_FILE /usr/share/metasploit-framework/data/wordlists/common_passwords.txt`

### 9. MSSQL 掃描

**用戶提問：**
```
掃描 Microsoft SQL Server 並檢查配置
```

**Trae AI 操作流程：**
1. MSSQL 發現：`auxiliary/scanner/mssql/mssql_ping`
2. MSSQL 登錄：`auxiliary/scanner/mssql/mssql_login`
3. 配置枚舉：`auxiliary/admin/mssql/mssql_enum`

## 進階掃描技巧

### 10. 組合掃描策略

**用戶提問：**
```
對目標進行全面的服務發現和漏洞評估
```

**Trae AI 建議的掃描順序：**
1. **主機發現**：`auxiliary/scanner/discovery/arp_sweep`
2. **端口掃描**：`auxiliary/scanner/portscan/tcp`
3. **服務識別**：針對開放端口使用相應的服務掃描模組
4. **漏洞檢測**：基於發現的服務運行漏洞掃描
5. **結果整理**：匯總所有發現的信息

### 11. 掃描優化設置

**用戶提問：**
```
如何優化掃描速度和準確性？
```

**Trae AI 建議的配置：**
```
# 增加線程數（謹慎使用）
set THREADS 20

# 設置超時時間
set TIMEOUT 10

# 設置重試次數
set RETRY 2

# 啟用詳細輸出
set VERBOSE true
```

## 掃描結果分析

### 12. 結果解讀和後續行動

**用戶提問：**
```
根據掃描結果，下一步應該做什麼？
```

**Trae AI 分析流程：**
1. **開放端口分析**：識別不必要的服務
2. **版本信息評估**：檢查是否存在已知漏洞
3. **配置問題識別**：發現安全配置缺陷
4. **攻擊面評估**：確定潛在的攻擊向量
5. **優先級排序**：根據風險等級制定測試計劃

## 注意事項

- **授權測試**：確保擁有目標系統的測試授權
- **網絡影響**：大規模掃描可能影響網絡性能
- **檢測規避**：某些掃描可能觸發安全設備告警
- **結果驗證**：手動驗證自動掃描的結果
- **文檔記錄**：詳細記錄掃描過程和結果

---

*定期更新掃描策略以應對新的安全威脅和防護技術。*