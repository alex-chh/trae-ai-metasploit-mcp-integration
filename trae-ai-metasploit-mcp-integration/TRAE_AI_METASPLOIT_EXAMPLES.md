# Trae AI 與 Metasploit MCP 使用範例

本文檔提供了使用 Trae AI 連接到遠端 Metasploit MCP 服務器的實際使用範例。

## 前置條件

- Kali Linux 上運行 Metasploit MCP 服務器 (端口 8085)
- Windows 上配置好的 Trae AI 環境
- 網絡連接正常 (172.31.44.17:8085)

## 基礎使用範例

### 1. 查詢 Metasploit 模組信息

**用戶提問：**
```
幫我搜索所有與 SMB 相關的 exploit 模組
```

**預期回應：**
Trae AI 會透過 MCP 連接查詢 Metasploit 框架，返回所有 SMB 相關的漏洞利用模組列表，包括：
- exploit/windows/smb/ms17_010_eternalblue
- exploit/windows/smb/ms08_067_netapi
- exploit/linux/samba/is_known_pipename
- 等等...

### 2. 獲取特定模組詳細信息

**用戶提問：**
```
告訴我 ms17_010_eternalblue 模組的詳細信息和使用方法
```

**預期回應：**
- 模組完整路徑：exploit/windows/smb/ms17_010_eternalblue
- 描述：MS17-010 EternalBlue SMB Remote Windows Kernel Pool Corruption
- 作者信息
- 目標平台：Windows
- 可用選項 (RHOSTS, RPORT, TARGET 等)
- 兼容的 payload 列表
- 使用範例

### 3. 查詢漏洞數據庫信息

**用戶提問：**
```
查詢 CVE-2017-0144 的相關信息和對應的 Metasploit 模組
```

**預期回應：**
- CVE 詳細描述
- 影響的系統版本
- CVSS 評分
- 對應的 Metasploit 模組
- 修復建議

### 4. 搜索特定服務的掃描模組

**用戶提問：**
```
我需要掃描目標的 SSH 服務，有哪些可用的 auxiliary 模組？
```

**預期回應：**
- auxiliary/scanner/ssh/ssh_version
- auxiliary/scanner/ssh/ssh_login
- auxiliary/scanner/ssh/ssh_enumusers
- auxiliary/scanner/ssh/ssh_identify_pubkeys
- 每個模組的功能說明和使用方法

### 5. 查詢 payload 選項

**用戶提問：**
```
列出所有可用的 Windows meterpreter payload
```

**預期回應：**
- windows/meterpreter/reverse_tcp
- windows/meterpreter/reverse_https
- windows/meterpreter/bind_tcp
- windows/x64/meterpreter/reverse_tcp
- 等等，包含每個 payload 的描述和適用場景

## 進階查詢範例

### 6. 組合條件搜索

**用戶提問：**
```
搜索所有針對 Windows 10 的遠程代碼執行漏洞利用模組
```

### 7. 模組兼容性查詢

**用戶提問：**
```
哪些 payload 與 exploit/windows/smb/ms17_010_eternalblue 兼容？
```

### 8. 安全研究查詢

**用戶提問：**
```
最近添加到 Metasploit 的新模組有哪些？
```

## 使用技巧

1. **具體化查詢**：使用具體的服務名稱、CVE 編號或系統版本
2. **分類搜索**：明確指定模組類型 (exploit, auxiliary, post, payload)
3. **組合查詢**：結合多個條件進行精確搜索
4. **實用性導向**：詢問具體的使用場景和配置方法

## 注意事項

- 所有操作僅限於授權的滲透測試環境
- 遵守相關法律法規和道德準則
- 定期更新 Metasploit 框架以獲取最新模組
- 確保網絡連接穩定以獲得最佳體驗

---

*此文檔將持續更新，添加更多實用範例和最佳實踐。*