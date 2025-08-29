# Trae AI + Metasploit MCP 完整使用指南

恭喜！您已成功建立 Trae AI 與遠端 Metasploit MCP 服務器的連接。本指南將幫助您充分利用這個強大的整合系統。

## 🎯 系統架構概覽

```
Windows (Trae AI - 10.0.0.85) ←→ HTTP/8085 ←→ Kali Linux (Metasploit MCP - 172.31.44.17) ←→ RPC/55553 ←→ Metasploit Framework
```

- **Windows 端**：Trae AI IDE 環境 (10.0.0.85)
- **Kali Linux 端**：MetasploitMCP 服務器 (172.31.44.17:8085)
- **連接方式**：HTTP 協議，使用 `npx mcp-remote --allow-http`
- **認證**：RPC 密碼 `N0viru$123`

## 📚 使用範例文檔

本目錄包含以下詳細的使用範例文檔：

### 1. [基礎使用範例](./TRAE_AI_METASPLOIT_EXAMPLES.md)
**適用場景**：初學者入門
- 查詢 Metasploit 模組信息
- 搜索特定類型的漏洞利用
- 獲取模組詳細配置信息
- CVE 漏洞查詢和對應模組
- 基礎的信息檢索技巧

**示例提問**：
```
幫我搜索所有與 SMB 相關的 exploit 模組
告訴我 ms17_010_eternalblue 模組的詳細信息
查詢 CVE-2017-0144 的相關信息
```

### 2. [網絡掃描範例](./NETWORK_SCANNING_EXAMPLES.md)
**適用場景**：網絡偵察和服務發現
- TCP/SYN 端口掃描
- 服務版本識別
- 漏洞掃描 (SMB, SSL, 數據庫)
- 網絡設備發現
- 掃描結果分析

**示例提問**：
```
幫我掃描 192.168.1.100 的常見端口
對 192.168.1.0/24 網段進行隱蔽的 SYN 掃描
檢查目標是否存在 MS17-010 漏洞
```

### 3. [漏洞利用範例](./EXPLOIT_EXAMPLES.md)
**適用場景**：實際的漏洞利用攻擊
- Windows 系統漏洞利用 (MS17-010, MS08-067)
- Linux 系統攻擊 (Samba, Apache Struts)
- Web 應用漏洞利用
- 服務特定攻擊 (SSH, FTP)
- Payload 配置和規避技術

**示例提問**：
```
利用 MS17-010 漏洞攻擊 192.168.1.50 並獲取 Meterpreter shell
對 Windows XP 系統使用 MS08-067 漏洞
利用 Struts2 REST Plugin XStream RCE 漏洞
```

### 4. [後滲透範例](./POST_EXPLOITATION_EXAMPLES.md)
**適用場景**：獲得初始訪問後的深入滲透
- 系統信息收集和枚舉
- 憑據提取和分析
- 權限提升技術
- 橫向移動策略
- 持久化機制建立
- 痕跡清理技術

**示例提問**：
```
收集 Windows 目標系統的詳細信息
從目標系統中提取存儲的憑據
嘗試在 Windows 系統上提升權限
在 Linux 系統上建立持久化機制
```

### 5. [Payload 生成範例](./PAYLOAD_GENERATION_EXAMPLES.md)
**適用場景**：自定義 Payload 創建和配置
- Windows/Linux/Web 平台 Payload
- 編碼和混淆技術
- 移動平台 Payload (Android, macOS)
- 多階段 Payload 設計
- 反檢測和規避技術

**示例提問**：
```
生成一個基本的 Windows reverse shell payload
生成經過編碼的 payload 以規避防病毒檢測
為 Web 應用漏洞生成 PHP payload
為 Android 設備生成 APK payload
```

### 6. [綜合攻擊鏈範例](./COMPREHENSIVE_ATTACK_CHAIN_EXAMPLES.md)
**適用場景**：完整的滲透測試項目
- 企業內網滲透完整流程
- Web 應用滲透測試
- 無線網絡安全評估
- 社會工程學攻擊
- 自動化攻擊腳本
- 專業報告生成

**示例提問**：
```
開始對目標企業網絡進行偵察
對發現的主機進行漏洞掃描
利用發現的漏洞獲取初始訪問權限
創建自動化的攻擊鏈腳本
```

## 🚀 快速開始

### 第一次使用建議

1. **驗證連接**
   ```
   Trae AI，請確認你能連接到 Metasploit 服務器
   ```

2. **基礎查詢測試**
   ```
   搜索所有可用的 Windows exploit 模組
   ```

3. **簡單掃描測試**
   ```
   幫我掃描 127.0.0.1 的端口 80 和 443
   ```

### 進階使用技巧

1. **組合查詢**
   ```
   搜索針對 Windows 10 的遠程代碼執行漏洞，並告訴我最有效的利用方法
   ```

2. **情境化請求**
   ```
   我發現目標運行 Apache Struts 2.3.24，請幫我找到相應的漏洞利用模組並配置攻擊
   ```

3. **完整流程請求**
   ```
   請幫我設計一個針對 192.168.1.0/24 網段的完整滲透測試方案
   ```

## ⚠️ 重要安全提醒

### 合法使用原則
- ✅ **僅在授權環境中使用**
- ✅ **遵守相關法律法規**
- ✅ **保護客戶敏感信息**
- ✅ **及時清理測試痕跡**
- ❌ **禁止未授權攻擊**
- ❌ **禁止惡意使用**

### 最佳實踐
1. **測試前**：確保擁有書面授權
2. **測試中**：記錄所有操作和發現
3. **測試後**：提供詳細報告和修復建議
4. **數據處理**：安全存儲和及時銷毀敏感數據

## 🔧 故障排除

### 常見問題

**Q: Trae AI 無法連接到 Metasploit 服務器**
```
A: 檢查以下項目：
1. Kali Linux 上的 MetasploitMCP 服務器是否運行在端口 8085
2. 網絡連接是否正常 (ping 172.31.44.17)
3. Windows 防火牆是否阻止連接
4. metasploit_mcp_trae_config.json 配置是否正確
```

**Q: 查詢結果不完整或錯誤**
```
A: 可能的原因：
1. Metasploit 框架需要更新
2. RPC 服務連接不穩定
3. 重啟 MetasploitMCP 服務器
4. 檢查 Metasploit 數據庫狀態
```

**Q: 執行 exploit 時失敗**
```
A: 診斷步驟：
1. 確認目標可達性
2. 驗證漏洞存在性
3. 檢查 payload 兼容性
4. 調整高級選項設置
```

### 獲取幫助

如果遇到問題，可以向 Trae AI 詢問：
```
我在使用 [具體功能] 時遇到 [具體問題]，請幫我診斷和解決
```

## 📈 學習路徑建議

### 初學者路徑
1. 閱讀 [基礎使用範例](./TRAE_AI_METASPLOIT_EXAMPLES.md)
2. 練習 [網絡掃描範例](./NETWORK_SCANNING_EXAMPLES.md)
3. 在測試環境中嘗試簡單的漏洞利用

### 中級用戶路徑
1. 深入學習 [漏洞利用範例](./EXPLOIT_EXAMPLES.md)
2. 掌握 [後滲透範例](./POST_EXPLOITATION_EXAMPLES.md)
3. 練習 [Payload 生成範例](./PAYLOAD_GENERATION_EXAMPLES.md)

### 高級用戶路徑
1. 研究 [綜合攻擊鏈範例](./COMPREHENSIVE_ATTACK_CHAIN_EXAMPLES.md)
2. 開發自定義攻擊腳本
3. 建立自動化滲透測試流程

## 🎓 持續學習資源

### 推薦學習材料
- Metasploit 官方文檔
- OWASP 測試指南
- NIST 網絡安全框架
- 各種 CVE 數據庫

### 實踐環境
- VulnHub 虛擬機
- HackTheBox 平台
- TryHackMe 課程
- 自建測試實驗室

## 📞 技術支持

如需技術支持或有任何疑問，請：
1. 查閱相關範例文檔
2. 向 Trae AI 詢問具體問題
3. 檢查系統日誌和錯誤信息
4. 參考 Metasploit 社區資源

---

**祝您使用愉快！** 🎉

通過 Trae AI 和 Metasploit MCP 的強大組合，您現在擁有了一個智能化的滲透測試助手。請負責任地使用這些工具，為網絡安全做出積極貢獻。

*最後更新：2025年1月*