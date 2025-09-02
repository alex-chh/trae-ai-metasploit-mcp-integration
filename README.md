# Trae AI Metasploit MCP Integration

這是一個完整的 Trae AI 與 Metasploit MCP (Model Context Protocol) 集成項目，提供從基礎配置到高級滲透測試的全面解決方案。

## 🎯 項目特色

- **🤖 智能化操作**: 透過自然語言與 Metasploit 交互
- **🔒 安全增強**: 強制安全密碼驗證，禁用默認密碼
- **⚡ 自動化部署**: 一鍵啟動腳本，自動配置所有服務
- **🌐 分離架構**: 支持 Kali Linux 服務器 + Windows 客戶端
- **📚 完整文檔**: 從新手到專家的全面指導

## 🏗️ 系統架構

```
┌─────────────────┐    HTTP/8085    ┌─────────────────┐    RPC/55553    ┌─────────────────┐
│   Windows       │◄──────────────►│   Kali Linux    │◄──────────────►│   Metasploit    │
│   (Trae AI)     │                │   (MetasploitMCP)│                │   Framework     │
│   客戶端主機     │                │   服務器主機      │                │   127.0.0.1     │
└─────────────────┘                └─────────────────┘                └─────────────────┘
```

## 🚀 快速開始（新手推薦）

### 第一步：在 Kali Linux 服務器上

```bash
# 1. 克隆項目
git clone https://github.com/alex-chh/trae-ai-metasploit-mcp-integration.git
cd trae-ai-metasploit-mcp-integration

# 2. 運行自動化腳本（互動模式）
python3 start_metasploit_mcp.py --interactive

# 或者直接啟動（非互動模式）
python3 start_metasploit_mcp.py --start-msfrpcd --host 0.0.0.0 --port 8085
```

**腳本會自動完成**：
- ✅ 檢查 Metasploit Framework 安裝
- ✅ 啟動 Metasploit RPC 服務（端口 55553）
- ✅ 下載並配置 MetasploitMCP 服務器
- ✅ 安裝所有必要的 Python 依賴
- ✅ 啟動 MetasploitMCP 服務器（端口 8085）
- ✅ 生成 Trae AI 配置文件

### 第二步：在 Windows 客戶端上

```powershell
# 1. 安裝 Node.js（如果未安裝）
# 從 https://nodejs.org/ 下載安裝

# 2. 安裝 mcp-remote
npm install -g mcp-remote

# 3. 測試連接（替換為您的 Kali Linux IP）
npx mcp-remote http://YOUR_KALI_IP:8085/sse --allow-http
```

### 第三步：配置 Trae AI

1. 打開 Trae AI → AI 側邊欄 → 設置 → MCP
2. 點擊 "+" → 手動添加
3. 使用腳本生成的 `metasploit_mcp_trae_config.json` 配置
4. 確認連接狀態為「已連接」

## 🔧 高級配置選項

### 自動化腳本參數

```bash
# 完整參數示例
python3 start_metasploit_mcp.py \
    --transport http \
    --host 0.0.0.0 \
    --port 8085 \
    --msf-server 127.0.0.1 \
    --msf-port 55553 \
    --start-msfrpcd \
    --generate-trae-config \
    --interactive
```

### 主要參數說明

- `--interactive`: 啟用互動配置模式（推薦新手）
- `--start-msfrpcd`: 自動啟動 Metasploit RPC 服務
- `--generate-trae-config`: 生成 Trae AI 配置文件
- `--host`: MetasploitMCP 服務器監聽地址
- `--port`: MetasploitMCP 服務器端口
- `--remote-host`: 遠程配置模式（僅生成配置文件）

### 安全功能

- **🔒 強制密碼驗證**: 不允許使用默認密碼或空密碼
- **🔑 密碼強度檢查**: 最少 6 個字符，需要確認輸入
- **🛡️ 安全提示**: 互動式密碼設置，使用 `getpass` 隱藏輸入

## 📚 完整文檔結構

### 🚀 安裝配置
- **[TRAE_AI_METASPLOIT_SETUP_GUIDE.md](TRAE_AI_METASPLOIT_SETUP_GUIDE.md)** - 新手完整安裝指南
- **[TRAE_AI_METASPLOIT_COMPLETE_GUIDE.md](TRAE_AI_METASPLOIT_COMPLETE_GUIDE.md)** - 完整集成指南

### 📖 使用範例
- **[TRAE_AI_METASPLOIT_EXAMPLES.md](TRAE_AI_METASPLOIT_EXAMPLES.md)** - 基礎使用範例
- **[NETWORK_SCANNING_EXAMPLES.md](NETWORK_SCANNING_EXAMPLES.md)** - 網絡掃描範例
- **[EXPLOIT_EXAMPLES.md](EXPLOIT_EXAMPLES.md)** - 漏洞利用範例
- **[POST_EXPLOITATION_EXAMPLES.md](POST_EXPLOITATION_EXAMPLES.md)** - 後滲透範例
- **[PAYLOAD_GENERATION_EXAMPLES.md](PAYLOAD_GENERATION_EXAMPLES.md)** - Payload 生成範例
- **[COMPREHENSIVE_ATTACK_CHAIN_EXAMPLES.md](COMPREHENSIVE_ATTACK_CHAIN_EXAMPLES.md)** - 完整攻擊鏈範例

### ⚙️ 配置文件
- **[metasploit_mcp_trae_config.json](metasploit_mcp_trae_config.json)** - Trae AI MCP 配置
- **[start_metasploit_mcp.py](start_metasploit_mcp.py)** - 自動化啟動腳本

## 🔍 主要功能

### 智能查詢
```
搜索所有 SMB 相關的 exploit 模組
告訴我 ms17_010_eternalblue 模組的詳細信息
查詢 CVE-2017-0144 的相關信息
```

### 網絡掃描
```
掃描 192.168.1.100 的常見端口
對 192.168.1.0/24 網段進行 SYN 掃描
檢查目標是否存在 MS17-010 漏洞
```

### 漏洞利用
```
利用 MS17-010 漏洞攻擊 192.168.1.50 並獲取 shell
對 Windows XP 系統使用 MS08-067 漏洞
```

### Payload 生成
```
生成一個 Windows reverse shell payload
生成經過編碼的 payload 以規避防病毒檢測
```

## 🛠️ 故障排除

### 常見問題

1. **連接失敗**
   - 檢查網絡連通性：`ping YOUR_KALI_IP`
   - 檢查端口開放：`Test-NetConnection -ComputerName YOUR_KALI_IP -Port 8085`
   - 檢查防火牆設置

2. **服務啟動失敗**
   - 檢查 Metasploit 安裝：`msfconsole -v`
   - 檢查 Python 版本：`python3 --version`
   - 重新運行腳本：`python3 start_metasploit_mcp.py --interactive`

3. **密碼問題**
   - 腳本會強制要求設置安全密碼
   - 不允許使用默認密碼 'yourpassword'
   - 密碼最少需要 6 個字符

## 📋 系統需求

### Kali Linux 服務器
- Metasploit Framework（通常預裝）
- Python 3.10+
- Git
- 網絡連接

### Windows 客戶端
- Trae AI IDE
- Node.js 18+
- PowerShell
- 網絡連接到 Kali Linux

## ⚠️ 重要聲明

**本項目僅供教育和授權的滲透測試使用。使用者必須：**

- ✅ 僅在擁有明確授權的環境中使用
- ✅ 遵守當地法律法規和道德準則
- ✅ 用於提升網絡安全防護能力
- ❌ 禁止用於任何非法或惡意活動

## 🤝 貢獻

歡迎提交 Issue 和 Pull Request 來改進這個項目。

## 📄 許可證

本項目遵循開源協議，僅供學習和研究使用。使用者需自行承擔使用責任。

---

**開始您的智能滲透測試之旅！** 🚀

如有問題，請參考詳細的設置指南或在 Issues 中提問。