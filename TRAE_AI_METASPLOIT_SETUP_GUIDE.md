# Trae AI + MetasploitMCP 完全新手配置指南

🎯 **目標**：讓完全不懂技術的人也能成功建立 Trae AI 與 MetasploitMCP 的集成

## 📋 什麼是這個集成？

這個集成讓您可以在 Trae AI 中用**自然語言**來控制 Metasploit（一個強大的滲透測試工具）。

**簡單來說**：
- 您可以對 Trae AI 說："幫我掃描 192.168.1.100 的端口"
- Trae AI 會自動執行相應的 Metasploit 命令
- 無需記憶複雜的命令語法

## 🏗️ 系統架構

```
┌─────────────────┐    HTTP    ┌─────────────────────┐    RPC    ┌─────────────────┐
│   Windows       │ ◄────────► │   Kali Linux        │ ◄───────► │   Metasploit    │
│   (Trae AI)     │            │   (MetasploitMCP)   │           │   Framework     │
│   10.0.0.85     │            │   172.31.44.17:8085 │           │   127.0.0.1:55553│
└─────────────────┘            └─────────────────────┘           └─────────────────┘
```

## ⚠️ 重要安全提醒

**🚨 請務必遵守以下原則：**
- ✅ 僅在**授權的測試環境**中使用
- ✅ 遵守當地法律法規
- ✅ 不要攻擊未經授權的系統
- ❌ 禁止用於惡意目的

## 📋 準備工作清單

在開始之前，請確保您有：

### 硬體需求
- [ ] Windows 電腦（安裝 Trae AI）
- [ ] Kali Linux 虛擬機或實體機（運行 MetasploitMCP）
- [ ] 兩台機器能夠網絡互通

### 軟體需求
- [ ] **Windows 端**：
  - Trae AI IDE
  - Node.js 18+ 
  - PowerShell
- [ ] **Kali Linux 端**：
  - Metasploit Framework（通常預裝）
  - Python 3.10+
  - Git

### 網絡需求
- [ ] Windows 能 ping 通 Kali Linux
- [ ] 防火牆允許端口 8085 和 55553

## 🚀 第一步：Kali Linux 端配置

### 1.1 檢查 Metasploit 是否已安裝

```bash
# 打開終端，輸入以下命令
msfconsole -v
```

**預期結果**：顯示 Metasploit 版本信息

如果顯示 "command not found"，請執行：
```bash
sudo apt update
sudo apt install metasploit-framework
```

### 1.2 下載 MetasploitMCP

```bash
# 切換到家目錄
cd ~

# 克隆 MetasploitMCP 項目
git clone https://github.com/GH05TCREW/MetasploitMCP.git

# 進入項目目錄
cd MetasploitMCP

# 檢查文件是否下載成功
ls -la
```

**預期結果**：看到 `MetasploitMCP.py` 和 `requirements.txt` 等文件

### 1.3 安裝 Python 依賴

```bash
# 確保使用 Python 3.10+
python3 --version

# 安裝依賴
pip3 install -r requirements.txt
```

**如果遇到權限問題**：
```bash
sudo pip3 install -r requirements.txt
```

### 1.4 啟動 Metasploit RPC 服務

```bash
# 啟動 RPC 服務（密碼設為 N0viru$123）
msfrpcd -P N0viru$123 -S -a 0.0.0.0 -p 55553
```

**重要說明**：
- `-P N0viru$123`：設置 RPC 密碼
- `-S`：禁用 SSL（簡化配置）
- `-a 0.0.0.0`：監聽所有網絡接口
- `-p 55553`：使用端口 55553

**預期結果**：看到 "MSGRPC Service Started" 消息

**保持這個終端窗口開啟！**

### 1.5 啟動 MetasploitMCP 服務器

**打開新的終端窗口**，執行：

```bash
# 進入 MetasploitMCP 目錄
cd ~/MetasploitMCP

# 設置環境變量
export MSF_PASSWORD=N0viru$123
export MSF_SERVER=127.0.0.1
export MSF_PORT=55553
export MSF_SSL=false

# 啟動 MetasploitMCP 服務器
python3 MetasploitMCP.py --transport http --host 0.0.0.0 --port 8085
```

**預期結果**：看到服務器啟動消息，顯示監聽在 `0.0.0.0:8085`

**保持這個終端窗口也開啟！**

### 1.6 驗證服務器運行狀態

**打開第三個終端窗口**，測試連接：

```bash
# 測試 MetasploitMCP 服務器
curl http://localhost:8085/sse

# 檢查 Metasploit RPC 服務
netstat -tlnp | grep 55553
```

**預期結果**：
- curl 命令返回 SSE 連接信息
- netstat 顯示端口 55553 正在監聽

## 🖥️ 第二步：Windows 端配置

### 2.1 檢查網絡連通性

打開 PowerShell，測試與 Kali Linux 的連接：

```powershell
# 替換 172.31.44.17 為您的 Kali Linux IP 地址
ping 172.31.44.17

# 測試端口連通性
Test-NetConnection -ComputerName 172.31.44.17 -Port 8085
```

**預期結果**：
- ping 成功
- 端口 8085 連接成功

### 2.2 檢查 Node.js 安裝

```powershell
# 檢查 Node.js 版本
node --version
npm --version
```

**如果未安裝 Node.js**：
1. 訪問 https://nodejs.org/
2. 下載並安裝 LTS 版本
3. 重新打開 PowerShell 驗證安裝

### 2.3 安裝 mcp-remote 工具

```powershell
# 全局安裝 mcp-remote
npm install -g mcp-remote

# 驗證安裝
npx mcp-remote --help
```

**預期結果**：顯示 mcp-remote 的幫助信息

### 2.4 測試 MCP 連接

```powershell
# 測試連接到 MetasploitMCP 服務器
# 替換 172.31.44.17 為您的 Kali Linux IP 地址
npx mcp-remote http://172.31.44.17:8085/sse --allow-http
```

**預期結果**：
- 顯示連接成功信息
- 可以看到可用的工具列表
- 按 Ctrl+C 退出測試

## 🔧 第三步：Trae AI 配置

### 3.1 創建 MCP 配置文件

在您的工作目錄中創建 `metasploit_mcp_config.json` 文件：

```json
{
    "mcpServers": {
        "metasploit": {
            "command": "npx",
            "args": [
                "mcp-remote",
                "http://172.31.44.17:8085/sse",
                "--allow-http"
            ],
            "env": {}
        }
    }
}
```

**重要**：將 `172.31.44.17` 替換為您的 Kali Linux 實際 IP 地址
**注意**：Windows 端 IP 地址為 `10.0.0.85`

### 3.2 在 Trae AI 中添加 MCP 服務器

1. **打開 Trae AI**
2. **點擊 AI 側邊欄右上角的設置圖標**
3. **選擇 "MCP"**
4. **點擊右上角的 "+" 按鈕**
5. **選擇 "手動添加"**
6. **將上面的 JSON 配置粘貼到配置窗口中**
7. **點擊 "確認"**

### 3.3 驗證 MCP 服務器狀態

在 Trae AI 的 MCP 設置頁面中：
- 查看 "metasploit" 服務器狀態
- 狀態應該顯示為 "已連接" 或綠色圖標

## ✅ 第四步：功能測試

### 4.1 基礎連接測試

在 Trae AI 中輸入：

```
你好，請確認你能連接到 Metasploit 服務器嗎？
```

**預期結果**：Trae AI 回復確認連接成功

### 4.2 簡單查詢測試

```
請搜索所有與 SMB 相關的 exploit 模組
```

**預期結果**：返回 SMB 相關的漏洞利用模組列表

### 4.3 掃描功能測試

```
幫我掃描 127.0.0.1 的端口 80 和 443
```

**預期結果**：執行端口掃描並返回結果

## 🔧 故障排除指南

### 問題 1：Trae AI 無法連接到 MetasploitMCP

**症狀**：MCP 服務器狀態顯示 "未連接" 或紅色

**解決步驟**：
1. 檢查 Kali Linux 上的 MetasploitMCP 服務器是否運行
2. 檢查網絡連通性：`ping 172.31.44.17`
3. 檢查端口：`Test-NetConnection -ComputerName 172.31.44.17 -Port 8085`
4. 檢查防火牆設置
5. 重啟 MetasploitMCP 服務器

### 問題 2：MetasploitMCP 服務器啟動失敗

**症狀**：Python 腳本報錯或無法啟動

**解決步驟**：
1. 檢查 Python 版本：`python3 --version`
2. 重新安裝依賴：`pip3 install -r requirements.txt`
3. 檢查 Metasploit RPC 服務是否運行：`netstat -tlnp | grep 55553`
4. 檢查環境變量設置

### 問題 3：Metasploit RPC 服務無法啟動

**症狀**：msfrpcd 命令報錯

**解決步驟**：
1. 檢查 Metasploit 是否正確安裝：`msfconsole -v`
2. 檢查端口是否被占用：`netstat -tlnp | grep 55553`
3. 嘗試使用不同端口：`msfrpcd -P N0viru$123 -S -a 0.0.0.0 -p 55554`
4. 重啟系統後再試

### 問題 4：查詢或掃描功能不工作

**症狀**：Trae AI 回復錯誤或無響應

**解決步驟**：
1. 檢查 Metasploit 數據庫狀態：在 msfconsole 中執行 `db_status`
2. 更新 Metasploit：`sudo apt update && sudo apt upgrade metasploit-framework`
3. 重啟所有服務（RPC 和 MetasploitMCP）
4. 檢查 Kali Linux 系統日誌

## 📚 使用範例

配置成功後，您可以嘗試以下查詢：

### 基礎查詢
```
搜索所有 Windows 相關的 exploit 模組
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

## 📖 進階學習資源

配置成功後，建議閱讀以下文檔：

1. **<mcfile name="TRAE_AI_METASPLOIT_COMPLETE_GUIDE.md" path="C:\\Users\\aduser\\Desktop\\tools\\TRAE_AI_METASPLOIT_COMPLETE_GUIDE.md"></mcfile>** - 完整使用指南
2. **<mcfile name="TRAE_AI_METASPLOIT_EXAMPLES.md" path="C:\\Users\\aduser\\Desktop\\tools\\TRAE_AI_METASPLOIT_EXAMPLES.md"></mcfile>** - 基礎使用範例
3. **<mcfile name="NETWORK_SCANNING_EXAMPLES.md" path="C:\\Users\\aduser\\Desktop\\tools\\NETWORK_SCANNING_EXAMPLES.md"></mcfile>** - 網絡掃描範例
4. **<mcfile name="EXPLOIT_EXAMPLES.md" path="C:\\Users\\aduser\\Desktop\\tools\\EXPLOIT_EXAMPLES.md"></mcfile>** - 漏洞利用範例

## 🎯 快速啟動檢查清單

每次使用前，請確認以下項目：

**Kali Linux 端**：
- [ ] Metasploit RPC 服務運行中（端口 55553）
- [ ] MetasploitMCP 服務器運行中（端口 8085）
- [ ] 網絡連接正常

**Windows 端**：
- [ ] Trae AI 中 MCP 服務器狀態為 "已連接"
- [ ] 能夠 ping 通 Kali Linux
- [ ] 端口 8085 連接正常

**功能測試**：
- [ ] 基礎查詢功能正常
- [ ] 掃描功能正常
- [ ] 無錯誤信息

## 📞 獲取幫助

如果遇到問題：

1. **檢查本指南的故障排除部分**
2. **向 Trae AI 詢問具體問題**：
   ```
   我在配置 MetasploitMCP 時遇到 [具體錯誤信息]，請幫我診斷
   ```
3. **檢查系統日誌和錯誤信息**
4. **參考官方文檔**

## 🎉 恭喜！

如果您成功完成了所有步驟，現在您已經擁有了一個智能化的滲透測試環境！

您可以用自然語言與 Metasploit 交互，大大簡化了複雜的安全測試工作流程。

**請記住**：始終負責任地使用這些工具，僅在授權的環境中進行測試。

---

*最後更新：2025年1月*
*版本：1.0*

**祝您使用愉快！** 🚀