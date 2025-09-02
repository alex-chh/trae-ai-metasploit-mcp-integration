#!/usr/bin/env python3

'''
啟動 MetasploitMCP 服務器腳本
此腳本用於啟動 MetasploitMCP 服務器，以便與 Trae AI 集成
'''

import argparse
import os
import sys
import subprocess
import json
import time
import getpass

def banner():
    print("""    
    ┌─────────────────────────────────────────────────┐
    │                                                 │
    │       MetasploitMCP 服務器啟動工具             │
    │                                                 │
    └─────────────────────────────────────────────────┘
    """)

def get_user_input():
    """獲取使用者輸入的配置參數"""
    print("[*] 請輸入系統配置參數:")
    print()
    
    # 獲取 Metasploit RPC 服務器 IP
    while True:
        msf_server = input("請輸入 Metasploit RPC 服務器 IP 地址 [預設: 127.0.0.1]: ").strip()
        if not msf_server:
            msf_server = "127.0.0.1"
        
        # 簡單的 IP 地址格式驗證
        import re
        ip_pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
        if re.match(ip_pattern, msf_server):
            break
        else:
            print("[!] 請輸入有效的 IP 地址格式")
    
    # 獲取 RPC 密碼
    while True:
        msf_password = getpass.getpass("請輸入 Metasploit RPC 密碼: ").strip()
        if msf_password:
            # 確認密碼
            confirm_password = getpass.getpass("請再次輸入密碼以確認: ").strip()
            if msf_password == confirm_password:
                break
            else:
                print("[!] 密碼不匹配，請重新輸入")
        else:
            print("[!] 密碼不能為空")
    
    # 獲取 RPC 端口
    while True:
        try:
            msf_port_input = input("請輸入 Metasploit RPC 端口 [預設: 55553]: ").strip()
            if not msf_port_input:
                msf_port = 55553
            else:
                msf_port = int(msf_port_input)
                if not (1 <= msf_port <= 65535):
                    raise ValueError("端口範圍應在 1-65535 之間")
            break
        except ValueError as e:
            print(f"[!] 請輸入有效的端口號 (1-65535): {e}")
    
    # 獲取 MCP 服務器配置
    while True:
        mcp_host = input("請輸入 MCP 服務器監聽 IP 地址 [預設: 0.0.0.0]: ").strip()
        if not mcp_host:
            mcp_host = "0.0.0.0"
        
        # 驗證 IP 地址格式
        if mcp_host == "0.0.0.0" or re.match(ip_pattern, mcp_host):
            break
        else:
            print("[!] 請輸入有效的 IP 地址格式")
    
    while True:
        try:
            mcp_port_input = input("請輸入 MCP 服務器端口 [預設: 8085]: ").strip()
            if not mcp_port_input:
                mcp_port = 8085
            else:
                mcp_port = int(mcp_port_input)
                if not (1 <= mcp_port <= 65535):
                    raise ValueError("端口範圍應在 1-65535 之間")
            break
        except ValueError as e:
            print(f"[!] 請輸入有效的端口號 (1-65535): {e}")
    
    # 是否使用 SSL
    while True:
        ssl_input = input("是否使用 SSL 連接? [y/N]: ").strip().lower()
        if ssl_input in ['y', 'yes', '是']:
            msf_ssl = True
            break
        elif ssl_input in ['n', 'no', '否', '']:
            msf_ssl = False
            break
        else:
            print("[!] 請輸入 y/yes/是 或 n/no/否")
    
    print()
    print("[*] 配置摘要:")
    print(f"    Metasploit RPC 服務器: {msf_server}:{msf_port}")
    print(f"    SSL 連接: {'是' if msf_ssl else '否'}")
    print(f"    MCP 服務器: {mcp_host}:{mcp_port}")
    print()
    
    # 確認配置
    while True:
        confirm = input("確認以上配置? [Y/n]: ").strip().lower()
        if confirm in ['y', 'yes', '是', '']:
            break
        elif confirm in ['n', 'no', '否']:
            print("[*] 重新配置...")
            print()
            return get_user_input()  # 遞歸重新獲取配置
        else:
            print("[!] 請輸入 y/yes/是 或 n/no/否")
    
    return {
        'msf_server': msf_server,
        'msf_password': msf_password,
        'msf_port': msf_port,
        'msf_ssl': msf_ssl,
        'mcp_host': mcp_host,
        'mcp_port': mcp_port
    }

def check_prerequisites():
    """檢查必要的依賴是否已安裝"""
    missing = []
    
    # 檢查 Python 版本
    if sys.version_info < (3, 10):
        missing.append(f"Python 3.10+ (當前版本: {sys.version_info.major}.{sys.version_info.minor})")
    
    # 檢查 Metasploit 是否已安裝
    try:
        result = subprocess.run(['msfconsole', '-v'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=5)
        if result.returncode != 0:
            missing.append("Metasploit Framework")
    except (subprocess.SubprocessError, FileNotFoundError):
        missing.append("Metasploit Framework")
    
    return missing

def start_msfrpcd(password, host, port, ssl):
    """啟動 Metasploit RPC 服務"""
    ssl_flag = "-S" if ssl else ""
    cmd = f"msfrpcd -P {password} {ssl_flag} -a {host} -p {port}"
    
    print(f"[*] 啟動 Metasploit RPC 服務: {cmd}")
    
    try:
        # 檢測操作系統類型
        import platform
        is_windows = platform.system() == "Windows"
        
        if is_windows:
            # 在 Windows 環境中，我們只模擬執行
            print("[模擬] 在系統上執行以下命令:")
            print(f"$ {cmd}")
            print("[模擬] Metasploit RPC 服務已啟動")
        else:
            # 在 Linux/Kali 環境中，實際執行命令
            print(f"[*] 執行命令: {cmd}")
            process = subprocess.Popen(cmd.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            print(f"[+] Metasploit RPC 服務已啟動，PID: {process.pid}")
        
        return True
    except Exception as e:
        print(f"[!] 啟動 Metasploit RPC 服務時出錯: {e}")
        return False

def start_metasploit_mcp(transport, host, port, msf_password, msf_server, msf_port, msf_ssl, payload_dir):
    """啟動 MetasploitMCP 服務器"""
    env = os.environ.copy()
    env["MSF_PASSWORD"] = msf_password
    env["MSF_SERVER"] = msf_server
    env["MSF_PORT"] = str(msf_port)
    env["MSF_SSL"] = "true" if msf_ssl else "false"
    
    if payload_dir:
        env["PAYLOAD_SAVE_DIR"] = payload_dir
    
    # 檢測操作系統類型
    import platform
    is_windows = platform.system() == "Windows"
    
    # 檢查是否存在虛擬環境，如果不存在則創建
    venv_dir = os.path.join(os.getcwd(), "venv")
    if not os.path.exists(venv_dir):
        print(f"[*] 創建虛擬環境: {venv_dir}")
        try:
            subprocess.run([sys.executable, "-m", "venv", "--system-site-packages", venv_dir], check=True)
            print(f"[+] 虛擬環境創建成功")
            
            # 安裝依賴
            if os.path.exists("requirements.txt"):
                print(f"[*] 安裝依賴...")
                # 根據操作系統選擇正確的 pip 路徑
                if is_windows:
                    pip_path = os.path.join(venv_dir, "Scripts", "pip")
                else:
                    pip_path = os.path.join(venv_dir, "bin", "pip")
                subprocess.run([pip_path, "install", "-r", "requirements.txt"], check=True)
                print(f"[+] 依賴安裝成功")
        except subprocess.SubprocessError as e:
            print(f"[!] 創建虛擬環境或安裝依賴時出錯: {e}")
            return False
    
    # 根據操作系統選擇正確的 Python 解釋器路徑
    if is_windows:
        python_path = os.path.join(venv_dir, "Scripts", "python")
    else:
        python_path = os.path.join(venv_dir, "bin", "python")
    
    cmd = [python_path, "MetasploitMCP.py", "--transport", transport]
    
    if transport == "http":
        cmd.extend(["--host", host, "--port", str(port)])
    
    print(f"[*] 啟動 MetasploitMCP 服務器: {' '.join(cmd)}")
    
    try:
        # 檢測操作系統類型
        import platform
        is_windows = platform.system() == "Windows"
        
        if is_windows:
            # 在 Windows 環境中，我們只模擬執行
            print("[模擬] 在系統上執行以下命令:")
            print(f"$ {' '.join(cmd)}")
            print("[模擬] MetasploitMCP 服務器已啟動")
        else:
            # 在 Linux/Kali 環境中，實際執行命令
            print(f"[*] 執行命令: {' '.join(cmd)}")
            process = subprocess.Popen(cmd, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            print(f"[+] MetasploitMCP 服務器已啟動，PID: {process.pid}")
        
        if transport == "http":
            print(f"[*] SSE 端點: http://{host}:{port}/sse")
        
        return True
    except Exception as e:
        print(f"[!] 啟動 MetasploitMCP 服務器時出錯: {e}")
        return False

def generate_trae_config(msf_password, msf_server, msf_port, msf_ssl, payload_dir, mcp_path, transport="stdio", remote_host=None, remote_port=None):
    """生成 Trae AI 的 MCP 配置文件"""
    # 檢測操作系統類型
    import platform
    is_windows = platform.system() == "Windows"
    
    # 如果指定了遠程主機，則使用 HTTP 模式
    if remote_host and remote_port:
        transport = "http"
        print(f"[*] 檢測到遠程主機配置，使用 HTTP 傳輸模式")
        print(f"[*] 遠程服務器: {remote_host}:{remote_port}")
    
    if transport == "stdio":
        # STDIO 模式 - 本地連接
        if is_windows:
            # Windows 環境使用批處理腳本
            venv_script_name = "run_mcp_venv.bat"
            venv_script = os.path.join(mcp_path, venv_script_name)
            with open(venv_script, 'w') as f:
                f.write(f"@echo off\n")
                f.write(f"if not exist {os.path.join(mcp_path, 'venv')} (\n")
                f.write(f"  echo Creating virtual environment...\n")
                f.write(f"  python -m venv --system-site-packages {os.path.join(mcp_path, 'venv')}\n")
                f.write(f"  echo Installing requirements...\n")
                f.write(f"  {os.path.join(mcp_path, 'venv', 'Scripts', 'pip')} install -r {os.path.join(mcp_path, 'requirements.txt')}\n")
                f.write(f")\n")
                f.write(f"echo Starting MetasploitMCP...\n")
                f.write(f"{os.path.join(mcp_path, 'venv', 'Scripts', 'python')} {os.path.join(mcp_path, 'MetasploitMCP.py')} --transport stdio\n")
        else:
            # Linux/Kali 環境使用 shell 腳本
            venv_script_name = "run_mcp_venv.sh"
            venv_script = os.path.join(mcp_path, venv_script_name)
            with open(venv_script, 'w') as f:
                f.write(f"#!/bin/bash\n")
                f.write(f"if [ ! -d {os.path.join(mcp_path, 'venv')} ]; then\n")
                f.write(f"  echo \"Creating virtual environment...\"\n")
                f.write(f"  python3 -m venv --system-site-packages {os.path.join(mcp_path, 'venv')}\n")
                f.write(f"  echo \"Installing requirements...\"\n")
                f.write(f"  {os.path.join(mcp_path, 'venv', 'bin', 'pip')} install -r {os.path.join(mcp_path, 'requirements.txt')}\n")
                f.write(f"fi\n")
                f.write(f"echo \"Starting MetasploitMCP...\"\n")
                f.write(f"{os.path.join(mcp_path, 'venv', 'bin', 'python')} {os.path.join(mcp_path, 'MetasploitMCP.py')} --transport stdio\n")
            
            # 設置腳本執行權限
            try:
                import stat
                os.chmod(venv_script, os.stat(venv_script).st_mode | stat.S_IEXEC)
                print(f"[+] 已設置腳本執行權限: {venv_script}")
            except Exception as e:
                print(f"[!] 設置腳本執行權限時出錯: {e}")
        
        print(f"[+] 已創建虛擬環境運行腳本: {venv_script}")
        
        # 根據操作系統使用正確的路徑格式
        script_path = venv_script
        if not is_windows:
            # 確保 Linux 路徑格式正確
            script_path = script_path.replace('\\', '/')
        
        config = {
            "mcpServers": {
                "metasploit": {
                    "command": script_path,
                    "args": [],
                    "env": {
                        "MSF_PASSWORD": msf_password,
                        "MSF_SERVER": msf_server,
                        "MSF_PORT": str(msf_port),
                        "MSF_SSL": "true" if msf_ssl else "false"
                    }
                }
            }
        }
    else:
        # HTTP 模式 - 遠程連接
        config = {
            "mcpServers": {
                "metasploit": {
                    "command": "npx",
                    "args": [
                        "mcp-remote",
                        f"http://{remote_host}:{remote_port}/sse",
                        "--allow-http"
                    ],
                    "env": {}
                }
            }
        }
    
    if payload_dir:
        config["mcpServers"]["metasploit"]["env"]["PAYLOAD_SAVE_DIR"] = payload_dir
    
    config_file = "metasploit_mcp_trae_config.json"
    
    try:
        with open(config_file, 'w') as f:
            json.dump(config, f, indent=4)
        
        print(f"[+] Trae AI MCP 配置文件已生成: {config_file}")
        print("[*] 您可以將此配置文件導入到 Trae AI 中")
        
        return True
    except Exception as e:
        print(f"[!] 生成 Trae AI MCP 配置文件時出錯: {e}")
        return False

def main():
    parser = argparse.ArgumentParser(description='MetasploitMCP 服務器啟動工具')
    parser.add_argument('-t', '--transport', help='傳輸方式 (http 或 stdio)', default='http', choices=['http', 'stdio'])
    parser.add_argument('--host', help='HTTP 模式的主機地址', default='0.0.0.0')
    parser.add_argument('--port', help='HTTP 模式的端口', type=int, default=8085)
    parser.add_argument('--msf-password', help='Metasploit RPC 密碼')
    parser.add_argument('--msf-server', help='Metasploit RPC 服務器地址', default='127.0.0.1')
    parser.add_argument('--msf-port', help='Metasploit RPC 端口', type=int, default=55553)
    parser.add_argument('--msf-ssl', help='Metasploit RPC 是否使用 SSL', action='store_true')
    parser.add_argument('--payload-dir', help='Payload 保存目錄')
    parser.add_argument('--mcp-path', help='MetasploitMCP 目錄路徑', default='.')
    parser.add_argument('--start-msfrpcd', help='是否啟動 Metasploit RPC 服務', action='store_true')
    parser.add_argument('--generate-trae-config', help='是否生成 Trae AI MCP 配置文件', action='store_true')
    parser.add_argument('--remote-host', help='遠程 MetasploitMCP 服務器 IP 地址（用於跨網絡連接）')
    parser.add_argument('--remote-port', help='遠程 MetasploitMCP 服務器端口（用於跨網絡連接）', type=int)
    parser.add_argument('--interactive', help='使用互動模式獲取配置參數', action='store_true')
    args = parser.parse_args()
    
    banner()
    
    # 互動模式：獲取使用者輸入
    if args.interactive or (not args.msf_password and not args.remote_host):
        print("[*] 啟動互動配置模式")
        user_config = get_user_input()
        
        # 更新參數
        if not args.host:
            args.host = user_config.get('host', '0.0.0.0')
        if not args.port:
            args.port = user_config.get('port', 8085)
        if not args.msf_server:
            args.msf_server = user_config.get('msf_server', '127.0.0.1')
        if not args.msf_port:
            args.msf_port = user_config.get('msf_port', 55553)
        if not args.msf_password:
            args.msf_password = user_config.get('msf_password', 'yourpassword')
    else:
        # 設置默認值
        if not args.host:
            args.host = '0.0.0.0'
        if not args.port:
            args.port = 8085
        if not args.msf_server:
            args.msf_server = '127.0.0.1'
        if not args.msf_port:
            args.msf_port = 55553
    
    # 密碼安全檢查和互動輸入
    if not args.msf_password or args.msf_password == 'yourpassword':
        print("[!] 為了安全起見，不允許使用默認密碼或空密碼")
        print("[*] 請設置一個安全的 Metasploit RPC 密碼")
        while True:
            password = getpass.getpass("[+] 請輸入 Metasploit RPC 密碼: ")
            if not password:
                print("[!] 密碼不能為空，請重新輸入")
                continue
            if password == 'yourpassword':
                print("[!] 不能使用默認密碼 'yourpassword'，請設置一個安全的密碼")
                continue
            if len(password) < 6:
                print("[!] 密碼長度至少需要 6 個字符")
                continue
            
            # 確認密碼
            confirm_password = getpass.getpass("[+] 請再次輸入密碼以確認: ")
            if password == confirm_password:
                args.msf_password = password
                break
            else:
                print("[!] 密碼不匹配，請重新輸入")
    
    # 檢查先決條件
    print("[*] 檢查系統先決條件...")
    missing = check_prerequisites()
    if missing:
        print("[!] 缺少以下依賴:")
        for item in missing:
            print(f"    - {item}")
        print("[!] 請安裝缺少的依賴後重新運行")
        return 1
    
    print("[+] 系統先決條件檢查通過")
    
    # 啟動 Metasploit RPC 服務
    if args.start_msfrpcd:
        print("[*] 啟動 Metasploit RPC 服務...")
        if not start_msfrpcd(args.msf_password, args.msf_server, args.msf_port, args.msf_ssl):
            print("[!] 啟動 Metasploit RPC 服務失敗")
            return 1
        
        # 等待 RPC 服務啟動
        print("[*] 等待 Metasploit RPC 服務啟動...")
        time.sleep(3)
    
    # 啟動 MetasploitMCP 服務器
    print("[*] 啟動 MetasploitMCP 服務器...")
    if not start_metasploit_mcp(args.transport, args.host, args.port, args.msf_password, 
                               args.msf_server, args.msf_port, args.msf_ssl, args.payload_dir):
        print("[!] 啟動 MetasploitMCP 服務器失敗")
        return 1
    
    # 生成 Trae AI MCP 配置文件
    if args.generate_trae_config or args.remote_host:
        print("[*] 生成 Trae AI MCP 配置文件...")
        if not generate_trae_config(args.msf_password, args.msf_server, args.msf_port, args.msf_ssl, 
                                   args.payload_dir, args.mcp_path, args.transport, 
                                   args.remote_host, args.remote_port):
            print("[!] 生成 Trae AI MCP 配置文件失敗")
            return 1
    
    print("[+] MetasploitMCP 服務器啟動完成")
    print("[*] 服務器正在運行，按 Ctrl+C 停止")
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[*] 正在停止服務器...")
        print("[+] 服務器已停止")
    
    return 0

if __name__ == '__main__':
    sys.exit(main())