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

def banner():
    print("""    
    ┌─────────────────────────────────────────────────┐
    │                                                 │
    │       MetasploitMCP 服務器啟動工具             │
    │                                                 │
    └─────────────────────────────────────────────────┘
    """)

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
    parser.add_argument('--msf-password', help='Metasploit RPC 密碼', default='yourpassword')
    parser.add_argument('--msf-server', help='Metasploit RPC 服務器地址', default='127.0.0.1')
    parser.add_argument('--msf-port', help='Metasploit RPC 端口', type=int, default=55553)
    parser.add_argument('--msf-ssl', help='Metasploit RPC 是否使用 SSL', action='store_true')
    parser.add_argument('--payload-dir', help='Payload 保存目錄')
    parser.add_argument('--mcp-path', help='MetasploitMCP 目錄路徑', default='.')
    parser.add_argument('--start-msfrpcd', help='是否啟動 Metasploit RPC 服務', action='store_true')
    parser.add_argument('--generate-trae-config', help='是否生成 Trae AI MCP 配置文件', action='store_true')
    parser.add_argument('--remote-host', help='遠程 MetasploitMCP 服務器 IP 地址（用於跨網絡連接）')
    parser.add_argument('--remote-port', help='遠程 MetasploitMCP 服務器端口（用於跨網絡連接）', type=int)
    args = parser.parse_args()
    
    banner()
    
    # 如果只是生成配置文件且指定了遠程主機，則跳過依賴檢查
    if args.generate_trae_config and args.remote_host and not (args.start_msfrpcd or (not args.generate_trae_config)):
        print("[*] 檢測到遠程配置模式，跳過本地依賴檢查")
    else:
        # 檢查依賴
        missing = check_prerequisites()
        if missing:
            print("[!] 缺少以下依賴:")
            for item in missing:
                print(f"  - {item}")
            print("請安裝缺少的依賴後再試")
            sys.exit(1)
    
    # 啟動 Metasploit RPC 服務
    if args.start_msfrpcd:
        if not start_msfrpcd(args.msf_password, args.msf_server, args.msf_port, args.msf_ssl):
            print("[!] 啟動 Metasploit RPC 服務失敗")
            sys.exit(1)
        
        print("[*] 等待 Metasploit RPC 服務啟動...")
        time.sleep(5)
    
    # 啟動 MetasploitMCP 服務器（僅在非純配置生成模式下）
    if not (args.generate_trae_config and args.remote_host and not args.start_msfrpcd):
        if not start_metasploit_mcp(
            args.transport, args.host, args.port, 
            args.msf_password, args.msf_server, args.msf_port, 
            args.msf_ssl, args.payload_dir
        ):
            print("[!] 啟動 MetasploitMCP 服務器失敗")
            sys.exit(1)
    
    # 生成 Trae AI MCP 配置文件
    if args.generate_trae_config:
        if not generate_trae_config(
            args.msf_password, args.msf_server, args.msf_port, 
            args.msf_ssl, args.payload_dir, args.mcp_path,
            args.transport, args.remote_host, args.remote_port
        ):
            print("[!] 生成 Trae AI MCP 配置文件失敗")
            sys.exit(1)
    
    # 如果只是生成配置文件且指定了遠程主機，則不進入服務器運行循環
    if args.generate_trae_config and args.remote_host and not args.start_msfrpcd:
        print("\n[+] 遠程連接配置文件生成完成")
        print("[*] 請在 Kali 服務器上啟動 MetasploitMCP 服務器:")
        print(f"[*] python3 start_metasploit_mcp.py --transport http --host 0.0.0.0 --port {args.remote_port or 8085}")
        return
    
    print("\n[+] MetasploitMCP 服務器已成功啟動")
    print("[*] 按 Ctrl+C 停止服務器")
    
    try:
        # 檢測操作系統類型
        import platform
        is_windows = platform.system() == "Windows"
        
        if is_windows:
            # 在 Windows 環境中，我們只模擬運行
            print("[模擬] 服務器正在運行...")
            print("[模擬] 按 Ctrl+C 停止服務器")
        else:
            # 在 Linux/Kali 環境中，實際保持腳本運行
            print("[*] 服務器正在運行...")
            print("[*] 按 Ctrl+C 停止服務器")
            # 保持腳本運行，直到用戶按下 Ctrl+C
            while True:
                time.sleep(1)
    except KeyboardInterrupt:
        print("\n[*] 正在停止服務器...")
    
    print("[+] 服務器已停止")

if __name__ == "__main__":
    main()