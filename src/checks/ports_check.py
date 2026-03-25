import sys
import subprocess
import re
import json
from pathlib import Path
from core.security_check import SecurityCheck
from core.platform_adapter import PlatformAdapter


class PortsChecker(SecurityCheck):
    """端口暴露检测"""

    def __init__(self):
        super().__init__("端口暴露检测", "CRITICAL")
        self.dangerous_ports = [3000, 8080, 9000, 4140, 18789, 18791, 9222, 9223]
        self.openclaw_ports = [18789, 18791, 18792, 18793, 18794, 18795]

    async def run(self):
        """执行端口检测"""
        self.status = "running"
        
        # 在run方法中获取最新路径
        self.config_path = PlatformAdapter.get_openclaw_path() / "openclaw.json"

        if sys.platform == "win32":
            await self._check_windows_ports()
        else:
            await self._check_linux_ports()

        # 检查其他网络安全配置
        await self._check_all_interfaces()
        await self._check_firewall_rules()
        await self._check_rate_limit()
        await self._check_tls_config()
        await self._check_cors_config()

        self.status = "completed"

    async def _check_windows_ports(self):
        """Windows端口检测"""
        try:
            # 使用netstat检测
            result = subprocess.run(
                ["netstat", "-ano"],
                capture_output=True,
                text=True,
                encoding='gbk',
                errors='ignore'
            )

            for port in self.dangerous_ports:
                # 检测0.0.0.0绑定（危险）
                pattern = rf'0\.0\.0\.0:{port}\s'
                if re.search(pattern, result.stdout):
                    self.report(f"端口 {port} 全网暴露 (0.0.0.0) - 高危", "CRITICAL")

                # 检测127.0.0.1绑定（相对安全）
                pattern_local = rf'127\.0\.0\.1:{port}\s'
                if re.search(pattern_local, result.stdout):
                    self.report(f"端口 {port} 本地绑定 (127.0.0.1) - 安全", "INFO")

                # 检测IPv6地址
                pattern_v6 = rf'\[::\]:{port}\s'
                if re.search(pattern_v6, result.stdout):
                    self.report(f"端口 {port} IPv6全网暴露 (::) - 高危", "CRITICAL")

        except Exception as e:
            self.report(f"端口检测失败: {e}", "LOW")

    async def _check_linux_ports(self):
        """Linux端口检测"""
        try:
            # 首先尝试ss命令
            result = subprocess.run(
                ["ss", "-tlnp"],
                capture_output=True,
                text=True
            )

            if result.returncode != 0:
                # 如果ss不可用，尝试netstat
                result = subprocess.run(
                    ["netstat", "-tlnp"],
                    capture_output=True,
                    text=True
                )

            for port in self.dangerous_ports:
                if f":{port}" in result.stdout:
                    if f"0.0.0.0:{port}" in result.stdout or f"[::]:{port}" in result.stdout:
                        self.report(f"端口 {port} 全网暴露 - 高危", "CRITICAL")
                    elif f"127.0.0.1:{port}" in result.stdout:
                        self.report(f"端口 {port} 本地绑定 - 安全", "INFO")

        except Exception as e:
            self.report(f"端口检测失败: {e}", "LOW")

    async def _check_all_interfaces(self):
        """检查全网接口"""
        exposed_services = []
        
        try:
            if sys.platform == "win32":
                result = subprocess.run(
                    ["netstat", "-ano"],
                    capture_output=True,
                    text=True,
                    encoding='gbk',
                    errors='ignore'
                )
                lines = result.stdout.split('\n')
                for line in lines:
                    if '0.0.0.0:' in line or ':::' in line:
                        match = re.search(r'0\.0\.0\.0:(\d+)|:::(\d+)', line)
                        if match:
                            port = match.group(1) or match.group(2)
                            if port and port.isdigit():
                                port_num = int(port)
                                if port_num not in self.openclaw_ports and port_num > 1024:
                                    exposed_services.append(f"Port {port}")
            else:
                # Linux
                result = subprocess.run(
                    ["ss", "-tlnp"],
                    capture_output=True,
                    text=True
                )
                if result.returncode != 0:
                    result = subprocess.run(
                        ["netstat", "-tlnp"],
                        capture_output=True,
                        text=True
                    )
                for line in result.stdout.split('\n'):
                    if '0.0.0.0:' in line or ':::' in line:
                        match = re.search(r'0\.0\.0\.0:(\d+)|:::(\d+)', line)
                        if match:
                            port = match.group(1) or match.group(2)
                            if port and port.isdigit():
                                port_num = int(port)
                                if port_num not in self.openclaw_ports and port_num > 1024:
                                    exposed_services.append(f"Port {port}")
        except Exception as e:
            self.report(f"全网接口检查失败: {e}", "LOW")

        if exposed_services:
            self.report(f"发现额外暴露的服务: {', '.join(exposed_services[:5])}", "MEDIUM")

    async def _check_firewall_rules(self):
        """检查防火墙规则"""
        try:
            if sys.platform == "win32":
                # Windows防火墙检查
                result = subprocess.run(
                    ["netsh", "advfirewall", "firewall", "show", "rule", "name=all"],
                    capture_output=True,
                    text=True,
                    encoding='gbk',
                    errors='ignore'
                )
                for port in self.dangerous_ports:
                    if f"LocalPort={port}" in result.stdout and "Action=Allow" in result.stdout:
                        self.report(f"防火墙允许端口 {port} 访问", "MEDIUM")
            else:
                # Linux防火墙检查
                if subprocess.run(["which", "iptables"], capture_output=True).returncode == 0:
                    for port in self.dangerous_ports:
                        result = subprocess.run(
                            ["iptables", "-L", "INPUT", "-n"],
                            capture_output=True,
                            text=True
                        )
                        if str(port) not in result.stdout:
                            self.report(f"未找到端口 {port} 的防火墙规则", "MEDIUM")
                elif subprocess.run(["which", "ufw"], capture_output=True).returncode == 0:
                    for port in self.dangerous_ports:
                        result = subprocess.run(
                            ["ufw", "status"],
                            capture_output=True,
                            text=True
                        )
                        if str(port) not in result.stdout:
                            self.report(f"未找到端口 {port} 的UFW规则", "LOW")
        except Exception as e:
            self.report(f"防火墙规则检查失败: {e}", "LOW")

    async def _check_rate_limit(self):
        """检查速率限制"""
        if not self.config_path.exists():
            return

        try:
            with open(self.config_path, 'r', encoding='utf-8') as f:
                config = json.load(f)
        except Exception:
            return

        rate_limit = config.get("gateway", {}).get("rateLimit", {})
        max_requests = rate_limit.get("maxRequests", 0)
        window_ms = rate_limit.get("windowMs", 0)

        if not max_requests or max_requests > 1000:
            self.report("未配置速率限制或限制过于宽松", "MEDIUM")

    async def _check_tls_config(self):
        """检查TLS配置"""
        if not self.config_path.exists():
            return

        try:
            with open(self.config_path, 'r', encoding='utf-8') as f:
                config = json.load(f)
        except Exception:
            return

        tls = config.get("gateway", {}).get("tls", {})
        tls_enabled = tls.get("enabled", False)
        bind = config.get("gateway", {}).get("bind", "loopback")

        if not tls_enabled:
            if bind != "loopback" and bind != "localhost" and bind != "127.0.0.1":
                self.report("未配置TLS且网关暴露在非回环接口", "HIGH")
            else:
                self.report("未配置TLS（仅回环接口，可接受）", "LOW")

    async def _check_cors_config(self):
        """检查CORS配置"""
        if not self.config_path.exists():
            return

        try:
            with open(self.config_path, 'r', encoding='utf-8') as f:
                config = json.load(f)
        except Exception:
            return

        cors = config.get("gateway", {}).get("cors", {})
        origins = cors.get("origins", [])

        if not origins:
            self.report("未配置CORS来源", "LOW")
        elif "*" in origins:
            self.report("CORS使用通配符，允许所有来源", "HIGH")

    async def fix(self):
        """修复端口暴露问题"""
        if not self.config_path or not self.config_path.exists():
            return
        
        try:
            with open(self.config_path, 'r', encoding='utf-8') as f:
                config = json.load(f)
        except Exception:
            return
        
        # 修复绑定地址
        if "gateway" not in config:
            config["gateway"] = {}
        
        # 设置绑定地址为loopback
        if config["gateway"].get("bind", "loopback") not in ["loopback", "localhost", "127.0.0.1"]:
            config["gateway"]["bind"] = "loopback"
            self.report("已将绑定地址设置为loopback", "INFO")
        
        # 修复CORS配置
        if "cors" not in config["gateway"]:
            config["gateway"]["cors"] = {}
        if "origins" not in config["gateway"]["cors"]:
            config["gateway"]["cors"]["origins"] = ["http://localhost:3000", "http://127.0.0.1:3000"]
            self.report("已配置CORS来源", "INFO")
        elif "*" in config["gateway"]["cors"]["origins"]:
            config["gateway"]["cors"]["origins"] = ["http://localhost:3000", "http://127.0.0.1:3000"]
            self.report("已修复CORS通配符问题", "INFO")
        
        # 修复速率限制
        if "rateLimit" not in config["gateway"]:
            config["gateway"]["rateLimit"] = {
                "maxRequests": 100,
                "windowMs": 60000
            }
            self.report("已配置速率限制", "INFO")
        
        # 保存修复后的配置
        try:
            with open(self.config_path, 'w', encoding='utf-8') as f:
                json.dump(config, f, ensure_ascii=False, indent=2)
        except Exception as e:
            self.report(f"保存配置失败: {e}", "LOW")
