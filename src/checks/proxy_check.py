import json
import re
from pathlib import Path
from core.security_check import SecurityCheck
from core.platform_adapter import PlatformAdapter


class ProxyChecker(SecurityCheck):
    """反代配置检查"""

    def __init__(self):
        super().__init__("反代配置检测", "HIGH")

    async def run(self):
        """执行反代配置检测"""
        self.status = "running"
        
        # 在run方法中获取最新路径
        self.config_path = PlatformAdapter.get_openclaw_path() / "openclaw.json"

        if not self.config_path.exists():
            self.report("未找到openclaw.json配置文件", "INFO")
            return

        try:
            with open(self.config_path, 'r', encoding='utf-8') as f:
                config = json.load(f)
        except Exception as e:
            self.report(f"配置文件解析失败: {e}")
            return

        # 1. 受信任代理配置检查
        await self._check_trusted_proxies(config)

        # 2. X-Forwarded-For 头处理
        await self._check_x_forwarded_for(config)

        # 3. 安全头配置
        await self._check_security_headers(config)

        # 4. 代理链安全
        await self._check_proxy_chain(config)

        self.status = "completed"

    async def _check_trusted_proxies(self, config):
        """检查受信任代理配置"""
        proxy_config = config.get("proxy", {})
        trusted_proxies = proxy_config.get("trustedProxies", [])

        if not trusted_proxies:
            self.report("未配置受信任代理列表，可能导致IP欺骗", "HIGH")
        elif "*" in trusted_proxies:
            self.report("受信任代理使用通配符，存在安全风险", "HIGH")
        else:
            # 检查是否包含非本地IP
            non_local = [ip for ip in trusted_proxies if not ip.startswith("127.") and ip != "localhost"]
            if non_local:
                self.report(f"受信任代理包含非本地IP: {', '.join(non_local)}", "MEDIUM")

    async def _check_x_forwarded_for(self, config):
        """检查X-Forwarded-For头处理"""
        proxy_config = config.get("proxy", {})
        if not proxy_config.get("trustXForwardedFor", False):
            self.report("未信任X-Forwarded-For头，可能导致真实IP获取失败", "LOW")

    async def _check_security_headers(self, config):
        """检查安全头配置"""
        proxy_config = config.get("proxy", {})
        headers = proxy_config.get("headers", {})

        # 检查关键安全头
        missing_headers = []
        if not headers.get("X-Content-Type-Options"):
            missing_headers.append("X-Content-Type-Options")
        if not headers.get("X-Frame-Options"):
            missing_headers.append("X-Frame-Options")
        if not headers.get("X-XSS-Protection"):
            missing_headers.append("X-XSS-Protection")
        if not headers.get("Strict-Transport-Security") and proxy_config.get("https", False):
            missing_headers.append("Strict-Transport-Security")

        if missing_headers:
            self.report(f"缺少安全头: {', '.join(missing_headers)}", "MEDIUM")

    async def _check_proxy_chain(self, config):
        """检查代理链配置"""
        proxy_config = config.get("proxy", {})
        chain = proxy_config.get("chain", [])

        if chain:
            # 检查代理链长度和安全性
            if len(chain) > 3:
                self.report(f"代理链长度过长: {len(chain)}个代理", "MEDIUM")
            
            # 检查是否使用了不安全的代理协议
            for proxy in chain:
                if isinstance(proxy, str) and proxy.startswith("http://"):
                    self.report(f"代理链中使用了不安全的HTTP代理: {proxy}", "HIGH")

    async def fix(self):
        """修复反代配置问题"""
        if not self.config_path or not self.config_path.exists():
            return
        
        try:
            with open(self.config_path, 'r', encoding='utf-8') as f:
                config = json.load(f)
        except Exception:
            return
        
        # 修复代理配置
        if "proxy" not in config:
            config["proxy"] = {}
        
        # 修复受信任代理
        if "trustedProxies" not in config["proxy"] or not config["proxy"]["trustedProxies"]:
            config["proxy"]["trustedProxies"] = ["127.0.0.1", "localhost"]
            self.report("已配置受信任代理为本地地址", "INFO")
        elif "*" in config["proxy"]["trustedProxies"]:
            config["proxy"]["trustedProxies"] = ["127.0.0.1", "localhost"]
            self.report("已修复受信任代理通配符问题", "INFO")
        
        # 信任X-Forwarded-For头
        if config["proxy"].get("trustXForwardedFor", False) is False:
            config["proxy"]["trustXForwardedFor"] = True
            self.report("已信任X-Forwarded-For头", "INFO")
        
        # 添加安全头
        if "headers" not in config["proxy"]:
            config["proxy"]["headers"] = {}
        
        security_headers = {
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "SAMEORIGIN",
            "X-XSS-Protection": "1; mode=block"
        }
        
        for header, value in security_headers.items():
            if header not in config["proxy"]["headers"]:
                config["proxy"]["headers"][header] = value
                self.report(f"已添加安全头: {header}", "INFO")
        
        # 修复HTTPS安全头
        if config["proxy"].get("https", False):
            if "Strict-Transport-Security" not in config["proxy"]["headers"]:
                config["proxy"]["headers"]["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
                self.report("已添加Strict-Transport-Security头", "INFO")
        
        # 修复代理链
        if "chain" in config["proxy"]:
            # 限制代理链长度
            if len(config["proxy"]["chain"]) > 3:
                config["proxy"]["chain"] = config["proxy"]["chain"][:3]
                self.report("已限制代理链长度为3个", "INFO")
            
            # 移除不安全的HTTP代理
            secure_chain = []
            for proxy in config["proxy"]["chain"]:
                if isinstance(proxy, str) and proxy.startswith("http://"):
                    self.report(f"已移除不安全的HTTP代理: {proxy}", "INFO")
                else:
                    secure_chain.append(proxy)
            config["proxy"]["chain"] = secure_chain
        
        # 保存修复后的配置
        try:
            with open(self.config_path, 'w', encoding='utf-8') as f:
                json.dump(config, f, ensure_ascii=False, indent=2)
        except Exception as e:
            self.report(f"保存配置失败: {e}", "LOW")
