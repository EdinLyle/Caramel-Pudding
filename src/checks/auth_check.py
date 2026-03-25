import json
import re
from pathlib import Path
from core.security_check import SecurityCheck
from core.platform_adapter import PlatformAdapter


class AuthChecker(SecurityCheck):
    """认证与口令检测"""

    def __init__(self):
        super().__init__("认证与口令检测", "HIGH")

    async def run(self):
        """执行认证与口令检测"""
        self.status = "running"
        
        # 在run方法中获取最新路径
        self.config_path = PlatformAdapter.get_openclaw_path() / "openclaw.json"

        # 1. 检查认证配置
        await self._check_auth_config()

        # 2. 检查弱口令风险
        await self._check_weak_passwords()

        # 3. 检查Token配置
        await self._check_token_config()

        # 4. 检查速率限制
        await self._check_rate_limit()

        self.status = "completed"

    async def _check_auth_config(self):
        """检查认证配置"""
        if not self.config_path.exists():
            return

        try:
            with open(self.config_path, 'r', encoding='utf-8') as f:
                config = json.load(f)

            # 检查认证是否启用
            auth_enabled = self._get_nested_value(config, 'auth.enabled')
            if auth_enabled is False:
                self.report("网关认证已关闭，存在未授权访问风险", "CRITICAL")

            # 检查认证模式
            auth_mode = self._get_nested_value(config, 'auth.mode')
            if auth_mode == 'none' or auth_mode is None:
                self.report("未设置认证模式", "CRITICAL")

            # 检查是否允许匿名访问
            allow_anonymous = self._get_nested_value(config, 'auth.allowAnonymous')
            if allow_anonymous is True:
                self.report("允许匿名访问", "CRITICAL")

        except Exception as e:
            self.report(f"认证配置检查失败: {e}", "LOW")

    async def _check_weak_passwords(self):
        """检查弱口令风险"""
        if not self.config_path.exists():
            return

        try:
            with open(self.config_path, 'r', encoding='utf-8') as f:
                config = json.load(f)

            # 检查默认密码
            password = self._get_nested_value(config, 'auth.password')
            if password:
                weak_passwords = [
                    'password', '123456', 'admin', 'root',
                    '12345678', 'qwerty', '111111',
                    'admin123', 'root123', 'password123'
                ]

                if password.lower() in weak_passwords:
                    self.report(f"检测到弱口令: {password}", "CRITICAL")

                # 检查密码长度
                if len(password) < 8:
                    self.report(f"密码长度过短: {len(password)} 字符", "HIGH")

                # 检查密码复杂度
                if not any(c.isupper() for c in password):
                    self.report("密码缺少大写字母", "MEDIUM")
                if not any(c.islower() for c in password):
                    self.report("密码缺少小写字母", "MEDIUM")
                if not any(c.isdigit() for c in password):
                    self.report("密码缺少数字", "MEDIUM")

        except Exception as e:
            self.report(f"弱口令检查失败: {e}", "LOW")

    async def _check_token_config(self):
        """检查Token配置"""
        if not self.config_path.exists():
            return

        try:
            with open(self.config_path, 'r', encoding='utf-8') as f:
                config = json.load(f)

            # 检查JWT Secret
            jwt_secret = self._get_nested_value(config, 'auth.jwt.secret')
            if jwt_secret:
                # 检查Secret强度
                if len(jwt_secret) < 32:
                    self.report(f"JWT Secret过短: {len(jwt_secret)} 字符", "HIGH")

                # 检查是否使用默认Secret
                if jwt_secret in ['secret', 'default', 'change-me']:
                    self.report("JWT Secret使用默认值", "CRITICAL")

            # 检查Token过期时间
            token_ttl = self._get_nested_value(config, 'auth.token.ttl')
            if token_ttl:
                # 如果TTL过长（超过30天）
                if token_ttl > 2592000:  # 30天 = 30 * 24 * 3600
                    self.report(f"Token过期时间过长: {token_ttl} 秒", "MEDIUM")

                # 如果TTL为0或None（永不过期）
                if token_ttl == 0 or token_ttl is None:
                    self.report("Token永不过期，存在安全风险", "HIGH")

        except Exception as e:
            self.report(f"Token配置检查失败: {e}", "LOW")

    async def _check_rate_limit(self):
        """检查速率限制"""
        if not self.config_path.exists():
            return

        try:
            with open(self.config_path, 'r', encoding='utf-8') as f:
                config = json.load(f)

            # 检查是否启用速率限制
            rate_limit_enabled = self._get_nested_value(config, 'rateLimit.enabled')
            if rate_limit_enabled is False:
                self.report("速率限制已关闭，存在暴力破解风险", "HIGH")

            # 检查速率限制配置
            if rate_limit_enabled:
                max_requests = self._get_nested_value(config, 'rateLimit.max')
                window = self._get_nested_value(config, 'rateLimit.window')

                if max_requests and max_requests > 1000:
                    self.report(f"速率限制过高: {max_requests} 次/窗口", "MEDIUM")

        except Exception as e:
            self.report(f"速率限制检查失败: {e}", "LOW")

    def _get_nested_value(self, d, key):
        """获取嵌套字典值"""
        keys = key.split('.')
        for k in keys:
            if isinstance(d, dict):
                d = d.get(k, {})
            else:
                return None
        return d if d != {} else None

    async def fix(self):
        """修复认证与口令问题"""
        if not self.config_path or not self.config_path.exists():
            return
        
        try:
            with open(self.config_path, 'r', encoding='utf-8') as f:
                config = json.load(f)
        except Exception:
            return
        
        # 修复认证配置
        if "auth" not in config:
            config["auth"] = {}
        
        # 启用认证
        if config["auth"].get("enabled", True) is False:
            config["auth"]["enabled"] = True
            self.report("已启用认证", "INFO")
        
        # 设置认证模式为token
        if config["auth"].get("mode", "token") == "none":
            config["auth"]["mode"] = "token"
            self.report("已设置认证模式为token", "INFO")
        
        # 禁用匿名访问
        if config["auth"].get("allowAnonymous", False) is True:
            config["auth"]["allowAnonymous"] = False
            self.report("已禁用匿名访问", "INFO")
        
        # 生成强密码
        if "password" in config["auth"]:
            import secrets
            import string
            new_password = ''.join(secrets.choice(string.ascii_letters + string.digits + string.punctuation) for _ in range(16))
            config["auth"]["password"] = new_password
            self.report("已生成强密码", "INFO")
        
        # 修复JWT配置
        if "jwt" not in config["auth"]:
            config["auth"]["jwt"] = {}
        if "secret" not in config["auth"]["jwt"] or len(config["auth"]["jwt"]["secret"]) < 32:
            import secrets
            config["auth"]["jwt"]["secret"] = secrets.token_hex(32)
            self.report("已生成强JWT Secret", "INFO")
        
        # 修复Token过期时间
        if "token" not in config["auth"]:
            config["auth"]["token"] = {}
        if "ttl" not in config["auth"]["token"] or config["auth"]["token"]["ttl"] > 2592000 or config["auth"]["token"]["ttl"] == 0:
            config["auth"]["token"]["ttl"] = 86400  # 24小时
            self.report("已设置Token过期时间为24小时", "INFO")
        
        # 修复速率限制
        if "rateLimit" not in config:
            config["rateLimit"] = {}
        if config["rateLimit"].get("enabled", True) is False:
            config["rateLimit"]["enabled"] = True
            self.report("已启用速率限制", "INFO")
        if "max" not in config["rateLimit"] or config["rateLimit"]["max"] > 1000:
            config["rateLimit"]["max"] = 100
            self.report("已设置速率限制为100次/窗口", "INFO")
        
        # 保存修复后的配置
        try:
            with open(self.config_path, 'w', encoding='utf-8') as f:
                json.dump(config, f, ensure_ascii=False, indent=2)
        except Exception as e:
            self.report(f"保存配置失败: {e}", "LOW")
