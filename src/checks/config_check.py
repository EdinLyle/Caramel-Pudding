import sys
import json
import re
import stat
import os
from pathlib import Path
from core.security_check import SecurityCheck
from core.platform_adapter import PlatformAdapter


class ConfigChecker(SecurityCheck):
    """配置安全检测"""

    def __init__(self):
        super().__init__("配置安全检测", "CRITICAL")

    async def run(self):
        """执行配置安全检测"""
        self.status = "running"

        # 在run方法中获取最新路径
        openclaw_path = PlatformAdapter.get_openclaw_path()
        
        # 检查当前路径是否为.openclaw目录
        if openclaw_path.name == ".openclaw":
            # 如果是.openclaw目录，检查上层目录是否有openclaw.json
            self.config_path = openclaw_path.parent / "openclaw.json"
            if not self.config_path.exists():
                # 如果上层目录也没有，检查当前目录
                self.config_path = openclaw_path / "openclaw.json"
        else:
            # 否则直接在当前路径查找
            self.config_path = openclaw_path / "openclaw.json"

        if not self.config_path.exists():
            self.report("未找到openclaw.json配置文件", "INFO")
            return

        try:
            with open(self.config_path, 'r', encoding='utf-8') as f:
                config = json.load(f)
        except Exception as e:
            self.report(f"配置文件解析失败: {e}")
            return

        # 1. 硬编码API Key检测
        await self._check_api_keys(config)

        # 2. 危险配置标志位检测
        await self._check_dangerous_flags(config)

        # 3. 文件权限检测
        await self._check_file_permissions()

        # 4. SOUL.md提示注入检测
        await self._check_soul_md()

        # 5. MEMORY.md敏感信息检测
        await self._check_memory_md()

        self.status = "completed"

    async def _check_api_keys(self, config):
        """检测硬编码API Key"""
        config_str = json.dumps(config, ensure_ascii=False)
        patterns = [
            r'(sk-[a-zA-Z0-9]{48})',  # OpenAI格式
            r'(ak-[a-zA-Z0-9]{32})',   # 阿里云格式
            r'["\']?api[_-]?key["\']?\s*:\s*["\']([a-zA-Z0-9]{32,})["\']',
            r'["\']?secret[_-]?key["\']?\s*:\s*["\']([a-zA-Z0-9]{32,})["\']',
            r'["\']?access[_-]?token["\']?\s*:\s*["\']([a-zA-Z0-9]{32,})["\']',
            r'sk-ant-[a-zA-Z0-9\-]{20,}',  # Anthropic格式
            r'sk-proj-[a-zA-Z0-9\-]{20,}',  # OpenAI项目格式
            r'AIza[0-9A-Za-z\-_]{35}',  # Google API格式
            r'ghp_[a-zA-Z0-9]{36}',  # GitHub Personal Access Token
            r'ghs_[a-zA-Z0-9]{36}',  # GitHub App Token
            r'Bearer [a-zA-Z0-9\-_\.]{40,}',  # Bearer Token
            r'AKIA[0-9A-Z]{16}',  # AWS Access Key
        ]

        for pattern in patterns:
            matches = re.findall(pattern, config_str, re.IGNORECASE)
            for match in matches:
                if isinstance(match, tuple):
                    match = match[0]
                if len(match) > 12:
                    masked = match[:8] + "*" * (len(match) - 12) + match[-4:]
                    self.report(f"发现硬编码API Key/Token: {masked}", "CRITICAL")

    async def _check_dangerous_flags(self, config):
        """检测危险配置"""
        dangerous_configs = [
            ("sandbox", False, "沙箱已关闭", "CRITICAL"),
            ("auth.enabled", False, "网关认证已关闭", "CRITICAL"),
            ("envEncryption", False, "环境变量明文存储", "HIGH"),
            ("confirmDestructive", False, "危险操作无需确认", "HIGH"),
            ("debug", True, "调试模式已开启", "MEDIUM"),
            ("allowUnsignedSkills", True, "允许未签名技能包", "HIGH"),
            ("autoUpdate", False, "自动更新已关闭", "MEDIUM"),
            ("allowAll", True, "允许所有操作", "HIGH"),
            ("disableSafety", True, "安全检查已关闭", "HIGH"),
            ("skipVerification", True, "跳过验证", "HIGH"),
            ("bypassAuth", True, "绕过认证", "CRITICAL"),
            ("devMode", True, "开发模式已开启", "MEDIUM"),
            ("insecure", True, "不安全模式已开启", "HIGH"),
            ("allowUnsafe", True, "允许不安全操作", "HIGH"),
        ]

        for key, danger_value, desc, risk in dangerous_configs:
            current = self._get_nested_value(config, key)
            if current == danger_value:
                self.report(f"{desc}", risk)

    async def _check_file_permissions(self):
        """检查配置文件权限"""
        if sys.platform == "win32":
            # Windows ACL检查
            try:
                import win32security
                sd = win32security.GetFileSecurity(
                    str(self.config_path),
                    win32security.DACL_SECURITY_INFORMATION
                )
                dacl = sd.GetSecurityDescriptorDacl()
                # 简化检查：检查是否有Everyone权限
                for idx in range(dacl.GetAceCount()):
                    ace = dacl.GetAce(idx)
                    # 这里可以添加更详细的权限检查逻辑
                    pass
            except:
                pass  # Windows ACL检查需要更多权限
        else:
            # Linux权限检查
            try:
                mode = os.stat(self.config_path).st_mode
                oct_mode = oct(mode)[-3:]
                if mode & stat.S_IROTH:  # 其他用户可读
                    self.report(f"配置文件权限过于宽松: {oct_mode} (其他用户可读)", "HIGH")
                if mode & stat.S_IWOTH:  # 其他用户可写
                    self.report(f"配置文件权限过于宽松: {oct_mode} (其他用户可写)", "CRITICAL")
                if mode & stat.S_IWGRP:  # 同组用户可写
                    self.report(f"配置文件权限较为宽松: {oct_mode} (同组用户可写)", "MEDIUM")
            except Exception as e:
                self.report(f"文件权限检查失败: {e}", "LOW")

    async def _check_soul_md(self):
        """SOUL.md提示注入检测"""
        soul_path = self.config_path.parent / "SOUL.md"
        if not soul_path.exists():
            return

        try:
            content = soul_path.read_text(encoding='utf-8', errors='ignore')
            injection_patterns = [
                r'(?i)(ignore previous|override|bypass|forget|jailbreak)',
                r'(?i)(你现在是|忽略之前|系统提示词覆盖)',
                r'(?i)(new instruction|system prompt override)',
                r'(?i)(as an ai, you are no longer|you are now free)',
            ]

            for pattern in injection_patterns:
                if re.search(pattern, content):
                    self.report("SOUL.md存在提示注入风险", "HIGH")
                    break
        except Exception as e:
            self.report(f"SOUL.md检查失败: {e}", "LOW")

    async def _check_memory_md(self):
        """MEMORY.md敏感信息检测"""
        memory_path = self.config_path.parent / "MEMORY.md"
        if not memory_path.exists():
            return

        try:
            content = memory_path.read_text(encoding='utf-8', errors='ignore')

            # 检测敏感关键词
            sensitive_keywords = [
                'api key', 'api_key', 'apikey',
                'secret key', 'secret_key', 'secretkey',
                'access token', 'access_token', 'accesstoken',
                'password', 'passwd',
                'token', 'credential', 'credentials',
                '私钥', '密码', '令牌', '密钥'
            ]

            found_keywords = []
            for keyword in sensitive_keywords:
                if keyword in content.lower():
                    found_keywords.append(keyword)

            if found_keywords:
                self.report(f"MEMORY.md包含敏感关键词: {', '.join(set(found_keywords))}", "HIGH")

        except Exception as e:
            self.report(f"MEMORY.md检查失败: {e}", "LOW")

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
        """修复配置文件安全问题"""
        import os
        import stat

        # 1. 修复配置文件权限
        if self.config_path.exists():
            if os.name == 'posix':  # Linux/macOS
                try:
                    # 检查权限
                    mode = os.stat(self.config_path).st_mode
                    if mode & stat.S_IROTH or mode & stat.S_IWOTH or mode & stat.S_IRGRP or mode & stat.S_IWGRP:
                        # 设置为600权限
                        os.chmod(self.config_path, 0o600)
                        self.report("已修复配置文件权限为600", "INFO")
                except Exception as e:
                    self.report(f"修复配置文件权限失败: {e}", "LOW")

        # 2. 修复危险配置标志
        if self.config_path.exists():
            try:
                with open(self.config_path, 'r', encoding='utf-8') as f:
                    config = json.load(f)

                # 修复危险标志
                dangerous_flags = [
                    "allowAll", "disableSafety", "skipVerification", "bypassAuth",
                    "devMode", "insecure", "allowUnsafe"
                ]

                fixed = False
                for flag in dangerous_flags:
                    if config.get(flag) is True:
                        config[flag] = False
                        fixed = True

                # 修复认证模式
                auth_mode = config.get("gateway", {}).get("auth", {}).get("mode", "none")
                if auth_mode == "none":
                    if "gateway" not in config:
                        config["gateway"] = {}
                    if "auth" not in config["gateway"]:
                        config["gateway"]["auth"] = {}
                    config["gateway"]["auth"]["mode"] = "token"
                    fixed = True

                # 修复绑定地址
                bind = config.get("gateway", {}).get("bind", "")
                if bind == "0.0.0.0" or bind == "all" or not bind:
                    if "gateway" not in config:
                        config["gateway"] = {}
                    config["gateway"]["bind"] = "loopback"
                    fixed = True

                # 保存修复后的配置
                if fixed:
                    with open(self.config_path, 'w', encoding='utf-8') as f:
                        json.dump(config, f, ensure_ascii=False, indent=2)
                    self.report("已修复危险配置标志", "INFO")
            except Exception as e:
                self.report(f"修复配置文件失败: {e}", "LOW")
