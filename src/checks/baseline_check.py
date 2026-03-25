import json
import os
from pathlib import Path
from core.security_check import SecurityCheck
from core.platform_adapter import PlatformAdapter


class BaselineChecker(SecurityCheck):
    """OpenClaw安全基线检查模块"""

    def __init__(self):
        super().__init__("安全基线检查", "HIGH")

    async def run(self):
        """执行安全基线检查"""
        self.status = "running"

        # 获取OpenClaw路径
        openclaw_path = PlatformAdapter.get_openclaw_path()
        
        # 检查配置文件安全基线
        await self._check_config_baseline()

        # 检查技能包安全基线
        await self._check_skills_baseline()

        # 检查网络安全基线
        await self._check_network_baseline()

        # 检查认证安全基线
        await self._check_auth_baseline()

        # 检查运行时安全基线
        await self._check_runtime_baseline()

        self.status = "completed"

    async def _check_config_baseline(self):
        """检查配置文件安全基线"""
        config_path = PlatformAdapter.get_openclaw_path() / "openclaw.json"
        if config_path.exists():
            try:
                with open(config_path, 'r', encoding='utf-8') as f:
                    config = json.load(f)
                
                # 检查配置文件权限
                if os.name == 'posix':
                    import stat
                    mode = os.stat(config_path).st_mode
                    if oct(mode)[-3:] != '600':
                        self.report("配置文件权限过于宽松，建议设置为600", "MEDIUM")
                
                # 检查危险配置标志
                if config.get("allowAll", False):
                    self.report("启用了allowAll配置，存在安全风险", "HIGH")
                
                if config.get("disableSafety", False):
                    self.report("禁用了安全检查，存在安全风险", "CRITICAL")
                
                # 检查认证设置
                auth_mode = config.get("gateway", {}).get("auth", {}).get("mode", "none")
                if auth_mode != "token":
                    self.report("认证模式未设置为token，存在安全风险", "HIGH")
                
                # 检查绑定地址
                bind = config.get("gateway", {}).get("bind", "")
                if bind == "0.0.0.0" or bind == "all":
                    self.report("绑定地址设置为全网暴露，存在安全风险", "HIGH")
            except Exception as e:
                self.report(f"配置文件安全基线检查失败: {e}", "LOW")
        else:
            self.report("未找到openclaw.json文件，无法检查配置文件安全基线", "LOW")

    async def _check_skills_baseline(self):
        """检查技能包安全基线"""
        skills_path = PlatformAdapter.get_openclaw_path() / "skills"
        if skills_path.exists():
            try:
                # 检查技能包目录结构
                skill_count = 0
                for skill_dir in skills_path.iterdir():
                    if skill_dir.is_dir():
                        skill_count += 1
                        # 检查技能包是否有package.json
                        package_file = skill_dir / "package.json"
                        if not package_file.exists():
                            self.report(f"技能包 {skill_dir.name} 缺少package.json文件", "MEDIUM")
                        
                        # 检查技能包权限
                        if os.name == 'posix':
                            import stat
                            for root, dirs, files in os.walk(skill_dir):
                                for file in files:
                                    file_path = os.path.join(root, file)
                                    mode = os.stat(file_path).st_mode
                                    if oct(mode)[-3:] == '777':
                                        self.report(f"技能包 {skill_dir.name} 中文件 {file} 权限过于宽松", "MEDIUM")
                
                if skill_count == 0:
                    self.report("未找到技能包，建议安装官方认证的技能包", "LOW")
            except Exception as e:
                self.report(f"技能包安全基线检查失败: {e}", "LOW")
        else:
            self.report("未找到skills目录，无法检查技能包安全基线", "LOW")

    async def _check_network_baseline(self):
        """检查网络安全基线"""
        config_path = PlatformAdapter.get_openclaw_path() / "openclaw.json"
        if config_path.exists():
            try:
                with open(config_path, 'r', encoding='utf-8') as f:
                    config = json.load(f)
                
                # 检查CORS配置
                cors = config.get("gateway", {}).get("cors", {})
                if cors.get("enabled", False):
                    origins = cors.get("origins", [])
                    if "*" in origins:
                        self.report("CORS配置使用通配符，存在安全风险", "MEDIUM")
                
                # 检查速率限制
                rate_limit = config.get("gateway", {}).get("rateLimit", {})
                if not rate_limit.get("enabled", False):
                    self.report("未启用速率限制，可能导致暴力破解攻击", "MEDIUM")
                
                # 检查端口配置
                port = config.get("gateway", {}).get("port", 8080)
                if port in [80, 443]:
                    self.report(f"使用标准端口 {port}，建议使用非标准端口以减少暴露面", "LOW")
            except Exception as e:
                self.report(f"网络安全基线检查失败: {e}", "LOW")
        else:
            self.report("未找到openclaw.json文件，无法检查网络安全基线", "LOW")

    async def _check_auth_baseline(self):
        """检查认证安全基线"""
        config_path = PlatformAdapter.get_openclaw_path() / "openclaw.json"
        if config_path.exists():
            try:
                with open(config_path, 'r', encoding='utf-8') as f:
                    config = json.load(f)
                
                # 检查认证启用状态
                auth = config.get("gateway", {}).get("auth", {})
                if not auth.get("enabled", True):
                    self.report("认证功能未启用，存在安全风险", "CRITICAL")
                
                # 检查认证模式
                if auth.get("mode", "none") != "token":
                    self.report("认证模式不是token，存在安全风险", "HIGH")
                
                # 检查Token配置
                token_config = auth.get("token", {})
                if not token_config.get("secret", ""):
                    self.report("未设置Token密钥，存在安全风险", "HIGH")
                
                # 检查Token过期时间
                expire_hours = token_config.get("expireHours", 24)
                if expire_hours > 72:
                    self.report(f"Token过期时间过长 ({expire_hours}小时)，建议设置为24小时以内", "MEDIUM")
            except Exception as e:
                self.report(f"认证安全基线检查失败: {e}", "LOW")
        else:
            self.report("未找到openclaw.json文件，无法检查认证安全基线", "LOW")

    async def _check_runtime_baseline(self):
        """检查运行时安全基线"""
        config_path = PlatformAdapter.get_openclaw_path() / "openclaw.json"
        if config_path.exists():
            try:
                with open(config_path, 'r', encoding='utf-8') as f:
                    config = json.load(f)
                
                # 检查命令限制
                deny_commands = config.get("denyCommands", [])
                dangerous_commands = ["rm", "sudo", "su", "bash", "sh", "powershell", "cmd"]
                if not any(cmd in deny_commands for cmd in dangerous_commands):
                    self.report("未限制危险命令，存在安全风险", "HIGH")
                
                # 检查会话超时
                session_timeout = config.get("sessionTimeout", 3600)
                if session_timeout > 7200:
                    self.report(f"会话超时时间过长 ({session_timeout}秒)，建议设置为3600秒以内", "MEDIUM")
                
                # 检查资源限制
                resources = config.get("resources", {})
                if not resources.get("memoryLimit", 0) or resources.get("memoryLimit", 0) > 4096:
                    self.report("未设置内存限制或限制过高，可能导致资源耗尽", "MEDIUM")
                
                # 检查日志配置
                logging = config.get("logging", {})
                log_level = logging.get("level", "info")
                if log_level == "debug":
                    self.report("日志级别设置为debug，可能泄露敏感信息", "LOW")
                
                # 检查自动更新
                auto_update = config.get("autoUpdate", False)
                if not auto_update:
                    self.report("未启用自动更新，可能错过安全补丁", "LOW")
            except Exception as e:
                self.report(f"运行时安全基线检查失败: {e}", "LOW")
        else:
            self.report("未找到openclaw.json文件，无法检查运行时安全基线", "LOW")

    async def fix(self):
        """修复安全基线问题"""
        config_path = PlatformAdapter.get_openclaw_path() / "openclaw.json"
        if config_path.exists():
            try:
                with open(config_path, 'r', encoding='utf-8') as f:
                    config = json.load(f)

                fixed = False

                # 修复配置文件权限
                if os.name == 'posix':
                    import stat
                    os.chmod(config_path, 0o600)
                    fixed = True

                # 修复危险配置标志
                if config.get("allowAll", False):
                    config["allowAll"] = False
                    fixed = True
                
                if config.get("disableSafety", False):
                    config["disableSafety"] = False
                    fixed = True

                # 修复认证设置
                if "gateway" not in config:
                    config["gateway"] = {}
                if "auth" not in config["gateway"]:
                    config["gateway"]["auth"] = {}
                if config["gateway"]["auth"].get("mode", "none") != "token":
                    config["gateway"]["auth"]["mode"] = "token"
                    fixed = True

                # 修复绑定地址
                if config["gateway"].get("bind", "") == "0.0.0.0" or config["gateway"].get("bind", "") == "all":
                    config["gateway"]["bind"] = "loopback"
                    fixed = True

                # 修复命令限制
                if "denyCommands" not in config:
                    config["denyCommands"] = ["rm", "sudo", "su", "bash", "sh", "powershell", "cmd"]
                    fixed = True

                # 保存修复后的配置
                if fixed:
                    with open(config_path, 'w', encoding='utf-8') as f:
                        json.dump(config, f, ensure_ascii=False, indent=2)
                    self.report("已修复部分安全基线问题", "INFO")
            except Exception as e:
                self.report(f"修复安全基线问题失败: {e}", "LOW")