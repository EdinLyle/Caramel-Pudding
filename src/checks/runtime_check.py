import json
import re
import os
import platform
from pathlib import Path
from core.security_check import SecurityCheck
from core.platform_adapter import PlatformAdapter


class RuntimeChecker(SecurityCheck):
    """运行时实例检查"""

    def __init__(self):
        super().__init__("运行时检查", "MEDIUM")

    async def run(self):
        """执行运行时检查"""
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

        # 1. 认证模式检查
        await self._check_auth_mode(config)

        # 2. 命令执行限制
        await self._check_deny_commands(config)

        # 3. 配对设备检查
        await self._check_paired_devices(config)

        # 4. 会话超时配置
        await self._check_session_ttl(config)

        # 5. 资源限制
        await self._check_resource_limits(config)

        # 6. 日志配置
        await self._check_log_config(config)

        # 7. 自动更新设置
        await self._check_auto_update(config)

        # 8. 调试模式检查
        await self._check_debug_mode(config)

        self.status = "completed"

    async def _check_auth_mode(self, config):
        """检查认证模式"""
        auth_config = config.get("gateway", {}).get("auth", {})
        auth_mode = auth_config.get("mode", "none")

        if auth_mode == "none":
            self.report("认证模式设置为none，存在安全风险", "CRITICAL")
        elif auth_mode not in ["token", "oauth", "saml"]:
            self.report(f"未知的认证模式: {auth_mode}", "MEDIUM")

    async def _check_deny_commands(self, config):
        """检查命令执行限制"""
        runtime_config = config.get("runtime", {})
        deny_commands = runtime_config.get("denyCommands", [])

        critical_commands = ["rm", "sudo", "su", "chmod", "chown", "dd", "mkfs"]
        missing_critical = [cmd for cmd in critical_commands if cmd not in deny_commands]

        if missing_critical:
            self.report(f"缺少关键命令限制: {', '.join(missing_critical)}", "HIGH")

    async def _check_paired_devices(self, config):
        """检查配对设备"""
        runtime_config = config.get("runtime", {})
        paired_devices = runtime_config.get("pairedDevices", [])

        if paired_devices:
            # 检查是否有未授权的设备
            for device in paired_devices:
                if not device.get("authorized", True):
                    self.report(f"存在未授权的配对设备: {device.get('name', 'Unknown')}", "MEDIUM")

    async def _check_session_ttl(self, config):
        """检查会话超时配置"""
        auth_config = config.get("gateway", {}).get("auth", {})
        session_ttl = auth_config.get("sessionTTL", 3600)

        if session_ttl > 86400:  # 超过24小时
            self.report(f"会话超时设置过长: {session_ttl}秒", "MEDIUM")

    async def _check_resource_limits(self, config):
        """检查资源限制"""
        runtime_config = config.get("runtime", {})
        limits = runtime_config.get("limits", {})

        # 检查内存限制
        memory_limit = limits.get("memory", 0)
        if memory_limit == 0:
            self.report("未设置内存限制，可能导致资源耗尽", "MEDIUM")

        # 检查CPU限制
        cpu_limit = limits.get("cpu", 0)
        if cpu_limit == 0:
            self.report("未设置CPU限制，可能导致资源耗尽", "MEDIUM")

    async def _check_log_config(self, config):
        """检查日志配置"""
        log_config = config.get("logging", {})
        log_level = log_config.get("level", "info")

        if log_level == "debug":
            self.report("日志级别设置为debug，可能泄露敏感信息", "LOW")

        # 检查日志轮转
        if not log_config.get("rotation", False):
            self.report("未配置日志轮转，可能导致日志文件过大", "LOW")

    async def _check_auto_update(self, config):
        """检查自动更新设置"""
        runtime_config = config.get("runtime", {})
        auto_update = runtime_config.get("autoUpdate", False)

        if not auto_update:
            self.report("自动更新已关闭，可能存在安全漏洞", "MEDIUM")

    async def _check_debug_mode(self, config):
        """检查调试模式"""
        runtime_config = config.get("runtime", {})
        debug_mode = runtime_config.get("debug", False)

        if debug_mode:
            self.report("调试模式已开启，存在安全风险", "HIGH")

    async def fix(self):
        """修复运行时配置问题"""
        if not self.config_path or not self.config_path.exists():
            return
        
        try:
            with open(self.config_path, 'r', encoding='utf-8') as f:
                config = json.load(f)
        except Exception:
            return
        
        # 修复认证模式
        if "gateway" not in config:
            config["gateway"] = {}
        if "auth" not in config["gateway"]:
            config["gateway"]["auth"] = {}
        if config["gateway"]["auth"].get("mode", "none") == "none":
            config["gateway"]["auth"]["mode"] = "token"
            self.report("已设置认证模式为token", "INFO")
        
        # 修复命令执行限制
        if "runtime" not in config:
            config["runtime"] = {}
        if "denyCommands" not in config["runtime"]:
            config["runtime"]["denyCommands"] = ["rm", "sudo", "su", "chmod", "chown", "dd", "mkfs"]
            self.report("已添加关键命令限制", "INFO")
        else:
            # 添加缺失的关键命令限制
            critical_commands = ["rm", "sudo", "su", "chmod", "chown", "dd", "mkfs"]
            for cmd in critical_commands:
                if cmd not in config["runtime"]["denyCommands"]:
                    config["runtime"]["denyCommands"].append(cmd)
                    self.report(f"已添加命令限制: {cmd}", "INFO")
        
        # 修复会话超时
        if "auth" not in config["gateway"]:
            config["gateway"]["auth"] = {}
        if "sessionTTL" not in config["gateway"]["auth"] or config["gateway"]["auth"]["sessionTTL"] > 86400:
            config["gateway"]["auth"]["sessionTTL"] = 86400  # 24小时
            self.report("已设置会话超时为24小时", "INFO")
        
        # 修复资源限制
        if "limits" not in config["runtime"]:
            config["runtime"]["limits"] = {}
        if "memory" not in config["runtime"]["limits"] or config["runtime"]["limits"]["memory"] == 0:
            config["runtime"]["limits"]["memory"] = 1024  # 1GB
            self.report("已设置内存限制为1GB", "INFO")
        if "cpu" not in config["runtime"]["limits"] or config["runtime"]["limits"]["cpu"] == 0:
            config["runtime"]["limits"]["cpu"] = 1  # 1核心
            self.report("已设置CPU限制为1核心", "INFO")
        
        # 修复日志配置
        if "logging" not in config:
            config["logging"] = {}
        if config["logging"].get("level", "info") == "debug":
            config["logging"]["level"] = "info"
            self.report("已将日志级别设置为info", "INFO")
        if not config["logging"].get("rotation", False):
            config["logging"]["rotation"] = True
            self.report("已启用日志轮转", "INFO")
        
        # 修复自动更新
        if "autoUpdate" not in config["runtime"] or config["runtime"]["autoUpdate"] is False:
            config["runtime"]["autoUpdate"] = True
            self.report("已启用自动更新", "INFO")
        
        # 修复调试模式
        if "debug" in config["runtime"] and config["runtime"]["debug"] is True:
            config["runtime"]["debug"] = False
            self.report("已关闭调试模式", "INFO")
        
        # 保存修复后的配置
        try:
            with open(self.config_path, 'w', encoding='utf-8') as f:
                json.dump(config, f, ensure_ascii=False, indent=2)
        except Exception as e:
            self.report(f"保存配置失败: {e}", "LOW")
