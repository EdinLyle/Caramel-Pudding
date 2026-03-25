import os
import json
import hashlib
import re
import platform
from typing import Dict, List, Tuple

class SecureClawAudit:
    def __init__(self):
        self.checks = {
            "version": self.check_version,
            "gateway_bind": self.check_gateway_bind,
            "authentication": self.check_authentication,
            "file_permissions": self.check_file_permissions,
            "credential_exposure": self.check_credential_exposure,
            "sandbox_mode": self.check_sandbox_mode,
            "approval_mode": self.check_approval_mode,
            "browser_relay": self.check_browser_relay,
            "supply_chain": self.check_supply_chain,
            "memory_integrity": self.check_memory_integrity,
            "dm_policy": self.check_dm_policy,
            "privacy": self.check_privacy,
            "cost_limits": self.check_cost_limits,
            "kill_switch": self.check_kill_switch
        }
        
    def run_audit(self, openclaw_dir: str) -> Dict:
        """运行完整的安全审计"""
        results = {}
        score = 0
        total_checks = len(self.checks)
        
        for check_name, check_func in self.checks.items():
            try:
                status, message, severity = check_func(openclaw_dir)
                results[check_name] = {
                    "status": status,
                    "message": message,
                    "severity": severity
                }
                if status == "PASS":
                    score += 1
            except Exception as e:
                results[check_name] = {
                    "status": "ERROR",
                    "message": f"检查失败: {str(e)}",
                    "severity": "ERROR"
                }
        
        final_score = int((score / total_checks) * 100)
        return {
            "results": results,
            "score": final_score,
            "total_checks": total_checks,
            "passed_checks": score
        }
    
    def check_version(self, openclaw_dir: str) -> Tuple[str, str, str]:
        """检查OpenClaw版本是否存在已知漏洞"""
        config_file = os.path.join(openclaw_dir, "openclaw.json")
        if not os.path.exists(config_file):
            return "FAIL", "未找到openclaw.json配置文件", "HIGH"
        
        try:
            with open(config_file, "r", encoding="utf-8") as f:
                config = json.load(f)
            
            version = config.get("version", "")
            if not version:
                return "FAIL", "未找到版本信息", "MEDIUM"
            
            # 检查CVE-2026-25253
            # 假设漏洞影响版本 < 2.1.0
            version_parts = version.split(".")
            if len(version_parts) >= 2:
                major = int(version_parts[0])
                minor = int(version_parts[1])
                if major < 2 or (major == 2 and minor < 1):
                    return "FAIL", f"版本 {version} 可能存在CVE-2026-25253漏洞", "CRITICAL"
            
            return "PASS", f"版本 {version} 未检测到已知漏洞", "INFO"
        except Exception as e:
            return "ERROR", f"解析配置文件失败: {str(e)}", "ERROR"
    
    def check_gateway_bind(self, openclaw_dir: str) -> Tuple[str, str, str]:
        """检查网关绑定地址"""
        config_file = os.path.join(openclaw_dir, "openclaw.json")
        if not os.path.exists(config_file):
            return "FAIL", "未找到openclaw.json配置文件", "HIGH"
        
        try:
            with open(config_file, "r", encoding="utf-8") as f:
                config = json.load(f)
            
            gateway = config.get("gateway", {})
            bind_address = gateway.get("bind", "127.0.0.1")
            
            if bind_address == "0.0.0.0":
                return "FAIL", "网关绑定到0.0.0.0，暴露到网络", "CRITICAL"
            elif bind_address in ["127.0.0.1", "localhost"]:
                return "PASS", f"网关绑定到 {bind_address}，仅本地访问", "INFO"
            else:
                return "WARN", f"网关绑定到 {bind_address}，请确认是否安全", "MEDIUM"
        except Exception as e:
            return "ERROR", f"解析配置文件失败: {str(e)}", "ERROR"
    
    def check_authentication(self, openclaw_dir: str) -> Tuple[str, str, str]:
        """检查认证设置"""
        config_file = os.path.join(openclaw_dir, "openclaw.json")
        if not os.path.exists(config_file):
            return "FAIL", "未找到openclaw.json配置文件", "HIGH"
        
        try:
            with open(config_file, "r", encoding="utf-8") as f:
                config = json.load(f)
            
            gateway = config.get("gateway", {})
            auth_token = gateway.get("authToken", "")
            
            if auth_token:
                return "PASS", "网关已配置认证令牌", "INFO"
            else:
                return "FAIL", "网关未配置认证令牌", "HIGH"
        except Exception as e:
            return "ERROR", f"解析配置文件失败: {str(e)}", "ERROR"
    
    def check_file_permissions(self, openclaw_dir: str) -> Tuple[str, str, str]:
        """检查文件权限"""
        issues = []
        
        # 检查.env文件
        env_file = os.path.join(openclaw_dir, ".env")
        if os.path.exists(env_file):
            if platform.system() != "Windows":
                perm = oct(os.stat(env_file).st_mode)[-3:]
                if perm != "600":
                    issues.append(f".env文件权限为 {perm}，建议设置为 600")
        
        # 检查配置文件
        config_file = os.path.join(openclaw_dir, "openclaw.json")
        if os.path.exists(config_file):
            if platform.system() != "Windows":
                perm = oct(os.stat(config_file).st_mode)[-3:]
                if perm != "600":
                    issues.append(f"配置文件权限为 {perm}，建议设置为 600")
        
        # 检查目录权限
        if platform.system() != "Windows":
            perm = oct(os.stat(openclaw_dir).st_mode)[-3:]
            if perm != "700":
                issues.append(f"目录权限为 {perm}，建议设置为 700")
        
        if issues:
            return "FAIL", " ".join(issues), "HIGH"
        else:
            return "PASS", "文件权限设置正确", "INFO"
    
    def check_credential_exposure(self, openclaw_dir: str) -> Tuple[str, str, str]:
        """检查凭证暴露"""
        credential_patterns = [
            r"sk-ant-[a-zA-Z0-9_-]{32}",  # Anthropic API key
            r"sk-proj-[a-zA-Z0-9_-]{32}",  # Anthropic project key
            r"xoxb-[0-9]{10,}-[0-9]{10,}-[a-zA-Z0-9]{24}",  # Slack bot token
            r"ghp_[a-zA-Z0-9]{36}",  # GitHub personal access token
            r"AKIA[0-9A-Z]{16}"  # AWS access key
        ]
        
        exposed_credentials = []
        
        # 搜索除了.env之外的文件
        for root, dirs, files in os.walk(openclaw_dir):
            # 跳过某些目录
            dirs[:] = [d for d in dirs if d not in [".git", "node_modules", "venv"]]
            
            for file in files:
                if file == ".env":
                    continue
                
                file_path = os.path.join(root, file)
                try:
                    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read()
                    
                    for pattern in credential_patterns:
                        matches = re.findall(pattern, content)
                        if matches:
                            exposed_credentials.append(f"在 {file_path} 中发现可能的凭证")
                            break
                except:
                    pass
        
        if exposed_credentials:
            return "FAIL", " ".join(exposed_credentials), "CRITICAL"
        else:
            return "PASS", "未发现凭证暴露", "INFO"
    
    def check_sandbox_mode(self, openclaw_dir: str) -> Tuple[str, str, str]:
        """检查沙箱模式"""
        config_file = os.path.join(openclaw_dir, "openclaw.json")
        if not os.path.exists(config_file):
            return "FAIL", "未找到openclaw.json配置文件", "HIGH"
        
        try:
            with open(config_file, "r", encoding="utf-8") as f:
                config = json.load(f)
            
            security = config.get("security", {})
            sandbox = security.get("sandbox", False)
            
            if sandbox:
                return "PASS", "沙箱模式已启用", "INFO"
            else:
                return "FAIL", "沙箱模式未启用", "HIGH"
        except Exception as e:
            return "ERROR", f"解析配置文件失败: {str(e)}", "ERROR"
    
    def check_approval_mode(self, openclaw_dir: str) -> Tuple[str, str, str]:
        """检查审批模式"""
        config_file = os.path.join(openclaw_dir, "openclaw.json")
        if not os.path.exists(config_file):
            return "FAIL", "未找到openclaw.json配置文件", "HIGH"
        
        try:
            with open(config_file, "r", encoding="utf-8") as f:
                config = json.load(f)
            
            security = config.get("security", {})
            approval = security.get("approvalRequired", False)
            
            if approval:
                return "PASS", "审批模式已启用", "INFO"
            else:
                return "FAIL", "审批模式未启用", "MEDIUM"
        except Exception as e:
            return "ERROR", f"解析配置文件失败: {str(e)}", "ERROR"
    
    def check_browser_relay(self, openclaw_dir: str) -> Tuple[str, str, str]:
        """检查浏览器中继"""
        # 简单检查端口18790是否被占用
        import socket
        
        def is_port_open(port):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            try:
                result = sock.connect_ex(("127.0.0.1", port))
                return result == 0
            finally:
                sock.close()
        
        if is_port_open(18790):
            return "WARN", "浏览器中继端口18790已打开，存在会话盗窃风险", "MEDIUM"
        else:
            return "PASS", "浏览器中继端口18790未打开", "INFO"
    
    def check_supply_chain(self, openclaw_dir: str) -> Tuple[str, str, str]:
        """检查供应链安全"""
        skills_dir = os.path.join(openclaw_dir, "skills")
        if not os.path.exists(skills_dir):
            return "PASS", "未找到技能目录", "INFO"
        
        dangerous_patterns = [
            r"curl.*\\|.*sh",
            r"wget.*\\|.*bash",
            r"eval\(",
            r"exec\(",
            r"webhook\.site"
        ]
        
        suspicious_skills = []
        
        for root, dirs, files in os.walk(skills_dir):
            for file in files:
                if file.endswith(".md") or file.endswith(".sh") or file.endswith(".py"):
                    file_path = os.path.join(root, file)
                    try:
                        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                            content = f.read()
                        
                        for pattern in dangerous_patterns:
                            if re.search(pattern, content):
                                skill_name = os.path.basename(root)
                                suspicious_skills.append(f"技能 {skill_name} 中发现可疑模式")
                                break
                    except:
                        pass
        
        if suspicious_skills:
            return "FAIL", " ".join(suspicious_skills), "HIGH"
        else:
            return "PASS", "未发现供应链安全问题", "INFO"
    
    def check_memory_integrity(self, openclaw_dir: str) -> Tuple[str, str, str]:
        """检查内存完整性"""
        cognitive_files = [
            "SOUL.md",
            "IDENTITY.md",
            "TOOLS.md",
            "AGENTS.md",
            "SECURITY.md",
            "MEMORY.md"
        ]
        
        missing_files = []
        for file in cognitive_files:
            file_path = os.path.join(openclaw_dir, file)
            if not os.path.exists(file_path):
                missing_files.append(file)
        
        if missing_files:
            return "FAIL", f"缺少认知文件: {', '.join(missing_files)}", "MEDIUM"
        else:
            return "PASS", "所有认知文件存在", "INFO"
    
    def check_dm_policy(self, openclaw_dir: str) -> Tuple[str, str, str]:
        """检查DM策略"""
        config_file = os.path.join(openclaw_dir, "openclaw.json")
        if not os.path.exists(config_file):
            return "FAIL", "未找到openclaw.json配置文件", "HIGH"
        
        try:
            with open(config_file, "r", encoding="utf-8") as f:
                config = json.load(f)
            
            dm_policy = config.get("dmPolicy", "")
            if dm_policy == "restricted":
                return "PASS", "DM策略设置为restricted", "INFO"
            else:
                return "WARN", f"DM策略设置为 {dm_policy}，建议设置为restricted", "MEDIUM"
        except Exception as e:
            return "ERROR", f"解析配置文件失败: {str(e)}", "ERROR"
    
    def check_privacy(self, openclaw_dir: str) -> Tuple[str, str, str]:
        """检查隐私设置"""
        soul_file = os.path.join(openclaw_dir, "SOUL.md")
        if not os.path.exists(soul_file):
            return "FAIL", "未找到SOUL.md文件", "MEDIUM"
        
        try:
            with open(soul_file, "r", encoding="utf-8") as f:
                content = f.read()
            
            if "SecureClaw Privacy Directives" in content:
                return "PASS", "隐私指令已添加到SOUL.md", "INFO"
            else:
                return "FAIL", "隐私指令未添加到SOUL.md", "MEDIUM"
        except Exception as e:
            return "ERROR", f"读取SOUL.md失败: {str(e)}", "ERROR"
    
    def check_cost_limits(self, openclaw_dir: str) -> Tuple[str, str, str]:
        """检查成本限制"""
        config_file = os.path.join(openclaw_dir, "openclaw.json")
        if not os.path.exists(config_file):
            return "FAIL", "未找到openclaw.json配置文件", "HIGH"
        
        try:
            with open(config_file, "r", encoding="utf-8") as f:
                config = json.load(f)
            
            cost = config.get("cost", {})
            hourly_limit = cost.get("hourlyLimitUsd", 0)
            
            if hourly_limit > 0:
                return "PASS", f"已设置每小时成本限制: ${hourly_limit}", "INFO"
            else:
                return "WARN", "未设置成本限制", "MEDIUM"
        except Exception as e:
            return "ERROR", f"解析配置文件失败: {str(e)}", "ERROR"
    
    def check_kill_switch(self, openclaw_dir: str) -> Tuple[str, str, str]:
        """检查终止开关"""
        kill_switch_file = os.path.join(openclaw_dir, ".secureclaw", "killswitch")
        if os.path.exists(kill_switch_file):
            return "WARN", "终止开关已激活", "HIGH"
        else:
            return "PASS", "终止开关未激活", "INFO"
