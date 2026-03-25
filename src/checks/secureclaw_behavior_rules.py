import os
import json
from typing import Dict, List, Tuple

class SecureClawBehaviorRules:
    def __init__(self):
        self.rules = {
            "unauthorized_access": self.check_unauthorized_access,
            "privilege_escalation": self.check_privilege_escalation,
            "data_exfiltration": self.check_data_exfiltration,
            "malicious_code": self.check_malicious_code,
            "resource_abuse": self.check_resource_abuse,
            "network_scanning": self.check_network_scanning,
            "command_injection": self.check_command_injection,
            "file_manipulation": self.check_file_manipulation,
            "process_creation": self.check_process_creation,
            "registry_modification": self.check_registry_modification,
            "service_management": self.check_service_management,
            "persistence_attempts": self.check_persistence_attempts,
            "evasion_techniques": self.check_evasion_techniques,
            "suspicious_connections": self.check_suspicious_connections,
            "unusual_behavior": self.check_unusual_behavior
        }
    
    def run_rules(self, openclaw_dir: str) -> Dict:
        """运行行为规则检查"""
        results = {}
        score = 0
        total_rules = len(self.rules)
        
        for rule_name, rule_func in self.rules.items():
            try:
                status, message, severity = rule_func(openclaw_dir)
                results[rule_name] = {
                    "status": status,
                    "message": message,
                    "severity": severity
                }
                if status == "PASS":
                    score += 1
            except Exception as e:
                results[rule_name] = {
                    "status": "ERROR",
                    "message": f"检查失败: {str(e)}",
                    "severity": "ERROR"
                }
        
        final_score = int((score / total_rules) * 100)
        return {
            "results": results,
            "score": final_score,
            "total_rules": total_rules,
            "passed_rules": score
        }
    
    def check_unauthorized_access(self, openclaw_dir: str) -> Tuple[str, str, str]:
        """检查未授权访问"""
        # 检查认证设置
        config_file = os.path.join(openclaw_dir, "openclaw.json")
        if not os.path.exists(config_file):
            return "FAIL", "未找到openclaw.json配置文件", "HIGH"
        
        try:
            with open(config_file, "r", encoding="utf-8") as f:
                config = json.load(f)
            
            gateway = config.get("gateway", {})
            auth_token = gateway.get("authToken", "")
            
            if auth_token:
                return "PASS", "已配置认证令牌，防止未授权访问", "INFO"
            else:
                return "FAIL", "未配置认证令牌，存在未授权访问风险", "CRITICAL"
        except Exception as e:
            return "ERROR", f"解析配置文件失败: {str(e)}", "ERROR"
    
    def check_privilege_escalation(self, openclaw_dir: str) -> Tuple[str, str, str]:
        """检查权限提升"""
        # 检查权限配置
        config_file = os.path.join(openclaw_dir, "openclaw.json")
        if not os.path.exists(config_file):
            return "FAIL", "未找到openclaw.json配置文件", "HIGH"
        
        try:
            with open(config_file, "r", encoding="utf-8") as f:
                config = json.load(f)
            
            security = config.get("security", {})
            allow_all = security.get("allowAll", False)
            
            if not allow_all:
                return "PASS", "未启用allowAll权限，防止权限提升", "INFO"
            else:
                return "FAIL", "启用了allowAll权限，存在权限提升风险", "CRITICAL"
        except Exception as e:
            return "ERROR", f"解析配置文件失败: {str(e)}", "ERROR"
    
    def check_data_exfiltration(self, openclaw_dir: str) -> Tuple[str, str, str]:
        """检查数据泄露"""
        # 检查数据泄露防护设置
        config_file = os.path.join(openclaw_dir, "openclaw.json")
        if not os.path.exists(config_file):
            return "FAIL", "未找到openclaw.json配置文件", "HIGH"
        
        try:
            with open(config_file, "r", encoding="utf-8") as f:
                config = json.load(f)
            
            security = config.get("security", {})
            sandbox = security.get("sandbox", False)
            
            if sandbox:
                return "PASS", "已启用沙箱，防止数据泄露", "INFO"
            else:
                return "FAIL", "未启用沙箱，存在数据泄露风险", "HIGH"
        except Exception as e:
            return "ERROR", f"解析配置文件失败: {str(e)}", "ERROR"
    
    def check_malicious_code(self, openclaw_dir: str) -> Tuple[str, str, str]:
        """检查恶意代码"""
        # 检查技能包中的恶意代码
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
        
        import re
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
                                suspicious_skills.append(f"技能 {skill_name} 中发现可疑代码")
                                break
                    except:
                        pass
        
        if suspicious_skills:
            return "FAIL", " ".join(suspicious_skills), "HIGH"
        else:
            return "PASS", "未发现恶意代码", "INFO"
    
    def check_resource_abuse(self, openclaw_dir: str) -> Tuple[str, str, str]:
        """检查资源滥用"""
        # 检查资源限制设置
        config_file = os.path.join(openclaw_dir, "openclaw.json")
        if not os.path.exists(config_file):
            return "FAIL", "未找到openclaw.json配置文件", "HIGH"
        
        try:
            with open(config_file, "r", encoding="utf-8") as f:
                config = json.load(f)
            
            resources = config.get("resources", {})
            memory_limit = resources.get("memoryLimitMb", 0)
            cpu_limit = resources.get("cpuLimitPercent", 0)
            
            if memory_limit > 0 or cpu_limit > 0:
                return "PASS", "已设置资源限制，防止资源滥用", "INFO"
            else:
                return "WARN", "未设置资源限制，可能存在资源滥用风险", "MEDIUM"
        except Exception as e:
            return "ERROR", f"解析配置文件失败: {str(e)}", "ERROR"
    
    def check_network_scanning(self, openclaw_dir: str) -> Tuple[str, str, str]:
        """检查网络扫描"""
        # 检查网络访问控制
        config_file = os.path.join(openclaw_dir, "openclaw.json")
        if not os.path.exists(config_file):
            return "FAIL", "未找到openclaw.json配置文件", "HIGH"
        
        try:
            with open(config_file, "r", encoding="utf-8") as f:
                config = json.load(f)
            
            gateway = config.get("gateway", {})
            bind_address = gateway.get("bind", "127.0.0.1")
            
            if bind_address in ["127.0.0.1", "localhost"]:
                return "PASS", "网关绑定到本地，防止网络扫描", "INFO"
            else:
                return "WARN", "网关绑定到非本地地址，可能存在网络扫描风险", "MEDIUM"
        except Exception as e:
            return "ERROR", f"解析配置文件失败: {str(e)}", "ERROR"
    
    def check_command_injection(self, openclaw_dir: str) -> Tuple[str, str, str]:
        """检查命令注入"""
        # 检查命令执行设置
        config_file = os.path.join(openclaw_dir, "openclaw.json")
        if not os.path.exists(config_file):
            return "FAIL", "未找到openclaw.json配置文件", "HIGH"
        
        try:
            with open(config_file, "r", encoding="utf-8") as f:
                config = json.load(f)
            
            security = config.get("security", {})
            disable_safety = security.get("disableSafety", False)
            
            if not disable_safety:
                return "PASS", "安全检查已启用，防止命令注入", "INFO"
            else:
                return "FAIL", "安全检查已禁用，存在命令注入风险", "CRITICAL"
        except Exception as e:
            return "ERROR", f"解析配置文件失败: {str(e)}", "ERROR"
    
    def check_file_manipulation(self, openclaw_dir: str) -> Tuple[str, str, str]:
        """检查文件操作"""
        # 检查文件操作权限
        config_file = os.path.join(openclaw_dir, "openclaw.json")
        if not os.path.exists(config_file):
            return "FAIL", "未找到openclaw.json配置文件", "HIGH"
        
        try:
            with open(config_file, "r", encoding="utf-8") as f:
                config = json.load(f)
            
            security = config.get("security", {})
            allow_unsafe = security.get("allowUnsafe", False)
            
            if not allow_unsafe:
                return "PASS", "已禁用不安全操作，防止文件操作滥用", "INFO"
            else:
                return "FAIL", "已启用不安全操作，存在文件操作风险", "HIGH"
        except Exception as e:
            return "ERROR", f"解析配置文件失败: {str(e)}", "ERROR"
    
    def check_process_creation(self, openclaw_dir: str) -> Tuple[str, str, str]:
        """检查进程创建"""
        # 检查进程创建限制
        config_file = os.path.join(openclaw_dir, "openclaw.json")
        if not os.path.exists(config_file):
            return "FAIL", "未找到openclaw.json配置文件", "HIGH"
        
        try:
            with open(config_file, "r", encoding="utf-8") as f:
                config = json.load(f)
            
            security = config.get("security", {})
            sandbox = security.get("sandbox", False)
            
            if sandbox:
                return "PASS", "已启用沙箱，限制进程创建", "INFO"
            else:
                return "FAIL", "未启用沙箱，存在进程创建风险", "HIGH"
        except Exception as e:
            return "ERROR", f"解析配置文件失败: {str(e)}", "ERROR"
    
    def check_registry_modification(self, openclaw_dir: str) -> Tuple[str, str, str]:
        """检查注册表修改"""
        # 检查注册表访问限制
        config_file = os.path.join(openclaw_dir, "openclaw.json")
        if not os.path.exists(config_file):
            return "FAIL", "未找到openclaw.json配置文件", "HIGH"
        
        try:
            with open(config_file, "r", encoding="utf-8") as f:
                config = json.load(f)
            
            security = config.get("security", {})
            sandbox = security.get("sandbox", False)
            
            if sandbox:
                return "PASS", "已启用沙箱，限制注册表修改", "INFO"
            else:
                return "FAIL", "未启用沙箱，存在注册表修改风险", "HIGH"
        except Exception as e:
            return "ERROR", f"解析配置文件失败: {str(e)}", "ERROR"
    
    def check_service_management(self, openclaw_dir: str) -> Tuple[str, str, str]:
        """检查服务管理"""
        # 检查服务管理权限
        config_file = os.path.join(openclaw_dir, "openclaw.json")
        if not os.path.exists(config_file):
            return "FAIL", "未找到openclaw.json配置文件", "HIGH"
        
        try:
            with open(config_file, "r", encoding="utf-8") as f:
                config = json.load(f)
            
            security = config.get("security", {})
            allow_all = security.get("allowAll", False)
            
            if not allow_all:
                return "PASS", "未启用allowAll权限，限制服务管理", "INFO"
            else:
                return "FAIL", "启用了allowAll权限，存在服务管理风险", "HIGH"
        except Exception as e:
            return "ERROR", f"解析配置文件失败: {str(e)}", "ERROR"
    
    def check_persistence_attempts(self, openclaw_dir: str) -> Tuple[str, str, str]:
        """检查持久化尝试"""
        # 检查持久化设置
        config_file = os.path.join(openclaw_dir, "openclaw.json")
        if not os.path.exists(config_file):
            return "FAIL", "未找到openclaw.json配置文件", "HIGH"
        
        try:
            with open(config_file, "r", encoding="utf-8") as f:
                config = json.load(f)
            
            security = config.get("security", {})
            sandbox = security.get("sandbox", False)
            
            if sandbox:
                return "PASS", "已启用沙箱，防止持久化", "INFO"
            else:
                return "FAIL", "未启用沙箱，存在持久化风险", "HIGH"
        except Exception as e:
            return "ERROR", f"解析配置文件失败: {str(e)}", "ERROR"
    
    def check_evasion_techniques(self, openclaw_dir: str) -> Tuple[str, str, str]:
        """检查逃避技术"""
        # 检查逃避技术防护
        config_file = os.path.join(openclaw_dir, "openclaw.json")
        if not os.path.exists(config_file):
            return "FAIL", "未找到openclaw.json配置文件", "HIGH"
        
        try:
            with open(config_file, "r", encoding="utf-8") as f:
                config = json.load(f)
            
            security = config.get("security", {})
            disable_safety = security.get("disableSafety", False)
            
            if not disable_safety:
                return "PASS", "安全检查已启用，防止逃避技术", "INFO"
            else:
                return "FAIL", "安全检查已禁用，存在逃避技术风险", "HIGH"
        except Exception as e:
            return "ERROR", f"解析配置文件失败: {str(e)}", "ERROR"
    
    def check_suspicious_connections(self, openclaw_dir: str) -> Tuple[str, str, str]:
        """检查可疑连接"""
        # 检查网络连接设置
        config_file = os.path.join(openclaw_dir, "openclaw.json")
        if not os.path.exists(config_file):
            return "FAIL", "未找到openclaw.json配置文件", "HIGH"
        
        try:
            with open(config_file, "r", encoding="utf-8") as f:
                config = json.load(f)
            
            gateway = config.get("gateway", {})
            bind_address = gateway.get("bind", "127.0.0.1")
            
            if bind_address in ["127.0.0.1", "localhost"]:
                return "PASS", "网关绑定到本地，防止可疑连接", "INFO"
            else:
                return "WARN", "网关绑定到非本地地址，可能存在可疑连接风险", "MEDIUM"
        except Exception as e:
            return "ERROR", f"解析配置文件失败: {str(e)}", "ERROR"
    
    def check_unusual_behavior(self, openclaw_dir: str) -> Tuple[str, str, str]:
        """检查异常行为"""
        # 检查异常行为检测
        config_file = os.path.join(openclaw_dir, "openclaw.json")
        if not os.path.exists(config_file):
            return "FAIL", "未找到openclaw.json配置文件", "HIGH"
        
        try:
            with open(config_file, "r", encoding="utf-8") as f:
                config = json.load(f)
            
            security = config.get("security", {})
            approval_required = security.get("approvalRequired", False)
            
            if approval_required:
                return "PASS", "已启用审批模式，检测异常行为", "INFO"
            else:
                return "WARN", "未启用审批模式，可能无法检测异常行为", "MEDIUM"
        except Exception as e:
            return "ERROR", f"解析配置文件失败: {str(e)}", "ERROR"
