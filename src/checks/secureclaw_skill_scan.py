import os
import re
from typing import Dict, List, Tuple

class SecureClawSkillScan:
    def __init__(self):
        # 恶意模式规则
        self.malicious_patterns = {
            "remote_code_execution": [
                r"curl.*\\|.*sh",
                r"wget.*\\|.*bash",
                r"curl.*\\|.*python",
                r"wget.*\\|.*python"
            ],
            "dynamic_execution": [
                r"eval\(",
                r"exec\(",
                r"Function\(",
                r"subprocess",
                r"os\.system"
            ],
            "obfuscation": [
                r"atob\(",
                r"btoa\(",
                r"String\.fromCharCode",
                r"\\\x[0-9a-fA-F]{2}"
            ],
            "credential_access": [
                r"process\.env",
                r"\.env",
                r"apiKey",
                r"secret",
                r"token"
            ],
            "config_tampering": [
                r"SOUL\.md",
                r"IDENTITY\.md",
                r"TOOLS\.md",
                r"openclaw\.json"
            ],
            "clawhavoc_campaign": [
                r"osascript display",
                r"xattr quarantine",
                r"ClickFix",
                r"webhook\.site"
            ]
        }
        
        # ClawHavoc活动相关的名称模式
        self.clawhavoc_names = [
            r"solana-wallet",
            r"phantom-tracker",
            r"clawhub.*",
            r"openclaw.*"
        ]
    
    def scan_skills(self, skills_dir: str) -> Dict:
        """扫描技能目录"""
        if not os.path.exists(skills_dir):
            return {"status": "ERROR", "message": "技能目录不存在"}
        
        results = {
            "scanned_skills": [],
            "suspicious_skills": []
        }
        
        # 遍历技能目录
        for skill_name in os.listdir(skills_dir):
            skill_path = os.path.join(skills_dir, skill_name)
            
            # 跳过非目录
            if not os.path.isdir(skill_path):
                continue
            
            # 跳过SecureClaw自身
            if skill_name == "secureclaw":
                continue
            
            # 扫描技能
            skill_result = self._scan_skill(skill_path, skill_name)
            results["scanned_skills"].append(skill_result)
            
            if skill_result["status"] == "SUSPICIOUS":
                results["suspicious_skills"].append(skill_result)
        
        return results
    
    def _scan_skill(self, skill_path: str, skill_name: str) -> Dict:
        """扫描单个技能"""
        result = {
            "name": skill_name,
            "path": skill_path,
            "status": "CLEAN",
            "issues": []
        }
        
        # 检查技能名称是否可疑
        for pattern in self.clawhavoc_names:
            if re.search(pattern, skill_name):
                result["status"] = "SUSPICIOUS"
                result["issues"].append(f"可疑的技能名称，可能与ClawHavoc活动相关")
                break
        
        # 扫描技能文件
        for root, dirs, files in os.walk(skill_path):
            for file in files:
                file_path = os.path.join(root, file)
                
                # 读取文件内容
                try:
                    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read()
                except:
                    continue
                
                # 检查恶意模式
                try:
                    for pattern_type, patterns in self.malicious_patterns.items():
                        for pattern in patterns:
                            if re.search(pattern, content):
                                result["status"] = "SUSPICIOUS"
                                result["issues"].append(f"在 {file} 中发现 {pattern_type} 模式")
                                break
                except re.error as e:
                    # 处理正则表达式错误，如不完整的转义序列
                    result["status"] = "SUSPICIOUS"
                    result["issues"].append(f"在 {file} 中发现可疑的转义序列: {str(e)}")
        
        return result
    
    def scan_file(self, file_path: str) -> Dict:
        """扫描单个文件"""
        if not os.path.exists(file_path):
            return {"status": "ERROR", "message": "文件不存在"}
        
        result = {
            "file": file_path,
            "status": "CLEAN",
            "issues": []
        }
        
        # 读取文件内容
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
        except Exception as e:
            return {"status": "ERROR", "message": f"读取文件失败: {str(e)}"}
        
        # 检查恶意模式
        for pattern_type, patterns in self.malicious_patterns.items():
            for pattern in patterns:
                if re.search(pattern, content):
                    result["status"] = "SUSPICIOUS"
                    result["issues"].append(f"发现 {pattern_type} 模式")
                    break
        
        return result
