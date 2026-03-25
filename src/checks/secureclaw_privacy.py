import re
from typing import Dict, List, Tuple

class SecureClawPrivacy:
    def __init__(self):
        # PII检测规则
        self.pii_rules = {
            "CRITICAL": [
                # API密钥和令牌
                r"sk-ant-[a-zA-Z0-9_-]{32}",  # Anthropic API key
                r"sk-proj-[a-zA-Z0-9_-]{32}",  # Anthropic project key
                r"xoxb-[0-9]{10,}-[0-9]{10,}-[a-zA-Z0-9]{24}",  # Slack bot token
                r"ghp_[a-zA-Z0-9]{36}",  # GitHub personal access token
                r"AKIA[0-9A-Z]{16}",  # AWS access key
                r"[0-9a-fA-F]{32}",  # MD5 hash
                r"[0-9a-fA-F]{40}",  # SHA1 hash
                # IP地址
                r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b",  # IPv4 address
                r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b",  # IPv6 address
                # SSH详情
                r"ssh-rsa [A-Za-z0-9+/]+=*",  # SSH public key
                r"-----BEGIN RSA PRIVATE KEY-----"
            ],
            "HIGH": [
                # 真实姓名
                r"\b[A-Z][a-z]+\s+[A-Z][a-z]+\b",  # First and last name
                # 内部文件路径
                r"~/.openclaw/",
                r"C:\\Users\\",
                r"/home/[a-zA-Z0-9_]+/",
                # 端口号
                r":[0-9]{1,5}",
                # 家庭成员姓名
                r"my (mother|father|sister|brother|wife|husband|child|son|daughter)\b",
                # 宗教实践
                r"(Christian|Muslim|Jewish|Buddhist|Hindu)\b"
            ],
            "MEDIUM": [
                # 位置短语
                r"lives in [A-Za-z]+(?: [A-Za-z]+)*",
                r"based in [A-Za-z]+(?: [A-Za-z]+)*",
                # 职业
                r"works as a [A-Za-z]+(?: [A-Za-z]+)*",
                r"employed as a [A-Za-z]+(?: [A-Za-z]+)*",
                # 设备名称
                r"(Pixel|iPhone|MacBook|iPad|Android|Windows)\b",
                # VPN/网络工具
                r"(Tailscale|WireGuard|OpenVPN|ExpressVPN)\b",
                # 日常活动
                r"every (day|week|month)\b",
                r"usually at [0-9]{1,2}:[0-9]{2}\b"
            ]
        }
    
    def check_privacy(self, text: str) -> Dict:
        """检查文本中的PII"""
        results = {
            "status": "CLEAN",
            "findings": []
        }
        
        for severity, patterns in self.pii_rules.items():
            for pattern in patterns:
                matches = re.findall(pattern, text)
                if matches:
                    results["status"] = "PII_FOUND"
                    results["findings"].append({
                        "severity": severity,
                        "pattern": pattern,
                        "matches": matches[:5]  # 只返回前5个匹配，避免结果过大
                    })
        
        return results
    
    def check_file(self, file_path: str) -> Dict:
        """检查文件中的PII"""
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
        except Exception as e:
            return {"status": "ERROR", "message": f"读取文件失败: {str(e)}"}
        
        return self.check_privacy(content)
    
    def get_privacy_score(self, findings: List) -> int:
        """计算隐私风险分数"""
        score = 0
        severity_scores = {
            "CRITICAL": 10,
            "HIGH": 5,
            "MEDIUM": 2
        }
        
        for finding in findings:
            severity = finding.get("severity", "MEDIUM")
            score += severity_scores.get(severity, 2) * len(finding.get("matches", []))
        
        return min(score, 100)  # 最高100分
