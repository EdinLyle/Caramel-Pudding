import yaml
import re
from pathlib import Path
from core.security_check import SecurityCheck
from core.platform_adapter import PlatformAdapter


class SkillsChecker(SecurityCheck):
    """技能包安全检测"""

    def __init__(self):
        super().__init__("技能包安全检测", "HIGH")
        # 已知恶意技能包名单
        self.malicious_skills = [
            "openclaw-miner",
            "claw-admin",
            "system-utils",
            "0penclaw",  # Typosquatting
            "openclaw-utils",
            "claw-root",
            "backdoor-claw",
            "claw-execute",
        ]

    async def run(self):
        """执行技能包安全检测"""
        self.status = "running"
        
        # 在run方法中获取最新路径
        self.skills_path = PlatformAdapter.get_openclaw_path() / "skills"

        if not self.skills_path.exists():
            self.report("技能包目录不存在", "INFO")
            return

        # 遍历所有技能包
        for skill_dir in self.skills_path.iterdir():
            if skill_dir.is_dir():
                await self._check_skill(skill_dir)

        self.status = "completed"

    async def _check_skill(self, skill_path):
        """检测单个技能包"""
        skill_yaml = skill_path / "skill.yaml"
        if not skill_yaml.exists():
            # 检查是否有manifest.json或其他配置文件
            skill_yaml = skill_path / "manifest.json"

        if not skill_yaml.exists():
            return

        try:
            if skill_yaml.suffix == '.yaml':
                with open(skill_yaml, 'r', encoding='utf-8') as f:
                    skill_config = yaml.safe_load(f)
            elif skill_yaml.suffix == '.json':
                import json
                with open(skill_yaml, 'r', encoding='utf-8') as f:
                    skill_config = json.load(f)
            else:
                return
        except Exception as e:
            self.report(f"技能包 {skill_path.name} 解析失败: {e}", "LOW")
            return

        # 1. 检查恶意名单
        if skill_path.name in self.malicious_skills:
            self.report(f"发现已知恶意技能包: {skill_path.name}", "CRITICAL")

        # 2. 检查Typosquatting（拼写劫持）
        await self._check_typosquatting(skill_path)

        # 3. 检查危险权限组合
        await self._check_dangerous_permissions(skill_path.name, skill_config)

        # 4. 检查Prompt注入
        await self._check_prompt_injection(skill_path)

        # 5. 检查网络请求
        await self._check_network_requests(skill_path)

        # 6. 检查SSRF风险
        await self._check_ssrf_risk(skill_path)

        # 7. 检查敏感路径访问
        await self._check_sensitive_path_access(skill_path)

        # 8. 检查技能包来源
        await self._check_skill_source(skill_path, skill_config)

        # 9. 检查危险API使用
        await self._check_dangerous_apis(skill_path)

    async def _check_typosquatting(self, skill_path):
        """检测拼写劫持"""
        name = skill_path.name.lower()

        # 常见的拼写错误
        typos = [
            "0penclaw",  # 0替换o
            "openc1aw",  # 1替换l
            "openclaww",  # 多个w
            "oppenclaw",  # 多个p
            "openc1awy",  # 1替换l, y替换
        ]

        if name in typos or any(typo in name for typo in typos):
            self.report(f"技能包 {skill_path.name} 存在拼写劫持风险", "HIGH")

    async def _check_dangerous_permissions(self, skill_name, config):
        """检查危险权限组合"""
        perms = config.get('permissions', {})

        dangerous_combos = [
            (["exec", "network"], "同时拥有执行和网络权限"),
            (["exec", "write"], "同时拥有执行和写入权限"),
            (["network", "read_all"], "同时拥有网络和全读权限"),
            (["exec", "system"], "同时拥有执行和系统权限"),
        ]

        for combo, desc in dangerous_combos:
            if all(perms.get(p, False) for p in combo):
                self.report(f"技能包 {skill_name} {desc}", "HIGH")

        # 单独检查危险权限
        if perms.get("exec_system", False):
            self.report(f"技能包 {skill_name} 拥有系统执行权限", "CRITICAL")
        if perms.get("network_c2", False):
            self.report(f"技能包 {skill_name} 拥有C2网络权限", "CRITICAL")

    async def _check_prompt_injection(self, skill_path):
        """检测Prompt劫持"""
        md_files = list(skill_path.glob("*.md"))
        py_files = list(skill_path.glob("*.py"))
        js_files = list(skill_path.glob("*.js"))

        injection_patterns = [
            r'(?i)(ignore previous|override|bypass|forget|jailbreak)',
            r'(?i)(system prompt override|new instruction)',
            r'(?i)(you are now free|as an ai, you are no longer)',
            r'(?i)(ignore all instructions|disregard previous)',
            r'(?i)(act as|pretend to be)',
        ]

        all_files = md_files + py_files + js_files
        for file in all_files:
            try:
                content = file.read_text(encoding='utf-8', errors='ignore')
                for pattern in injection_patterns:
                    if re.search(pattern, content):
                        self.report(f"技能包 {skill_path.name} 文件 {file.name} 存在Prompt注入风险", "HIGH")
                        break
            except:
                continue

    async def _check_network_requests(self, skill_path):
        """检查可疑网络请求"""
        # 检查代码中是否包含可疑的URL或IP
        suspicious_domains = [
            "pastebin.com",
            "t.me",
            "discord.com",
            "webhook.site",
            "requestbin.net",
        ]

        code_files = list(skill_path.glob("**/*.py")) + list(skill_path.glob("**/*.js"))

        for file in code_files:
            try:
                content = file.read_text(encoding='utf-8', errors='ignore')
                for domain in suspicious_domains:
                    if domain in content.lower():
                        self.report(f"技能包 {skill_path.name} 包含可疑域名: {domain}", "MEDIUM")
            except:
                continue

    async def _check_ssrf_risk(self, skill_path):
        """检测SSRF风险"""
        ssrf_patterns = [
            r'fetch\s*\(\s*\$\{.*user',
            r'http\.get\s*\(\s*\$\{.*input',
            r'axios\s*\.\s*(get|post)\s*\(\s*\$\{.*param',
            r'url\s*[=:]\s*.*\$\{.*\}',
            r'request\s*\(.*\$\{.*url',
        ]

        code_files = list(skill_path.glob("**/*.py")) + list(skill_path.glob("**/*.js"))

        for file in code_files:
            try:
                content = file.read_text(encoding='utf-8', errors='ignore')
                for pattern in ssrf_patterns:
                    if re.search(pattern, content):
                        self.report(f"技能包 {skill_path.name} 文件 {file.name} 存在SSRF风险", "HIGH")
                        break
            except:
                continue

    async def _check_sensitive_path_access(self, skill_path):
        """检测敏感路径访问"""
        sensitive_paths = [
            r'\.ssh',
            r'\.gnupg',
            r'/etc/passwd',
            r'/etc/shadow',
            r'\.aws/credentials',
            r'\.config/gcloud',
            r'id_rsa\|id_ed25519',
            r'\$HOME/\.(bash_history\|zsh_history)',
            r'PRIVATE.*KEY',
            r'\.kube/config',
        ]

        code_files = list(skill_path.glob("**/*.py")) + list(skill_path.glob("**/*.js"))

        for file in code_files:
            try:
                content = file.read_text(encoding='utf-8', errors='ignore')
                for pattern in sensitive_paths:
                    if re.search(pattern, content):
                        self.report(f"技能包 {skill_path.name} 文件 {file.name} 访问敏感路径", "HIGH")
                        break
            except:
                continue

    async def _check_skill_source(self, skill_path, config):
        """检查技能包来源"""
        # 检查是否有来源信息
        source_info = config.get('source') or config.get('repository') or config.get('homepage') or config.get('author')
        if not source_info:
            self.report(f"技能包 {skill_path.name} 缺少来源信息", "MEDIUM")

    async def _check_dangerous_apis(self, skill_path):
        """检测危险API使用"""
        dangerous_apis = [
            r'child_process',
            r'exec\(',
            r'spawn\(',
            r'shell\.',
            r'fs\.write',
            r'writeFile\(',
            r'createWriteStream\(',
        ]

        code_files = list(skill_path.glob("**/*.py")) + list(skill_path.glob("**/*.js"))

        for file in code_files:
            try:
                content = file.read_text(encoding='utf-8', errors='ignore')
                for api in dangerous_apis:
                    if re.search(api, content):
                        self.report(f"技能包 {skill_path.name} 文件 {file.name} 使用危险API: {api}", "HIGH")
            except:
                continue

    async def fix(self):
        """修复技能包安全问题"""
        # 获取技能包目录
        self.skills_path = PlatformAdapter.get_openclaw_path() / "skills"
        
        if not self.skills_path or not self.skills_path.exists():
            return
        
        # 移除已知恶意技能包
        for skill_dir in self.skills_path.iterdir():
            if skill_dir.is_dir() and skill_dir.name in self.malicious_skills:
                try:
                    import shutil
                    shutil.rmtree(skill_dir)
                    self.report(f"已移除恶意技能包: {skill_dir.name}", "INFO")
                except Exception as e:
                    self.report(f"移除恶意技能包失败: {e}", "LOW")
