import re
from pathlib import Path
from core.security_check import SecurityCheck
from core.platform_adapter import PlatformAdapter


class SecretsChecker(SecurityCheck):
    """密钥泄露检测"""

    def __init__(self):
        super().__init__("密钥泄露检测", "CRITICAL")

    async def run(self):
        """执行密钥泄露检测"""
        self.status = "running"

        base_path = PlatformAdapter.get_openclaw_path()

        # 1. 私钥文件检测
        await self._check_private_keys(base_path)

        # 2. 助记词检测
        await self._check_mnemonics(base_path)

        # 3. 数据库明文检测
        await self._check_db_encryption(base_path)

        # 4. 日志文件敏感信息检测
        await self._check_logs(base_path)

        self.status = "completed"

    async def _check_private_keys(self, base_path):
        """检测私钥文件"""
        key_extensions = ['*.pem', '*.key', '*.p12', '*.pfx', '*.jks', '*.keystore']
        found_keys = []

        for ext in key_extensions:
            for file in base_path.rglob(ext):
                found_keys.append(str(file.relative_to(base_path)))

        for key_file in found_keys:
            self.report(f"发现私钥文件: {key_file}", "CRITICAL")

    async def _check_mnemonics(self, base_path):
        """检测助记词/钱包种子"""
        memory_path = base_path / "memory"

        if not memory_path.exists():
            return

        # 助记词正则（12、15、18、21或24个单词）
        # 助记词通常是BIP39标准，每个单词来自特定词汇表
        mnemonic_patterns = [
            # 12个单词模式
            r'\b([a-zA-Z]{3,8}\s+){11}[a-zA-Z]{3,8}\b',
            # 24个单词模式
            r'\b([a-zA-Z]{3,8}\s+){23}[a-zA-Z]{3,8}\b',
        ]

        # 钱包相关敏感词
        wallet_keywords = [
            'mnemonic', 'seed phrase', '助记词', '钱包',
            'private key', '私钥', 'secret phrase', '密钥短语'
        ]

        for file in memory_path.rglob("*"):
            if file.is_file() and file.suffix in ['.txt', '.md', '.json']:
                try:
                    content = file.read_text(encoding='utf-8', errors='ignore')

                    # 检查助记词模式
                    for pattern in mnemonic_patterns:
                        matches = re.findall(pattern, content)
                        for match in matches:
                            words = match.strip().split()
                            if 11 <= len(words) <= 24:
                                self.report(f"发现疑似助记词: {file.name}", "CRITICAL")

                    # 检查钱包相关敏感词
                    for keyword in wallet_keywords:
                        if keyword.lower() in content.lower():
                            self.report(f"发现钱包相关敏感词: {file.name} - {keyword}", "HIGH")
                            break

                except:
                    continue

    async def _check_db_encryption(self, base_path):
        """检测数据库明文"""
        # 检查SQLite数据库
        db_files = list(base_path.rglob("*.db")) + list(base_path.rglob("*.sqlite")) + list(base_path.rglob("*.sqlite3"))

        for db_file in db_files:
            try:
                # 检查数据库是否加密
                with open(db_file, 'rb') as f:
                    header = f.read(16)

                # SQLite未加密的数据库以"SQLite format 3"开头
                if b'SQLite format 3' in header:
                    self.report(f"发现未加密SQLite数据库: {db_file.name}", "HIGH")

            except:
                continue

    async def _check_logs(self, base_path):
        """检测日志文件中的敏感信息"""
        log_files = list(base_path.rglob("*.log")) + list(base_path.rglob("logs/*.txt"))

        # API Key模式
        api_patterns = [
            r'(sk-[a-zA-Z0-9]{48})',
            r'(ak-[a-zA-Z0-9]{32})',
            r'Bearer\s+[a-zA-Z0-9]{32,}',
            r'Token:\s*[a-zA-Z0-9]{32,}',
        ]

        for log_file in log_files:
            try:
                with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                    # 只读取最后1000行
                    lines = f.readlines()[-1000:]
                    content = ''.join(lines)

                for pattern in api_patterns:
                    matches = re.findall(pattern, content, re.IGNORECASE)
                    for match in matches:
                        if isinstance(match, tuple):
                            match = match[0]
                        if len(match) > 12:
                            self.report(f"日志文件 {log_file.name} 包含敏感Token", "HIGH")
                            break

            except:
                continue

    async def fix(self):
        """修复密钥泄露问题"""
        base_path = PlatformAdapter.get_openclaw_path()
        
        # 清理敏感文件
        sensitive_extensions = ['*.pem', '*.key', '*.p12', '*.pfx', '*.jks', '*.keystore']
        found_files = []
        
        for ext in sensitive_extensions:
            for file in base_path.rglob(ext):
                found_files.append(file)
        
        for file in found_files:
            try:
                # 备份文件
                backup_file = file.with_suffix(file.suffix + '.bak')
                file.rename(backup_file)
                # 创建空文件替代
                file.write_text('')
                self.report(f"已备份并清理敏感文件: {file.name}", "INFO")
            except Exception as e:
                self.report(f"清理文件失败: {e}", "LOW")
        
        # 清理日志文件中的敏感信息
        log_files = list(base_path.rglob("*.log")) + list(base_path.rglob("logs/*.txt"))
        
        for log_file in log_files:
            try:
                with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                
                # 替换敏感信息
                api_patterns = [
                    r'(sk-[a-zA-Z0-9]{48})',
                    r'(ak-[a-zA-Z0-9]{32})',
                    r'Bearer\s+[a-zA-Z0-9]{32,}',
                    r'Token:\s*[a-zA-Z0-9]{32,}',
                ]
                
                for pattern in api_patterns:
                    import re
                    content = re.sub(pattern, r'[REDACTED]', content, flags=re.IGNORECASE)
                
                # 写回文件
                with open(log_file, 'w', encoding='utf-8') as f:
                    f.write(content)
                
                self.report(f"已清理日志文件中的敏感信息: {log_file.name}", "INFO")
            except Exception as e:
                self.report(f"清理日志失败: {e}", "LOW")
