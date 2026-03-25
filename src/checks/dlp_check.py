import json
import re
import os
import asyncio
from pathlib import Path
from core.security_check import SecurityCheck
from core.platform_adapter import PlatformAdapter


class DLPChecker(SecurityCheck):
    """数据泄露防护检查"""

    def __init__(self):
        super().__init__("数据泄露防护检查", "CRITICAL")
        self.max_depth = 5  # 最大目录遍历深度
        self.max_file_size = 10 * 1024 * 1024  # 最大文件大小 (10MB)

    async def run(self):
        """执行数据泄露防护检查"""
        self.status = "running"

        # 在run方法中获取最新路径
        self.config_path = PlatformAdapter.get_openclaw_path()

        try:
            # 合并目录遍历，只遍历一次
            await self._check_all()
        except Exception as e:
            self.report(f"DLP检查执行失败: {e}", "ERROR")

        # 4. 文件哈希基线完整性验证
        await self._check_file_integrity()

        # 5. Brain/Memory数据备份验证
        await self._check_brain_backup()

        self.status = "completed"

    async def _check_all(self):
        """一次性检查所有DLP项目"""
        private_key_patterns = [
            r'-----BEGIN (RSA|DSA|EC|OPENSSH|PGP) PRIVATE KEY-----',
            r'-----BEGIN PRIVATE KEY-----',
            r'-----BEGIN ENCRYPTED PRIVATE KEY-----',
            r'private_key.*=.*["\'][a-zA-Z0-9+/=]{100,}["\']',
            r'private.*key.*=.*["\'][a-zA-Z0-9+/=]{100,}["\']',
        ]

        mnemonic_patterns = [
            r'\b(seed|mnemonic|passphrase|recovery phrase)\b.*["\'][a-zA-Z\s]{50,}["\']',
            r'\b(seed|mnemonic|passphrase|recovery phrase)\b.*:\s*["\'][a-zA-Z\s]{50,}["\']',
            r'\b(seed|mnemonic|passphrase|recovery phrase)\b.*=.*["\'][a-zA-Z\s]{50,}["\']',
        ]

        sensitive_patterns = {
            'api_key': r'\b(api[_\s-]?key|apikey)\b.*["\'][a-zA-Z0-9]{20,}["\']',
            'access_token': r'\b(access[_\s-]?token|accesstoken)\b.*["\'][a-zA-Z0-9]{20,}["\']',
            'password': r'\b(password|passwd)\b.*["\'][^"\']{8,}["\']',
            'secret': r'\b(secret[_\s-]?key|secretkey)\b.*["\'][a-zA-Z0-9]{20,}["\']',
            'token': r'\b(token)\b.*["\'][a-zA-Z0-9]{20,}["\']',
        }

        sensitive_extensions = ['.pem', '.key', '.pfx', '.p12', '.der']
        text_extensions = ['.json', '.md', '.txt', '.env', '.yaml', '.yml']

        found_private_keys = []
        found_mnemonics = []
        found_sensitive_info = {}

        # 限制遍历深度的函数
        def limited_walk(path, max_depth):
            yield from os.walk(path)
            depth = 0
            for root, dirs, files in os.walk(path):
                # 计算当前深度
                current_depth = root[len(str(path)):].count(os.sep)
                if current_depth >= max_depth:
                    dirs[:] = []  # 停止深入
                yield root, dirs, files

        # 搜索文件
        for root, dirs, files in limited_walk(self.config_path, self.max_depth):
            # 跳过不需要的目录
            dirs[:] = [d for d in dirs if d not in ['node_modules', '.git', 'venv', 'env', 'build', 'dist']]
            
            for file in files:
                file_path = Path(root) / file
                
                # 检查文件大小
                try:
                    if file_path.stat().st_size > self.max_file_size:
                        continue
                except:
                    continue
                
                # 检查文件扩展名
                if any(file.endswith(ext) for ext in sensitive_extensions):
                    found_private_keys.append(str(file_path.relative_to(self.config_path)))
                
                # 检查文本文件内容
                if file.endswith(tuple(text_extensions)):
                    try:
                        content = file_path.read_text(encoding='utf-8', errors='ignore')
                        
                        # 检查私钥
                        for pattern in private_key_patterns:
                            if re.search(pattern, content, re.IGNORECASE):
                                found_private_keys.append(str(file_path.relative_to(self.config_path)))
                                break
                        
                        # 检查助记词
                        for pattern in mnemonic_patterns:
                            if re.search(pattern, content, re.IGNORECASE):
                                found_mnemonics.append(str(file_path.relative_to(self.config_path)))
                                break
                        
                        # 检查敏感信息
                        for info_type, pattern in sensitive_patterns.items():
                            matches = re.findall(pattern, content, re.IGNORECASE)
                            if matches:
                                if info_type not in found_sensitive_info:
                                    found_sensitive_info[info_type] = []
                                found_sensitive_info[info_type].append(str(file_path.relative_to(self.config_path)))
                    except:
                        pass
                
                # 每处理10个文件，让出控制权
                if len(files) > 10 and files.index(file) % 10 == 0:
                    await asyncio.sleep(0.01)

        # 报告结果
        if found_private_keys:
            self.report(f"发现可能的私钥文件: {', '.join(list(set(found_private_keys))[:5])}", "CRITICAL")
        
        if found_mnemonics:
            self.report(f"发现可能的助记词/种子短语: {', '.join(list(set(found_mnemonics))[:5])}", "CRITICAL")
        
        for info_type, files in found_sensitive_info.items():
            if files:
                self.report(f"发现{info_type}敏感信息: {', '.join(list(set(files))[:3])}", "HIGH")

    async def _check_file_integrity(self):
        """检查文件哈希基线完整性"""
        # 检查是否存在文件哈希基线文件
        integrity_file = self.config_path / ".integrity.json"
        if not integrity_file.exists():
            self.report("未找到文件哈希基线文件，无法验证文件完整性", "MEDIUM")
            return

        try:
            with open(integrity_file, 'r', encoding='utf-8') as f:
                baseline = json.load(f)
        except Exception as e:
            self.report(f"文件哈希基线文件解析失败: {e}", "MEDIUM")
            return

        # 验证文件完整性
        mismatches = []
        for file_path, expected_hash in baseline.items():
            full_path = self.config_path / file_path
            if full_path.exists():
                try:
                    # 检查文件大小
                    if full_path.stat().st_size > self.max_file_size:
                        continue
                    
                    import hashlib
                    with open(full_path, 'rb') as f:
                        content = f.read()
                        actual_hash = hashlib.sha256(content).hexdigest()
                    if actual_hash != expected_hash:
                        mismatches.append(file_path)
                except:
                    pass

        if mismatches:
            self.report(f"文件完整性验证失败: {', '.join(mismatches[:5])}", "HIGH")

    async def _check_brain_backup(self):
        """检查Brain/Memory数据备份"""
        brain_dir = self.config_path / "brain"
        memory_file = self.config_path / "MEMORY.md"

        backup_found = False

        # 检查brain目录是否存在
        if brain_dir.exists() and brain_dir.is_dir():
            # 检查是否有备份文件
            backup_files = list(brain_dir.glob("*backup*"))
            if backup_files:
                backup_found = True

        # 检查MEMORY.md是否存在
        if memory_file.exists():
            try:
                # 检查文件大小
                if memory_file.stat().st_size <= self.max_file_size:
                    content = memory_file.read_text(encoding='utf-8', errors='ignore')
                    if "backup" in content.lower():
                        backup_found = True
            except:
                pass

        if not backup_found:
            self.report("未找到Brain/Memory数据备份，存在数据丢失风险", "MEDIUM")

    async def fix(self):
        """修复数据泄露防护问题"""
        base_path = PlatformAdapter.get_openclaw_path()
        
        # 创建文件哈希基线
        integrity_file = base_path / ".integrity.json"
        try:
            import hashlib
            integrity_data = {}
            
            # 计算关键文件的哈希值
            critical_files = [
                "openclaw.json",
                "SOUL.md",
                "MEMORY.md",
            ]
            
            for file_name in critical_files:
                file_path = base_path / file_name
                if file_path.exists():
                    try:
                        if file_path.stat().st_size <= self.max_file_size:
                            with open(file_path, 'rb') as f:
                                content = f.read()
                                file_hash = hashlib.sha256(content).hexdigest()
                                integrity_data[file_name] = file_hash
                    except Exception as e:
                        self.report(f"计算文件哈希失败: {e}", "LOW")
            
            # 保存哈希基线
            if integrity_data:
                with open(integrity_file, 'w', encoding='utf-8') as f:
                    json.dump(integrity_data, f, ensure_ascii=False, indent=2)
                self.report("已创建文件哈希基线", "INFO")
        except Exception as e:
            self.report(f"创建文件哈希基线失败: {e}", "LOW")
        
        # 创建Brain/Memory备份
        brain_dir = base_path / "brain"
        memory_file = base_path / "MEMORY.md"
        
        # 确保brain目录存在
        if not brain_dir.exists():
            try:
                brain_dir.mkdir(parents=True, exist_ok=True)
                self.report("已创建brain目录", "INFO")
            except Exception as e:
                self.report(f"创建brain目录失败: {e}", "LOW")
        
        # 创建备份文件
        if memory_file.exists():
            try:
                backup_file = base_path / "MEMORY.md.bak"
                import shutil
                shutil.copy2(memory_file, backup_file)
                self.report("已创建MEMORY.md备份", "INFO")
            except Exception as e:
                self.report(f"创建备份失败: {e}", "LOW")
        
        # 清理敏感文件
        sensitive_extensions = ['.pem', '.key', '.pfx', '.p12', '.der']
        found_files = []
        
        for ext in sensitive_extensions:
            for file in base_path.rglob(ext):
                found_files.append(file)
        
        for file in found_files:
            try:
                # 备份文件
                backup_file = file.with_suffix(file.suffix + '.bak')
                import shutil
                shutil.copy2(file, backup_file)
                # 创建空文件替代
                file.write_text('')
                self.report(f"已备份并清理敏感文件: {file.name}", "INFO")
            except Exception as e:
                self.report(f"清理文件失败: {e}", "LOW")
