import sys
import subprocess
import json
from pathlib import Path
from core.security_check import SecurityCheck
from core.platform_adapter import PlatformAdapter


class HostChecker(SecurityCheck):
    """主机安全检测"""

    def __init__(self):
        super().__init__("主机安全检测", "MEDIUM")

    async def run(self):
        """执行主机安全检测"""
        self.status = "running"
        
        # 在run方法中获取最新路径
        self.base_path = PlatformAdapter.get_openclaw_path()

        # 1. 检测异常外联连接
        await self._check_outbound_connections()

        # 2. 检查可疑定时任务
        await self._check_scheduled_tasks()

        # 3. 检查文件变更
        await self._check_file_changes()

        # 4. 检查异常进程
        await self._check_suspicious_processes()

        self.status = "completed"

    async def _check_outbound_connections(self):
        """检测异常外联连接"""
        suspicious_domains = [
            'malicious.com',
            'c2-server',
            'evil.com',
            'attacker.net',
        ]

        suspicious_ips = [
            # 已知恶意IP段
        ]

        try:
            if sys.platform == "win32":
                # Windows使用netstat检查外联
                result = subprocess.run(
                    ["netstat", "-ano"],
                    capture_output=True,
                    text=True,
                    encoding='gbk',
                    errors='ignore'
                )

                lines = result.stdout.split('\n')
                for line in lines:
                    if 'ESTABLISHED' in line:
                        # 检查是否连接到可疑域名/IP
                        for domain in suspicious_domains:
                            if domain in line:
                                self.report(f"发现异常外联: {domain}", "HIGH")

            else:
                # Linux使用ss或netstat检查外联
                result = subprocess.run(
                    ["ss", "-tnp"],
                    capture_output=True,
                    text=True,
                    errors='ignore'
                )

                if result.returncode != 0:
                    result = subprocess.run(
                        ["netstat", "-tnp"],
                        capture_output=True,
                        text=True,
                        errors='ignore'
                    )

                lines = result.stdout.split('\n')
                for line in lines:
                    for domain in suspicious_domains:
                        if domain in line:
                            self.report(f"发现异常外联: {domain}", "HIGH")

        except Exception as e:
            self.report(f"外联连接检查失败: {e}", "LOW")

    async def _check_scheduled_tasks(self):
        """检查可疑定时任务"""
        suspicious_patterns = [
            'reverse shell',
            'backdoor',
            'keylogger',
            'miner',
            'cryptocurrency',
            'bitcoin',
            'malware',
        ]

        try:
            if sys.platform == "win32":
                # Windows检查任务计划程序
                result = subprocess.run(
                    ['schtasks', '/query', '/fo', 'LIST', '/v'],
                    capture_output=True,
                    text=True,
                    encoding='gbk',
                    errors='ignore'
                )

                for pattern in suspicious_patterns:
                    if pattern.lower() in result.stdout.lower():
                        self.report(f"发现可疑任务计划: 包含关键词 {pattern}", "HIGH")

            else:
                # Linux检查crontab
                # 检查系统crontab
                crontab_paths = ['/etc/crontab', '/etc/cron.d/', '/var/spool/cron/']

                for path in crontab_paths:
                    if Path(path).exists():
                        if Path(path).is_dir():
                            for file in Path(path).iterdir():
                                await self._check_cron_file(file, suspicious_patterns)
                        else:
                            await self._check_cron_file(Path(path), suspicious_patterns)

        except Exception as e:
            self.report(f"定时任务检查失败: {e}", "LOW")

    async def _check_cron_file(self, file_path, patterns):
        """检查单个cron文件"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()

            for pattern in patterns:
                if pattern.lower() in content.lower():
                    self.report(f"发现可疑定时任务: {file_path.name} - {pattern}", "HIGH")

        except:
            pass

    async def _check_file_changes(self):
        """检查文件变更"""
        # 检查最近24小时内修改的关键文件
        import time
        from datetime import datetime, timedelta

        critical_files = [
            self.base_path / "openclaw.json",
            self.base_path / "SOUL.md",
            self.base_path / "MEMORY.md",
        ]

        one_day_ago = time.time() - (24 * 3600)

        for file_path in critical_files:
            if file_path.exists():
                try:
                    mtime = file_path.stat().st_mtime
                    if mtime > one_day_ago:
                        mod_time = datetime.fromtimestamp(mtime)
                        self.report(f"关键文件最近有变更: {file_path.name} - {mod_time}", "MEDIUM")

                except:
                    pass

    async def _check_suspicious_processes(self):
        """检查异常进程"""
        suspicious_process_names = [
            'miner',
            'cryptonight',
            'xmrig',
            'backdoor',
            'trojan',
            'keylogger',
            'rat',
            'reverse_shell',
        ]

        try:
            if sys.platform == "win32":
                # Windows使用tasklist
                result = subprocess.run(
                    ['tasklist', '/fo', 'csv'],
                    capture_output=True,
                    text=True,
                    encoding='gbk',
                    errors='ignore'
                )

                for proc_name in suspicious_process_names:
                    if proc_name in result.stdout.lower():
                        self.report(f"发现可疑进程: {proc_name}", "HIGH")

            else:
                # Linux使用ps
                result = subprocess.run(
                    ['ps', 'aux'],
                    capture_output=True,
                    text=True,
                    errors='ignore'
                )

                for proc_name in suspicious_process_names:
                    if proc_name in result.stdout.lower():
                        self.report(f"发现可疑进程: {proc_name}", "HIGH")

        except Exception as e:
            self.report(f"异常进程检查失败: {e}", "LOW")

    async def fix(self):
        """修复主机安全问题"""
        # 清理可疑进程（需要管理员权限）
        suspicious_process_names = [
            'miner',
            'cryptonight',
            'xmrig',
            'backdoor',
            'trojan',
            'keylogger',
            'rat',
            'reverse_shell',
        ]
        
        try:
            if sys.platform == "win32":
                # Windows终止可疑进程
                result = subprocess.run(
                    ['tasklist', '/fo', 'csv'],
                    capture_output=True,
                    text=True,
                    encoding='gbk',
                    errors='ignore'
                )
                
                for proc_name in suspicious_process_names:
                    if proc_name in result.stdout.lower():
                        try:
                            # 尝试终止进程
                            subprocess.run(
                                ['taskkill', '/f', '/im', f'{proc_name}.exe'],
                                capture_output=True,
                                text=True
                            )
                            self.report(f"已尝试终止可疑进程: {proc_name}", "INFO")
                        except Exception as e:
                            self.report(f"终止进程失败: {e}", "LOW")
            else:
                # Linux终止可疑进程
                result = subprocess.run(
                    ['ps', 'aux'],
                    capture_output=True,
                    text=True,
                    errors='ignore'
                )
                
                for proc_name in suspicious_process_names:
                    if proc_name in result.stdout.lower():
                        try:
                            # 尝试终止进程
                            subprocess.run(
                                ['pkill', '-f', proc_name],
                                capture_output=True,
                                text=True
                            )
                            self.report(f"已尝试终止可疑进程: {proc_name}", "INFO")
                        except Exception as e:
                            self.report(f"终止进程失败: {e}", "LOW")
        except Exception as e:
            self.report(f"修复主机安全问题失败: {e}", "LOW")
