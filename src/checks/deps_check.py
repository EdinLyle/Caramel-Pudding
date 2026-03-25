import json
import sys
from pathlib import Path
from core.security_check import SecurityCheck
from core.platform_adapter import PlatformAdapter


class DepsChecker(SecurityCheck):
    """依赖供应链检测"""

    def __init__(self):
        super().__init__("依赖供应链检测", "MEDIUM")

    async def run(self):
        """执行依赖供应链检测"""
        self.status = "running"
        
        # 在run方法中获取最新路径
        self.base_path = PlatformAdapter.get_openclaw_path()

        # 1. 检查Node.js依赖
        await self._check_node_deps()

        # 2. 检查Python依赖
        await self._check_python_deps()

        # 3. 检查Typosquatting包
        await self._check_typosquatting()

        self.status = "completed"

    async def _check_node_deps(self):
        """检查Node.js依赖"""
        package_json = self.base_path / "package.json"
        package_lock = self.base_path / "package-lock.json"

        # 已知恶意或过时的包
        known_malicious = [
            'event-stream',  # 2018年供应链攻击
            'flatmap-stream',  # 2018年供应链攻击
            'eslint-scope',  # 2018年供应链攻击
        ]

        try:
            if package_json.exists():
                with open(package_json, 'r', encoding='utf-8') as f:
                    package = json.load(f)

                dependencies = package.get('dependencies', {})
                devDependencies = package.get('devDependencies', {})

                all_deps = {**dependencies, **devDependencies}

                # 检查已知恶意包
                for dep_name, dep_version in all_deps.items():
                    if dep_name in known_malicious:
                        self.report(f"发现已知恶意依赖包: {dep_name}@{dep_version}", "CRITICAL")

                # 检查依赖数量
                if len(all_deps) > 500:
                    self.report(f"依赖包数量过多: {len(all_deps)} 个", "MEDIUM")

            # 检查package-lock.json完整性
            if package_json.exists() and not package_lock.exists():
                self.report("缺少package-lock.json，依赖锁定不完整", "MEDIUM")

        except Exception as e:
            self.report(f"Node.js依赖检查失败: {e}", "LOW")

    async def _check_python_deps(self):
        """检查Python依赖"""
        requirements_files = [
            self.base_path / "requirements.txt",
            self.base_path / "setup.py",
            self.base_path / "pyproject.toml",
        ]

        # 已知有安全问题的Python包
        vulnerable_packages = {
            'requests': '<2.20.0',  # CVE-2018-18074
            'pillow': '<6.2.2',     # CVE-2019-19911
            'paramiko': '<2.4.2',    # CVE-2018-1000805
            'pyyaml': '<5.1',        # 多个CVE
        }

        try:
            for req_file in requirements_files:
                if req_file.exists():
                    if req_file.suffix == '.txt':
                        await self._check_requirements_txt(req_file, vulnerable_packages)
                    elif req_file.suffix == '.py':
                        await self._check_setup_py(req_file)
                    elif req_file.suffix == '.toml':
                        await self._check_pyproject_toml(req_file)

        except Exception as e:
            self.report(f"Python依赖检查失败: {e}", "LOW")

    async def _check_requirements_txt(self, req_file, vulnerable_packages):
        """检查requirements.txt"""
        with open(req_file, 'r', encoding='utf-8') as f:
            lines = f.readlines()

        for line in lines:
            line = line.strip()
            if not line or line.startswith('#'):
                continue

            # 解析包名和版本
            parts = line.split('==')
            if len(parts) >= 1:
                pkg_name = parts[0].strip().lower()

                if pkg_name in vulnerable_packages:
                    self.report(f"发现已知漏洞依赖: {pkg_name} (版本要求: {vulnerable_packages[pkg_name]})", "HIGH")

    async def _check_setup_py(self, setup_file):
        """检查setup.py"""
        with open(setup_file, 'r', encoding='utf-8') as f:
            content = f.read()

        # 检查是否使用了不安全的安装方法
        unsafe_patterns = [
            'install_requires=[',
            'dependency_links=',
        ]

        for pattern in unsafe_patterns:
            if pattern in content:
                self.report(f"{setup_file.name} 使用了可能不安全的依赖安装方式", "MEDIUM")

    async def _check_pyproject_toml(self, toml_file):
        """检查pyproject.toml"""
        # 简化检查，实际应该使用toml解析库
        with open(toml_file, 'r', encoding='utf-8') as f:
            content = f.read()

        # 检查是否包含外部链接
        if 'http://' in content or 'git+' in content:
            self.report(f"{toml_file.name} 包含外部依赖链接", "MEDIUM")

    async def _check_typosquatting(self):
        """检查Typosquatting（拼写劫持）包"""
        if sys.platform == "win32":
            return  # Windows主要使用其他包管理器

        # Node.js常见拼写错误
        node_typos = [
            'react-domm',      # react-dom
            'vuee',            # vue
            'lodashs',         # lodash
            'axio',            # axios
            'expresss',        # express
        ]

        # Python常见拼写错误
        python_typos = [
            'djangoo',         # django
            'flaskk',          # flask
            'requst',          # requests
            'numpyy',          # numpy
            'pandass',         # pandas
        ]

        all_typos = node_typos + python_typos

        # 检查package.json
        package_json = self.base_path / "package.json"
        if package_json.exists():
            with open(package_json, 'r', encoding='utf-8') as f:
                package = json.load(f)

            dependencies = package.get('dependencies', {})
            devDependencies = package.get('devDependencies', {})
            all_deps = {**dependencies, **devDependencies}

            for dep_name in all_deps.keys():
                if dep_name.lower() in all_typos:
                    self.report(f"发现疑似Typosquatting包: {dep_name}", "HIGH")

    async def fix(self):
        """修复依赖供应链问题"""
        # 检查Node.js依赖
        package_json = self.base_path / "package.json"
        if package_json.exists():
            try:
                import subprocess
                # 运行npm audit fix
                result = subprocess.run(
                    ["npm", "audit", "fix"],
                    cwd=str(self.base_path),
                    capture_output=True,
                    text=True
                )
                if result.returncode == 0:
                    self.report("已运行npm audit fix修复依赖漏洞", "INFO")
                else:
                    self.report(f"npm audit fix执行失败: {result.stderr}", "LOW")
            except Exception as e:
                self.report(f"修复Node.js依赖失败: {e}", "LOW")
        
        # 检查Python依赖
        requirements_file = self.base_path / "requirements.txt"
        if requirements_file.exists():
            try:
                import subprocess
                # 升级pip
                subprocess.run(
                    [sys.executable, "-m", "pip", "install", "--upgrade", "pip"],
                    capture_output=True,
                    text=True
                )
                # 升级依赖
                result = subprocess.run(
                    [sys.executable, "-m", "pip", "install", "--upgrade", "-r", "requirements.txt"],
                    cwd=str(self.base_path),
                    capture_output=True,
                    text=True
                )
                if result.returncode == 0:
                    self.report("已升级Python依赖", "INFO")
                else:
                    self.report(f"升级Python依赖失败: {result.stderr}", "LOW")
            except Exception as e:
                self.report(f"修复Python依赖失败: {e}", "LOW")
