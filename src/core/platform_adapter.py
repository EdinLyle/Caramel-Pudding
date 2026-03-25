import sys
import os
from pathlib import Path
from datetime import datetime

class PlatformAdapter:
    """跨平台适配器"""
    
    # 存储自定义OpenClaw路径
    _custom_openclaw_path = None

    @classmethod
    def set_openclaw_path(cls, path):
        """设置自定义OpenClaw路径"""
        if path:
            cls._custom_openclaw_path = Path(path).resolve()
        else:
            cls._custom_openclaw_path = None

    @classmethod
    def get_openclaw_path(cls):
        """获取OpenClaw配置路径"""
        # 如果设置了自定义路径
        if cls._custom_openclaw_path:
            # 检查自定义路径是否已经是.openclaw目录
            if cls._custom_openclaw_path.name == ".openclaw" and cls._custom_openclaw_path.is_dir():
                return cls._custom_openclaw_path
            # 检查自定义路径是否包含.openclaw子目录
            openclaw_subdir = cls._custom_openclaw_path / ".openclaw"
            if openclaw_subdir.exists() and openclaw_subdir.is_dir():
                return openclaw_subdir
            # 检查自定义路径是否是OpenClaw目录
            if cls._is_openclaw_directory(cls._custom_openclaw_path):
                return cls._custom_openclaw_path
            # 如果以上都不是，返回自定义路径
            return cls._custom_openclaw_path
        
        # 自动搜索OpenClaw安装路径
        search_paths = cls._search_openclaw_paths()
        for path in search_paths:
            # 检查是否包含.openclaw子目录（优先）
            openclaw_subdir = path / ".openclaw"
            if openclaw_subdir.exists() and openclaw_subdir.is_dir():
                return openclaw_subdir
            # 检查是否为OpenClaw目录
            if cls._is_openclaw_directory(path):
                return path
        
        # 检查常见的.openclaw位置
        common_openclaw_paths = []
        if sys.platform == "win32":
            common_openclaw_paths = [
                Path(os.environ.get("USERPROFILE", os.environ.get("HOMEPATH", "~"))) / ".openclaw",
            ]
        else:
            common_openclaw_paths = [
                Path.home() / ".openclaw",
                Path("/opt/openclaw/.openclaw"),
                Path("/usr/local/openclaw/.openclaw"),
            ]
        
        for path in common_openclaw_paths:
            if path.exists() and path.is_dir():
                return path
        
        # 默认路径
        if sys.platform == "win32":
            return Path(os.environ.get("USERPROFILE", os.environ.get("HOMEPATH", "~"))) / ".openclaw"
        return Path.home() / ".openclaw"
    
    @staticmethod
    def _search_openclaw_paths():
        """搜索可能的OpenClaw安装路径"""
        paths = []
        
        # 常见安装位置
        if sys.platform == "win32":
            # Windows常见位置
            paths.extend([
                Path(os.environ.get("ProgramFiles", "C:\\Program Files")) / "OpenClaw",
                Path(os.environ.get("ProgramFiles(x86)", "C:\\Program Files (x86)")) / "OpenClaw",
                Path(os.environ.get("LOCALAPPDATA", "C:\\Users\\Default\\AppData\\Local")) / "OpenClaw",
                Path(os.environ.get("APPDATA", "C:\\Users\\Default\\AppData\\Roaming")) / "OpenClaw",
                Path(os.environ.get("USERPROFILE", "C:\\Users\\Default")) / "OpenClaw",
                Path(os.environ.get("USERPROFILE", "C:\\Users\\Default")) / "Downloads" / "OpenClaw",
                Path("D:\\OpenClaw"),
                Path("E:\\OpenClaw"),
                Path("D:\\Program Files\\OpenClaw"),
                Path("E:\\Program Files\\OpenClaw"),
            ])
        else:
            # Linux/macOS常见位置
            paths.extend([
                Path("/opt/openclaw"),
                Path("/usr/local/openclaw"),
                Path.home() / "openclaw",
                Path.home() / ".local" / "openclaw",
                Path.home() / "Downloads" / "openclaw",
                Path("/usr/share/openclaw"),
                Path("/var/lib/openclaw"),
            ])
        
        # 检查环境变量
        if "OPENCLAW_HOME" in os.environ:
            paths.append(Path(os.environ["OPENCLAW_HOME"]))
        
        # 检查当前目录及其父目录
        current_dir = Path.cwd()
        for _ in range(5):  # 向上搜索5级目录，增加搜索深度
            paths.append(current_dir)
            paths.append(current_dir / "openclaw")
            paths.append(current_dir / "OpenClaw")
            paths.append(current_dir / ".openclaw")
            if current_dir.parent == current_dir:  # 到达根目录
                break
            current_dir = current_dir.parent
        
        # 去重并返回存在的路径
        existing_paths = []
        seen = set()
        for path in paths:
            try:
                path_str = str(path.resolve())
                if path_str not in seen and path.exists() and path.is_dir():
                    seen.add(path_str)
                    existing_paths.append(path)
            except:
                pass
        
        return existing_paths
    
    @staticmethod
    def _is_openclaw_directory(path):
        """判断是否为OpenClaw目录"""
        if not path.exists() or not path.is_dir():
            return False
        
        # 检查核心文件和目录，需要至少包含以下两个关键文件/目录
        key_indicators = [
            path / "openclaw.json",  # 核心配置文件
            path / ".openclaw",  # 配置目录
            path / "package.json",  # Node.js项目文件
            path / "brain",  # 大脑数据目录
            path / "skills",  # 技能包目录
            path / "MEMORY.md",  # 记忆文件
        ]
        
        # 计算存在的关键指标数量
        existing_indicators = 0
        for indicator in key_indicators:
            if indicator.exists():
                existing_indicators += 1
        
        # 需要至少存在2个关键指标才认为是OpenClaw目录
        return existing_indicators >= 2

    @staticmethod
    def get_shell():
        """获取默认Shell"""
        return "powershell.exe" if sys.platform == "win32" else "bash"

    @staticmethod
    def is_admin():
        """检查是否有管理员/root权限"""
        if sys.platform == "win32":
            try:
                import ctypes
                return ctypes.windll.shell32.IsUserAnAdmin() != 0
            except:
                return False
        else:
            return os.getuid() == 0

    @staticmethod
    def get_platform_name():
        """获取平台名称"""
        if sys.platform == "win32":
            return "Windows"
        elif sys.platform == "darwin":
            return "macOS"
        else:
            return "Linux"

    @staticmethod
    def normalize_path(path):
        """标准化路径"""
        return Path(path).resolve()
