import customtkinter as ctk
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import threading
import sys
from pathlib import Path
from PIL import Image
import requests
import json
import os

# 添加src目录到Python路径
sys.path.insert(0, str(Path(__file__).parent))

from core.scanner import OpenClawScanner
from core.platform_adapter import PlatformAdapter
from checks import (
    ConfigChecker,
    PortsChecker,
    SkillsChecker,
    SecretsChecker,
    AuthChecker,
    HostChecker,
    DepsChecker,
    ProxyChecker,
    RuntimeChecker,
    DLPChecker,
    VulnerabilityChecker,
    BaselineChecker,
)


class OpenClawScannerUI(ctk.CTk):
    """OpenClaw-焦糖布丁主界面"""

    def __init__(self):
        super().__init__()

        self.title("🦞 焦糖布丁 v4.0")
        self.geometry("1300x800")
        self.minsize(1100, 600)

        # 设置主题 - 插画风格
        ctk.set_appearance_mode("Light")
        ctk.set_default_color_theme("blue")
        
        # 自定义颜色 - 插画风格
        self.primary_color = "#73D13D"  # 主色调（浅绿色）
        self.text_color = "#2C2C2C"  # 文本颜色（深灰色）
        self.error_color = "#FA5252"  # 错误颜色（红色）
        self.success_color = "#87CE61"  # 成功颜色（浅绿色）
        self.warning_color = "#FFD93D"  # 警告颜色（黄色）
        self.info_color = "#4DABF7"  # 信息颜色（蓝色）
        self.bg_color = "#FFF9F0"  # 背景颜色（浅黄色）
        self.container_color = "#FFFFFF"  # 容器背景（白色）
        self.card_color = "#FFF0F6"  # 卡片背景
        self.border_color = "#2C2C2C"  # 边框颜色（深灰色）
        self.selected_color = "#E6F7FF"  # 选中颜色
        
        # 设置窗口背景色
        self.configure(fg_color=self.bg_color)

        # 初始化扫描器
        self.scanner = OpenClawScanner()
        self._init_checks()

        # 配置文件路径
        self.config_file = Path(__file__).parent.parent / "config" / "ai_model_config.json"
        # 加载AI模型配置
        self.ai_model_config = self._load_ai_model_config()

        # 当前检测结果
        self.current_results = []

        # SecureClaw结果存储
        self.secureclaw_audit_result = None
        self.secureclaw_harden_result = None
        self.secureclaw_skill_scan_result = None
        self.secureclaw_integrity_result = None
        self.secureclaw_privacy_result = None
        self.secureclaw_behavior_result = None

        # 设置UI
        self._setup_ui()

    def _load_ai_model_config(self):
        """加载AI模型配置"""
        default_config = {
            "configs": [
                {
                    "name": "默认配置",
                    "model_type": "ollama",
                    "ollama": {
                        "model": "llama3",
                        "url": "http://localhost:11434/api/generate"
                    },
                    "cloud": {
                        "api_key": "",
                        "api_url": "https://api.example.com/v1/chat/completions"
                    }
                }
            ],
            "current_config": "默认配置"
        }
        
        if self.config_file.exists():
            try:
                with open(self.config_file, 'r', encoding='utf-8') as f:
                    config_data = json.load(f)
                # 确保配置格式正确
                if "configs" not in config_data:
                    # 兼容旧格式
                    old_config = config_data
                    config_data = {
                        "configs": [
                            {
                                "name": "默认配置",
                                "model_type": old_config.get("model_type", "ollama"),
                                "ollama": old_config.get("ollama", {
                                    "model": "llama3",
                                    "url": "http://localhost:11434/api/generate"
                                }),
                                "cloud": old_config.get("cloud", {
                                    "api_key": "",
                                    "api_url": "https://api.example.com/v1/chat/completions"
                                })
                            }
                        ],
                        "current_config": "默认配置"
                    }
                    # 保存为新格式
                    self._save_ai_model_config(config_data)
                return config_data
            except Exception as e:
                print(f"加载AI模型配置失败: {e}")
                return default_config
        else:
            # 确保配置目录存在
            self.config_file.parent.mkdir(exist_ok=True)
            # 保存默认配置
            self._save_ai_model_config(default_config)
            return default_config

    def _save_ai_model_config(self, config):
        """保存AI模型配置"""
        try:
            with open(self.config_file, 'w', encoding='utf-8') as f:
                json.dump(config, f, ensure_ascii=False, indent=2)
        except Exception as e:
            print(f"保存AI模型配置失败: {e}")

    def _get_current_config(self):
        """获取当前配置"""
        config_name = self.ai_model_config.get("current_config", "默认配置")
        for config in self.ai_model_config.get("configs", []):
            if config.get("name") == config_name:
                return config
        # 如果找不到当前配置，返回第一个配置
        if self.ai_model_config.get("configs"):
            return self.ai_model_config["configs"][0]
        # 如果没有配置，返回默认配置
        return {
            "model_type": "ollama",
            "ollama": {
                "model": "llama3",
                "url": "http://localhost:11434/api/generate"
            },
            "cloud": {
                "api_key": "",
                "api_url": "https://api.example.com/v1/chat/completions"
            }
        }

    def _save_new_config(self, config_name, config_data):
        """保存新配置"""
        # 检查配置名是否已存在
        for config in self.ai_model_config.get("configs", []):
            if config.get("name") == config_name:
                # 更新现有配置
                config.update(config_data)
                break
        else:
            # 添加新配置
            new_config = {
                "name": config_name,
                **config_data
            }
            self.ai_model_config.setdefault("configs", []).append(new_config)
        # 设置为当前配置
        self.ai_model_config["current_config"] = config_name
        # 保存配置
        self._save_ai_model_config(self.ai_model_config)

    def _delete_config(self, config_name):
        """删除配置"""
        configs = self.ai_model_config.get("configs", [])
        new_configs = [config for config in configs if config.get("name") != config_name]
        if new_configs != configs:
            self.ai_model_config["configs"] = new_configs
            # 如果删除的是当前配置，设置第一个配置为当前配置
            if self.ai_model_config.get("current_config") == config_name:
                if new_configs:
                    self.ai_model_config["current_config"] = new_configs[0].get("name")
                else:
                    self.ai_model_config["current_config"] = None
            # 保存配置
            self._save_ai_model_config(self.ai_model_config)
            return True
        return False

    def _init_checks(self):
        """初始化所有检测器"""
        self.scanner.register_check(ConfigChecker())
        self.scanner.register_check(SkillsChecker())
        self.scanner.register_check(PortsChecker())
        self.scanner.register_check(AuthChecker())
        self.scanner.register_check(DepsChecker())
        self.scanner.register_check(HostChecker())
        self.scanner.register_check(SecretsChecker())
        self.scanner.register_check(ProxyChecker())
        self.scanner.register_check(RuntimeChecker())
        self.scanner.register_check(DLPChecker())
        self.scanner.register_check(VulnerabilityChecker())
        self.scanner.register_check(BaselineChecker())

        # 映射检测器到UI控件
        self.check_map = {
            'config': ConfigChecker,
            'skills': SkillsChecker,
            'ports': PortsChecker,
            'auth': AuthChecker,
            'deps': DepsChecker,
            'host': HostChecker,
            'secrets': SecretsChecker,
            'proxy': ProxyChecker,
            'runtime': RuntimeChecker,
            'dlp': DLPChecker,
            'vulnerability': VulnerabilityChecker,
            'baseline': BaselineChecker,
        }

    def _setup_ui(self):
        """设置UI布局"""
        # 顶部标题栏
        self.header = ctk.CTkFrame(self, height=80, fg_color=self.primary_color, corner_radius=16, border_width=3, border_color=self.border_color)
        self.header.pack(fill="x", padx=10, pady=10)


        ctk.CTkLabel(
            self.header,
            text="🦞 焦糖布丁 v4.0",
            font= ("Microsoft YaHei", 24, "bold"),
            text_color="white"
        ).pack(side="left", padx=20)

        # 状态标签
        self.status_label = ctk.CTkLabel(
            self.header,
            text="就绪",
            font=("Microsoft YaHei", 12, "bold"),
            text_color="red"
        )
        self.status_label.pack(side="right", padx=20)

        # 菜单按钮
        self.menu_btn = ctk.CTkButton(
            self.header,
            text="帮助".upper(),
            command=self._open_menu,
            width=80,
            fg_color="#52C41A",
            hover_color="#389e0d",
            text_color="white",
            border_color=self.border_color,
            border_width=3,
            corner_radius=12,
            font= ("Microsoft YaHei", 10, "bold")
        )
        self.menu_btn.pack(side="right", padx=10)

        # 主内容区（左右分栏）
        self.main_frame = ctk.CTkFrame(self, fg_color=self.container_color, corner_radius=16, border_width=3, border_color=self.border_color)
        self.main_frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        # 配置grid布局
        self.main_frame.grid_columnconfigure(0, minsize=500, weight=0)
        self.main_frame.grid_columnconfigure(1, weight=1)
        self.main_frame.grid_rowconfigure(0, weight=1)

        # 左侧控制面板
        self.control_frame = ctk.CTkFrame(self.main_frame, width=500, fg_color=self.container_color, corner_radius=16, border_width=3, border_color=self.border_color)
        self.control_frame.grid(row=0, column=0, sticky="ns", padx=10, pady=10)

        # 创建滚动帧
        self.scrollable_frame = ctk.CTkScrollableFrame(self.control_frame, fg_color=self.container_color, corner_radius=12, width=780)
        self.scrollable_frame.pack(fill="both", expand=True, padx=10, pady=10)

        # OpenClaw安装目录选择
        ctk.CTkLabel(
            self.scrollable_frame,
            text="OpenClaw安装目录",
            font=("Microsoft YaHei", 16, "bold"),
            text_color=self.text_color
        ).pack(pady=10)

        # 目录路径显示
        self.path_frame = ctk.CTkFrame(self.scrollable_frame, fg_color=self.bg_color, corner_radius=12, border_width=3, border_color=self.border_color)
        self.path_frame.pack(fill="x", padx=20, pady=5)

        self.path_label = ctk.CTkLabel(
            self.path_frame,
            text=str(PlatformAdapter.get_openclaw_path()),
            font=('Microsoft YaHei', 10),
            wraplength=400,
            text_color=self.text_color
        )
        self.path_label.pack(side="left", fill="x", expand=True)

        self.browse_btn = ctk.CTkButton(
            self.path_frame,
            text="浏览".upper(),
            command=self._browse_openclaw_path,
            width=60,
            fg_color=self.primary_color,
            hover_color="#389e0d",
            text_color="white",
            border_color=self.border_color,
            border_width=3,
            corner_radius=12,
            font=("Microsoft YaHei", 10, "bold")
        )
        self.browse_btn.pack(side="right")

        # 检测模块标签页
        self.tabview = ctk.CTkTabview(self.scrollable_frame, fg_color=self.container_color, corner_radius=12, border_width=2, border_color=self.border_color)
        self.tabview.pack(fill="both", expand=True, padx=10, pady=10, ipady=10)

        # 添加标签页
        self.tabview.add("甜筒基础防护")
        self.tabview.add("焦糖高级防护")
        self.tabview.add("龙虾安全守卫")

        # 检测项复选框
        self.check_vars = {}

        # 基础安全检测标签页
        basic_tab = self.tabview.tab("甜筒基础防护")
        ctk.CTkLabel(
            basic_tab,
            text="甜筒基础防护",
            font=("Microsoft YaHei", 14, "bold"),
            text_color=self.primary_color
        ).pack(pady=10)

        # 全选/取消全选按钮 - 基础安全
        basic_select_frame = ctk.CTkFrame(basic_tab, fg_color="transparent")
        basic_select_frame.pack(fill="x", padx=20, pady=5)
        
        def select_all_basic():
            for key in ["config", "skills", "ports", "auth", "host"]:
                if key in self.check_vars:
                    self.check_vars[key].set(True)
        
        def deselect_all_basic():
            for key in ["config", "skills", "ports", "auth", "host"]:
                if key in self.check_vars:
                    self.check_vars[key].set(False)
        
        ctk.CTkButton(
            basic_select_frame,
            text="全选",
            command=select_all_basic,
            font=("Microsoft YaHei", 10, "bold"),
            fg_color=self.primary_color,
            hover_color="#52C41A",
            text_color="white",
            border_color=self.border_color,
            border_width=2,
            corner_radius=8
        ).pack(side="left", padx=5, fill="x", expand=True)
        
        ctk.CTkButton(
            basic_select_frame,
            text="取消全选",
            command=deselect_all_basic,
            font=("Microsoft YaHei", 10, "bold"),
            fg_color=self.primary_color,
            hover_color="#52C41A",
            text_color="white",
            border_color=self.border_color,
            border_width=2,
            corner_radius=8
        ).pack(side="left", padx=5, fill="x", expand=True)

        basic_checks = [
            ("配置安全", "config"),
            ("技能包安全", "skills"),
            ("端口暴露", "ports"),
            ("认证口令", "auth"),
            ("主机安全", "host"),
        ]

        for name, key in basic_checks:
            var = ctk.BooleanVar(value=False)  # 默认不勾选
            self.check_vars[key] = var
            ctk.CTkCheckBox(
                basic_tab,
                text=name,
                variable=var,
                font=("Microsoft YaHei", 12),
                text_color=self.text_color,
                fg_color=self.primary_color,
                border_color=self.border_color,
                border_width=3,
                corner_radius=8
            ).pack(anchor="w", padx=20, pady=5)

        # 高级安全检测标签页
        advanced_tab = self.tabview.tab("焦糖高级防护")
        ctk.CTkLabel(
            advanced_tab,
            text="焦糖高级防护",
            font=("Microsoft YaHei", 14, "bold"),
            text_color=self.primary_color
        ).pack(pady=10)

        # 全选/取消全选按钮 - 高级安全
        advanced_select_frame = ctk.CTkFrame(advanced_tab, fg_color="transparent")
        advanced_select_frame.pack(fill="x", padx=20, pady=5)
        
        def select_all_advanced():
            for key in ["deps", "secrets", "proxy", "runtime", "dlp", "vulnerability", "baseline"]:
                if key in self.check_vars:
                    self.check_vars[key].set(True)
        
        def deselect_all_advanced():
            for key in ["deps", "secrets", "proxy", "runtime", "dlp", "vulnerability", "baseline"]:
                if key in self.check_vars:
                    self.check_vars[key].set(False)
        
        ctk.CTkButton(
            advanced_select_frame,
            text="全选",
            command=select_all_advanced,
            font=("Microsoft YaHei", 10, "bold"),
            fg_color=self.primary_color,
            hover_color="#52C41A",
            text_color="white",
            border_color=self.border_color,
            border_width=2,
            corner_radius=8
        ).pack(side="left", padx=5, fill="x", expand=True)
        
        ctk.CTkButton(
            advanced_select_frame,
            text="取消全选",
            command=deselect_all_advanced,
            font=("Microsoft YaHei", 10, "bold"),
            fg_color=self.primary_color,
            hover_color="#52C41A",
            text_color="white",
            border_color=self.border_color,
            border_width=2,
            corner_radius=8
        ).pack(side="left", padx=5, fill="x", expand=True)

        advanced_checks = [
            ("依赖供应链", "deps"),
            ("密钥泄露", "secrets"),
            ("反代配置", "proxy"),
            ("运行时检查", "runtime"),
            ("数据泄露防护", "dlp"),
            ("漏洞扫描", "vulnerability"),
            ("安全基线检查", "baseline"),
        ]

        for name, key in advanced_checks:
            var = ctk.BooleanVar(value=False)  # 默认不勾选
            self.check_vars[key] = var
            ctk.CTkCheckBox(
                advanced_tab,
                text=name,
                variable=var,
                font=("Microsoft YaHei", 12),
                text_color=self.text_color,
                fg_color=self.primary_color,
                border_color=self.border_color,
                border_width=3,
                corner_radius=8
            ).pack(anchor="w", padx=20, pady=5)

        # SecureClaw安全标签页
        secureclaw_tab = self.tabview.tab("龙虾安全守卫")
        ctk.CTkLabel(
            secureclaw_tab,
            text="龙虾安全守卫",
            font=("Microsoft YaHei", 14, "bold"),
            text_color=self.primary_color
        ).pack(pady=10)

        # SecureClaw功能按钮
        self.secureclaw_audit_btn = ctk.CTkButton(
            secureclaw_tab,
            text="🔍 安全审计",
            command=self._run_secureclaw_audit,
            height=32,
            font=("Microsoft YaHei", 11, "bold"),
            fg_color=self.primary_color,
            hover_color="#52C41A",
            text_color="white",
            border_color=self.border_color,
            border_width=2,
            corner_radius=12
        )
        self.secureclaw_audit_btn.pack(fill="x", padx=20, pady=5, expand=True)

        self.secureclaw_harden_btn = ctk.CTkButton(
            secureclaw_tab,
            text="🔧 自动加固",
            command=self._run_secureclaw_harden,
            height=32,
            font=("Microsoft YaHei", 11, "bold"),
            fg_color=self.primary_color,
            hover_color="#52C41A",
            text_color="white",
            border_color=self.border_color,
            border_width=2,
            corner_radius=12
        )
        self.secureclaw_harden_btn.pack(fill="x", padx=20, pady=5, expand=True)

        self.secureclaw_skill_scan_btn = ctk.CTkButton(
            secureclaw_tab,
            text="🔍 技能扫描",
            command=self._run_secureclaw_skill_scan,
            height=32,
            font=("Microsoft YaHei", 11, "bold"),
            fg_color=self.primary_color,
            hover_color="#52C41A",
            text_color="white",
            border_color=self.border_color,
            border_width=2,
            corner_radius=12
        )
        self.secureclaw_skill_scan_btn.pack(fill="x", padx=20, pady=5, expand=True)

        self.secureclaw_integrity_btn = ctk.CTkButton(
            secureclaw_tab,
            text="🔍 完整性检查",
            command=self._run_secureclaw_integrity,
            height=32,
            font=("Microsoft YaHei", 11, "bold"),
            fg_color=self.primary_color,
            hover_color="#52C41A",
            text_color="white",
            border_color=self.border_color,
            border_width=2,
            corner_radius=12
        )
        self.secureclaw_integrity_btn.pack(fill="x", padx=20, pady=5, expand=True)

        self.secureclaw_privacy_btn = ctk.CTkButton(
            secureclaw_tab,
            text="🔍 隐私检查",
            command=self._run_secureclaw_privacy,
            height=32,
            font= ("Microsoft YaHei", 11, "bold"),
            fg_color=self.primary_color,
            hover_color="#52C41A",
            text_color="white",
            border_color=self.border_color,
            border_width=2,
            corner_radius=12
        )
        self.secureclaw_privacy_btn.pack(fill="x", padx=20, pady=5, expand=True)

        self.secureclaw_behavior_btn = ctk.CTkButton(
            secureclaw_tab,
            text="🔍 行为规则检查",
            command=self._run_secureclaw_behavior_rules,
            height=32,
            font= ("Microsoft YaHei", 11, "bold"),
            fg_color=self.primary_color,
            hover_color="#52C41A",
            text_color="white",
            border_color=self.border_color,
            border_width=2,
            corner_radius=12
        )
        self.secureclaw_behavior_btn.pack(fill="x", padx=20, pady=5, expand=True)

        # 报告导出按钮
        ctk.CTkLabel(
            secureclaw_tab,
            text="导出报告",
            font=("Microsoft YaHei", 14, "bold"),
            text_color=self.primary_color
        ).pack(pady=10)

        self.export_secureclaw_audit_report_btn = ctk.CTkButton(
            secureclaw_tab,
            text="📄 导出审计报告",
            command=self._export_secureclaw_audit_report,
            state="disabled",
            height=32,
            font= ("Microsoft YaHei", 11, "bold"),
            fg_color=self.primary_color,
            hover_color="#52C41A",
            text_color="white",
            border_color=self.border_color,
            border_width=2,
            corner_radius=12
        )
        self.export_secureclaw_audit_report_btn.pack(fill="x", padx=20, pady=5, expand=True)

        self.export_secureclaw_harden_report_btn = ctk.CTkButton(
            secureclaw_tab,
            text="📄 导出加固报告",
            command=self._export_secureclaw_harden_report,
            state="disabled",
            height=32,
            font= ("Microsoft YaHei", 11, "bold"),
            fg_color=self.primary_color,
            hover_color="#52C41A",
            text_color="white",
            border_color=self.border_color,
            border_width=2,
            corner_radius=12
        )
        self.export_secureclaw_harden_report_btn.pack(fill="x", padx=20, pady=5, expand=True)

        self.export_secureclaw_skill_scan_report_btn = ctk.CTkButton(
            secureclaw_tab,
            text="📄 导出技能扫描报告",
            command=self._export_secureclaw_skill_scan_report,
            state="disabled",
            height=32,
            font= ("Microsoft YaHei", 11, "bold"),
            fg_color=self.primary_color,
            hover_color="#52C41A",
            text_color="white",
            border_color=self.border_color,
            border_width=2,
            corner_radius=12
        )
        self.export_secureclaw_skill_scan_report_btn.pack(fill="x", padx=20, pady=5, expand=True)

        self.export_secureclaw_integrity_report_btn = ctk.CTkButton(
            secureclaw_tab,
            text="📄 导出完整性报告",
            command=self._export_secureclaw_integrity_report,
            state="disabled",
            height=32,
            font= ("Microsoft YaHei", 11, "bold"),
            fg_color=self.primary_color,
            hover_color="#52C41A",
            text_color="white",
            border_color=self.border_color,
            border_width=2,
            corner_radius=12
        )
        self.export_secureclaw_integrity_report_btn.pack(fill="x", padx=20, pady=5, expand=True)

        self.export_secureclaw_privacy_report_btn = ctk.CTkButton(
            secureclaw_tab,
            text="📄 导出隐私报告",
            command=self._export_secureclaw_privacy_report,
            state="disabled",
            height=32,
            font= ("Microsoft YaHei", 11, "bold"),
            fg_color=self.primary_color,
            hover_color="#52C41A",
            text_color="white",
            border_color=self.border_color,
            border_width=2,
            corner_radius=12
        )
        self.export_secureclaw_privacy_report_btn.pack(fill="x", padx=20, pady=5, expand=True)

        self.export_secureclaw_behavior_report_btn = ctk.CTkButton(
            secureclaw_tab,
            text="📄 导出行为规则报告",
            command=self._export_secureclaw_behavior_report,
            state="disabled",
            height=32,
            font= ("Microsoft YaHei", 11, "bold"),
            fg_color=self.primary_color,
            hover_color="#52C41A",
            text_color="white",
            border_color=self.border_color,
            border_width=2,
            corner_radius=12
        )
        self.export_secureclaw_behavior_report_btn.pack(fill="x", padx=20, pady=5, expand=True)

        # 修复按钮
        self.fix_btn = ctk.CTkButton(
            self.scrollable_frame,
            text="🔧 修复选中风险".upper(),
            command=self._open_fix_dialog,
            state="disabled",
            height=32,
            font=("Microsoft YaHei", 11, "bold"),
            fg_color=self.primary_color,
            hover_color="#52C41A",
            text_color="white",
            border_color=self.border_color,
            border_width=2,
            corner_radius=12
        )
        self.fix_btn.pack(fill="x", padx=20, pady=5, expand=True)

        # 进度条
        self.progress = ctk.CTkProgressBar(
            self.scrollable_frame,
            fg_color=self.bg_color,
            progress_color=self.primary_color,
            border_color=self.border_color,
            border_width=2,
            corner_radius=10
        )
        self.progress.pack(fill="x", padx=20, pady=10)
        self.progress.set(0)

        # 按钮区
        self.scan_btn = ctk.CTkButton(
            self.scrollable_frame,
            text="🔍 开始全面检测".upper(),
            command=self._start_scan,
            height=36,
            font=("Microsoft YaHei", 12, "bold"),
            fg_color=self.primary_color,
            hover_color="#389e0d",
            text_color="white",
            border_color=self.border_color,
            border_width=2,
            corner_radius=12
        )
        self.scan_btn.pack(fill="x", padx=20, pady=5, expand=True)

        self.export_html_btn = ctk.CTkButton(
            self.scrollable_frame,
            text="📄 导出HTML报告".upper(),
            command=lambda: self._export_report("html"),
            state="disabled",
            height=32,
            font=("Microsoft YaHei", 11, "bold"),
            fg_color=self.primary_color,
            hover_color="#389e0d",
            text_color="white",
            border_color=self.border_color,
            border_width=2,
            corner_radius=12
        )
        self.export_html_btn.pack(fill="x", padx=20, pady=3, expand=True)

        self.export_json_btn = ctk.CTkButton(
            self.scrollable_frame,
            text="📄 导出JSON报告".upper(),
            command=lambda: self._export_report("json"),
            state="disabled",
            height=32,
            font=("Microsoft YaHei", 11, "bold"),
            fg_color=self.primary_color,
            hover_color="#389e0d",
            text_color="white",
            border_color=self.border_color,
            border_width=2,
            corner_radius=12
        )
        self.export_json_btn.pack(fill="x", padx=20, pady=3, expand=True)

        self.ai_audit_btn = ctk.CTkButton(
            self.scrollable_frame,
            text="🤖 AI深度审计".upper(),
            command=self._generate_ai_audit,
            state="disabled",
            height=32,
            font=("Microsoft YaHei", 11, "bold"),
            fg_color=self.primary_color,
            hover_color="#389e0d",
            text_color="white",
            border_color=self.border_color,
            border_width=2,
            corner_radius=12
        )
        self.ai_audit_btn.pack(fill="x", padx=20, pady=3, expand=True)

        # 统计信息
        self.stats_frame = ctk.CTkFrame(self.scrollable_frame, fg_color=self.card_color, corner_radius=12, border_width=2, border_color=self.border_color)
        self.stats_frame.pack(fill="both", expand=True, padx=20, pady=10)

        self.stats_label = ctk.CTkLabel(
            self.stats_frame,
            text="检测统计:\n总计: 0",
            font=("Microsoft YaHei", 11, "bold"),
            text_color=self.text_color,
            justify="left"
        )
        self.stats_label.pack(fill="both", expand=True, pady=8, padx=8)

        # 右侧结果展示区
        self.result_frame = ctk.CTkFrame(self.main_frame, fg_color=self.container_color, corner_radius=16, border_width=3, border_color=self.border_color)
        self.result_frame.grid(row=0, column=1, sticky="nsew", padx=10, pady=10)

        # 结果表格
        self._setup_result_table()

    def _setup_result_table(self):
        """设置结果表格"""
        # 使用ttk.Treeview
        self.tree_frame = ctk.CTkFrame(self.result_frame, fg_color=self.bg_color, corner_radius=12, border_width=3, border_color=self.border_color)
        self.tree_frame.pack(fill="both", expand=True, padx=10, pady=10)

        columns = ("risk", "check", "finding", "time")
        self.tree = ttk.Treeview(
            self.tree_frame,
            columns=columns,
            show="headings",
            height=20,
            selectmode="extended"
        )

        # 设置字体大小和样式
        style = ttk.Style()
        style.configure("Treeview", 
                      font=("Microsoft YaHei", 12),
                      background=self.bg_color,
                      foreground=self.text_color,
                      rowheight=34)
        style.configure("Treeview.Heading", 
                      font=("Microsoft YaHei", 14, "bold"),
                      background=self.primary_color,
                      foreground="#2C2C2C",
                      relief="flat")
        style.map("Treeview", 
                 background=[("selected", self.selected_color)],
                 foreground=[("selected", self.text_color)])

        # 设置列
        self.tree.heading("risk", text="风险等级")
        self.tree.heading("check", text="检测项")
        self.tree.heading("finding", text="详情")
        self.tree.heading("time", text="时间")

        # 调整列宽
        self.tree.column("risk", width=120, minwidth=100)
        self.tree.column("check", width=180, minwidth=150)
        self.tree.column("finding", width=600, minwidth=400)
        self.tree.column("time", width=180, minwidth=150)

        # 滚动条
        scrollbar = ttk.Scrollbar(self.tree_frame, command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)

        self.tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        # 设置行颜色标签
        self.tree.tag_configure("CRITICAL", background=self.error_color, foreground="white", font=("Microsoft YaHei", 12, "bold"))
        self.tree.tag_configure("HIGH", background=self.error_color, foreground="white", font=("Microsoft YaHei", 12, "bold"))
        self.tree.tag_configure("MEDIUM", background=self.warning_color, foreground=self.text_color, font=("Microsoft YaHei", 12, "bold"))
        self.tree.tag_configure("LOW", background=self.success_color, foreground="white", font=("Microsoft YaHei", 12))
        self.tree.tag_configure("INFO", background=self.info_color, foreground="white", font=("Microsoft YaHei", 12))

    def _start_scan(self):
        """开始扫描"""
        if self.scanner.is_running:
            return

        # 清空之前的结果
        for item in self.tree.get_children():
            self.tree.delete(item)

        # 获取选中的检测项
        selected_checks = []
        for key, var in self.check_vars.items():
            if var.get():
                check_class = self.check_map[key]
                selected_checks.append(check_class())

        if not selected_checks:
            messagebox.showwarning("提示", "请至少选择一个检测项")
            return

        # 更新UI状态
        self.scan_btn.configure(state="disabled", text="检测中...")
        self.export_html_btn.configure(state="disabled")
        self.export_json_btn.configure(state="disabled")
        self.progress.set(0)
        self.stats_label.configure(text="检测统计:\n总计: 0")

        # 在新线程中运行扫描
        thread = threading.Thread(target=self._run_scan_thread, args=(selected_checks,))
        thread.daemon = True
        thread.start()

    def _run_scan_thread(self, selected_checks):
        """扫描线程"""
        import asyncio

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        def update_progress(msg, val):
            self.after(0, lambda: self._update_ui(msg, val))

        results = loop.run_until_complete(
            self.scanner.run_selected(selected_checks, progress_callback=update_progress, fix=False)
        )

        self.after(0, lambda: self._scan_complete(results))

    def _update_ui(self, message, value):
        """更新UI"""
        self.status_label.configure(text=message)
        self.progress.set(value / 100)

    def _scan_complete(self, results):
        """扫描完成"""
        self.scan_btn.configure(state="normal", text="🔍 开始全面检测")
        self.export_html_btn.configure(state="normal")
        self.export_json_btn.configure(state="normal")
        self.ai_audit_btn.configure(state="normal")
        self.fix_btn.configure(state="normal")
        self.progress.set(1.0)
        self.status_label.configure(text=f"检测完成，发现 {len(results)} 个问题")

        # 填充结果
        for finding in results:
            self.tree.insert(
                "",
                "end",
                values=(
                    finding['risk'],
                    finding['check'],
                    finding['finding'],
                    finding['timestamp']
                ),
                tags=(finding['risk'],)
            )

        self.current_results = results

        # 更新统计信息
        summary = self.scanner.get_summary(results)
        stats_text = f"""检测统计:
总计: {summary['total']}
严重: {summary['critical']}
高危: {summary['high']}
中危: {summary['medium']}
低危: {summary['low']}
信息: {summary['info']}"""
        self.stats_label.configure(text=stats_text)

        # 如果有CRITICAL风险，弹窗警告
        critical_count = sum(1 for r in results if r['risk'] == 'CRITICAL')
        high_count = sum(1 for r in results if r['risk'] == 'HIGH')

        if critical_count > 0:
            messagebox.showwarning(
                "严重风险警告",
                f"发现 {critical_count} 个严重安全风险！\n请立即处理！"
            )
        elif high_count > 0:
            messagebox.showwarning(
                "高危风险提醒",
                f"发现 {high_count} 个高危安全风险！\n建议尽快处理！"
            )

    def _export_report(self, format_type):
        """导出报告"""
        file_types = {
            "html": [("HTML文件", "*.html"), ("所有文件", "*.*")],
            "json": [("JSON文件", "*.json"), ("所有文件", "*.*")],
        }

        file_path = filedialog.asksaveasfilename(
            defaultextension=f".{format_type}",
            filetypes=file_types.get(format_type, [("所有文件", "*.*")])
        )

        if file_path:
            try:
                content = self.scanner.generate_report(self.current_results, format_type)
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(content)

                messagebox.showinfo(
                    "导出成功",
                    f"报告已保存至:\n{file_path}"
                )
            except Exception as e:
                messagebox.showerror("导出失败", f"导出报告时出错:\n{str(e)}")

    def _run_secureclaw_audit(self):
        """运行🦞 焦糖布丁安全审计"""
        openclaw_dir = str(PlatformAdapter.get_openclaw_path())
        if not os.path.exists(openclaw_dir):
            messagebox.showwarning("提示", "OpenClaw目录不存在，请先设置正确的目录")
            return

        # 更新状态
        self.status_label.configure(text="正在执行安全审计...")
        self.secureclaw_audit_btn.configure(state="disabled")

        # 在新线程中运行
        def run_audit():
            try:
                result = self.scanner.run_secureclaw_audit(openclaw_dir)
                self.after(0, lambda: self._secureclaw_audit_complete(result))
            except Exception as e:
                self.after(0, lambda: messagebox.showerror("错误", f"安全审计失败:\n{str(e)}"))
                self.after(0, lambda: self.status_label.configure(text="就绪"))
                self.after(0, lambda: self.secureclaw_audit_btn.configure(state="normal"))

        thread = threading.Thread(target=run_audit)
        thread.daemon = True
        thread.start()

    def _secureclaw_audit_complete(self, result):
        """安全审计完成"""
        self.status_label.configure(text="安全审计完成")
        self.secureclaw_audit_btn.configure(state="normal")

        # 存储结果并启用导出按钮
        self.secureclaw_audit_result = result
        self.export_secureclaw_audit_report_btn.configure(state="normal")

        # 显示审计结果
        score = result.get("score", 0)
        passed_checks = result.get("passed_checks", 0)
        total_checks = result.get("total_checks", 0)
        results = result.get("results", {})

        # 创建结果对话框
        dialog = ctk.CTkToplevel(self)
        dialog.title("SecureClaw安全审计结果")
        dialog.geometry("800x600")
        dialog.transient(self)
        dialog.grab_set()

        # 设置对话框样式
        dialog.configure(fg_color=self.bg_color)

        # 滚动帧
        scroll_frame = ctk.CTkScrollableFrame(dialog, fg_color=self.container_color, corner_radius=16, border_width=3, border_color=self.border_color)
        scroll_frame.pack(fill="both", expand=True, padx=10, pady=10)

        # 评分信息
        score_frame = ctk.CTkFrame(scroll_frame, fg_color=self.container_color, corner_radius=12, border_width=2, border_color=self.border_color)
        score_frame.pack(fill="x", padx=10, pady=10)

        ctk.CTkLabel(
            score_frame,
            text=f"安全评分: {score}/100",
            font=("Microsoft YaHei", 16, "bold"),
            text_color=self.text_color
        ).pack(pady=10)

        ctk.CTkLabel(
            score_frame,
            text=f"通过检查: {passed_checks}/{total_checks}",
            font=("Microsoft YaHei", 12),
            text_color=self.text_color
        ).pack(pady=5)

        # 详细结果
        ctk.CTkLabel(
            scroll_frame,
            text="详细检查结果:",
            font=("Microsoft YaHei", 14, "bold"),
            text_color=self.primary_color
        ).pack(pady=10)

        for check_name, check_result in results.items():
            status = check_result.get("status")
            message = check_result.get("message")
            severity = check_result.get("severity")

            # 状态颜色
            if status == "PASS":
                status_color = self.success_color
            elif status == "FAIL":
                status_color = self.error_color
            elif status == "WARN":
                status_color = self.warning_color
            else:
                status_color = self.info_color

            # 创建检查结果帧
            check_frame = ctk.CTkFrame(scroll_frame, fg_color=self.container_color, corner_radius=12, border_width=2, border_color=self.border_color)
            check_frame.pack(fill="x", padx=10, pady=5)

            ctk.CTkLabel(
                check_frame,
                text=check_name,
                font=("Microsoft YaHei", 12, "bold"),
                text_color=self.text_color,
                width=150
            ).pack(side="left", padx=10, pady=5)

            ctk.CTkLabel(
                check_frame,
                text=status,
                font=("Microsoft YaHei", 12, "bold"),
                text_color=status_color,
                width=100
            ).pack(side="left", padx=10, pady=5)

            ctk.CTkLabel(
                check_frame,
                text=message,
                font=("Microsoft YaHei", 10),
                text_color=self.text_color,
                wraplength=400
            ).pack(side="left", fill="x", expand=True, padx=10, pady=5)

        # 关闭按钮
        ctk.CTkButton(
            dialog,
            text="关闭",
            command=dialog.destroy,
            height=32,
            font=("Microsoft YaHei", 11, "bold"),
            fg_color=self.primary_color,
            hover_color="#52C41A",
            text_color="white",
            border_color=self.border_color,
            border_width=2,
            corner_radius=12
        ).pack(fill="x", padx=10, pady=10)

    def _run_secureclaw_harden(self):
        """运行🦞 焦糖布丁自动加固"""
        openclaw_dir = str(PlatformAdapter.get_openclaw_path())
        if not os.path.exists(openclaw_dir):
            messagebox.showwarning("提示", "OpenClaw目录不存在，请先设置正确的目录")
            return

        # 更新状态
        self.status_label.configure(text="正在执行自动加固...")
        self.secureclaw_harden_btn.configure(state="disabled")

        # 在新线程中运行
        def run_harden():
            try:
                result = self.scanner.run_secureclaw_harden(openclaw_dir)
                self.after(0, lambda: self._secureclaw_harden_complete(result))
            except Exception as e:
                self.after(0, lambda: messagebox.showerror("错误", f"自动加固失败:\n{str(e)}"))
                self.after(0, lambda: self.status_label.configure(text="就绪"))
                self.after(0, lambda: self.secureclaw_harden_btn.configure(state="normal"))

        thread = threading.Thread(target=run_harden)
        thread.daemon = True
        thread.start()

    def _secureclaw_harden_complete(self, result):
        """自动加固完成"""
        self.status_label.configure(text="自动加固完成")
        self.secureclaw_harden_btn.configure(state="normal")

        # 存储结果并启用导出按钮
        self.secureclaw_harden_result = result
        self.export_secureclaw_harden_report_btn.configure(state="normal")

        # 显示加固结果
        backup = result.get("backup", "")

        # 创建结果对话框
        dialog = ctk.CTkToplevel(self)
        dialog.title("SecureClaw自动加固结果")
        dialog.geometry("800x600")
        dialog.transient(self)
        dialog.grab_set()

        # 设置对话框样式
        dialog.configure(fg_color=self.bg_color)

        # 滚动帧
        scroll_frame = ctk.CTkScrollableFrame(dialog, fg_color=self.container_color, corner_radius=16, border_width=3, border_color=self.border_color)
        scroll_frame.pack(fill="both", expand=True, padx=10, pady=10)

        # 备份信息
        if backup:
            ctk.CTkLabel(
                scroll_frame,
                text=f"备份创建: {backup}",
                font=("Microsoft YaHei", 12),
                text_color=self.info_color
            ).pack(pady=10)

        # 加固结果
        ctk.CTkLabel(
            scroll_frame,
            text="加固结果:",
            font=("Microsoft YaHei", 14, "bold"),
            text_color=self.primary_color
        ).pack(pady=10)

        for harden_item, item_result in result.items():
            if harden_item == "backup":
                continue

            status = item_result.get("status")
            message = item_result.get("message")

            # 状态颜色
            if status == "SUCCESS":
                status_color = self.success_color
            elif status == "ERROR":
                status_color = self.error_color
            elif status == "WARN":
                status_color = self.warning_color
            else:
                status_color = self.info_color

            # 创建加固结果帧
            harden_frame = ctk.CTkFrame(scroll_frame, fg_color=self.container_color, corner_radius=12, border_width=2, border_color=self.border_color)
            harden_frame.pack(fill="x", padx=10, pady=5)

            ctk.CTkLabel(
                harden_frame,
                text=harden_item,
                font=("Microsoft YaHei", 12, "bold"),
                text_color=self.text_color,
                width=150
            ).pack(side="left", padx=10, pady=5)

            ctk.CTkLabel(
                harden_frame,
                text=status,
                font=("Microsoft YaHei", 12, "bold"),
                text_color=status_color,
                width=100
            ).pack(side="left", padx=10, pady=5)

            ctk.CTkLabel(
                harden_frame,
                text=message,
                font=("Microsoft YaHei", 10),
                text_color=self.text_color,
                wraplength=400
            ).pack(side="left", fill="x", expand=True, padx=10, pady=5)

        # 关闭按钮
        ctk.CTkButton(
            dialog,
            text="关闭",
            command=dialog.destroy,
            height=32,
            font=("Microsoft YaHei", 11, "bold"),
            fg_color=self.primary_color,
            hover_color="#52C41A",
            text_color="white",
            border_color=self.border_color,
            border_width=2,
            corner_radius=12
        ).pack(fill="x", padx=10, pady=10)

    def _run_secureclaw_skill_scan(self):
        """运行🦞 焦糖布丁技能扫描"""
        openclaw_dir = str(PlatformAdapter.get_openclaw_path())
        skills_dir = os.path.join(openclaw_dir, "skills")
        if not os.path.exists(skills_dir):
            messagebox.showwarning("提示", "技能目录不存在，请先设置正确的OpenClaw目录")
            return

        # 更新状态
        self.status_label.configure(text="正在执行技能扫描...")
        self.secureclaw_skill_scan_btn.configure(state="disabled")

        # 在新线程中运行
        def run_scan():
            try:
                result = self.scanner.run_secureclaw_skill_scan(skills_dir)
                self.after(0, lambda: self._secureclaw_skill_scan_complete(result))
            except Exception as e:
                self.after(0, lambda: messagebox.showerror("错误", f"技能扫描失败:\n{str(e)}"))
                self.after(0, lambda: self.status_label.configure(text="就绪"))
                self.after(0, lambda: self.secureclaw_skill_scan_btn.configure(state="normal"))

        thread = threading.Thread(target=run_scan)
        thread.daemon = True
        thread.start()

    def _secureclaw_skill_scan_complete(self, result):
        """技能扫描完成"""
        self.status_label.configure(text="技能扫描完成")
        self.secureclaw_skill_scan_btn.configure(state="normal")

        # 存储结果并启用导出按钮
        self.secureclaw_skill_scan_result = result
        self.export_secureclaw_skill_scan_report_btn.configure(state="normal")

        # 显示扫描结果
        scanned_skills = result.get("scanned_skills", [])
        suspicious_skills = result.get("suspicious_skills", [])

        # 创建结果对话框
        dialog = ctk.CTkToplevel(self)
        dialog.title("SecureClaw技能扫描结果")
        dialog.geometry("800x600")
        dialog.transient(self)
        dialog.grab_set()

        # 设置对话框样式
        dialog.configure(fg_color=self.bg_color)

        # 滚动帧
        scroll_frame = ctk.CTkScrollableFrame(dialog, fg_color=self.container_color, corner_radius=16, border_width=3, border_color=self.border_color)
        scroll_frame.pack(fill="both", expand=True, padx=10, pady=10)

        # 扫描统计
        ctk.CTkLabel(
            scroll_frame,
            text=f"扫描技能数: {len(scanned_skills)}",
            font=("Microsoft YaHei", 14, "bold"),
            text_color=self.text_color
        ).pack(pady=10)

        ctk.CTkLabel(
            scroll_frame,
            text=f"可疑技能数: {len(suspicious_skills)}",
            font=("Microsoft YaHei", 14, "bold"),
            text_color=self.error_color
        ).pack(pady=5)

        # 详细结果
        ctk.CTkLabel(
            scroll_frame,
            text="技能扫描结果:",
            font=("Microsoft YaHei", 14, "bold"),
            text_color=self.primary_color
        ).pack(pady=10)

        for skill in scanned_skills:
            name = skill.get("name")
            status = skill.get("status")
            issues = skill.get("issues", [])

            # 状态颜色
            if status == "CLEAN":
                status_color = self.success_color
            else:
                status_color = self.error_color

            # 创建技能结果帧
            skill_frame = ctk.CTkFrame(scroll_frame, fg_color=self.container_color, corner_radius=12, border_width=2, border_color=self.border_color)
            skill_frame.pack(fill="x", padx=10, pady=5)

            ctk.CTkLabel(
                skill_frame,
                text=name,
                font=("Microsoft YaHei", 12, "bold"),
                text_color=self.text_color,
                width=150
            ).pack(side="left", padx=10, pady=5)

            ctk.CTkLabel(
                skill_frame,
                text=status,
                font=("Microsoft YaHei", 12, "bold"),
                text_color=status_color,
                width=100
            ).pack(side="left", padx=10, pady=5)

            if issues:
                issues_text = "\n".join(issues)
                ctk.CTkLabel(
                    skill_frame,
                    text=issues_text,
                    font=("Microsoft YaHei", 10),
                    text_color=self.text_color,
                    wraplength=400
                ).pack(side="left", fill="x", expand=True, padx=10, pady=5)
            else:
                ctk.CTkLabel(
                    skill_frame,
                    text="无问题",
                    font=("Microsoft YaHei", 10),
                    text_color=self.text_color
                ).pack(side="left", fill="x", expand=True, padx=10, pady=5)

        # 关闭按钮
        ctk.CTkButton(
            dialog,
            text="关闭",
            command=dialog.destroy,
            height=32,
            font=("Microsoft YaHei", 11, "bold"),
            fg_color=self.primary_color,
            hover_color="#52C41A",
            text_color="white",
            border_color=self.border_color,
            border_width=2,
            corner_radius=12
        ).pack(fill="x", padx=10, pady=10)

    def _run_secureclaw_integrity(self):
        """运行🦞 焦糖布丁文件完整性检查"""
        openclaw_dir = str(PlatformAdapter.get_openclaw_path())
        if not os.path.exists(openclaw_dir):
            messagebox.showwarning("提示", "OpenClaw目录不存在，请先设置正确的目录")
            return

        # 更新状态
        self.status_label.configure(text="正在执行文件完整性检查...")
        self.secureclaw_integrity_btn.configure(state="disabled")

        # 在新线程中运行
        def run_integrity():
            try:
                result = self.scanner.run_secureclaw_integrity(openclaw_dir)
                self.after(0, lambda: self._secureclaw_integrity_complete(result))
            except Exception as e:
                self.after(0, lambda: messagebox.showerror("错误", f"文件完整性检查失败:\n{str(e)}"))
                self.after(0, lambda: self.status_label.configure(text="就绪"))
                self.after(0, lambda: self.secureclaw_integrity_btn.configure(state="normal"))

        thread = threading.Thread(target=run_integrity)
        thread.daemon = True
        thread.start()

    def _secureclaw_integrity_complete(self, result):
        """文件完整性检查完成"""
        self.status_label.configure(text="文件完整性检查完成")
        self.secureclaw_integrity_btn.configure(state="normal")

        # 存储结果并启用导出按钮
        self.secureclaw_integrity_result = result
        self.export_secureclaw_integrity_report_btn.configure(state="normal")

        # 显示检查结果
        status = result.get("status")
        details = result.get("details", [])

        # 创建结果对话框
        dialog = ctk.CTkToplevel(self)
        dialog.title("SecureClaw文件完整性检查结果")
        dialog.geometry("800x600")
        dialog.transient(self)
        dialog.grab_set()

        # 设置对话框样式
        dialog.configure(fg_color=self.bg_color)

        # 滚动帧
        scroll_frame = ctk.CTkScrollableFrame(dialog, fg_color=self.container_color, corner_radius=16, border_width=3, border_color=self.border_color)
        scroll_frame.pack(fill="both", expand=True, padx=10, pady=10)

        # 整体状态
        ctk.CTkLabel(
            scroll_frame,
            text=f"整体状态: {status}",
            font=("Microsoft YaHei", 14, "bold"),
            text_color=self.success_color if status == "INTACT" else self.error_color
        ).pack(pady=10)

        # 详细结果
        ctk.CTkLabel(
            scroll_frame,
            text="文件检查结果:",
            font=("Microsoft YaHei", 14, "bold"),
            text_color=self.primary_color
        ).pack(pady=10)

        for detail in details:
            file = detail.get("file")
            file_status = detail.get("status")
            message = detail.get("message")

            # 状态颜色
            if file_status == "INTACT":
                status_color = self.success_color
            elif file_status == "TAMPERED":
                status_color = self.error_color
            elif file_status == "MISSING":
                status_color = self.error_color
            elif file_status == "NO_BASELINE":
                status_color = self.warning_color
            else:
                status_color = self.info_color

            # 创建文件结果帧
            file_frame = ctk.CTkFrame(scroll_frame, fg_color=self.container_color, corner_radius=12, border_width=2, border_color=self.border_color)
            file_frame.pack(fill="x", padx=10, pady=5)

            ctk.CTkLabel(
                file_frame,
                text=file,
                font=("Microsoft YaHei", 12, "bold"),
                text_color=self.text_color,
                width=150
            ).pack(side="left", padx=10, pady=5)

            ctk.CTkLabel(
                file_frame,
                text=file_status,
                font=("Microsoft YaHei", 12, "bold"),
                text_color=status_color,
                width=100
            ).pack(side="left", padx=10, pady=5)

            ctk.CTkLabel(
                file_frame,
                text=message,
                font=("Microsoft YaHei", 10),
                text_color=self.text_color,
                wraplength=400
            ).pack(side="left", fill="x", expand=True, padx=10, pady=5)

        # 关闭按钮
        ctk.CTkButton(
            dialog,
            text="关闭",
            command=dialog.destroy,
            height=32,
            font=("Microsoft YaHei", 11, "bold"),
            fg_color=self.primary_color,
            hover_color="#52C41A",
            text_color="white",
            border_color=self.border_color,
            border_width=2,
            corner_radius=12
        ).pack(fill="x", padx=10, pady=10)

    def _run_secureclaw_privacy(self):
        """运行🦞 焦糖布丁隐私检查"""
        # 创建文本输入对话框
        dialog = ctk.CTkToplevel(self)
        dialog.title("SecureClaw隐私检查")
        dialog.geometry("800x600")
        dialog.transient(self)
        dialog.grab_set()

        # 设置对话框样式
        dialog.configure(fg_color=self.bg_color)

        # 文本输入
        ctk.CTkLabel(
            dialog,
            text="请输入要检查的文本:",
            font=("Microsoft YaHei", 14, "bold"),
            text_color=self.text_color
        ).pack(pady=10)

        text_input = ctk.CTkTextbox(
            dialog,
            height=300,
            fg_color=self.container_color,
            text_color=self.text_color,
            border_color=self.border_color,
            border_width=2,
            corner_radius=12,
            font=("Microsoft YaHei", 12)
        )
        text_input.pack(fill="x", padx=20, pady=10)

        # 检查按钮
        def check_privacy():
            text = text_input.get("1.0", "end").strip()
            if not text:
                messagebox.showwarning("提示", "请输入要检查的文本")
                return

            # 更新状态
            self.status_label.configure(text="正在执行隐私检查...")
            dialog.destroy()

            # 在新线程中运行
            def run_privacy():
                try:
                    result = self.scanner.run_secureclaw_privacy(text)
                    self.after(0, lambda: self._secureclaw_privacy_complete(result))
                except Exception as e:
                    self.after(0, lambda: messagebox.showerror("错误", f"隐私检查失败:\n{str(e)}"))
                    self.after(0, lambda: self.status_label.configure(text="就绪"))
                    self.after(0, lambda: self.secureclaw_privacy_btn.configure(state="normal"))

            thread = threading.Thread(target=run_privacy)
            thread.daemon = True
            thread.start()

        ctk.CTkButton(
            dialog,
            text="检查隐私",
            command=check_privacy,
            height=32,
            font=("Microsoft YaHei", 11, "bold"),
            fg_color=self.primary_color,
            hover_color="#52C41A",
            text_color="white",
            border_color=self.border_color,
            border_width=2,
            corner_radius=12
        ).pack(fill="x", padx=20, pady=10)

        # 关闭按钮
        ctk.CTkButton(
            dialog,
            text="取消",
            command=dialog.destroy,
            height=32,
            font=("Microsoft YaHei", 11, "bold"),
            fg_color=self.primary_color,
            hover_color="#52C41A",
            text_color="white",
            border_color=self.border_color,
            border_width=2,
            corner_radius=12
        ).pack(fill="x", padx=20, pady=5)

    def _secureclaw_privacy_complete(self, result):
        """隐私检查完成"""
        self.status_label.configure(text="隐私检查完成")
        self.secureclaw_privacy_btn.configure(state="normal")

        # 存储结果并启用导出按钮
        self.secureclaw_privacy_result = result
        self.export_secureclaw_privacy_report_btn.configure(state="normal")

        # 显示检查结果
        status = result.get("status")
        detected_pii = result.get("detected_pii", [])

        # 创建结果对话框
        dialog = ctk.CTkToplevel(self)
        dialog.title("SecureClaw隐私检查结果")
        dialog.geometry("800x600")
        dialog.transient(self)
        dialog.grab_set()

        # 设置对话框样式
        dialog.configure(fg_color=self.bg_color)

        # 滚动帧
        scroll_frame = ctk.CTkScrollableFrame(dialog, fg_color=self.container_color, corner_radius=16, border_width=3, border_color=self.border_color)
        scroll_frame.pack(fill="both", expand=True, padx=10, pady=10)

        # 整体状态
        ctk.CTkLabel(
            scroll_frame,
            text=f"检查结果: {status}",
            font=("Microsoft YaHei", 14, "bold"),
            text_color=self.success_color if status == "CLEAN" else self.error_color
        ).pack(pady=10)

        # 详细结果
        if findings:
            ctk.CTkLabel(
                scroll_frame,
                text="发现的隐私问题:",
                font=("Microsoft YaHei", 14, "bold"),
                text_color=self.primary_color
            ).pack(pady=10)

            for finding in findings:
                severity = finding.get("severity")
                pattern = finding.get("pattern")
                matches = finding.get("matches", [])

                # 严重程度颜色
                if severity == "CRITICAL":
                    severity_color = self.error_color
                elif severity == "HIGH":
                    severity_color = self.error_color
                elif severity == "MEDIUM":
                    severity_color = self.warning_color
                else:
                    severity_color = self.info_color

                # 创建隐私问题帧
                finding_frame = ctk.CTkFrame(scroll_frame, fg_color=self.container_color, corner_radius=12, border_width=2, border_color=self.border_color)
                finding_frame.pack(fill="x", padx=10, pady=5)

                ctk.CTkLabel(
                    finding_frame,
                    text=severity,
                    font=("Microsoft YaHei", 12, "bold"),
                    text_color=severity_color,
                    width=100
                ).pack(side="left", padx=10, pady=5)

                ctk.CTkLabel(
                    finding_frame,
                    text=pattern,
                    font=("Microsoft YaHei", 10),
                    text_color=self.text_color,
                    wraplength=200
                ).pack(side="left", fill="x", expand=True, padx=10, pady=5)

                if matches:
                    matches_text = "匹配: " + ", ".join(matches[:3]) + ("..." if len(matches) > 3 else "")
                    ctk.CTkLabel(
                        finding_frame,
                        text=matches_text,
                        font=("Microsoft YaHei", 10),
                        text_color=self.text_color,
                        wraplength=200
                    ).pack(side="left", padx=10, pady=5)
        else:
            ctk.CTkLabel(
                scroll_frame,
                text="未发现隐私问题",
                font=("Microsoft YaHei", 12),
                text_color=self.success_color
            ).pack(pady=10)

        # 关闭按钮
        ctk.CTkButton(
            dialog,
            text="关闭",
            command=dialog.destroy,
            height=32,
            font=("Microsoft YaHei", 11, "bold"),
            fg_color=self.primary_color,
            hover_color="#52C41A",
            text_color="white",
            border_color=self.border_color,
            border_width=2,
            corner_radius=12
        ).pack(fill="x", padx=10, pady=10)

    def _browse_openclaw_path(self):
        """浏览选择OpenClaw安装目录"""
        selected_dir = filedialog.askdirectory(
            title="选择OpenClaw安装目录",
            initialdir=str(PlatformAdapter.get_openclaw_path())
        )

        if selected_dir:
            # 设置自定义路径
            PlatformAdapter.set_openclaw_path(selected_dir)
            # 更新UI显示
            self.path_label.configure(text=str(PlatformAdapter.get_openclaw_path()))
            # 显示成功消息
            messagebox.showinfo(
                "目录设置成功",
                f"OpenClaw安装目录已设置为:\n{selected_dir}"
            )

    def _open_fix_dialog(self):
        """打开修复对话框"""
        selected_items = self.tree.selection()
        if not selected_items:
            messagebox.showinfo("提示", "请先选择要修复的风险项")
            return

        # 创建修复对话框
        fix_dialog = ctk.CTkToplevel(self)
        fix_dialog.title("修复风险")
        fix_dialog.geometry("600x400")
        fix_dialog.minsize(500, 300)
        fix_dialog.transient(self)
        fix_dialog.grab_set()

        # 设置对话框样式
        fix_dialog.configure(fg_color=self.bg_color)

        # 创建滚动帧
        scrollable_frame = ctk.CTkScrollableFrame(fix_dialog, fg_color=self.container_color, corner_radius=16, border_width=3, border_color=self.border_color)
        scrollable_frame.pack(fill="both", expand=True, padx=10, pady=10)

        # 选择的风险项
        selected_findings = []
        for item in selected_items:
            values = self.tree.item(item, "values")
            finding = next((f for f in self.current_results if f['risk'] == values[0] and f['check'] == values[1] and f['finding'] == values[2]), None)
            if finding:
                selected_findings.append(finding)

        # 修复选项
        fix_vars = []
        for i, finding in enumerate(selected_findings):
            frame = ctk.CTkFrame(scrollable_frame, fg_color=self.container_color, corner_radius=12, border_width=2, border_color=self.border_color)
            frame.pack(fill="x", padx=10, pady=5)

            var = ctk.BooleanVar(value=True)
            fix_vars.append((var, finding))

            # 风险等级标签
            risk_color = self.error_color if finding['risk'] in ['CRITICAL', 'HIGH'] else self.warning_color if finding['risk'] == 'MEDIUM' else self.success_color
            risk_label = ctk.CTkLabel(frame, text=finding['risk'], font=('Microsoft YaHei', 10, 'bold'), text_color=risk_color, width=80)
            risk_label.pack(side="left", padx=10, pady=5)

            # 检查项和发现
            info_frame = ctk.CTkFrame(frame, fg_color="transparent")
            info_frame.pack(side="left", fill="x", expand=True, padx=10, pady=5)

            check_label = ctk.CTkLabel(info_frame, text=finding['check'], font=('Microsoft YaHei', 12, 'bold'), text_color=self.text_color)
            check_label.pack(anchor="w")

            finding_label = ctk.CTkLabel(info_frame, text=finding['finding'], font=('Microsoft YaHei', 10), text_color=self.text_color, wraplength=300)
            finding_label.pack(anchor="w", pady=(2, 0))

            # 修复方案
            fix_suggestion = self.scanner._get_fix_suggestion(finding)
            fix_label = ctk.CTkLabel(info_frame, text="修复方案:", font=('Microsoft YaHei', 10, 'bold'), text_color=self.primary_color)
            fix_label.pack(anchor="w", pady=(5, 0))
            
            # 真实修复操作
            real_fix_operation = ""
            if finding['check'] == '配置安全检测':
                if '硬编码API Key' in finding['finding']:
                    real_fix_operation = "1. 检查并移除硬编码的API Key\n2. 建议移至环境变量"
                elif '配置文件权限过于宽松' in finding['finding']:
                    real_fix_operation = "1. 将配置文件权限设置为600\n2. 命令: chmod 600 openclaw.json"
                elif '沙箱已关闭' in finding['finding']:
                    real_fix_operation = "1. 在openclaw.json中启用沙箱\n2. 设置: \"sandbox\": true"
                else:
                    real_fix_operation = "1. 修复配置文件权限\n2. 修复危险配置标志\n3. 启用认证和安全设置"
            elif finding['check'] == '技能包安全检测':
                if '恶意代码' in finding['finding'] or '恶意技能包' in finding['finding']:
                    real_fix_operation = "1. 移除恶意技能包\n2. 清理技能包目录"
                elif '权限过高' in finding['finding']:
                    real_fix_operation = "1. 审查技能包权限\n2. 移除不必要的危险权限"
                else:
                    real_fix_operation = "1. 移除恶意技能包\n2. 审查技能包权限"
            elif finding['check'] == '端口暴露检测':
                real_fix_operation = "1. 修改绑定地址为loopback\n2. 配置防火墙规则\n3. 启用认证"
            elif finding['check'] == '认证与口令检测':
                real_fix_operation = "1. 配置强密码\n2. 启用认证模式\n3. 定期轮换密码"
            elif finding['check'] == '依赖供应链检测':
                real_fix_operation = "1. 运行npm audit fix或pnpm audit fix\n2. 更新依赖到最新版本"
            elif finding['check'] == '主机安全检测':
                real_fix_operation = "1. 启用防火墙\n2. 以最小权限运行OpenClaw\n3. 更新系统补丁"
            elif finding['check'] == '密钥泄露检测':
                real_fix_operation = "1. 搜索并移除硬编码密钥\n2. 使用环境变量存储敏感信息"
            elif finding['check'] == '反代配置检测':
                real_fix_operation = "1. 审查反向代理配置\n2. 启用HTTPS\n3. 配置适当的认证"
            elif finding['check'] == '运行时检查':
                real_fix_operation = "1. 重启OpenClaw服务\n2. 检查日志文件\n3. 修复运行时异常"
            elif finding['check'] == '数据泄露防护检测':
                real_fix_operation = "1. 实施数据加密\n2. 配置访问控制\n3. 定期审计数据处理"
            elif finding['check'] == '漏洞扫描':
                if 'CVE-2026-25253' in finding['finding']:
                    real_fix_operation = "1. 启用认证模式\n2. 设置: \"auth.mode\": \"token\"\n3. 更新OpenClaw到最新版本"
                elif '默认暴露公网' in finding['finding']:
                    real_fix_operation = "1. 修改绑定地址为loopback\n2. 配置防火墙规则\n3. 启用认证"
                elif '插件投毒' in finding['finding']:
                    real_fix_operation = "1. 移除可疑技能包\n2. 只使用来自可信来源的技能包\n3. 运行: openclaw skills verify"
                elif '权限失控' in finding['finding']:
                    real_fix_operation = "1. 配置权限控制\n2. 禁用allowAll权限\n3. 遵循最小权限原则"
                elif '架构缺陷' in finding['finding']:
                    real_fix_operation = "1. 启用沙箱\n2. 配置网络隔离\n3. 设置资源限制"
                else:
                    real_fix_operation = "1. 更新OpenClaw到最新版本\n2. 应用安全补丁\n3. 定期进行漏洞扫描"
            else:
                real_fix_operation = "执行相应的修复操作"
            
            # 显示真实修复操作
            real_fix_label = ctk.CTkLabel(info_frame, text="真实修复操作:", font=('Microsoft YaHei', 10, 'bold'), text_color="red")
            real_fix_label.pack(anchor="w", pady=(5, 0))
            real_fix_content = ctk.CTkLabel(info_frame, text=real_fix_operation, font=('Microsoft YaHei', 9), text_color=self.text_color, wraplength=280)
            real_fix_content.pack(anchor="w")

            # 修复复选框
            checkbox = ctk.CTkCheckBox(frame, variable=var, fg_color=self.primary_color, border_color=self.border_color, border_width=2, corner_radius=8)
            checkbox.pack(side="right", padx=10, pady=5)

        # 修复按钮
        def perform_fix():
            fix_dialog.destroy()
            self._perform_fix([f for var, f in fix_vars if var.get()])

        fix_button = ctk.CTkButton(fix_dialog, text="执行修复".upper(), command=perform_fix, height=40, font=('Microsoft YaHei', 12, 'bold'), fg_color=self.primary_color, hover_color="#52C41A", text_color="white", border_color=self.border_color, border_width=3, corner_radius=16)
        fix_button.pack(fill="x", padx=10, pady=10)

    def _perform_fix(self, findings):
        """执行修复"""
        if not findings:
            return

        # 更新状态
        self.status_label.configure(text="正在修复...")
        self.fix_btn.configure(state="disabled")

        # 按检查类型分组，避免重复修复
        check_types = {}
        for finding in findings:
            check_name = finding['check']
            if check_name not in check_types:
                check_types[check_name] = []
            check_types[check_name].append(finding)

        # 执行修复
        fixed_count = 0
        for check_name, findings_list in check_types.items():
            try:
                # 根据检测项执行不同的修复
                if check_name == '配置安全检测':
                    # 配置文件修复
                    from checks.config_check import ConfigChecker
                    checker = ConfigChecker()
                    # 先运行检测以初始化必要属性
                    import asyncio
                    asyncio.run(checker.run())
                    # 执行修复
                    asyncio.run(checker.fix())
                    fixed_count += len(findings_list)
                
                elif check_name == '技能包安全检测':
                    # 技能包修复
                    from checks.skills_check import SkillsChecker
                    checker = SkillsChecker()
                    import asyncio
                    asyncio.run(checker.run())
                    asyncio.run(checker.fix())
                    fixed_count += len(findings_list)
                
                elif check_name == '端口暴露检测':
                    # 端口配置修复
                    from checks.ports_check import PortsChecker
                    checker = PortsChecker()
                    import asyncio
                    asyncio.run(checker.run())
                    asyncio.run(checker.fix())
                    fixed_count += len(findings_list)
                
                elif check_name == '认证与口令检测':
                    # 认证配置修复
                    from checks.auth_check import AuthChecker
                    checker = AuthChecker()
                    import asyncio
                    asyncio.run(checker.run())
                    asyncio.run(checker.fix())
                    fixed_count += len(findings_list)
                
                elif check_name == '依赖供应链检测':
                    # 依赖更新
                    from checks.deps_check import DepsChecker
                    checker = DepsChecker()
                    import asyncio
                    asyncio.run(checker.run())
                    asyncio.run(checker.fix())
                    fixed_count += len(findings_list)
                
                elif check_name == '主机安全检测':
                    # 主机安全修复
                    from checks.host_check import HostChecker
                    checker = HostChecker()
                    import asyncio
                    asyncio.run(checker.run())
                    asyncio.run(checker.fix())
                    fixed_count += len(findings_list)
                
                elif check_name == '密钥泄露检测':
                    # 密钥泄露修复
                    from checks.secrets_check import SecretsChecker
                    checker = SecretsChecker()
                    import asyncio
                    asyncio.run(checker.run())
                    asyncio.run(checker.fix())
                    fixed_count += len(findings_list)
                
                elif check_name == '反代配置检测':
                    # 反代配置修复
                    from checks.proxy_check import ProxyChecker
                    checker = ProxyChecker()
                    import asyncio
                    asyncio.run(checker.run())
                    asyncio.run(checker.fix())
                    fixed_count += len(findings_list)
                
                elif check_name == '运行时检查':
                    # 运行时修复
                    from checks.runtime_check import RuntimeChecker
                    checker = RuntimeChecker()
                    import asyncio
                    asyncio.run(checker.run())
                    asyncio.run(checker.fix())
                    fixed_count += len(findings_list)
                
                elif check_name == '数据泄露防护检测':
                    # DLP修复
                    from checks.dlp_check import DLPChecker
                    checker = DLPChecker()
                    import asyncio
                    asyncio.run(checker.run())
                    asyncio.run(checker.fix())
                    fixed_count += len(findings_list)
                
                elif check_name == '漏洞扫描':
                    # 漏洞修复
                    from checks.vulnerability_check import VulnerabilityChecker
                    checker = VulnerabilityChecker()
                    import asyncio
                    asyncio.run(checker.run())
                    asyncio.run(checker.fix())
                    fixed_count += len(findings_list)
                
                elif check_name == '安全基线检查':
                    # 安全基线修复
                    from checks.baseline_check import BaselineChecker
                    checker = BaselineChecker()
                    import asyncio
                    asyncio.run(checker.run())
                    asyncio.run(checker.fix())
                    fixed_count += len(findings_list)
                
                else:
                    # 其他检测项的修复逻辑
                    print(f"暂不支持{check_name}的自动修复")
                    
            except Exception as e:
                print(f"修复{check_name}失败: {e}")

        # 更新状态
        self.status_label.configure(text=f"修复完成，成功修复 {fixed_count} 个问题")
        messagebox.showinfo("修复完成", f"成功修复 {fixed_count} 个问题")

        # 重新扫描以更新结果
        self._start_scan()

    def _open_menu(self):
        """打开帮助菜单"""
        # 创建菜单对话框
        menu_dialog = ctk.CTkToplevel(self)
        menu_dialog.title("帮助中心")
        menu_dialog.geometry("1000x800")
        menu_dialog.minsize(900, 700)
        menu_dialog.transient(self)
        menu_dialog.grab_set()

        # 设置对话框样式
        menu_dialog.configure(fg_color=self.bg_color)

        # 创建标签页
        tabview = ctk.CTkTabview(menu_dialog, fg_color=self.container_color, corner_radius=16, border_width=3, border_color=self.border_color)
        tabview.pack(fill="both", expand=True, padx=10, pady=10)

        # 添加标签页
        tabview.add("使用手册")
        tabview.add("修复实现")
        tabview.add("关于工具")
        tabview.add("改进建议")

        # 使用手册标签页
        manual_tab = tabview.tab("使用手册")
        manual_frame = ctk.CTkScrollableFrame(manual_tab, fg_color=self.container_color, corner_radius=12, border_width=2, border_color=self.border_color)
        manual_frame.pack(fill="both", expand=True, padx=10, pady=10)

        # 使用手册内容
        manual_title = ctk.CTkLabel(manual_frame, text="🦞 焦糖布丁 v4.0使用手册", font=("Microsoft YaHei", 18, "bold"), text_color=self.text_color)
        manual_title.pack(pady=20)

        # 快速开始
        start_section = ctk.CTkFrame(manual_frame, fg_color=self.container_color, corner_radius=12, border_width=2, border_color=self.border_color)
        start_section.pack(fill="x", padx=10, pady=10)
        start_title = ctk.CTkLabel(start_section, text="快速开始", font=("Microsoft YaHei", 16, "bold"), text_color=self.primary_color)
        start_title.pack(padx=10, pady=10)

        start_content = """
1. 选择OpenClaw安装目录：点击"浏览"按钮选择OpenClaw的安装目录
2. 选择检测维度：勾选需要检测的安全维度
3. 开始检测：点击"开始全面检测"按钮启动安全扫描
4. 查看结果：扫描完成后，在右侧表格中查看检测结果
5. 导出报告：点击"导出HTML报告"或"导出JSON报告"保存检测报告
6. 修复风险：选择发现的风险项，点击"修复选中风险"按钮进行修复
"""
        start_text = ctk.CTkLabel(start_section, text=start_content, font=("Microsoft YaHei", 12), text_color=self.text_color, wraplength=600, justify="left")
        start_text.pack(padx=20, pady=10)

        # 检测维度说明
        dimensions_section = ctk.CTkFrame(manual_frame, fg_color=self.container_color, corner_radius=12, border_width=2, border_color=self.border_color)
        dimensions_section.pack(fill="x", padx=10, pady=10)
        dimensions_title = ctk.CTkLabel(dimensions_section, text="检测维度说明", font=("Microsoft YaHei", 16, "bold"), text_color=self.primary_color)
        dimensions_title.pack(padx=10, pady=10)

        dimensions_content = """
- 配置安全检测：检测openclaw.json配置文件中的安全问题
- 技能包安全检测：检测技能包的安全性和潜在风险
- 端口暴露检测：检测网络端口暴露情况
- 认证与口令检测：检测认证配置和密码强度
- 依赖供应链检测：检测依赖包的安全漏洞
- 主机安全检测：检测主机系统的安全配置
- 密钥泄露检测：检测代码中的硬编码密钥
- 反代配置检测：检测反向代理配置的安全性
- 运行时检查：检测OpenClaw运行时状态
- 数据泄露防护检测：检测数据泄露防护措施
- 漏洞扫描：检测OpenClaw已知的安全漏洞，如CVE-2026-25253等
"""
        dimensions_text = ctk.CTkLabel(dimensions_section, text=dimensions_content, font=("Microsoft YaHei", 12), text_color=self.text_color, wraplength=600, justify="left")
        dimensions_text.pack(padx=20, pady=10)

        # 修复实现标签页
        fix_tab = tabview.tab("修复实现")
        fix_frame = ctk.CTkScrollableFrame(fix_tab, fg_color=self.container_color, corner_radius=12, border_width=2, border_color=self.border_color)
        fix_frame.pack(fill="both", expand=True, padx=10, pady=10)

        # 修复实现内容（保持原有内容）
        fix_title = ctk.CTkLabel(fix_frame, text="修复实现详情", font=("Microsoft YaHei", 18, "bold"), text_color=self.text_color)
        fix_title.pack(pady=20)

        # 配置安全检测
        config_frame = ctk.CTkFrame(fix_frame, fg_color=self.container_color, corner_radius=12, border_width=2, border_color=self.border_color)
        config_frame.pack(fill="x", padx=10, pady=10)
        config_title = ctk.CTkLabel(config_frame, text="配置安全检测", font=("Microsoft YaHei", 14, "bold"), text_color=self.primary_color)
        config_title.pack(padx=10, pady=10)
        
        config_items = [
            ("配置文件权限", "修改配置文件权限为600 (Linux)", "修改openclaw.json文件权限"),
            ("危险配置标志", "禁用危险选项如allowAll、disableSafety等", "修改openclaw.json配置"),
            ("认证设置", "设置认证模式为token，启用认证", "修改openclaw.json配置"),
            ("绑定地址", "设置绑定地址为loopback", "修改openclaw.json配置")
        ]
        
        for item in config_items:
            item_frame = ctk.CTkFrame(config_frame, fg_color="transparent")
            item_frame.pack(fill="x", padx=20, pady=5)
            ctk.CTkLabel(item_frame, text=item[0], font=("Microsoft YaHei", 12, "bold"), text_color=self.text_color, width=150).pack(side="left")
            ctk.CTkLabel(item_frame, text=item[1], font=("Microsoft YaHei", 11), text_color=self.text_color, wraplength=400).pack(side="left", fill="x", expand=True, padx=10)
            ctk.CTkLabel(item_frame, text=item[2], font=("Microsoft YaHei", 10), text_color=self.info_color, width=150).pack(side="right")

        # 技能包安全检测
        skills_frame = ctk.CTkFrame(fix_frame, fg_color=self.container_color, corner_radius=12, border_width=2, border_color=self.border_color)
        skills_frame.pack(fill="x", padx=10, pady=10)
        skills_title = ctk.CTkLabel(skills_frame, text="技能包安全检测", font=("Microsoft YaHei", 14, "bold"), text_color=self.primary_color)
        skills_title.pack(padx=10, pady=10)
        
        skills_items = [
            ("恶意技能包", "移除已知恶意技能包", "删除技能包目录")
        ]
        
        for item in skills_items:
            item_frame = ctk.CTkFrame(skills_frame, fg_color="transparent")
            item_frame.pack(fill="x", padx=20, pady=5)
            ctk.CTkLabel(item_frame, text=item[0], font=("Microsoft YaHei", 12, "bold"), text_color=self.text_color, width=150).pack(side="left")
            ctk.CTkLabel(item_frame, text=item[1], font=("Microsoft YaHei", 11), text_color=self.text_color, wraplength=400).pack(side="left", fill="x", expand=True, padx=10)
            ctk.CTkLabel(item_frame, text=item[2], font=("Microsoft YaHei", 10), text_color=self.info_color, width=150).pack(side="right")

        # 端口暴露检测
        ports_frame = ctk.CTkFrame(fix_frame, fg_color=self.container_color, corner_radius=12, border_width=2, border_color=self.border_color)
        ports_frame.pack(fill="x", padx=10, pady=10)
        ports_title = ctk.CTkLabel(ports_frame, text="端口暴露检测", font=("Microsoft YaHei", 14, "bold"), text_color=self.primary_color)
        ports_title.pack(padx=10, pady=10)
        
        ports_items = [
            ("绑定地址", "设置绑定地址为loopback", "修改openclaw.json配置"),
            ("CORS配置", "设置CORS来源为本地地址", "修改openclaw.json配置"),
            ("速率限制", "配置速率限制防止暴力破解", "修改openclaw.json配置")
        ]
        
        for item in ports_items:
            item_frame = ctk.CTkFrame(ports_frame, fg_color="transparent")
            item_frame.pack(fill="x", padx=20, pady=5)
            ctk.CTkLabel(item_frame, text=item[0], font=("Microsoft YaHei", 12, "bold"), text_color=self.text_color, width=150).pack(side="left")
            ctk.CTkLabel(item_frame, text=item[1], font=("Microsoft YaHei", 11), text_color=self.text_color, wraplength=400).pack(side="left", fill="x", expand=True, padx=10)
            ctk.CTkLabel(item_frame, text=item[2], font=("Microsoft YaHei", 10), text_color=self.info_color, width=150).pack(side="right")

        # 认证与口令检测
        auth_frame = ctk.CTkFrame(fix_frame, fg_color=self.container_color, corner_radius=12, border_width=2, border_color=self.border_color)
        auth_frame.pack(fill="x", padx=10, pady=10)
        auth_title = ctk.CTkLabel(auth_frame, text="认证与口令检测", font=("Microsoft YaHei", 14, "bold"), text_color=self.primary_color)
        auth_title.pack(padx=10, pady=10)
        
        auth_items = [
            ("认证启用", "启用认证功能", "修改openclaw.json配置"),
            ("认证模式", "设置认证模式为token", "修改openclaw.json配置"),
            ("密码强度", "生成强随机密码", "修改openclaw.json配置"),
            ("JWT Secret", "生成强JWT Secret", "修改openclaw.json配置"),
            ("Token过期", "设置Token过期时间为24小时", "修改openclaw.json配置"),
            ("速率限制", "启用速率限制防止暴力破解", "修改openclaw.json配置")
        ]
        
        for item in auth_items:
            item_frame = ctk.CTkFrame(auth_frame, fg_color="transparent")
            item_frame.pack(fill="x", padx=20, pady=5)
            ctk.CTkLabel(item_frame, text=item[0], font=("Microsoft YaHei", 12, "bold"), text_color=self.text_color, width=150).pack(side="left")
            ctk.CTkLabel(item_frame, text=item[1], font=("Microsoft YaHei", 11), text_color=self.text_color, wraplength=400).pack(side="left", fill="x", expand=True, padx=10)
            ctk.CTkLabel(item_frame, text=item[2], font=("Microsoft YaHei", 10), text_color=self.info_color, width=150).pack(side="right")

        # 依赖供应链检测
        deps_frame = ctk.CTkFrame(fix_frame, fg_color=self.container_color, corner_radius=12, border_width=2, border_color=self.border_color)
        deps_frame.pack(fill="x", padx=10, pady=10)
        deps_title = ctk.CTkLabel(deps_frame, text="依赖供应链检测", font=("Microsoft YaHei", 14, "bold"), text_color=self.primary_color)
        deps_title.pack(padx=10, pady=10)
        
        deps_items = [
            ("Node.js依赖", "运行npm audit fix修复依赖漏洞", "执行命令行工具"),
            ("Python依赖", "升级Python依赖到最新版本", "执行命令行工具")
        ]
        
        for item in deps_items:
            item_frame = ctk.CTkFrame(deps_frame, fg_color="transparent")
            item_frame.pack(fill="x", padx=20, pady=5)
            ctk.CTkLabel(item_frame, text=item[0], font=("Microsoft YaHei", 12, "bold"), text_color=self.text_color, width=150).pack(side="left")
            ctk.CTkLabel(item_frame, text=item[1], font=("Microsoft YaHei", 11), text_color=self.text_color, wraplength=400).pack(side="left", fill="x", expand=True, padx=10)
            ctk.CTkLabel(item_frame, text=item[2], font=("Microsoft YaHei", 10), text_color=self.info_color, width=150).pack(side="right")

        # 主机安全检测
        host_frame = ctk.CTkFrame(fix_frame, fg_color=self.container_color, corner_radius=12, border_width=2, border_color=self.border_color)
        host_frame.pack(fill="x", padx=10, pady=10)
        host_title = ctk.CTkLabel(host_frame, text="主机安全检测", font=("Microsoft YaHei", 14, "bold"), text_color=self.primary_color)
        host_title.pack(padx=10, pady=10)
        
        host_items = [
            ("可疑进程", "尝试终止可疑进程（如挖矿程序、后门等）", "执行系统命令（需要管理员权限）")
        ]
        
        for item in host_items:
            item_frame = ctk.CTkFrame(host_frame, fg_color="transparent")
            item_frame.pack(fill="x", padx=20, pady=5)
            ctk.CTkLabel(item_frame, text=item[0], font=("Microsoft YaHei", 12, "bold"), text_color=self.text_color, width=150).pack(side="left")
            ctk.CTkLabel(item_frame, text=item[1], font=("Microsoft YaHei", 11), text_color=self.text_color, wraplength=400).pack(side="left", fill="x", expand=True, padx=10)
            ctk.CTkLabel(item_frame, text=item[2], font=("Microsoft YaHei", 10), text_color=self.info_color, width=150).pack(side="right")

        # 密钥泄露检测
        secrets_frame = ctk.CTkFrame(fix_frame, fg_color=self.container_color, corner_radius=12, border_width=2, border_color=self.border_color)
        secrets_frame.pack(fill="x", padx=10, pady=10)
        secrets_title = ctk.CTkLabel(secrets_frame, text="密钥泄露检测", font=("Microsoft YaHei", 14, "bold"), text_color=self.primary_color)
        secrets_title.pack(padx=10, pady=10)
        
        secrets_items = [
            ("敏感文件", "备份并清理敏感文件（私钥文件等）", "备份文件并创建空文件替代"),
            ("日志清理", "清理日志文件中的敏感信息", "修改日志文件")
        ]
        
        for item in secrets_items:
            item_frame = ctk.CTkFrame(secrets_frame, fg_color="transparent")
            item_frame.pack(fill="x", padx=20, pady=5)
            ctk.CTkLabel(item_frame, text=item[0], font=("Microsoft YaHei", 12, "bold"), text_color=self.text_color, width=150).pack(side="left")
            ctk.CTkLabel(item_frame, text=item[1], font=("Microsoft YaHei", 11), text_color=self.text_color, wraplength=400).pack(side="left", fill="x", expand=True, padx=10)
            ctk.CTkLabel(item_frame, text=item[2], font=("Microsoft YaHei", 10), text_color=self.info_color, width=150).pack(side="right")

        # 反代配置检测
        proxy_frame = ctk.CTkFrame(fix_frame, fg_color=self.container_color, corner_radius=12, border_width=2, border_color=self.border_color)
        proxy_frame.pack(fill="x", padx=10, pady=10)
        proxy_title = ctk.CTkLabel(proxy_frame, text="反代配置检测", font=("Microsoft YaHei", 14, "bold"), text_color=self.primary_color)
        proxy_title.pack(padx=10, pady=10)
        
        proxy_items = [
            ("受信任代理", "配置受信任代理为本地地址", "修改openclaw.json配置"),
            ("X-Forwarded-For", "信任X-Forwarded-For头", "修改openclaw.json配置"),
            ("安全头", "添加安全头", "修改openclaw.json配置"),
            ("代理链", "限制代理链长度，移除不安全的HTTP代理", "修改openclaw.json配置")
        ]
        
        for item in proxy_items:
            item_frame = ctk.CTkFrame(proxy_frame, fg_color="transparent")
            item_frame.pack(fill="x", padx=20, pady=5)
            ctk.CTkLabel(item_frame, text=item[0], font=("Microsoft YaHei", 12, "bold"), text_color=self.text_color, width=150).pack(side="left")
            ctk.CTkLabel(item_frame, text=item[1], font=("Microsoft YaHei", 11), text_color=self.text_color, wraplength=400).pack(side="left", fill="x", expand=True, padx=10)
            ctk.CTkLabel(item_frame, text=item[2], font=("Microsoft YaHei", 10), text_color=self.info_color, width=150).pack(side="right")

        # 运行时检查
        runtime_frame = ctk.CTkFrame(fix_frame, fg_color=self.container_color, corner_radius=12, border_width=2, border_color=self.border_color)
        runtime_frame.pack(fill="x", padx=10, pady=10)
        runtime_title = ctk.CTkLabel(runtime_frame, text="运行时检查", font=("Microsoft YaHei", 14, "bold"), text_color=self.primary_color)
        runtime_title.pack(padx=10, pady=10)
        
        runtime_items = [
            ("认证模式", "设置认证模式为token", "修改openclaw.json配置"),
            ("命令限制", "添加关键命令限制", "修改openclaw.json配置"),
            ("会话超时", "设置会话超时为24小时", "修改openclaw.json配置"),
            ("资源限制", "配置内存和CPU限制", "修改openclaw.json配置"),
            ("日志配置", "设置日志级别为info，启用日志轮转", "修改openclaw.json配置"),
            ("自动更新", "启用自动更新", "修改openclaw.json配置"),
            ("调试模式", "关闭调试模式", "修改openclaw.json配置")
        ]
        
        for item in runtime_items:
            item_frame = ctk.CTkFrame(runtime_frame, fg_color="transparent")
            item_frame.pack(fill="x", padx=20, pady=5)
            ctk.CTkLabel(item_frame, text=item[0], font=("Microsoft YaHei", 12, "bold"), text_color=self.text_color, width=150).pack(side="left")
            ctk.CTkLabel(item_frame, text=item[1], font=("Microsoft YaHei", 11), text_color=self.text_color, wraplength=400).pack(side="left", fill="x", expand=True, padx=10)
            ctk.CTkLabel(item_frame, text=item[2], font=("Microsoft YaHei", 10), text_color=self.info_color, width=150).pack(side="right")

        # 数据泄露防护检测
        dlp_frame = ctk.CTkFrame(fix_frame, fg_color=self.container_color, corner_radius=12, border_width=2, border_color=self.border_color)
        dlp_frame.pack(fill="x", padx=10, pady=10)
        dlp_title = ctk.CTkLabel(dlp_frame, text="数据泄露防护检测", font= ("Microsoft YaHei", 14, "bold"), text_color=self.primary_color)
        dlp_title.pack(padx=10, pady=10)
        
        dlp_items = [
            ("文件哈希基线", "创建文件哈希基线", "创建.integrity.json文件"),
            ("Brain/Memory备份", "创建Brain/Memory备份", "创建备份文件"),
            ("敏感文件", "备份并清理敏感文件", "备份文件并创建空文件替代")
        ]
        
        for item in dlp_items:
            item_frame = ctk.CTkFrame(dlp_frame, fg_color="transparent")
            item_frame.pack(fill="x", padx=20, pady=5)
            ctk.CTkLabel(item_frame, text=item[0], font= ("Microsoft YaHei", 12, "bold"), text_color=self.text_color, width=150).pack(side="left")
            ctk.CTkLabel(item_frame, text=item[1], font= ("Microsoft YaHei", 11), text_color=self.text_color, wraplength=400).pack(side="left", fill="x", expand=True, padx=10)
            ctk.CTkLabel(item_frame, text=item[2], font= ("Microsoft YaHei", 10), text_color=self.info_color, width=150).pack(side="right")

        # 漏洞扫描
        vulnerability_frame = ctk.CTkFrame(fix_frame, fg_color=self.container_color, corner_radius=12, border_width=2, border_color=self.border_color)
        vulnerability_frame.pack(fill="x", padx=10, pady=10)
        vulnerability_title = ctk.CTkLabel(vulnerability_frame, text="漏洞扫描", font= ("Microsoft YaHei", 14, "bold"), text_color=self.primary_color)
        vulnerability_title.pack(padx=10, pady=10)
        
        vulnerability_items = [
            ("CVE-2026-25253", "启用认证模式，更新OpenClaw到最新版本", "修改openclaw.json配置"),
            ("默认暴露公网", "修改绑定地址为loopback，配置防火墙规则", "修改openclaw.json配置"),
            ("插件投毒", "只使用来自可信来源的技能包，定期更新技能包", "执行命令行工具"),
            ("权限失控", "配置权限控制，禁用allowAll权限", "修改openclaw.json配置"),
            ("架构缺陷", "启用沙箱，配置网络隔离，设置资源限制", "修改openclaw.json配置")
        ]
        
        for item in vulnerability_items:
            item_frame = ctk.CTkFrame(vulnerability_frame, fg_color="transparent")
            item_frame.pack(fill="x", padx=20, pady=5)
            ctk.CTkLabel(item_frame, text=item[0], font= ("Microsoft YaHei", 12, "bold"), text_color=self.text_color, width=150).pack(side="left")
            ctk.CTkLabel(item_frame, text=item[1], font= ("Microsoft YaHei", 11), text_color=self.text_color, wraplength=400).pack(side="left", fill="x", expand=True, padx=10)
            ctk.CTkLabel(item_frame, text=item[2], font= ("Microsoft YaHei", 10), text_color=self.info_color, width=150).pack(side="right")

        # 关于工具标签页
        about_tab = tabview.tab("关于工具")
        about_frame = ctk.CTkFrame(about_tab, fg_color=self.container_color, corner_radius=12, border_width=2, border_color=self.border_color)
        about_frame.pack(fill="both", expand=True, padx=10, pady=10)

        # 工具信息
        tool_info = ctk.CTkFrame(about_frame, fg_color=self.container_color, corner_radius=12, border_width=2, border_color=self.border_color)
        tool_info.pack(fill="x", padx=10, pady=10)
        tool_title = ctk.CTkLabel(tool_info, text="🦞 焦糖布丁 v4.0", font=("Microsoft YaHei", 18, "bold"), text_color=self.primary_color)
        tool_title.pack(padx=10, pady=10)

        tool_description = """
🦞 焦糖布丁 v4.0是一款专业的安全扫描工具，专为OpenClaw AI Gateway设计，
能够全面检测OpenClaw的安全配置、技能包安全、网络暴露、认证配置等多个维度的安全问题。

主要功能：
- 多维度安全检测
- 自动修复安全问题
- 生成详细的安全报告
- 增加漏洞扫描功能
- AI辅助安全审计(提示词)
- 跨平台支持
基于 Dejavu 二开优化 | 致谢原作者原项目：https://github.com/AscendGrace/Dejavu 
版本：2.0.0
"""
        tool_text = ctk.CTkLabel(tool_info, text=tool_description, font=("Microsoft YaHei", 12), text_color=self.text_color, wraplength=600, justify="left")
        tool_text.pack(padx=20, pady=10)

        # 作者信息
        author_info = ctk.CTkScrollableFrame(about_frame, fg_color=self.container_color, corner_radius=12, border_width=2, border_color=self.border_color)
        author_info.pack(fill="both", expand=True, padx=20, pady=20)
        author_title = ctk.CTkLabel(author_info, text="作者信息", font=("Microsoft YaHei", 18, "bold"), text_color=self.primary_color)
        author_title.pack(padx=20, pady=20)

        # 作者信息和二维码
        author_frame = ctk.CTkFrame(author_info, fg_color="transparent")
        author_frame.pack(padx=30, pady=30, fill="both", expand=True)
        
        # 左侧文字信息
        author_text_frame = ctk.CTkFrame(author_frame, fg_color="transparent", width=300)
        author_text_frame.pack(side="left", padx=30, fill="y")
        
        author_content = """
作者：0x八月

微信：扫描右侧二维码

感谢您使用 焦糖布丁 ！
如有任何问题或建议，欢迎联系作者。
"""
        author_text = ctk.CTkLabel(author_text_frame, text=author_content, font=("Microsoft YaHei", 16), text_color=self.text_color, wraplength=280, justify="left")
        author_text.pack(padx=30, pady=30, fill="y")
        
        # 右侧二维码
        qr_frame = ctk.CTkFrame(author_frame, fg_color="transparent")
        qr_frame.pack(side="right", padx=30, pady=30, fill="both", expand=True)
        
        # 加载本地微信二维码图片
        import os
        import sys
        
        try:
            # 获取图片路径，支持打包后的环境
            if hasattr(sys, '_MEIPASS'):
                # 打包后的路径
                qr_path = os.path.join(sys._MEIPASS, 'assets', 'WeChat.jpg')
            else:
                # 开发环境路径
                qr_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'assets', 'WeChat.jpg')
            
            qr_image = Image.open(qr_path)
            # 调整图片大小以确保清晰显示，保持原始比例
            qr_width, qr_height = qr_image.size
            # 增加图片显示大小
            scale_factor = 0.3
            new_width = int(qr_width * scale_factor)
            new_height = int(qr_height * scale_factor)
            qr_ctk_image = ctk.CTkImage(light_image=qr_image, dark_image=qr_image, size=(new_width, new_height))
            qr_label = ctk.CTkLabel(qr_frame, image=qr_ctk_image, text="")
            qr_label.pack(padx=30, pady=30)
        except Exception as e:
            # 如果无法加载图片，显示提示信息
            qr_label = ctk.CTkLabel(qr_frame, text="二维码加载失败", font=("Microsoft YaHei", 16), text_color=self.text_color)
            qr_label.pack(padx=30, pady=30, fill="both", expand=True)

        # 改进建议标签页
        feedback_tab = tabview.tab("改进建议")
        feedback_frame = ctk.CTkFrame(feedback_tab, fg_color=self.container_color, corner_radius=12, border_width=2, border_color=self.border_color)
        feedback_frame.pack(fill="both", expand=True, padx=10, pady=10)

        # 问卷星问卷
        feedback_title = ctk.CTkLabel(feedback_frame, text="改进建议", font=("Microsoft YaHei", 18, "bold"), text_color=self.text_color)
        feedback_title.pack(pady=20)

        feedback_content = """
为了不断改进🦞 焦糖布丁 v4.0，我们希望听到您的意见和建议。

请点击下方按钮，填写问卷星问卷，帮助我们了解您的使用体验和需求。
"""
        feedback_text = ctk.CTkLabel(feedback_frame, text=feedback_content, font=("Microsoft YaHei", 12), text_color=self.text_color, wraplength=600, justify="left")
        feedback_text.pack(padx=20, pady=20)

        # 打开问卷星按钮
        def open_questionnaire():
            import webbrowser
            webbrowser.open("https://v.wjx.cn/vm/mLNTDOR.aspx#")  # 替换为实际的问卷星链接

        questionnaire_btn = ctk.CTkButton(
            feedback_frame, 
            text="填写改进建议问卷", 
            command=open_questionnaire,
            height=40,
            font=("Microsoft YaHei", 14, "bold"),
            fg_color=self.primary_color,
            hover_color="#389e0d",
            text_color="white",
            border_color=self.border_color,
            border_width=3,
            corner_radius=16
        )
        questionnaire_btn.pack(padx=20, pady=20)

    def _open_model_config_dialog(self):
        """打开模型配置对话框"""
        config_dialog = ctk.CTkToplevel(self)
        config_dialog.title("AI模型配置")
        config_dialog.geometry("800x600")
        config_dialog.minsize(700, 500)
        config_dialog.transient(self)
        config_dialog.grab_set()
        config_dialog.configure(fg_color=self.bg_color)

        # 配置管理区域
        config_manage_frame = ctk.CTkFrame(config_dialog, fg_color=self.container_color, corner_radius=12, border_width=2, border_color=self.border_color)
        config_manage_frame.pack(fill="x", padx=20, pady=10)
        ctk.CTkLabel(config_manage_frame, text="配置管理", font=("Microsoft YaHei", 14, "bold"), text_color=self.text_color).pack(padx=20, pady=10)

        # 配置名称输入
        name_frame = ctk.CTkFrame(config_manage_frame, fg_color="transparent")
        name_frame.pack(fill="x", padx=20, pady=5)
        ctk.CTkLabel(name_frame, text="配置名称", font=("Microsoft YaHei", 10), text_color=self.text_color, width=100).pack(side="left", padx=5)
        config_name_var = ctk.StringVar(value="新配置")
        ctk.CTkEntry(name_frame, textvariable=config_name_var, width=300, border_color=self.border_color, border_width=2, corner_radius=8).pack(side="left", padx=5)

        # 配置列表
        list_frame = ctk.CTkFrame(config_manage_frame, fg_color="transparent")
        list_frame.pack(fill="x", padx=20, pady=10)
        ctk.CTkLabel(list_frame, text="已保存配置", font=("Microsoft YaHei", 10), text_color=self.text_color).pack(anchor="w", padx=5, pady=5)
        
        config_listbox = tk.Listbox(
            list_frame,
            width=50,
            height=5,
            font=("Microsoft YaHei", 11),
            bg=self.container_color,
            fg=self.text_color,
            borderwidth=2,
            relief="solid"
        )
        config_listbox.pack(fill="x", padx=5, pady=5)
        
        # 填充配置列表
        for config in self.ai_model_config.get("configs", []):
            config_listbox.insert(tk.END, config.get("name"))
        
        # 配置操作按钮
        button_frame = ctk.CTkFrame(config_manage_frame, fg_color="transparent")
        button_frame.pack(fill="x", padx=20, pady=5)
        
        def load_selected_config():
            selected_index = config_listbox.curselection()
            if selected_index:
                config_name = config_listbox.get(selected_index)
                for config in self.ai_model_config.get("configs", []):
                    if config.get("name") == config_name:
                        model_type_var.set(config.get("model_type", "ollama"))
                        ollama_model_var.set(config.get("ollama", {}).get("model", "llama3"))
                        ollama_url_var.set(config.get("ollama", {}).get("url", "http://localhost:11434/api/generate"))
                        cloud_api_key_var.set(config.get("cloud", {}).get("api_key", ""))
                        cloud_api_url_var.set(config.get("cloud", {}).get("api_url", "https://api.example.com/v1/chat/completions"))
                        config_name_var.set(config_name)
                        break
        
        def delete_selected_config():
            selected_index = config_listbox.curselection()
            if selected_index:
                config_name = config_listbox.get(selected_index)
                if messagebox.askyesno("删除配置", f"确定要删除配置 '{config_name}' 吗？"):
                    if self._delete_config(config_name):
                        # 更新列表
                        config_listbox.delete(0, tk.END)
                        for config in self.ai_model_config.get("configs", []):
                            config_listbox.insert(tk.END, config.get("name"))
                        messagebox.showinfo("删除成功", f"配置 '{config_name}' 已删除")
        
        ctk.CTkButton(button_frame, text="加载配置", command=load_selected_config, width=100, font=("Microsoft YaHei", 10, "bold"), fg_color=self.primary_color, hover_color="#52C41A", text_color="white", border_color=self.border_color, border_width=2, corner_radius=8).pack(side="left", padx=5)
        ctk.CTkButton(button_frame, text="删除配置", command=delete_selected_config, width=100, font=("Microsoft YaHei", 10, "bold"), fg_color=self.error_color, hover_color="#fa8c8c", text_color="white", border_color=self.border_color, border_width=2, corner_radius=8).pack(side="left", padx=5)

        # 模型配置区域
        model_config_frame = ctk.CTkFrame(config_dialog, fg_color=self.container_color, corner_radius=12, border_width=2, border_color=self.border_color)
        model_config_frame.pack(fill="x", padx=20, pady=10)
        ctk.CTkLabel(model_config_frame, text="模型配置", font=("Microsoft YaHei", 14, "bold"), text_color=self.text_color).pack(padx=20, pady=10)

        # 模型选择
        ctk.CTkLabel(model_config_frame, text="模型类型", font=("Microsoft YaHei", 12, "bold"), text_color=self.text_color).pack(anchor="w", padx=20, pady=5)
        current_config = self._get_current_config()
        model_type_var = ctk.StringVar(value=current_config.get("model_type", "ollama"))
        model_frame = ctk.CTkFrame(model_config_frame, fg_color="transparent")
        model_frame.pack(fill="x", padx=20, pady=5)
        
        ctk.CTkRadioButton(model_frame, text="本地 Ollama 模型", variable=model_type_var, value="ollama", font=("Microsoft YaHei", 12), text_color=self.text_color).pack(anchor="w", padx=10, pady=5)
        ctk.CTkRadioButton(model_frame, text="国内云端模型", variable=model_type_var, value="cloud", font=("Microsoft YaHei", 12), text_color=self.text_color).pack(anchor="w", padx=10, pady=5)

        # Ollama配置
        ollama_frame = ctk.CTkFrame(model_config_frame, fg_color="transparent")
        ollama_frame.pack(fill="x", padx=20, pady=5)
        ctk.CTkLabel(ollama_frame, text="Ollama 配置", font=("Microsoft YaHei", 12, "bold"), text_color=self.text_color).pack(anchor="w", padx=10, pady=5)
        
        ctk.CTkLabel(ollama_frame, text="模型名称", font=("Microsoft YaHei", 10), text_color=self.text_color, width=100).pack(side="left", padx=10, pady=2)
        ollama_model_var = ctk.StringVar(value=current_config.get("ollama", {}).get("model", "llama3"))
        ctk.CTkEntry(ollama_frame, textvariable=ollama_model_var, width=300, border_color=self.border_color, border_width=2, corner_radius=8).pack(side="left", padx=5)
        
        url_frame = ctk.CTkFrame(ollama_frame, fg_color="transparent")
        url_frame.pack(fill="x", padx=10, pady=5)
        ctk.CTkLabel(url_frame, text="API URL", font=("Microsoft YaHei", 10), text_color=self.text_color, width=100).pack(side="left", padx=10, pady=2)
        ollama_url_var = ctk.StringVar(value=current_config.get("ollama", {}).get("url", "http://localhost:11434/api/generate"))
        ctk.CTkEntry(url_frame, textvariable=ollama_url_var, width=400, border_color=self.border_color, border_width=2, corner_radius=8).pack(side="left", padx=5)

        # 云端模型配置
        cloud_frame = ctk.CTkFrame(model_config_frame, fg_color="transparent")
        cloud_frame.pack(fill="x", padx=20, pady=5)
        ctk.CTkLabel(cloud_frame, text="云端模型配置", font=("Microsoft YaHei", 12, "bold"), text_color=self.text_color).pack(anchor="w", padx=10, pady=5)
        
        api_key_frame = ctk.CTkFrame(cloud_frame, fg_color="transparent")
        api_key_frame.pack(fill="x", padx=10, pady=5)
        ctk.CTkLabel(api_key_frame, text="API Key", font=("Microsoft YaHei", 10), text_color=self.text_color, width=100).pack(side="left", padx=10, pady=2)
        cloud_api_key_var = ctk.StringVar(value=current_config.get("cloud", {}).get("api_key", ""))
        ctk.CTkEntry(api_key_frame, textvariable=cloud_api_key_var, width=400, show="*", border_color=self.border_color, border_width=2, corner_radius=8).pack(side="left", padx=5)
        
        cloud_url_frame = ctk.CTkFrame(cloud_frame, fg_color="transparent")
        cloud_url_frame.pack(fill="x", padx=10, pady=5)
        ctk.CTkLabel(cloud_url_frame, text="API URL", font=("Microsoft YaHei", 10), text_color=self.text_color, width=100).pack(side="left", padx=10, pady=2)
        cloud_api_url_var = ctk.StringVar(value=current_config.get("cloud", {}).get("api_url", "https://api.example.com/v1/chat/completions"))
        ctk.CTkEntry(cloud_url_frame, textvariable=cloud_api_url_var, width=400, border_color=self.border_color, border_width=2, corner_radius=8).pack(side="left", padx=5)

        # 按钮区域
        button_frame = ctk.CTkFrame(config_dialog, fg_color="transparent")
        button_frame.pack(fill="x", padx=20, pady=10)

        def save_config():
            config_name = config_name_var.get().strip()
            if not config_name:
                messagebox.showwarning("警告", "请输入配置名称")
                return
            
            model_config = {
                "model_type": model_type_var.get(),
                "ollama": {
                    "model": ollama_model_var.get(),
                    "url": ollama_url_var.get()
                },
                "cloud": {
                    "api_key": cloud_api_key_var.get(),
                    "api_url": cloud_api_url_var.get()
                }
            }
            
            # 保存配置
            self._save_new_config(config_name, model_config)
            
            # 更新配置列表
            config_listbox.delete(0, tk.END)
            for config in self.ai_model_config.get("configs", []):
                config_listbox.insert(tk.END, config.get("name"))
            
            messagebox.showinfo("保存成功", f"配置 '{config_name}' 已保存")

        def confirm_config():
            config_name = config_name_var.get().strip()
            if not config_name:
                messagebox.showwarning("警告", "请输入配置名称")
                return
            
            model_config = {
                "model_type": model_type_var.get(),
                "ollama": {
                    "model": ollama_model_var.get(),
                    "url": ollama_url_var.get()
                },
                "cloud": {
                    "api_key": cloud_api_key_var.get(),
                    "api_url": cloud_api_url_var.get()
                }
            }
            
            # 保存配置
            self._save_new_config(config_name, model_config)
            config_dialog.destroy()
            self._generate_ai_audit(model_config)

        ctk.CTkButton(button_frame, text="保存配置".upper(), command=save_config, height=36, font=("Microsoft YaHei", 11, "bold"), fg_color=self.primary_color, hover_color="#52C41A", text_color="white", border_color=self.border_color, border_width=2, corner_radius=12).pack(side="left", fill="x", expand=True, padx=5)
        ctk.CTkButton(button_frame, text="确认并审计".upper(), command=confirm_config, height=36, font=("Microsoft YaHei", 11, "bold"), fg_color=self.primary_color, hover_color="#52C41A", text_color="white", border_color=self.border_color, border_width=2, corner_radius=12).pack(side="left", fill="x", expand=True, padx=5)

    def _generate_ai_audit(self, model_config=None):
        """生成AI深度审计文件"""
        if not model_config:
            self._open_model_config_dialog()
            return

        # 生成审计Prompt
        audit_prompt = """
# OpenClaw 安全配置审计 Prompt v2.0

## 角色定义
你是一名专业的 AI 基础设施安全审计员，专注于 OpenClaw 开源 AI 网关的安全配置分析。

## 输入材料
- 焦糖布丁自动扫描报告（Markdown 格式，附后）
- 待审计的 `openclaw.json` 配置片段（如有）
- 运行时抓取数据（如有）

## 审计维度

### 1. 配置语义分析
- `bind` 参数：`loopback` 仅本地，`lan` 局域网，`all` 全网暴露
- `auth.mode`：`token` 需要令牌，`none` 完全开放（高危）
- `denyCommands`：空数组意味着允许所有 shell 命令——评估风险
- `trustedProxies`：空数组在反代后可能导致 IP 伪造

### 2. 技能（Skills）审计
对每个 skills 配置，评估：
- 权限最小化原则：该 skill 是否请求了不必要的工具权限？
- 危险工具组合：`bash` + `file_write` + `network_fetch` 同时存在是高危信号
- SSRF 风险：`fetch`/`http` 工具 + 用户可控 URL 参数
- 提示注入面：skill 描述中是否存在可被用户操控的指令拼接

### 3. 网络暴露研判
- 端口暴露 + 无认证 = 立即修复
- 端口暴露 + 弱 token = 高危，说明原因
- 反代后的 X-Forwarded-For 信任链分析

### 4. 认证令牌分析
- 熵值估算：40位 hex = ~160 bit entropy（充分）
- 令牌轮换周期建议
- 是否存在令牌硬编码迹象

### 5. 供应链安全
- 原生 `.node` 模块带来的二进制信任问题
- 第三方 skill 包的来源核查建议
- `pnpm-lock.yaml` 完整性校验方式

## 输出格式要求

请输出以下结构：

```
## 安全审计摘要

### 综合风险等级
[CRITICAL | HIGH | MEDIUM | LOW]

### 关键发现（Top 5）
1. [严重程度] 发现描述 → 建议修复措施
...

### 深度分析

#### 配置语义
...

#### Skills 权限审计
...

#### 修复优先级路线图
| 优先级 | 项目 | 预计工时 | 影响 |
|--------|------|---------|------|
...

### 结论
```

---

## 扫描报告

"""

        # 生成Markdown格式的扫描报告
        report_content = self.scanner.generate_report(self.current_results, "text")
        
        # 组合Prompt和报告
        ai_audit_content = audit_prompt + report_content

        # 创建进度对话框
        progress_dialog = ctk.CTkToplevel(self)
        progress_dialog.title("AI审计中")
        progress_dialog.geometry("400x200")
        progress_dialog.minsize(300, 150)
        progress_dialog.transient(self)
        progress_dialog.grab_set()
        progress_dialog.configure(fg_color=self.bg_color)

        # 进度信息
        ctk.CTkLabel(progress_dialog, text="正在调用AI模型进行深度审计，请稍候...", font=("Microsoft YaHei", 12), text_color=self.text_color).pack(pady=20)
        progress_bar = ctk.CTkProgressBar(progress_dialog, fg_color=self.bg_color, progress_color=self.primary_color, border_color=self.border_color, border_width=2, corner_radius=10)
        progress_bar.pack(fill="x", padx=20, pady=10)
        progress_bar.set(0)
        status_label = ctk.CTkLabel(progress_dialog, text="准备中...", font=("Microsoft YaHei", 10), text_color=self.text_color)
        status_label.pack(pady=10)

        # 调用AI模型
        def call_ai_model():
            try:
                # 更新状态
                def update_status(message, progress):
                    self.after(0, lambda: status_label.configure(text=message))
                    self.after(0, lambda: progress_bar.set(progress))

                update_status("正在准备审计数据...", 0.1)

                if model_config["model_type"] == "ollama":
                    update_status("正在调用本地Ollama模型...", 0.3)
                    # 调用本地ollama模型
                    url = model_config["ollama"]["url"]
                    model = model_config["ollama"]["model"]
                    
                    # 验证URL格式
                    if not url.startswith(('http://', 'https://')):
                        url = 'http://' + url
                    
                    payload = {
                        "model": model,
                        "prompt": ai_audit_content,
                        "stream": False,
                        "options": {
                            "temperature": 0.7,
                            "max_tokens": 4096,
                            "thinking": False  # 禁用think模式
                        }
                    }
                    
                    response = requests.post(url, json=payload, timeout=60)  # 增加超时时间
                    response.raise_for_status()
                    result = response.json()
                    audit_result = result.get("response", "")
                else:
                    update_status("正在调用云端模型...", 0.3)
                    # 调用国内云端模型
                    url = model_config["cloud"]["api_url"]
                    api_key = model_config["cloud"]["api_key"]
                    
                    # 检测是否为DeepSeek API
                    if "deepseek.com" in url:
                        # DeepSeek API格式
                        payload = {
                            "model": "deepseek-chat",  # DeepSeek默认模型
                            "messages": [
                                {"role": "system", "content": "你是一名专业的 AI 基础设施安全审计员"},
                                {"role": "user", "content": ai_audit_content}
                            ],
                            "temperature": 0.7,
                            "max_tokens": 4096
                        }
                    else:
                        # 通用格式
                        payload = {
                            "model": "gpt-3.5-turbo",  # 根据实际云端模型调整
                            "messages": [
                                {"role": "system", "content": "你是一名专业的 AI 基础设施安全审计员"},
                                {"role": "user", "content": ai_audit_content}
                            ],
                            "temperature": 0.7,
                            "max_tokens": 4096
                        }
                    
                    headers = {
                        "Authorization": f"Bearer {api_key}",
                        "Content-Type": "application/json"
                    }
                    
                    response = requests.post(url, json=payload, headers=headers, timeout=60)  # 增加超时时间
                    response.raise_for_status()
                    result = response.json()
                    audit_result = result["choices"][0]["message"]["content"]
                
                update_status("审计完成，正在处理结果...", 0.8)

                # 保存结果
                file_path = filedialog.asksaveasfilename(
                    defaultextension=".md",
                    filetypes=[("Markdown文件", "*.md"), ("所有文件", "*.*")]
                )
                
                if file_path:
                    with open(file_path, 'w', encoding='utf-8') as f:
                        f.write(audit_result)
                    
                    # 关闭进度对话框
                    self.after(0, lambda: progress_dialog.destroy())
                    
                    # 显示审计结果预览
                    def show_audit_result():
                        result_dialog = ctk.CTkToplevel(self)
                        result_dialog.title("AI审计结果")
                        result_dialog.geometry("800x600")
                        result_dialog.minsize(600, 400)
                        result_dialog.transient(self)
                        result_dialog.grab_set()
                        result_dialog.configure(fg_color=self.bg_color)

                        # 结果标题
                        ctk.CTkLabel(result_dialog, text="AI深度审计结果", font=("Microsoft YaHei", 16, "bold"), text_color=self.text_color).pack(pady=10)

                        # 结果内容
                        result_text = ctk.CTkTextbox(result_dialog, fg_color=self.container_color, text_color=self.text_color, border_color=self.border_color, border_width=2, corner_radius=12, font=("Microsoft YaHei", 11))
                        result_text.pack(fill="both", expand=True, padx=20, pady=10)
                        result_text.insert("0.0", audit_result)
                        result_text.configure(state="disabled")

                        # 保存信息
                        ctk.CTkLabel(result_dialog, text=f"结果已保存至: {file_path}", font=("Microsoft YaHei", 10), text_color=self.info_color).pack(pady=5)

                        # 关闭按钮
                        ctk.CTkButton(result_dialog, text="关闭", command=result_dialog.destroy, height=32, font=("Microsoft YaHei", 11, "bold"), fg_color=self.primary_color, hover_color="#52C41A", text_color="white", border_color=self.border_color, border_width=2, corner_radius=12).pack(pady=10)

                    self.after(0, show_audit_result)
                else:
                    # 关闭进度对话框
                    self.after(0, lambda: progress_dialog.destroy())
            except Exception as e:
                # 关闭进度对话框
                self.after(0, lambda: progress_dialog.destroy())
                # 使用默认参数捕获e的值
                self.after(0, lambda e=e: messagebox.showerror("AI审计失败", f"调用AI模型时出错:\n{str(e)}"))

        # 在新线程中调用AI模型
        thread = threading.Thread(target=call_ai_model)
        thread.daemon = True
        thread.start()

    def _run_secureclaw_behavior_rules(self):
        """运行🦞 焦糖布丁行为规则检查"""
        openclaw_dir = str(PlatformAdapter.get_openclaw_path())
        if not os.path.exists(openclaw_dir):
            messagebox.showwarning("提示", "OpenClaw目录不存在，请先设置正确的目录")
            return

        # 更新状态
        self.status_label.configure(text="正在执行行为规则检查...")
        self.secureclaw_behavior_btn.configure(state="disabled")

        # 在新线程中运行
        def run_behavior_rules():
            try:
                result = self.scanner.run_secureclaw_behavior_rules(openclaw_dir)
                self.after(0, lambda: self._secureclaw_behavior_rules_complete(result))
            except Exception as e:
                self.after(0, lambda: messagebox.showerror("错误", f"行为规则检查失败:\n{str(e)}"))
                self.after(0, lambda: self.status_label.configure(text="就绪"))
                self.after(0, lambda: self.secureclaw_behavior_btn.configure(state="normal"))

        thread = threading.Thread(target=run_behavior_rules)
        thread.daemon = True
        thread.start()

    def _secureclaw_behavior_rules_complete(self, result):
        """行为规则检查完成"""
        self.status_label.configure(text="行为规则检查完成")
        self.secureclaw_behavior_btn.configure(state="normal")

        # 存储结果并启用导出按钮
        self.secureclaw_behavior_result = result
        self.export_secureclaw_behavior_report_btn.configure(state="normal")

        # 显示检查结果
        score = result.get("score", 0)
        passed_rules = result.get("passed_rules", 0)
        total_rules = result.get("total_rules", 0)
        results = result.get("results", {})

        # 创建结果对话框
        dialog = ctk.CTkToplevel(self)
        dialog.title("SecureClaw行为规则检查结果")
        dialog.geometry("800x600")
        dialog.transient(self)
        dialog.grab_set()

        # 设置对话框样式
        dialog.configure(fg_color=self.bg_color)

        # 滚动帧
        scroll_frame = ctk.CTkScrollableFrame(dialog, fg_color=self.container_color, corner_radius=16, border_width=3, border_color=self.border_color)
        scroll_frame.pack(fill="both", expand=True, padx=10, pady=10)

        # 评分信息
        score_frame = ctk.CTkFrame(scroll_frame, fg_color=self.container_color, corner_radius=12, border_width=2, border_color=self.border_color)
        score_frame.pack(fill="x", padx=10, pady=10)

        ctk.CTkLabel(
            score_frame,
            text=f"行为规则评分: {score}/100",
            font= ("Microsoft YaHei", 16, "bold"),
            text_color=self.text_color
        ).pack(pady=10)

        ctk.CTkLabel(
            score_frame,
            text=f"通过规则: {passed_rules}/{total_rules}",
            font= ("Microsoft YaHei", 12),
            text_color=self.text_color
        ).pack(pady=5)

        # 详细结果
        ctk.CTkLabel(
            scroll_frame,
            text="详细规则检查结果:",
            font= ("Microsoft YaHei", 14, "bold"),
            text_color=self.primary_color
        ).pack(pady=10)

        for rule_name, rule_result in results.items():
            status = rule_result.get("status")
            message = rule_result.get("message")
            severity = rule_result.get("severity")

            # 状态颜色
            if status == "PASS":
                status_color = self.success_color
            elif status == "FAIL":
                status_color = self.error_color
            elif status == "WARN":
                status_color = self.warning_color
            else:
                status_color = self.info_color

            # 创建规则结果帧
            rule_frame = ctk.CTkFrame(scroll_frame, fg_color=self.container_color, corner_radius=12, border_width=2, border_color=self.border_color)
            rule_frame.pack(fill="x", padx=10, pady=5)

            ctk.CTkLabel(
                rule_frame,
                text=rule_name,
                font= ("Microsoft YaHei", 12, "bold"),
                text_color=self.text_color,
                width=150
            ).pack(side="left", padx=10, pady=5)

            ctk.CTkLabel(
                rule_frame,
                text=status,
                font= ("Microsoft YaHei", 12, "bold"),
                text_color=status_color,
                width=100
            ).pack(side="left", padx=10, pady=5)

            ctk.CTkLabel(
                rule_frame,
                text=message,
                font= ("Microsoft YaHei", 10),
                text_color=self.text_color,
                wraplength=400
            ).pack(side="left", fill="x", expand=True, padx=10, pady=5)

        # 关闭按钮
        ctk.CTkButton(
            dialog,
            text="关闭",
            command=dialog.destroy,
            height=32,
            font= ("Microsoft YaHei", 11, "bold"),
            fg_color=self.primary_color,
            hover_color="#52C41A",
            text_color="white",
            border_color=self.border_color,
            border_width=2,
            corner_radius=12
        ).pack(fill="x", padx=10, pady=10)

    def _export_secureclaw_audit_report(self):
        """焦糖布丁安全审计报告"""
        if not self.secureclaw_audit_result:
            messagebox.showwarning("提示", "请先运行安全审计")
            return

        file_path = filedialog.asksaveasfilename(
            defaultextension=".html",
            filetypes=[("HTML文件", "*.html"), ("所有文件", "*.*")]
        )

        if file_path:
            try:
                content = self.scanner.generate_secureclaw_audit_report(self.secureclaw_audit_result, "html")
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(content)

                messagebox.showinfo(
                    "导出成功",
                    f"报告已保存至:\n{file_path}"
                )
            except Exception as e:
                messagebox.showerror("导出失败", f"导出报告时出错:\n{str(e)}")

    def _export_secureclaw_harden_report(self):
        """焦糖布丁自动加固报告"""
        if not self.secureclaw_harden_result:
            messagebox.showwarning("提示", "请先运行自动加固")
            return

        file_path = filedialog.asksaveasfilename(
            defaultextension=".html",
            filetypes=[("HTML文件", "*.html"), ("所有文件", "*.*")]
        )

        if file_path:
            try:
                content = self.scanner.generate_secureclaw_harden_report(self.secureclaw_harden_result, "html")
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(content)

                messagebox.showinfo(
                    "导出成功",
                    f"报告已保存至:\n{file_path}"
                )
            except Exception as e:
                messagebox.showerror("导出失败", f"导出报告时出错:\n{str(e)}")

    def _export_secureclaw_skill_scan_report(self):
        """焦糖布丁技能扫描报告"""
        if not self.secureclaw_skill_scan_result:
            messagebox.showwarning("提示", "请先运行技能扫描")
            return

        file_path = filedialog.asksaveasfilename(
            defaultextension=".html",
            filetypes=[("HTML文件", "*.html"), ("所有文件", "*.*")]
        )

        if file_path:
            try:
                content = self.scanner.generate_secureclaw_skill_scan_report(self.secureclaw_skill_scan_result, "html")
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(content)

                messagebox.showinfo(
                    "导出成功",
                    f"报告已保存至:\n{file_path}"
                )
            except Exception as e:
                messagebox.showerror("导出失败", f"导出报告时出错:\n{str(e)}")

    def _export_secureclaw_integrity_report(self):
        """焦糖布丁文件完整性检查报告"""
        if not self.secureclaw_integrity_result:
            messagebox.showwarning("提示", "请先运行文件完整性检查")
            return

        file_path = filedialog.asksaveasfilename(
            defaultextension=".html",
            filetypes=[("HTML文件", "*.html"), ("所有文件", "*.*")]
        )

        if file_path:
            try:
                content = self.scanner.generate_secureclaw_integrity_report(self.secureclaw_integrity_result, "html")
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(content)

                messagebox.showinfo(
                    "导出成功",
                    f"报告已保存至:\n{file_path}"
                )
            except Exception as e:
                messagebox.showerror("导出失败", f"导出报告时出错:\n{str(e)}")

    def _export_secureclaw_privacy_report(self):
        """焦糖布丁隐私检查报告"""
        if not self.secureclaw_privacy_result:
            messagebox.showwarning("提示", "请先运行隐私检查")
            return

        file_path = filedialog.asksaveasfilename(
            defaultextension=".html",
            filetypes=[("HTML文件", "*.html"), ("所有文件", "*.*")]
        )

        if file_path:
            try:
                content = self.scanner.generate_secureclaw_privacy_report(self.secureclaw_privacy_result, "html")
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(content)

                messagebox.showinfo(
                    "导出成功",
                    f"报告已保存至:\n{file_path}"
                )
            except Exception as e:
                messagebox.showerror("导出失败", f"导出报告时出错:\n{str(e)}")

    def _export_secureclaw_behavior_report(self):
        """焦糖布丁行为规则检查报告"""
        if not self.secureclaw_behavior_result:
            messagebox.showwarning("提示", "请先运行行为规则检查")
            return

        file_path = filedialog.asksaveasfilename(
            defaultextension=".html",
            filetypes=[("HTML文件", "*.html"), ("所有文件", "*.*")]
        )

        if file_path:
            try:
                content = self.scanner.generate_secureclaw_behavior_rules_report(self.secureclaw_behavior_result, "html")
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(content)

                messagebox.showinfo(
                    "导出成功",
                    f"报告已保存至:\n{file_path}"
                )
            except Exception as e:
                messagebox.showerror("导出失败", f"导出报告时出错:\n{str(e)}")


if __name__ == "__main__":
    app = OpenClawScannerUI()
    app.mainloop()
