#!/usr/bin/env python3
import argparse
import sys
from pathlib import Path

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
)

def main():
    """命令行工具入口"""
    parser = argparse.ArgumentParser(
        description="🦞 焦糖布丁 - 命令行版本",
        formatter_class=argparse.RawTextHelpFormatter
    )
    
    # OpenClaw安装路径参数
    parser.add_argument(
        "-p", "--path",
        type=str,
        help="指定OpenClaw安装目录路径"
    )
    
    # 检测模式
    parser.add_argument(
        "-m", "--mode",
        choices=["all", "config", "skills", "ports", "auth", "deps", "host", "secrets", "proxy", "runtime", "dlp"],
        default="all",
        help="检测模式\n" 
        "all: 全部检测 (默认)\n" 
        "config: 配置安全检测\n" 
        "skills: 技能包安全检测\n" 
        "ports: 端口暴露检测\n" 
        "auth: 认证与口令检测\n" 
        "deps: 依赖供应链检测\n" 
        "host: 主机安全检测\n" 
        "secrets: 密钥泄露检测\n" 
        "proxy: 反代配置检测\n" 
        "runtime: 运行时检查\n" 
        "dlp: 数据泄露防护检测"
    )
    
    # 修复模式
    parser.add_argument(
        "-f", "--fix",
        action="store_true",
        help="启用自动修复模式"
    )
    
    # 报告格式
    parser.add_argument(
        "-o", "--output",
        choices=["json", "html", "text"],
        default="text",
        help="报告输出格式 (默认: text)"
    )
    
    # 报告文件路径
    parser.add_argument(
        "-r", "--report",
        type=str,
        help="报告输出文件路径"
    )
    
    # 静默模式
    parser.add_argument(
        "-q", "--quiet",
        action="store_true",
        help="静默模式，只输出关键信息"
    )
    
    args = parser.parse_args()
    
    # 设置自定义OpenClaw路径
    if args.path:
        PlatformAdapter.set_openclaw_path(args.path)
        if not args.quiet:
            print(f"[INFO] OpenClaw安装目录已设置为: {PlatformAdapter.get_openclaw_path()}")
    
    # 初始化扫描器
    scanner = OpenClawScanner()
    
    # 注册检测模块
    checks = {
        "config": ConfigChecker,
        "skills": SkillsChecker,
        "ports": PortsChecker,
        "auth": AuthChecker,
        "deps": DepsChecker,
        "host": HostChecker,
        "secrets": SecretsChecker,
        "proxy": ProxyChecker,
        "runtime": RuntimeChecker,
        "dlp": DLPChecker,
    }
    
    # 根据模式选择检测模块
    selected_checks = []
    if args.mode == "all":
        for check_class in checks.values():
            selected_checks.append(check_class())
    else:
        if args.mode in checks:
            selected_checks.append(checks[args.mode]())
        else:
            print(f"[ERROR] 无效的检测模式: {args.mode}")
            sys.exit(1)
    
    if not selected_checks:
        print("[ERROR] 没有选择任何检测模块")
        sys.exit(1)
    
    if not args.quiet:
        print("[INFO] 开始安全检测...")
        print(f"[INFO] 检测模式: {args.mode}")
        print(f"[INFO] 自动修复: {'启用' if args.fix else '禁用'}")
        print(f"[INFO] 输出格式: {args.output}")
        print(f"[INFO] OpenClaw路径: {PlatformAdapter.get_openclaw_path()}")
        print("=" * 60)
    
    # 运行检测
    import asyncio
    
    async def run_scan():
        def progress_callback(msg, val):
            if not args.quiet:
                print(f"[PROGRESS] {msg} ({val}%)")
        
        results = await scanner.run_selected(
            selected_checks,
            progress_callback=progress_callback,
            fix=args.fix
        )
        return results
    
    results = asyncio.run(run_scan())
    
    # 生成报告
    report_content = scanner.generate_report(results, args.output)
    
    # 输出报告
    if args.report:
        try:
            with open(args.report, 'w', encoding='utf-8') as f:
                f.write(report_content)
            if not args.quiet:
                print(f"[INFO] 报告已保存至: {args.report}")
        except Exception as e:
            print(f"[ERROR] 保存报告失败: {str(e)}")
            sys.exit(1)
    else:
        print(report_content)
    
    # 计算退出码
    summary = scanner.get_summary(results)
    if summary['critical'] > 0:
        sys.exit(2)  # 严重风险
    elif summary['high'] > 0:
        sys.exit(1)  # 高危风险
    else:
        sys.exit(0)  # 无风险或低风险

if __name__ == "__main__":
    main()
