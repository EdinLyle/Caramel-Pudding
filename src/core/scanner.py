import asyncio
from typing import List, Callable, Optional
from datetime import datetime
from checks import SecureClawAudit, SecureClawHarden, SecureClawSkillScan, SecureClawIntegrity, SecureClawPrivacy, SecureClawBehaviorRules


class OpenClawScanner:
    """OpenClaw安全扫描器核心引擎"""

    def __init__(self):
        self.checks: List = []  # 所有检测器列表
        self.is_running = False
        self.progress = 0
        self.callback: Optional[Callable] = None

    def register_check(self, check):
        """注册检测器"""
        self.checks.append(check)

    def clear_checks(self):
        """清空检测器"""
        self.checks = []

    async def run_all(self, progress_callback=None):
        """并行执行所有检测"""
        self.is_running = True
        self.callback = progress_callback
        total = len(self.checks)

        results = []

        for idx, check in enumerate(self.checks):
            if progress_callback:
                progress_callback(f"正在检测: {check.name}", (idx / total) * 100)

            try:
                await check.run()
                results.extend(check.findings)
            except Exception as e:
                check.report(f"检测异常: {str(e)}", "LOW")
                check.status = "error"

        if progress_callback:
            progress_callback("检测完成", 100)

        self.is_running = False
        return results

    async def run_selected(self, selected_checks, progress_callback=None, fix=False):
        """执行选定的检测"""
        self.is_running = True
        self.callback = progress_callback
        total = len(selected_checks)

        results = []

        for idx, check in enumerate(selected_checks):
            if progress_callback:
                progress_callback(f"正在检测: {check.name}", (idx / total) * 100)

            try:
                await check.run()
                results.extend(check.findings)
                
                # 如果启用了修复模式，执行修复
                if fix:
                    if progress_callback:
                        progress_callback(f"正在修复: {check.name}", (idx / total) * 100)
                    await check.fix()
            except Exception as e:
                check.report(f"检测异常: {str(e)}", "LOW")
                check.status = "error"

        if progress_callback:
            progress_callback("检测完成", 100)

        self.is_running = False
        return results

    def get_summary(self, findings):
        """获取检测结果摘要"""
        summary = {
            "total": len(findings),
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
        }

        for finding in findings:
            risk = finding.get('risk', 'LOW').lower()
            # 确保风险等级映射正确
            risk_map = {
                'critical': 'critical',
                'high': 'high',
                'medium': 'medium',
                'low': 'low',
                'info': 'info'
            }
            mapped_risk = risk_map.get(risk, 'low')
            if mapped_risk in summary:
                summary[mapped_risk] += 1

        return summary

    def calculate_score(self, findings):
        """计算安全评分"""
        # 模块权重配置（与dejavu保持一致）
        module_weights = {
            'skills': 0.20,    # 20%
            'network': 0.20,    # 20%
            'config': 0.15,     # 15%
            'proxy': 0.15,      # 15%
            'deps': 0.10,       # 10%
            'runtime': 0.10,     # 10%
            'auth': 0.05,       # 5%
            'host': 0.03,        # 3%
            'dlp': 0.02,         # 2%
            'vulnerability': 0.10,  # 10%
        }

        # 风险等级扣分
        risk_deductions = {
            'CRITICAL': 100,    # 严重问题直接扣100分
            'HIGH': 50,         # 高危问题扣50分
            'MEDIUM': 25,       # 中危问题扣25分
            'LOW': 10,          # 低危问题扣10分
            'INFO': 0,           # 信息性问题不扣分
        }

        # 按模块分组
        module_findings = {}
        for finding in findings:
            check = finding.get('check', 'unknown')
            # 从检查名称中提取模块名
            module = 'unknown'
            
            # 直接映射检查名称到模块
            check_module_map = {
                '配置安全检测': 'config',
                '技能包安全检测': 'skills',
                '端口暴露检测': 'network',
                '认证与口令检测': 'auth',
                '依赖供应链检测': 'deps',
                '主机安全检测': 'host',
                '密钥泄露检测': 'dlp',
                '反代配置检测': 'proxy',
                '运行时检查': 'runtime',
                '数据泄露防护检测': 'dlp',
                '漏洞扫描': 'vulnerability'
            }
            
            if check in check_module_map:
                module = check_module_map[check]
            else:
                # 尝试从检查类型中提取模块
                for key in module_weights:
                    if key in check.lower():
                        module = key
                        break
            
            if module not in module_findings:
                module_findings[module] = []
            module_findings[module].append(finding)

        # 计算模块得分
        total_score = 100
        for module, module_findings_list in module_findings.items():
            if module in module_weights:
                weight = module_weights[module]
                # 计算该模块的最高风险等级
                max_risk = 'INFO'
                for finding in module_findings_list:
                    risk = finding.get('risk', 'LOW').upper()
                    if risk_deductions.get(risk, 0) > risk_deductions.get(max_risk, 0):
                        max_risk = risk
                # 应用扣分
                deduction = risk_deductions.get(max_risk, 0) * weight
                total_score -= deduction

        # 确保分数在0-100之间
        total_score = max(0, min(100, total_score))

        return total_score

    def get_risk_level(self, score):
        """根据评分获取风险等级"""
        if score >= 90:
            return "LOW RISK"
        elif score >= 70:
            return "MEDIUM RISK"
        elif score >= 50:
            return "HIGH RISK"
        else:
            return "CRITICAL RISK"

    def get_exit_code(self, findings):
        """获取语义化退出码
        
        0: 无MEDIUM及以上问题
        1: 存在MEDIUM严重性问题
        2: 存在HIGH严重性问题
        3: 存在CRITICAL严重性问题
        """
        summary = self.get_summary(findings)
        
        if summary['critical'] > 0:
            return 3
        elif summary['high'] > 0:
            return 2
        elif summary['medium'] > 0:
            return 1
        else:
            return 0

    def generate_report(self, findings, format="html"):
        """生成检测报告"""
        if format == "html":
            return self._generate_html_report(findings)
        elif format == "json":
            return self._generate_json_report(findings)
        elif format == "text":
            return self._generate_text_report(findings)
        else:
            raise ValueError(f"不支持的报告格式: {format}")
    
    def run_secureclaw_audit(self, openclaw_dir):
        """运行🦞 焦糖布丁安全审计"""
        auditor = SecureClawAudit()
        return auditor.run_audit(openclaw_dir)
    
    def generate_secureclaw_audit_report(self, audit_result, format="html"):
        """生成🦞 焦糖布丁安全审计报告"""
        if format == "html":
            return self._generate_secureclaw_audit_html_report(audit_result)
        elif format == "json":
            return self._generate_secureclaw_audit_json_report(audit_result)
        else:
            raise ValueError(f"不支持的报告格式: {format}")
    
    def run_secureclaw_harden(self, openclaw_dir):
        """运行🦞 焦糖布丁自动加固"""
        hardener = SecureClawHarden()
        return hardener.run_harden(openclaw_dir)
    
    def generate_secureclaw_harden_report(self, harden_result, format="html"):
        """生成🦞 焦糖布丁自动加固报告"""
        if format == "html":
            return self._generate_secureclaw_harden_html_report(harden_result)
        elif format == "json":
            return self._generate_secureclaw_harden_json_report(harden_result)
        else:
            raise ValueError(f"不支持的报告格式: {format}")
    
    def run_secureclaw_skill_scan(self, skills_dir):
        """运行🦞 焦糖布丁技能扫描"""
        scanner = SecureClawSkillScan()
        return scanner.scan_skills(skills_dir)
    
    def generate_secureclaw_skill_scan_report(self, scan_result, format="html"):
        """生成🦞 焦糖布丁技能扫描报告"""
        if format == "html":
            return self._generate_secureclaw_skill_scan_html_report(scan_result)
        elif format == "json":
            return self._generate_secureclaw_skill_scan_json_report(scan_result)
        else:
            raise ValueError(f"不支持的报告格式: {format}")
    
    def run_secureclaw_integrity(self, openclaw_dir):
        """运行🦞 焦糖布丁文件完整性检查"""
        integrity = SecureClawIntegrity()
        return integrity.check_integrity(openclaw_dir)
    
    def generate_secureclaw_integrity_report(self, integrity_result, format="html"):
        """生成🦞 焦糖布丁文件完整性检查报告"""
        if format == "html":
            return self._generate_secureclaw_integrity_html_report(integrity_result)
        elif format == "json":
            return self._generate_secureclaw_integrity_json_report(integrity_result)
        else:
            raise ValueError(f"不支持的报告格式: {format}")
    
    def run_secureclaw_privacy(self, text):
        """运行🦞 焦糖布丁隐私检查"""
        privacy = SecureClawPrivacy()
        return privacy.check_privacy(text)
    
    def generate_secureclaw_privacy_report(self, privacy_result, format="html"):
        """生成🦞 焦糖布丁隐私检查报告"""
        if format == "html":
            return self._generate_secureclaw_privacy_html_report(privacy_result)
        elif format == "json":
            return self._generate_secureclaw_privacy_json_report(privacy_result)
        else:
            raise ValueError(f"不支持的报告格式: {format}")
    
    def create_secureclaw_baselines(self, openclaw_dir):
        """创建🦞 焦糖布丁认知文件基线"""
        integrity = SecureClawIntegrity()
        return integrity.create_baselines(openclaw_dir)
    
    def run_secureclaw_behavior_rules(self, openclaw_dir):
        """运行🦞 焦糖布丁行为规则检查"""
        rules = SecureClawBehaviorRules()
        return rules.run_rules(openclaw_dir)
    
    def generate_secureclaw_behavior_rules_report(self, rules_result, format="html"):
        """生成🦞 焦糖布丁行为规则检查报告"""
        if format == "html":
            return self._generate_secureclaw_behavior_rules_html_report(rules_result)
        elif format == "json":
            return self._generate_secureclaw_behavior_rules_json_report(rules_result)
        else:
            raise ValueError(f"不支持的报告格式: {format}")

    def _generate_html_report(self, findings):
        """生成HTML报告"""
        summary = self.get_summary(findings)
        score = self.calculate_score(findings)
        risk_level = self.get_risk_level(score)

        # 构建HTML报告
        html = '''<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>🦞 焦糖布丁安全检测报告</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        body {
            font-family: "Microsoft YaHei", "Segoe UI", Arial, sans-serif;
            margin: 40px;
            background-color: #FFF9F0;
            color: #2C2C2C;
        }
        .container {
            max-width: 1400px;
            margin: 0 auto;
        }
        .header {
            background-color: #73D13D;
            padding: 40px;
            border-radius: 16px;
            margin-bottom: 30px;
            border: 3px solid #2C2C2C;
            position: relative;
            overflow: hidden;
            box-shadow: 4px 4px 0 #2C2C2C;
            text-align: center;
        }
        .disclaimer {
            background-color: #FFD93D;
            padding: 20px;
            border-radius: 16px;
            margin: 20px 0;
            border: 3px solid #2C2C2C;
            box-shadow: 4px 4px 0 #2C2C2C;
            text-align: center;
            font-weight: bold;
            color: #2C2C2C;
        }
        .header::before {
            content: '';
            position: absolute;
            top: 0;
            right: 0;
            width: 200px;
            height: 200px;
            background: url('data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iMjAwIiBoZWlnaHQ9IjIwMCIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIj48cGF0aCBkPSJNMTAgMTAgMTgwIDE4MCIgZmlsbD0iI2ZmZmZmZiIvPjxwYXRoIGQ9Ik0xMCAxODAgMTgwIDEwIiBmaWxsPSIjZmZmZmZmIi8+PHBhdGggZD0iTTEwIDkwIDE4MCA5MCIgZmlsbD0iI2ZmZmZmZiIvPjwvc3ZnPg==') no-repeat center;
            background-size: contain;
            opacity: 0.2;
        }
        .summary-card::before {
            content: '';
            display: block;
            width: 40px;
            height: 40px;
            margin: 0 auto 10px;
            background-size: contain;
            background-repeat: no-repeat;
            background-position: center;
        }
        .summary-card:nth-child(1)::before {
            background-image: url('data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iNDAiIGhlaWdodD0iNDAiIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwL3N2ZyI+PHBhdGggZD0iTTEwIDEwIDIwIDIwIDEwIDMwIiBmaWxsPSIjMkMyQzJDIi8+PHBhdGggZD0iTTIwIDEwIDMwIDIwIDIwIDMwIiBmaWxsPSIjMkMyQzJDIi8+PHBhdGggZD0iTTEwIDIwIDIwIDMwIDEwIDQwIiBmaWxsPSIjMkMyQzJDIi8+PHBhdGggZD0iTTIwIDIwIDMwIDMwIDIwIDQwIiBmaWxsPSIjMkMyQzJDIi8+PC9zdmc+');
        }
        .summary-card:nth-child(2)::before {
            background-image: url('data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iNDAiIGhlaWdodD0iNDAiIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwL3N2ZyI+PHBhdGggZD0iTTIwIDUgMjAgMzUiIHN0cm9rZT0iI0ZBNTI1MiIgc3Ryb2tlLXdpZHRoPSIzIi8+PHBhdGggZD0iTTEwIDE1IDEwIDI1IiBzdHJva2U9IiNmYTUyNTIiIHN0cm9rZS13aWR0aD0iMyIvPjxwYXRoIGQ9Ik0zMCAxNSAzMCAyNSIgc3Ryb2tlPSIjZmE1MjUyIiBzdHJva2Utd2lkdGg9IjMiLz48cGF0aCBkPSJNMTAgMTAgMzAgMTAgMjAgMzAiIHN0cm9rZT0iI0ZBNTI1MiIgc3Ryb2tlLXdpZHRoPSIzIi8+PC9zdmc+');
        }
        .summary-card:nth-child(3)::before {
            background-image: url('data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iNDAiIGhlaWdodD0iNDAiIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwL3N2ZyI+PHBhdGggZD0iTTIwIDUgMjAgMzUiIHN0cm9rZT0iI0ZBNTI1MiIgc3Ryb2tlLXdpZHRoPSIzIi8+PHBhdGggZD0iTTEwIDE1IDEwIDI1IiBzdHJva2U9IiNmYTUyNTIiIHN0cm9rZS13aWR0aD0iMyIvPjxwYXRoIGQ9Ik0zMCAxNSAzMCAyNSIgc3Ryb2tlPSIjZmE1MjUyIiBzdHJva2Utd2lkdGg9IjMiLz48L3N2Zz4=');
        }
        .summary-card:nth-child(4)::before {
            background-image: url('data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iNDAiIGhlaWdodD0iNDAiIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwL3N2ZyI+PHBhdGggZD0iTTIwIDUgMjAgMzUiIHN0cm9rZT0iI0ZGRDkzRCIgc3Ryb2tlLXdpZHRoPSIzIi8+PHBhdGggZD0iTTEwIDE1IDEwIDI1IiBzdHJva2U9IiNGRkQ5M0QiIHN0cm9rZS13aWR0aD0iMyIvPjxwYXRoIGQ9Ik0zMCAxNSAzMCAyNSIgc3Ryb2tlPSIjRkZEOjNkIiBzdHJva2Utd2lkdGg9IjMiLz48L3N2Zz4=');
        }
        .summary-card:nth-child(5)::before {
            background-image: url('data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iNDAiIGhlaWdodD0iNDAiIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwL3N2ZyI+PHBhdGggZD0iTTIwIDUgMjAgMzUiIHN0cm9rZT0iI0Y1QzQxQSIgc3Ryb2tlLXdpZHRoPSIzIi8+PHBhdGggZD0iTTEwIDE1IDEwIDI1IiBzdHJva2U9IiNBNUM0MWEiIHN0cm9rZS13aWR0aD0iMyIvPjxwYXRoIGQ9Ik0zMCAxNSAzMCAyNSIgc3Ryb2tlPSIjODVDNDFhIiBzdHJva2Utd2lkdGg9IjMiLz48L3N2Zz4=');
        }
        .recommendation::before {
            content: '';
            position: absolute;
            top: 20px;
            right: 20px;
            width: 100px;
            height: 100px;
            background: url('data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iMTAwIiBoZWlnaHQ9IjEwMCIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIj48cGF0aCBkPSJNMTAgMTAgOTAgOTAiIGZpbGw9IiMyQzJDMkMiLz48cGF0aCBkPSJNMTAgOTAgOTAgMTAiIGZpbGw9IiMyQzJDMkMiLz48cGF0aCBkPSJNMTAgNTAgOTAgNTAiIGZpbGw9IiMyQzJDMkMiLz48L3N2Zz4=') no-repeat center;
            background-size: contain;
            opacity: 0.2;
        }
        .recommendation {
            position: relative;
        }
        .header h1 {
            font-size: 36px;
            margin-bottom: 10px;
            color: white;
            font-weight: 600;
        }
        .header p {
            font-size: 16px;
            opacity: 0.9;
            margin-bottom: 5px;
            color: white;
        }
        .score-card {
            background-color: #FFFFFF;
            padding: 20px;
            border-radius: 16px;
            margin-bottom: 30px;
            border: 3px solid #2C2C2C;
            text-align: center;
            box-shadow: 4px 4px 0 #2C2C2C;
        }
        .score-value {
            font-size: 48px;
            font-weight: bold;
            color: #2C2C2C;
            margin-bottom: 10px;
        }
        .risk-level {
            font-size: 24px;
            font-weight: bold;
            margin-bottom: 10px;
        }
        .risk-level.LOW { color: #51CF66; }
        .risk-level.MEDIUM { color: #FFD93D; }
        .risk-level.HIGH { color: #FA5252; }
        .risk-level.CRITICAL { color: #FA5252; }
        .summary {
            display: grid;
            grid-template-columns: repeat(5, 1fr);
            gap: 20px;
            margin-bottom: 30px;
        }
        .summary-card {
            background-color: #FFFFFF;
            padding: 20px;
            border-radius: 16px;
            text-align: center;
            border: 3px solid #2C2C2C;
            box-shadow: 4px 4px 0 #2C2C2C;
        }
        .summary-card h3 {
            font-size: 32px;
            margin-bottom: 10px;
            color: #2C2C2C;
            font-weight: 600;
        }
        .summary-card p {
            font-size: 14px;
            color: #2C2C2C;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        .critical { color: #FA5252; }
        .high { color: #FA5252; }
        .medium { color: #FFD93D; }
        .low { color: #51CF66; }
        .info { color: #4DABF7; }
        .total { color: #2C2C2C; font-size: 40px; }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
            background-color: #FFFFFF;
            border-radius: 16px;
            overflow: hidden;
            border: 3px solid #2C2C2C;
            box-shadow: 4px 4px 0 #2C2C2C;
        }
        th {
            background-color: #73D13D;
            padding: 15px;
            text-align: left;
            font-weight: bold;
            color: white;
        }
        td {
            padding: 12px;
            border-bottom: 1px solid #2C2C2C;
        }
        tr:hover {
            background-color: #F0F0F0;
        }
        .timestamp {
            color: #2C2C2C;
            font-size: 0.9em;
        }
        .tag {
            display: inline-block;
            padding: 4px 12px;
            border-radius: 8px;
            font-size: 12px;
            font-weight: bold;
            border: 3px solid #2C2C2C;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        .tag-critical {
            background: #FA5252;
            color: white;
        }
        .tag-high {
            background: #FA5252;
            color: white;
        }
        .tag-medium {
            background: #FFD93D;
            color: #2C2C2C;
        }
        .tag-low {
            background: #51CF66;
            color: white;
        }
        .tag-info {
            background: #4DABF7;
            color: white;
        }
        .recommendation {
            background-color: #FFFFFF;
            padding: 20px;
            border-radius: 16px;
            margin-top: 30px;
            border: 3px solid #2C2C2C;
            box-shadow: 4px 4px 0 #2C2C2C;
        }
        .recommendation h2 {
            font-size: 24px;
            margin-bottom: 15px;
            color: #2C2C2C;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        .recommendation h3 {
            font-size: 18px;
            margin: 20px 0 10px;
            color: #2C2C2C;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        .recommendation ul {
            list-style-type: none;
            padding-left: 20px;
        }
        .recommendation li {
            margin-bottom: 10px;
            position: relative;
        }
        .recommendation li::before {
            content: '•';
            color: #73D13D;
            font-weight: bold;
            position: absolute;
            left: -20px;
        }
        .fix-command {
            background: #FFF9F0;
            padding: 10px;
            border-radius: 8px;
            font-family: 'Courier New', monospace;
            margin: 5px 0;
            border: 3px solid #2C2C2C;
            box-shadow: 2px 2px 0 #2C2C2C;
        }
        button {
            background-color: #73D13D;
            color: white;
            border: 3px solid #2C2C2C;
            padding: 10px 20px;
            border-radius: 12px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            box-shadow: 4px 4px 0 #2C2C2C;
            cursor: pointer;
        }
        button:hover {
            background-color: #52C41A;
        }
        button:active {
            transform: translate(2px, 2px);
            box-shadow: 2px 2px 0 #2C2C2C;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🦞 OpenClaw 基线安全检测报告</h1>
            <p>生成时间: ''' + datetime.now().strftime('%Y-%m-%d %H:%M:%S') + '''</p>
            <p>检测工具: 🦞 焦糖布丁</p>
            <p>工具作者: 0x八月</p>
            <p>发现风险项: ''' + str(summary['total']) + ''' 个</p>
        </div>
        
        <div class="disclaimer">
            ⚠️ 工具修复方案和内容仅供参考，由于传播、利用此工具所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，作者不为此承担任何责任。
        </div>

        <div class="score-card">
            <div class="score-value">''' + str(score) + '''/100</div>
            <div class="risk-level ''' + risk_level.split()[0] + '''">''' + risk_level + '''</div>
            <p>基于模块加权评分系统</p>
        </div>

        <div class="summary">
            <div class="summary-card">
                <h3 class="total">''' + str(summary['total']) + '''</h3>
                <p>总计</p>
            </div>
            <div class="summary-card">
                <h3 class="critical">''' + str(summary['critical']) + '''</h3>
                <p>严重</p>
            </div>
            <div class="summary-card">
                <h3 class="high">''' + str(summary['high']) + '''</h3>
                <p>高危</p>
            </div>
            <div class="summary-card">
                <h3 class="medium">''' + str(summary['medium']) + '''</h3>
                <p>中危</p>
            </div>
            <div class="summary-card">
                <h3 class="low">''' + str(summary['low']) + '''</h3>
                <p>低危</p>
            </div>
        </div>

        <table>
            <thead>
                <tr>
                    <th>风险等级</th>
                    <th>检测项</th>
                    <th>发现问题</th>
                    <th>修复方式</th>
                    <th>时间戳</th>
                </tr>
            </thead>
            <tbody>
'''

        for f in findings:
            risk_class = f['risk'].lower()
            # 生成修复建议
            fix_suggestion = self._get_fix_suggestion(f)
            html += '''
                <tr>
                    <td><span class="tag tag-''' + risk_class + '''">''' + f['risk'] + '''</span></td>
                    <td>''' + f['check'] + '''</td>
                    <td>''' + f['finding'] + '''</td>
                    <td>''' + fix_suggestion.replace('\n', '<br>') + '''</td>
                    <td class="timestamp">''' + f['timestamp'] + '''</td>
                </tr>
'''

        html += '''
            </tbody>
        </table>

        <div class="recommendation">
            <h2>安全建议</h2>
            
            <h3>配置安全检测</h3>
            <ul>
                <li><strong>问题:</strong> 硬编码API Key</li>
                <li><strong>修复方案:</strong> 将API Key移至环境变量，使用secrets manager管理敏感信息</li>
                <li><strong>修复命令:</strong> export API_KEY=your_key</li>
            </ul>
            <ul>
                <li><strong>问题:</strong> 配置文件权限过于宽松</li>
                <li><strong>修复方案:</strong> 修改配置文件权限</li>
                <li><strong>修复命令:</strong> chmod 600 openclaw.json</li>
            </ul>
            <ul>
                <li><strong>问题:</strong> 沙箱已关闭</li>
                <li><strong>修复方案:</strong> 在openclaw.json中启用沙箱</li>
                <li><strong>修复命令:</strong> 设置: "sandbox": true</li>
            </ul>
            
            <h3>技能包安全检测</h3>
            <ul>
                <li><strong>问题:</strong> 恶意代码</li>
                <li><strong>修复方案:</strong> 移除恶意技能包，更新技能包</li>
                <li><strong>修复命令:</strong> openclaw skills remove <skill-name> && openclaw skills update</li>
            </ul>
            <ul>
                <li><strong>问题:</strong> 权限过高</li>
                <li><strong>修复方案:</strong> 审核技能包权限，移除不必要的权限</li>
                <li><strong>修复命令:</strong> 手动审查技能包配置</li>
            </ul>
            
            <h3>端口暴露检测</h3>
            <ul>
                <li><strong>问题:</strong> 公网暴露</li>
                <li><strong>修复方案:</strong> 修改绑定地址，配置防火墙规则</li>
                <li><strong>修复命令:</strong> 设置: "bind": "loopback"或"lan"</li>
            </ul>
            
            <h3>认证与口令检测</h3>
            <ul>
                <li><strong>问题:</strong> 弱密码</li>
                <li><strong>修复方案:</strong> 使用强随机密码，定期轮换密码</li>
                <li><strong>修复命令:</strong> openssl rand -hex 16</li>
            </ul>
            
            <h3>依赖供应链检测</h3>
            <ul>
                <li><strong>问题:</strong> 依赖漏洞</li>
                <li><strong>修复方案:</strong> 修复依赖漏洞，定期更新依赖</li>
                <li><strong>修复命令:</strong> npm audit fix 或 pnpm audit fix</li>
            </ul>
            
            <h3>主机安全检测</h3>
            <ul>
                <li><strong>问题:</strong> 防火墙未启用</li>
                <li><strong>修复方案:</strong> 启用防火墙，限制必要端口的访问</li>
                <li><strong>修复命令:</strong> sudo ufw enable (Linux)</li>
            </ul>
            
            <h3>密钥泄露检测</h3>
            <ul>
                <li><strong>问题:</strong> 硬编码密钥</li>
                <li><strong>修复方案:</strong> 移除硬编码的密钥，使用环境变量</li>
                <li><strong>修复命令:</strong> export API_KEY=your_key</li>
            </ul>
            
            <h3>反代配置检测</h3>
            <ul>
                <li><strong>问题:</strong> 不安全的代理设置</li>
                <li><strong>修复方案:</strong> 配置适当的代理设置，启用认证，配置HTTPS</li>
                <li><strong>修复命令:</strong> 审查并修改反向代理配置</li>
            </ul>
            
            <h3>运行时检查</h3>
            <ul>
                <li><strong>问题:</strong> 运行时异常</li>
                <li><strong>修复方案:</strong> 重启OpenClaw服务，检查日志文件</li>
                <li><strong>修复命令:</strong> openclaw restart</li>
            </ul>
            
            <h3>数据泄露防护检测</h3>
            <ul>
                <li><strong>问题:</strong> 敏感数据未加密</li>
                <li><strong>修复方案:</strong> 实施数据加密，配置访问控制，定期审计数据处理</li>
                <li><strong>修复命令:</strong> 配置数据加密设置</li>
            </ul>
            
            <h3>漏洞扫描</h3>
            <ul>
                <li><strong>问题:</strong> CVE-2026-25253（认证令牌窃取）</li>
                <li><strong>修复方案:</strong> 启用认证模式，更新OpenClaw到最新版本</li>
                <li><strong>修复命令:</strong> 设置: "auth.mode": "token"</li>
            </ul>
            <ul>
                <li><strong>问题:</strong> 默认暴露公网</li>
                <li><strong>修复方案:</strong> 修改绑定地址，配置防火墙规则</li>
                <li><strong>修复命令:</strong> 设置: "bind": "loopback"</li>
            </ul>
            <ul>
                <li><strong>问题:</strong> 插件投毒</li>
                <li><strong>修复方案:</strong> 只使用来自可信来源的技能包，定期更新技能包</li>
                <li><strong>修复命令:</strong> openclaw skills verify</li>
            </ul>
            
            <h3>总体建议</h3>
            <ul>
                <li>定期进行安全扫描，及时发现和修复安全问题</li>
                <li>保持OpenClaw及其依赖的最新版本</li>
                <li>遵循最小权限原则配置OpenClaw</li>
                <li>定期备份配置和数据</li>
                <li>建立安全事件响应机制</li>
            </ul>
        </div>
    </div>
</body>
</html>
'''
        return html

    def _generate_json_report(self, findings):
        """生成JSON报告"""
        import json

        summary = self.get_summary(findings)
        score = self.calculate_score(findings)
        risk_level = self.get_risk_level(score)

        report = {
            "metadata": {
                "title": "🦞 焦糖布丁安全检测报告",
                "generated_at": datetime.now().isoformat(),
                "scanner_version": "2.0.0",
                "total_findings": summary['total']
            },
            "summary": summary,
            "score": score,
            "risk_level": risk_level,
            "findings": findings
        }

        return json.dumps(report, ensure_ascii=False, indent=2)

    def _get_fix_suggestion(self, finding):
        """根据检测结果生成修复建议"""
        check = finding['check']
        finding_text = finding['finding']
        
        # 配置安全检测修复建议
        if check == '配置安全检测':
            if '硬编码API Key' in finding_text:
                return "1. 将API Key移至环境变量\n2. 使用secrets manager管理敏感信息\n3. 命令: export API_KEY=your_key"
            elif '配置文件权限过于宽松' in finding_text:
                return "1. 修改配置文件权限\n2. 命令: chmod 600 openclaw.json"
            elif '沙箱已关闭' in finding_text:
                return "1. 在openclaw.json中启用沙箱\n2. 设置: \"sandbox\": true"
            elif '网关认证已关闭' in finding_text:
                return "1. 启用认证\n2. 设置: \"auth.enabled\": true\n3. 配置认证模式和密码"
            elif '环境变量明文存储' in finding_text:
                return "1. 启用环境变量加密\n2. 设置: \"envEncryption\": true"
            elif '危险操作无需确认' in finding_text:
                return "1. 启用危险操作确认\n2. 设置: \"confirmDestructive\": true"
            elif '调试模式已开启' in finding_text:
                return "1. 在生产环境关闭调试模式\n2. 设置: \"debug\": false"
            elif '允许未签名技能包' in finding_text:
                return "1. 禁止未签名技能包\n2. 设置: \"allowUnsignedSkills\": false"
            elif '自动更新已关闭' in finding_text:
                return "1. 启用自动更新\n2. 设置: \"autoUpdate\": true"
            elif '允许所有操作' in finding_text:
                return "1. 禁用允许所有操作\n2. 设置: \"allowAll\": false"
            elif '安全检查已关闭' in finding_text:
                return "1. 启用安全检查\n2. 设置: \"disableSafety\": false"
            elif '跳过验证' in finding_text:
                return "1. 启用验证\n2. 设置: \"skipVerification\": false"
            elif '绕过认证' in finding_text:
                return "1. 禁用绕过认证\n2. 设置: \"bypassAuth\": false"
            elif '开发模式已开启' in finding_text:
                return "1. 在生产环境关闭开发模式\n2. 设置: \"devMode\": false"
            elif '不安全模式已开启' in finding_text:
                return "1. 禁用不安全模式\n2. 设置: \"insecure\": false"
            elif '允许不安全操作' in finding_text:
                return "1. 禁用不安全操作\n2. 设置: \"allowUnsafe\": false"
            elif 'SOUL.md存在提示注入风险' in finding_text:
                return "1. 移除尝试绕过安全约束的指令\n2. 审核SOUL.md内容"
            elif 'MEMORY.md包含敏感关键词' in finding_text:
                return "1. 从MEMORY.md中移除敏感信息\n2. 定期检查敏感内容"
            elif '未找到openclaw.json配置文件' in finding_text:
                return "1. 运行初始化命令\n2. 命令: openclaw init"
            elif '配置文件解析失败' in finding_text:
                return "1. 修复JSON语法错误\n2. 使用JSON验证工具检查"
            else:
                return "1. 检查openclaw.json配置文件\n2. 确保所有安全选项正确配置\n3. 参考官方文档进行最佳实践配置"
        
        # 技能包安全修复建议
        elif check == '技能包安全检测':
            if '恶意代码' in finding_text:
                return "1. 移除恶意技能包\n2. 命令: openclaw skills remove <skill-name>\n3. 运行: openclaw skills update"
            elif '权限过高' in finding_text:
                return "1. 审核技能包权限\n2. 移除不必要的权限\n3. 只授予最小必要权限"
            elif '未签名' in finding_text:
                return "1. 只使用来自可信来源的签名技能包\n2. 命令: openclaw skills verify"
            elif '技能包' in finding_text:
                return "1. 更新技能包到最新版本\n2. 命令: openclaw skills update"
            else:
                return "1. 审查所有已安装的技能包\n2. 移除未使用的技能包\n3. 定期更新技能包到最新版本"
        
        # 端口暴露修复建议
        elif check == '端口暴露检测':
            if '公网暴露' in finding_text:
                return "1. 修改绑定地址\n2. 设置: \"bind\": \"loopback\"或\"lan\"\n3. 配置防火墙规则"
            elif '无认证' in finding_text:
                return "1. 启用认证\n2. 设置: \"auth.enabled\": true\n3. 配置强密码"
            elif '端口' in finding_text:
                return "1. 使用防火墙限制端口访问\n2. 命令: iptables -I INPUT -p tcp --dport <port> -j DROP (Linux)"
            else:
                return "1. 检查OpenClaw绑定地址配置\n2. 确保只在必要的网络接口上监听\n3. 配置适当的防火墙规则"
        
        # 认证与口令检测修复建议
        elif check == '认证与口令检测':
            if '弱密码' in finding_text:
                return "1. 使用强随机密码\n2. 命令: openssl rand -hex 16\n3. 定期轮换密码"
            elif '未设置' in finding_text:
                return "1. 在openclaw.json中设置认证\n2. 配置: \"auth.mode\": \"token\""
            elif '认证' in finding_text:
                return "1. 配置适当的认证设置\n2. 启用速率限制防止暴力破解"
            else:
                return "1. 确保启用认证\n2. 使用强密码或令牌\n3. 定期轮换认证凭证"
        
        # 依赖供应链修复建议
        elif check == '依赖供应链检测':
            if '漏洞' in finding_text:
                return "1. 修复依赖漏洞\n2. 命令: npm audit fix 或 pnpm audit fix\n3. 定期更新依赖"
            elif '过时' in finding_text:
                return "1. 更新依赖到最新安全版本\n2. 命令: npm update 或 pnpm update"
            elif '依赖' in finding_text:
                return "1. 运行依赖更新\n2. 命令: npm update 或 pnpm update"
            else:
                return "1. 定期检查依赖漏洞\n2. 运行: npm audit 或 pnpm audit\n3. 及时更新有漏洞的依赖"
        
        # 主机安全修复建议
        elif check == '主机安全检测':
            if '防火墙' in finding_text:
                return "1. 启用防火墙\n2. 限制必要端口的访问\n3. 命令: sudo ufw enable (Linux)"
            elif '权限' in finding_text:
                return "1. 以最小权限运行OpenClaw\n2. 避免使用root/管理员权限"
            elif '主机' in finding_text:
                return "1. 审查系统安全设置\n2. 定期更新系统补丁"
            else:
                return "1. 确保系统防火墙已启用\n2. 以非特权用户运行OpenClaw\n3. 定期更新系统和软件"
        
        # 密钥泄露检测修复建议
        elif check == '密钥泄露检测':
            if '密钥' in finding_text or 'token' in finding_text:
                return "1. 移除硬编码的密钥\n2. 使用环境变量\n3. 命令: export API_KEY=your_key"
            elif '泄露' in finding_text:
                return "1. 审查代码中的硬编码凭证\n2. 使用secrets manager"
            else:
                return "1. 搜索代码库中的硬编码密钥\n2. 使用环境变量存储敏感信息\n3. 定期轮换密钥"
        
        # 反代配置检测修复建议
        elif check == '反代配置检测':
            if '不安全' in finding_text:
                return "1. 配置适当的代理设置\n2. 启用认证\n3. 配置HTTPS"
            elif '反代' in finding_text:
                return "1. 审查反向代理配置\n2. 确保正确设置X-Forwarded-For"
            else:
                return "1. 审查反向代理配置\n2. 确保启用HTTPS\n3. 配置适当的认证"
        
        # 运行时检查修复建议
        elif check == '运行时检查':
            if '异常' in finding_text:
                return "1. 重启OpenClaw服务\n2. 检查日志文件\n3. 命令: openclaw restart"
            elif '运行时' in finding_text:
                return "1. 检查OpenClaw服务状态\n2. 命令: openclaw status"
            else:
                return "1. 检查OpenClaw服务状态\n2. 查看日志文件排查问题\n3. 必要时重启服务"
        
        # 数据泄露防护检测修复建议
        elif check == '数据泄露防护检测':
            if '敏感数据' in finding_text:
                return "1. 实施数据加密\n2. 配置访问控制\n3. 定期审计数据处理"
            elif '泄露' in finding_text:
                return "1. 审查数据处理实践\n2. 实施数据分类和保护措施"
            else:
                return "1. 实施数据加密\n2. 配置访问控制\n3. 定期审计数据处理流程"
        
        # 漏洞扫描修复建议
        elif check == '漏洞扫描':
            if 'CVE-2026-25253' in finding_text:
                return "1. 启用认证模式\n2. 设置: \"auth.mode\": \"token\"\n3. 更新OpenClaw到最新版本"
            elif '默认暴露公网' in finding_text:
                return "1. 修改绑定地址\n2. 设置: \"bind\": \"loopback\"\n3. 配置防火墙规则"
            elif '插件投毒' in finding_text:
                return "1. 只使用来自可信来源的技能包\n2. 命令: openclaw skills verify\n3. 定期更新技能包"
            elif '权限失控' in finding_text:
                return "1. 配置权限控制\n2. 禁用allowAll权限\n3. 遵循最小权限原则"
            elif '架构缺陷' in finding_text:
                return "1. 启用沙箱\n2. 配置网络隔离\n3. 设置资源限制"
            elif '漏洞' in finding_text:
                return "1. 更新OpenClaw到最新版本\n2. 应用安全补丁\n3. 定期检查漏洞公告"
            else:
                return "1. 更新OpenClaw到最新版本\n2. 应用安全补丁\n3. 定期进行漏洞扫描"
        
        # 默认修复建议
        return "1. 审查并修复问题\n2. 按照安全最佳实践进行配置\n3. 定期进行安全审计"


    def _generate_text_report(self, findings):
        """生成文本报告"""
        summary = self.get_summary(findings)
        score = self.calculate_score(findings)
        risk_level = self.get_risk_level(score)

        text = f'''
{'='*80}
OpenClaw 基线安全检测报告
{'='*80}

生成时间: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}

检测摘要:
{'-'*80}
总计:     {summary['total']} 个
严重:     {summary['critical']} 个
高危:     {summary['high']} 个
中危:     {summary['medium']} 个
低危:     {summary['low']} 个
信息:     {summary['info']} 个

安全评分:
{'-'*80}
得分:     {score:.1f}/100
风险等级: {risk_level}

检测结果:
{'-'*80}
'''

        for idx, f in enumerate(findings, 1):
            text += f'''
[{idx}] {f['risk']} - {f['check']}
    问题: {f['finding']}
    修复建议: {self._get_fix_suggestion(f)}
    时间: {f['timestamp']}
'''

        text += f'''
{'='*80}
'''

        return text
    
    def _generate_secureclaw_audit_html_report(self, audit_result):
        """生成🦞 焦糖布丁安全审计HTML报告"""
        score = audit_result.get("score", 0)
        passed_checks = audit_result.get("passed_checks", 0)
        total_checks = audit_result.get("total_checks", 0)
        results = audit_result.get("results", {})

        # 构建HTML报告
        html = '''<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>🦞 焦糖布丁安全审计报告</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        body {
            font-family: "Microsoft YaHei", "Segoe UI", Arial, sans-serif;
            margin: 40px;
            background-color: #FFF9F0;
            color: #2C2C2C;
        }
        .container {
            max-width: 1400px;
            margin: 0 auto;
        }
        .header {
            background-color: #73D13D;
            padding: 40px;
            border-radius: 16px;
            margin-bottom: 30px;
            border: 3px solid #2C2C2C;
            position: relative;
            overflow: hidden;
            box-shadow: 4px 4px 0 #2C2C2C;
            text-align: center;
        }
        .disclaimer {
            background-color: #FFD93D;
            padding: 20px;
            border-radius: 16px;
            margin: 20px 0;
            border: 3px solid #2C2C2C;
            box-shadow: 4px 4px 0 #2C2C2C;
            text-align: center;
            font-weight: bold;
            color: #2C2C2C;
        }
        .header::before {
            content: '';
            position: absolute;
            top: 0;
            right: 0;
            width: 200px;
            height: 200px;
            background: url('data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iMjAwIiBoZWlnaHQ9IjIwMCIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIj48cGF0aCBkPSJNMTAgMTAgMTgwIDE4MCIgZmlsbD0iI2ZmZmZmZiIvPjxwYXRoIGQ9Ik0xMCAxODAgMTgwIDEwIiBmaWxsPSIjZmZmZmZmIi8+PHBhdGggZD0iTTEwIDkwIDE4MCA5MCIgZmlsbD0iI2ZmZmZmZiIvPjwvc3ZnPg==') no-repeat center;
            background-size: contain;
            opacity: 0.2;
        }
        .score-card {
            background-color: #FFFFFF;
            padding: 20px;
            border-radius: 16px;
            margin-bottom: 30px;
            border: 3px solid #2C2C2C;
            text-align: center;
            box-shadow: 4px 4px 0 #2C2C2C;
        }
        .score-value {
            font-size: 48px;
            font-weight: bold;
            color: #2C2C2C;
            margin-bottom: 10px;
        }
        .score-info {
            font-size: 16px;
            color: #2C2C2C;
            margin-bottom: 5px;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
            background-color: #FFFFFF;
            border-radius: 16px;
            overflow: hidden;
            border: 3px solid #2C2C2C;
            box-shadow: 4px 4px 0 #2C2C2C;
        }
        th {
            background-color: #73D13D;
            padding: 15px;
            text-align: left;
            font-weight: bold;
            color: white;
        }
        td {
            padding: 12px;
            border-bottom: 1px solid #2C2C2C;
        }
        tr:hover {
            background-color: #F0F0F0;
        }
        .tag {
            display: inline-block;
            padding: 4px 12px;
            border-radius: 8px;
            font-size: 12px;
            font-weight: bold;
            border: 3px solid #2C2C2C;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        .tag-pass {
            background: #51CF66;
            color: white;
        }
        .tag-fail {
            background: #FA5252;
            color: white;
        }
        .tag-warn {
            background: #FFD93D;
            color: #2C2C2C;
        }
        .recommendation {
            background-color: #FFFFFF;
            padding: 20px;
            border-radius: 16px;
            margin-top: 30px;
            border: 3px solid #2C2C2C;
            box-shadow: 4px 4px 0 #2C2C2C;
        }
        .recommendation h2 {
            font-size: 24px;
            margin-bottom: 15px;
            color: #2C2C2C;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        .recommendation ul {
            list-style-type: none;
            padding-left: 20px;
        }
        .recommendation li {
            margin-bottom: 10px;
            position: relative;
        }
        .recommendation li::before {
            content: '•';
            color: #73D13D;
            font-weight: bold;
            position: absolute;
            left: -20px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🦞 焦糖布丁 安全审计报告</h1>
            <p>生成时间: ''' + datetime.now().strftime('%Y-%m-%d %H:%M:%S') + '''</p>
            <p>检测工具: 🦞 焦糖布丁</p>
            <p>工具作者: 0x八月</p>
        </div>
        
        <div class="disclaimer">
            ⚠️ 工具修复方案和内容仅供参考，由于传播、利用此工具所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，作者不为此承担任何责任。
        </div>

        <div class="score-card">
            <div class="score-value">''' + str(score) + '''/100</div>
            <div class="score-info">安全评分</div>
            <div class="score-info">通过检查: ''' + str(passed_checks) + '''/''' + str(total_checks) + '''</div>
        </div>

        <table>
            <thead>
                <tr>
                    <th>检查项</th>
                    <th>状态</th>
                    <th>结果</th>
                </tr>
            </thead>
            <tbody>
'''

        for check_name, check_result in results.items():
            status = check_result.get("status")
            message = check_result.get("message")
            status_class = "pass" if status == "PASS" else "fail" if status == "FAIL" else "warn"
            html += '''
                <tr>
                    <td>''' + check_name + '''</td>
                    <td><span class="tag tag-''' + status_class + '''">''' + status + '''</span></td>
                    <td>''' + message + '''</td>
                </tr>
'''

        html += '''
            </tbody>
        </table>

        <div class="recommendation">
            <h2>安全建议</h2>
            <ul>
                <li>根据审计结果，及时修复发现的安全问题</li>
                <li>定期进行安全审计，确保系统安全状态</li>
                <li>遵循最小权限原则配置系统</li>
                <li>保持系统和依赖的最新版本</li>
                <li>建立安全事件响应机制</li>
            </ul>
        </div>
    </div>
</body>
</html>
'''
        return html
    
    def _generate_secureclaw_audit_json_report(self, audit_result):
        """生成🦞 焦糖布丁安全审计JSON报告"""
        import json

        report = {
            "metadata": {
                "title": "焦糖布丁安全审计报告",
                "generated_at": datetime.now().isoformat(),
                "scanner_version": "2.0.0"
            },
            "score": audit_result.get("score", 0),
            "passed_checks": audit_result.get("passed_checks", 0),
            "total_checks": audit_result.get("total_checks", 0),
            "results": audit_result.get("results", {})
        }

        return json.dumps(report, ensure_ascii=False, indent=2)
    
    def _generate_secureclaw_harden_html_report(self, harden_result):
        """生成🦞 焦糖布丁自动加固HTML报告"""
        backup = harden_result.get("backup", "")
        harden_items = {k: v for k, v in harden_result.items() if k != "backup"}

        # 构建HTML报告
        html = '''<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>🦞 焦糖布丁自动加固报告</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        body {
            font-family: "Microsoft YaHei", "Segoe UI", Arial, sans-serif;
            margin: 40px;
            background-color: #FFF9F0;
            color: #2C2C2C;
        }
        .container {
            max-width: 1400px;
            margin: 0 auto;
        }
        .header {
            background-color: #73D13D;
            padding: 40px;
            border-radius: 16px;
            margin-bottom: 30px;
            border: 3px solid #2C2C2C;
            position: relative;
            overflow: hidden;
            box-shadow: 4px 4px 0 #2C2C2C;
            text-align: center;
        }
        .disclaimer {
            background-color: #FFD93D;
            padding: 20px;
            border-radius: 16px;
            margin: 20px 0;
            border: 3px solid #2C2C2C;
            box-shadow: 4px 4px 0 #2C2C2C;
            text-align: center;
            font-weight: bold;
            color: #2C2C2C;
        }
        .header::before {
            content: '';
            position: absolute;
            top: 0;
            right: 0;
            width: 200px;
            height: 200px;
            background: url('data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iMjAwIiBoZWlnaHQ9IjIwMCIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIj48cGF0aCBkPSJNMTAgMTAgMTgwIDE4MCIgZmlsbD0iI2ZmZmZmZiIvPjxwYXRoIGQ9Ik0xMCAxODAgMTgwIDEwIiBmaWxsPSIjZmZmZmZmIi8+PHBhdGggZD0iTTEwIDkwIDE4MCA5MCIgZmlsbD0iI2ZmZmZmZiIvPjwvc3ZnPg==') no-repeat center;
            background-size: contain;
            opacity: 0.2;
        }
        .info-card {
            background-color: #FFFFFF;
            padding: 20px;
            border-radius: 16px;
            margin-bottom: 30px;
            border: 3px solid #2C2C2C;
            box-shadow: 4px 4px 0 #2C2C2C;
        }
        .info-card h2 {
            font-size: 24px;
            margin-bottom: 15px;
            color: #2C2C2C;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        .info-card p {
            font-size: 16px;
            color: #2C2C2C;
            margin-bottom: 10px;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
            background-color: #FFFFFF;
            border-radius: 16px;
            overflow: hidden;
            border: 3px solid #2C2C2C;
            box-shadow: 4px 4px 0 #2C2C2C;
        }
        th {
            background-color: #73D13D;
            padding: 15px;
            text-align: left;
            font-weight: bold;
            color: white;
        }
        td {
            padding: 12px;
            border-bottom: 1px solid #2C2C2C;
        }
        tr:hover {
            background-color: #F0F0F0;
        }
        .tag {
            display: inline-block;
            padding: 4px 12px;
            border-radius: 8px;
            font-size: 12px;
            font-weight: bold;
            border: 3px solid #2C2C2C;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        .tag-success {
            background: #51CF66;
            color: white;
        }
        .tag-error {
            background: #FA5252;
            color: white;
        }
        .tag-warn {
            background: #FFD93D;
            color: #2C2C2C;
        }
        .recommendation {
            background-color: #FFFFFF;
            padding: 20px;
            border-radius: 16px;
            margin-top: 30px;
            border: 3px solid #2C2C2C;
            box-shadow: 4px 4px 0 #2C2C2C;
        }
        .recommendation h2 {
            font-size: 24px;
            margin-bottom: 15px;
            color: #2C2C2C;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        .recommendation ul {
            list-style-type: none;
            padding-left: 20px;
        }
        .recommendation li {
            margin-bottom: 10px;
            position: relative;
        }
        .recommendation li::before {
            content: '•';
            color: #73D13D;
            font-weight: bold;
            position: absolute;
            left: -20px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🦞 焦糖布丁 自动加固报告</h1>
            <p>生成时间: ''' + datetime.now().strftime('%Y-%m-%d %H:%M:%S') + '''</p>
            <p>检测工具: 🦞 焦糖布丁</p>
            <p>工具作者: 0x八月</p>
        </div>
        
        <div class="disclaimer">
            ⚠️ 工具修复方案和内容仅供参考，由于传播、利用此工具所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，作者不为此承担任何责任。
        </div>

        <div class="info-card">
            <h2>加固信息</h2>
            ''' + (f"<p><strong>备份创建:</strong> {backup}</p>" if backup else "<p><strong>备份创建:</strong> 无</p>") + '''
        </div>

        <table>
            <thead>
                <tr>
                    <th>加固项</th>
                    <th>状态</th>
                    <th>结果</th>
                </tr>
            </thead>
            <tbody>
'''

        for harden_item, item_result in harden_items.items():
            status = item_result.get("status")
            message = item_result.get("message")
            status_class = "success" if status == "SUCCESS" else "error" if status == "ERROR" else "warn"
            html += f'''
                <tr>
                    <td>{harden_item}</td>
                    <td><span class="tag tag-{status_class}">{status}</span></td>
                    <td>{message}</td>
                </tr>
'''

        html += '''
            </tbody>
        </table>

        <div class="recommendation">
            <h2>加固建议</h2>
            <ul>
                <li>定期运行自动加固，确保系统安全配置</li>
                <li>备份重要配置文件，以便在需要时恢复</li>
                <li>审查加固结果，确保所有安全措施都已正确应用</li>
                <li>结合安全审计，全面提升系统安全水平</li>
            </ul>
        </div>
    </div>
</body>
</html>
'''
        return html
    
    def _generate_secureclaw_harden_json_report(self, harden_result):
        """生成🦞 焦糖布丁自动加固JSON报告"""
        import json

        report = {
            "metadata": {
                "title": "焦糖布丁自动加固报告",
                "generated_at": datetime.now().isoformat(),
                "scanner_version": "2.0.0"
            },
            "backup": harden_result.get("backup", ""),
            "results": {k: v for k, v in harden_result.items() if k != "backup"}
        }

        return json.dumps(report, ensure_ascii=False, indent=2)
    
    def _generate_secureclaw_skill_scan_html_report(self, scan_result):
        """生成🦞 焦糖布丁技能扫描HTML报告"""
        scanned_skills = scan_result.get("scanned_skills", [])
        suspicious_skills = scan_result.get("suspicious_skills", [])

        # 构建HTML报告
        html = '''<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>焦糖布丁技能扫描报告</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        body {
            font-family: "Microsoft YaHei", "Segoe UI", Arial, sans-serif;
            margin: 40px;
            background-color: #FFF9F0;
            color: #2C2C2C;
        }
        .container {
            max-width: 1400px;
            margin: 0 auto;
        }
        .header {
            background-color: #73D13D;
            padding: 40px;
            border-radius: 16px;
            margin-bottom: 30px;
            border: 3px solid #2C2C2C;
            position: relative;
            overflow: hidden;
            box-shadow: 4px 4px 0 #2C2C2C;
            text-align: center;
        }
        .disclaimer {
            background-color: #FFD93D;
            padding: 20px;
            border-radius: 16px;
            margin: 20px 0;
            border: 3px solid #2C2C2C;
            box-shadow: 4px 4px 0 #2C2C2C;
            text-align: center;
            font-weight: bold;
            color: #2C2C2C;
        }
        .header::before {
            content: '';
            position: absolute;
            top: 0;
            right: 0;
            width: 200px;
            height: 200px;
            background: url('data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iMjAwIiBoZWlnaHQ9IjIwMCIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIj48cGF0aCBkPSJNMTAgMTAgMTgwIDE4MCIgZmlsbD0iI2ZmZmZmZiIvPjxwYXRoIGQ9Ik0xMCAxODAgMTgwIDEwIiBmaWxsPSIjZmZmZmZmIi8+PHBhdGggZD0iTTEwIDkwIDE4MCA5MCIgZmlsbD0iI2ZmZmZmZiIvPjwvc3ZnPg==') no-repeat center;
            background-size: contain;
            opacity: 0.2;
        }
        .info-card {
            background-color: #FFFFFF;
            padding: 20px;
            border-radius: 16px;
            margin-bottom: 30px;
            border: 3px solid #2C2C2C;
            box-shadow: 4px 4px 0 #2C2C2C;
            text-align: center;
        }
        .info-card h2 {
            font-size: 24px;
            margin-bottom: 15px;
            color: #2C2C2C;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        .info-card p {
            font-size: 16px;
            color: #2C2C2C;
            margin-bottom: 10px;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
            background-color: #FFFFFF;
            border-radius: 16px;
            overflow: hidden;
            border: 3px solid #2C2C2C;
            box-shadow: 4px 4px 0 #2C2C2C;
        }
        th {
            background-color: #73D13D;
            padding: 15px;
            text-align: left;
            font-weight: bold;
            color: white;
        }
        td {
            padding: 12px;
            border-bottom: 1px solid #2C2C2C;
        }
        tr:hover {
            background-color: #F0F0F0;
        }
        .tag {
            display: inline-block;
            padding: 4px 12px;
            border-radius: 8px;
            font-size: 12px;
            font-weight: bold;
            border: 3px solid #2C2C2C;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        .tag-clean {
            background: #51CF66;
            color: white;
        }
        .tag-suspicious {
            background: #FA5252;
            color: white;
        }
        .recommendation {
            background-color: #FFFFFF;
            padding: 20px;
            border-radius: 16px;
            margin-top: 30px;
            border: 3px solid #2C2C2C;
            box-shadow: 4px 4px 0 #2C2C2C;
        }
        .recommendation h2 {
            font-size: 24px;
            margin-bottom: 15px;
            color: #2C2C2C;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        .recommendation ul {
            list-style-type: none;
            padding-left: 20px;
        }
        .recommendation li {
            margin-bottom: 10px;
            position: relative;
        }
        .recommendation li::before {
            content: '•';
            color: #73D13D;
            font-weight: bold;
            position: absolute;
            left: -20px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🦞 焦糖布丁 技能扫描报告</h1>
            <p>生成时间: ''' + datetime.now().strftime('%Y-%m-%d %H:%M:%S') + '''</p>
            <p>检测工具: 🦞 焦糖布丁</p>
            <p>工具作者: 0x八月</p>
        </div>
        
        <div class="disclaimer">
            ⚠️ 工具修复方案和内容仅供参考，由于传播、利用此工具所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，作者不为此承担任何责任。
        </div>

        <div class="info-card">
            <h2>扫描统计</h2>
            <p>扫描技能数: ''' + str(len(scanned_skills)) + '''</p>
            <p>可疑技能数: ''' + str(len(suspicious_skills)) + '''</p>
        </div>

        <table>
            <thead>
                <tr>
                    <th>技能名称</th>
                    <th>状态</th>
                    <th>问题</th>
                </tr>
            </thead>
            <tbody>
'''

        for skill in scanned_skills:
            name = skill.get("name")
            status = skill.get("status")
            issues = skill.get("issues", [])
            status_class = "clean" if status == "CLEAN" else "suspicious"
            issues_text = "<br>".join(issues) if issues else "无问题"
            html += f'''
                <tr>
                    <td>{name}</td>
                    <td><span class="tag tag-{status_class}">{status}</span></td>
                    <td>{issues_text}</td>
                </tr>
'''

        html += '''
            </tbody>
        </table>

        <div class="recommendation">
            <h2>安全建议</h2>
            <ul>
                <li>定期扫描技能包，确保系统安全</li>
                <li>移除或修复发现的可疑技能</li>
                <li>只从可信来源安装技能包</li>
                <li>定期更新技能包到最新版本</li>
            </ul>
        </div>
    </div>
</body>
</html>
'''
        return html
    
    def _generate_secureclaw_skill_scan_json_report(self, scan_result):
        """生成🦞 焦糖布丁技能扫描JSON报告"""
        import json

        report = {
            "metadata": {
                "title": "焦糖布丁技能扫描报告",
                "generated_at": datetime.now().isoformat(),
                "scanner_version": "2.0.0"
            },
            "scanned_skills": scan_result.get("scanned_skills", []),
            "suspicious_skills": scan_result.get("suspicious_skills", [])
        }

        return json.dumps(report, ensure_ascii=False, indent=2)
    
    def _generate_secureclaw_integrity_html_report(self, integrity_result):
        """生成🦞 焦糖布丁文件完整性检查HTML报告"""
        status = integrity_result.get("status")
        details = integrity_result.get("details", [])

        # 构建HTML报告
        html = '''<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>🦞 焦糖布丁文件完整性检查报告</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        body {
            font-family: "Microsoft YaHei", "Segoe UI", Arial, sans-serif;
            margin: 40px;
            background-color: #FFF9F0;
            color: #2C2C2C;
        }
        .container {
            max-width: 1400px;
            margin: 0 auto;
        }
        .header {
            background-color: #73D13D;
            padding: 40px;
            border-radius: 16px;
            margin-bottom: 30px;
            border: 3px solid #2C2C2C;
            position: relative;
            overflow: hidden;
            box-shadow: 4px 4px 0 #2C2C2C;
            text-align: center;
        }
        .disclaimer {
            background-color: #FFD93D;
            padding: 20px;
            border-radius: 16px;
            margin: 20px 0;
            border: 3px solid #2C2C2C;
            box-shadow: 4px 4px 0 #2C2C2C;
            text-align: center;
            font-weight: bold;
            color: #2C2C2C;
        }
        .header::before {
            content: '';
            position: absolute;
            top: 0;
            right: 0;
            width: 200px;
            height: 200px;
            background: url('data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iMjAwIiBoZWlnaHQ9IjIwMCIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIj48cGF0aCBkPSJNMTAgMTAgMTgwIDE4MCIgZmlsbD0iI2ZmZmZmZiIvPjxwYXRoIGQ9Ik0xMCAxODAgMTgwIDEwIiBmaWxsPSIjZmZmZmZmIi8+PHBhdGggZD0iTTEwIDkwIDE4MCA5MCIgZmlsbD0iI2ZmZmZmZiIvPjwvc3ZnPg==') no-repeat center;
            background-size: contain;
            opacity: 0.2;
        }
        .info-card {
            background-color: #FFFFFF;
            padding: 20px;
            border-radius: 16px;
            margin-bottom: 30px;
            border: 3px solid #2C2C2C;
            box-shadow: 4px 4px 0 #2C2C2C;
            text-align: center;
        }
        .info-card h2 {
            font-size: 24px;
            margin-bottom: 15px;
            color: #2C2C2C;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        .info-card p {
            font-size: 16px;
            color: #2C2C2C;
            margin-bottom: 10px;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
            background-color: #FFFFFF;
            border-radius: 16px;
            overflow: hidden;
            border: 3px solid #2C2C2C;
            box-shadow: 4px 4px 0 #2C2C2C;
        }
        th {
            background-color: #73D13D;
            padding: 15px;
            text-align: left;
            font-weight: bold;
            color: white;
        }
        td {
            padding: 12px;
            border-bottom: 1px solid #2C2C2C;
        }
        tr:hover {
            background-color: #F0F0F0;
        }
        .tag {
            display: inline-block;
            padding: 4px 12px;
            border-radius: 8px;
            font-size: 12px;
            font-weight: bold;
            border: 3px solid #2C2C2C;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        .tag-intact {
            background: #51CF66;
            color: white;
        }
        .tag-tampered {
            background: #FA5252;
            color: white;
        }
        .tag-missing {
            background: #FA5252;
            color: white;
        }
        .tag-no-baseline {
            background: #FFD93D;
            color: #2C2C2C;
        }
        .recommendation {
            background-color: #FFFFFF;
            padding: 20px;
            border-radius: 16px;
            margin-top: 30px;
            border: 3px solid #2C2C2C;
            box-shadow: 4px 4px 0 #2C2C2C;
        }
        .recommendation h2 {
            font-size: 24px;
            margin-bottom: 15px;
            color: #2C2C2C;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        .recommendation ul {
            list-style-type: none;
            padding-left: 20px;
        }
        .recommendation li {
            margin-bottom: 10px;
            position: relative;
        }
        .recommendation li::before {
            content: '•';
            color: #73D13D;
            font-weight: bold;
            position: absolute;
            left: -20px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🦞 焦糖布丁 文件完整性检查报告</h1>
            <p>生成时间: ''' + datetime.now().strftime('%Y-%m-%d %H:%M:%S') + '''</p>
            <p>检测工具: 🦞 焦糖布丁</p>
            <p>工具作者: 0x八月</p>
        </div>
        
        <div class="disclaimer">
            ⚠️ 工具修复方案和内容仅供参考，由于传播、利用此工具所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，作者不为此承担任何责任。
        </div>

        <div class="info-card">
            <h2>整体状态</h2>
            <p>状态: ''' + status + '''</p>
        </div>

        <table>
            <thead>
                <tr>
                    <th>文件</th>
                    <th>状态</th>
                    <th>结果</th>
                </tr>
            </thead>
            <tbody>
'''

        for detail in details:
            file = detail.get("file")
            file_status = detail.get("status")
            message = detail.get("message")
            status_class = "intact" if file_status == "INTACT" else "tampered" if file_status == "TAMPERED" else "missing" if file_status == "MISSING" else "no-baseline"
            html += f'''
                <tr>
                    <td>{file}</td>
                    <td><span class="tag tag-{status_class}">{file_status}</span></td>
                    <td>{message}</td>
                </tr>
'''

        html += '''
            </tbody>
        </table>

        <div class="recommendation">
            <h2>安全建议</h2>
            <ul>
                <li>定期进行文件完整性检查，确保系统文件未被篡改</li>
                <li>为重要文件创建基线，以便后续检查</li>
                <li>修复或替换被篡改的文件</li>
                <li>建立文件完整性监控机制，及时发现异常</li>
            </ul>
        </div>
    </div>
</body>
</html>
'''
        return html
    
    def _generate_secureclaw_integrity_json_report(self, integrity_result):
        """生成🦞 焦糖布丁文件完整性检查JSON报告"""
        import json

        report = {
            "metadata": {
                "title": "焦糖布丁文件完整性检查报告",
                "generated_at": datetime.now().isoformat(),
                "scanner_version": "2.0.0"
            },
            "status": integrity_result.get("status"),
            "details": integrity_result.get("details", [])
        }

        return json.dumps(report, ensure_ascii=False, indent=2)
    
    def _generate_secureclaw_privacy_html_report(self, privacy_result):
        """生成🦞 焦糖布丁隐私检查HTML报告"""
        status = privacy_result.get("status")
        detected_pii = privacy_result.get("detected_pii", [])

        # 构建HTML报告
        html = '''<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>🦞 焦糖布丁隐私检查报告</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        body {
            font-family: "Microsoft YaHei", "Segoe UI", Arial, sans-serif;
            margin: 40px;
            background-color: #FFF9F0;
            color: #2C2C2C;
        }
        .container {
            max-width: 1400px;
            margin: 0 auto;
        }
        .header {
            background-color: #73D13D;
            padding: 40px;
            border-radius: 16px;
            margin-bottom: 30px;
            border: 3px solid #2C2C2C;
            position: relative;
            overflow: hidden;
            box-shadow: 4px 4px 0 #2C2C2C;
            text-align: center;
        }
        .disclaimer {
            background-color: #FFD93D;
            padding: 20px;
            border-radius: 16px;
            margin: 20px 0;
            border: 3px solid #2C2C2C;
            box-shadow: 4px 4px 0 #2C2C2C;
            text-align: center;
            font-weight: bold;
            color: #2C2C2C;
        }
        .header::before {
            content: '';
            position: absolute;
            top: 0;
            right: 0;
            width: 200px;
            height: 200px;
            background: url('data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iMjAwIiBoZWlnaHQ9IjIwMCIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIj48cGF0aCBkPSJNMTAgMTAgMTgwIDE4MCIgZmlsbD0iI2ZmZmZmZiIvPjxwYXRoIGQ9Ik0xMCAxODAgMTgwIDEwIiBmaWxsPSIjZmZmZmZmIi8+PHBhdGggZD0iTTEwIDkwIDE4MCA5MCIgZmlsbD0iI2ZmZmZmZiIvPjwvc3ZnPg==') no-repeat center;
            background-size: contain;
            opacity: 0.2;
        }
        .info-card {
            background-color: #FFFFFF;
            padding: 20px;
            border-radius: 16px;
            margin-bottom: 30px;
            border: 3px solid #2C2C2C;
            box-shadow: 4px 4px 0 #2C2C2C;
            text-align: center;
        }
        .info-card h2 {
            font-size: 24px;
            margin-bottom: 15px;
            color: #2C2C2C;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        .info-card p {
            font-size: 16px;
            color: #2C2C2C;
            margin-bottom: 10px;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
            background-color: #FFFFFF;
            border-radius: 16px;
            overflow: hidden;
            border: 3px solid #2C2C2C;
            box-shadow: 4px 4px 0 #2C2C2C;
        }
        th {
            background-color: #73D13D;
            padding: 15px;
            text-align: left;
            font-weight: bold;
            color: white;
        }
        td {
            padding: 12px;
            border-bottom: 1px solid #2C2C2C;
        }
        tr:hover {
            background-color: #F0F0F0;
        }
        .recommendation {
            background-color: #FFFFFF;
            padding: 20px;
            border-radius: 16px;
            margin-top: 30px;
            border: 3px solid #2C2C2C;
            box-shadow: 4px 4px 0 #2C2C2C;
        }
        .recommendation h2 {
            font-size: 24px;
            margin-bottom: 15px;
            color: #2C2C2C;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        .recommendation ul {
            list-style-type: none;
            padding-left: 20px;
        }
        .recommendation li {
            margin-bottom: 10px;
            position: relative;
        }
        .recommendation li::before {
            content: '•';
            color: #73D13D;
            font-weight: bold;
            position: absolute;
            left: -20px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🦞 焦糖布丁 隐私检查报告</h1>
            <p>生成时间: ''' + datetime.now().strftime('%Y-%m-%d %H:%M:%S') + '''</p>
            <p>检测工具: 🦞 焦糖布丁</p>
            <p>工具作者: 0x八月</p>
        </div>
        
        <div class="disclaimer">
            ⚠️ 工具修复方案和内容仅供参考，由于传播、利用此工具所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，作者不为此承担任何责任。
        </div>

        <div class="info-card">
            <h2>检查结果</h2>
            <p>状态: ''' + status + '''</p>
            <p>检测到的PII数量: ''' + str(len(detected_pii)) + '''</p>
        </div>

        <table>
            <thead>
                <tr>
                    <th>类型</th>
                    <th>内容</th>
                </tr>
            </thead>
            <tbody>
'''

        for pii in detected_pii:
            pii_type = pii.get("type")
            pii_content = pii.get("content")
            html += f'''
                <tr>
                    <td>{pii_type}</td>
                    <td>{pii_content}</td>
                </tr>
'''

        html += '''
            </tbody>
        </table>

        <div class="recommendation">
            <h2>隐私保护建议</h2>
            <ul>
                <li>避免在代码和配置文件中存储敏感个人信息</li>
                <li>使用环境变量或加密存储敏感数据</li>
                <li>实施数据分类和访问控制</li>
                <li>定期进行隐私检查，确保敏感信息不被泄露</li>
            </ul>
        </div>
    </div>
</body>
</html>
'''
        return html
    
    def _generate_secureclaw_privacy_json_report(self, privacy_result):
        """生成🦞 焦糖布丁隐私检查JSON报告"""
        import json

        report = {
            "metadata": {
                "title": "焦糖布丁隐私检查报告",
                "generated_at": datetime.now().isoformat(),
                "scanner_version": "2.0.0"
            },
            "status": privacy_result.get("status"),
            "detected_pii": privacy_result.get("detected_pii", [])
        }

        return json.dumps(report, ensure_ascii=False, indent=2)
    
    def _generate_secureclaw_behavior_rules_html_report(self, rules_result):
        """生成🦞 焦糖布丁行为规则检查HTML报告"""
        score = rules_result.get("score", 0)
        total_rules = rules_result.get("total_rules", 0)
        passed_rules = rules_result.get("passed_rules", 0)
        results = rules_result.get("results", {})

        # 计算违规数量
        violations = []
        for rule_name, rule_result in results.items():
            if rule_result.get("status") != "PASS":
                violations.append({
                    "rule": rule_name,
                    "details": rule_result.get("message", "")
                })

        # 构建HTML报告
        html = '''<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>🦞焦糖布丁 为规则检查报告</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        body {
            font-family: "Microsoft YaHei", "Segoe UI", Arial, sans-serif;
            margin: 40px;
            background-color: #FFF9F0;
            color: #2C2C2C;
        }
        .container {
            max-width: 1400px;
            margin: 0 auto;
        }
        .header {
            background-color: #73D13D;
            padding: 40px;
            border-radius: 16px;
            margin-bottom: 30px;
            border: 3px solid #2C2C2C;
            position: relative;
            overflow: hidden;
            box-shadow: 4px 4px 0 #2C2C2C;
            text-align: center;
        }
        .disclaimer {
            background-color: #FFD93D;
            padding: 20px;
            border-radius: 16px;
            margin: 20px 0;
            border: 3px solid #2C2C2C;
            box-shadow: 4px 4px 0 #2C2C2C;
            text-align: center;
            font-weight: bold;
            color: #2C2C2C;
        }
        .header::before {
            content: '';
            position: absolute;
            top: 0;
            right: 0;
            width: 200px;
            height: 200px;
            background: url('data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iMjAwIiBoZWlnaHQ9IjIwMCIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIj48cGF0aCBkPSJNMTAgMTAgMTgwIDE4MCIgZmlsbD0iI2ZmZmZmZiIvPjxwYXRoIGQ9Ik0xMCAxODAgMTgwIDEwIiBmaWxsPSIjZmZmZmZmIi8+PHBhdGggZD0iTTEwIDkwIDE4MCA5MCIgZmlsbD0iI2ZmZmZmZiIvPjwvc3ZnPg==') no-repeat center;
            background-size: contain;
            opacity: 0.2;
        }
        .info-card {
            background-color: #FFFFFF;
            padding: 20px;
            border-radius: 16px;
            margin-bottom: 30px;
            border: 3px solid #2C2C2C;
            box-shadow: 4px 4px 0 #2C2C2C;
            text-align: center;
        }
        .info-card h2 {
            font-size: 24px;
            margin-bottom: 15px;
            color: #2C2C2C;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        .info-card p {
            font-size: 16px;
            color: #2C2C2C;
            margin-bottom: 10px;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
            background-color: #FFFFFF;
            border-radius: 16px;
            overflow: hidden;
            border: 3px solid #2C2C2C;
            box-shadow: 4px 4px 0 #2C2C2C;
        }
        th {
            background-color: #73D13D;
            padding: 15px;
            text-align: left;
            font-weight: bold;
            color: white;
        }
        td {
            padding: 12px;
            border-bottom: 1px solid #2C2C2C;
        }
        tr:hover {
            background-color: #F0F0F0;
        }
        .recommendation {
            background-color: #FFFFFF;
            padding: 20px;
            border-radius: 16px;
            margin-top: 30px;
            border: 3px solid #2C2C2C;
            box-shadow: 4px 4px 0 #2C2C2C;
        }
        .recommendation h2 {
            font-size: 24px;
            margin-bottom: 15px;
            color: #2C2C2C;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        .recommendation ul {
            list-style-type: none;
            padding-left: 20px;
        }
        .recommendation li {
            margin-bottom: 10px;
            position: relative;
        }
        .recommendation li::before {
            content: '•';
            color: #73D13D;
            font-weight: bold;
            position: absolute;
            left: -20px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🦞 焦糖布丁 行为规则检查报告</h1>
            <p>生成时间: ''' + datetime.now().strftime('%Y-%m-%d %H:%M:%S') + '''</p>
            <p>检测工具: 🦞 焦糖布丁</p>
            <p>工具作者: 0x八月</p>
        </div>
        
        <div class="disclaimer">
            ⚠️ 工具修复方案和内容仅供参考，由于传播、利用此工具所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，作者不为此承担任何责任。
        </div>

        <div class="info-card">
            <h2>检查结果</h2>
            <p>安全评分: ''' + str(score) + '''/100</p>
            <p>通过规则: ''' + str(passed_rules) + '''/''' + str(total_rules) + '''</p>
            <p>违规数量: ''' + str(len(violations)) + '''</p>
        </div>

        <table>
            <thead>
                <tr>
                    <th>规则名称</th>
                    <th>违规详情</th>
                </tr>
            </thead>
            <tbody>
'''

        for violation in violations:
            rule_name = violation.get("rule")
            details = violation.get("details")
            html += f'''
                <tr>
                    <td>{rule_name}</td>
                    <td>{details}</td>
                </tr>
'''

        html += '''
            </tbody>
        </table>

        <div class="recommendation">
            <h2>安全建议</h2>
            <ul>
                <li>定期检查系统行为，确保符合安全规则</li>
                <li>修复发现的行为规则违规</li>
                <li>建立行为规则监控机制，及时发现异常</li>
                <li>结合其他安全检测，全面提升系统安全水平</li>
            </ul>
        </div>
    </div>
</body>
</html>
'''
        return html
    
    def _generate_secureclaw_behavior_rules_json_report(self, rules_result):
        """生成🦞 焦糖布丁行为规则检查JSON报告"""
        import json

        report = {
            "metadata": {
                "title": "焦糖布丁行为规则检查报告",
                "generated_at": datetime.now().isoformat(),
                "scanner_version": "2.0.0"
            },
            "status": rules_result.get("status"),
            "violations": rules_result.get("violations", [])
        }

        return json.dumps(report, ensure_ascii=False, indent=2)