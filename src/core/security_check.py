from abc import ABC, abstractmethod
from datetime import datetime


class SecurityCheck(ABC):
    """安全检测基类"""

    def __init__(self, name, risk_level):
        self.name = name
        self.risk_level = risk_level  # CRITICAL, HIGH, MEDIUM, LOW
        self.findings = []
        self.status = "pending"  # pending/running/completed/error

    @abstractmethod
    async def run(self):
        """执行检测"""
        raise NotImplementedError

    def report(self, finding, risk_level=None):
        """报告发现"""
        if risk_level is None:
            risk_level = self.risk_level

        self.findings.append({
            "check": self.name,
            "risk": risk_level.upper(),
            "finding": finding,
            "timestamp": datetime.now().isoformat()
        })

    def reset(self):
        """重置检测状态"""
        self.findings = []
        self.status = "pending"

    async def fix(self):
        """修复发现的问题"""
        # 子类可以重写此方法实现具体的修复逻辑
        pass
