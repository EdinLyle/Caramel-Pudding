import os
import hashlib
from typing import Dict, List, Tuple

class SecureClawIntegrity:
    def __init__(self):
        self.cognitive_files = [
            "SOUL.md",
            "IDENTITY.md",
            "TOOLS.md",
            "AGENTS.md",
            "SECURITY.md",
            "MEMORY.md"
        ]
    
    def check_integrity(self, openclaw_dir: str) -> Dict:
        """检查认知文件完整性"""
        baselines_dir = os.path.join(openclaw_dir, ".secureclaw", "baselines")
        
        # 检查基线目录是否存在
        if not os.path.exists(baselines_dir):
            return {
                "status": "ERROR",
                "message": "未找到基线目录，请先运行加固功能创建基线"
            }
        
        results = {
            "status": "INTACT",
            "details": []
        }
        
        for file in self.cognitive_files:
            file_path = os.path.join(openclaw_dir, file)
            baseline_file = os.path.join(baselines_dir, f"{file}.sha256")
            
            # 检查文件是否存在
            if not os.path.exists(file_path):
                results["status"] = "TAMPERED"
                results["details"].append({
                    "file": file,
                    "status": "MISSING",
                    "message": "文件不存在"
                })
                continue
            
            # 检查基线文件是否存在
            if not os.path.exists(baseline_file):
                results["status"] = "TAMPERED"
                results["details"].append({
                    "file": file,
                    "status": "NO_BASELINE",
                    "message": "未找到基线文件"
                })
                continue
            
            # 计算当前文件哈希
            try:
                with open(file_path, "rb") as f:
                    content = f.read()
                current_hash = hashlib.sha256(content).hexdigest()
                
                # 读取基线哈希
                with open(baseline_file, "r", encoding="utf-8") as f:
                    baseline_hash = f.read().strip()
                
                # 比较哈希
                if current_hash == baseline_hash:
                    results["details"].append({
                        "file": file,
                        "status": "INTACT",
                        "message": "文件完整性正常"
                    })
                else:
                    results["status"] = "TAMPERED"
                    results["details"].append({
                        "file": file,
                        "status": "TAMPERED",
                        "message": f"文件已被篡改，预期哈希: {baseline_hash[:16]}..., 当前哈希: {current_hash[:16]}..."
                    })
            except Exception as e:
                results["status"] = "ERROR"
                results["details"].append({
                    "file": file,
                    "status": "ERROR",
                    "message": f"检查失败: {str(e)}"
                })
        
        return results
    
    def create_baselines(self, openclaw_dir: str) -> Dict:
        """创建认知文件基线"""
        baselines_dir = os.path.join(openclaw_dir, ".secureclaw", "baselines")
        os.makedirs(baselines_dir, exist_ok=True)
        
        results = {
            "status": "SUCCESS",
            "created_baselines": []
        }
        
        for file in self.cognitive_files:
            file_path = os.path.join(openclaw_dir, file)
            if os.path.exists(file_path):
                try:
                    # 计算文件哈希
                    with open(file_path, "rb") as f:
                        content = f.read()
                    hash_obj = hashlib.sha256(content)
                    hash_hex = hash_obj.hexdigest()
                    
                    # 保存基线
                    baseline_file = os.path.join(baselines_dir, f"{file}.sha256")
                    with open(baseline_file, "w", encoding="utf-8") as f:
                        f.write(hash_hex)
                    
                    results["created_baselines"].append(file)
                except Exception as e:
                    results["status"] = "ERROR"
                    results["message"] = f"创建 {file} 基线失败: {str(e)}"
                    break
        
        if not results["created_baselines"]:
            results["status"] = "WARN"
            results["message"] = "未找到认知文件，无法创建基线"
        
        return results
    
    def update_baselines(self, openclaw_dir: str) -> Dict:
        """更新认知文件基线"""
        return self.create_baselines(openclaw_dir)
