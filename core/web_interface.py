# -*- coding: utf-8 -*-
"""
web_interface.py - AI Web接口封装
负责读取配置、调用Ollama API、处理响应
"""

import json
import os
import urllib.request
import urllib.error
from typing import Optional, Dict

import yaml


# 配置文件路径（相对于core目录的上层）
_CONFIG_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "cfg.yaml"
)


"""加载YAML配置"""
def _load_cfg() -> Dict:
    with open(_CONFIG_PATH, 'r', encoding='utf-8') as f:
        return yaml.safe_load(f)


"""AI接口"""
class WebInterface:


    """检查ai能不能用"""

    def check_service(self) -> bool:

        try:
            base = self.ollama_url.replace('/api/chat', '')
            req = urllib.request.Request(f"{base}/api/tags")
            with urllib.request.urlopen(req, timeout=5) as resp:
                return resp.status == 200
        except Exception:
            return False


    def __init__(self, model: str = None, ollama_url: str = None, timeout: int = None):
        self.cfg = _load_cfg()
        ai_cfg = self.cfg.get('ai', {})
        ollama_cfg = ai_cfg.get('ollama', {})
        self.model = model or ollama_cfg.get('model', 'deepseek-r1:7b')
        host = ollama_cfg.get('host', 'http://localhost:11434')
        self.ollama_url = ollama_url or f"{host}/api/chat"
        self.timeout = timeout or ollama_cfg.get('timeout', 120)
        self.max_html = ai_cfg.get('max_html_length', 8000)
        self.prompts = self.cfg.get('prompts', {})

    def chat(self, prompt: str, system: str = None) -> Optional[str]:
        """调用chat接口"""
        body = {
            "model": self.model,
            "messages": [],
            "stream": False
        }
        if system:
            body["messages"].append({"role": "system", "content": system})
        body["messages"].append({"role": "user", "content": prompt})

        data = json.dumps(body, ensure_ascii=False).encode("utf-8")
        req = urllib.request.Request(
            self.ollama_url,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                result = json.loads(resp.read().decode("utf-8"))
                return result.get("message", {}).get("content", "")
        except urllib.error.URLError as e:
            raise ConnectionError(f"无法连接Ollama服务({self.ollama_url}): {e}")
        except Exception as e:
            raise RuntimeError(f"AI请求失败: {e}")

    """AI分析页面的安全风险"""
    def analyze_html(self, url: str, html: str) -> str:
        html_clip = html[:self.max_html] if len(html) > self.max_html else html
        system = self.prompts.get('analyze_html_system', '')
        user_tpl = self.prompts.get('analyze_html_user', '')
        prompt = user_tpl.format(url=url, html=html_clip)
        return self.chat(prompt, system)


        """AI综合扫描结果生成报告"""
    def generate_report(self, url: str, passive_result: str, active_result: str) -> str:

        system = self.prompts.get('generate_report_system', '')
        user_tpl = self.prompts.get('generate_report_user', '')
        prompt = user_tpl.format(url=url, passive_result=passive_result, active_result=active_result)
        return self.chat(prompt, system)


