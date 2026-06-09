""""
AI智能分析模块
"""

from core.web_interface import WebInterface


class AIAnalyzer:


    def __init__(self, model=None, ollama_url=None):
        self._iface = WebInterface(model=model, ollama_url=ollama_url)

    """先检查Ollama能不能用啊"""
    def check_service(self) -> bool:
        return self._iface.check_service()

    """AI分析安全风险"""
    def analyze_html(self, url: str, html: str) -> str:

        return self._iface.analyze_html(url, html)

    """直接让ai生成审计报告"""
    def generate_report(self, url: str, passive_result: str, active_result: str) -> str:
        return self._iface.generate_report(url, passive_result, active_result)


