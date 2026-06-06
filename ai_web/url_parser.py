# -*- coding: utf-8 -*-
"""
URL解析、数据类定义
"""

from typing import Optional, Dict, List
from dataclasses import dataclass, field
from urllib.parse import urlparse, parse_qs
from PyQt6.QtCore import QObject, pyqtSignal, QUrl
from PyQt6.QtWebEngineWidgets import QWebEngineView


@dataclass
class URLInfo:
    url: str
    protocol: str = ""
    domain: str = ""
    path: str = ""
    query_params: Dict[str, List[str]] = field(default_factory=dict)
    is_https: bool = False
    is_ip: bool = False
    suspicious_params: List[str] = field(default_factory=list)


@dataclass
class FormInfo:
    action: str = ""
    method: str = "GET"
    inputs: Dict[str, str] = field(default_factory=dict)
    has_password: bool = False
    uses_https: bool = False


@dataclass
class ScriptInfo:
    src: str = ""
    content: str = ""
    is_external: bool = False
    uses_eval: bool = False
    uses_innerhtml: bool = False
    uses_document_write: bool = False


class SecureBrowser(QObject):
    url_changed = pyqtSignal(str)
    load_started = pyqtSignal(str)
    load_finished = pyqtSignal(bool, str)
    security_warning = pyqtSignal(str)

    def __init__(self):
        super().__init__()
        self.web_view: Optional[QWebEngineView] = None
        self.current_url: str = ""
        self.page_content: str = ""
        self.url_info: Optional[URLInfo] = None

    def set_web_view(self, web_view: QWebEngineView):
        self.web_view = web_view
        self.web_view.urlChanged.connect(self._on_url_changed)
        self.web_view.loadStarted.connect(self._on_load_started)
        self.web_view.loadFinished.connect(self._on_load_finished)

    def _on_url_changed(self, url: QUrl):
        self.current_url = url.toString()
        self.url_info = self._parse_url(self.current_url)
        self.url_changed.emit(self.current_url)

    def _on_load_started(self):
        self.load_started.emit(self.current_url)

    def _on_load_finished(self, success: bool):
        if self.web_view:
            self.web_view.page().toHtml(self._on_html_received)
        self.load_finished.emit(success, self.current_url)

    def _on_html_received(self, html: str):
        self.page_content = html

    def _parse_url(self, url: str) -> URLInfo:
        import re
        try:
            parsed = urlparse(url)
            query_params = parse_qs(parsed.query)
            is_ip = bool(re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', parsed.netloc))
            suspicious_keywords = ['id', 'user', 'pass', 'password', 'pwd', 'token', 'key',
                                   'secret', 'auth', 'login', 'admin', 'file', 'path', 'url', 'redirect']
            suspicious_params = [p for p in query_params.keys() if p.lower() in suspicious_keywords]
            return URLInfo(url=url, protocol=parsed.scheme, domain=parsed.netloc,
                           path=parsed.path, query_params=query_params, is_https=parsed.scheme == 'https',
                           is_ip=is_ip, suspicious_params=suspicious_params)
        except:
            return URLInfo(url=url)
