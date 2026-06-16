# 浏览器 + 主动扫描 + AI 分析界面

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton,
    QTextEdit, QListWidget, QLabel, QLineEdit,
    QMessageBox, QSplitter, QApplication, QTabWidget,
    QProgressBar
)
from PyQt6.QtCore import Qt, QUrl, QThread, pyqtSignal
from PyQt6.QtWebEngineWidgets import QWebEngineView
from ai_web.payload_scanner import ActiveScanner
from ai_web.ai_analyzer import AIAnalyzer
import sys
import os
import json
import urllib.request

#先强制软件渲染，避免GPU/虚拟化炸缸
os.environ["QTWEBENGINE_CHROMIUM_FLAGS"] = (
    "--disable-gpu "
    "--disable-software-rasterizer "
    "--disable-gpu-compositing "
    "--disable-gpu-vsync "
    "--no-sandbox"
)
os.environ["QT_OPENGL"] = "software"
os.environ["QTWEBENGINE_DISABLE_SANDBOX"] = "1"


# 我直接一个扫描线程 再小回传一下
class ScanWorker(QThread):
    log_signal = pyqtSignal(str)
    vuln_signal = pyqtSignal(str)
    done_signal = pyqtSignal(dict)

    def __init__(self, scanner, url):
        super().__init__()
        self.scanner = scanner
        self.url = url

    def run(self):
        try:
            def on_log(text):
                try:
                    self.log_signal.emit(str(text))
                except Exception:
                    pass

            def on_vuln(vuln_dict):
                try:
                    # 兼容 dict 和 string 两种回调
                    if isinstance(vuln_dict, dict):
                        desc = f"{vuln_dict.get('type','')} | {vuln_dict.get('details','')} | payload={vuln_dict.get('payload','')}"
                    else:
                        desc = str(vuln_dict)
                    self.vuln_signal.emit(desc)
                    on_log(desc)
                except Exception:
                    pass

            self.scanner.logger = on_log
            # callback 接收 dict（report_vuln 传的是字符串）
            self.scanner.callback = lambda s: on_vuln(s) if isinstance(s, (dict, str)) else None

            # 同步扫描
            self.scanner.current_url = self.url
            self.scanner.found_vulns = []
            self.scanner.scan_logs = []
            self.scanner.running = True

            # 直接调用 start_scan（内部含浏览器启动和完整流程）
            self.scanner.start_scan(self.url)

            # 返回结果
            try:
                result = self.scanner.get_results()
            except Exception:
                result = {
                    "url": self.url,
                    "vuln_count": len(self.scanner.found_vulns),
                    "vulnerabilities": self.scanner.found_vulns,
                    "logs": self.scanner.scan_logs[-200:],
                }
            self.done_signal.emit(result)
        except Exception as e:
            self.log_signal.emit(f"[ERROR] 扫描线程异常: {e}")
            self.done_signal.emit({
                "url": self.url,
                "vuln_count": 0,
                "vulnerabilities": [],
                "logs": [f"扫描异常: {e}"],
            })


# 小小检查一下你的ai启动没有嗷
def check_local_ollama(ollama_url="http://localhost:11434"):
    """返回 (ok:bool, message:str, models:list)"""
    try:
        base = ollama_url.rstrip("/").replace("/api/chat", "")
        req = urllib.request.Request(f"{base}/api/tags")
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            models = [m.get("name", "") for m in data.get("models", [])]
            return True, f"连接成功，已加载模型: {', '.join(models) if models else '(无)'}", models
    except Exception as e:
        return False, f"无法连接 {ollama_url}: {e}", []


# 直接开始ai分析线程啊
class AIWorker(QThread):
    log_signal = pyqtSignal(str)
    result_signal = pyqtSignal(str)

    def __init__(self, analyzer, mode, **kwargs):
        super().__init__()
        self.analyzer = analyzer
        self.mode = mode   # "html" 或 "summary"
        self.kwargs = kwargs

    def run(self):
        try:
            iface = self.analyzer._iface
            info = f"[AI] 将请求: url={iface.ollama_url}  model={iface.model}"
            self.log_signal.emit(info)

            if self.mode == "html":
                self.log_signal.emit("[AI] 正在分析页面内容...")
                text = self.analyzer.analyze_html(
                    self.kwargs["url"], self.kwargs["html"]
                )
                self.result_signal.emit(text)

            elif self.mode == "summary":
                self.log_signal.emit("[AI] 正在汇总扫描结果...")
                text = self.analyzer.generate_report(
                    self.kwargs["url"],
                    self.kwargs["passive_result"],
                    self.kwargs["active_result"],
                )
                self.result_signal.emit(text)
        except Exception as e:
            self.result_signal.emit(f"[AI 分析失败] {e}")





#主界面
class BrowserGUI(QWidget):

    def __init__(self):
        super().__init__()
        self.setWindowTitle("AI Web Security Browser")
        self.resize(1400, 850)


        self.scanner = ActiveScanner()
        self.analyzer = AIAnalyzer()


        self.current_html = ""
        self.current_url = ""
        self.last_scan_result = None

        self.scan_worker = None
        self.ai_worker = None

        self.init_ui()

    # 再搞个ui
    def init_ui(self):
        main_layout = QVBoxLayout(self)

        #url一栏
        top = QHBoxLayout()
        self.url_bar = QLineEdit()
        self.url_bar.setText("")
        self.visit_btn = QPushButton("访问")
        self.scan_btn = QPushButton("开始扫描")
        self.stop_btn = QPushButton("停止")
        self.ai_html_btn = QPushButton("AI分析页面")
        self.ai_summary_btn = QPushButton("AI汇总分析")
        self.check_model_btn = QPushButton("检查本地模型")
        top.addWidget(QLabel("URL:"))
        top.addWidget(self.url_bar, 1)
        top.addWidget(self.visit_btn)
        top.addWidget(self.scan_btn)
        top.addWidget(self.stop_btn)
        top.addWidget(self.ai_html_btn)
        top.addWidget(self.ai_summary_btn)
        top.addWidget(self.check_model_btn)
        main_layout.addLayout(top)

        # AI 状态一栏
        status_layout = QHBoxLayout()
        self.ai_status_label = QLabel("AI 状态: 尚未检查")
        status_layout.addWidget(self.ai_status_label)
        status_layout.addStretch(1)
        main_layout.addLayout(status_layout)

        # 搞个进度条不然还以为不会扫呢
        self.progress = QProgressBar()
        self.progress.setRange(0, 0)  # 不确定进度（忙碌）
        self.progress.setVisible(False)
        main_layout.addWidget(self.progress)

        # 搞个分割页
        splitter = QSplitter(Qt.Orientation.Horizontal)

        # 左边是浏览器
        self.browser = QWebEngineView()
        splitter.addWidget(self.browser)
        splitter.setStretchFactor(0, 3)

        # 右边是标签页
        self.tabs = QTabWidget()

        # 第一个按钮搞个扫描日志
        self.tab_log = QWidget()
        log_layout = QVBoxLayout(self.tab_log)
        log_layout.addWidget(QLabel("扫描日志"))
        self.log_box = QTextEdit()
        self.log_box.setReadOnly(True)
        log_layout.addWidget(self.log_box)

        # 第二个按钮搞个漏洞列表
        self.tab_vuln = QWidget()
        vuln_layout = QVBoxLayout(self.tab_vuln)
        vuln_layout.addWidget(QLabel("发现的漏洞（点击查看详情）"))
        self.vuln_list = QListWidget()
        vuln_layout.addWidget(self.vuln_list, 1)
        vuln_layout.addWidget(QLabel("漏洞详情"))
        self.vuln_detail = QTextEdit()
        self.vuln_detail.setReadOnly(True)
        vuln_layout.addWidget(self.vuln_detail)

        #第三个按钮搞个AI分析
        self.tab_ai = QWidget()
        ai_layout = QVBoxLayout(self.tab_ai)
        # 分两块：页面静态分析 / 汇总分析
        ai_layout.addWidget(QLabel("AI 页面静态分析（扫描前自动执行）"))
        self.ai_html_box = QTextEdit()
        self.ai_html_box.setReadOnly(True)
        ai_layout.addWidget(self.ai_html_box, 1)

        ai_layout.addWidget(QLabel("AI 扫描汇总分析（扫描后自动执行）"))
        self.ai_summary_box = QTextEdit()
        self.ai_summary_box.setReadOnly(True)
        ai_layout.addWidget(self.ai_summary_box, 2)

        self.tabs.addTab(self.tab_log, "扫描日志")
        self.tabs.addTab(self.tab_vuln, "漏洞列表")
        self.tabs.addTab(self.tab_ai, "AI 分析")

        splitter.addWidget(self.tabs)
        splitter.setStretchFactor(1, 2)
        splitter.setSizes([800, 600])
        main_layout.addWidget(splitter, 1)

        # 事件绑定
        self.visit_btn.clicked.connect(self.visit_url)
        self.scan_btn.clicked.connect(self.start_scan)
        self.stop_btn.clicked.connect(self.stop_scan)
        self.ai_html_btn.clicked.connect(self.manual_ai_html)
        self.ai_summary_btn.clicked.connect(self.manual_ai_summary)
        self.check_model_btn.clicked.connect(self.on_check_model)
        self.vuln_list.itemClicked.connect(self.on_vuln_clicked)

        # 浏览器页面切换后同步URL，并保存HTML给AI分析 在这个地方栽过好几个跟头。。。
        self.browser.urlChanged.connect(self.on_url_changed)
        self.browser.loadFinished.connect(self.on_load_finished)

        # 启动时自动检查一次 ai
        self.on_check_model()

    # 来个浏览器事件
    def visit_url(self):
        url = self.url_bar.text().strip()
        if not url:
            return
        if not url.startswith("http"):
            url = "http://" + url
            self.url_bar.setText(url)
        self.current_url = url
        self.browser.setUrl(QUrl(url))

    def on_url_changed(self, qurl):
        url = qurl.toString()
        if url and url != self.url_bar.text():
            self.url_bar.setText(url)
        self.current_url = url

    def on_load_finished(self, ok):

        try:
            self.browser.page().toHtml(self._save_html)
        except Exception as e:
            print(f"保存html失败: {e}")

    def _save_html(self, html):
        self.current_html = html or ""

    # 检查本地模型
    def on_check_model(self):
        """检查本地 Ollama 服务是否可用，并显示当前配置的 URL 和模型名"""
        try:
            iface = self.analyzer._iface
            current_config = f"配置: {iface.ollama_url} | model={iface.model}"
        except Exception as e:
            current_config = f"读取配置失败: {e}"
            self.ai_status_label.setText(f"AI 状态: {current_config}")
            return

        ok, msg, models = check_local_ollama(iface.ollama_url)
        if ok:
            status = f"✅ AI 状态: 已连接本地 Ollama | {current_config} | {msg}"
            self.ai_status_label.setText(status)
            self.ai_status_label.setStyleSheet("color: darkgreen;")
        else:
            status = f"❌ AI 状态: {msg} | {current_config}"
            self.ai_status_label.setText(status)
            self.ai_status_label.setStyleSheet("color: darkred;")

    # 扫描
    def start_scan(self):
        url = self.url_bar.text().strip()
        if not url:
            QMessageBox.warning(self, "提示", "请先输入URL或访问页面")
            return

        # 清空上次结果
        self.log_box.clear()
        self.vuln_list.clear()
        self.vuln_detail.clear()
        self.tabs.setCurrentIndex(0)

        #先用AI做页面静态分析
        if self.current_html:
            self._run_ai_html(url, self.current_html)

        # 再启动主动扫描
        self.progress.setVisible(True)
        self.scan_worker = ScanWorker(self.scanner, url)
        self.scan_worker.log_signal.connect(self._on_log)
        self.scan_worker.vuln_signal.connect(self._on_vuln)
        self.scan_worker.done_signal.connect(self._on_scan_done)
        self.scan_worker.start()

        self._on_log(f"[*] 开始扫描: {url}")

    def stop_scan(self):
        if self.scanner:
            self.scanner.stop()
        self._on_log("[!] 用户停止扫描")
        self.progress.setVisible(False)

    def _on_log(self, text):
        self.log_box.append(text)

    def _on_vuln(self, text):
        self.vuln_list.addItem(text)
        self.vuln_detail.append(text)

    def on_vuln_clicked(self, item):
        self.vuln_detail.setText(item.text())

    def _on_scan_done(self, result):
        self.progress.setVisible(False)
        self.last_scan_result = result
        self._on_log(f"[+] 扫描完成。漏洞数: {result['vuln_count']}")

        #最后AI汇总分析
        active_text = "\n".join(result["logs"][-50:])
        vulns_text = "\n".join(
            [f"- {v['type']}: {v['description']} (payload={v['payload']})"
             for v in result["vulnerabilities"]]
        ) or "（未发现漏洞）"
        combined = f"=== 扫描日志摘要 ===\n{active_text}\n\n=== 漏洞列表 ===\n{vulns_text}"
        self._run_ai_summary(result["url"], combined)

    # ai超绝分析
    def manual_ai_html(self):
        url = self.url_bar.text().strip() or self.current_url
        if not self.current_html or not url:
            QMessageBox.warning(self, "提示", "请先访问一个页面")
            return
        self.tabs.setCurrentIndex(2)
        self._run_ai_html(url, self.current_html)

    def manual_ai_summary(self):
        if not self.last_scan_result:
            QMessageBox.warning(self, "提示", "请先执行一次扫描")
            return
        self.tabs.setCurrentIndex(2)
        result = self.last_scan_result
        active_text = "\n".join(result["logs"][-50:])
        vulns_text = "\n".join(
            [f"- {v['type']}: {v['description']} (payload={v['payload']})"
             for v in result["vulnerabilities"]]
        ) or "（未发现漏洞）"
        combined = f"=== 扫描日志摘要 ===\n{active_text}\n\n=== 漏洞列表 ===\n{vulns_text}"
        self._run_ai_summary(result["url"], combined)

    def _run_ai_html(self, url, html):
        self.ai_worker = AIWorker(self.analyzer, "html", url=url, html=html)
        self.ai_worker.log_signal.connect(self._on_ai_log)
        self.ai_worker.result_signal.connect(self._on_ai_html_result)
        self.ai_worker.start()
        self.tabs.setCurrentIndex(2)

    def _run_ai_summary(self, url, active_result):
        self.ai_worker = AIWorker(
            self.analyzer, "summary",
            url=url, passive_result="", active_result=active_result
        )
        self.ai_worker.log_signal.connect(self._on_ai_log)
        self.ai_worker.result_signal.connect(self._on_ai_summary_result)
        self.ai_worker.start()
        self.tabs.setCurrentIndex(2)

    def _on_ai_log(self, text):
        self.log_box.append(text)

    def _on_ai_html_result(self, text):
        self.ai_html_box.setPlainText(text)

    def _on_ai_summary_result(self, text):
        self.ai_summary_box.setPlainText(text)


#浏览器   启动！！！！！！！
def main():
    app = QApplication(sys.argv)
    win = BrowserGUI()
    win.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
