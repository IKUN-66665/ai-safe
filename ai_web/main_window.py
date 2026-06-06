import sys, os, json
from datetime import datetime
from typing import Optional, Dict, List

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLineEdit, QPushButton, QLabel, QTabWidget, QTextEdit,
    QProgressBar, QGroupBox, QFrame, QSplitter,
    QMessageBox, QComboBox, QCheckBox, QListWidget
)
from PyQt6.QtCore import Qt, QUrl, pyqtSignal, QThread
from PyQt6.QtWebEngineWidgets import QWebEngineView
from PyQt6.QtWebEngineCore import QWebEnginePage

from .url_parser import SecureBrowser
from .static_analyzer import PassiveAnalyzer, PassiveAnalysisReport
from .payload_scanner import ActiveScanner, ActiveScanReport
from .ai_analyzer import AIAnalyzer


class PassiveThread(QThread):
    finished = pyqtSignal(object)
    error = pyqtSignal(str)

    def __init__(self, analyzer, url, html):
        super().__init__()
        self.analyzer = analyzer
        self.url = url
        self.html = html

    def run(self):
        try:
            r = self.analyzer.analyze(self.url, self.html)
            self.finished.emit(r)
        except Exception as e:
            self.error.emit(str(e))


class ScanThread(QThread):
    progress = pyqtSignal(str, int)
    finished = pyqtSignal(object)
    error = pyqtSignal(str)

    def __init__(self, scanner, url, scan_types=None, html_content=None):
        super().__init__()
        self.scanner = scanner
        self.url = url
        self.scan_types = scan_types
        self.html_content = html_content

    def run(self):
        try:
            r = self.scanner.scan_url(
                url=self.url, scan_types=self.scan_types,
                progress_callback=lambda msg, pct: self.progress.emit(msg, pct),
                html_content=self.html_content
            )
            self.finished.emit(r)
        except Exception as e:
            self.error.emit(str(e))


class AIThread(QThread):
    finished = pyqtSignal(str)
    error = pyqtSignal(str)
    status = pyqtSignal(str)

    def __init__(self, analyzer, task, **kwargs):
        super().__init__()
        self.analyzer = analyzer
        self.task = task
        self.kwargs = kwargs

    def run(self):
        try:
            if self.task == 'html':
                self.status.emit("AI正在分析页面HTML...")
                r = self.analyzer.analyze_html(self.kwargs['url'], self.kwargs['html'])
            elif self.task == 'report':
                self.status.emit("AI正在生成审计报告...")
                r = self.analyzer.generate_report(
                    self.kwargs['url'],
                    self.kwargs['passive_result'],
                    self.kwargs['active_result']
                )
            else:
                r = "未知任务"
            self.finished.emit(r)
        except ConnectionError as e:
            self.error.emit(str(e))
        except Exception as e:
            self.error.emit(f"AI分析失败: {e}")


class BrowserGUI(QMainWindow):

    def __init__(self):
        super().__init__()
        self.setWindowTitle("Web安全审计浏览器")
        self.setGeometry(100, 100, 1400, 900)

        self.browser = SecureBrowser()
        self.passive_analyzer = PassiveAnalyzer()
        self.active_scanner = ActiveScanner()
        self.ai_analyzer = AIAnalyzer()

        self.current_passive_report = None
        self.current_active_report = None
        self.is_user_navigation = False

        self._passive_thread = None
        self._scan_thread = None
        self._ai_thread = None

        self._build_ui()
        self._connect_signals()

    def _build_ui(self):
        cw = QWidget()
        self.setCentralWidget(cw)
        main_lay = QHBoxLayout(cw)
        main_lay.setContentsMargins(8, 8, 8, 8)
        main_lay.setSpacing(6)

        # 用QSplitter替代普通layout，支持拖拽调整宽度
        splitter = QSplitter(Qt.Orientation.Horizontal)

        left = QWidget()
        left_lay = QVBoxLayout(left)
        left_lay.setContentsMargins(0, 0, 0, 0)
        left_lay.setSpacing(6)

        nav = QHBoxLayout()
        self.back_btn = QPushButton("←")
        self.forward_btn = QPushButton("→")
        self.refresh_btn = QPushButton("↻")
        self.url_input = QLineEdit()
        self.url_input.setPlaceholderText("输入网址...")
        self.go_btn = QPushButton("访问")
        nav.addWidget(self.back_btn)
        nav.addWidget(self.forward_btn)
        nav.addWidget(self.refresh_btn)
        nav.addWidget(self.url_input, 1)
        nav.addWidget(self.go_btn)
        left_lay.addLayout(nav)

        self.web_view = QWebEngineView()
        self.browser.set_web_view(self.web_view)
        left_lay.addWidget(self.web_view, 1)

        splitter.addWidget(left)

        right = QWidget()
        right_lay = QVBoxLayout(right)
        right_lay.setContentsMargins(0, 0, 0, 0)
        right_lay.setSpacing(6)

        self.tab_widget = QTabWidget()
        self.tab_widget.addTab(self._build_quick_tab(), "快速分析")
        self.tab_widget.addTab(self._build_passive_tab(), "被动分析")
        self.tab_widget.addTab(self._build_scan_tab(), "主动扫描")
        self.tab_widget.addTab(self._build_owasp_tab(), "OWASP报告")
        self.tab_widget.addTab(self._build_ai_tab(), "AI智能分析")
        right_lay.addWidget(self.tab_widget)

        splitter.addWidget(right)
        # 初始比例 2:1
        splitter.setSizes([933, 467])
        splitter.setStretchFactor(0, 2)
        splitter.setStretchFactor(1, 1)

        main_lay.addWidget(splitter, 1)

    def _build_quick_tab(self):
        w = QWidget()
        lay = QVBoxLayout(w)
        self.quick_status = QLabel("等待分析...")
        self.quick_status.setWordWrap(True)
        lay.addWidget(self.quick_status)
        self.quick_detail = QTextEdit()
        self.quick_detail.setReadOnly(True)
        lay.addWidget(self.quick_detail)
        return w

    def _build_passive_tab(self):
        w = QWidget()
        lay = QVBoxLayout(w)
        self.passive_status = QLabel("等待分析...")
        self.passive_status.setWordWrap(True)
        lay.addWidget(self.passive_status)
        self.passive_detail = QTextEdit()
        self.passive_detail.setReadOnly(True)
        lay.addWidget(self.passive_detail)
        return w

    def _build_scan_tab(self):
        w = QWidget()
        lay = QVBoxLayout(w)

        ctrl = QHBoxLayout()
        self.scan_type_combo = QComboBox()
        self.scan_type_combo.addItems(["全部扫描", "仅XSS", "仅SQL注入", "仅命令注入", "仅路径遍历"])
        self.start_scan_btn = QPushButton("开始扫描")
        self.stop_scan_btn = QPushButton("停止")
        self.stop_scan_btn.setEnabled(False)
        ctrl.addWidget(QLabel("扫描类型:"))
        ctrl.addWidget(self.scan_type_combo)
        ctrl.addWidget(self.start_scan_btn)
        ctrl.addWidget(self.stop_scan_btn)
        lay.addLayout(ctrl)

        self.scan_progress_bar = QProgressBar()
        lay.addWidget(self.scan_progress_bar)
        self.scan_status_label = QLabel("就绪")
        lay.addWidget(self.scan_status_label)

        self.scan_detail = QTextEdit()
        self.scan_detail.setReadOnly(True)
        lay.addWidget(self.scan_detail)
        return w

    def _build_owasp_tab(self):
        w = QWidget()
        lay = QVBoxLayout(w)
        self.owasp_list = QListWidget()
        lay.addWidget(self.owasp_list)
        exp_row = QHBoxLayout()
        self.export_html_btn = QPushButton("导出HTML报告")
        self.export_json_btn = QPushButton("导出JSON数据")
        exp_row.addWidget(self.export_html_btn)
        exp_row.addWidget(self.export_json_btn)
        exp_row.addStretch()
        lay.addLayout(exp_row)
        return w

    def _build_ai_tab(self):
        w = QWidget()
        lay = QVBoxLayout(w)

        info = QGroupBox("AI模型配置")
        info_lay = QHBoxLayout(info)
        info_lay.addWidget(QLabel("模型:"))
        self.ai_model_label = QLabel("deepseek-r1:7b (Ollama)")
        self.ai_model_label.setStyleSheet("color:blue;font-weight:bold;")
        info_lay.addWidget(self.ai_model_label)
        info_lay.addStretch()
        self.ai_status_dot = QLabel("●")
        self.ai_status_dot.setStyleSheet("color:gray;font-size:16px;")
        self.ai_status_label = QLabel("未检测")
        info_lay.addWidget(self.ai_status_dot)
        info_lay.addWidget(self.ai_status_label)
        self.ai_check_btn = QPushButton("检测连接")
        info_lay.addWidget(self.ai_check_btn)
        lay.addWidget(info)

        ctrl = QHBoxLayout()
        self.ai_analyze_btn = QPushButton("AI分析当前页面")
        self.ai_analyze_btn.setMinimumHeight(40)
        self.ai_report_btn = QPushButton("AI生成审计报告")
        self.ai_report_btn.setMinimumHeight(40)
        self.ai_report_btn.setEnabled(False)
        ctrl.addWidget(self.ai_analyze_btn)
        ctrl.addWidget(self.ai_report_btn)
        lay.addLayout(ctrl)

        res = QGroupBox("AI分析结果")
        res_lay = QVBoxLayout(res)
        self.ai_result_text = QTextEdit()
        self.ai_result_text.setReadOnly(True)
        res_lay.addWidget(self.ai_result_text)
        lay.addWidget(res)
        return w

    def _connect_signals(self):
        self.back_btn.clicked.connect(self.web_view.back)
        self.forward_btn.clicked.connect(self.web_view.forward)
        self.refresh_btn.clicked.connect(self.web_view.reload)
        self.go_btn.clicked.connect(self._on_go)
        self.url_input.returnPressed.connect(self._on_go)
        self.browser.load_finished.connect(self._on_page_loaded)
        self.browser.url_changed.connect(self._on_url_changed)

        self.start_scan_btn.clicked.connect(self.start_active_scan)
        self.stop_scan_btn.clicked.connect(self.active_scanner.stop_scan)

        self.export_html_btn.clicked.connect(self.export_html_report)
        self.export_json_btn.clicked.connect(self.export_json_report)
        self.ai_check_btn.clicked.connect(self._check_ai_service)
        self.ai_analyze_btn.clicked.connect(self._start_ai_analyze)
        self.ai_report_btn.clicked.connect(self._start_ai_report)

    def _on_go(self):
        url = self.url_input.text().strip()
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
            self.url_input.setText(url)
        self.is_user_navigation = True
        self.web_view.setUrl(QUrl(url))

    def _on_url_changed(self, url):
        self.url_input.setText(url)

    def _on_page_loaded(self, success, url):
        if success and self.is_user_navigation:
            self.statusBar().showMessage(f"已加载: {url}")
            self.web_view.page().toHtml(self._on_html_ready)

    def _on_html_ready(self, html):
        self._last_html = html
        self.is_user_navigation = False
        url = self.url_input.text().strip()
        self.statusBar().showMessage("后台分析中...")
        self._passive_thread = PassiveThread(self.passive_analyzer, url, html)
        self._passive_thread.finished.connect(self._on_passive_done)
        self._passive_thread.error.connect(lambda e: self.statusBar().showMessage(f"分析失败: {e}"))
        self._passive_thread.start()

    def _on_passive_done(self, rpt):
        tmp_r = rpt
        self.current_passive_report = tmp_r
        self._refresh_passive_ui()
        self._refresh_quick_ui()
        self.statusBar().showMessage("被动分析完成")
        if getattr(self, '_pending_full_scan', False):
            self._pending_full_scan = False
            self.start_active_scan()
        self.ai_report_btn.setEnabled(True)

    def _refresh_passive_ui(self):
        pr = self.current_passive_report
        if not pr:
            return
        self.passive_status.setText(f"风险等级: {pr.risk_level} ({pr.risk_score}/100)")
        detail = f"URL: {pr.url}\n\n"
        detail += f"发现 {len(pr.issues)} 个问题:\n"
        for i in pr.issues:
            detail += f"  - {i}\n"
        detail += f"\n漏洞详情:\n"
        for v in pr.vulnerabilities:
            detail += f"  [{v['severity']}] {v['type']}: {v['description']}\n"
        self.passive_detail.setPlainText(detail)

    def _refresh_quick_ui(self):
        pr = self.current_passive_report
        if not pr:
            return
        self.quick_status.setText(f"风险等级: {pr.risk_level}")
        summary = f"快速摘要:\n"
        summary += f"- URL: {pr.url}\n"
        summary += f"- 风险评分: {pr.risk_score}/100\n"
        summary += f"- 发现问题: {len(pr.issues)} 个\n"
        summary += f"- 漏洞数量: {len(pr.vulnerabilities)} 个\n"
        self.quick_detail.setPlainText(summary)

    def run_full_scan(self):
        self.statusBar().showMessage("完整审计中...")
        self.run_passive_analysis()
        self._pending_full_scan = True

    def run_passive_analysis(self):
        self.is_user_navigation = True
        self._on_html_ready(self._last_html if hasattr(self, '_last_html') else "")

    def start_active_scan(self):
        url = self.url_input.text().strip()
        if not url:
            QMessageBox.warning(self, "提示", "请先输入或访问一个网址")
            return
        type_map = {
            "全部扫描": None, "仅XSS": ["xss"], "仅SQL注入": ["sqli"],
            "仅命令注入": ["command_injection"], "仅路径遍历": ["path_traversal"]
        }
        st = type_map.get(self.scan_type_combo.currentText())
        self.start_scan_btn.setEnabled(False)
        self.stop_scan_btn.setEnabled(True)
        self.scan_progress_bar.setValue(0)
        self.scan_status_label.setText("初始化...")

        html = getattr(self, '_last_html', None)
        self._scan_thread = ScanThread(self.active_scanner, url, st, html)
        self._scan_thread.progress.connect(self._on_scan_progress)
        self._scan_thread.finished.connect(self._on_scan_done)
        self._scan_thread.error.connect(self._on_scan_err)
        self._scan_thread.start()

    def _on_scan_progress(self, msg, pct):
        self.scan_status_label.setText(msg)
        self.scan_progress_bar.setValue(pct)

    def _on_scan_done(self, rpt):
        tmp_r = rpt
        self.current_active_report = tmp_r
        self._refresh_scan_ui()
        self.start_scan_btn.setEnabled(True)
        self.stop_scan_btn.setEnabled(False)
        self.statusBar().showMessage("主动扫描完成")
        self.ai_report_btn.setEnabled(True)

    def _on_scan_err(self, err):
        self.scan_detail.append(f"扫描错误: {err}")
        self.start_scan_btn.setEnabled(True)
        self.stop_scan_btn.setEnabled(False)
        self.statusBar().showMessage(f"扫描失败: {err}")

    def _refresh_scan_ui(self):
        tmp_r = self.current_active_report
        if not tmp_r:
            return
        detail = f"扫描结果:\n"
        detail += f"- URL: {tmp_r.url}\n"
        detail += f"- 风险等级: {tmp_r.risk_level}\n"
        detail += f"- 扫描耗时: {tmp_r.scan_time:.2f}秒\n"
        detail += f"- 请求次数: {tmp_r.cnt}\n"
        detail += f"- 漏洞数量: {len(tmp_r.vulnerabilities)}\n\n"
        for v in tmp_r.vulnerabilities:
            detail += f"[{v.severity}] {v.name}\n"
            detail += f"  位置: {v.location}\n"
            detail += f"  描述: {v.description}\n"
            detail += f"  修复: {v.remediation}\n"
            detail += f"  OWASP: {v.owasp_category}\n\n"
        self.scan_detail.setPlainText(detail)

    def _check_ai_service(self):
        self.ai_check_btn.setEnabled(False)
        self.ai_status_label.setText("检测中...")
        self.ai_status_dot.setStyleSheet("color:orange;font-size:16px;")
        from PyQt6.QtCore import QTimer
        QTimer.singleShot(100, self._do_check_ai)

    def _do_check_ai(self):
        ok = self.ai_analyzer.check_service()
        if ok:
            self.ai_status_label.setText("已连接")
            self.ai_status_dot.setStyleSheet("color:green;font-size:16px;")
            self.statusBar().showMessage("Ollama服务已连接")
        else:
            self.ai_status_label.setText("未连接")
            self.ai_status_dot.setStyleSheet("color:red;font-size:16px;")
            self.statusBar().showMessage("无法连接Ollama服务，请确认Ollama已启动")
        self.ai_check_btn.setEnabled(True)

    def _start_ai_analyze(self):
        url = self.url_input.text().strip()
        if not url:
            QMessageBox.warning(self, "提示", "请先访问一个网页")
            return
        html = getattr(self, '_last_html', None)
        if not html:
            QMessageBox.warning(self, "提示", "页面HTML尚未加载完成")
            return
        self.ai_analyze_btn.setEnabled(False)
        self.ai_result_text.setHtml("<p>正在调用AI分析页面，请稍候...</p>")
        self._ai_thread = AIThread(self.ai_analyzer, 'html', url=url, html=html)
        self._ai_thread.status.connect(lambda msg: self.statusBar().showMessage(msg))
        self._ai_thread.finished.connect(self._on_ai_analyze_done)
        self._ai_thread.error.connect(self._on_ai_err)
        self._ai_thread.start()

    def _on_ai_analyze_done(self, result):
        self.ai_analyze_btn.setEnabled(True)
        html_text = result.replace("\n", "<br>")
        self.ai_result_text.setHtml(f"<h3>AI页面分析结果</h3><hr>{html_text}")
        self.statusBar().showMessage("AI页面分析完成")

    def _start_ai_report(self):
        url = self.url_input.text().strip()
        pr = self.current_passive_report
        ar = self.current_active_report
        if not pr and not ar:
            QMessageBox.warning(self, "提示", "请先完成被动分析或主动扫描")
            return
        p_text = ""
        if pr:
            p_text = f"风险等级: {pr.risk_level} ({pr.risk_score}/100)\n"
            p_text += f"问题列表: {pr.issues}\n"
            p_text += f"漏洞: {pr.vulnerabilities}\n"
            p_text += f"表单数: {len(pr.forms)}, 脚本数: {len(pr.scripts)}"
        a_text = ""
        if ar:
            a_text = f"风险等级: {ar.risk_level}\n"
            a_text += f"耗时: {ar.scan_time:.2f}s, 请求: {ar.cnt}次\n"
            a_text += f"漏洞数: {len(ar.vulnerabilities)}\n"
            for v in ar.vulnerabilities:
                a_text += f"  - [{v.severity}] {v.name}: {v.description}\n"

        self.ai_report_btn.setEnabled(False)
        self.ai_result_text.setHtml("<p>正在调用AI生成审计报告，请稍候...</p>")
        self._ai_thread = AIThread(self.ai_analyzer, 'report',
                                   url=url, passive_result=p_text, active_result=a_text)
        self._ai_thread.status.connect(lambda msg: self.statusBar().showMessage(msg))
        self._ai_thread.finished.connect(self._on_ai_report_done)
        self._ai_thread.error.connect(self._on_ai_err)
        self._ai_thread.start()

    def _on_ai_report_done(self, result):
        self.ai_report_btn.setEnabled(True)
        html_text = result.replace("\n", "<br>")
        self.ai_result_text.setHtml(f"<h3>AI安全审计报告</h3><hr>{html_text}")
        self.statusBar().showMessage("AI审计报告生成完成")

    def _on_ai_err(self, err):
        self.ai_analyze_btn.setEnabled(True)
        self.ai_report_btn.setEnabled(True)
        self.ai_result_text.setHtml(f"<p style='color:red;'>错误: {err}</p>")
        self.statusBar().showMessage(f"AI分析失败: {err}")

    def export_html_report(self):
        pr = self.current_passive_report
        ar = self.current_active_report
        if not pr and not ar:
            QMessageBox.warning(self, "提示", "无数据可导出")
            return
        try:
            fn = f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
            with open(fn, 'w', encoding='utf-8') as f:
                f.write(self._gen_html(pr, ar))
            QMessageBox.information(self, "完成", f"已导出: {fn}")
        except Exception as e:
            QMessageBox.critical(self, "错误", str(e))

    def export_json_report(self):
        pr = self.current_passive_report
        ar = self.current_active_report
        if not pr and not ar:
            QMessageBox.warning(self, "提示", "无数据可导出")
            return
        try:
            fn = f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            data = {}
            if pr:
                data['passive'] = {
                    'url': pr.url, 'risk_level': pr.risk_level, 'risk_score': pr.risk_score,
                    'issues': pr.issues, 'vulnerabilities': pr.vulnerabilities,
                    'forms': len(pr.forms), 'scripts': len(pr.scripts)
                }
            if ar:
                data['active'] = {
                    'url': ar.url, 'risk_level': ar.risk_level,
                    'scan_time': ar.scan_time, 'cnt': ar.cnt,
                    'vulnerabilities': [
                        {'name': v.name, 'type': v.vuln_type, 'severity': v.severity,
                         'location': v.location, 'description': v.description}
                        for v in ar.vulnerabilities
                    ]
                }
            with open(fn, 'w', encoding='utf-8') as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
            QMessageBox.information(self, "完成", f"已导出: {fn}")
        except Exception as e:
            QMessageBox.critical(self, "错误", str(e))

    def _gen_html(self, pr, ar):
        html = "<html><head><meta charset='utf-8'><title>安全审计报告</title></head><body>"
        html += "<h1>Web安全审计报告</h1>"
        if pr:
            html += f"<h2>被动分析</h2><p>URL: {pr.url}</p><p>风险: {pr.risk_level} ({pr.risk_score}/100)</p>"
            html += "<ul>"
            for i in pr.issues:
                html += f"<li>{i}</li>"
            html += "</ul>"
        if ar:
            html += f"<h2>主动扫描</h2><p>URL: {ar.url}</p><p>风险: {ar.risk_level}</p>"
            html += f"<p>耗时: {ar.scan_time:.2f}s, 请求: {ar.cnt}</p><ul>"
            for v in ar.vulnerabilities:
                html += f"<li>[{v.severity}] {v.name}: {v.description}</li>"
            html += "</ul>"
        html += "</body></html>"
        return html


def main():
    app = QApplication(sys.argv)
    window = BrowserGUI()
    window.show()
    sys.exit(app.exec())
