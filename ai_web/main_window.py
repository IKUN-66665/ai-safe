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


class SecureWebPage(QWebEnginePage):
    def __init__(self, parent=None, gui=None):
        super().__init__(parent)
        self.gui = gui

    def createWindow(self, t):
        return self


class BrowserGUI(QMainWindow):

    def __init__(self):
        super().__init__()
        self.setWindowTitle("Web安全审计浏览器")
        self.setGeometry(100, 100, 1500, 950)

        self.browser = SecureBrowser()
        self.passive_analyzer = PassiveAnalyzer()
        self.active_scanner = ActiveScanner()

        self.current_passive_report = None
        self.current_active_report = None
        self.is_user_navigation = False

        # 线程引用，防止被gc回收
        self._passive_thread = None
        self._scan_thread = None

        self.init_ui()
        self.connect_signals()
        self.reset_ui()

    def reset_ui(self):
        self.url_status_label.setText("等待分析...")
        self.risk_score_label.setText("风险等级: --")
        self.risk_score_label.setStyleSheet("font-size: 18px; font-weight: bold; color: gray;")
        self.risk_progress.setValue(0)
        self.issues_list.clear()
        self.issues_list.addItem("请输入网址后开始安全审计")

        self.passive_url_text.setHtml("<p>等待分析...</p>")
        self.passive_form_text.setHtml("<p>等待分析...</p>")
        self.passive_js_text.setHtml("<p>等待分析...</p>")
        self.passive_header_text.setHtml("<p>等待分析...</p>")

        self.active_result_text.setHtml("<p>请点击「开始扫描」按钮进行主动扫描</p>")
        self.owasp_overview_text.setHtml("<h3>OWASP Top 10 (2021)</h3><p>等待扫描...</p>")
        self.owasp_findings_text.setHtml("<p>等待扫描...</p>")
        self.owasp_recommendations_text.setHtml("<p>等待扫描...</p>")

    def init_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        root = QVBoxLayout(central)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        # 工具栏
        tb = QFrame()
        tb.setFixedHeight(40)
        tb.setStyleSheet("QFrame{background:#f5f5f5;border-bottom:1px solid #ddd;}")
        tb_lay = QHBoxLayout(tb)
        tb_lay.setContentsMargins(5, 2, 5, 2)
        tb_lay.setSpacing(3)

        self.back_btn = QPushButton("")
        self.back_btn.setFixedSize(32, 32)
        self.back_btn.setToolTip("后退")
        self.forward_btn = QPushButton("")
        self.forward_btn.setFixedSize(32, 32)
        self.forward_btn.setToolTip("前进")
        self.refresh_btn = QPushButton("")
        self.refresh_btn.setFixedSize(32, 32)
        self.refresh_btn.setToolTip("刷新")

        self.url_input = QLineEdit()
        self.url_input.setPlaceholderText("输入网址...")
        self.url_input.setMinimumWidth(200)

        self.go_btn = QPushButton("访问")
        self.go_btn.setDefault(True)
        # go_btn 不设置固定样式，用系统默认

        self.security_indicator = QLabel(" 就绪")
        self.security_indicator.setFixedWidth(80)
        self.security_indicator.setStyleSheet("color:gray;font-weight:bold;font-size:12px;")

        tb_lay.addWidget(self.back_btn)
        tb_lay.addWidget(self.forward_btn)
        tb_lay.addWidget(self.refresh_btn)
        tb_lay.addWidget(self.url_input, 1)
        tb_lay.addWidget(self.go_btn)
        tb_lay.addWidget(self.security_indicator)
        root.addWidget(tb)

        # 主体分栏
        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.setHandleWidth(1)

        # 左边浏览器
        left = QWidget()
        ll = QVBoxLayout(left)
        ll.setContentsMargins(0, 0, 0, 0)
        ll.setSpacing(0)
        self.web_view = QWebEngineView()
        sp = SecureWebPage(self.web_view, self)
        self.web_view.setPage(sp)
        self.browser.set_web_view(self.web_view)
        ll.addWidget(self.web_view)
        splitter.addWidget(left)

        # 右边分析面板
        right = QWidget()
        rl = QVBoxLayout(right)
        rl.setContentsMargins(0, 0, 0, 0)

        self.tab_widget = QTabWidget()
        self.tab_widget.setDocumentMode(True)

        self.tab_widget.addTab(self._build_quick_tab(), "快速分析")
        self.tab_widget.addTab(self._build_passive_tab(), "被动分析")
        self.tab_widget.addTab(self._build_scan_tab(), "主动扫描")
        self.tab_widget.addTab(self._build_owasp_tab(), "OWASP报告")

        rl.addWidget(self.tab_widget)
        splitter.addWidget(right)
        splitter.setSizes([950, 450])
        root.addWidget(splitter)
        self.statusBar().showMessage("就绪 - 请输入网址开始安全审计")

    def _build_quick_tab(self):
        w = QWidget()
        lay = QVBoxLayout(w)

        # url状态和风险评分放一起
        info_group = QGroupBox("URL状态 / 风险评分")
        ig_lay = QVBoxLayout(info_group)
        self.url_status_label = QLabel("等待分析...")
        self.url_status_label.setWordWrap(True)
        ig_lay.addWidget(self.url_status_label)
        self.risk_score_label = QLabel("风险等级: --")
        self.risk_score_label.setStyleSheet("font-size:18px;font-weight:bold;")
        ig_lay.addWidget(self.risk_score_label)
        self.risk_progress = QProgressBar()
        self.risk_progress.setRange(0, 100)
        ig_lay.addWidget(self.risk_progress)
        lay.addWidget(info_group)

        btn_row = QHBoxLayout()
        self.quick_scan_btn = QPushButton("快速扫描")
        self.full_scan_btn = QPushButton("完整审计")
        btn_row.addWidget(self.quick_scan_btn)
        btn_row.addWidget(self.full_scan_btn)
        lay.addLayout(btn_row)

        issues_group = QGroupBox("发现的问题")
        il = QVBoxLayout(issues_group)
        self.issues_list = QListWidget()
        self.issues_list.setMaximumHeight(150)
        il.addWidget(self.issues_list)
        lay.addWidget(issues_group)
        lay.addStretch()
        return w

    def _build_passive_tab(self):
        w = QWidget()
        lay = QVBoxLayout(w)

        # 把URL分析和HTTP头部合并
        top_group = QGroupBox("URL / HTTP头部")
        tl = QVBoxLayout(top_group)
        self.passive_url_text = QTextEdit()
        self.passive_url_text.setReadOnly(True)
        self.passive_url_text.setMaximumHeight(120)
        tl.addWidget(self.passive_url_text)
        self.passive_header_text = QTextEdit()
        self.passive_header_text.setReadOnly(True)
        self.passive_header_text.setMaximumHeight(80)
        tl.addWidget(self.passive_header_text)
        lay.addWidget(top_group)

        # 表单和JS合并
        mid_group = QGroupBox("表单 / JavaScript")
        ml = QVBoxLayout(mid_group)
        self.passive_form_text = QTextEdit()
        self.passive_form_text.setReadOnly(True)
        self.passive_form_text.setMaximumHeight(120)
        ml.addWidget(self.passive_form_text)
        self.passive_js_text = QTextEdit()
        self.passive_js_text.setReadOnly(True)
        ml.addWidget(self.passive_js_text)
        lay.addWidget(mid_group)
        return w

    def _build_scan_tab(self):
        w = QWidget()
        lay = QVBoxLayout(w)

        cfg = QGroupBox("扫描配置")
        cfg_lay = QVBoxLayout(cfg)
        row1 = QHBoxLayout()
        row1.addWidget(QLabel("扫描类型:"))
        self.scan_type_combo = QComboBox()
        self.scan_type_combo.addItems(["全部扫描", "仅XSS", "仅SQL注入", "仅命令注入", "仅路径遍历"])
        row1.addWidget(self.scan_type_combo)
        row1.addStretch()
        cfg_lay.addLayout(row1)

        row2 = QHBoxLayout()
        self.deep_scan_check = QCheckBox("深度扫描")
        self.deep_scan_check.setChecked(True)
        self.follow_redirect_check = QCheckBox("跟随重定向")
        self.follow_redirect_check.setChecked(True)
        row2.addWidget(self.deep_scan_check)
        row2.addWidget(self.follow_redirect_check)
        row2.addStretch()
        cfg_lay.addLayout(row2)
        lay.addWidget(cfg)

        ctrl = QHBoxLayout()
        self.start_scan_btn = QPushButton("开始扫描")
        self.start_scan_btn.setMinimumHeight(40)
        # 不设置绿色背景样式，用默认
        self.stop_scan_btn = QPushButton("停止扫描")
        self.stop_scan_btn.setMinimumHeight(40)
        self.stop_scan_btn.setEnabled(False)
        ctrl.addWidget(self.start_scan_btn)
        ctrl.addWidget(self.stop_scan_btn)
        lay.addLayout(ctrl)

        pg = QGroupBox("进度")
        pg_lay = QVBoxLayout(pg)
        self.scan_progress_bar = QProgressBar()
        self.scan_progress_bar.setRange(0, 100)
        pg_lay.addWidget(self.scan_progress_bar)
        self.scan_status_label = QLabel("等待开始...")
        pg_lay.addWidget(self.scan_status_label)
        lay.addWidget(pg)

        res = QGroupBox("结果")
        res_lay = QVBoxLayout(res)
        self.active_result_text = QTextEdit()
        self.active_result_text.setReadOnly(True)
        res_lay.addWidget(self.active_result_text)
        lay.addWidget(res)
        return w

    def _build_owasp_tab(self):
        w = QWidget()
        lay = QVBoxLayout(w)

        og = QGroupBox("OWASP Top 10 (2021) 检测概览")
        ol = QVBoxLayout(og)
        self.owasp_overview_text = QTextEdit()
        self.owasp_overview_text.setReadOnly(True)
        self.owasp_overview_text.setMaximumHeight(180)
        self.owasp_overview_text.setHtml("<h3>OWASP Top 10 (2021)</h3><p>等待扫描...</p>")
        ol.addWidget(self.owasp_overview_text)
        lay.addWidget(og)

        fg = QGroupBox("详细发现")
        fl = QVBoxLayout(fg)
        self.owasp_findings_text = QTextEdit()
        self.owasp_findings_text.setReadOnly(True)
        fl.addWidget(self.owasp_findings_text)
        lay.addWidget(fg)

        rg = QGroupBox("修复建议")
        rl2 = QVBoxLayout(rg)
        self.owasp_recommendations_text = QTextEdit()
        self.owasp_recommendations_text.setReadOnly(True)
        rl2.addWidget(self.owasp_recommendations_text)
        lay.addWidget(rg)

        exp_row = QHBoxLayout()
        self.export_html_btn = QPushButton("导出HTML报告")
        self.export_json_btn = QPushButton("导出JSON数据")
        exp_row.addWidget(self.export_html_btn)
        exp_row.addWidget(self.export_json_btn)
        exp_row.addStretch()
        lay.addLayout(exp_row)
        return w

    def connect_signals(self):
        self.back_btn.clicked.connect(self.web_view.back)
        self.forward_btn.clicked.connect(self.web_view.forward)
        self.refresh_btn.clicked.connect(self.web_view.reload)
        self.go_btn.clicked.connect(self.navigate_to_url)
        self.url_input.returnPressed.connect(self.navigate_to_url)
        self.browser.url_changed.connect(self.on_url_changed)
        self.browser.load_finished.connect(self.on_load_finished)
        self.quick_scan_btn.clicked.connect(self.run_quick_scan)
        self.full_scan_btn.clicked.connect(self.run_full_scan)
        self.start_scan_btn.clicked.connect(self.start_active_scan)
        self.stop_scan_btn.clicked.connect(self.stop_active_scan)
        self.export_html_btn.clicked.connect(self.export_html_report)
        self.export_json_btn.clicked.connect(self.export_json_report)

    def navigate_to_url(self):
        url = self.url_input.text().strip()
        if not url:
            return
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
            self.url_input.setText(url)
        self.is_user_navigation = True
        self.statusBar().showMessage(f"正在加载: {url}")
        self.web_view.setUrl(QUrl(url))

    def on_url_changed(self, url):
        self.url_input.setText(url)
        if not self.is_user_navigation:
            return
        if url.startswith('https://'):
            self.security_indicator.setText(" HTTPS")
            self.security_indicator.setStyleSheet("color:green;font-weight:bold;font-size:14px;")
        else:
            self.security_indicator.setText(" HTTP")
            self.security_indicator.setStyleSheet("color:orange;font-weight:bold;font-size:14px;")

    def on_load_finished(self, success, url):
        if not self.is_user_navigation:
            return
        if success:
            self.statusBar().showMessage(f"页面加载完成: {url}")
            from PyQt6.QtCore import QTimer
            QTimer.singleShot(500, self.run_passive_analysis)
        else:
            self.statusBar().showMessage(f"页面加载失败: {url}")

    def run_passive_analysis(self):
        if not self.is_user_navigation:
            return
        url = self.url_input.text().strip()
        if not url:
            return
        self.statusBar().showMessage("正在运行被动分析...")
        self.web_view.page().toHtml(self._on_html_ready)

    def _on_html_ready(self, html):
        if not self.is_user_navigation:
            return
        self._last_html = html  # 保存HTML供主动扫描使用
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
        # 如果完整审计在等待，现在启动主动扫描
        if getattr(self, '_pending_full_scan', False):
            self._pending_full_scan = False
            self.start_active_scan()

    def _refresh_passive_ui(self):
        tmp_r = self.current_passive_report
        if not tmp_r:
            return
        t = f"<b>URL:</b> {tmp_r.url}<br><b>协议:</b> {tmp_r.url_info.protocol}<br>"
        t += f"<b>域名:</b> {tmp_r.url_info.domain}<br>"
        t += f"<b>HTTPS:</b> {'是' if tmp_r.url_info.is_https else '否'}<br>"
        t += f"<b>IP地址:</b> {'是' if tmp_r.url_info.is_ip else '否'}<br>"
        if tmp_r.url_info.suspicious_params:
            t += f"<b>可疑参数:</b> {', '.join(tmp_r.url_info.suspicious_params)}"
        self.passive_url_text.setHtml(t)

        ft = ""
        for i, f in enumerate(tmp_r.forms, 1):
            ft += f"<b>表单 {i}:</b> Action={f.action} Method={f.method} 密码字段={'有' if f.has_password else '无'}<br>"
        self.passive_form_text.setHtml(ft or "未发现表单")

        jt = ""
        for s in tmp_r.scripts:
            jt += f"<b>脚本:</b> {s.src or '内联'}"
            if s.uses_eval:
                jt += " [eval]"
            jt += "<br>"
        self.passive_js_text.setHtml(jt or "未发现JS")

        ht = ""
        for k, v in tmp_r.security_headers.items():
            ht += f"<b>{k}:</b> {v or '未设置'}<br>"
        self.passive_header_text.setHtml(ht or "无头部信息")

    def _refresh_quick_ui(self):
        tmp_r = self.current_passive_report
        if not tmp_r:
            return
        self.url_status_label.setText(
            f"URL状态: {'安全' if tmp_r.url_info.is_https else '不安全'}\n风险等级: {tmp_r.risk_level}")

        colors = {"安全": "green", "低危": "lightgreen", "中危": "orange", "高危": "red", "严重": "darkred"}
        c = colors.get(tmp_r.risk_level, "black")
        self.risk_score_label.setText(f"风险等级: {tmp_r.risk_level}")
        self.risk_score_label.setStyleSheet(f"font-size:18px;font-weight:bold;color:{c};")
        self.risk_progress.setValue(tmp_r.risk_score)

        self.issues_list.clear()
        for iss in tmp_r.issues:
            self.issues_list.addItem(iss)
        if not tmp_r.issues:
            self.issues_list.addItem("未发现明显问题")

    def run_quick_scan(self):
        self.statusBar().showMessage("快速扫描中...")
        self.run_passive_analysis()

    def run_full_scan(self):
        self.statusBar().showMessage("完整审计中...")
        self.run_passive_analysis()
        # 等被动分析拿到HTML后再启动主动扫描
        self._pending_full_scan = True

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

        # 如果有当前页面的HTML，传给扫描器用于提取表单参数
        html = getattr(self, '_last_html', None)
        self._scan_thread = ScanThread(self.active_scanner, url, st, html)
        self._scan_thread.progress.connect(self._on_scan_progress)
        self._scan_thread.finished.connect(self._on_scan_done)
        self._scan_thread.error.connect(self._on_scan_err)
        self._scan_thread.start()

    def _on_scan_progress(self, msg, pct):
        self.scan_progress_bar.setValue(pct)
        self.scan_status_label.setText(msg)
        self.statusBar().showMessage(msg)

    def _on_scan_done(self, rpt):
        tmp_r = rpt
        self.current_active_report = tmp_r
        self.start_scan_btn.setEnabled(True)
        self.stop_scan_btn.setEnabled(False)
        self.scan_progress_bar.setValue(100)
        self.scan_status_label.setText("扫描完成")
        self.statusBar().showMessage("主动扫描完成")
        self._refresh_scan_ui()
        self._refresh_owasp_ui()

    def _on_scan_err(self, err):
        self.start_scan_btn.setEnabled(True)
        self.stop_scan_btn.setEnabled(False)
        self.scan_status_label.setText(f"扫描失败: {err}")

    def stop_active_scan(self):
        self.active_scanner.stop_scan()
        self.start_scan_btn.setEnabled(True)
        self.stop_scan_btn.setEnabled(False)
        self.scan_status_label.setText("已停止")

    def _refresh_scan_ui(self):
        tmp_r = self.current_active_report
        if not tmp_r:
            return
        h = f"<h3>扫描结果</h3>"
        h += f"<p><b>目标:</b> {tmp_r.url}</p>"
        h += f"<p><b>耗时:</b> {tmp_r.scan_time:.2f}s &nbsp; <b>请求:</b> {tmp_r.cnt}次 &nbsp; <b>漏洞:</b> {len(tmp_r.vulnerabilities)}个</p>"
        h += f"<p><b>风险等级:</b> <span style='color:red;'>{tmp_r.risk_level}</span></p><hr><h4>漏洞详情:</h4>"
        sev_clr = {"严重": "darkred", "高危": "red", "中危": "orange", "低危": "yellow"}
        for v in tmp_r.vulnerabilities:
            clr = sev_clr.get(v.severity, "black")
            h += f"<div style='background:#f5f5f5;padding:10px;margin:5px 0;border-left:4px solid {clr};'>"
            h += f"<b>[{v.severity}] {v.name}</b><br>类型: {v.vuln_type}<br>位置: {v.location}<br>描述: {v.description}<br>修复: {v.remediation}</div>"
        if not tmp_r.vulnerabilities:
            h += "<p style='color:green;'>未发现漏洞</p>"
        self.active_result_text.setHtml(h)

    def _refresh_owasp_ui(self):
        tmp_r = self.current_active_report
        if not tmp_r:
            return
        vt = {}
        for v in tmp_r.vulnerabilities:
            vt.setdefault(v.owasp_category, []).append(v)

        owasp_map = {
            "A01:2021": "访问控制失效", "A02:2021": "加密失败", "A03:2021": "注入攻击",
            "A04:2021": "不安全设计", "A05:2021": "安全配置错误", "A06:2021": "脆弱和过时的组件",
            "A07:2021": "身份识别和身份验证失败", "A08:2021": "软件和数据完整性失败",
            "A09:2021": "安全日志和监控失败", "A10:2021": "服务器端请求伪造(SSRF)"
        }
        ot = "<h3>OWASP Top 10 (2021) 检测结果</h3><table style='width:100%;'>"
        for code, name in owasp_map.items():
            if code in vt:
                ot += f"<tr><td><b>{code}</b> {name}</td><td><span style='color:red;'>发现 {len(vt[code])} 个</span></td></tr>"
            else:
                ot += f"<tr><td><b>{code}</b> {name}</td><td><span style='color:green;'>通过</span></td></tr>"
        ot += "</table>"
        self.owasp_overview_text.setHtml(ot)

        ft = ""
        for code, vulns in vt.items():
            ft += f"<h4>{code}</h4>"
            for v in vulns:
                ft += f"<p><b>{v.name}</b><br>位置: {v.location}<br>描述: {v.description}</p>"
        self.owasp_findings_text.setHtml(ft or "<p style='color:green;'>未发现OWASP漏洞</p>")

        recs = list(set(v.remediation for v in tmp_r.vulnerabilities))
        rt = "<h4>修复建议</h4><ol>"
        for r in recs:
            rt += f"<li>{r}</li>"
        rt += "</ol>"
        self.owasp_recommendations_text.setHtml(rt or "<p style='color:green;'>安全性良好</p>")

    def export_html_report(self):
        pr = self.current_passive_report
        ar = self.current_active_report
        if not pr and not ar:
            QMessageBox.warning(self, "提示", "没有可导出的数据")
            return

        url = self.url_input.text()
        now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        fname = f"security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        fpath = os.path.join(os.path.expanduser("~"), "Desktop", fname)

        # 样式块 - 可抽离到外部css
        css_block = """
<style>
body{font-family:sans-serif;max-width:900px;margin:0 auto;padding:20px;}
table{border-collapse:collapse;width:100%;}
th,td{border:1px solid #ddd;padding:8px;text-align:left;}
th{background:#f5f5f5;}
.sev-critical{color:darkred;}
.sev-high{color:red;}
.sev-medium{color:orange;}
.sev-low{color:olive;}
.tag{display:inline-block;padding:2px 8px;border-radius:3px;font-size:12px;}
.tag-red{background:#ffebee;color:#c62828;}
.tag-green{background:#e8f5e9;color:#1b5e20;}
</style>
"""

        lines = [
            "<!DOCTYPE html><html><head><meta charset='UTF-8'>",
            "<title>Web安全审计报告</title>",
            css_block,
            "</head><body>",
            f"<h1>Web安全审计报告</h1>",
            f"<p><b>目标URL:</b> {url}</p>",
            f"<p><b>生成时间:</b> {now}</p><hr>"
        ]

        if pr:
            lines.append("<h2>一、被动分析结果</h2>")
            lines.append(f"<p><b>协议:</b> {pr.url_info.protocol} &nbsp; <b>域名:</b> {pr.url_info.domain}")
            lines.append(f"&nbsp; <b>HTTPS:</b> {'是' if pr.url_info.is_https else '否'}")
            lines.append(f"&nbsp; <b>IP地址:</b> {'是' if pr.url_info.is_ip else '否'}</p>")
            lines.append(f"<p><b>风险等级:</b> <span class='sev-high'>{pr.risk_level}</span> ({pr.risk_score}/100)</p>")

            if pr.issues:
                lines.append("<h3>发现的问题</h3><ul>")
                for iss in pr.issues:
                    lines.append(f"<li>{iss}</li>")
                lines.append("</ul>")

            if pr.vulnerabilities:
                lines.append("<h3>漏洞列表</h3><table><tr><th>类型</th><th>严重程度</th><th>位置</th><th>描述</th></tr>")
                for v in pr.vulnerabilities:
                    lines.append(f"<tr><td>{v['type']}</td><td>{v['severity']}</td><td>{v['location']}</td><td>{v['description']}</td></tr>")
                lines.append("</table>")

            if pr.forms:
                lines.append("<h3>表单信息</h3><table><tr><th>Action</th><th>Method</th><th>密码字段</th></tr>")
                for f in pr.forms:
                    lines.append(f"<tr><td>{f.action}</td><td>{f.method}</td><td>{'是' if f.has_password else '否'}</td></tr>")
                lines.append("</table>")

        if ar:
            lines.append("<h2>二、主动扫描结果</h2>")
            lines.append(f"<p><b>耗时:</b> {ar.scan_time:.2f}s &nbsp; <b>请求数:</b> {ar.cnt} &nbsp; <b>漏洞数:</b> {len(ar.vulnerabilities)}</p>")
            lines.append(f"<p><b>风险等级:</b> <span class='sev-high'>{ar.risk_level}</span></p>")

            if ar.vulnerabilities:
                lines.append("<h3>漏洞详情</h3><table><tr><th>名称</th><th>严重程度</th><th>类型</th><th>位置</th><th>描述</th><th>修复建议</th></tr>")
                for v in ar.vulnerabilities:
                    lines.append(f"<tr><td>{v.name}</td><td>{v.severity}</td><td>{v.vuln_type}</td><td>{v.location}</td><td>{v.description}</td><td>{v.remediation}</td></tr>")
                lines.append("</table>")

        lines.append("<hr><p style='color:gray;font-size:12px;'>由Web安全审计浏览器自动生成</p></body></html>")

        with open(fpath, 'w', encoding='utf-8') as f:
            f.write('\n'.join(lines))
        QMessageBox.information(self, "导出成功", f"HTML报告已保存到:\n{fpath}")

    def export_json_report(self):
        pr = self.current_passive_report
        ar = self.current_active_report
        if not pr and not ar:
            QMessageBox.warning(self, "提示", "没有可导出的数据")
            return

        url = self.url_input.text()
        data = {
            "url": url,
            "generated_at": datetime.now().isoformat(),
            "passive_analysis": None,
            "active_scan": None
        }

        if pr:
            data["passive_analysis"] = {
                "url_info": {
                    "protocol": pr.url_info.protocol,
                    "domain": pr.url_info.domain,
                    "is_https": pr.url_info.is_https,
                    "is_ip": pr.url_info.is_ip,
                    "suspicious_params": pr.url_info.suspicious_params
                },
                "risk_level": pr.risk_level,
                "risk_score": pr.risk_score,
                "issues": pr.issues,
                "vulnerabilities": pr.vulnerabilities,
                "forms": [
                    {"action": f.action, "method": f.method, "has_password": f.has_password}
                    for f in pr.forms
                ],
                "scripts": [
                    {"src": s.src, "is_external": s.is_external, "uses_eval": s.uses_eval,
                     "uses_innerhtml": s.uses_innerhtml, "uses_document_write": s.uses_document_write}
                    for s in pr.scripts
                ],
                "security_headers": pr.security_headers
            }

        if ar:
            data["active_scan"] = {
                "scan_time": ar.scan_time,
                "cnt": ar.cnt,
                "risk_level": ar.risk_level,
                "vulnerabilities": [
                    {
                        "name": v.name, "type": v.vuln_type, "severity": v.severity,
                        "location": v.location, "description": v.description,
                        "remediation": v.remediation, "owasp_category": v.owasp_category,
                        "evidence": v.evidence
                    }
                    for v in ar.vulnerabilities
                ]
            }

        fname = f"security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        fpath = os.path.join(os.path.expanduser("~"), "Desktop", fname)
        with open(fpath, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        QMessageBox.information(self, "导出成功", f"JSON报告已保存到:\n{fpath}")


def main():
    app = QApplication(sys.argv)
    app.setStyle('Fusion')
    win = BrowserGUI()
    win.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    _root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if _root not in sys.path:
        sys.path.insert(0, _root)
    main()
