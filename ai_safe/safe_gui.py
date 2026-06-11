import sys
import json
from pathlib import Path
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QPushButton, QTextEdit, QProgressBar, QFileDialog,
    QMessageBox, QFrame, QSplitter, QListWidget, QListWidgetItem,
    QInputDialog, QTabWidget
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QFont, QDragEnterEvent, QDropEvent

from core.ai_interface import create_ai_manager
from ai_safe.safe_scan import FileAnalyzer


class ScanWorker(QThread):
    """后台扫描线程 - 支持单文件和文件夹"""
    sig_prog = pyqtSignal(str, int, int)  # 消息, 当前, 总数
    sig_res = pyqtSignal(dict)
    sig_err = pyqtSignal(str)
    sig_skip = pyqtSignal(str)
    sig_finished = pyqtSignal(list)

    def __init__(self, path, mgr, analyzer):
        super().__init__()
        self.path = Path(path)
        self.mgr = mgr
        self.analyzer = analyzer
        self._stop = False

    def stop(self):
        self._stop = True

    def run(self):
        try:
            # 是文件夹：调用scan_folder
            if self.path.is_dir():
                results = []
                files = []
                extensions = ['.exe', '.dll', '.sys', '.scr', '.bat', '.cmd',
                              '.ps1', '.vbs', '.js', '.jar', '.py']
                for ext in extensions:
                    files.extend(self.path.rglob(f"*{ext}"))
                # 也收集无扩展名文件
                try:
                    for fp in self.path.rglob("*"):
                        if fp.is_file() and not fp.suffix and not fp.name.startswith('.'):
                            if not any(fp.name == f.name for f in files):
                                files.append(fp)
                except Exception:
                    pass
                total = len(files)
                self.sig_prog.emit(f"共找到 {total} 个文件", 0, total)

                for idx, fp in enumerate(files):
                    if self._stop:
                        break

                    # 先检查白名单
                    is_white, reason = self.analyzer.is_whitelisted(fp)
                    if is_white:
                        self.sig_skip.emit(f"⏭ 跳过 (白名单): {fp.name} - {reason}")
                        continue

                    try:
                        res = self.analyzer.analyze_file(str(fp))
                        results.append({"path": str(fp), "result": res})
                        self.sig_prog.emit(f"正在分析: {fp.name}", idx + 1, total)

                        # 如果有AI管理器，做AI分析
                        if self.mgr and "error" not in res and "whitelisted" not in res:
                            matches = res.get("rule_matches", [])
                            if matches:  # 只有匹配到规则才调用AI
                                self.sig_prog.emit(f"AI分析中: {fp.name}", idx + 1, total)
                                text = self.analyzer.fmt4ai(res)
                                try:
                                    ai_res = self.mgr.analyze("", text)
                                    res["ai_analysis"] = ai_res
                                except Exception:
                                    pass

                        self.sig_res.emit({"path": str(fp), "result": res})

                    except Exception as e:
                        self.sig_err.emit(f"分析 {fp.name} 出错: {str(e)}")

                self.sig_finished.emit(results)

            # 是文件：analyze_file
            else:
                # 检查白名单
                is_white, reason = self.analyzer.is_whitelisted(self.path)
                if is_white:
                    self.sig_skip.emit(f"⏭ 白名单: {reason}")
                    self.sig_finished.emit([])
                    return

                self.sig_prog.emit(f"分析文件: {self.path.name}", 1, 1)
                res = self.analyzer.analyze_file(str(self.path))

                if "error" in res:
                    self.sig_err.emit(res["error"])
                    return

                if res.get("whitelisted"):
                    self.sig_skip.emit(f"⏭ 白名单: {res.get('reason', 'N/A')}")
                    self.sig_finished.emit([])
                    return

                results = [{"path": str(self.path), "result": res}]

                # AI分析（如果有规则匹配才调用）
                matches = res.get("rule_matches", [])
                if self.mgr and matches:
                    self.sig_prog.emit("AI分析中...", 1, 1)
                    text = self.analyzer.fmt4ai(res)
                    try:
                        ai_res = self.mgr.analyze("", text)
                        res["ai_analysis"] = ai_res
                    except Exception:
                        pass

                self.sig_res.emit({"path": str(self.path), "result": res})
                self.sig_finished.emit(results)

        except Exception as e:
            self.sig_err.emit(f"扫描出错: {str(e)}")


class DropBox(QFrame):
    """拖入区域 - 支持文件夹和文件"""
    dropped = pyqtSignal(str)

    def __init__(self):
        super().__init__()
        self.setAcceptDrops(True)
        self.setMinimumHeight(200)
        self.setFrameStyle(QFrame.Shape.StyledPanel | QFrame.Shadow.Sunken)
        self.setStyleSheet("""
            DropBox {
                background-color: #f8f9fa;
                border: 3px dashed #6c757d;
                border-radius: 10px;
            }
            DropBox[active="true"] {
                background-color: #e3f2fd;
                border: 3px dashed #2196F3;
            }
            QLabel {
                color: #495057;
                font-family: "Microsoft YaHei";
                font-size: 14px;
            }
        """)
        ly = QVBoxLayout(self)
        ly.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self.lab = QLabel("📁 拖入文件夹进行批量扫描\n或\n拖入单个文件分析")
        self.lab.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.lab.setWordWrap(True)
        ly.addWidget(self.lab)

        btn_ly = QHBoxLayout()
        self.btn_sel_file = QPushButton("选择文件")
        self.btn_sel_file.setFont(QFont("Microsoft YaHei", 10))
        self.btn_sel_file.setStyleSheet("""
            QPushButton {
                background-color: #2196F3;
                color: white;
                border: none;
                padding: 10px 24px;
                border-radius: 5px;
                font-size: 14px;
            }
            QPushButton:hover { background-color: #1976D2; }
        """)
        self.btn_sel_file.clicked.connect(self.sel_file)

        self.btn_sel_dir = QPushButton("选择文件夹")
        self.btn_sel_dir.setFont(QFont("Microsoft YaHei", 10))
        self.btn_sel_dir.setStyleSheet("""
            QPushButton {
                background-color: #4CAF50;
                color: white;
                border: none;
                padding: 10px 24px;
                border-radius: 5px;
                font-size: 14px;
            }
            QPushButton:hover { background-color: #388E3C; }
        """)
        self.btn_sel_dir.clicked.connect(self.sel_folder)

        btn_ly.addWidget(self.btn_sel_file)
        btn_ly.addWidget(self.btn_sel_dir)
        ly.addLayout(btn_ly)

    def dragEnterEvent(self, event: QDragEnterEvent):
        if event.mimeData().hasUrls():
            self.setProperty("active", "true")
            self.style().unpolish(self)
            self.style().polish(self)
            event.acceptProposedAction()

    def dragLeaveEvent(self, event):
        self.setProperty("active", "false")
        self.style().unpolish(self)
        self.style().polish(self)

    def dropEvent(self, event: QDropEvent):
        self.setProperty("active", "false")
        self.style().unpolish(self)
        self.style().polish(self)
        urls = event.mimeData().urls()
        if urls:
            fp = urls[0].toLocalFile()
            self.dropped.emit(fp)

    def sel_file(self):
        fp, _ = QFileDialog.getOpenFileName(
            self, "选择文件", "",
            "可执行文件 (*.exe *.dll *.sys *.scr);;脚本 (*.bat *.cmd *.ps1 *.vbs *.js *.py);;所有文件 (*.*)")
        if fp:
            self.dropped.emit(fp)

    def sel_folder(self):
        folder = QFileDialog.getExistingDirectory(
            self, "选择文件夹", "")
        if folder:
            self.dropped.emit(folder)


class ResultPanel(QWidget):
    """结果面板 - 包含列表和详情"""
    def __init__(self):
        super().__init__()
        self._current_results = []
        self._init_ui()

    def _init_ui(self):
        ly = QVBoxLayout(self)

        # 状态框
        self.status_frame = QFrame()
        self.status_frame.setStyleSheet("""
            QFrame {
                background-color: #f8f9fa;
                border-radius: 8px;
                padding: 8px;
            }
        """)
        sf = QHBoxLayout(self.status_frame)

        self.rl = QLabel("等待扫描...")
        self.rl.setFont(QFont("Microsoft YaHei", 14, QFont.Weight.Bold))
        self.rl.setAlignment(Qt.AlignmentFlag.AlignLeft)
        sf.addWidget(self.rl)

        self.summary = QLabel("")
        self.summary.setFont(QFont("Microsoft YaHei", 10))
        self.summary.setAlignment(Qt.AlignmentFlag.AlignRight)
        sf.addWidget(self.summary)

        ly.addWidget(self.status_frame)

        # 标签页 - 结果列表 + 详情
        tab_widget = QTabWidget()

        # 扫描结果列表
        list_widget = QWidget()
        list_layout = QVBoxLayout(list_widget)

        list_layout.addWidget(QLabel("📋 扫描结果列表:"))
        self.result_list = QListWidget()
        self.result_list.setFont(QFont("Microsoft YaHei", 9))
        self.result_list.itemClicked.connect(self._on_item_clicked)
        self.result_list.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.result_list.customContextMenuRequested.connect(self._on_context_menu)
        list_layout.addWidget(self.result_list)

        # 快捷操作
        action_layout = QHBoxLayout()
        self.btn_add_to_whitelist = QPushButton("🔒 将选中项加入白名单")
        self.btn_add_to_whitelist.setStyleSheet("""
            QPushButton {
                background-color: #ff9800;
                color: white;
                padding: 6px 12px;
                border-radius: 4px;
                border: none;
            }
            QPushButton:hover { background-color: #f57c00; }
        """)
        self.btn_add_to_whitelist.clicked.connect(self._add_to_whitelist)
        action_layout.addWidget(self.btn_add_to_whitelist)
        action_layout.addStretch()
        list_layout.addLayout(action_layout)

        tab_widget.addTab(list_widget, "扫描结果")

        # 详情面板
        detail_widget = QWidget()
        detail_layout = QVBoxLayout(detail_widget)

        detail_layout.addWidget(QLabel("📝 详细信息:"))
        self.detail_box = QTextEdit()
        self.detail_box.setReadOnly(True)
        self.detail_box.setFont(QFont("Consolas", 9))
        detail_layout.addWidget(self.detail_box)

        tab_widget.addTab(detail_widget, "详细信息")

        # 日志面板
        log_widget = QWidget()
        log_layout = QVBoxLayout(log_widget)
        log_layout.addWidget(QLabel("📜 扫描日志:"))
        self.log_box = QTextEdit()
        self.log_box.setReadOnly(True)
        self.log_box.setFont(QFont("Consolas", 9))
        log_layout.addWidget(self.log_box)

        tab_widget.addTab(log_widget, "扫描日志")

        ly.addWidget(tab_widget, stretch=1)

    def clear_results(self):
        self.result_list.clear()
        self.detail_box.clear()
        self.log_box.clear()
        self._current_results = []
        self.rl.setText("等待扫描...")
        self.rl.setStyleSheet("color: #495057; font-size: 14px; font-weight: bold;")
        self.summary.setText("")

    def add_result(self, item: dict):
        self._current_results.append(item)
        path = item.get("path", "未知")
        res = item.get("result", {})

        # 计算风险等级
        risk_level = "安全"
        icon = "✅"
        color = "#4caf50"

        if res.get("whitelisted"):
            risk_level = "白名单"
            icon = "🔒"
            color = "#9c27b0"
        elif "error" in res:
            risk_level = "错误"
            icon = "❌"
            color = "#f44336"
        else:
            rules = res.get("rule_matches", [])
            api_count = len(res.get("suspicious_apis", []))
            risks = res.get("risk_indicators", [])
            if len(rules) >= 2 or any(
                    r.get("severity") == "critical" for r in rules):
                risk_level = "高危"
                icon = "🔴"
                color = "#d32f2f"
            elif rules or len(risks) >= 2:
                risk_level = "中危"
                icon = "🟡"
                color = "#ff9800"
            elif api_count > 3:
                risk_level = "低风险"
                icon = "🟢"
                color = "#4caf50"

        # 构造列表项
        filename = Path(path).name
        display_text = f"{icon} [{risk_level}] {filename}"
        list_item = QListWidgetItem(display_text)
        list_item.setForeground(Qt.GlobalColor.fromString(color) if color != "#ff9800"
                                 else Qt.GlobalColor.darkYellow)
        list_item.setData(Qt.ItemDataRole.UserRole, path)
        self.result_list.addItem(list_item)

        # 更新状态
        total = len(self._current_results)
        risks_count = sum(1 for r in self._current_results
                          if not r.get("result", {}).get("whitelisted")
                          and r.get("result", {}).get("rule_matches", []))
        self.summary.setText(f"已扫描: {total} | 可疑: {risks_count}")

    def _on_item_clicked(self, item):
        """点击显示详情"""
        idx = self.result_list.row(item)
        if 0 <= idx < len(self._current_results):
            self._show_detail(self._current_results[idx])

    def _show_detail(self, item: dict):
        """显示详细信息"""
        path = item.get("path", "未知")
        res = item.get("result", {})

        if res.get("whitelisted"):
            self.detail_box.setText(
                f"文件: {path}\n\n"
                f"⚠️ 该文件已加入白名单，被跳过扫描\n"
                f"原因: {res.get('reason', 'N/A')}"
            )
            return

        if "error" in res:
            self.detail_box.setText(
                f"文件: {path}\n\n"
                f"❌ 错误: {res['error']}"
            )
            return

        # 文件信息
        fi = res.get("file_info", {})
        text = "=" * 60 + "\n"
        text += "📁 文件信息\n"
        text += "=" * 60 + "\n"
        text += f"文件名: {fi.get('file_name', 'N/A')}\n"
        text += f"大小: {fi.get('file_size', 0)} bytes\n"
        text += f"路径: {fi.get('file_path', 'N/A')}\n"
        hashes = fi.get("hashes", {})
        text += f"MD5: {hashes.get('md5', 'N/A')[:32]}\n"
        text += f"SHA256: {hashes.get('sha256', 'N/A')[:32]}\n"
        text += f"熵值: {res.get('entropy', 0)}\n\n"

        # 恶意规则匹配
        rules = res.get("rule_matches", [])
        if rules:
            text += "=" * 60 + "\n"
            text += "🚨 恶意规则匹配\n"
            text += "=" * 60 + "\n"
            for r in rules:
                text += f"  [{r['severity'].upper()}] {r['name']}\n"
                text += f"    {r['description']}\n\n"

        # 风险指标
        risks = res.get("risk_indicators", [])
        if risks:
            text += "=" * 60 + "\n"
            text += "⚠️ 风险指标\n"
            text += "=" * 60 + "\n"
            for r in risks:
                text += f"  - {r}\n"
            text += "\n"

        # API
        apis = res.get("suspicious_apis", [])
        if apis:
            text += "=" * 60 + "\n"
            text += f"🔍 可疑API调用 ({len(apis)}个)\n"
            text += "=" * 60 + "\n"
            for a in apis[:15]:
                text += f"  - {a['api']}: {a['ctx']}\n"
            text += "\n"

        # 模式匹配
        pats = res.get("suspicious_patterns", [])
        if pats:
            text += "=" * 60 + "\n"
            text += f"📜 可疑字符串 ({len(pats)}处)\n"
            text += "=" * 60 + "\n"
            for p in pats[:10]:
                text += f"  - {p['match']}\n"
            text += "\n"

        # PE信息
        pe = res.get("pe_info", {})
        if pe.get("is_pe"):
            text += "=" * 60 + "\n"
            text += "💿 PE文件信息\n"
            text += "=" * 60 + "\n"
            text += f"类型: {'DLL' if pe.get('is_dll') else 'EXE'}\n"
            text += f"位数: {'64' if pe.get('is_64') else '32'}\n"
            text += f"入口: {pe.get('entry', 'N/A')}\n"
            text += f"镜像基址: {pe.get('base', 'N/A')}\n"
            if pe.get("bad_secs"):
                text += f"可疑节区: {', '.join(pe['bad_secs'])}\n"
            if pe.get("err"):
                text += f"解析错误: {pe['err']}\n"
            text += "\n"

        # AI分析结果
        if "ai_analysis" in res:
            text += "=" * 60 + "\n"
            text += "🤖 AI分析结果\n"
            text += "=" * 60 + "\n"
            ai = res["ai_analysis"]
            if isinstance(ai, dict):
                text += f"风险评分: {ai.get('risk_score', 'N/A')}\n"
                text += f"是否恶意: {'是' if ai.get('is_malicious') else '否'}\n"
                text += f"威胁类型: {ai.get('threat_type', '未知')}\n"
                text += f"风险等级: {ai.get('risk_level', '未知')}\n"
                if ai.get("indicators"):
                    text += f"\n关键指标:\n"
                    for ind in ai.get("indicators", []):
                        text += f"  - {ind}\n"
                if ai.get("recommendation"):
                    text += f"\n建议: {ai['recommendation']}\n"
            else:
                text += str(ai)

        self.detail_box.setText(text)

    def _on_context_menu(self, pos):
        """右键菜单"""
        item = self.result_list.itemAt(pos)
        if item:
            self._add_to_whitelist()

    def _add_to_whitelist(self):
        """将选中项加入白名单"""
        item = self.result_list.currentItem()
        if not item:
            QMessageBox.information(self, "提示", "请先选择要加入白名单的文件")
            return

        idx = self.result_list.currentRow()
        if 0 <= idx < len(self._current_results):
            path = self._current_results[idx].get("path", "")
            if not path:
                return

            # 让用户选择白名单类型
            options = ["按路径加入", "按文件名加入", "按哈希加入"]
            choice, ok = QInputDialog.getItem(
                self, "加入白名单", f"选择方式加入 {Path(path).name}:",
                options, 0, False)
            if not ok:
                return

            # 这里通过主窗口的analyzer加入
            if hasattr(self, '_analyzer') and self._analyzer:
                if choice == "按路径加入":
                    self._analyzer.add_whitelist_path(path)
                    QMessageBox.information(self, "成功", f"已按路径加入白名单")
                elif choice == "按文件名加入":
                    self._analyzer.add_whitelist_name(Path(path).name)
                    QMessageBox.information(self, "成功", f"已按文件名加入白名单")
                elif choice == "按哈希加入":
                    # 需要哈希值
                    text, ok2 = QInputDialog.getText(
                        self, "哈希白名单", "输入文件MD5或SHA256哈希:")
                    if ok2 and text:
                        self._analyzer.add_whitelist_hash(text)
                        QMessageBox.information(self, "成功", "已按哈希加入白名单")

    def set_analyzer(self, analyzer):
        """设置analyzer引用，用于白名单操作"""
        self._analyzer = analyzer


class MainWin(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("🛡️ AI-Safe 病毒查杀工具")
        self.setMinimumSize(900, 700)
        self.mgr = None
        self.analyzer = None
        self.wk = None
        self._init_ui()
        self._init_core()

    def _init_ui(self):
        cw = QWidget()
        self.setCentralWidget(cw)

        mly = QVBoxLayout(cw)
        mly.setSpacing(10)
        mly.setContentsMargins(15, 15, 15, 15)

        # 标题
        tl = QLabel("🛡️ AI-Safe - 人工智能病毒查杀")
        tl.setFont(QFont("Microsoft YaHei", 20, QFont.Weight.Bold))
        tl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        tl.setStyleSheet("color: #1976D2; margin: 5px;")
        mly.addWidget(tl)

        # 说明
        st = QLabel("拖入文件夹进行批量扫描 | 拖入文件进行单文件分析 | 扫描结果可加入白名单")
        st.setFont(QFont("Microsoft YaHei", 10))
        st.setAlignment(Qt.AlignmentFlag.AlignCenter)
        st.setStyleSheet("color: #666;")
        mly.addWidget(st)

        # 状态显示
        self.status = QLabel("初始化...")
        self.status.setFont(QFont("Microsoft YaHei", 10))
        self.status.setStyleSheet("color: #666; padding: 5px;")
        mly.addWidget(self.status)

        # 进度条
        self.pb = QProgressBar()
        self.pb.setVisible(False)
        self.pb.setFormat("扫描中... %v/%m")
        mly.addWidget(self.pb)

        # 主区域 - 分隔器
        sp = QSplitter(Qt.Orientation.Vertical)
        self.box = DropBox()
        self.box.dropped.connect(self.start_scan)
        sp.addWidget(self.box)

        self.panel = ResultPanel()
        sp.addWidget(self.panel)
        sp.setSizes([220, 450])
        mly.addWidget(sp, stretch=1)

        # 底部按钮
        bly = QHBoxLayout()

        self.btn_stop = QPushButton("⏹ 停止扫描")
        self.btn_stop.setFont(QFont("Microsoft YaHei", 10))
        self.btn_stop.setStyleSheet("""
            QPushButton {
                background-color: #f44336;
                color: white;
                border: none;
                padding: 8px 16px;
                border-radius: 5px;
            }
            QPushButton:hover { background-color: #d32f2f; }
            QPushButton:disabled { background-color: #ccc; }
        """)
        self.btn_stop.setVisible(False)
        self.btn_stop.clicked.connect(self._stop_scan)
        bly.addWidget(self.btn_stop)

        self.btn_clear = QPushButton("🗑️ 清除结果")
        self.btn_clear.setFont(QFont("Microsoft YaHei", 10))
        self.btn_clear.setStyleSheet("""
            QPushButton {
                background-color: #9e9e9e;
                color: white;
                border: none;
                padding: 8px 16px;
                border-radius: 5px;
            }
            QPushButton:hover { background-color: #757575; }
        """)
        self.btn_clear.clicked.connect(self._clear_results)
        bly.addWidget(self.btn_clear)

        bly.addStretch()

        self.btn_about = QPushButton("ℹ️ 关于")
        self.btn_about.setFont(QFont("Microsoft YaHei", 10))
        self.btn_about.setStyleSheet("""
            QPushButton {
                background-color: #2196F3;
                color: white;
                border: none;
                padding: 8px 16px;
                border-radius: 5px;
            }
            QPushButton:hover { background-color: #1976D2; }
        """)
        self.btn_about.clicked.connect(self._show_about)
        bly.addWidget(self.btn_about)

        mly.addLayout(bly)

    def _init_core(self):
        try:
            cfg_p = Path(__file__).parent.parent / 'cfg.yaml'
            import yaml
            with open(cfg_p, 'r', encoding='utf-8') as f:
                cfg = yaml.safe_load(f)

            # AI管理器
            self.mgr = create_ai_manager(str(cfg_p))
            h = self.mgr.check_health()

            # 文件分析器
            av = cfg.get('av', {})
            self.analyzer = FileAnalyzer(
                max_file_size=av.get('max_size', 104857600),
                max_strings=av.get('code_extract', {}).get('max_str', 1000)
            )

            # 设置面板的analyzer引用（用于白名单）
            self.panel.set_analyzer(self.analyzer)

            if h["status"] == "healthy":
                model_info = h.get('model', 'unknown')
                self.status.setText(
                    f"✅ 就绪 | AI: {model_info} | 白名单: {self.analyzer.get_whitelist_info()}")
                self.status.setStyleSheet("color: #4caf50; padding: 5px;")
            else:
                self.status.setText("⚠️ AI未就绪 - 基础扫描可用")
                self.status.setStyleSheet("color: #ff9800; padding: 5px;")

        except Exception as e:
            self.status.setText(f"⚠️ 初始化警告: {str(e)} - 基础扫描可用")
            self.status.setStyleSheet("color: #ff9800; padding: 5px;")
            # 仍然创建基础扫描器
            self.analyzer = FileAnalyzer()
            self.panel.set_analyzer(self.analyzer)

    def start_scan(self, fp: str):
        if not self.analyzer:
            QMessageBox.warning(self, "错误", "核心模块未初始化")
            return

        p = Path(fp)
        if not p.exists():
            QMessageBox.warning(self, "错误", f"路径不存在: {fp}")
            return

        # 更新提示
        if p.is_dir():
            self.box.lab.setText(f"📁 正在扫描文件夹:\n{p.name}")
        else:
            self.box.lab.setText(f"📄 正在分析文件:\n{p.name}")

        # 清空旧结果
        self.panel.clear_results()

        # 进度条
        self.pb.setVisible(True)
        self.pb.setRange(0, 0)
        self.btn_stop.setVisible(True)

        # 启动扫描线程
        self.wk = ScanWorker(fp, self.mgr, self.analyzer)
        self.wk.sig_prog.connect(self._on_progress)
        self.wk.sig_res.connect(self._on_result)
        self.wk.sig_err.connect(self._on_error)
        self.wk.sig_skip.connect(self._on_skip)
        self.wk.sig_finished.connect(self._on_finished)
        self.wk.start()

    def _on_progress(self, msg: str, current: int, total: int):
        self.status.setText(f"⏳ {msg} ({current}/{total})")
        self.status.setStyleSheet("color: #2196F3; padding: 5px;")
        if total > 0:
            self.pb.setMaximum(total)
            self.pb.setValue(current)

    def _on_result(self, item: dict):
        self.panel.add_result(item)

    def _on_error(self, err: str):
        self.panel.log_box.append(f"❌ 错误: {err}")

    def _on_skip(self, msg: str):
        self.panel.log_box.append(msg)

    def _on_finished(self, results: list):
        self.pb.setVisible(False)
        self.btn_stop.setVisible(False)
        self.box.lab.setText("📁 拖入文件夹进行批量扫描\n或\n拖入单个文件分析")

        total = len(results)
        matched = sum(1 for r in results
                      if r.get("result", {}).get("rule_matches", []))
        safe_count = sum(1 for r in results
                         if not r.get("result", {}).get("rule_matches", [])
                         and "error" not in r.get("result", {}))

        if total == 0:
            self.status.setText("✅ 扫描完成 - 未发现可疑文件")
        else:
            self.status.setText(
                f"✅ 扫描完成 | 共 {total} 个文件 | 可疑: {matched} | 安全: {safe_count}")
        self.status.setStyleSheet("color: #4caf50; padding: 5px;")

        self.panel.rl.setText("✅ 扫描完成")
        self.panel.rl.setStyleSheet("color: #4caf50; font-size: 14px; font-weight: bold;")
        self.panel.summary.setText(f"总计: {total} | 可疑: {matched} | 安全: {safe_count}")

        if total > 0:
            self.panel.log_box.append(
                f"\n{'='*60}\n扫描完成! 总计: {total} 可疑: {matched} 安全: {safe_count}")

    def _stop_scan(self):
        if self.wk and self.wk.isRunning():
            self.wk.stop()
            self.wk.wait()
            self.status.setText("⏹ 已停止扫描")
            self.status.setStyleSheet("color: #f44336; padding: 5px;")
            self.pb.setVisible(False)
            self.btn_stop.setVisible(False)
            self.box.lab.setText("📁 拖入文件夹进行批量扫描\n或\n拖入单个文件分析")

    def _clear_results(self):
        self.panel.clear_results()
        self.status.setText("✅ 就绪")
        self.status.setStyleSheet("color: #4caf50; padding: 5px;")

    def _show_about(self):
        QMessageBox.about(
            self, "关于 AI-Safe",
            "<h2>🛡️ AI-Safe v2.0</h2>"
            "<p><b>人工智能病毒查杀工具</b></p>"
            "<ul style='text-align: left;'>"
            "<li>📁 支持文件夹批量扫描</li>"
            "<li>📄 支持单文件深度分析</li>"
            "<li>🔒 智能白名单管理（路径/哈希/文件名）</li>"
            "<li>🧠 基于本地LLM的AI威胁评估</li>"
            "<li>📊 PE文件结构 / 字符串 / 恶意规则多维度分析</li>"
            "</ul>"
            "<p><small>Python + PyQt6 + Ollama</small></p>"
        )

    def closeEvent(self, event):
        if self.wk and self.wk.isRunning():
            self.wk.stop()
            self.wk.wait()
        event.accept()


def main():
    app = QApplication(sys.argv)
    app.setStyle('Fusion')
    app.setFont(QFont("Microsoft YaHei", 9))
    w = MainWin()
    w.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
