import sys
import json
from pathlib import Path
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QPushButton, QTextEdit, QProgressBar, QFileDialog,
    QMessageBox, QFrame, QScrollArea, QSplitter
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QFont, QDragEnterEvent, QDropEvent

from core.ai_interface import create_ai_manager
from ai_safe.safe_scan import FileAnalyzer


class Worker(QThread):
    """后台干活"""
    sig_prog = pyqtSignal(str)
    sig_res = pyqtSignal(dict)
    sig_err = pyqtSignal(str)

    def __init__(self, fp, mgr, analyzer):
        super().__init__()
        self.fp = fp
        self.mgr = mgr
        self.analyzer = analyzer

    def run(self):
        try:
            self.sig_prog.emit("提取特征...")
            res = self.analyzer.analyze_file(self.fp)

            if "error" in res:
                self.sig_err.emit(res["error"])
                return

            matches = res.get("rule_matches", [])

            self.sig_prog.emit("AI分析中...")
            txt = self.analyzer.fmt4ai(res)

            import yaml
            try:
                cfg_p = Path(__file__).parent.parent / 'cfg.yaml'
                with open(cfg_p, 'r', encoding='utf-8') as f:
                    cfg = yaml.safe_load(f)
                prompt = cfg.get('av', {}).get('prompt', '')
            except:
                prompt = "出现联网、注册表、文件操作即为恶意，0~100打分，严格高分，仅JSON"

            ai_res = self.mgr.analyze(prompt, txt)

            # 没判类型，字符串进来直接炸
            final = {
                "finfo": res.get("file_info", {}),
                "ai": ai_res,
                "static": {
                    "ent": res.get("entropy", 0),
                    "api_cnt": len(res.get("suspicious_apis", [])),
                    "pat_cnt": len(res.get("suspicious_patterns", [])),
                    "risks": res.get("risk_indicators", []),
                    "rules": matches
                }
            }
            self.sig_res.emit(final)

        except Exception as e:
            self.sig_err.emit(f"出错: {str(e)}")


class DropBox(QFrame):
    dropped = pyqtSignal(str)

    def __init__(self):
        super().__init__()
        self.setAcceptDrops(True)
        self.setMinimumHeight(180)
        self.setFrameStyle(QFrame.Shape.StyledPanel | QFrame.Shadow.Sunken)
        self.setStyleSheet("""
            DropBox {
                background-color: #f0f0f0;
                border: 3px dashed #999;
                border-radius: 10px;
            }
            DropBox[active="true"] {
                background-color: #e3f2fd;
                border: 3px dashed #2196F3;
            }
        """)
        ly = QVBoxLayout(self)
        ly.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.lab = QLabel("拖文件过来\n或点按钮选")
        self.lab.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.lab.setFont(QFont("Microsoft YaHei", 14))
        self.lab.setStyleSheet("color: #666;")
        ly.addWidget(self.lab)

        btn_ly = QHBoxLayout()
        self.btn_sel = QPushButton("选文件")
        self.btn_sel.setFont(QFont("Microsoft YaHei", 11))
        self.btn_sel.setStyleSheet("""
            QPushButton {
                background-color: #2196F3;
                color: white;
                border: none;
                padding: 8px 16px;
                border-radius: 5px;
            }
            QPushButton:hover { background-color: #1976D2; }
        """)
        self.btn_sel.clicked.connect(self.sel_file)
        btn_ly.addWidget(self.btn_sel)
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
            # 文件夹没判断，拖进来直接崩
            self.dropped.emit(fp)

    def sel_file(self):
        fp, _ = QFileDialog.getOpenFileName(
            self, "选文件", "",
            "可执行文件 (*.exe *.dll *.sys *.scr);;脚本 (*.bat *.cmd *.ps1 *.vbs *.js *.py);;所有文件")
        if fp:
            self.dropped.emit(fp)


class ResultPanel(QWidget):
    def __init__(self):
        super().__init__()
        self._init_ui()

    def _init_ui(self):
        ly = QVBoxLayout(self)

        self.rf = QFrame()
        self.rf.setStyleSheet("""
            QFrame {
                background-color: #f5f5f5;
                border-radius: 10px;
                padding: 10px;
            }
        """)
        rly = QVBoxLayout(self.rf)

        self.rl = QLabel("等着...")
        self.rl.setFont(QFont("Microsoft YaHei", 18, QFont.Weight.Bold))
        self.rl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        rly.addWidget(self.rl)

        self.sl = QLabel("")
        self.sl.setFont(QFont("Microsoft YaHei", 14))
        self.sl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        rly.addWidget(self.sl)

        ly.addWidget(self.rf)

        self.rt = QTextEdit()
        self.rt.setReadOnly(True)
        self.rt.setFont(QFont("Consolas", 10))
        self.rt.setPlaceholderText("结果在这显示...")
        ly.addWidget(self.rt)

    def show_res(self, res: dict):
        ai = res.get("ai", {})

        if "error" in ai:
            self.rl.setText("❌ 失败")
            self.rl.setStyleSheet("color: #f44336;")
            self.rt.setText(f"错误: {ai['error']}")
            return

        lv = ai.get("risk_level", "unknown")
        sc = ai.get("risk_score", 0)
        bad = ai.get("is_malicious", False)

        if lv == "critical" or sc >= 80:
            c = "#f44336"; ic = "🔴"; t = "极高风险"
        elif lv == "high" or sc >= 60:
            c = "#ff9800"; ic = "🟠"; t = "高风险"
        elif lv == "medium" or sc >= 40:
            c = "#ffeb3b"; ic = "🟡"; t = "中风险"
        elif lv == "low" or sc >= 20:
            c = "#4caf50"; ic = "🟢"; t = "低风险"
        else:
            c = "#4caf50"; ic = "✅"; t = "安全"

        self.rl.setText(f"{ic} {t}")
        self.rl.setStyleSheet(f"color: {c};")
        self.sl.setText(f"评分: {sc}/100")

        lines = []
        lines.append("=" * 50)
        lines.append("AI分析")
        lines.append("=" * 50)
        lines.append(f"恶意: {'是' if bad else '否'}")
        lines.append(f"类型: {ai.get('threat_type', '未知')}")
        lines.append(f"等级: {lv}")
        lines.append(f"评分: {sc}/100")
        lines.append("")

        ids = ai.get("indicators", [])
        if ids:
            lines.append("指标:")
            for i in ids:
                lines.append(f"  - {i}")
            lines.append("")

        bh = ai.get("behavior_analysis", '')
        if bh:
            lines.append(f"行为: {bh}")
            lines.append("")

        rc = ai.get('recommendation', '')
        if rc:
            lines.append(f"建议: {rc}")
            lines.append("")

        # 合规没做

        st = res.get("static", {})
        lines.append("\n" + "=" * 50)
        lines.append("静态分析")
        lines.append("=" * 50)
        lines.append(f"熵值: {st.get('ent', 0)}")
        lines.append(f"可疑API: {st.get('api_cnt', 0)}个")
        lines.append(f"可疑模式: {st.get('pat_cnt', 0)}处")

        fi = res.get("finfo", {})
        lines.append("\n" + "=" * 50)
        lines.append("文件信息")
        lines.append("=" * 50)
        lines.append(f"名: {fi.get('file_name', 'N/A')}")
        lines.append(f"大小: {fi.get('file_size', 0)} bytes")

        self.rt.setText("\n".join(lines))


class MainWin(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("AI-Safe")
        self.setMinimumSize(800, 600)
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

        tl = QLabel("🛡️ AI-Safe")
        tl.setFont(QFont("Microsoft YaHei", 20, QFont.Weight.Bold))
        tl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        tl.setStyleSheet("color: #2196F3;")
        mly.addWidget(tl)

        st = QLabel("AI文件安全检测")
        st.setFont(QFont("Microsoft YaHei", 11))
        st.setAlignment(Qt.AlignmentFlag.AlignCenter)
        st.setStyleSheet("color: #666;")
        mly.addWidget(st)

        self.status = QLabel("初始化...")
        self.status.setFont(QFont("Microsoft YaHei", 10))
        self.status.setStyleSheet("color: #666;")
        mly.addWidget(self.status)

        self.pb = QProgressBar()
        self.pb.setVisible(False)
        mly.addWidget(self.pb)

        sp = QSplitter(Qt.Orientation.Vertical)
        self.box = DropBox()
        self.box.dropped.connect(self.start)
        sp.addWidget(self.box)

        self.panel = ResultPanel()
        scr = QScrollArea()
        scr.setWidget(self.panel)
        scr.setWidgetResizable(True)
        sp.addWidget(scr)
        sp.setSizes([200, 400])
        mly.addWidget(sp)

        bly = QHBoxLayout()

        self.btn_clr = QPushButton("清除")
        self.btn_clr.setFont(QFont("Microsoft YaHei", 10))
        self.btn_clr.setStyleSheet("""
            QPushButton {
                background-color: #757575;
                color: white;
                border: none;
                padding: 8px 16px;
                border-radius: 5px;
            }
            QPushButton:hover { background-color: #616161; }
        """)
        self.btn_clr.clicked.connect(self.clr)
        bly.addWidget(self.btn_clr)
        bly.addStretch()

        self.btn_about = QPushButton("关于")
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
        self.btn_about.clicked.connect(self.about)
        bly.addWidget(self.btn_about)

        mly.addLayout(bly)

    def _init_core(self):
        try:
            cfg_p = Path(__file__).parent.parent / 'cfg.yaml'
            import yaml
            with open(cfg_p, 'r', encoding='utf-8') as f:
                cfg = yaml.safe_load(f)

            self.mgr = create_ai_manager(str(cfg_p))
            h = self.mgr.check_health()

            if h["status"] == "healthy":
                self.status.setText(f"✅ AI就绪 | 模型: {h.get('model', 'unknown')}")
                self.status.setStyleSheet("color: #4caf50;")
            else:
                self.status.setText("⚠️ AI未就绪")
                self.status.setStyleSheet("color: #ff9800;")

            av = cfg.get('av', {})
            self.analyzer = FileAnalyzer(
                max_file_size=av.get('max_size', 104857600),
                max_strings=av.get('code_extract', {}).get('max_str', 1000)
            )
        except Exception as e:
            self.status.setText(f"❌ 初始化失败: {str(e)}")
            self.status.setStyleSheet("color: #f44336;")

    def start(self, fp: str):
        if not self.mgr or not self.analyzer:
            QMessageBox.warning(self, "错误", "核心没初始化好")
            return

        if not self.mgr.provider.is_available():
            QMessageBox.warning(self, "AI未就绪", "先开Ollama")
            return

        # 文件/文件夹没区分，直接干
        p = Path(fp)
        self.box.lab.setText(f"分析: {p.name}")
        self.pb.setVisible(True)
        self.pb.setRange(0, 0)
        self.panel.rl.setText("🔍 分析中...")
        self.panel.rl.setStyleSheet("color: #2196F3;")
        self.panel.rt.clear()

        self.wk = Worker(fp, self.mgr, self.analyzer)
        self.wk.sig_prog.connect(self._prog)
        self.wk.sig_res.connect(self._done)
        self.wk.sig_err.connect(self._err)
        self.wk.start()

    def _prog(self, msg: str):
        self.status.setText(f"⏳ {msg}")

    def _done(self, res: dict):
        self.pb.setVisible(False)
        self.box.lab.setText("拖文件过来\n或点按钮选")
        self.status.setText("✅ 完成")
        self.panel.show_res(res)

    def _err(self, err: str):
        self.pb.setVisible(False)
        self.box.lab.setText("拖文件过来\n或点按钮选")
        self.status.setText("❌ 失败")
        self.panel.rl.setText("❌ 失败")
        self.panel.rl.setStyleSheet("color: #f44336;")
        self.panel.rt.setText(f"错误:\n{err}")

    def clr(self):
        self.panel.rl.setText("等着...")
        self.panel.rl.setStyleSheet("")
        self.panel.sl.clear()
        self.panel.rt.clear()
        self.status.setText("就绪")

    def about(self):
        QMessageBox.about(
            self, "关于",
            "<h2>🛡️ AI-Safe v1.0</h2>"
            "<p>文件安全分析工具</p>"
            "<p>Python + PyQt6 + Ollama</p>"
        )

    def closeEvent(self, event):
        if self.wk and self.wk.isRunning():
            self.wk.terminate()
            self.wk.wait()
        event.accept()


def main():
    app = QApplication(sys.argv)
    app.setStyle('Fusion')
    app.setFont(QFont("Microsoft YaHei", 10))
    w = MainWin()
    w.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
