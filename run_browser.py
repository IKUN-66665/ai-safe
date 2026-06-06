# -*- coding: utf-8 -*-
"""
run_browser.py - 启动入口
"""

import sys
import os
import logging


logging.basicConfig(level=logging.ERROR)
os.environ['QT_LOGGING_RULES'] = '*.debug=false;qt.network.*=false;qt.webengine.*=false'


project_root = os.path.dirname(os.path.abspath(__file__))
if project_root not in sys.path:
    sys.path.insert(0, project_root)


if __name__ == "__main__":
    print("=" * 60)
    print("Web安全审计浏览器 - OWASP Top 10检测")
    print("=" * 60)
    print("\n正在启动浏览器...\n")

    try:
        from PyQt6.QtWidgets import QApplication
        from PyQt6.QtCore import QUrl
        from ai_web.main_window import BrowserGUI

        app = QApplication(sys.argv)
        app.setStyle('Fusion')

        window = BrowserGUI()
        window.show()

        sys.exit(app.exec())

    except Exception as e:
        print(f"启动失败: {e}")
        import traceback
        traceback.print_exc()
        input("按回车键退出...")
