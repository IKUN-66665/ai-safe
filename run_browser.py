import os
import sys

# ===== 强制软件渲染 =====

os.environ["QTWEBENGINE_CHROMIUM_FLAGS"] = (
    "--disable-gpu "
    "--disable-software-rasterizer "
    "--disable-gpu-compositing "
    "--disable-gpu-vsync "
    "--no-sandbox"
)

os.environ["QT_OPENGL"] = "software"

os.environ["QTWEBENGINE_DISABLE_SANDBOX"] = "1"

# ===================================

from PyQt6.QtWidgets import QApplication
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QSurfaceFormat

from ai_web.main_window import BrowserGUI


def main():

    QApplication.setAttribute(
        Qt.ApplicationAttribute.AA_UseSoftwareOpenGL
    )

    app = QApplication(sys.argv)

    win = BrowserGUI()

    win.show()

    sys.exit(app.exec())


if __name__ == "__main__":
    main()