# AI-Safe

用 PyQt6 写的文件安全检测工具，基于 Ollama 本地 AI 做语义分析。

![Python](https://img.shields.io/badge/python-3.8+-blue.svg)
![PyQt6](https://img.shields.io/badge/PyQt6-GUI-green.svg)
![Ollama](https://img.shields.io/badge/Ollama-local%20AI-orange.svg)

## 干啥用的 / What it does

拖个文件进去，AI 分析是不是恶意软件。本地跑，不需要联网上传文件。

支持的可执行文件：
- PE 文件（exe、dll、sys、scr）
- 脚本（bat、cmd、ps1、vbs、js、py）

Drop a file in, AI analyzes if it's malware. Runs locally, no upload needed.

Supported: PE files (exe, dll, sys, scr) and scripts (bat, cmd, ps1, vbs, js, py).

## 效果 / Features

- 拖放文件分析 / Drag & drop file analysis
- AI 语义分析风险等级 / AI semantic risk analysis
- 静态特征提取（熵值、API、字符串）/ Static feature extraction (entropy, APIs, strings)
- 规则匹配（PS 下载执行、注册表自启、键盘记录等）/ Rule matching (PS download, registry persistence, keylogger, etc.)

## 环境 / Requirements

- Python 3.8+
- Windows（PyQt6 用了 Windows 特定代码）/ Windows specific
- Ollama（本地 AI）/ Local AI

## 安装 / Installation

```bash
# 1. 克隆 / Clone
git clone https://github.com/yourname/ai-safe.git
cd ai-safe

# 2. 装依赖 / Install deps
pip install -r requirements.txt

# 3. 装 Ollama，下载模型 / Install Ollama & pull model
# https://ollama.com 下载安装 / Download from https://ollama.com
ollama pull deepseek-r1:7b

# 4. 跑起来 / Run
python run_safe.py
```

## 项目结构 / Project Structure

```
ai-safe/
├── ai_safe/
│   ├── __init__.py
│   ├── safe_gui.py          # 主界面 / Main GUI
│   └── safe_scan.py         # 文件分析 / File analyzer
├── core/
│   └── ai_interface.py      # AI 接口 / AI interface
├── cfg.yaml                 # 配置 / Config
├── run_safe.py              # 启动入口 / Entry point
└── README.md
```

## 使用 / Usage

| 步骤 | 截图 |
| ---- | ---- |
| 1. 启动等 AI 就绪 / Launch & wait | ![Step 1](use1.png) |
| 2. 拖文件分析 / Drag file | ![Step 2](use2.png) |
| 3. 查看报告 / View report | ![Step 3](use3.png) |

1. 启动等 AI 服务就绪（状态栏绿色）/ Launch and wait for AI ready (green status)
2. 拖文件进去或点"选文件" / Drag file or click "Select File"
3. 等分析完看评分和报告 / Wait for analysis and view report



## 技术栈 / Tech Stack

- Python 3.8+
- PyQt6
- Ollama（deepseek-r1:7b）
- pefile

## 免责 / Disclaimer

仅供学习研究，别当生产环境的安全工具用。AI 分析可能误判，结合其他工具综合判断。

For educational purposes only. Do not use as production security tool. AI analysis may produce false positives.

## License

MIT
