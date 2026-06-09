# AI-Safe

用 PyQt6 写的文件安全检测工具 + Web安全审计浏览器，基于 Ollama 本地 AI 做语义分析。

![Python](https://img.shields.io/badge/python-3.8+-blue.svg)
![PyQt6](https://img.shields.io/badge/PyQt6-GUI-green.svg)
![Ollama](https://img.shields.io/badge/Ollama-local%20AI-orange.svg)

## 干啥用的 / What it does

**模块一：文件安全检测**
拖个文件进去，AI 分析是不是恶意软件。本地跑，不需要联网上传文件。

支持的可执行文件：
- PE 文件（exe、dll、sys、scr）
- 脚本（bat、cmd、ps1、vbs、js、py、jar、sh）

**模块二：Web安全审计浏览器（新增功能）**
内置浏览器访问网站，自动进行被动分析和主动扫描，AI 生成安全审计报告。

## 效果 / Features

- 拖放文件分析 / Drag & drop file analysis
- AI 语义分析风险等级 / AI semantic risk analysis
- 静态特征提取（熵值、API、字符串）/ Static feature extraction (entropy, APIs, strings)
- 规则匹配（PS 下载执行、注册表自启、键盘记录等）/ Rule matching (PS download, registry persistence, keylogger, etc.)
- **Web安全审计浏览器（新增）** / Web security audit browser (new)
  - 内置浏览器访问目标网站
  - 被动分析（SSL、Headers、Forms、JS、CORS）
  - 主动扫描（XSS、SQLi、命令注入等）
  - AI 综合生成安全审计报告

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
#什么模型都可以 越强大的模型越好，但需要更大的内存 
# 4. 跑起来 / Run
# 文件安全检测
python run_safe.py
# Web安全审计浏览器
python run_browser.py
```

## 项目结构 / Project Structure

```
ai-safe/
├── ai_safe/              # 文件安全检测模块
│   ├── __init__.py
│   ├── safe_gui.py      # 主界面 / Main GUI
│   └── safe_scan.py     # 文件分析 / File analyzer
├── ai_web/              # Web安全审计浏览器模块（新增）
│   ├── __init__.py
│   ├── main_window.py   # 浏览器主界面
│   ├── ai_analyzer.py   # AI分析器
│   ├── payload_scanner.py  # 主动扫描器
├── core/
│   ├── ai_interface.py  # AI 接口 / AI interface
│   └── web_interface.py # Web AI 接口 / Web AI interface
├── cfg.yaml             # 配置 / Config
├── run_safe.py          # 文件检测入口 / File scan entry
├── run_browser.py       # 浏览器入口 / Browser entry
└── README.md
```

## 使用 / Usage

### 文件安全检测

| 步骤 | 截图 |
| ---- | ---- |
| 1. 启动等 AI 就绪 / Launch & wait | ![Step 1](use1.png) |
| 2. 拖文件分析 / Drag file | ![Step 2](use2.png) |
| 3. 查看报告 / View report | ![Step 3](use3.png) |

1. 启动等 AI 服务就绪（状态栏绿色）/ Launch and wait for AI ready (green status)
2. 拖文件进去或点"选文件" / Drag file or click "Select File"
3. 等分析完看评分和报告 / Wait for analysis and view report

### Web安全审计浏览器（新增功能）

| 步骤                            | 截图 | 说明                           |
|-------------------------------| ---- |------------------------------|
| 1. 打开浏览器访问目标网站 / Open browser | ![Step 5](5.png) | 输入URL，点击访问，再点击开始扫描，右侧会导出扫描结果 |
| 2. 漏洞列表/Vulnerability List     | ![Step 6](6.png) | 点击"漏洞列表"查看详细信息 |                           |
| 3. AI综合分析 / AI analysis       | ![Step 4](4.png) | AI综合生成完整安全审计报告               |

1. 启动浏览器模块 / Launch browser module
2. 输入目标URL并访问 / Enter target URL and visit
3. 查看实时页面分析结果 / View real-time page analysis
4. 点击"被动分析"获取详细信息 / Click "Passive Analysis" for details
5. 点击"AI分析"获取综合安全报告 / Click "AI Analysis" for full report

## 技术栈 / Tech Stack

- Python 3.8+
- PyQt6
- Ollama（deepseek-r1:7b）
- pefile
- PyQtWebEngine

## 免责 / Disclaimer

仅供学习研究，别当生产环境的安全工具用。AI 分析可能误判，结合其他工具综合判断。

For educational purposes only. Do not use as production security tool. AI analysis may produce false positives.

## 更新日志

### 2026-06-07
- 新增：Web安全审计浏览器模块，支持内置浏览器访问目标网站、被动分析、AI综合生成安全报告
- 修复：杀毒模块新增Fork炸弹、删除系统文件、关闭防火墙等多个恶意规则检测，提升对危险脚本的识别能力
### 2026-06-10
- 升级：更新升级web安全审计浏览器模块，可以主动分析扫描目标网站的风险，本人在dvwa靶场上测试漏洞会有反应，比之前的静态分析准确率更高
