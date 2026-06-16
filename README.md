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





#### 后续优化方向（Roadmap）

### 1. Context-Aware XSS（上下文感知 XSS）

当前 Payload Mutation 已支持多种编码与混淆策略，

但尚未完全实现：

“基于上下文的 Payload 自适应生成”。

例如：

```html
<input value="PAYLOAD">
```

与：

```js
var a = "PAYLOAD"
```

属于完全不同的注入上下文，

需要采用不同的逃逸策略与 Payload。

下一阶段计划实现：

* HTML Context Detection
* Attribute Context Escape
* JavaScript String Breakout
* URL Context Adaptation

以提升现代 Web 环境中的 XSS 检测准确率。



### 2. JavaScript Sink 分析（DOM XSS）

当前版本已支持 Endpoint Discovery，

但尚未实现完整的：

Source → Sink 流分析。

下一阶段计划重点分析：

* innerHTML
* eval
* document.write
* setTimeout
* Function()

等危险 Sink，

并结合用户可控输入进行 DOM XSS 检测。



### 3. Headless Browser 自动交互

当前 Playwright 主要用于 Payload 验证。

但现代 Web 应用大量依赖：

* Route 切换
* 动态渲染
* Tab 交互
* 登录状态
* Lazy Load

后续计划扩展为：

轻量级 Headless Browser Crawler，

支持：

* 自动点击
* 状态保持
* 页面遍历
* 动态内容发现



### 4. API 参数结构推断

当前已支持 API Endpoint Discovery，

但尚未支持：

自动推断参数结构与 JSON Schema。

后续计划增加：

* 参数名提取
* 类型推断
* JSON 结构分析
* GraphQL Schema 探测
* Request Replay




##### 技术难点与挑战

### 1. 动态网站中的误报问题

传统扫描器仅通过：

```python
len(response.text)
```

比较响应长度，

在动态网站中误报率极高。

为降低误报，

项目实现了：

* 三向响应比较（TRUE / FALSE / NORMAL）
* DOM 结构差异分析
* 状态码比较
* 重定向差异分析
* MIME 类型校验
* 安全关键字变化检测

用于提升 SQL 注入检测稳定性。



### 2. 时间盲注稳定性问题

网络波动容易导致：

Time-Based SQL Injection 出现误报。

项目引入：

* 多次采样
* 基准均值建立
* 标准差分析
* Z-score 统计检验

用于降低网络抖动带来的误判。



### 3. 上下文相关 XSS 检测

现代 XSS Payload 强依赖注入上下文。

项目会先检测：

Payload 在响应中的反射位置，

再根据：

* HTML Context
* Attribute Context
* JavaScript Context
* URL Context

动态选择 Payload，

而非使用固定 Payload 列表。



### 4. Payload 固定特征问题

传统固定 Payload 容易被 WAF 规则识别。

项目实现多维度 Mutation Engine：

* 大小写混淆
* 注释插入
* Unicode 编码
* URL 编码
* Tag Mutation
* Payload Split
* 空格替换

用于提升 Payload 多样性。




## 当前局限性（Limitations）

当前版本仍存在以下限制：

* 不适用于生产级渗透测试环境
* 对高级 WAF/CDN 防护绕过能力有限
* 尚未实现完整浏览器侧 Taint Tracking
* 复杂认证流程支持有限
* AI 分析结果仍可能存在误报
* DOM-Based XSS 检测能力仍不完善
* API Schema 推断能力仍在开发中
* 未实现动态沙箱执行能力

本项目仅用于安全研究、教学与授权测试环境。





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
- 升级：更新升级web安全审计浏览器模块，Web安全测试模块支持在授权环境中进行，可以进行一些分析，在dvwa靶场上测试漏洞会有反应，比之前的静态分析准确率更高
### 2026-06-12
- 新增：文件安全检测模块，可以支持文件夹上传检测
- 修复：文件安全检测模块新增白名单，可以降低误报率，web审计浏览器修复扫描普通网站时会出现超时的漏洞
### 2026-06-17
- 升级：原本的代码是只靠大量payload来检测，只有Error-based，Boolean-based和Time-based blind ，本人实测过很多次发现只能够对一些SQL拼接 没参数化 没过滤 没WAF的很老的网站才有效果，对现代网站完全没有效果，所以对代码全新升级：8大组件 + 爬虫 + Diff引擎 + Payload变异 + 上下文感知XSS + 统计时间盲注 + JSON API + CSRF自动处理可以更好应对现代网站