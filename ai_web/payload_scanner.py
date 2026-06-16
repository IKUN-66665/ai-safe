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



# 第七部分：Parameter Analyzer + Context Detector


class ParameterAnalyzer:
    """
    参数分析器 - 检测参数所在上下文
    - html: 注入在HTML内容中
    - attribute: 注入在HTML属性中
    - js_string: 注入在JS字符串中
    - url: URL参数
    """

    def detect_context(self, normal_response_text: str, reflected_string: str) -> str:
        """
        根据响应中反射的位置判断上下文
        返回: "html" | "attribute" | "js_string" | "url" | "none"
        """
        if not normal_response_text or not reflected_string:
            return "html"

        text = normal_response_text
        needle = reflected_string[:20] if len(reflected_string) > 20 else reflected_string
        pos = text.lower().find(needle.lower()) if needle else -1

        if pos < 0:
            return "html"

        # 检查前后字符
        context_window_start = max(0, pos - 50)
        context_window_end = min(len(text), pos + len(needle) + 50)
        ctx = text[context_window_start:context_window_end]

        # 检查是否在HTML属性中（前后有引号+等号）
        if re.search(r'[a-zA-Z]+=("|\')', ctx):
            return "attribute"

        # 检查是否在 JS 字符串中
        if "var " in ctx or "const " in ctx or "let " in ctx or "=" in ctx and (";" in ctx or "\n" in ctx):
            if re.search(r'["\'].*' + re.escape(needle), ctx, re.IGNORECASE | re.DOTALL):
                return "js_string"

        return "html"

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



# 第九部分：主动扫描器 - 整合所有组件


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

            # === 阶段 0: 爬虫发现 ===
            self.log("[*] ===== 扫描阶段 0/4: 爬虫发现端点 =====")
            discovered = {"links": [], "forms": [], "js_endpoints": [], "api_paths": []}
            try:
                discovered = self.crawler.discover(url)
                all_forms = self.extract_forms(url)
                all_forms.extend(discovered["forms"])
            except Exception as e:
                self.log(f"[-] 爬虫阶段异常: {e}，降级为当前页面表单")
                all_forms = self.extract_forms(url)

            parsed = urlparse(url)
            query_params = parse_qs(parsed.query)
            self.log(f"[+] URL参数: {list(query_params.keys())}, 表单: {len(all_forms)}")

            if api_endpoints := list(discovered.get("js_endpoints", [])) + list(discovered.get("api_paths", [])):
                self.log(f"[+] 发现可能API端点: {len(api_endpoints)} 个")

            # === 阶段 1: SQL Injection (Error-based + Boolean-blind) ===
            self.log("[*] ===== 扫描阶段 1/4: SQL注入 (错误型 + 布尔盲注) =====")
            try:
                self._scan_sql_forms(url, all_forms)
            except Exception as e:
                self.log(f"[-] 阶段1(表单SQL)异常: {e}")
            if query_params and self.running:
                try:
                    self._scan_sql_get(url, query_params)
                except Exception as e:
                    self.log(f"[-] 阶段1(URL参数SQL)异常: {e}")

            # === 阶段 2: SQL Injection (Time-based) ===
            self.log("[*] ===== 扫描阶段 2/4: SQL注入 (时间盲注 - 统计方法) =====")
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
            self.log("[*] ===== 扫描阶段 3/4: XSS (源码检测 + 上下文感知) =====")
            try:
                if self.running:
                    self._scan_xss(url, all_forms, query_params)
            except Exception as e:
                self.log(f"[-] 阶段3(XSS源码)异常: {e}")

            # === 阶段 4: Playwright 浏览器验证 ===
            self.log("[*] ===== 扫描阶段 4/4: Playwright 浏览器验证 =====")
            try:
                if self.running:
                    self._scan_xss_browser(url, all_forms, query_params)
            except Exception as e:
                self.log(f"[-] 阶段4(浏览器验证)异常: {e}（浏览器不可用则跳过此阶段）")

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
                context = self.analyzer.detect_context(probe_resp.text or "", probe)
                self.log(f"[DEBUG] 参数 {field_name} 反射上下文: {context}")

                # 根据上下文生成 payload
                payloads = self.mutator.generate_xss_payloads(context=context, max_count=12)

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

                context = self.analyzer.detect_context(probe_resp.text or "", "xssprobe_xyz")
                payloads = self.mutator.generate_xss_payloads(context=context, max_count=10)

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

    def _scan_xss_browser(self, url: str, forms: List[Dict], query_params: Dict):
        """使用 Playwright 浏览器验证 XSS"""

        if not self._launch_browser():
            self.log("[-] Playwright 浏览器不可用，跳过浏览器验证")
            return

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
