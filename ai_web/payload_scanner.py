# 主动扫描器：SQL注入 / XSS / 命令注入 检测

import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
from playwright.sync_api import sync_playwright
import threading
import time
import re
import json

SQL_PAYLOADS = [
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' OR '1'='1' #",
    "1' AND '1'='1",
    "1' AND '1'='2",
    "' UNION SELECT NULL--",
    "' UNION SELECT 1,2,3--",
    "admin' OR '1'='1",
]

XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "\"><script>alert(1)</script>",
    "javascript:alert(1)",
    "<svg onload=alert(1)>",
]

SQL_ERRORS = [
    "sql syntax", "mysql_fetch", "mysql_num", "ORA-",
    "SQLite", "syntax error", "unclosed quotation",
    "mysql", "postgresql", "sqlite",
]

# 常见靶场关键字
HACKERLAB_DOMAINS = ["dvwa", "sqli-labs", "bWAPP", "webscarab", "dvwa.local"]

# 普通商业网站响应长度差异容忍度更高（因为有广告、动态内容等）
# 靶场页面相对静态，可以更严格
LEN_DIFF_THRESHOLD_LOOSE = 500   # 宽松阈值（普通网站）
LEN_DIFF_THRESHOLD_STRICT = 20    # 严格阈值（靶场）

DVWA_LOGIN_URL = "http://127.0.0.1/dvwa/login.php"
DVWA_SECURITY_URL = "http://127.0.0.1/dvwa/security.php"


def build_target_url(base_url, form_action):
    if not base_url.endswith("/"):
        base_url += "/"
    form_action = form_action.lstrip("/")
    return urljoin(base_url, form_action)


class ActiveScanner:

    def __init__(self, logger=None, callback=None):
        self.logger = logger
        self.callback = callback
        self.running = False
        self.session = requests.Session()
        self.playwright = None
        self.browser = None
        # 收集扫描结果，给AI用
        self.current_url = ""
        self.found_vulns = []
        self.scan_logs = []

    def is_hackerlab(self, url):
        """判断目标是否为靶场环境（靶场页面静态，阈值可以严格）"""
        url_lower = url.lower()
        for domain in HACKERLAB_DOMAINS:
            if domain in url_lower:
                return True
        return False

    def _get_len_threshold(self, url):
        """根据目标类型返回合适的长度差异阈值"""
        if self.is_hackerlab(url):
            return LEN_DIFF_THRESHOLD_STRICT
        return LEN_DIFF_THRESHOLD_LOOSE


    def log(self, text):
        print(text)
        self.scan_logs.append(text)
        if self.logger:
            self.logger(text)

    def stop(self):
        self.running = False
        if self.browser:
            try:
                self.browser.close()
            except:
                pass

    def _report_vuln(self, vuln_type, description, payload, url):
        self.found_vulns.append({
            "type": vuln_type,
            "description": description,
            "payload": payload,
            "url": url,
        })
        line = f"[!!!] {vuln_type}: {description} | Payload: {payload}"
        self.log(line)
        if self.callback:
            self.callback(line)


    def login_dvwa(self, username="admin", password="password"):
        try:
            r = self.session.get(DVWA_LOGIN_URL, timeout=10)
            soup = BeautifulSoup(r.text, "html.parser")
            token_el = soup.find("input", {"name": "user_token"})
            token = token_el["value"] if token_el else ""

            data = {"username": username, "password": password, "Login": "Login"}
            if token:
                data["user_token"] = token
            r = self.session.post(DVWA_LOGIN_URL, data=data, timeout=10)

            r = self.session.get(DVWA_SECURITY_URL, timeout=10)
            soup = BeautifulSoup(r.text, "html.parser")
            token_el = soup.find("input", {"name": "user_token"})
            token = token_el["value"] if token_el else ""

            data = {"security": "low", "seclev_submit": "Submit", "user_token": token}
            self.session.post(DVWA_SECURITY_URL, data=data, timeout=10)
            self.log("[+] DVWA 登录成功")
            return True
        except Exception as e:
            self.log(f"[-] DVWA 登录异常: {e}")
            return False


    def start_scan(self, url):
        # 重置当前扫描结果
        self.current_url = url
        self.found_vulns = []
        self.scan_logs = []
        self.running = True

        if "dvwa" in url.lower():
            self.login_dvwa()

        thread = threading.Thread(target=self._scan, args=(url,), daemon=True)
        thread.start()


    def get_results(self):
        return {
            "url": self.current_url,
            "vulnerabilities": list(self.found_vulns),
            "logs": list(self.scan_logs),
            "vuln_count": len(self.found_vulns),
        }


    def _scan(self, url):
        try:
            self.log("[*] 开始扫描: " + url)
            forms = self.extract_forms(url)
            self.log(f"[+] 发现表单: {len(forms)}")

            # 检测URL参数 + 表单参数
            parsed = urlparse(url)
            query_params = parse_qs(parsed.query)
            self.log(f"[DEBUG] URL参数: {list(query_params.keys())}")

            # 先搞SQL注入
            self.log("[*] 正在扫描 SQL Injection")
            if query_params:
                self._check_sql_get(url, query_params)
            for form in forms:
                if not self.running:
                    return
                self._check_sql_form(url, form)

            # 再搞：XSS
            self.log("[*] 正在扫描 XSS")
            self._scan_xss(url, forms, query_params)

            self.log(f"[+] 扫描完成，共发现 {len(self.found_vulns)} 个漏洞")
        except Exception as e:
            self.log(f"[ERROR] {e}")

    def extract_forms(self, url):
        forms = []
        try:
            r = self.session.get(url, timeout=10)
            soup = BeautifulSoup(r.text, "html.parser")
            forms = soup.find_all("form")
        except Exception as e:
            self.log(str(e))
        return forms

    def _form_details(self, form):
        action = form.attrs.get("action", "")
        method = form.attrs.get("method", "get").lower()
        inputs = []
        for tag in form.find_all("input"):
            inputs.append({"type": tag.attrs.get("type", "text"), "name": tag.attrs.get("name")})
        return {"action": action, "method": method, "inputs": inputs}

    # SQL 注入
    def _check_sql_get(self, url, query_params):
        parsed = urlparse(url)
        is_target_hackerlab = self.is_hackerlab(url)

        for param_name in query_params:
            if not self.running:
                return
            try:
                normal_resp = self.session.get(url, timeout=10)
                normal_len = len(normal_resp.text)
                normal_status = normal_resp.status_code

                true_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{param_name}=1' AND '1'='1"
                false_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{param_name}=1' AND '1'='2"

                true_resp = self.session.get(true_url, timeout=10)
                false_resp = self.session.get(false_url, timeout=10)
                true_len = len(true_resp.text)
                false_len = len(false_resp.text)

                self.log(f"[DEBUG] 参数 {param_name}: 正常={normal_len}/{normal_status} True={true_len}/{true_resp.status_code} False={false_len}/{false_resp.status_code}")

                combined = (true_resp.text + false_resp.text).lower()
                for err in SQL_ERRORS:
                    if err.lower() in combined:
                        self._report_vuln("SQL注入漏洞", f"URL参数 {param_name} 出现SQL错误提示",
                                          f"1' AND '1'='1", url)
                        return

                # 只有靶场环境才使用长度差异检测
                if is_target_hackerlab:
                    if abs(true_len - false_len) > LEN_DIFF_THRESHOLD_STRICT:
                        self._report_vuln("SQL注入漏洞(Blind)",
                                          f"URL参数 {param_name} 对真/假条件响应长度差异明显",
                                          f"1' AND '1'='1", url)
                        return

                    or_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{param_name}=' OR '1'='1"
                    or_resp = self.session.get(or_url, timeout=10)
                    if abs(len(or_resp.text) - normal_len) > LEN_DIFF_THRESHOLD_STRICT:
                        self._report_vuln("SQL注入漏洞",
                                          f"URL参数 {param_name} 对 OR payload响应异常",
                                          f"' OR '1'='1", url)
                        return

            except Exception as e:
                self.log(f"[-] SQL GET 测试异常: {e}")
                continue

    def _check_sql_form(self, url, form):
        details = self._form_details(form)
        target_url = build_target_url(url, details["action"])
        is_target_hackerlab = self.is_hackerlab(url)

        for input_tag in details["inputs"]:
            if not input_tag["name"] or not self.running:
                continue
            param = input_tag["name"]

            normal_data = {param: "test"}
            try:
                if details["method"] == "post":
                    normal_resp = self.session.post(target_url, data=normal_data, timeout=10)
                else:
                    normal_resp = self.session.get(target_url, params=normal_data, timeout=10)
                normal_len = len(normal_resp.text)
            except:
                normal_len = 0

            for payload in SQL_PAYLOADS:
                if not self.running:
                    return
                data = {param: payload}
                try:
                    if details["method"] == "post":
                        r = self.session.post(target_url, data=data, timeout=10)
                    else:
                        r = self.session.get(target_url, params=data, timeout=10)

                    for err in SQL_ERRORS:
                        if err.lower() in r.text.lower():
                            self._report_vuln("SQL注入漏洞", f"表单参数 {param}", payload, target_url)
                            return

                    # 只有靶场环境才使用长度差异检测
                    if is_target_hackerlab and normal_len:
                        if abs(len(r.text) - normal_len) > LEN_DIFF_THRESHOLD_STRICT:
                            self._report_vuln("SQL注入漏洞(Blind)",
                                              f"表单参数 {param} 响应长度异常", payload, target_url)
                            return
                except Exception as e:
                    self.log(str(e))

    # XSS 扫描 - 双模式：普通网站用快速HTTP反射检测，靶场用完整Playwright检测
    def _scan_xss(self, url, forms, query_params):
        is_target_hackerlab = self.is_hackerlab(url)

        try:
            # 靶场环境：完整Playwright检测
            if is_target_hackerlab:
                self._scan_xss_playwright(url, forms, query_params)
                return

            # 普通网站：先使用快速HTTP反射检测（不启动浏览器，不会超时）
            # 如果HTTP检测发现可疑反射，再尝试Playwright验证
            self.log("[*] XSS扫描(快速HTTP模式): 正在检测反射型XSS")

            found_any = False

            # 检测URL参数
            if query_params:
                if self._check_xss_get_http(url, list(query_params.keys())):
                    found_any = True

            # 检测表单
            for form in forms:
                if not self.running:
                    break
                if self._check_xss_form_http(url, form):
                    found_any = True

            if not found_any:
                self.log("[+] XSS扫描完成: 未检测到反射型XSS")
            else:
                self.log("[+] XSS扫描完成: 发现潜在XSS注入点")

        except Exception as e:
            self.log(f"[-] XSS扫描异常: {e}")

    def _check_xss_get_http(self, url, param_names):
        """
        快速HTTP反射检测：检查payload是否原样出现在响应中
        """
        parsed = urlparse(url)
        found = False

        for param in param_names:
            if not self.running:
                break
            try:
                for payload in XSS_PAYLOADS:
                    if not self.running:
                        break
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{param}={payload}"
                    try:
                        resp = self.session.get(test_url, timeout=5)
                        # 检查payload是否原样出现在响应中（可能被转义）
                        resp_text_lower = resp.text.lower()
                        payload_lower = payload.lower()

                        # 检查原始payload是否出现
                        if payload_lower in resp_text_lower:
                            test_url_log = test_url[:100] + ("..." if len(test_url) > 100 else "")
                            self._report_vuln("XSS漏洞(疑似)", f"URL参数 {param} 发现payload反射",
                                              payload, test_url_log)
                            found = True
                            break
                    except Exception:
                        continue

            except Exception as e:
                self.log(f"[-] XSS GET HTTP检测异常: {e}")
                continue

        return found

    def _check_xss_form_http(self, url, form):
        """
        快速HTTP反射检测：检查表单参数的payload反射
        """
        details = self._form_details(form)
        target_url = build_target_url(url, details["action"])
        found = False

        for input_tag in details["inputs"]:
            if not input_tag["name"] or not self.running:
                continue
            param = input_tag["name"]

            for payload in XSS_PAYLOADS:
                if not self.running:
                    break
                data = {param: payload}
                try:
                    if details["method"] == "post":
                        resp = self.session.post(target_url, data=data, timeout=5)
                    else:
                        resp = self.session.get(target_url, params=data, timeout=5)

                    resp_text_lower = resp.text.lower()
                    payload_lower = payload.lower()

                    if payload_lower in resp_text_lower:
                        self._report_vuln("XSS漏洞(疑似)",
                                          f"表单参数 {param} 发现payload反射",
                                          payload, target_url)
                        found = True
                        break
                except Exception:
                    continue

        return found

    def _scan_xss_playwright(self, url, forms, query_params):
        """
        靶场用：完整Playwright检测，捕获alert对话框
        """
        try:
            self.playwright = sync_playwright().start()
            self.browser = self.playwright.chromium.launch(headless=True)

            # 先cookie传给浏览器
            cookies = []
            for c in self.session.cookies:
                cookies.append({"name": c.name, "value": c.value,
                                "domain": "127.0.0.1", "path": "/"})

            # 测URL参数
            if query_params:
                self._check_xss_get(url, list(query_params.keys()), cookies)

            # 测表单
            for form in forms:
                if not self.running:
                    break
                self._check_xss_form(url, form, cookies)

            self.browser.close()
            self.playwright.stop()
            self.log("[+] XSS扫描(Playwright模式)完成")
        except Exception as e:
            self.log(f"[-] XSS扫描(Playwright)失败: {e}")
            if self.browser:
                try:
                    self.browser.close()
                except:
                    pass
            if self.playwright:
                try:
                    self.playwright.stop()
                except:
                    pass

    def _check_xss_get(self, url, param_names, cookies):
        parsed = urlparse(url)
        for param in param_names:
            if not self.running:
                return
            try:
                context = self.browser.new_context()
                if cookies:
                    context.add_cookies(cookies)
                page = context.new_page()

                for payload in XSS_PAYLOADS:
                    if not self.running:
                        break
                    triggered = False

                    def on_dialog(dialog):
                        nonlocal triggered
                        triggered = True
                        try:
                            dialog.accept()
                        except:
                            pass

                    page.once("dialog", on_dialog)
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{param}={payload}"
                    try:
                        page.goto(test_url, wait_until="domcontentloaded", timeout=10000)
                        page.wait_for_timeout(1500)
                    except Exception as e:
                        self.log(f"[-] XSS GET 超时: {e}")
                        continue

                    if triggered:
                        self._report_vuln("XSS漏洞", f"URL参数 {param} 反射XSS", payload, test_url)
                        break

                page.close()
                context.close()
            except Exception as e:
                self.log(f"[-] XSS GET 异常: {e}")

    def _check_xss_form(self, url, form, cookies):
        details = self._form_details(form)
        target_url = build_target_url(url, details["action"])
        try:
            context = self.browser.new_context()
            if cookies:
                context.add_cookies(cookies)
            page = context.new_page()

            for input_tag in details["inputs"]:
                if not input_tag["name"] or not self.running:
                    continue
                param = input_tag["name"]

                for payload in XSS_PAYLOADS:
                    if not self.running:
                        break
                    triggered = False

                    def on_dialog(dialog):
                        nonlocal triggered
                        triggered = True
                        try:
                            dialog.accept()
                        except:
                            pass

                    page.once("dialog", on_dialog)
                    try:
                        page.goto(target_url, wait_until="domcontentloaded", timeout=10000)
                        page.wait_for_timeout(500)

                        try:
                            page.fill(f'input[name="{param}"]', payload)
                        except:
                            pass

                        try:
                            page.click("input[type=submit], button[type=submit]")
                        except:
                            try:
                                page.keyboard.press("Enter")
                            except:
                                pass

                        page.wait_for_timeout(1500)
                    except Exception as e:
                        self.log(f"[-] XSS 表单测试异常: {e}")
                        continue

                    if triggered:
                        self._report_vuln("XSS漏洞", f"表单参数 {param}", payload, target_url)
                        break

            page.close()
            context.close()
        except Exception as e:
            self.log(f"[-] XSS 表单扫描异常: {e}")
