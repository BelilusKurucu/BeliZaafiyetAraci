# BeliZaafiyetAracı

## 🔍 Açıklama

**BeliZaafiyetAracı**, web uygulamalarındaki güvenlik zafiyetlerini tespit etmek amacıyla geliştirilmiş bir Python aracıdır. 
Bu araç sayesinde HTTP başlık zafiyetleri, SQL Injection, XSS açıkları ve dosya yükleme zafiyetleri gibi birçok temel güvenlik sorunlarını test edebilirsiniz.

Yazılım tamamen Türkçe arayüze sahiptir ve terminal üzerinden interaktif olarak çalışır.

---

## ⚙️ Özellikler

- HTTP Güvenlik Başlıkları Analizi
- SQL Injection Testleri (error-based, boolean-based, union-based, time-based)
- XSS Testleri (parametre, form, DOM, JS)
- Dosya Yükleme Zafiyeti Testi (shell ve index yükleme)
- Log kayıt sistemi
- Temiz terminal arayüzü

---

## 💻 Kurulum

Python 3 yüklü olması gereklidir.

```bash
git clone https://github.com/BelilusKurucu/BeliZaafiyetAraci.git
cd BeliZaafiyetAraci
pip install -r requirements.txt
python BeliZaafiyetAracı.py
```

---

## 🧪 Kullanım

Uygulamayı başlattıktan sonra aşağıdaki komutları kullanabilirsiniz:

```bash
start     # Sistemi başlatır
stop      # Sistemi durdurur
status    # Sistemin mevcut durumunu gösterir
help      # Yardım menüsünü gösterir
exit      # Uygulamadan çıkış yapar
```

Ek test fonksiyonları kod içeriğinde aşağıdaki fonksiyonlar ile çağrılabilir:

```python
sql_injection_test("http://site.com/index.php?id=1")
xss_test("http://site.com/search?q=test")
baslik_analiz("http://site.com", "tr")
```

---

## 📁 Gereksinimler

- `requests`
- `beautifulsoup4`

```bash
pip install requests beautifulsoup4
```

---

## 🧠 Uyarı

Bu yazılım sadece **eğitim** ve **güvenlik testleri** amacıyla kullanılmalıdır. Yetkisiz sistemlerde kullanmak **yasadışıdır** ve etik dışıdır.

---

## 🧑‍💻 Geliştirici

**@BelilusKurucu** tarafından geliştirilmiştir.
