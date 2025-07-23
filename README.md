# 🛡️ BeliZaafiyetAraci

[BelilusKurucu](https://github.com/BelilusKurucu) tarafından geliştirilen **BeliZaafiyetAraci**, gelişmiş bir web zafiyet tarayıcısıdır.  
SQLmap’in güçlü altyapısını örnek alarak geliştirilmiş özel `SQL Injection` modülü ile birlikte gelir.

---

## 🔍 Açıklama

**BeliZaafiyetAracı**, web uygulamalarındaki güvenlik zafiyetlerini tespit etmek amacıyla geliştirilmiş bir Python aracıdır. 
Bu araç sayesinde HTTP başlık zafiyetleri, SQL Injection, XSS açıkları ve dosya yükleme zafiyetleri gibi birçok temel güvenlik sorunlarını test edebilirsiniz.

Yazılım tamamen Türkçe arayüze sahiptir ve terminal üzerinden interaktif olarak çalışır.

---

## ⚙️ Özellikler

- HTTP Güvenlik Başlıkları Analizi
- SQL Injection Testleri (error-based, boolean-based, union-based, time-based)
- SQLmap tarzı modül: DB → Tablo → Sütun → Veri çekme
- XSS Testleri (parametre, form, DOM, JS)
- Dosya Yükleme Zafiyeti Testi (shell ve index yükleme)
- WAF / Rate Limit / Cloudflare Bypass
- Renkli çıktılar (rich kütüphanesi)
- Tekrar eden açıkları filtreleyen çıktı sistemi
- Log kayıt sistemi
- Temiz terminal arayüzü

---

## 💻 Kurulum

Python 3 yüklü olması gereklidir.

```bash
git clone https://github.com/BelilusKurucu/BeliZaafiyetAraci.git
cd BeliZaafiyetAraci
pip install -r requirements.txt
python BeliZaafiyetAraci.py
```

---

## 🧪 Kullanım

Uygulama açıldığında:

```bash
start     # Sistemi başlatır
stop      # Sistemi durdurur
status    # Sistemin mevcut durumunu gösterir
help      # Yardım menüsünü gösterir
exit      # Uygulamadan çıkış yapar
```

### 🧠 SQL Injection Menüsü (sqlmap tarzı)

```bash
sqli      # SQLi modülünü başlatır
```

Açılan menü:
```
 [1] Açıkları Tara
 [2] Veritabanlarını Listele
 [3] Tabloları Listele
 [4] Sütunları Listele
 [5] Verileri Çek
 [0] Ana menüye dön
```

---

## 📁 Gereksinimler

- `requests`
- `beautifulsoup4`
- `rich`

```bash
pip install -r requirements.txt
```

---

## ⚠️ Uyarı

Bu yazılım sadece **eğitim** ve **güvenlik testleri** amacıyla kullanılmalıdır. Yetkisiz sistemlerde kullanmak **yasadışıdır** ve etik dışıdır.

---

## 👨‍💻 Geliştirici

**BelilusKurucu**  
📬 Telegram: [@BelilusKurucu](https://t.me/BelilusKurucu)