<div align="center">

### 🇹🇷 Turkhackteam.org İthafı
*Bu proje, Türkiye'nin en köklü siber güvenlik ve bilişim platformu olan **Turkhackteam.org** topluluğuna adanmıştır. Bilgiye ve açık kaynaklı istihbarata verdiğimiz değer, THT misyonunun bir parçasıdır.*

[![Turkhackteam](https://img.shields.io/badge/Official-Turkhackteam.org-red.svg)](https://www.turkhackteam.org)

</div>

# AI_AGENT_OSINT
Bu araç bir ajan beyni ile gizli taramalar yapar ve istihbari düzeyde hem açık hem kapalı kaynaklı istihbarat toplar
# 🦅 Cyber-Eagle OSINT Intelligence Framework

[![Python](https://img.shields.io/badge/Python-3.x-blue.svg)](https://www.python.org/)
[![OSINT](https://img.shields.io/badge/Domain-OSINT-red.svg)]()
[![Status](https://img.shields.io/badge/Status-Active-brightgreen.svg)]()
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)]()

**Cyber-Eagle**, siber güvenlik analistleri ve araştırmacılar için tasarlanmış, modüler, hızlı ve akıllı bir **Açık Kaynak İstihbaratı (OSINT)** framework'üdür. API anahtarlarıyla uğraşmadan, pasif tekniklerle hedef analizi yapmanızı sağlar.

---

### 🚀 Özellikler
- **Asenkron Motor:** `aiohttp` ile aynı anda onlarca siteyi tarama gücü.
- **Akıllı Heuristics:** Kullanıcı adı varyasyonlarını otomatik türetme.
- **Stealth Mode:** Gerçekçi tarayıcı başlıkları ile gizli çalışma.
- **Gelişmiş Raporlama:** Sonuçları JSON formatında ve şık terminal tablolarıyla analiz etme.
- **Modüler Mimari:** Yeni tarayıcılar eklemeye uygun altyapı.

### 🛠 Kurulum
Termux veya Linux terminalinize şu komutları girin:

```bash
git clone [https://github.com/ThT0AltayHR/AI_AGENT_OSINT.git](https://github.com/ThT0AltayHR/AI_AGENT_OSINT.git)
cd AI_AGENT_OSINT
pip install -r requirements.txt
💻 Kullanım
# Kullanıcı adı taraması
python cyber_eagle_standalone.py -k <kullanici_adi>

# Dork araması
python cyber_eagle_standalone.py -d <sorgu>

# Domain istihbaratı
python cyber_eagle_standalone.py --domain example.com

# Tam kapsamlı tarama
python cyber_eagle_standalone.py --full <hedef>
🛡 Disclaimer (Yasal Uyarı)
Bu yazılım, yalnızca eğitim ve güvenlik araştırması amaçlı geliştirilmiştir. Kullanıcı, bu aracı kullanarak yaptığı tüm işlemlerden bizzat sorumludur. Hedef sistemler üzerinde izinsiz tarama yapmak veya gizlilik ihlali oluşturacak eylemlerde bulunmak yasalara aykırı olabilir. Cyber-Eagle, asla kötü niyetli faaliyetler için kullanılamaz. Yazılımı kullanmadan önce yasal mevzuatları okuduğunuzdan emin olun.
Geliştirici: ThT0AltayHR | 🦅 Cyber-Eagle Project
