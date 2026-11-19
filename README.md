# Japon DPI v1.1.0

**Japon DPI**, resmi GoodbyeDPI prensibiyle birebir uyumlu çalışan; **%100 açık kaynaklı, saf C11 (x64)** ile yazılmış, sıfır paketleyici (UPX/PyInstaller yok) içeren, ultra hafif (~126 KB) ve yüksek performanslı bir WinDivert 2.2 DPI aşma aracıdır.

---

## Neden Hızlı ve Stabil?

- **Birebir GoodbyeDPI Çalışma Prensibi:** `-5 --set-ttl 5` modunda gelen hiçbir TCP paketi (SYN-ACK/RST/veri) kullanıcı moduna alınmaz; yerel ağ (`192.168/16`, `10/8`, `172.16/12`, `127/8`) çekirdekte hariç tutulur ve QUIC/HTTP3 açık bırakılarak sitelerin 0-RTT hızında açılması sağlanır.
- **Ters Parçalama + `PSH=1` Koruması:** `[2..son)` parçası önce, `[0..2)` parçası sonra gönderilir; hedef sunucu parçaları tek bir bütün `ClientHello` olarak birleştirip uygulamayı tek seferde uyandırır (sıfır ekstra gecikme).
- **Modern Tarayıcı (ML-KEM768) & Whitelist Desteği:** 1400+ baytlık Post-Quantum `ClientHello` paketlerini eksiksiz yakalar, [whitelist.txt](whitelist.txt) ile YouTube/Google/Steam/oyun trafiğine hiç dokunmaz.
- **Sıfır Bellek Sızıntısı:** Paket döngüsünde `malloc`/`free` çağrısı yapılmaz; sabit boyutlu O(1) hash tabloları ile günlerce stabil çalışır.

---

## Hazır Kurulum ve Güvenlik Doğrulaması

`x86_64\` klasöründe gereken tüm dosyalar hazırdır (**Windows Defender dışlamasına gerek kalmadan** çalışır):
- `japondpi.exe` — Saf C11 kaynak kodundan yerel derlenmiş native x64 çalıştırılabilir dosya
- `WinDivert.dll` & `WinDivert64.sys` — Resmi `basil00/WinDivert` **v2.2.0-C** (DigiCert EV + Microsoft WHQL Attestation imzalı, Windows 10/11 Secure Boot uyumlu)

> **Doğrulama:** `x86_64\WinDivert64.sys` dosyasına sağ tıklayıp **Özellikler → Dijital İmzalar** sekmesinden resmi geliştirici ve Microsoft WHQL imzasını doğrulayabilirsiniz. `src\` altındaki kaynak kodları inceleyip `build.bat` ile istediğiniz zaman `japondpi.exe` dosyasını yeniden derleyebilirsiniz.

---

## İnternet Sağlayıcısına Göre Kullanım (.bat Profilleri)

Aşağıdaki `.bat` dosyalarından kendi internet sağlayıcınıza uygun olana **sağ tıklayıp "Yönetici olarak çalıştır"** seçeneğini seçin:

| Dosya | Sağlayıcı / Kullanım | Uygulanan Yöntem |
|---|---|---|
| `1_turk_telekom.bat` | **Türk Telekom / TTNET** | `-5 --set-ttl 5` + Hızlı OpenDNS (`208.67.222.222:443`) + HTTP/3 Açık + Discord Portları + `whitelist.txt` |
| `2_superonline_alternatif1.bat` | **Turkcell Superonline (Önerilen)** | `-5 --set-ttl 3` + Yandex DNS (`77.88.8.8:1253`, IPv4+IPv6) + `whitelist.txt` |
| `3_superonline_alternatif2.bat` | **Turkcell Superonline (Alt. 2)** | `-5` (Auto-TTL) + Yandex DNS (`77.88.8.8:1253`) + `whitelist.txt` |
| `4_superonline_alternatif3.bat` | **Turkcell Superonline (Alt. 3)** | `-9` (Ayrı Wrong-Chksum + Wrong-Seq + Seçici QUIC) + Yandex DNS + `whitelist.txt` |
| `5_kablonet_vodafone.bat` | **Türksat Kablonet & Vodafone Net** | `-5 --set-ttl 5` + Hızlı OpenDNS (`208.67.222.222:443`) + `whitelist.txt` |
| `6_turknet_dns_yok.bat` | **Türknet / Özel DoH DNS** | `-5 --set-ttl 5` (DNS'e dokunmaz) + `whitelist.txt` |
| `7_genel_evrensel.bat` | **Tüm ISS'ler (Evrensel)** | `-9` + Hızlı OpenDNS (`208.67.222.222:443`) + `whitelist.txt` |
| `servis_kaldir.bat` | **Tam Kaldırma** | Çalışan `japondpi.exe`, `JaponDPI` servisi ve `WinDivert` sürücüsünü temizler |

> **İpucu:** İlk denemede hangi `.bat` profilinin sorunsuz açtığını test edin. Siyah pencere açık kaldığı sürece Japon DPI aktif kalır; `Ctrl+C` ile güvenle durdurabilirsiniz.

---

## Arka Planda Otomatik Çalıştırma (Windows Servisi)

Siyah konsol penceresinin sürekli açık kalmasını istemiyorsanız `servis\` klasöründeki kurulum dosyalarını kullanabilirsiniz:

1. Sağlayıcınıza uygun servis kurulum dosyasına sağ tıklayıp **Yönetici olarak çalıştır** deyin (örneğin `servis\servis_kur_turk_telekom.bat` veya `servis\servis_kur_superonline_alt1.bat`).
2. Artık bilgisayar her açıldığında arka planda sessizce otomatik çalışır.
3. Tamamen kaldırmak istediğinizde `servis\servis_kaldir.bat` dosyasını **Yönetici olarak çalıştır**ın (hem `JaponDPI` servisini hem de `WinDivert` çekirdek sürücüsünü temizler).

---

## Oyunlar & Riot Vanguard Notu

- Oyun paketleri (UDP oyun portları, Discord ses portları `50000-65535` ve şifreli oyun TCP akışları) WinDivert çekirdek filtresinden **hiç geçmez**.
- `--block-quic` bayrağı yalnızca doğrulanmış RFC 9000 QUIC v1/v2 `Initial` paketlerini (`UDP:443`, `>=1200 byte`) engeller; VPN, WireGuard veya oyun trafiğine dokunmaz.
- Resmi WHQL imzalı `WinDivert 2.2.2-A` sürücüsü Windows 10/11 Güvenli Önyükleme (Secure Boot) ve HVCI ile uyumludur.

---

## Sık Kullanılan Komut Satırı Parametreleri

Tüm parametre listesi için:
```cmd
x86_64\japondpi.exe --help
```

Dahili paket motoru doğrulama testleri için:
```cmd
x86_64\japondpi.exe --self-test
```

Canlı alan adı günlüğü görmek için profilinizin sonuna `-v` ekleyebilirsiniz:
```cmd
x86_64\japondpi.exe --set-ttl 5 --split-sni --dns-addr 77.88.8.8 --dns-port 1253 --block-quic -v
```
