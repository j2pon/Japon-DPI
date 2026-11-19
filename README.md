# Japon DPI v1.0.0

**Japon DPI**, GoodbyeDPI prensibiyle çalışan, **%100 açık kaynaklı, saf C (x64)** ile yazılmış, sıfır paketleyici (UPX/PyInstaller yok) içeren, ultra hafif (~84 KB) ve yüksek performanslı bir WinDivert 2.2 DPI aşma aracıdır.

---

## Neden Hızlı ve Stabil?

- **Çekirdek Düzeyinde Akıllı Filtreleme:** WinDivert filtresi yalnızca TLS `ClientHello` el sıkışma paketlerini (`0x16 0x03 ... 0x01`), HTTP başlık isteklerini ve (açıksa) UDP:53 DNS sorgularını yakalar. Video akışları, dosya indirmeleri, Discord ses paketleri ve oyun trafiği kullanıcı moduna hiç taşınmaz — **0 ms ping artışı, 0 hız kaybı**.
- **Modern Tarayıcı / Post-Quantum (ML-KEM768) Uyumlu:** Chrome, Brave, Edge ve Firefox'un 1400+ baytlık yeni nesil TLS ClientHello paketlerini eksiksiz yakalar ve LSO/TSO güvenli parçalama yapar.
- **Sıfır Bellek Sızıntısı:** Paket döngüsünde tek bir `malloc`/`free` çağrısı bile yapılmaz; sabit boyutlu O(1) hash tabloları ile günlerce stabil çalışır.
- **Şeffaf ve Denetlenebilir:** Tüm kaynak kod `src\` klasöründedir; `build.bat` ile istediğiniz zaman kendiniz yeniden derleyebilirsiniz.

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
| `1_turk_telekom.bat` | **Türk Telekom / TTNET** | TTL=5 Sahte Paket + SNI Ortası Bölme + IPv4/IPv6 DNS (`77.88.8.8:1253`) + QUIC |
| `2_superonline_alternatif1.bat` | **Turkcell Superonline (Önerilen)** | TTL=3 + 2x Sahte Paket + Ters Sıralı SNI Bölme + DNS (`77.88.8.8:1253`) + IPv6 DNS Engeli |
| `3_superonline_alternatif2.bat` | **Turkcell Superonline (Alt. 2)** | Wrong-Seq + 2x Sahte Paket + 3-Parçalı Ters Bölme + DNS (Bölgesel hop farkları için) |
| `4_superonline_alternatif3.bat` | **Turkcell Superonline (Alt. 3)** | TTL=5 + Wrong-Seq + 3-Parçalı Ters Bölme + DNS (Fiber/Farklı BRAS için) |
| `5_kablonet_vodafone.bat` | **Türksat Kablonet & Vodafone Net** | Auto-TTL (Otomatik Hop Ölçümü) + Ters SNI Bölme + IPv4/IPv6 DNS + QUIC |
| `6_turknet_dns_yok.bat` | **Türknet / Özel DoH DNS** | Auto-TTL + SNI Bölme + QUIC (Sistem DNS ayarınıza dokunmaz) |
| `7_genel_evrensel.bat` | **Tüm ISS'ler (Evrensel)** | `-5` + Bozuk Checksum + Wrong-Seq + DNS Yönlendirme + QUIC |

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
