@echo off
chcp 65001 >nul
title Japon DPI - Turk Telekom / TTNET
pushd "%~dp0"

net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [HATA] Yonetici haklari gerekiyor!
    echo Lutfen bu dosyaya sag tiklayip "Yonetici olarak calistir" secin.
    echo.
    pause
    exit /b 1
)

echo [PROFIL] Turk Telekom / TTNET (TTL=5 + SNI Bolme + IPv4/IPv6 DNS Yonlendirme + QUIC)
echo.
"%~dp0x86_64\japondpi.exe" --set-ttl 5 --split-sni -e 2 -f 2 -r -m -p --dns-addr 77.88.8.8 --dns-port 1253 --dnsv6-addr 2a02:6b8::feed:0ff --dnsv6-port 1253 --block-quic
echo.
pause
popd
