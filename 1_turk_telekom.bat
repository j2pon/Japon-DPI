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

echo [PROFIL] Turk Telekom / TTNET (Auto-TTL + Wrong-Seq + Ters SNI + Hizli OpenDNS:443 + YouTube Whitelist)
ipconfig /flushdns >nul 2>&1
echo.
"%~dp0x86_64\japondpi.exe" --auto-ttl --set-ttl 5 --wrong-seq --split-sni --reverse-frag -e 2 -f 2 -r -m -p --port 2053 --dns-addr 208.67.222.222 --dns-port 443 --block-dnsv6 --block-quic --whitelist "%~dp0whitelist.txt"
echo.
pause
popd
