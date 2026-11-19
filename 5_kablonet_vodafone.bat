@echo off
chcp 65001 >nul
title Japon DPI - Kablonet & Vodafone Net
pushd "%~dp0"

net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [HATA] Yonetici haklari gerekiyor!
    echo Lutfen bu dosyaya sag tiklayip "Yonetici olarak calistir" secin.
    echo.
    pause
    exit /b 1
)

echo [PROFIL] Turksat Kablonet / Vodafone Net (Auto-TTL + Ters SNI Bolme + DNS + Port 2053)
ipconfig /flushdns >nul 2>&1
echo.
"%~dp0x86_64\japondpi.exe" --auto-ttl --set-ttl 5 --split-sni --reverse-frag -e 2 -f 2 -r -m -p --port 2053 --dns-addr 77.88.8.8 --dns-port 1253 --dnsv6-addr 2a02:6b8::feed:0ff --dnsv6-port 1253 --block-quic
echo.
pause
popd
