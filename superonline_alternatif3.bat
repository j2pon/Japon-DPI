@echo off
chcp 65001 >nul
title Japon DPI - Superonline Alternatif 3 (TTL=3 + Yandex DNS)
pushd "%~dp0"

net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [HATA] Yonetici haklari gerekiyor!
    echo Lutfen bu dosyaya sag tiklayip "Yonetici olarak calistir" secin.
    echo.
    pause
    exit /b 1
)

echo [PROFIL] Superonline Alternatif 3 (--set-ttl 3 + Yandex DNS:1253 IPv4/IPv6)
echo.
"%~dp0x86_64\japondpi.exe" --set-ttl 3 --dns-addr 77.88.8.8 --dns-port 1253 --dnsv6-addr 2a02:6b8::feed:0ff --dnsv6-port 1253
echo.
pause
popd
