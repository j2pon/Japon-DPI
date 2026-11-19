@echo off
chcp 65001 >nul
title Japon DPI - Superonline (Alternatif 3 - Agresif -9)
pushd "%~dp0"

net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [HATA] Yonetici haklari gerekiyor!
    echo Lutfen bu dosyaya sag tiklayip "Yonetici olarak calistir" secin.
    echo.
    pause
    exit /b 1
)

echo [PROFIL] Turkcell Superonline Alternatif 3 (GoodbyeDPI -9 + Yandex DNS:1253)
echo.
"%~dp0x86_64\japondpi.exe" -9 --port 2053 --port 2083 --port 2087 --port 2096 --port 8443 --dns-addr 77.88.8.8 --dns-port 1253 --dnsv6-addr 2a02:6b8::feed:0ff --dnsv6-port 1253 --whitelist "%~dp0whitelist.txt"
echo.
pause
popd
