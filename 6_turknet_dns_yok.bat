@echo off
chcp 65001 >nul
title Japon DPI - Turknet / Ozel DNS (DNS Degistirmeden)
pushd "%~dp0"

net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [HATA] Yonetici haklari gerekiyor!
    echo Lutfen bu dosyaya sag tiklayip "Yonetici olarak calistir" secin.
    echo.
    pause
    exit /b 1
)

echo [PROFIL] Turknet / Ozel DNS (GoodbyeDPI -5 --set-ttl 5, DNS degistirilmez)
echo.
"%~dp0x86_64\japondpi.exe" -5 --set-ttl 5 --port 2053 --port 2083 --port 2087 --port 2096 --port 8443 --whitelist "%~dp0whitelist.txt"
echo.
pause
popd
