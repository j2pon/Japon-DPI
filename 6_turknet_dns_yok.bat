@echo off
chcp 65001 >nul
title Japon DPI - Turknet / Ozel DNS (DNS Yonlendirmesiz)
pushd "%~dp0"

net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [HATA] Yonetici haklari gerekiyor!
    echo Lutfen bu dosyaya sag tiklayip "Yonetici olarak calistir" secin.
    echo.
    pause
    exit /b 1
)

echo [PROFIL] Turknet / Ozel DNS (Auto-TTL + SNI Bolme + QUIC + Port 2053, DNS degistirilmez)
ipconfig /flushdns >nul 2>&1
echo.
"%~dp0x86_64\japondpi.exe" --auto-ttl --set-ttl 5 --wrong-seq --split-sni -e 2 -f 2 -r -m -p --port 2053 --block-quic --whitelist "%~dp0whitelist.txt"
echo.
pause
popd
