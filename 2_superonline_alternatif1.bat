@echo off
chcp 65001 >nul
title Japon DPI - Superonline (Alternatif 1 - Onerilen)
pushd "%~dp0"

net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [HATA] Yonetici haklari gerekiyor!
    echo Lutfen bu dosyaya sag tiklayip "Yonetici olarak calistir" secin.
    echo.
    pause
    exit /b 1
)

echo [PROFIL] Turkcell Superonline Alternatif 1 (TTL=3 + 2x Fake + Ters SNI Bolme + DNS)
echo.
"%~dp0x86_64\japondpi.exe" --set-ttl 3 --fake-repeats 2 --split-sni --reverse-frag -e 2 -f 2 -r -p --dns-addr 77.88.8.8 --dns-port 1253 --block-dnsv6 --block-quic
echo.
pause
popd
