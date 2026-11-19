@echo off
chcp 65001 >nul
title Japon DPI - Genel Evrensel Profil (Tum ISS)
pushd "%~dp0"

net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [HATA] Yonetici haklari gerekiyor!
    echo Lutfen bu dosyaya sag tiklayip "Yonetici olarak calistir" secin.
    echo.
    pause
    exit /b 1
)

echo [PROFIL] Genel Evrensel Profil (-5 + Bozuk Checksum/Seq + DNS Yonlendirme + QUIC + Port 2053)
ipconfig /flushdns >nul 2>&1
echo.
"%~dp0x86_64\japondpi.exe" -5 --wrong-checksum --wrong-seq --port 2053 --dns-addr 208.67.222.222 --dns-port 443 --block-dnsv6 --block-quic --whitelist "%~dp0whitelist.txt"
echo.
pause
popd
