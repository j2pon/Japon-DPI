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

echo [PROFIL] Genel Evrensel Profil (-5 + Bozuk Checksum/Seq + DNS Yonlendirme + QUIC)
echo.
"%~dp0x86_64\japondpi.exe" -5 --wrong-checksum --wrong-seq --dns-addr 77.88.8.8 --dns-port 1253 --block-dnsv6 --block-quic
echo.
pause
popd
