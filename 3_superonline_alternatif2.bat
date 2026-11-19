@echo off
chcp 65001 >nul
title Japon DPI - Superonline (Alternatif 2 - Wrong-Seq + 3-Parcali)
pushd "%~dp0"

net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [HATA] Yonetici haklari gerekiyor!
    echo Lutfen bu dosyaya sag tiklayip "Yonetici olarak calistir" secin.
    echo.
    pause
    exit /b 1
)

echo [PROFIL] Turkcell Superonline Alternatif 2 (Wrong-Seq + 3-Parcali Ters Bolme + DNS + Port 2053)
ipconfig /flushdns >nul 2>&1
echo.
"%~dp0x86_64\japondpi.exe" --wrong-seq --fake-repeats 2 --multi-split --reverse-frag -e 2 -f 2 -r -p --port 2053 --dns-addr 77.88.8.8 --dns-port 1253 --block-dnsv6 --block-quic
echo.
pause
popd
