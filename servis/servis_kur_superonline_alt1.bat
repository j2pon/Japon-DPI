@echo off
chcp 65001 >nul
title Japon DPI Servis Kurulumu - Superonline (Alternatif 1)
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [HATA] Yonetici haklari gerekiyor! Sag tiklayip "Yonetici olarak calistir" secin.
    pause
    exit /b 1
)

for %%I in ("%~dp0..") do set "ROOT=%%~fI"
set "EXE=%ROOT%\x86_64\japondpi.exe"

if not exist "%ROOT%\x86_64\WinDivert.dll" (
    echo [HATA] x86_64 klasorunde WinDivert.dll bulunamadi! Once README.md adimlarini izleyin.
    pause
    exit /b 1
)
if not exist "%ROOT%\x86_64\WinDivert64.sys" (
    echo [HATA] x86_64 klasorunde WinDivert64.sys bulunamadi! Once README.md adimlarini izleyin.
    pause
    exit /b 1
)

echo Eski servis temizleniyor...
sc stop "JaponDPI" >nul 2>&1
timeout /t 1 /nobreak >nul
sc delete "JaponDPI" >nul 2>&1

echo Japon DPI servisi (Superonline Alternatif 1) kuruluyor...
set "WL=%ROOT%\whitelist.txt"
sc create "JaponDPI" binPath= "\"%EXE%\" --service --set-ttl 3 --fake-repeats 2 --split-sni --reverse-frag -e 2 -f 2 -r -p --port 2053 --port 2083 --port 2087 --port 2096 --port 8443 --dns-addr 77.88.8.8 --dns-port 1253 --block-dnsv6 --block-quic --whitelist \"%WL%\"" start= "auto" DisplayName= "Japon DPI"
sc description "JaponDPI" "Japon DPI - Superonline Profili 1 (WinDivert 2.2)"
sc start "JaponDPI"
ipconfig /flushdns >nul 2>&1
echo.
echo [TAMAM] Servis kuruldu ve baslatildi. Bilgisayar acilinca otomatik calisacaktir.
pause
