@echo off
chcp 65001 >nul
title Japon DPI Servis Kurulumu - Turknet (DNS Degistirmeden)
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

echo Japon DPI servisi (Turknet) kuruluyor...
set "WL=%ROOT%\whitelist.txt"
sc create "JaponDPI" binPath= "\"%EXE%\" --service --auto-ttl --set-ttl 5 --wrong-seq --split-sni -e 2 -f 2 -r -m -p --port 2053 --block-quic --whitelist \"%WL%\"" start= "auto" DisplayName= "Japon DPI"
sc description "JaponDPI" "Japon DPI - Turknet Profili (WinDivert 2.2)"
sc start "JaponDPI"
ipconfig /flushdns >nul 2>&1
echo.
echo [TAMAM] Servis kuruldu ve baslatildi. Bilgisayar acilinca otomatik calisacaktir.
pause
