@echo off
chcp 65001 >nul
title Japon DPI Servis Kurulumu - Superonline Alternatif 4
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [HATA] Yonetici haklari gerekiyor! Sag tiklayip "Yonetici olarak calistir" secin.
    pause
    exit /b 1
)

for %%I in ("%~dp0..") do set "ROOT=%%~fI"
set "EXE=%ROOT%\x86_64\japondpi.exe"

if not exist "%ROOT%\x86_64\WinDivert.dll" (
    echo [HATA] x86_64 klasorunde WinDivert.dll bulunamadi!
    pause
    exit /b 1
)
if not exist "%ROOT%\x86_64\WinDivert64.sys" (
    echo [HATA] x86_64 klasorunde WinDivert64.sys bulunamadi!
    pause
    exit /b 1
)

echo Eski servis temizleniyor...
taskkill /f /im japondpi.exe >nul 2>&1
sc stop "JaponDPI" >nul 2>&1
timeout /t 1 /nobreak >nul
sc delete "JaponDPI" >nul 2>&1

echo Japon DPI servisi (Superonline Alternatif 4) kuruluyor...
sc create "JaponDPI" binPath= "\"%EXE%\" --service -5 --dns-addr 77.88.8.8 --dns-port 1253 --dnsv6-addr 2a02:6b8::feed:0ff --dnsv6-port 1253" start= "auto" DisplayName= "Japon DPI"
sc description "JaponDPI" "Japon DPI - Superonline Alternatif 4 (WinDivert 2.2)"
sc start "JaponDPI"
ipconfig /flushdns >nul 2>&1
echo.
echo [TAMAM] Superonline Alternatif 4 servisi kuruldu ve baslatildi.
pause
