@echo off
chcp 65001 >nul
title Japon DPI - Servis ve Surucuyu Durdur / Kaldir
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [HATA] Yonetici haklari gerekiyor!
    echo Lutfen bu dosyaya sag tiklayip "Yonetici olarak calistir" secin.
    echo.
    pause
    exit /b 1
)

echo [1/4] Calisan Japon DPI islemi kapatiliyor...
taskkill /f /im japondpi.exe >nul 2>&1

echo [2/4] Japon DPI Windows servisi durduruluyor ve siliniyor...
sc stop "JaponDPI" >nul 2>&1
timeout /t 1 /nobreak >nul
sc delete "JaponDPI" >nul 2>&1

echo [3/4] WinDivert cekirdek surucusu durduruluyor ve siliniyor...
sc stop "WinDivert" >nul 2>&1
sc delete "WinDivert" >nul 2>&1
sc stop "WinDivert14" >nul 2>&1
sc delete "WinDivert14" >nul 2>&1

echo [4/4] Windows DNS onbellegi temizleniyor...
ipconfig /flushdns >nul 2>&1

echo.
echo [TAMAM] Japon DPI servisi, calisan sureci ve WinDivert surucusu tamamen kaldirildi.
echo.
pause
