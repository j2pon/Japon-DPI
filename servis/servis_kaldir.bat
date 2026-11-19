@echo off
chcp 65001 >nul
title Japon DPI - Servis ve Surucu Kaldir
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [HATA] Yonetici haklari gerekiyor! Sag tiklayip "Yonetici olarak calistir" secin.
    pause
    exit /b 1
)

echo Japon DPI servisi durduruluyor ve siliniyor...
sc stop "JaponDPI" >nul 2>&1
timeout /t 1 /nobreak >nul
sc delete "JaponDPI" >nul 2>&1

echo WinDivert cekirdek surucusu durduruluyor ve temizleniyor...
sc stop "WinDivert" >nul 2>&1
sc delete "WinDivert" >nul 2>&1
sc stop "WinDivert14" >nul 2>&1
sc delete "WinDivert14" >nul 2>&1

echo.
echo [TAMAM] Japon DPI servisi ve WinDivert surucusu sistemden temizlendi.
pause
