@echo off
chcp 65001 >nul
title Japon DPI - Kaynak Koddan Derleme
pushd "%~dp0"

where gcc >nul 2>&1
if %errorlevel% neq 0 (
    echo [HATA] PATH icinde 'gcc' bulunamadi.
    echo Yeniden derlemek icin w64devkit (https://github.com/skeeto/w64devkit/releases)
    echo veya MinGW-w64 (winget install BrechtSanders.WinLibs.POSIX.UCRT) kurabilirsiniz.
    pause
    exit /b 1
)

if not exist "x86_64" mkdir "x86_64"

echo [1/3] Surum bilgisi derleniyor...
windres src\version.rc -O coff -o src\version.res
if %errorlevel% neq 0 (
    echo [HATA] windres basarisiz oldu.
    pause
    exit /b 1
)

echo [2/3] japondpi.exe derleniyor (Saf C11, -O2, Sifir Paketleyici)...
gcc -std=c11 -O2 -Wall -Wextra -Werror ^
    src\main.c src\wd_loader.c src\fake_payloads.c src\ttl_cache.c ^
    src\dns_redir.c src\domain_list.c src\dpi_engine.c src\service.c ^
    src\version.res ^
    -o x86_64\japondpi.exe ^
    -lws2_32 -ladvapi32 -static-libgcc -s

set "RC=%errorlevel%"
del /f /q src\version.res >nul 2>&1

if %RC% neq 0 (
    echo [HATA] Derleme basarisiz oldu!
    pause
    exit /b 1
)

echo [3/3] Dahili birim testleri calistiriliyor...
x86_64\japondpi.exe --self-test
echo.
echo [TAMAM] x86_64\japondpi.exe basariyla derlendi!
pause
popd
