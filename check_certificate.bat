@echo off
set URL=https://qr.novax-intl.com/

echo Checking HTTPS for %URL% ...
curl -I %URL%
if %errorlevel%==0 (
    echo HTTPS is working!
) else (
    echo HTTPS check failed.
)

pause
