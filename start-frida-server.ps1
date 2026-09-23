# 启动雷电模拟器里的 frida-server（root）。用法： powershell -File start-frida-server.ps1
$adb = "D:\leidian\LDPlayer9\adb.exe"
$dev = "emulator-5554"
Write-Host "[*] devices:"; & $adb devices
& $adb -s $dev shell "su -c 'chmod 755 /data/local/tmp/frida-server'"
& $adb -s $dev shell "su -c 'nohup /data/local/tmp/frida-server >/dev/null 2>&1 &'"
Start-Sleep -Seconds 3
Write-Host "[*] frida-server process:"; & $adb -s $dev shell "su -c 'ps -A | grep frida'"
Write-Host "[*] host frida-ps -U (first 5):"
& "D:\逆向\逆向学习\tools\venv\Scripts\frida-ps.exe" -U 2>&1 | Select-Object -First 6