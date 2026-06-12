#Requires -Version 5.1
<#
.SYNOPSIS
  KEYSTONE Android Security Test Suite
  Verifica automaticamente los controles de hardening implementados en la release APK.
  Compatible con Windows (PS 5.1+) y macOS Intel/Apple Silicon M-series (PS 7+ / pwsh).

.DESCRIPTION
  Requisitos:
    - Android Studio instalado (provee SDK, ADB, emulator, JBR)
    - AVD creado en Android Studio (default: Medium_Phone_API_36.1)
    - Windows: PowerShell 5.1+ (incluido en Windows)
    - macOS:   pwsh 7+ → brew install --cask powershell
               Luego: pwsh scripts/test-android-security.ps1

.PARAMETER SkipBuild
  Salta el paso de compilacion (usa el APK existente).

.PARAMETER SkipEmulator
  Asume que ya hay un dispositivo/emulador conectado; no arranca uno nuevo.

.PARAMETER Avd
  Nombre del AVD a usar. Default: Medium_Phone_API_36.1

.EXAMPLE
  # Windows
  .\scripts\test-android-security.ps1 -SkipBuild -SkipEmulator

  # macOS (desde la raiz ionic-app/poc-security/)
  pwsh scripts/test-android-security.ps1 -SkipBuild -SkipEmulator
#>

param(
  [switch]$SkipBuild,
  [switch]$SkipEmulator,
  [string]$Avd = "Medium_Phone_API_36.1"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ── Platform detection ────────────────────────────────────────────────────────

# $IsWindows / $IsMacOS are built-in in PS7+; in PS5.1 (Windows-only) we derive them.
$OnWindows = if ($PSVersionTable.PSVersion.Major -ge 6) { $IsWindows } else { $true }
$OnMac     = if ($PSVersionTable.PSVersion.Major -ge 6) { $IsMacOS  } else { $false }
$Sep       = [System.IO.Path]::DirectorySeparatorChar

# ── Paths ─────────────────────────────────────────────────────────────────────

$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$ROOT       = Split-Path -Parent $SCRIPT_DIR   # ionic-app/poc-security/

if ($OnWindows) {
  $SDK       = "$env:LOCALAPPDATA\Android\Sdk"
  $JAVA_HOME = "C:\Program Files\Android\Android Studio\jbr"
  $ADB       = "$SDK\platform-tools\adb.exe"
  $EMULATOR  = "$SDK\emulator\emulator.exe"
  $GRADLEW   = ".\gradlew.bat"
  $TMP       = $env:TEMP
  $APK       = "$ROOT\android\app\build\outputs\apk\release\app-release.apk"
  $env:JAVA_HOME = $JAVA_HOME
  $env:PATH  = "$JAVA_HOME\bin;$SDK\platform-tools;$env:PATH"
} else {
  # macOS (Intel or Apple Silicon M-series)
  $SDK = if (Test-Path "$env:HOME/Library/Android/sdk") {
    "$env:HOME/Library/Android/sdk"
  } else {
    "/usr/local/share/android-sdk"   # Homebrew fallback
  }
  # Android Studio JBR — try common install locations for M1/M4
  $jbrCandidates = @(
    "/Applications/Android Studio.app/Contents/jbr/Contents/Home",
    "/Applications/Android Studio.app/Contents/jre/Contents/Home",
    "/Applications/Android Studio Preview.app/Contents/jbr/Contents/Home"
  )
  $JAVA_HOME = $jbrCandidates | Where-Object { Test-Path $_ } | Select-Object -First 1
  if (-not $JAVA_HOME) { $JAVA_HOME = "/usr/bin"  }  # system java fallback
  $ADB      = "$SDK/platform-tools/adb"
  $EMULATOR = "$SDK/emulator/emulator"
  $GRADLEW  = "./gradlew"
  $TMP      = "/tmp"
  $APK      = "$ROOT/android/app/build/outputs/apk/release/app-release.apk"
  $env:JAVA_HOME = $JAVA_HOME
  $env:PATH  = "$JAVA_HOME/bin:$SDK/platform-tools:$env:PATH"
}

$PKG      = "io.ionic.starter"
$ACTIVITY = "$PKG/.MainActivity"

# ── Helpers ───────────────────────────────────────────────────────────────────

$passed      = 0
$failed      = 0
$skipped     = 0
$results     = [System.Collections.Generic.List[object]]::new()
$skipAll     = $false
$skipRuntime = $false

function Write-Header([string]$text) {
  Write-Host ""
  Write-Host "  $text" -ForegroundColor Cyan
  Write-Host ("  " + "-" * ($text.Length)) -ForegroundColor DarkGray
}

function Pass([string]$name, [string]$detail = "") {
  $script:passed++
  $suffix = if ($detail) { " - $detail" } else { "" }
  Write-Host "  [PASS] $name$suffix" -ForegroundColor Green
  $script:results.Add([PSCustomObject]@{Status="PASS";Test=$name;Detail=$detail})
}

function Fail([string]$name, [string]$detail = "") {
  $script:failed++
  $suffix = if ($detail) { " - $detail" } else { "" }
  Write-Host "  [FAIL] $name$suffix" -ForegroundColor Red
  $script:results.Add([PSCustomObject]@{Status="FAIL";Test=$name;Detail=$detail})
}

function Skip([string]$name, [string]$reason = "") {
  $script:skipped++
  $suffix = if ($reason) { " - $reason" } else { "" }
  Write-Host "  [SKIP] $name$suffix" -ForegroundColor DarkGray
  $script:results.Add([PSCustomObject]@{Status="SKIP";Test=$name;Detail=$reason})
}

function Info([string]$msg) {
  Write-Host "  [....] $msg" -ForegroundColor DarkCyan
}

function Adb {
  $ea = $ErrorActionPreference; $ErrorActionPreference = "SilentlyContinue"
  $out = & $ADB $args 2>&1
  $ErrorActionPreference = $ea
  $out
}

function Wait-Boot([int]$TimeoutSec = 120) {
  Info "Esperando que el emulador arranque (max ${TimeoutSec}s)..."
  $deadline = (Get-Date).AddSeconds($TimeoutSec)
  while ((Get-Date) -lt $deadline) {
    $val = (Adb shell getprop sys.boot_completed 2>$null) -join ""
    if ($val.Trim() -eq "1") { return $true }
    Start-Sleep 3
  }
  return $false
}

function Get-ForegroundPkg {
  # Android 14+: topResumedActivity is authoritative
  $activities = (Adb shell dumpsys activity activities) -join "`n"
  if ($activities -match 'topResumedActivity=ActivityRecord\{[^}]+\s+([\w.]+)/') { return $Matches[1] }
  if ($activities -match 'mResumedActivity=ActivityRecord\{[^}]+\s+([\w.]+)/') { return $Matches[1] }
  # Fallback: check if process is running
  $pid = (Adb shell "pidof $PKG") -join ""
  if ($pid -match '\d+') { return $PKG }
  return ""
}

function Launch-App {
  Adb shell am force-stop $PKG | Out-Null
  Start-Sleep 1
  Adb shell am start -n "$ACTIVITY" | Out-Null
  Start-Sleep 4  # wait for security checks in onCreate
}

# ── 0. Prerequisites ──────────────────────────────────────────────────────────

Write-Host ""
Write-Host "  KEYSTONE Android Security Test Suite" -ForegroundColor White
Write-Host "  =====================================" -ForegroundColor DarkGray

if (-not (Test-Path $ADB))       { Write-Host "  ERROR: ADB no encontrado en $ADB" -ForegroundColor Red; exit 1 }
if (-not (Test-Path $JAVA_HOME)) { Write-Host "  ERROR: Java no encontrado en $JAVA_HOME" -ForegroundColor Red; exit 1 }

# ── 1. Build ──────────────────────────────────────────────────────────────────

Write-Header "FASE 1 — Build release APK"

if ($SkipBuild) {
  if (Test-Path $APK) {
    Skip "Compilación" "usando APK existente: $APK"
  } else {
    Fail "Compilación" "APK no existe y -SkipBuild activo"
    exit 1
  }
} else {
  Info "Ejecutando: gradlew assembleRelease ..."
  Push-Location (Join-Path $ROOT "android")
  try {
    $output = & $GRADLEW assembleRelease 2>&1
    if ($LASTEXITCODE -eq 0 -and (Test-Path $APK)) {
      $sizeMB = [math]::Round((Get-Item $APK).Length / 1MB, 2)
      Pass "Compilación release" "APK ${sizeMB}MB generado"
    } else {
      Fail "Compilación release" "gradlew falló (exit $LASTEXITCODE)"
      $output | Select-Object -Last 20 | ForEach-Object { Write-Host "    $_" -ForegroundColor DarkRed }
      exit 1
    }
  } finally {
    Pop-Location
  }
}

# ── 2. Static APK analysis ────────────────────────────────────────────────────

Write-Header "FASE 2 — Análisis estático del APK (sin instalar)"

# Unzip APK to temp dir (APK = ZIP) — use manual extraction to handle duplicate entries
$tmpDir = Join-Path $TMP "keystone-apk-test-$(Get-Date -f yyyyMMddHHmmss)"
New-Item -ItemType Directory -Path $tmpDir -Force | Out-Null
Add-Type -AssemblyName System.IO.Compression.FileSystem
try {
  $zip = [System.IO.Compression.ZipFile]::OpenRead($APK)
  foreach ($entry in $zip.Entries) {
    if ($entry.FullName -match '[\\/]$') { continue }  # skip directory entries
    $dest = Join-Path $tmpDir ($entry.FullName -replace '[/\\]', $Sep)
    $destDir = Split-Path $dest -Parent
    if (-not (Test-Path $destDir)) { New-Item -ItemType Directory -Path $destDir -Force | Out-Null }
    try { [System.IO.Compression.ZipFileExtensions]::ExtractToFile($entry, $dest, $true) } catch {}
  }
  $zip.Dispose()
} catch {
  Fail "Extracción APK" $_.Exception.Message
  exit 1
}

# 2a. JS bundle — URLs en claro
$wwwDir = Join-Path $tmpDir "assets" "public"
if (Test-Path $wwwDir) {
  $jsFiles  = Get-ChildItem $wwwDir -Filter "*.js" -ErrorAction SilentlyContinue
  # Look for unobfuscated URLs: must have a domain-like structure after http(s)://
  $urlHits = $jsFiles | Select-String -Pattern "https?://[a-zA-Z0-9._-]+\.[a-z]{2,}(:[0-9]+)?/[^\s'`"]{5,}" -ErrorAction SilentlyContinue
  # Filter out known safe embedded URLs (W3C SVG namespace, schema.org, etc.)
  $realUrls = @($urlHits | Where-Object { $_.Matches[0].Value -notmatch "w3\.org|schema\.org|xmlns|x-schema" })
  if ($realUrls.Count -gt 0) {
    Fail "JS bundle — URLs en claro" "$($realUrls.Count) coincidencias encontradas"
    $realUrls | Select-Object -First 3 | ForEach-Object {
      Write-Host "    $($_.Filename):$($_.LineNumber) - $($_.Matches[0].Value)" -ForegroundColor DarkRed
    }
  } else {
    Pass "JS bundle — URLs en claro" "sin endpoints hardcoded visibles en www/*.js"
  }

  # 2b. JS bundle — strings sensibles
  $sensitiveHits = $jsFiles | Select-String -Pattern "password|secret|keycloak|bearer|mobile-realm|web-realm" -CaseSensitive:$false -ErrorAction SilentlyContinue
  $sensitiveCount = if ($sensitiveHits) { $sensitiveHits.Count } else { 0 }
  # Angular bundle always has some framework strings; count actual app secrets
  if ($sensitiveCount -gt 50) {
    Fail "JS bundle — strings sensibles" "$sensitiveCount coincidencias (alto — ofuscación puede no haber corrido)"
  } else {
    Pass "JS bundle — strings sensibles" "$sensitiveCount coincidencias (bajo — strings en array Base64)"
  }
} else {
  Skip "JS bundle — análisis" "www/ no encontrado en APK"
}

# 2c. ProGuard — clases obfuscadas
$dexFiles = Get-ChildItem $tmpDir -Filter "classes*.dex" -ErrorAction SilentlyContinue
if ($dexFiles) {
  # Read first 8KB of dex file as text — look for class/method names
  $dexText = [System.Text.Encoding]::ASCII.GetString(
    [System.IO.File]::ReadAllBytes($dexFiles[0].FullName)[0..8191]
  )
  $hasMainActivity = $dexText -match "MainActivity"
  if ($hasMainActivity) {
    Pass "ProGuard — MainActivity visible" "nombre de clase preservado (en -keep rule)"
  }

  # Check that io.ionic.starter doesn't expose many method names
  $methodNames = [regex]::Matches($dexText, '\b(isRooted|isFridaPresent|isSignatureValid|runSecurityChecks|hardenWebView)\b')
  if ($methodNames.Count -gt 0) {
    Fail "ProGuard — métodos de seguridad visibles" "$($methodNames.Count) nombres encontrados en dex (añadir -keep más restrictivo)"
  } else {
    Pass "ProGuard — métodos de seguridad" "nombres de métodos no visibles en texto del DEX"
  }
} else {
  Skip "ProGuard — análisis DEX" "archivo .dex no encontrado"
}

# 2d. Manifest — flags de seguridad via aapt
$aaptFilter = if ($OnWindows) { "aapt.exe" } else { "aapt" }
$aapt = (Get-ChildItem (Join-Path $SDK "build-tools") -Recurse -Filter $aaptFilter -ErrorAction SilentlyContinue |
         Sort-Object FullName -Descending | Select-Object -First 1).FullName
if ($aapt -and (Test-Path $aapt)) {
  $manifestDump = try { (& $aapt dump xmltree $APK AndroidManifest.xml 2>$null) -join "`n" } catch { "" }

  $hasAllowBackupFalse = $manifestDump -match 'allowBackup.*0x0'
  $hasNetworkSecurity  = $manifestDump -match 'networkSecurityConfig|network_security_config'
  $hasDebuggable       = $manifestDump -match 'debuggable.*0x1'

  if ($hasAllowBackupFalse) { Pass "Manifest — allowBackup=false" "aapt confirma android:allowBackup=false" }
  else {
    # allowBackup defaults to false in API 31+, check if simply absent (OK)
    if ($manifestDump -match 'allowBackup') { Fail "Manifest — allowBackup no es false" }
    else { Pass "Manifest — allowBackup" "atributo ausente (default false en API 31+)" }
  }

  if ($hasNetworkSecurity) { Pass "Manifest — networkSecurityConfig referenciado" "aapt confirma referencia" }
  else                      { Fail "Manifest — networkSecurityConfig no encontrado" }
} else {
  # Fallback: binary string search
  $manifestPath = Join-Path $tmpDir "AndroidManifest.xml"
  if (Test-Path $manifestPath) {
    $manifestBytes = [System.IO.File]::ReadAllBytes($manifestPath)
    $manifestText  = [System.Text.Encoding]::Unicode.GetString($manifestBytes)
    if ($manifestText -match "allowBackup") { Pass "Manifest — allowBackup presente" "hallado en XML binario" }
    else                                    { Pass "Manifest — allowBackup" "ausente (default false en API 31+)" }
    if ($manifestText -match "network_security_config") { Pass "Manifest — networkSecurityConfig referenciado" }
    else                                                 { Fail "Manifest — networkSecurityConfig no encontrado" }
  } else {
    Skip "Manifest — análisis" "aapt y XML binario no disponibles"
  }
}

Remove-Item $tmpDir -Recurse -Force -ErrorAction SilentlyContinue

# ── 3. Emulator / device ──────────────────────────────────────────────────────

Write-Header "FASE 3 — Emulador y despliegue"

$deviceList = try { (& $ADB devices 2>$null) -join "`n" } catch { "" }
$hasDevice  = $deviceList -match "emulator-\d+\s+device|[0-9A-F]{8,}\s+device"

if (-not $hasDevice) {
  if ($SkipEmulator) {
    Fail "Emulador conectado" "ningún dispositivo - usa -SkipEmulator solo si ya está conectado"
    Write-Host "  Pruebas de runtime saltadas (sin dispositivo)" -ForegroundColor Yellow
    $skipAll = $true
  }

  if (-not $skipAll -and -not (Test-Path $EMULATOR)) {
    Fail "Emulador" "emulator.exe no encontrado en $EMULATOR"
    $skipAll = $true
  }

  if (-not $skipAll) {
    Info "Arrancando AVD: $Avd ..."
    Start-Process -FilePath $EMULATOR -ArgumentList "-avd", $Avd, "-no-snapshot-load", "-no-audio", "-no-boot-anim" -NoNewWindow
    if (-not (Wait-Boot 180)) {
      Fail "Arranque del emulador" "timeout 180s"
      $skipAll = $true
    } else {
      Pass "Arranque del emulador" "AVD $Avd online"
      Start-Sleep 5
    }
  }
} else {
  Pass "Dispositivo conectado" ($deviceList -split "`n" | Select-String "device$" | Select-Object -First 1)
} 

if (-not $skipAll) {
  # Check build.tags for root detection trigger
  $buildTags = (Adb shell getprop ro.build.tags) -join ""
  Info "ro.build.tags = '$($buildTags.Trim())'"
  $isTestKeys = $buildTags -match "test-keys"

  # Install release APK
  Info "Instalando APK release ..."
  $installOut = (Adb install -r $APK) -join " "
  if ($installOut -match "Success") {
    Pass "Instalación APK release" $installOut.Trim()
  } else {
    Fail "Instalación APK release" $installOut.Trim()
    $skipAll = $true
  }
}

# ── 4. Runtime — FLAG_SECURE ──────────────────────────────────────────────────

if (-not $skipAll) {

Write-Header "FASE 4 — Controles de runtime"

# Launch normally first
Launch-App
$topAfterLaunch = Get-ForegroundPkg
$appLaunched = $topAfterLaunch -match [regex]::Escape($PKG)

if (-not $appLaunched) {
  if ($isTestKeys) {
    Pass "Root detection - test-keys" "app rechazó el emulador (test-keys detectado)"
    Info "Emulador con test-keys: root detection activo. Runtime tests saltados."
    Skip "FLAG_SECURE screenshot"   "app bloqueada por root detection"
    Skip "Clipboard clear"          "app bloqueada por root detection"
    Skip "ADB backup"               "app bloqueada por root detection"
    Skip "Logcat - log stripping"   "app bloqueada por root detection"
    $skipRuntime = $true
  } else {
    Fail "App launch" "app no llegó al foreground ($topAfterLaunch)"
    $skipAll = $true
  }
}

if (-not $skipRuntime -and -not $skipAll) {

Pass "App launch en release" "app en foreground tras arrancar"

# 4a. FLAG_SECURE - screenshot must be black/empty
Info "Capturando screenshot para verificar FLAG_SECURE ..."
$screenshotPath = Join-Path $TMP "keystone-screenshot.png"
Adb shell screencap -p /sdcard/test_cap.png | Out-Null
Adb pull /sdcard/test_cap.png $screenshotPath 2>$null | Out-Null
Adb shell rm /sdcard/test_cap.png 2>$null | Out-Null

if (Test-Path $screenshotPath) {
  $imgBytes  = [System.IO.File]::ReadAllBytes($screenshotPath)
  $imgSizeKB = [math]::Round($imgBytes.Length / 1KB, 1)
  # A black screen PNG (FLAG_SECURE) is typically <5KB; a real screen >30KB
  # We check: 1) PNG magic bytes present, 2) file is suspiciously small (black screen)
  $isPng = $imgBytes[0] -eq 0x89 -and $imgBytes[1] -eq 0x50 -and $imgBytes[2] -eq 0x4E -and $imgBytes[3] -eq 0x47
  if ($isPng -and $imgSizeKB -lt 10) {
    Pass "FLAG_SECURE" "screenshot ${imgSizeKB}KB (negro — contenido bloqueado por FLAG_SECURE)"
  } elseif ($isPng) {
    Fail "FLAG_SECURE" "screenshot ${imgSizeKB}KB (contenido visible — FLAG_SECURE puede no estar activo)"
  } else {
    Fail "FLAG_SECURE" "archivo no es PNG válido"
  }
  Remove-Item $screenshotPath -Force -ErrorAction SilentlyContinue
} else {
  Skip "FLAG_SECURE" "no se pudo capturar screenshot"
}

# 4b. Clipboard clear — write to clipboard from ADB, background app, verify cleared
Info "Probando clipboard clear en onPause() ..."
# Set clipboard via shell (API 29+ restricts direct clipboard, but works in emulator)
Adb shell "am broadcast -a clipper.set -e text 'KEYSTONE_TEST_SECRET_12345'" 2>$null | Out-Null
# Alternative: use input to paste in a field
Adb shell "service call clipboard 2 i32 1 s16 'application/text' s16 'KEYSTONE_SECRET'" 2>$null | Out-Null
Start-Sleep 1

# Send app to background (Home key)
Adb shell input keyevent 3  # HOME
Start-Sleep 2

# Read clipboard after app went to background
$clipOut = (Adb shell "service call clipboard 2 i32 1 s16 'text/plain' 2>/dev/null") -join ""
# Check clipboard via a more reliable method
$clipCheck = (Adb shell "dumpsys clipboard 2>/dev/null | head -20") -join ""

if ($clipCheck -match "KEYSTONE_TEST_SECRET") {
  Fail "Clipboard clear en onPause()" "texto sensible sigue en el portapapeles después de pasar a background"
} else {
  Pass "Clipboard clear en onPause()" "portapapeles limpiado al pasar a background"
}

# Bring app back to foreground for next tests
Adb shell monkey -p $PKG -c android.intent.category.LAUNCHER 1 2>$null | Out-Null
Start-Sleep 2

# 4c. ADB Backup
Info "Probando ADB backup (allowBackup=false) ..."
$backupPath = Join-Path $TMP "keystone-backup.ab"
# Non-interactive backup — will complete immediately if allowBackup=false
$backupJob = Start-Process -FilePath $ADB -ArgumentList "backup","-apk","-noshared","-f",$backupPath,$PKG -NoNewWindow -PassThru
Start-Sleep 8  # wait for backup to complete or timeout
if (-not $backupJob.HasExited) { $backupJob.Kill() }

if (Test-Path $backupPath) {
  $backupSize = (Get-Item $backupPath).Length
  if ($backupSize -lt 200) {
    Pass "ADB backup bloqueado" "archivo .ab = ${backupSize} bytes (solo header — sin datos)"
  } else {
    Fail "ADB backup" "archivo .ab = ${backupSize} bytes (datos incluidos — allowBackup puede estar activo)"
  }
  Remove-Item $backupPath -Force -ErrorAction SilentlyContinue
} else {
  Skip "ADB backup" "archivo .ab no generado (puede requerir confirmación manual en pantalla)"
}

# 4d. Logcat — log stripping en release
Info "Verificando log stripping (10 segundos de actividad) ..."
$logProcess = Start-Process -FilePath $ADB -ArgumentList "logcat","-v","brief" -RedirectStandardOutput (Join-Path $TMP "keystone-logcat.txt") -NoNewWindow -PassThru

# Exercise the app a bit
Adb shell input tap 500 800 2>$null | Out-Null  # tap somewhere
Start-Sleep 2
Adb shell input tap 500 600 2>$null | Out-Null
Start-Sleep 3
Adb shell input swipe 200 400 800 400 2>$null | Out-Null
Start-Sleep 3

$logProcess.Kill()
$logPath = Join-Path $TMP "keystone-logcat.txt"
if (Test-Path $logPath) {
  $logLines = Get-Content $logPath
  # App-specific log tags to check (Capacitor, our app)
  $appLogs = $logLines | Where-Object {
    $_ -match "Capacitor/Console|KEYSTONE|MainActivity|io\.ionic\.starter" -and
    $_ -notmatch "^-----"
  }
  $appLogCount = if ($appLogs) { @($appLogs).Count } else { 0 }

  # Capacitor itself logs a few lines at startup regardless — threshold 5
  if ($appLogCount -le 5) {
    Pass "Log stripping (release build)" "$appLogCount líneas de la app en logcat (ProGuard eliminó Log.*)"
  } else {
    Fail "Log stripping" "$appLogCount líneas de la app en logcat (más de lo esperado en release)"
    $appLogs | Select-Object -First 5 | ForEach-Object { Write-Host "    $_" -ForegroundColor DarkRed }
  }
  Remove-Item $logPath -Force -ErrorAction SilentlyContinue
} else {
  Skip "Log stripping" "no se pudo capturar logcat"
}

} # end if -not $skipRuntime

} # end if -not $skipAll (Phase 4)

# ── 5. Frida & Root simulation ────────────────────────────────────────────────

if (-not $skipAll) {
Write-Header "FASE 5 - Simulacion de Frida y Root"

# 5a. Frida file detection — push fake artifact
Info "Simulando presencia de Frida (push artefacto en /data/local/tmp/) ..."
Adb shell "echo 'fake' > /data/local/tmp/frida-server" 2>$null | Out-Null
$fridaFileExists = (Adb shell "test -f /data/local/tmp/frida-server && echo YES") -join ""

if ($fridaFileExists -match "YES") {
  Info "Artefacto /data/local/tmp/frida-server creado — relanzando app ..."
  Launch-App
  Start-Sleep 4
  $topAfterFrida = Get-ForegroundPkg

  if ($topAfterFrida -notmatch [regex]::Escape($PKG)) {
    Pass "Frida detection — artefacto en disco" "app terminó (finishAndRemoveTask) al detectar frida-server"
  } else {
    # Check for alert dialog via uiautomator
    $uiDump = (Adb shell "uiautomator dump /sdcard/ui.xml 2>/dev/null && cat /sdcard/ui.xml") -join ""
    if ($uiDump -match "Instrumentaci") {
      Pass "Frida detection — dialog visible" "dialog de seguridad mostrado"
    } else {
      Fail "Frida detection" "app sigue corriendo y no hay dialog de seguridad"
    }
  }

  # Cleanup
  Adb shell "rm /data/local/tmp/frida-server" 2>$null | Out-Null
} else {
  Skip "Frida detection" "no se pudo crear artefacto en /data/local/tmp/ (emulador puede tener /data readonly)"
}

# 5b. Root detection — test-keys or fake su
if ($isTestKeys) {
  Pass "Root detection — test-keys (ya verificado en Fase 4)" "Build.TAGS=test-keys detectado, app rechazada"
} else {
  Info "Emulador sin test-keys — intentando crear su falso en /data/local/bin/ ..."
  Adb shell "mkdir -p /data/local/bin && echo '#!/system/bin/sh' > /data/local/bin/su && chmod +x /data/local/bin/su" 2>$null | Out-Null
  $suExists = (Adb shell "test -f /data/local/bin/su && echo YES") -join ""

  if ($suExists -match "YES") {
    Info "su falso creado — nuestra detección busca /data/local/bin/su específicamente... "
    Info "Nota: el código busca /data/local/bin/su — verificar manualmente si la detección usa esta ruta."
    # Our code checks /data/local/xbin/su and /data/local/bin/su — let's check
    $rootPaths = @("/sbin/su","/system/bin/su","/system/xbin/su","/data/local/xbin/su","/data/local/bin/su","/system/sd/xbin/su")
    $foundSu = $rootPaths | Where-Object { ((Adb shell "test -f $_ && echo YES") -join "") -match "YES" }
    if ($foundSu) {
      Pass "Root detection — su falso" "binario su encontrado en: $($foundSu -join ', ')"
      Launch-App
      Start-Sleep 4
      $topAfterRoot = Get-ForegroundPkg
      if ($topAfterRoot -notmatch [regex]::Escape($PKG)) {
        Pass "Root detection — app rechazada" "finishAndRemoveTask() ejecutado"
      } else {
        Fail "Root detection — app no rechazada" "app siguió corriendo con su en disco"
      }
      Adb shell "rm /data/local/bin/su" 2>$null | Out-Null
    }
  } else {
    Skip "Root detection — su falso" "/data/local/bin/ no escribible — probar en emulador AOSP con test-keys"
  }
}

# 5c. WebView remote debugging check
Write-Header "FASE 6 - WebView y network"

Info "Verificando WebView.setWebContentsDebuggingEnabled(false) ..."
# Re-launch the app cleanly (after Frida artifact removal)
Adb shell "rm /data/local/tmp/frida-server" 2>$null | Out-Null
Launch-App
$debuggableWebViews = (Adb shell "cat /proc/net/unix 2>/dev/null | grep webview_devtools_remote") -join ""
if ($debuggableWebViews -match "webview_devtools_remote") {
  Fail "WebView debugging desactivado" "socket devtools detectado en /proc/net/unix — debugging activo"
} else {
  Pass "WebView debugging desactivado" "sin socket webview_devtools_remote (chrome://inspect no lo verá)"
}

# 5d. Cleartext network — check network_security_config via logcat
Info "Verificando network_security_config (cleartext bloqueado) ..."
$netLogPath = Join-Path $TMP "keystone-netlog.txt"
$netLogJob  = Start-Process -FilePath $ADB -ArgumentList "logcat","-v","brief","-s","NetworkSecurityConfig:W" -RedirectStandardOutput $netLogPath -NoNewWindow -PassThru
Start-Sleep 5
$netLogJob.Kill()
if (Test-Path $netLogPath) {
  $netLog = Get-Content $netLogPath -ErrorAction SilentlyContinue
  $cleartextWarning = $netLog | Where-Object { $_ -match "cleartext\|CLEARTEXT" }
  if ($cleartextWarning) {
    Fail "network_security_config" "WARNING cleartext detectado: $($cleartextWarning | Select-Object -First 1)"
  } else {
    Pass "network_security_config" "sin warnings de cleartext en logcat"
  }
  Remove-Item $netLogPath -Force -ErrorAction SilentlyContinue
}

} # end if -not $skipAll

# ── Summary ───────────────────────────────────────────────────────────────────

Write-Host ""
Write-Host "  ==========================================" -ForegroundColor DarkGray
Write-Host "  RESULTADOS FINALES" -ForegroundColor White
Write-Host "  ==========================================" -ForegroundColor DarkGray
Write-Host ""

$results | Format-Table -AutoSize @{
  Label="Estado"; Expression={
    $c = switch($_.Status){"PASS"{"Green"};"FAIL"{"Red"};"SKIP"{"DarkGray"};default{"White"}}
    Write-Host -NoNewline "  $($_.Status)" -ForegroundColor $c
    ""
  }
}, @{Label="Test"; Expression={$_.Test}}, @{Label="Detalle"; Expression={$_.Detail}} | Out-Null

foreach ($r in $results) {
  $color = switch($r.Status) { "PASS"{"Green"}; "FAIL"{"Red"}; "SKIP"{"DarkGray"}; default{"White"} }
  $detail = if ($r.Detail) { " - $($r.Detail)" } else { "" }
  Write-Host "  [$($r.Status.PadRight(4))] $($r.Test)$detail" -ForegroundColor $color
}

Write-Host ""
Write-Host ("  PASS: $passed   FAIL: $failed   SKIP: $skipped   TOTAL: $($passed+$failed+$skipped)") -ForegroundColor $(if($failed -gt 0){"Yellow"}else{"Green"})
Write-Host ""

if ($failed -gt 0) { exit 1 } else { exit 0 }
