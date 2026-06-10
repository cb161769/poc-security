#!/usr/bin/env pwsh
<#
.SYNOPSIS
  Android security test suite — Docker/Linux variant.
  Tests the same controls as test-android-security.ps1 using Linux-native paths.
  Designed to run against a remote emulator via ADB TCP.
#>
param(
  [string]$AdbHost = "android-emulator",
  [int]   $AdbPort = 5555,
  [string]$Pkg     = "io.ionic.starter",
  [string]$ApkPath = "/apk-input/app-release.apk"
)

$SERIAL = "${AdbHost}:${AdbPort}"
$script:pass = 0; $script:fail = 0; $script:warn = 0
$results = [System.Collections.Generic.List[hashtable]]::new()

function Adb {
    param([string[]]$A)
    & adb -s $SERIAL @A 2>&1
}

function Record([string]$Status, [string]$Name, [string]$Detail) {
    $icon = @{ Pass = "✓"; Fail = "✗"; Warn = "⚠" }[$Status]
    $color = @{ Pass = "Green"; Fail = "Red"; Warn = "Yellow" }[$Status]
    Write-Host "  $icon " -NoNewline
    Write-Host $Name -ForegroundColor $color -NoNewline
    Write-Host " — $Detail"
    $results.Add(@{ Status = $Status; Name = $Name; Detail = $Detail })
    if ($Status -eq "Pass") { $script:pass++ }
    elseif ($Status -eq "Fail") { $script:fail++ }
    else { $script:warn++ }
}

function Launch-App {
    Adb @("shell", "am", "force-stop", $Pkg) | Out-Null
    Start-Sleep 1
    Adb @("shell", "monkey", "-p", $Pkg, "-c", "android.intent.category.LAUNCHER", "1") | Out-Null
    Start-Sleep 3
}

function Get-ForegroundPkg {
    (Adb @("shell", "dumpsys activity activities")) -join "`n" |
        Select-String "mResumedActivity" |
        ForEach-Object { $_.ToString() }
}

Write-Host ""
Write-Host "═══════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "  ANDROID SECURITY TESTS — Docker/Linux           " -ForegroundColor Cyan
Write-Host "═══════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "  Serial  : $SERIAL"
Write-Host "  Package : $Pkg"
Write-Host "  APK     : $ApkPath"
Write-Host ""

# ─── Phase 1 · Static APK analysis ────────────────────────────────────────────
Write-Host "── Phase 1: Static APK Analysis ──" -ForegroundColor Cyan

if (Test-Path $ApkPath) {
    $raw = [System.IO.File]::ReadAllBytes($ApkPath)
    $txt = [System.Text.Encoding]::Latin1.GetString($raw)

    # Cleartext HTTP endpoints (exclude localhost / emulator dev addresses)
    $httpHits = [regex]::Matches($txt, 'http://[a-zA-Z0-9._:/-]+') |
        Where-Object { $_.Value -notmatch '(localhost|10\.0\.2\.2|schemas\.android\.com|www\.w3\.org)' }
    if ($httpHits.Count -eq 0) {
        Record "Pass" "No cleartext HTTP URLs" "No non-localhost http:// found in APK"
    } else {
        $sample = ($httpHits | Select-Object -First 3 -ExpandProperty Value) -join " | "
        Record "Fail" "Cleartext HTTP URL(s) in APK" $sample
    }

    # allowBackup should be false
    if ($txt -match 'allowBackup') {
        Record "Warn" "allowBackup flag present" "Binary contains 'allowBackup' — verify it is set to false via manifest"
    } else {
        Record "Pass" "allowBackup stripped" "String 'allowBackup' not in binary (ProGuard cleaned)"
    }

    # debuggable must not appear in release APK
    if ($txt -match 'debuggable="true"') {
        Record "Fail" "debuggable=true in APK" "Release APK contains debuggable=true"
    } else {
        Record "Pass" "Not debuggable" "debuggable=true not found in release APK"
    }

    # Obfuscation signal: short method names (a, b, c) indicate ProGuard/R8 ran
    $shortNames = [regex]::Matches($txt, '\bpublic (?:static )?(?:final )?[a-z]\b') | Measure-Object
    if ($shortNames.Count -gt 10) {
        Record "Pass" "ProGuard/R8 obfuscation" "Found $($shortNames.Count) short identifiers — minification active"
    } else {
        Record "Warn" "ProGuard signal weak" "Only $($shortNames.Count) short identifiers found — verify minifyEnabled=true"
    }
} else {
    Record "Warn" "Static analysis skipped" "APK not found at $ApkPath — mount android-apk volume"
}

# ─── Phase 2 · FLAG_SECURE ────────────────────────────────────────────────────
Write-Host ""
Write-Host "── Phase 2: FLAG_SECURE ──" -ForegroundColor Cyan

Launch-App

$tmpPng = "/tmp/sc_$([DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()).png"
$rawPng = Adb @("exec-out", "screencap", "-p")

# exec-out returns a byte array as strings in PS — write via pipeline
try {
    $pngBytes = [System.Text.Encoding]::Latin1.GetBytes(($rawPng -join ""))
    [System.IO.File]::WriteAllBytes($tmpPng, $pngBytes)
} catch {
    # Fallback: use adb pull
    Adb @("shell", "screencap", "-p", "/sdcard/sc_test.png") | Out-Null
    Adb @("pull", "/sdcard/sc_test.png", $tmpPng) | Out-Null
    Adb @("shell", "rm", "-f", "/sdcard/sc_test.png") | Out-Null
}

if (Test-Path $tmpPng) {
    $bytes  = [System.IO.File]::ReadAllBytes($tmpPng)
    $isPng  = $bytes.Length -gt 4 -and $bytes[0] -eq 0x89 -and $bytes[1] -eq 0x50
    $sizeKB = [math]::Round($bytes.Length / 1KB, 1)
    if ($isPng -and $sizeKB -lt 10) {
        Record "Pass" "FLAG_SECURE active" "Screenshot ${sizeKB}KB — black screen (content blocked)"
    } elseif ($isPng) {
        Record "Fail" "FLAG_SECURE missing" "Screenshot ${sizeKB}KB — content is visible"
    } else {
        Record "Warn" "FLAG_SECURE" "Unexpected screencap output (${sizeKB}KB, not PNG header)"
    }
    Remove-Item $tmpPng -Force -ErrorAction SilentlyContinue
} else {
    Record "Warn" "FLAG_SECURE" "Could not capture screenshot"
}

# ─── Phase 3 · Root detection — test-keys ────────────────────────────────────
Write-Host ""
Write-Host "── Phase 3: Root / Tamper Detection ──" -ForegroundColor Cyan

$buildTags = (Adb @("shell", "getprop", "ro.build.tags")) -join "" | ForEach-Object { $_.Trim() }
if ($buildTags -match "test-keys") {
    Launch-App; Start-Sleep 4
    $fg = Get-ForegroundPkg
    if ($fg -notmatch [regex]::Escape($Pkg)) {
        Record "Pass" "Root detection — build tags" "App exited on test-keys device (build: $buildTags)"
    } else {
        Record "Warn" "Root detection — build tags" "App still running on test-keys build — emulator exception not blocking"
    }
} else {
    Record "Pass" "Root detection — build tags" "Tags: '$buildTags' (no test-keys)"
}

# Plant fake su artifact
Adb @("shell", "echo 'fake' > /data/local/tmp/su") | Out-Null
Launch-App; Start-Sleep 4
$fgSu = Get-ForegroundPkg
if ($fgSu -notmatch [regex]::Escape($Pkg)) {
    Record "Pass" "Root detection — su artifact" "App terminated with /data/local/tmp/su present"
} else {
    Record "Fail" "Root detection — su artifact" "App running despite fake su at /data/local/tmp/su"
}
Adb @("shell", "rm -f /data/local/tmp/su") | Out-Null

# ─── Phase 4 · Frida detection ───────────────────────────────────────────────
Write-Host ""
Write-Host "── Phase 4: Frida Detection ──" -ForegroundColor Cyan

Adb @("shell", "echo 'fake' > /data/local/tmp/frida-server") | Out-Null
Launch-App; Start-Sleep 4
$fgFrida = Get-ForegroundPkg
if ($fgFrida -notmatch [regex]::Escape($Pkg)) {
    Record "Pass" "Frida detection — disk artifact" "App terminated with frida-server artifact present"
} else {
    Record "Fail" "Frida detection — disk artifact" "App running despite /data/local/tmp/frida-server"
}
Adb @("shell", "rm -f /data/local/tmp/frida-server") | Out-Null

# ─── Phase 5 · Signature validation ─────────────────────────────────────────
Write-Host ""
Write-Host "── Phase 5: Signature ──" -ForegroundColor Cyan

$sigOut = (Adb @("shell", "pm", "list", "packages", "--show-versioncode")) -join ""
if ($sigOut -match [regex]::Escape($Pkg)) {
    # Package is installed and signed — signature check passes at install time
    Record "Pass" "Signature accepted by OS" "Package $Pkg is installed (OS verified signature at install)"
} else {
    Record "Warn" "Signature check" "Package $Pkg not found in package manager — APK not installed"
}

# ─── Phase 6 · WebView debugging socket ──────────────────────────────────────
Write-Host ""
Write-Host "── Phase 6: WebView Debugging ──" -ForegroundColor Cyan

Launch-App; Start-Sleep 3
$unixSockets = (Adb @("shell", "cat /proc/net/unix 2>/dev/null")) -join ""
if ($unixSockets -match "webview_devtools_remote") {
    Record "Fail" "WebView debug disabled" "webview_devtools_remote socket found — remote debugging is ON"
} else {
    Record "Pass" "WebView debug disabled" "No webview_devtools_remote socket — debugging is OFF"
}

# ─── Phase 7 · Logcat leak ───────────────────────────────────────────────────
Write-Host ""
Write-Host "── Phase 7: Log Leak ──" -ForegroundColor Cyan

Launch-App; Start-Sleep 3
$pidStr = (Adb @("shell", "pidof $Pkg")) -join "" | ForEach-Object { $_.Trim() }
if ($pidStr -match '^\d+$') {
    $logLines = Adb @("logcat", "-d", "--pid=$pidStr")
    $appLines = $logLines | Where-Object { $_ -notmatch '^\-\-\-' }
    if ($appLines.Count -lt 5) {
        Record "Pass" "Log stripping active" "$($appLines.Count) app log entries (ProGuard stripped verbose logs)"
    } else {
        Record "Fail" "Logs not stripped" "$($appLines.Count) log entries for app — add -assumenosideeffects in ProGuard"
    }
} else {
    Record "Warn" "Log check" "Could not get PID for $Pkg"
}

# ─── Phase 8 · Cleartext network ─────────────────────────────────────────────
Write-Host ""
Write-Host "── Phase 8: Network Security Config ──" -ForegroundColor Cyan

# Verify network_security_config blocks cleartext via package info
$nscCheck = (Adb @("shell", "dumpsys package $Pkg")) -join ""
if ($nscCheck -match "networkSecurityConfig|network_security_config") {
    Record "Pass" "network_security_config present" "Package declares networkSecurityConfig"
} else {
    Record "Warn" "network_security_config" "Could not confirm networkSecurityConfig via dumpsys"
}

# ─── Summary ──────────────────────────────────────────────────────────────────
$total = $script:pass + $script:fail + $script:warn
Write-Host ""
Write-Host "═══════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "  RESULTS" -ForegroundColor Cyan
Write-Host "═══════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "  Passed   : $($script:pass) / $total" -ForegroundColor Green
Write-Host "  Failed   : $($script:fail) / $total" -ForegroundColor $(if ($script:fail -gt 0) { "Red" } else { "Green" })
Write-Host "  Warnings : $($script:warn) / $total" -ForegroundColor Yellow

if ($script:fail -gt 0) {
    Write-Host ""
    Write-Host "FAILED CHECKS:" -ForegroundColor Red
    $results | Where-Object { $_.Status -eq "Fail" } | ForEach-Object {
        Write-Host "  ✗ $($_.Name)" -ForegroundColor Red
        Write-Host "    $($_.Detail)"
    }
    exit 1
}

Write-Host ""
Write-Host "All critical checks passed." -ForegroundColor Green
exit 0
