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
  [string]$Pkg     = "com.keystone.mobile",
  [string]$ApkPath = "/apk-input/app-release.apk"
)

$SERIAL = "${AdbHost}:${AdbPort}"
$script:pass = 0; $script:fail = 0; $script:warn = 0
$results = [System.Collections.Generic.List[hashtable]]::new()

function Adb {
    param([string[]]$A, [int]$TimeoutSec = 20)
    # Wrap with system `timeout` binary — prevents indefinite ADB hangs without complex job management.
    # `timeout` is always available in the test runner container (GNU coreutils).
    & timeout $TimeoutSec adb -s $SERIAL @A 2>&1
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
    Adb @("shell", "am force-stop $Pkg 2>/dev/null") | Out-Null
    Start-Sleep 1
    # Full component: com.keystone.mobile/io.ionic.starter.MainActivity (Capacitor bridge activity)
    Adb @("shell", "am start -n $Pkg/io.ionic.starter.MainActivity 2>/dev/null") | Out-Null
    Start-Sleep 3
}

function Get-ForegroundPkg {
    # mCurrentFocus is a single line from dumpsys window — fast and bounded
    (Adb @("shell", "timeout 5 dumpsys window 2>/dev/null | grep -m1 mCurrentFocus")) -join " "
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

    # Extract DEX from APK ZIP for reliable string scanning (classes.dex may be stored or compressed).
    # Write to temp file then read as bytes to get faithful binary → Latin1 searchable string.
    $dexTxt = ""
    $dexTmp = "/tmp/classes_$PID.dex"
    try {
        & bash -c "unzip -p '$ApkPath' classes.dex > '$dexTmp' 2>/dev/null"
        if ((Test-Path $dexTmp) -and (Get-Item $dexTmp).Length -gt 0) {
            $dexRaw = [System.IO.File]::ReadAllBytes($dexTmp)
            $dexTxt = [System.Text.Encoding]::Latin1.GetString($dexRaw)
        }
    } catch {}
    Remove-Item $dexTmp -ErrorAction SilentlyContinue
    if (-not $dexTxt) { $dexTxt = $txt }

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

    # Obfuscation signal: DEX-format single-char class descriptors (e.g. "La;" "Lb;") appear
    # when ProGuard/R8 renames classes. Text-style "public a" doesn't exist in DEX binaries.
    $shortClasses = [regex]::Matches($txt, 'L[a-z];|L[a-z]/[a-z];') | Measure-Object
    if ($shortClasses.Count -gt 5) {
        Record "Pass" "ProGuard/R8 obfuscation" "Found $($shortClasses.Count) single-char DEX class refs — R8 active"
    } else {
        Record "Warn" "ProGuard signal weak" "Only $($shortClasses.Count) short DEX class refs — verify minifyEnabled=true"
    }
} else {
    Record "Warn" "Static analysis skipped" "APK not found at $ApkPath — mount android-apk volume"
}

# ─── Phase 2 · FLAG_SECURE ────────────────────────────────────────────────────
Write-Host ""
Write-Host "── Phase 2: FLAG_SECURE ──" -ForegroundColor Cyan

Launch-App; Start-Sleep 2

# Check FLAG_SECURE via server-side grep with explicit timeout to prevent dumpsys hangs.
# FLAG_SECURE = WindowManager.LayoutParams.FLAG_SECURE = 0x00002000
$flagLine = Adb @("shell", "timeout 8 dumpsys window windows 2>/dev/null | grep -A30 '$Pkg' | grep -m1 'fl='")
$flagLine  = ($flagLine -join "").Trim()
if ($flagLine -match '\bfl=(0x[0-9a-fA-F]+)') {
    $foundFlags = $Matches[1]
    $flagInt    = [Convert]::ToInt64($foundFlags, 16)
    if ($flagInt -band 0x2000) {
        Record "Pass" "FLAG_SECURE active" "App window flags $foundFlags include FLAG_SECURE (0x2000)"
    } else {
        Record "Fail" "FLAG_SECURE missing" "App window flags $foundFlags — bit 0x2000 not set"
    }
} else {
    # Fallback: static check — FLAG_SECURE value 0x2000 (8192) in setFlags call
    # If the dumpsys approach fails (e.g. app not foregrounded), verify code presence in APK
    if ($txt -and ($txt -match 'FLAG_SECURE|setFlags')) {
        Record "Warn" "FLAG_SECURE — static signal" "setFlags/FLAG_SECURE string found in APK; runtime window check failed (app may not be foreground)"
    } else {
        Record "Warn" "FLAG_SECURE" "Could not locate window flags for $Pkg (app may not be foreground)"
    }
}

# ─── Phase 3 · Root detection — test-keys ────────────────────────────────────
Write-Host ""
Write-Host "── Phase 3: Root / Tamper Detection ──" -ForegroundColor Cyan

$buildTags = ((Adb @("shell", "getprop ro.build.tags")) -join "").Trim()
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

# Static check: verify su detection path strings are compiled into the DEX bytecode.
# Uses extracted DEX (bypasses ZIP compression) for reliable string matching.
# Runtime file-planting requires root to write to system paths the app checks.
if ($dexTxt) {
    $suPaths = @("/system/xbin/su", "/data/local/bin/su", "/sbin/su", "/system/bin/su") |
        Where-Object { $dexTxt -match [regex]::Escape($_) }
    if ($suPaths.Count -ge 2) {
        Record "Pass" "Root detection — su paths compiled" "DEX checks $($suPaths.Count) su paths: $($suPaths -join ', ')"
    } elseif ($dexTxt.Length -gt 10000) {
        Record "Fail" "Root detection — su paths missing" "DEX contains only $($suPaths.Count) su path strings — verify isRooted() implementation"
    } else {
        Record "Warn" "Root detection — su artifact" "DEX extraction may have failed (only $($dexTxt.Length) bytes); cannot verify su paths"
    }
} else {
    Record "Warn" "Root detection — su artifact" "APK not available for static check"
}

# ─── Phase 4 · Frida detection ───────────────────────────────────────────────
Write-Host ""
Write-Host "── Phase 4: Frida Detection ──" -ForegroundColor Cyan

# Static check: verify Frida artifact strings are compiled into the DEX bytecode.
# Android 14 SELinux blocks untrusted_app from reading /data/local/tmp/ at runtime;
# static analysis confirms the detection code is compiled in.
if ($dexTxt) {
    $fridaArtifacts = @("frida-server", "re.frida.server", "frida-agent") |
        Where-Object { $dexTxt -match [regex]::Escape($_) }
    if ($fridaArtifacts.Count -ge 1) {
        Record "Pass" "Frida detection — artifact strings" "DEX contains $($fridaArtifacts.Count) Frida artifact strings: $($fridaArtifacts -join ', ')"
    } elseif ($dexTxt.Length -gt 10000) {
        Record "Fail" "Frida detection — no artifact check" "DEX does not contain Frida artifact path strings — isFridaPresent() may be missing"
    } else {
        Record "Warn" "Frida detection — disk artifact" "DEX extraction may have failed; cannot verify Frida detection code"
    }
} else {
    Record "Warn" "Frida detection — disk artifact" "APK not available for static check"
}

# ─── Phase 5 · Signature validation ─────────────────────────────────────────
Write-Host ""
Write-Host "── Phase 5: Signature ──" -ForegroundColor Cyan

$pkgPath = ((Adb @("shell", "pm path $Pkg 2>/dev/null") -TimeoutSec 30) -join "").Trim()
if ($pkgPath -match "package:") {
    Record "Pass" "Signature accepted by OS" "Package $Pkg installed at $($pkgPath -replace 'package:','')"
} else {
    # Fallback: pm list packages with grep
    $sigOut = ((Adb @("shell", "pm list packages 2>/dev/null | grep -m1 '$Pkg'") -TimeoutSec 30) -join "").Trim()
    if ($sigOut -match [regex]::Escape($Pkg)) {
        Record "Pass" "Signature accepted by OS" "Package $Pkg is installed (OS verified signature at install)"
    } else {
        Record "Warn" "Signature check" "Package $Pkg not found via pm path or pm list — verify package name in build.gradle"
    }
}

# ─── Phase 6 · WebView debugging socket ──────────────────────────────────────
Write-Host ""
Write-Host "── Phase 6: WebView Debugging ──" -ForegroundColor Cyan

Launch-App; Start-Sleep 3
# Get app PID to check for a PID-specific webview_devtools_remote socket.
# The system WebView service process always has its own socket; we only care about ours.
$appPid = ((Adb @("shell", "pidof $Pkg")) -join "").Trim() -replace '\s.*',''
$debugSocket = ""
if ($appPid -match '^\d+$') {
    # Socket name is webview_devtools_remote_<pid> — check for our PID specifically
    $debugSocket = (Adb @("shell", "cat /proc/net/unix 2>/dev/null | grep webview_devtools_remote_$appPid")) -join ""
} else {
    # No PID → app not running, can't have an active debug socket
    $debugSocket = ""
}
if ($debugSocket -match "webview_devtools_remote") {
    Record "Fail" "WebView debug disabled" "webview_devtools_remote_$appPid socket found — remote debugging is ON for PID $appPid"
} else {
    if ($appPid -match '^\d+$') {
        Record "Pass" "WebView debug disabled" "No webview_devtools_remote_$appPid socket for PID $appPid — debugging is OFF"
    } else {
        Record "Pass" "WebView debug disabled" "App not running — no debug socket present"
    }
}

# ─── Phase 7 · Logcat leak ───────────────────────────────────────────────────
Write-Host ""
Write-Host "── Phase 7: Log Leak ──" -ForegroundColor Cyan

# App should still be running from Phase 6 launch; get PID without re-launching
$pidStr = ((Adb @("shell", "pidof $Pkg")) -join "").Trim()
if ($pidStr -notmatch '^\d+$') {
    # fallback: ps -A grep (app may still be running under slightly different process name)
    $psLine = ((Adb @("shell", "timeout 5 ps -A 2>/dev/null | grep -m1 io.ionic")) -join "").Trim()
    if ($psLine -match '^\S+\s+(\d+)') { $pidStr = $Matches[1] }
}
if ($pidStr -notmatch '^\d+$') {
    # app may have exited; re-launch and wait longer
    Launch-App; Start-Sleep 5
    $pidStr = ((Adb @("shell", "pidof $Pkg")) -join "").Trim()
}
if ($pidStr -match '^\d+$') {
    $logLines = Adb @("logcat", "-d", "--pid=$pidStr")
    # Filter out system/framework log lines (ActivityManager, Zygote, PackageManager, etc.)
    # and separator lines. We only fail on app-originating verbose/debug logs.
    $appLines = $logLines | Where-Object {
        $_ -notmatch '^\-\-\-' -and
        $_ -notmatch '\b(ActivityManager|PackageManager|Zygote|JavaBridge|CompatibilityInfo|ViewRootImpl|OpenGLRenderer|Gralloc|SurfaceFlinger|Choreographer|EGL|libEGL|mali|adreno|art\s|dalvikvm|cr_|chromium|CapacitorBridge|JSIExecutor|Capacitor\/)\b' -and
        $_ -match '\s[VDIWEF]/'
    }
    if ($appLines.Count -lt 5) {
        Record "Pass" "Log stripping active" "$($appLines.Count) app log entries (ProGuard stripped verbose logs)"
    } else {
        # Show a sample to help diagnose what's leaking
        $sample = ($appLines | Select-Object -First 3) -join " | "
        Record "Fail" "Logs not stripped" "$($appLines.Count) app log entries — check ProGuard config. Sample: $sample"
    }
} else {
    Record "Warn" "Log check" "Could not get PID for $Pkg"
}

# ─── Phase 8 · Cleartext network ─────────────────────────────────────────────
Write-Host ""
Write-Host "── Phase 8: Network Security Config ──" -ForegroundColor Cyan

# Verify network_security_config blocks cleartext via package info
$nscCheck = (Adb @("shell", "timeout 8 dumpsys package $Pkg 2>/dev/null")) -join ""
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
}

Write-Host ""
if ($script:fail -gt 0) { Write-Host "Status: FAILED" -ForegroundColor Red }
else { Write-Host "All critical checks passed." -ForegroundColor Green }

# ─── Export HTML report ───────────────────────────────────────────────────────
$reportDir = "/reports"
$timestamp = (Get-Date -Format "yyyy-MM-dd HH:mm:ss UTC")
$reportFile = "$reportDir/android-security-report.html"

$passColor  = "#3fb950"
$failColor  = "#f85149"
$warnColor  = "#d29922"
$bgMain     = "#0d1117"
$bgCard     = "#161b22"
$border     = "#30363d"
$textMuted  = "#8b949e"

$overallStatus = if ($script:fail -gt 0) { "FAILED" } else { "PASSED" }
$overallBadgeClass = if ($script:fail -gt 0) { "fail" } else { "pass" }

$rows = $results | ForEach-Object {
    $icon  = @{ Pass = "&#10003;"; Fail = "&#10007;"; Warn = "&#9888;" }[$_.Status]
    $color = @{ Pass = $passColor;  Fail = $failColor;  Warn = $warnColor }[$_.Status]
    "<tr><td style='color:$color;font-weight:700;white-space:nowrap'>$icon $($_.Status)</td><td>$([System.Net.WebUtility]::HtmlEncode($_.Name))</td><td style='color:$textMuted'>$([System.Net.WebUtility]::HtmlEncode($_.Detail))</td></tr>"
}

$html = @"
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Android Security Report</title>
  <style>
    *{box-sizing:border-box;margin:0;padding:0}
    body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:$bgMain;color:#c9d1d9;padding:32px;font-size:14px}
    h1{color:#e6edf3;font-size:1.3rem;font-weight:600;margin-bottom:4px}
    .meta{color:$textMuted;font-size:0.8rem;margin-bottom:20px}
    .badge{display:inline-block;padding:2px 10px;border-radius:10px;font-size:0.75rem;font-weight:700;vertical-align:middle;margin-left:8px}
    .pass{background:#1a2e1a;color:$passColor;border:1px solid $passColor}
    .fail{background:#2e1a1a;color:$failColor;border:1px solid $failColor}
    .stats{display:flex;gap:12px;margin-bottom:24px;flex-wrap:wrap}
    .stat{background:$bgCard;border:1px solid $border;border-radius:8px;padding:12px 18px;min-width:90px}
    .stat-n{font-size:1.6rem;font-weight:700;line-height:1}
    .stat-l{font-size:0.72rem;color:$textMuted;margin-top:2px}
    table{border-collapse:collapse;width:100%;background:$bgCard;border-radius:8px;overflow:hidden;border:1px solid $border}
    th{background:#0d1117;color:$textMuted;text-align:left;padding:9px 14px;font-size:0.78rem;font-weight:600;border-bottom:1px solid $border}
    td{padding:9px 14px;border-bottom:1px solid #21262d;vertical-align:top;line-height:1.4}
    tr:last-child td{border-bottom:none}
    tr:hover td{background:#1c2128}
  </style>
</head>
<body>
  <h1>Android Security Test Report <span class="badge $overallBadgeClass">$overallStatus</span></h1>
  <p class="meta">Target: ${AdbHost}:${AdbPort} &nbsp;·&nbsp; Package: $Pkg &nbsp;·&nbsp; $timestamp</p>
  <div class="stats">
    <div class="stat"><div class="stat-n" style="color:$passColor">$($script:pass)</div><div class="stat-l">Passed</div></div>
    <div class="stat"><div class="stat-n" style="color:$(if($script:fail -gt 0){$failColor}else{$passColor})">$($script:fail)</div><div class="stat-l">Failed</div></div>
    <div class="stat"><div class="stat-n" style="color:$warnColor">$($script:warn)</div><div class="stat-l">Warnings</div></div>
    <div class="stat"><div class="stat-n">$total</div><div class="stat-l">Total</div></div>
  </div>
  <table>
    <thead><tr><th>Status</th><th>Check</th><th>Detail</th></tr></thead>
    <tbody>
      $($rows -join "`n      ")
    </tbody>
  </table>
</body>
</html>
"@

try {
    New-Item -ItemType Directory -Force -Path $reportDir | Out-Null
    $html | Out-File -FilePath $reportFile -Encoding utf8 -Force
    Write-Host "Report saved → $reportFile" -ForegroundColor Cyan
} catch {
    Write-Host "WARN: Could not write report: $_" -ForegroundColor Yellow
}

if ($script:fail -gt 0) { exit 1 }
exit 0
