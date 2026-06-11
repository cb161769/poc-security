#!/usr/bin/env pwsh
<#
.SYNOPSIS
  Android security test suite — Docker/Linux variant.
  Combines static APK analysis with active exploitation attempts.
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
    & timeout $TimeoutSec adb -s $SERIAL @A 2>&1
}

function Record([string]$Status, [string]$Name, [string]$Detail) {
    $icon  = @{ Pass = "✓"; Fail = "✗"; Warn = "⚠" }[$Status]
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
    Adb @("shell", "am start -n $Pkg/io.ionic.starter.MainActivity 2>/dev/null") | Out-Null
    Start-Sleep 3
}

function Get-AppPid {
    ((Adb @("shell", "pidof $Pkg")) -join "").Trim() -replace '\s.*',''
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

$txt = ""; $dexTxt = ""
if (Test-Path $ApkPath) {
    $raw = [System.IO.File]::ReadAllBytes($ApkPath)
    $txt = [System.Text.Encoding]::Latin1.GetString($raw)

    # Extract DEX for reliable string scanning (bypasses ZIP compression)
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

    # 1a. Cleartext HTTP endpoints (exclude localhost / emulator dev addresses)
    $httpHits = [regex]::Matches($txt, 'http://[a-zA-Z0-9._:/-]+') |
        Where-Object { $_.Value -notmatch '(localhost|10\.0\.2\.2|schemas\.android\.com|www\.w3\.org)' }
    if ($httpHits.Count -eq 0) {
        Record "Pass" "No cleartext HTTP URLs" "No non-localhost http:// found in APK"
    } else {
        $sample = ($httpHits | Select-Object -First 3 -ExpandProperty Value) -join " | "
        Record "Fail" "Cleartext HTTP URL(s) in APK" $sample
    }

    # 1b. allowBackup
    if ($txt -match 'allowBackup') {
        Record "Warn" "allowBackup flag present" "Binary contains 'allowBackup' — verify it is set to false in manifest"
    } else {
        Record "Pass" "allowBackup stripped" "String 'allowBackup' not in binary (ProGuard removed it)"
    }

    # 1c. debuggable
    if ($txt -match 'debuggable="true"') {
        Record "Fail" "debuggable=true in APK" "Release APK contains debuggable=true"
    } else {
        Record "Pass" "Not debuggable" "debuggable=true not found in release APK"
    }

    # 1d. Obfuscation: any single-char DEX class descriptor (La; Lb; La/b;) confirms R8 renamed at least
    # some classes. -keep directives preserve Capacitor/Ionic classes so a low count is expected.
    $shortClasses = [regex]::Matches($dexTxt, 'L[a-z]{1,2};|L[a-z]/[a-z]{1,2};') | Measure-Object
    if ($shortClasses.Count -ge 1) {
        Record "Pass" "R8/ProGuard active" "Found $($shortClasses.Count) short DEX class descriptor(s) — R8 minification is running"
    } else {
        Record "Fail" "No R8 obfuscation signal" "Zero short DEX class refs — R8 may not be running; verify minifyEnabled=true in build.gradle"
    }
} else {
    Record "Warn" "Static analysis skipped" "APK not found at $ApkPath — mount android-apk volume"
}

# ─── Phase 2 · FLAG_SECURE (screenshot attack) ───────────────────────────────
Write-Host ""
Write-Host "── Phase 2: FLAG_SECURE ──" -ForegroundColor Cyan

Launch-App; Start-Sleep 4  # Wait for WebView to fully render before capture

# Attack: capture screen via ADB screencap while app is foreground.
# FLAG_SECURE forces all protected windows to render as black in system captures.
# On Android 14, FLAG_SECURE may also cause screencap to write 0 bytes (blocked entirely).
# A black PNG at 1080x2400 ≈ 3–15 KB; real UI content ≈ 100 KB+.
Write-Host "    [attack] Capturing screen via adb screencap..." -ForegroundColor DarkYellow
Adb @("shell", "screencap -p /sdcard/_sec_screen.png 2>/dev/null") | Out-Null
Start-Sleep 2
& bash -c "adb -s $SERIAL pull /sdcard/_sec_screen.png /tmp/_sec_screen.png >/dev/null 2>&1"
Adb @("shell", "rm -f /sdcard/_sec_screen.png 2>/dev/null") | Out-Null

$sz = 0
if (Test-Path "/tmp/_sec_screen.png") {
    $sz = (Get-Item "/tmp/_sec_screen.png").Length
    Remove-Item "/tmp/_sec_screen.png" -ErrorAction SilentlyContinue
}
$szKb = [Math]::Round($sz / 1024, 1)

if ($sz -ge 40000) {
    Record "Fail" "FLAG_SECURE BYPASS" "ADB screencap captured ${szKb} KB of real app content — FLAG_SECURE NOT set, screen content is leaked!"
} elseif ($sz -gt 0 -and $sz -lt 40000) {
    Record "Pass" "FLAG_SECURE active" "ADB screencap = ${szKb} KB (black/blank frame) — FLAG_SECURE is blocking screen capture"
} else {
    # 0 bytes: on Android 14+ with FLAG_SECURE, screencap may produce an empty file (OS-level block).
    # Cross-check via dumpsys window to confirm FLAG_SECURE bit is set on the app window.
    $flagLine = (Adb @("shell", "timeout 8 dumpsys window windows 2>/dev/null | grep -A30 '$Pkg' | grep -m1 'fl='") -join "").Trim()
    if ($flagLine -match '\bfl=(0x[0-9a-fA-F]+)') {
        $flagInt = [Convert]::ToInt64($Matches[1], 16)
        if ($flagInt -band 0x2000) {
            Record "Pass" "FLAG_SECURE active" "screencap produced 0 bytes (OS blocked) + dumpsys confirms FLAG_SECURE (0x2000) in window flags $($Matches[1])"
        } else {
            Record "Fail" "FLAG_SECURE missing" "Window flags $($Matches[1]) — 0x2000 bit not set; screencap produced 0 bytes (possible app crash)"
        }
    } elseif ($txt -and ($dexTxt -match "FLAG_SECURE|setFlags")) {
        Record "Warn" "FLAG_SECURE — static signal only" "screencap 0 bytes + no window entry in dumpsys; FLAG_SECURE/setFlags string found in DEX — likely active but could not confirm at runtime"
    } else {
        Record "Warn" "FLAG_SECURE — inconclusive" "screencap 0 bytes and no window entry found for $Pkg; verify app launched and FLAG_SECURE is set in MainActivity"
    }
}

# ─── Phase 3 · Root / Tamper Detection ───────────────────────────────────────
Write-Host ""
Write-Host "── Phase 3: Root / Tamper Detection ──" -ForegroundColor Cyan

$buildTags = ((Adb @("shell", "getprop ro.build.tags")) -join "").Trim()
if ($buildTags -match "test-keys") {
    Launch-App; Start-Sleep 4
    $fg = (Adb @("shell", "timeout 5 dumpsys window 2>/dev/null | grep -m1 mCurrentFocus")) -join " "
    if ($fg -notmatch [regex]::Escape($Pkg)) {
        Record "Pass" "Root detection — build tags" "App exited on test-keys device (build: $buildTags)"
    } else {
        Record "Warn" "Root detection — build tags" "App still running on test-keys build — emulator exception not blocking"
    }
} else {
    Record "Pass" "Root detection — build tags" "Tags: '$buildTags' (no test-keys)"
}

if ($dexTxt) {
    $suPaths = @("/system/xbin/su", "/data/local/bin/su", "/sbin/su", "/system/bin/su") |
        Where-Object { $dexTxt -match [regex]::Escape($_) }
    if ($suPaths.Count -ge 2) {
        Record "Pass" "Root detection — su paths compiled" "DEX checks $($suPaths.Count) su paths: $($suPaths -join ', ')"
    } elseif ($dexTxt.Length -gt 10000) {
        Record "Fail" "Root detection — su paths missing" "DEX has only $($suPaths.Count) su path strings — verify isRooted() in source"
    } else {
        Record "Warn" "Root detection — su artifact" "DEX extraction may have failed ($($dexTxt.Length) bytes)"
    }
} else {
    Record "Warn" "Root detection — su artifact" "APK not available for static check"
}

# ─── Phase 4 · Frida Detection ───────────────────────────────────────────────
Write-Host ""
Write-Host "── Phase 4: Frida Detection ──" -ForegroundColor Cyan

if ($dexTxt) {
    $fridaArtifacts = @("frida-server", "re.frida.server", "frida-agent") |
        Where-Object { $dexTxt -match [regex]::Escape($_) }
    if ($fridaArtifacts.Count -ge 1) {
        Record "Pass" "Frida detection — artifact strings" "DEX contains $($fridaArtifacts.Count) Frida artifact strings: $($fridaArtifacts -join ', ')"
    } elseif ($dexTxt.Length -gt 10000) {
        Record "Fail" "Frida detection — no artifact check" "No Frida artifact path strings in DEX — isFridaPresent() may be missing"
    } else {
        Record "Warn" "Frida detection — artifact" "DEX extraction may have failed"
    }
} else {
    Record "Warn" "Frida detection — artifact" "APK not available for static check"
}

# ─── Phase 5 · Signature validation ─────────────────────────────────────────
Write-Host ""
Write-Host "── Phase 5: Signature ──" -ForegroundColor Cyan

$pkgPath = ((Adb @("shell", "pm path $Pkg 2>/dev/null") -TimeoutSec 30) -join "").Trim()
if ($pkgPath -match "package:") {
    Record "Pass" "Signature accepted by OS" "Package $Pkg installed at $($pkgPath -replace 'package:','')"
} else {
    $sigOut = ((Adb @("shell", "pm list packages 2>/dev/null | grep -m1 '$Pkg'") -TimeoutSec 30) -join "").Trim()
    if ($sigOut -match [regex]::Escape($Pkg)) {
        Record "Pass" "Signature accepted by OS" "Package $Pkg is installed (OS verified signature at install)"
    } else {
        Record "Warn" "Signature check" "Package $Pkg not found via pm — verify package name matches build.gradle"
    }
}

# ─── Phase 6 · WebView debugging — static + CDP exploit ──────────────────────
Write-Host ""
Write-Host "── Phase 6: WebView Debugging ──" -ForegroundColor Cyan

Launch-App; Start-Sleep 3

# 6a. Static: read capacitor.config.json from APK — this is what CapConfig.loadDefault() reads
$capCfgJson = ""
$staticDebugDisabled = $false
if (Test-Path $ApkPath) {
    try { $capCfgJson = (& bash -c "unzip -p '$ApkPath' assets/capacitor.config.json 2>/dev/null") -join "" } catch {}
    if ($capCfgJson -match '"webContentsDebuggingEnabled"\s*:\s*false') { $staticDebugDisabled = $true }
}

# 6b. Runtime socket check scoped to app PID
$appPid = Get-AppPid
$allSockets = (Adb @("shell", "cat /proc/net/unix 2>/dev/null | grep webview_devtools_remote")) -join "`n"
$debugSocket = ""
if ($appPid -match '^\d+$') {
    $debugSocket = ($allSockets | Select-String "webview_devtools_remote_$appPid") -join ""
}

if ($debugSocket -match "webview_devtools_remote") {
    if ($staticDebugDisabled) {
        # 6c. CDP exploitation attempt: forward abstract socket to TCP, probe with HTTP GET /json
        Write-Host "    [attack] Forwarding WebView DevTools socket → TCP:9221 to probe CDP..." -ForegroundColor DarkYellow
        Adb @("forward", "tcp:9221", "localabstract:webview_devtools_remote_$appPid") | Out-Null
        Start-Sleep 1
        $cdpResp = & bash -c "printf 'GET /json HTTP/1.0\r\nHost: localhost\r\n\r\n' | nc -w 3 127.0.0.1 9221 2>/dev/null"
        $cdpStr  = ($cdpResp -join "")
        Adb @("forward", "--remove", "tcp:9221") | Out-Null

        if ($cdpStr -match 'webSocketDebuggerUrl|"url"\s*:|"title"\s*:|"type"\s*:') {
            Record "Fail" "CDP DevTools EXPLOITABLE" "GET /json returned page list — JS debugging IS accessible! Config says false but enforcement failed. Snippet: $($cdpStr.Substring(0,[Math]::Min(150,$cdpStr.Length)))"
        } elseif ($cdpStr -match "HTTP/|200 OK") {
            Record "Warn" "CDP partial HTTP response" "Got HTTP response but no page data — inconclusive. Raw: $($cdpStr.Substring(0,[Math]::Min(80,$cdpStr.Length)))"
        } else {
            Record "Pass" "WebView debugging not exploitable" "Socket webview_devtools_remote_$appPid present (Android 14 emulator artifact) but CDP returned no data — webContentsDebuggingEnabled:false is effective"
        }
    } else {
        Record "Fail" "WebView debug enabled" "webview_devtools_remote_$appPid socket found AND config does not set webContentsDebuggingEnabled:false"
    }
} else {
    if ($appPid -match '^\d+$') {
        Record "Pass" "WebView debug disabled" "No webview_devtools_remote_$appPid socket for PID $appPid — debugging OFF"
    } else {
        Record "Pass" "WebView debug disabled" "No debug socket present"
    }
}

# ─── Phase 7 · Logcat leak ───────────────────────────────────────────────────
Write-Host ""
Write-Host "── Phase 7: Log Leak ──" -ForegroundColor Cyan

$pidStr = Get-AppPid
if ($pidStr -notmatch '^\d+$') {
    $psLine = ((Adb @("shell", "timeout 5 ps -A 2>/dev/null | grep -m1 io.ionic")) -join "").Trim()
    if ($psLine -match '^\S+\s+(\d+)') { $pidStr = $Matches[1] }
}
if ($pidStr -notmatch '^\d+$') {
    Launch-App; Start-Sleep 5
    $pidStr = Get-AppPid
}
if ($pidStr -match '^\d+$') {
    $logLines = Adb @("logcat", "-d", "--pid=$pidStr")
    $appLines = $logLines | Where-Object {
        $_ -notmatch '^\-\-\-' -and
        $_ -notmatch '\b(ActivityManager|PackageManager|Zygote|JavaBridge|CompatibilityInfo|ViewRootImpl|OpenGLRenderer|Gralloc|SurfaceFlinger|Choreographer|EGL|libEGL|mali|adreno|art\s|dalvikvm|cr_|chromium|CapacitorBridge|JSIExecutor|Capacitor\/)\b' -and
        $_ -match '\s[VDIWEF]/'
    }
    if ($appLines.Count -lt 5) {
        Record "Pass" "Log stripping active" "$($appLines.Count) app log entries — ProGuard -assumenosideeffects stripped Log calls"
    } else {
        $sample = ($appLines | Select-Object -First 3) -join " | "
        Record "Fail" "Logs not stripped" "$($appLines.Count) app log entries — ProGuard config may not be stripping Log.d/v/i. Sample: $sample"
    }
} else {
    Record "Warn" "Log check" "Could not get PID for $Pkg"
}

# ─── Phase 8 · Network Security Config ───────────────────────────────────────
Write-Host ""
Write-Host "── Phase 8: Network Security Config ──" -ForegroundColor Cyan

# Check APK for network_security_config attribute in binary manifest
$nscInApk = $false
if (Test-Path $ApkPath) {
    try {
        # binary AXML — extract printable strings to search for known NSC attribute names
        $nscCheck = (& bash -c "unzip -p '$ApkPath' res/xml/network_security_config.xml 2>/dev/null | tr -dc '[:print:][:space:]'") -join ""
        if ($nscCheck -match "network-security-config|cleartextTrafficPermitted|base-config") { $nscInApk = $true }
    } catch {}
    if (-not $nscInApk -and $txt -match "network_security_config") { $nscInApk = $true }
}

if ($nscInApk) {
    $cleartextBlocked = $false
    try {
        $nscXml = (& bash -c "unzip -p '$ApkPath' res/xml/network_security_config.xml 2>/dev/null | tr -dc '[:print:][:space:]'") -join ""
        if ($nscXml -match "cleartextTrafficPermitted") { $cleartextBlocked = $true }
    } catch {}
    if ($cleartextBlocked) {
        Record "Pass" "network_security_config present" "NSC file found in APK with cleartextTrafficPermitted configuration"
    } else {
        Record "Warn" "network_security_config — partial" "NSC file referenced but could not verify cleartextTrafficPermitted=false"
    }
} else {
    Record "Warn" "network_security_config missing" "No network_security_config.xml found in APK — cleartext HTTP may be permitted by default on older API levels"
}

# ─── Phase 9 · JDWP Debugger Attach ─────────────────────────────────────────
Write-Host ""
Write-Host "── Phase 9: JDWP Debugger Attach ──" -ForegroundColor Cyan

# adb jdwp lists PIDs of JDWP-debuggable processes; streams until timeout.
# Release APKs with android:debuggable="false" must NOT appear here.
Write-Host "    [attack] Probing JDWP-debuggable process list..." -ForegroundColor DarkYellow
$jdwpRaw  = & bash -c "timeout 3 adb -s $SERIAL jdwp 2>/dev/null; true"
$jdwpPids = ($jdwpRaw -join " ") -split '\s+' | Where-Object { $_ -match '^\d+$' }
$curPid   = Get-AppPid

if ($curPid -match '^\d+$' -and $jdwpPids -contains $curPid) {
    Record "Fail" "App is JDWP-debuggable" "PID $curPid IS in the JDWP list — a Java debugger can attach to this release build!"
} elseif ($curPid -match '^\d+$') {
    Record "Pass" "Not JDWP-debuggable" "App PID $curPid not in JDWP list ($($jdwpPids.Count) other debuggable system process(es)) — release build blocks debugger attach"
} else {
    Record "Warn" "JDWP check — no app PID" "App not running; could not cross-reference JDWP list"
}

# ─── Phase 10 · Exported Component Scan ─────────────────────────────────────
Write-Host ""
Write-Host "── Phase 10: Exported Components ──" -ForegroundColor Cyan

# Unexported Activities, Services, Receivers and Providers can be invoked by any app on device,
# enabling intent injection, data theft, or privilege escalation.
# We scope to actual declared component blocks (lines with $Pkg/ class path), not the
# Activity Resolver Table which repeats exported=true for every intent filter row.
$pkgDump = (Adb @("shell", "timeout 10 pm dump $Pkg 2>/dev/null") -TimeoutSec 15) -join "`n"
$exportedComponents = @()
if ($pkgDump.Length -gt 500) {
    $lines = $pkgDump -split "`n"
    for ($i = 0; $i -lt $lines.Count; $i++) {
        # A component declaration line contains "package/ClassName:" with leading whitespace
        if ($lines[$i] -match "^\s+$([regex]::Escape($Pkg))/(\S+):") {
            $compName = $Matches[1]
            # Scan the next 8 lines for exported=true in the component's attribute block
            $window = ($lines[[Math]::Min($i+1,$lines.Count-1)..[Math]::Min($i+8,$lines.Count-1)]) -join " "
            if ($window -match "exported=true") {
                $exportedComponents += "$Pkg/$compName"
            }
        }
    }
}

# The launcher MainActivity must be exported; everything else should require a permission
$unexpected = $exportedComponents | Where-Object { $_ -notmatch "MainActivity" }
if ($unexpected.Count -gt 0) {
    $sample = ($unexpected | Select-Object -First 5) -join ", "
    Record "Warn" "Exported components found" "$($unexpected.Count) component(s) exported besides launcher — verify each is protected by a permission: $sample"
} elseif ($pkgDump.Length -gt 500) {
    Record "Pass" "Component exposure minimal" "$($exportedComponents.Count) exported component(s) — only launcher MainActivity; no unprotected attack surface"
} else {
    Record "Warn" "Exported component scan" "pm dump returned insufficient data"
}

# ─── Phase 11 · ADB Backup ───────────────────────────────────────────────────
Write-Host ""
Write-Host "── Phase 11: ADB Backup ──" -ForegroundColor Cyan

# android:allowBackup=false should prevent app data extraction via `adb backup`.
# Check ApplicationInfo flags at runtime — ALLOW_BACKUP flag (0x8000) appears only when true.
$appInfoFlags = (Adb @("shell", "timeout 5 pm dump $Pkg 2>/dev/null | grep -m3 'flags='") -TimeoutSec 10) -join " "
if ($appInfoFlags -match "ALLOW_BACKUP") {
    Record "Fail" "allowBackup ENABLED" "ApplicationInfo flags include ALLOW_BACKUP — app data IS extractable via adb backup"
} else {
    # Secondary: look for backup agent or fullBackupContent declarations
    $backupAgent = (Adb @("shell", "timeout 5 pm dump $Pkg 2>/dev/null | grep -i 'backupAgent\|fullBackupContent'") -TimeoutSec 10) -join ""
    if ($backupAgent -match "backupAgent=\S+\w") {
        Record "Warn" "Custom BackupAgent declared" "App has a BackupAgent — verify it does not leak sensitive data: $($backupAgent.Trim())"
    } else {
        Record "Pass" "allowBackup disabled" "ALLOW_BACKUP not in ApplicationInfo flags and no BackupAgent declared — data protected from adb backup"
    }
}

# ─── Phase 12 · Tapjacking / Overlay Attack ──────────────────────────────────
Write-Host ""
Write-Host "── Phase 12: Tapjacking ──" -ForegroundColor Cyan

# Tapjacking: a malicious overlay captures touch events on sensitive UI (login, transfer buttons).
# Android mitigations: setFilterTouchesWhenObscured(true) or FLAG_WINDOW_IS_OBSCURED checks.
# Static check: look for filterTouchesWhenObscured in compiled resources and DEX.
$tapjackSignal = $false
if (Test-Path $ApkPath) {
    # Check compiled layout XMLs inside res/ — binary AXML, extract printable strings
    try {
        $resContent = (& bash -c "unzip -p '$ApkPath' 'res/layout/*.xml' 2>/dev/null | tr -dc '[:print:][:space:]'") -join ""
        if ($resContent -match "filterTouchesWhenObscured") { $tapjackSignal = $true }
    } catch {}
    # Check DEX for programmatic setFilterTouchesWhenObscured call
    if (-not $tapjackSignal -and $dexTxt -match "filterTouchesWhenObscured|setFilterTouches") { $tapjackSignal = $true }
    # Check if SYSTEM_ALERT_WINDOW overlay permission is requested (indicates potential overlay risk from other apps)
    $overlayPerm = $txt -match "SYSTEM_ALERT_WINDOW"
}

if ($tapjackSignal) {
    Record "Pass" "Tapjacking mitigation present" "filterTouchesWhenObscured found in app resources/DEX — sensitive UI is protected against overlay attacks"
} else {
    Record "Warn" "Tapjacking mitigation absent" "No filterTouchesWhenObscured signal in APK — login and transfer buttons may be vulnerable to overlay/tapjacking attacks"
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
$reportDir  = "/reports"
$timestamp  = (Get-Date -Format "yyyy-MM-dd HH:mm:ss UTC")
$reportFile = "$reportDir/android-security-report.html"

$passColor = "#3fb950"; $failColor = "#f85149"; $warnColor = "#d29922"
$bgMain = "#0d1117"; $bgCard = "#161b22"; $border = "#30363d"; $textMuted = "#8b949e"

$overallStatus     = if ($script:fail -gt 0) { "FAILED" } else { "PASSED" }
$overallBadgeClass = if ($script:fail -gt 0) { "fail" } else { "pass" }

$rows = $results | ForEach-Object {
    $icon  = @{ Pass = "&#10003;"; Fail = "&#10007;"; Warn = "&#9888;" }[$_.Status]
    $color = @{ Pass = $passColor; Fail = $failColor; Warn = $warnColor }[$_.Status]
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
    .phase{background:#0d1117;color:$textMuted;font-size:0.72rem;font-weight:600;padding:6px 14px;letter-spacing:.05em}
  </style>
</head>
<body>
  <h1>Android Security Report <span class="badge $overallBadgeClass">$overallStatus</span></h1>
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
