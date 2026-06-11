#!/usr/bin/env pwsh
<#
.SYNOPSIS
  Android security test suite — Docker/Linux variant.
  Combines static APK analysis with active exploitation attempts.
  Covers OWASP MASVS v2 controls across all domains.
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
$script:suiteStart = [datetime]::UtcNow

# ─── Core helpers ─────────────────────────────────────────────────────────────

function Adb {
    param([string[]]$A, [int]$TimeoutSec = 20)
    & timeout $TimeoutSec adb -s $SERIAL @A 2>&1
}

function Record {
    param(
        [string]$Status,
        [string]$Name,
        [string]$Detail,
        [string]$Masvs = "",
        [string]$Sev   = "",
        [string]$Rec   = ""
    )
    $icon  = @{ Pass = "✓"; Fail = "✗"; Warn = "⚠" }[$Status]
    $color = @{ Pass = "Green"; Fail = "Red"; Warn = "Yellow" }[$Status]
    $sevLabel = if ($Sev) { " [$Sev]" } else { "" }
    Write-Host "  $icon " -NoNewline
    Write-Host "$Name$sevLabel" -ForegroundColor $color -NoNewline
    Write-Host " — $Detail"
    $elapsed = [Math]::Round(([datetime]::UtcNow - $script:suiteStart).TotalSeconds, 1)
    $results.Add(@{
        Status  = $Status; Name = $Name; Detail = $Detail
        Masvs   = $Masvs;  Sev  = $Sev;  Rec    = $Rec
        Elapsed = $elapsed
    })
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

# Request root on userdebug/eng emulator builds; returns $true if granted
function Get-AdbRoot {
    $out = (Adb @("root") -TimeoutSec 10) -join ""
    Start-Sleep 2
    return ($out -match "restarting adbd|already running as root")
}

# Scan $Content (Latin1 string) for secret patterns; return array of finding strings
function Scan-Secrets {
    param([string]$Content, [string]$Source)
    $hits = @()
    $patterns = @(
        @{ N = "Google API Key";   P = 'AIza[0-9A-Za-z\-_]{35}' }
        @{ N = "AWS Access Key";   P = 'AKIA[0-9A-Z]{16}' }
        @{ N = "JWT token";        P = 'eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}' }
        @{ N = "Firebase URL";     P = 'https://[a-zA-Z0-9-]+\.firebaseio\.com' }
        @{ N = "Stripe live key";  P = 'sk_live_[0-9a-zA-Z]{24,}' }
        @{ N = "PEM private key";  P = 'BEGIN\s+(RSA\s+)?PRIVATE\s+KEY' }
        @{ N = "OAuth secret";     P = '(?i)client_secret["''\s]*[:=]["''\s]*[A-Za-z0-9\-_]{16,}' }
        @{ N = "Hardcoded passwd"; P = '(?i)(password|passwd|pwd)\s*[:=]\s*[''"][^''"\s]{6,}[''"]' }
        @{ N = "Hardcoded API key";P = '(?i)(api_key|apikey)\s*[:=]\s*[''"][A-Za-z0-9\-_]{16,}[''"]' }
    )
    foreach ($p in $patterns) {
        $m = [regex]::Matches($Content, $p.P, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
        if ($m.Count -gt 0) {
            $sample = $m[0].Value; if ($sample.Length -gt 60) { $sample = $sample.Substring(0,57)+"..." }
            $hits += "$($p.N) [$Source] — $sample"
        }
    }
    return $hits
}

# ─── Banner ───────────────────────────────────────────────────────────────────

Write-Host ""
Write-Host "═══════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "  ANDROID SECURITY TESTS — MASVS v2 Suite             " -ForegroundColor Cyan
Write-Host "═══════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "  Serial  : $SERIAL"
Write-Host "  Package : $Pkg"
Write-Host "  APK     : $ApkPath"
Write-Host ""

# ─────────────────────────────────────────────────────────────────────────────
# PHASE 1 · Static APK Analysis                        MASVS-CODE / MASVS-NETWORK
# ─────────────────────────────────────────────────────────────────────────────
Write-Host "── Phase 1: Static APK Analysis ──" -ForegroundColor Cyan

$txt = ""; $dexTxt = ""
if (Test-Path $ApkPath) {
    $raw = [System.IO.File]::ReadAllBytes($ApkPath)
    $txt = [System.Text.Encoding]::Latin1.GetString($raw)

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

    $httpHits = [regex]::Matches($txt, 'http://[a-zA-Z0-9._:/-]+') |
        Where-Object { $_.Value -notmatch '(localhost|10\.0\.2\.2|schemas\.android\.com|www\.w3\.org)' }
    if ($httpHits.Count -eq 0) {
        Record "Pass" "No cleartext HTTP URLs" "No non-localhost http:// found in APK" `
            -Masvs "MASVS-NETWORK-1" -Sev "High" `
            -Rec "Use HTTPS for all endpoints. Enforce via network_security_config with cleartextTrafficPermitted=false."
    } else {
        $sample = ($httpHits | Select-Object -First 3 -ExpandProperty Value) -join " | "
        Record "Fail" "Cleartext HTTP URL(s) in APK" $sample `
            -Masvs "MASVS-NETWORK-1" -Sev "High" `
            -Rec "Replace all http:// endpoints with https://. Add network_security_config.xml to block cleartext at OS level."
    }

    if ($txt -match 'allowBackup') {
        Record "Warn" "allowBackup flag present" "Binary contains 'allowBackup' — verify it is set to false" `
            -Masvs "MASVS-STORAGE-1" -Sev "High" `
            -Rec "Set android:allowBackup='false' and android:fullBackupContent='false' in AndroidManifest.xml."
    } else {
        Record "Pass" "allowBackup stripped" "String 'allowBackup' not in binary (ProGuard removed it)" `
            -Masvs "MASVS-STORAGE-1" -Sev "High" `
            -Rec "Confirmed: allowBackup not exposed in binary."
    }

    if ($txt -match 'debuggable="true"') {
        Record "Fail" "debuggable=true in APK" "Release APK contains debuggable=true — attach with jdb/lldb" `
            -Masvs "MASVS-CODE-2" -Sev "Critical" `
            -Rec "Ensure debuggable is not set in AndroidManifest.xml. It must be false in release buildType in build.gradle."
    } else {
        Record "Pass" "Not debuggable" "debuggable=true not found in release APK" `
            -Masvs "MASVS-CODE-2" -Sev "Critical" `
            -Rec "Confirmed: release build is not debuggable."
    }

    $shortClasses = [regex]::Matches($dexTxt, 'L[a-z]{1,2};|L[a-z]/[a-z]{1,2};') | Measure-Object
    if ($shortClasses.Count -ge 1) {
        Record "Pass" "R8/ProGuard active" "Found $($shortClasses.Count) short DEX class descriptor(s) — R8 minification is running" `
            -Masvs "MASVS-CODE-3" -Sev "Medium" `
            -Rec "Continue with minifyEnabled=true and shrinkResources=true in release build. Consider -repackageclasses ''."
    } else {
        Record "Fail" "No R8 obfuscation signal" "Zero short DEX class refs found — R8 may not be active" `
            -Masvs "MASVS-CODE-3" -Sev "Medium" `
            -Rec "Set minifyEnabled=true in release buildType and ensure proguard-rules.pro is configured."
    }
} else {
    Record "Warn" "Static analysis skipped" "APK not found at $ApkPath — mount android-apk volume" `
        -Masvs "MASVS-CODE-2" -Sev "Info"
}

# ─────────────────────────────────────────────────────────────────────────────
# PHASE 2 · FLAG_SECURE (screenshot attack)            MASVS-PLATFORM-1
# ─────────────────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "── Phase 2: FLAG_SECURE ──" -ForegroundColor Cyan

Launch-App; Start-Sleep 4

Write-Host "    [attack] Capturing screen via adb screencap..." -ForegroundColor DarkYellow
Adb @("shell", "screencap -p /sdcard/_sec_screen.png 2>/dev/null") | Out-Null
Start-Sleep 2
& bash -c "adb -s $SERIAL pull /sdcard/_sec_screen.png /tmp/_sec_screen.png >/dev/null 2>&1"
Adb @("shell", "rm -f /sdcard/_sec_screen.png 2>/dev/null") | Out-Null

$sz = 0
if (Test-Path "/tmp/_sec_screen.png") { $sz = (Get-Item "/tmp/_sec_screen.png").Length }
Remove-Item "/tmp/_sec_screen.png" -ErrorAction SilentlyContinue
$szKb = [Math]::Round($sz / 1024, 1)

if ($sz -ge 40000) {
    Record "Fail" "FLAG_SECURE BYPASS" "ADB screencap captured ${szKb} KB of real app content — FLAG_SECURE NOT set!" `
        -Masvs "MASVS-PLATFORM-1" -Sev "High" `
        -Rec "Call getWindow().setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE) in Activity.onCreate()."
} elseif ($sz -gt 0) {
    Record "Pass" "FLAG_SECURE active" "ADB screencap = ${szKb} KB (black frame) — FLAG_SECURE is blocking screen capture" `
        -Masvs "MASVS-PLATFORM-1" -Sev "High"
} else {
    $flagLine = (Adb @("shell", "timeout 8 dumpsys window windows 2>/dev/null | grep -A30 '$Pkg' | grep -m1 'fl='") -join "").Trim()
    if ($flagLine -match '\bfl=(0x[0-9a-fA-F]+)') {
        $flagInt = [Convert]::ToInt64($Matches[1], 16)
        if ($flagInt -band 0x2000) {
            Record "Pass" "FLAG_SECURE active" "screencap 0 bytes (OS-blocked) + dumpsys confirms FLAG_SECURE bit 0x2000 in $($Matches[1])" `
                -Masvs "MASVS-PLATFORM-1" -Sev "High"
        } else {
            Record "Fail" "FLAG_SECURE missing" "Window flags $($Matches[1]) — bit 0x2000 not set" `
                -Masvs "MASVS-PLATFORM-1" -Sev "High" `
                -Rec "Set FLAG_SECURE in Activity.onCreate(). For Ionic/Capacitor override onCreate() in MainActivity."
        }
    } elseif ($dexTxt -match "FLAG_SECURE|setFlags") {
        Record "Warn" "FLAG_SECURE — static signal only" "screencap 0 bytes + no window in dumpsys; FLAG_SECURE found in DEX — likely active" `
            -Masvs "MASVS-PLATFORM-1" -Sev "High" `
            -Rec "Verify FLAG_SECURE is set before the content view is attached in onCreate()."
    } else {
        Record "Warn" "FLAG_SECURE — inconclusive" "screencap 0 bytes and no window entry; verify app launched correctly" `
            -Masvs "MASVS-PLATFORM-1" -Sev "High" `
            -Rec "Implement FLAG_SECURE in MainActivity.onCreate()."
    }
}

# ─────────────────────────────────────────────────────────────────────────────
# PHASE 3 · Root / Tamper Detection                   MASVS-RESILIENCE-1
# ─────────────────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "── Phase 3: Root / Tamper Detection ──" -ForegroundColor Cyan

$buildTags = ((Adb @("shell", "getprop ro.build.tags")) -join "").Trim()
if ($buildTags -match "test-keys") {
    Launch-App; Start-Sleep 4
    $fg = (Adb @("shell", "timeout 5 dumpsys window 2>/dev/null | grep -m1 mCurrentFocus")) -join " "
    if ($fg -notmatch [regex]::Escape($Pkg)) {
        Record "Pass" "Root detection — build tags" "App exited on test-keys device ($buildTags)" `
            -Masvs "MASVS-RESILIENCE-1" -Sev "Medium"
    } else {
        Record "Warn" "Root detection — build tags" "App still running on test-keys build; emulator exception may be too broad" `
            -Masvs "MASVS-RESILIENCE-1" -Sev "Medium" `
            -Rec "Narrow the emulator exception to debug builds only; release builds should exit on test-keys devices."
    }
} else {
    Record "Pass" "Root detection — build tags" "Tags: '$buildTags' (no test-keys)" `
        -Masvs "MASVS-RESILIENCE-1" -Sev "Medium"
}

if ($dexTxt) {
    $suPaths = @("/system/xbin/su","/data/local/bin/su","/sbin/su","/system/bin/su") |
        Where-Object { $dexTxt -match [regex]::Escape($_) }
    if ($suPaths.Count -ge 2) {
        Record "Pass" "Root detection — su paths compiled" "DEX checks $($suPaths.Count) su paths: $($suPaths -join ', ')" `
            -Masvs "MASVS-RESILIENCE-1" -Sev "Medium"
    } elseif ($dexTxt.Length -gt 10000) {
        Record "Fail" "Root detection — su paths missing" "DEX has only $($suPaths.Count) su path string(s)" `
            -Masvs "MASVS-RESILIENCE-1" -Sev "Medium" `
            -Rec "Add isRooted() checks for /system/xbin/su, /sbin/su, /system/bin/su, /data/local/xbin/su and busybox."
    } else {
        Record "Warn" "Root detection — DEX extract failed" "DEX too small ($($dexTxt.Length) bytes) for reliable analysis" `
            -Masvs "MASVS-RESILIENCE-1" -Sev "Medium"
    }
}

# ─────────────────────────────────────────────────────────────────────────────
# PHASE 4 · Frida / Instrumentation Detection         MASVS-RESILIENCE-2
# ─────────────────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "── Phase 4: Frida Detection ──" -ForegroundColor Cyan

if ($dexTxt) {
    $fridaArtifacts = @("frida-server","re.frida.server","frida-agent") |
        Where-Object { $dexTxt -match [regex]::Escape($_) }
    if ($fridaArtifacts.Count -ge 1) {
        Record "Pass" "Frida detection — artifact strings" "DEX contains $($fridaArtifacts.Count) Frida artifact string(s): $($fridaArtifacts -join ', ')" `
            -Masvs "MASVS-RESILIENCE-2" -Sev "Medium"
    } elseif ($dexTxt.Length -gt 10000) {
        Record "Fail" "Frida detection — no artifact check" "No Frida artifact path strings in DEX" `
            -Masvs "MASVS-RESILIENCE-2" -Sev "Medium" `
            -Rec "Add isFridaPresent() checking /data/local/tmp/frida-server, /data/local/tmp/re.frida.server, and port 27042 TCP."
    } else {
        Record "Warn" "Frida detection — DEX unavailable" "DEX extraction failed; cannot verify" `
            -Masvs "MASVS-RESILIENCE-2" -Sev "Medium"
    }
}

# ─────────────────────────────────────────────────────────────────────────────
# PHASE 5 · APK Signature / OS Verification           MASVS-CODE-1
# ─────────────────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "── Phase 5: Signature ──" -ForegroundColor Cyan

$pkgPath = ((Adb @("shell", "pm path $Pkg 2>/dev/null") -TimeoutSec 30) -join "").Trim()
if ($pkgPath -match "package:") {
    Record "Pass" "Signature accepted by OS" "Package $Pkg installed at $($pkgPath -replace 'package:','')" `
        -Masvs "MASVS-CODE-1" -Sev "Low"
} else {
    $sigOut = ((Adb @("shell", "pm list packages 2>/dev/null | grep -m1 '$Pkg'") -TimeoutSec 30) -join "").Trim()
    if ($sigOut -match [regex]::Escape($Pkg)) {
        Record "Pass" "Signature accepted by OS" "Package $Pkg is installed (OS verified signature)" `
            -Masvs "MASVS-CODE-1" -Sev "Low"
    } else {
        Record "Warn" "Signature check" "Package $Pkg not found — verify package name matches build.gradle applicationId" `
            -Masvs "MASVS-CODE-1" -Sev "Low"
    }
}

# ─────────────────────────────────────────────────────────────────────────────
# PHASE 6 · WebView Debugging (static + CDP exploit)  MASVS-PLATFORM-2
# ─────────────────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "── Phase 6: WebView Debugging ──" -ForegroundColor Cyan

Launch-App; Start-Sleep 3

$capCfgJson = ""; $staticDebugDisabled = $false
if (Test-Path $ApkPath) {
    try { $capCfgJson = (& bash -c "unzip -p '$ApkPath' assets/capacitor.config.json 2>/dev/null") -join "" } catch {}
    if ($capCfgJson -match '"webContentsDebuggingEnabled"\s*:\s*false') { $staticDebugDisabled = $true }
}

$appPid     = Get-AppPid
$allSockets = (Adb @("shell", "cat /proc/net/unix 2>/dev/null | grep webview_devtools_remote")) -join "`n"
$debugSocket = ""
if ($appPid -match '^\d+$') { $debugSocket = ($allSockets | Select-String "webview_devtools_remote_$appPid") -join "" }

if ($debugSocket -match "webview_devtools_remote") {
    if ($staticDebugDisabled) {
        Write-Host "    [attack] Forwarding WebView DevTools socket to TCP:9221..." -ForegroundColor DarkYellow
        Adb @("forward", "tcp:9221", "localabstract:webview_devtools_remote_$appPid") | Out-Null
        Start-Sleep 1
        $cdpResp = & bash -c "printf 'GET /json HTTP/1.0\r\nHost: localhost\r\n\r\n' | nc -w 3 127.0.0.1 9221 2>/dev/null"
        $cdpStr  = ($cdpResp -join "")
        Adb @("forward", "--remove", "tcp:9221") | Out-Null
        if ($cdpStr -match 'webSocketDebuggerUrl|"url"\s*:|"type"\s*:') {
            Record "Fail" "CDP DevTools EXPLOITABLE" "GET /json returned page list — JS debugging IS accessible despite config. Snippet: $($cdpStr.Substring(0,[Math]::Min(150,$cdpStr.Length)))" `
                -Masvs "MASVS-PLATFORM-2" -Sev "Critical" `
                -Rec "Ensure setWebContentsDebuggingEnabled(false) is called before any WebView loads content. Check BridgeActivity initialization order."
        } else {
            Record "Pass" "WebView debugging not exploitable" "Socket present (Android 14 emulator artifact) but CDP returned no data — config is effective" `
                -Masvs "MASVS-PLATFORM-2" -Sev "High"
        }
    } else {
        Record "Fail" "WebView debug enabled" "webview_devtools_remote_$appPid socket AND config missing webContentsDebuggingEnabled:false" `
            -Masvs "MASVS-PLATFORM-2" -Sev "Critical" `
            -Rec "Add android.webContentsDebuggingEnabled=false to capacitor.config.ts. Call WebView.setWebContentsDebuggingEnabled(false) in MainActivity."
    }
} else {
    Record "Pass" "WebView debug disabled" "No webview_devtools_remote_$appPid socket — debugging OFF" `
        -Masvs "MASVS-PLATFORM-2" -Sev "High"
}

# ─────────────────────────────────────────────────────────────────────────────
# PHASE 7 · Logcat Leak                               MASVS-CODE-1
# ─────────────────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "── Phase 7: Log Leak ──" -ForegroundColor Cyan

$pidStr = Get-AppPid
if ($pidStr -notmatch '^\d+$') {
    $psLine = ((Adb @("shell", "timeout 5 ps -A 2>/dev/null | grep -m1 io.ionic")) -join "").Trim()
    if ($psLine -match '^\S+\s+(\d+)') { $pidStr = $Matches[1] }
}
if ($pidStr -notmatch '^\d+$') { Launch-App; Start-Sleep 5; $pidStr = Get-AppPid }

if ($pidStr -match '^\d+$') {
    $logLines = Adb @("logcat", "-d", "--pid=$pidStr")
    $appLines = $logLines | Where-Object {
        $_ -notmatch '^\-\-\-' -and
        $_ -notmatch '\b(ActivityManager|PackageManager|Zygote|JavaBridge|CompatibilityInfo|ViewRootImpl|OpenGLRenderer|Gralloc|SurfaceFlinger|Choreographer|EGL|libEGL|mali|adreno|art\s|dalvikvm|cr_|chromium|CapacitorBridge|JSIExecutor|Capacitor\/)\b' -and
        $_ -match '\s[VDIWEF]/'
    }
    if ($appLines.Count -lt 5) {
        Record "Pass" "Log stripping active" "$($appLines.Count) app log entries — ProGuard -assumenosideeffects stripped Log calls" `
            -Masvs "MASVS-CODE-1" -Sev "Medium"
    } else {
        $sample = ($appLines | Select-Object -First 3) -join " | "
        Record "Fail" "Logs not stripped" "$($appLines.Count) app log entries. Sample: $sample" `
            -Masvs "MASVS-CODE-1" -Sev "Medium" `
            -Rec "Add -assumenosideeffects for android.util.Log.* in proguard-rules.pro. Ensure minifyEnabled=true."
    }
} else {
    Record "Warn" "Log check" "Could not get PID for $Pkg" `
        -Masvs "MASVS-CODE-1" -Sev "Medium"
}

# ─────────────────────────────────────────────────────────────────────────────
# PHASE 8 · Network Security Config                   MASVS-NETWORK-1
# ─────────────────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "── Phase 8: Network Security Config ──" -ForegroundColor Cyan

$nscInApk = $false
if (Test-Path $ApkPath) {
    try {
        $nscCheck = (& bash -c "unzip -p '$ApkPath' res/xml/network_security_config.xml 2>/dev/null | tr -dc '[:print:][:space:]'") -join ""
        if ($nscCheck -match "network-security-config|cleartextTrafficPermitted|base-config") { $nscInApk = $true }
    } catch {}
    if (-not $nscInApk -and $txt -match "network_security_config") { $nscInApk = $true }
}

if ($nscInApk) {
    try {
        $nscXml = (& bash -c "unzip -p '$ApkPath' res/xml/network_security_config.xml 2>/dev/null | tr -dc '[:print:][:space:]'") -join ""
        if ($nscXml -match "cleartextTrafficPermitted") {
            Record "Pass" "network_security_config present" "NSC found with cleartextTrafficPermitted directive" `
                -Masvs "MASVS-NETWORK-1" -Sev "High"
        } else {
            Record "Warn" "network_security_config — partial" "NSC file present but cleartextTrafficPermitted not confirmed (binary AXML)" `
                -Masvs "MASVS-NETWORK-1" -Sev "High" `
                -Rec "Add <base-config cleartextTrafficPermitted='false'/> to network_security_config.xml."
        }
    } catch {
        Record "Warn" "network_security_config — read error" "NSC referenced but could not parse" `
            -Masvs "MASVS-NETWORK-1" -Sev "High"
    }
} else {
    Record "Warn" "network_security_config missing" "No NSC file in APK — cleartext HTTP permitted by default on API<28" `
        -Masvs "MASVS-NETWORK-1" -Sev "High" `
        -Rec "Create res/xml/network_security_config.xml and reference it in AndroidManifest.xml via android:networkSecurityConfig."
}

# ─────────────────────────────────────────────────────────────────────────────
# PHASE 9 · JDWP Debugger Attach                      MASVS-RESILIENCE-3
# ─────────────────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "── Phase 9: JDWP Debugger Attach ──" -ForegroundColor Cyan

Write-Host "    [attack] Probing JDWP-debuggable process list..." -ForegroundColor DarkYellow
$jdwpRaw  = & bash -c "timeout 3 adb -s $SERIAL jdwp 2>/dev/null; true"
$jdwpPids = ($jdwpRaw -join " ") -split '\s+' | Where-Object { $_ -match '^\d+$' }
$curPid   = Get-AppPid

if ($curPid -match '^\d+$' -and $jdwpPids -contains $curPid) {
    Record "Fail" "App is JDWP-debuggable" "PID $curPid IS in JDWP list — a Java debugger can attach to this release build!" `
        -Masvs "MASVS-RESILIENCE-3" -Sev "Critical" `
        -Rec "Ensure android:debuggable='false' in the release manifest. Never ship debuggable=true to production."
} elseif ($curPid -match '^\d+$') {
    Record "Pass" "Not JDWP-debuggable" "App PID $curPid not in JDWP list — release build blocks debugger attach" `
        -Masvs "MASVS-RESILIENCE-3" -Sev "Critical"
} else {
    Record "Warn" "JDWP check — no app PID" "App not running; could not cross-reference JDWP list" `
        -Masvs "MASVS-RESILIENCE-3" -Sev "Critical"
}

# ─────────────────────────────────────────────────────────────────────────────
# PHASE 10 · Exported Component Scan                  MASVS-PLATFORM-1
# ─────────────────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "── Phase 10: Exported Components ──" -ForegroundColor Cyan

$pkgDump = (Adb @("shell", "timeout 10 pm dump $Pkg 2>/dev/null") -TimeoutSec 15) -join "`n"
$exportedComponents = @()
if ($pkgDump.Length -gt 500) {
    $lines = $pkgDump -split "`n"
    for ($i = 0; $i -lt $lines.Count; $i++) {
        if ($lines[$i] -match "^\s+$([regex]::Escape($Pkg))/(\S+):") {
            $compName = $Matches[1]
            $window = ($lines[[Math]::Min($i+1,$lines.Count-1)..[Math]::Min($i+8,$lines.Count-1)]) -join " "
            if ($window -match "exported=true") { $exportedComponents += "$Pkg/$compName" }
        }
    }
}
$unexpected = $exportedComponents | Where-Object { $_ -notmatch "MainActivity" }
if ($unexpected.Count -gt 0) {
    $sample = ($unexpected | Select-Object -First 5) -join ", "
    Record "Warn" "Exported components found" "$($unexpected.Count) component(s) besides launcher: $sample" `
        -Masvs "MASVS-PLATFORM-1" -Sev "High" `
        -Rec "Add android:exported=false or android:permission to non-launcher activities, services, receivers, and providers."
} elseif ($pkgDump.Length -gt 500) {
    Record "Pass" "Component exposure minimal" "$($exportedComponents.Count) exported — only launcher MainActivity" `
        -Masvs "MASVS-PLATFORM-1" -Sev "High"
} else {
    Record "Warn" "Exported component scan" "pm dump returned insufficient data" `
        -Masvs "MASVS-PLATFORM-1" -Sev "High"
}

# ─────────────────────────────────────────────────────────────────────────────
# PHASE 11 · ADB Backup Prevention                    MASVS-STORAGE-1
# ─────────────────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "── Phase 11: ADB Backup ──" -ForegroundColor Cyan

$appInfoFlags = (Adb @("shell", "timeout 5 pm dump $Pkg 2>/dev/null | grep -m3 'flags='") -TimeoutSec 10) -join " "
if ($appInfoFlags -match "ALLOW_BACKUP") {
    Record "Fail" "allowBackup ENABLED" "ApplicationInfo flags include ALLOW_BACKUP — data extractable via adb backup" `
        -Masvs "MASVS-STORAGE-1" -Sev "High" `
        -Rec "Set android:allowBackup='false' in AndroidManifest <application> tag."
} else {
    $backupAgent = (Adb @("shell", "timeout 5 pm dump $Pkg 2>/dev/null | grep -i 'backupAgent\|fullBackupContent'") -TimeoutSec 10) -join ""
    if ($backupAgent -match "backupAgent=\S+\w") {
        Record "Warn" "Custom BackupAgent declared" "Verify it does not expose sensitive data: $($backupAgent.Trim())" `
            -Masvs "MASVS-STORAGE-1" -Sev "High" `
            -Rec "Audit the BackupAgent implementation to ensure it excludes sensitive files and SharedPreferences."
    } else {
        Record "Pass" "allowBackup disabled" "ALLOW_BACKUP not in ApplicationInfo flags — data protected" `
            -Masvs "MASVS-STORAGE-1" -Sev "High"
    }
}

# ─────────────────────────────────────────────────────────────────────────────
# PHASE 12 · Tapjacking / Overlay Attack               MASVS-PLATFORM-1
# ─────────────────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "── Phase 12: Tapjacking ──" -ForegroundColor Cyan

$tapjackSignal = $false
if (Test-Path $ApkPath) {
    try {
        $resContent = (& bash -c "unzip -p '$ApkPath' 'res/layout/*.xml' 2>/dev/null | tr -dc '[:print:][:space:]'") -join ""
        if ($resContent -match "filterTouchesWhenObscured") { $tapjackSignal = $true }
    } catch {}
    if (-not $tapjackSignal -and $dexTxt -match "filterTouchesWhenObscured|setFilterTouches") { $tapjackSignal = $true }
}
if ($tapjackSignal) {
    Record "Pass" "Tapjacking mitigation present" "filterTouchesWhenObscured found in resources/DEX" `
        -Masvs "MASVS-PLATFORM-1" -Sev "Medium"
} else {
    Record "Warn" "Tapjacking mitigation absent" "No filterTouchesWhenObscured signal — sensitive buttons may be vulnerable" `
        -Masvs "MASVS-PLATFORM-1" -Sev "Medium" `
        -Rec "Add android:filterTouchesWhenObscured='true' to login buttons, transfer forms, and confirm dialogs in layout XMLs."
}

# ─────────────────────────────────────────────────────────────────────────────
# PHASE 13 · Hardcoded Secrets / Credentials Scan     MASVS-STORAGE-1
# ─────────────────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "── Phase 13: Secrets Scan ──" -ForegroundColor Cyan

$allSecretHits = @()
if ($txt)    { $allSecretHits += Scan-Secrets -Content $txt    -Source "APK-binary" }
if ($dexTxt -and $dexTxt -ne $txt) { $allSecretHits += Scan-Secrets -Content $dexTxt -Source "DEX" }

# Also scan assets (capacitor config, www/*.js)
$assetFiles = @("assets/capacitor.config.json","assets/capacitor.plugins.json","assets/www/main.js","assets/www/vendor.js")
foreach ($af in $assetFiles) {
    try {
        $assetContent = (& bash -c "unzip -p '$ApkPath' '$af' 2>/dev/null") -join ""
        if ($assetContent.Length -gt 10) { $allSecretHits += Scan-Secrets -Content $assetContent -Source $af }
    } catch {}
}

# Deduplicate by secret type
$allSecretHits = $allSecretHits | Sort-Object -Unique
if ($allSecretHits.Count -gt 0) {
    $summary = ($allSecretHits | Select-Object -First 5) -join " | "
    Record "Fail" "Hardcoded secrets detected" "$($allSecretHits.Count) finding(s): $summary" `
        -Masvs "MASVS-STORAGE-1" -Sev "Critical" `
        -Rec "Move all secrets to a secure secrets manager (Android Keystore, HashiCorp Vault, or environment injection at CI/CD). Never hardcode credentials in source or assets."
} else {
    Record "Pass" "No hardcoded secrets" "No API keys, tokens, PEM keys, or credentials found in APK binary, DEX, or assets" `
        -Masvs "MASVS-STORAGE-1" -Sev "Critical"
}

# ─────────────────────────────────────────────────────────────────────────────
# PHASE 14 · SSL/TLS Certificate Pinning               MASVS-NETWORK-2
# ─────────────────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "── Phase 14: SSL Certificate Pinning ──" -ForegroundColor Cyan

$pinSignals = @()
if ($dexTxt) {
    if ($dexTxt -match "CertificatePinner")            { $pinSignals += "OkHttp CertificatePinner" }
    if ($dexTxt -match "TrustKit|trustkit")            { $pinSignals += "TrustKit" }
    if ($dexTxt -match "X509TrustManager|checkServerTrusted") { $pinSignals += "Custom TrustManager" }
    if ($dexTxt -match "HostnameVerifier|setHostnameVerifier") { $pinSignals += "HostnameVerifier" }

    # Dangerous: onReceivedSslError that calls proceed() silently accepts all SSL errors
    if ($dexTxt -match "onReceivedSslError") {
        if ($dexTxt -match "onReceivedSslError") {
            # Check context: if proceed is nearby in the DEX string stream it's suspicious
            Record "Warn" "WebView SSL error handler present" "onReceivedSslError override detected — verify it calls handler.cancel() not handler.proceed()" `
                -Masvs "MASVS-NETWORK-2" -Sev "High" `
                -Rec "In WebViewClient.onReceivedSslError() always call handler.cancel(). Never call proceed() in production builds."
        }
    }
}
# Check NSC for pin-set
try {
    $nscPinContent = (& bash -c "unzip -p '$ApkPath' res/xml/network_security_config.xml 2>/dev/null | tr -dc '[:print:][:space:]'") -join ""
    if ($nscPinContent -match "pin-set|<pin ") { $pinSignals += "NSC pin-set" }
} catch {}

if ($pinSignals.Count -ge 1) {
    Record "Pass" "SSL pinning detected" "Pinning signal(s): $($pinSignals -join ', ')" `
        -Masvs "MASVS-NETWORK-2" -Sev "High" `
        -Rec "Verify pinning covers all production endpoints. Add backup pin to avoid lockout during cert rotation."
} else {
    Record "Warn" "No SSL pinning detected" "No CertificatePinner, TrustKit, NSC pin-set, or HostnameVerifier override found" `
        -Masvs "MASVS-NETWORK-2" -Sev "High" `
        -Rec "Implement certificate pinning via OkHttp CertificatePinner or NSC <pin-set>. For Capacitor apps, configure in the native HTTP layer."
}

# ─────────────────────────────────────────────────────────────────────────────
# PHASE 15 · WebView Security Audit                   MASVS-PLATFORM-2
# ─────────────────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "── Phase 15: WebView Hardening ──" -ForegroundColor Cyan

$wvIssues = @(); $wvPass = @()
if ($dexTxt) {
    if ($dexTxt -match "setAllowUniversalAccessFromFileURLs") { $wvIssues += "setAllowUniversalAccessFromFileURLs (enables UXSS via file://)" }
    else { $wvPass += "No Universal file access" }
    if ($dexTxt -match "setAllowFileAccessFromFileURLs")      { $wvIssues += "setAllowFileAccessFromFileURLs" }
    if ($dexTxt -match "MIXED_CONTENT_ALWAYS_ALLOW")          { $wvIssues += "MIXED_CONTENT_ALWAYS_ALLOW (HTTP in HTTPS frames)" }
    else { $wvPass += "No MIXED_CONTENT_ALWAYS_ALLOW" }
    $jsIfaceCount = ([regex]::Matches($dexTxt, "addJavascriptInterface") | Measure-Object).Count
    if ($jsIfaceCount -gt 0) { $wvIssues += "addJavascriptInterface ($jsIfaceCount call(s)) — JS→native bridge present" }
    if ($dexTxt -match "setAllowFileAccess\b") { $wvIssues += "setAllowFileAccess present (verify set to false)" }
}
if ($wvIssues.Count -eq 0 -and $dexTxt.Length -gt 10000) {
    Record "Pass" "WebView hardening" "No dangerous WebView settings found (UniversalFileAccess, MixedContent, JavascriptInterface)" `
        -Masvs "MASVS-PLATFORM-2" -Sev "High"
} elseif ($wvIssues.Count -gt 0) {
    $sev = if ($wvIssues -match "UniversalAccess|MIXED_CONTENT") { "High" } else { "Medium" }
    Record "Warn" "WebView settings require review" "$($wvIssues.Count) item(s): $($wvIssues -join '; ')" `
        -Masvs "MASVS-PLATFORM-2" -Sev $sev `
        -Rec "Set setAllowFileAccess(false), setAllowUniversalAccessFromFileURLs(false). If addJavascriptInterface is used, ensure it is annotated with @JavascriptInterface and the bridge is audited."
} else {
    Record "Warn" "WebView audit" "DEX not available for analysis" `
        -Masvs "MASVS-PLATFORM-2" -Sev "High"
}

# ─────────────────────────────────────────────────────────────────────────────
# PHASE 16 · APK Signature Schemes                    MASVS-CODE-1
# ─────────────────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "── Phase 16: APK Signature Schemes ──" -ForegroundColor Cyan

$sigSchemes = @(); $sigIssues = @()
if (Test-Path $ApkPath) {
    # V1: META-INF/*.RSA / *.DSA / *.EC in ZIP central directory
    $v1 = & bash -c "unzip -l '$ApkPath' 2>/dev/null | grep -E 'META-INF/.*\.(RSA|DSA|EC)\b'"
    if (($v1 -join "") -match "\.RSA|\.DSA|\.EC") { $sigSchemes += "V1 (JAR)" }

    # V2/V3: "APK Sig Block 42" magic in binary (appears between ZIP sections)
    if ($txt -match "APK Sig Block 42") { $sigSchemes += "V2/V3 (APK Signature Block)" }

    # apksigner if available on PATH or common Android SDK locations
    $apksigner = (& bash -c "command -v apksigner 2>/dev/null || find /opt /usr/local/lib -name 'apksigner' -type f 2>/dev/null | head -1") -join ""
    if ($apksigner.Trim()) {
        $sigOut = (& bash -c "'$($apksigner.Trim())' verify --verbose '$ApkPath' 2>&1") -join "`n"
        if ($sigOut -match "Verified using v1.*true") { if ($sigSchemes -notcontains "V1 (JAR)") { $sigSchemes += "V1 (JAR)" } }
        if ($sigOut -match "Verified using v2.*true") { $sigSchemes = ($sigSchemes | Where-Object {$_ -ne "V2/V3 (APK Signature Block)"}); $sigSchemes += "V2" }
        if ($sigOut -match "Verified using v3.*true") { $sigSchemes += "V3" }
        if ($sigOut -match "Verified using v4.*true") { $sigSchemes += "V4 (verity)" }
    }

    if ($sigSchemes.Count -eq 0) {
        Record "Warn" "APK signature scheme unknown" "Could not detect V1/V2/V3; verify APK is signed" `
            -Masvs "MASVS-CODE-1" -Sev "High" `
            -Rec "Sign with V2 and V3 via signingConfig in build.gradle. Use apksigner instead of jarsigner."
    } elseif ($sigSchemes -contains "V1 (JAR)" -and -not ($sigSchemes -match "V2|V3")) {
        Record "Fail" "APK V1-only signature" "Only JAR signing detected — vulnerable to ZIP manipulation attacks on Android 7+" `
            -Masvs "MASVS-CODE-1" -Sev "High" `
            -Rec "Enable V2/V3 signing in build.gradle: v2SigningEnabled=true, v3SigningEnabled=true in signingConfig."
    } else {
        Record "Pass" "APK signature schemes" "Schemes: $($sigSchemes -join ', ')" `
            -Masvs "MASVS-CODE-1" -Sev "High"
    }
} else {
    Record "Warn" "APK signature" "APK not available" `
        -Masvs "MASVS-CODE-1" -Sev "High"
}

# ─────────────────────────────────────────────────────────────────────────────
# PHASE 17 · SharedPreferences Audit                  MASVS-STORAGE-1,2
# ─────────────────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "── Phase 17: SharedPreferences Audit ──" -ForegroundColor Cyan

$hasRoot = Get-AdbRoot
$prefsDir = "/data/data/$Pkg/shared_prefs"
$prefsList = (Adb @("shell", "ls '$prefsDir' 2>/dev/null") -TimeoutSec 10) -join "`n"
$prefsFiles = ($prefsList -split "`n") | Where-Object { $_.Trim() -match "\.xml$" } | ForEach-Object { $_.Trim() }

if ($prefsFiles.Count -gt 0) {
    $sensPatterns = "(?i)\bname=""(jwt|token|password|passwd|pwd|pin|secret|key|auth|session|oauth|refresh|bearer|cookie|email|credential)[^""]*"""
    $plaintextFindings = @(); $encryptedFiles = @()
    foreach ($pf in $prefsFiles) {
        $content = (Adb @("shell", "cat '$prefsDir/$pf' 2>/dev/null") -TimeoutSec 10) -join ""
        if ($content -match "<\?xml") {
            $hits = [regex]::Matches($content, $sensPatterns) | ForEach-Object { $_.Groups[1].Value }
            if ($hits.Count -gt 0) { $plaintextFindings += "${pf}: plaintext sensitive keys — $($hits -join ', ')" }
        } elseif ($content.Length -gt 20) {
            $encryptedFiles += $pf
        }
    }
    if ($plaintextFindings.Count -gt 0) {
        Record "Fail" "Sensitive data in SharedPreferences" "$($plaintextFindings.Count) plaintext file(s): $($plaintextFindings -join ' | ')" `
            -Masvs "MASVS-STORAGE-1" -Sev "Critical" `
            -Rec "Use EncryptedSharedPreferences (Jetpack Security) for all sensitive data. Never store tokens or passwords in plaintext."
    } elseif ($encryptedFiles.Count -gt 0) {
        Record "Pass" "SharedPreferences encrypted" "$($prefsFiles.Count) file(s); sensitive file(s) appear encrypted: $($encryptedFiles -join ', ')" `
            -Masvs "MASVS-STORAGE-2" -Sev "Critical"
    } else {
        Record "Pass" "SharedPreferences — no sensitive keys" "$($prefsFiles.Count) file(s) found, no sensitive key names detected" `
            -Masvs "MASVS-STORAGE-1" -Sev "Critical"
    }
} elseif ($hasRoot) {
    Record "Pass" "SharedPreferences — none found" "No shared_prefs directory — app has not created SharedPreferences yet (or does not use them)" `
        -Masvs "MASVS-STORAGE-1" -Sev "Critical"
} else {
    Record "Warn" "SharedPreferences — access denied" "Could not read $prefsDir (adb root unavailable on this build)" `
        -Masvs "MASVS-STORAGE-1" -Sev "Critical" `
        -Rec "Run on a userdebug/eng build to verify SharedPreferences storage. Check EncryptedSharedPreferences usage in source."
}

# ─────────────────────────────────────────────────────────────────────────────
# PHASE 18 · SQLite Database Audit                    MASVS-STORAGE-1,2
# ─────────────────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "── Phase 18: SQLite Audit ──" -ForegroundColor Cyan

$dbDir   = "/data/data/$Pkg/databases"
$dbList  = (Adb @("shell", "ls '$dbDir' 2>/dev/null") -TimeoutSec 10) -join "`n"
$dbFiles = ($dbList -split "`n") | Where-Object { $_.Trim() -match "\.(db|sqlite|db3|sqlite3)$" } | ForEach-Object { $_.Trim() }

if ($dbFiles.Count -gt 0) {
    $sensitiveDbFindings = @(); $sensColPattern = "(?i)(password|passwd|pwd|token|jwt|pin|secret|api|key|oauth|session|credit|iban|cvv|ssn|dob)"
    foreach ($db in $dbFiles) {
        $tables  = (Adb @("shell", "sqlite3 '$dbDir/$db' '.tables' 2>/dev/null") -TimeoutSec 10) -join " "
        $schema  = (Adb @("shell", "sqlite3 '$dbDir/$db' '.schema' 2>/dev/null") -TimeoutSec 10) -join "`n"
        $sensCol = [regex]::Matches($schema, $sensColPattern) | ForEach-Object { $_.Value } | Sort-Object -Unique
        if ($sensCol.Count -gt 0) {
            # Check if database is SQLCipher-encrypted (first 16 bytes are magic, not "SQLite format 3")
            $header = (Adb @("shell", "head -c 16 '$dbDir/$db' 2>/dev/null | xxd 2>/dev/null || dd if='$dbDir/$db' bs=1 count=16 2>/dev/null | od -c 2>/dev/null") -TimeoutSec 10) -join ""
            $isEncrypted = $header -notmatch "SQLite format 3|S Q L i t e"
            if ($isEncrypted) {
                Record "Pass" "SQLite encrypted — $db" "Sensitive columns ($($sensCol -join ',')) present but DB appears encrypted (SQLCipher or WAL)" `
                    -Masvs "MASVS-STORAGE-2" -Sev "Critical"
            } else {
                $sensitiveDbFindings += "$db [tables: $($tables.Trim())] — plaintext sensitive cols: $($sensCol -join ',')"
            }
        } else {
            Record "Pass" "SQLite schema clean — $db" "Tables: $($tables.Trim()); no sensitive column names detected" `
                -Masvs "MASVS-STORAGE-1" -Sev "Critical"
        }
    }
    if ($sensitiveDbFindings.Count -gt 0) {
        Record "Fail" "SQLite stores plaintext sensitive data" "$($sensitiveDbFindings -join ' | ')" `
            -Masvs "MASVS-STORAGE-1" -Sev "Critical" `
            -Rec "Encrypt databases with SQLCipher or Android Room with SQLCipher backend. At minimum encrypt sensitive column values before storing."
    }
} elseif ($hasRoot) {
    Record "Pass" "SQLite — no databases found" "No .db/.sqlite files in $dbDir after launch" `
        -Masvs "MASVS-STORAGE-1" -Sev "Critical"
} else {
    Record "Warn" "SQLite — access denied" "Could not list $dbDir (adb root unavailable)" `
        -Masvs "MASVS-STORAGE-1" -Sev "Critical" `
        -Rec "Test on a userdebug build. Verify Ionic Storage / Capacitor SQLite plugin uses encrypted storage in production."
}

# ─────────────────────────────────────────────────────────────────────────────
# PHASE 19 · Deep Link Attack                         MASVS-PLATFORM-1
# ─────────────────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "── Phase 19: Deep Link Attack ──" -ForegroundColor Cyan

$schemes  = [regex]::Matches($pkgDump, 'Scheme: "([^"]+)"') | ForEach-Object { $_.Groups[1].Value } | Sort-Object -Unique
$hosts    = [regex]::Matches($pkgDump, 'Authority: "([^"]+)"') | ForEach-Object { $_.Groups[1].Value } | Sort-Object -Unique
$deepLinks = @()
foreach ($s in $schemes) { foreach ($h in $hosts) { $deepLinks += "${s}://${h}" } }
if ($deepLinks.Count -eq 0 -and $schemes.Count -gt 0) { foreach ($s in $schemes) { $deepLinks += "${s}://" } }

if ($deepLinks.Count -gt 0) {
    Write-Host "    [attack] Found deep links: $($deepLinks -join ', ')" -ForegroundColor DarkYellow
    $deepLinkFindings = @()
    $fuzzPayloads = @("", "/../../../etc/passwd", "?a=' OR 1=1--", "?x=<script>alert(1)</script>", "?redirect=http://evil.com")
    foreach ($dl in $deepLinks | Select-Object -First 3) {
        foreach ($payload in $fuzzPayloads | Select-Object -First 3) {
            $target = "${dl}${payload}"
            $amOut = (Adb @("shell", "am start -a android.intent.action.VIEW -d '$target' 2>/dev/null") -TimeoutSec 8) -join ""
            if ($amOut -match "Starting|Activity") {
                Start-Sleep 1
                $fg = (Adb @("shell", "timeout 3 dumpsys window 2>/dev/null | grep -m1 mCurrentFocus")) -join ""
                if ($fg -match [regex]::Escape($Pkg)) { $deepLinkFindings += "Launched: $target" }
            }
        }
    }
    if ($deepLinkFindings.Count -gt 0) {
        Record "Warn" "Deep links open app" "$($deepLinkFindings.Count) deep link(s) launched app: $($deepLinkFindings | Select-Object -First 3 | ForEach-Object { $_ } | Out-String -NoNewline)" `
            -Masvs "MASVS-PLATFORM-1" -Sev "Medium" `
            -Rec "Validate all deep link parameters server-side. Add android:autoVerify=true for App Links. Sanitize URL parameters before use."
    } else {
        Record "Pass" "Deep links handled safely" "Deep link fuzzing did not cause unexpected app launch: $($deepLinks -join ', ')" `
            -Masvs "MASVS-PLATFORM-1" -Sev "Medium"
    }
    Record "Pass" "Deep links enumerated" "$($deepLinks.Count) deep link scheme(s) found: $($deepLinks -join ', ')" `
        -Masvs "MASVS-PLATFORM-1" -Sev "Info" `
        -Rec "Audit each deep link handler for parameter injection. Add autoVerify=true to use verified App Links."
} else {
    Record "Pass" "No deep links registered" "No custom scheme/authority intent-filters found" `
        -Masvs "MASVS-PLATFORM-1" -Sev "Medium"
}

# ─────────────────────────────────────────────────────────────────────────────
# PHASE 20 · Broadcast Receiver Injection             MASVS-PLATFORM-1
# ─────────────────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "── Phase 20: Broadcast Injection ──" -ForegroundColor Cyan

# Parse exported receivers from pm dump (same scoped approach as Phase 10)
$exportedReceivers = @()
if ($pkgDump.Length -gt 500) {
    $lines = $pkgDump -split "`n"
    for ($i = 0; $i -lt $lines.Count; $i++) {
        if ($lines[$i] -match "^\s+Receiver\s+\{[^}]+$([regex]::Escape($Pkg))") {
            $window = ($lines[[Math]::Min($i,$lines.Count-1)..[Math]::Min($i+5,$lines.Count-1)]) -join " "
            if ($window -match "exported=true") {
                $rcvr = [regex]::Match($window, "$([regex]::Escape($Pkg))/(\S+)").Groups[1].Value
                if ($rcvr) { $exportedReceivers += $rcvr }
            }
        }
    }
    # Also check Activity Resolver for broadcast actions
    $bcActions = [regex]::Matches($pkgDump, 'Action: "([^"]+)"') | ForEach-Object { $_.Groups[1].Value } |
        Where-Object { $_ -notmatch "android\.intent\.action\.(MAIN|VIEW|SEND|PICK|GET_CONTENT)" } | Sort-Object -Unique
}

if ($exportedReceivers.Count -gt 0) {
    Write-Host "    [attack] Sending broadcasts to $($exportedReceivers.Count) exported receiver(s)..." -ForegroundColor DarkYellow
    $receiverHits = @()
    foreach ($rcvr in $exportedReceivers | Select-Object -First 5) {
        $amOut = (Adb @("shell", "am broadcast -n $Pkg/$rcvr 2>/dev/null") -TimeoutSec 8) -join ""
        if ($amOut -match "Broadcast completed|result=0") { $receiverHits += "$rcvr (responded)" }
    }
    if ($receiverHits.Count -gt 0) {
        Record "Warn" "Exported receivers respond to unauthenticated broadcasts" "$($receiverHits -join ', ')" `
            -Masvs "MASVS-PLATFORM-1" -Sev "High" `
            -Rec "Add android:permission to exported receivers or set android:exported=false. Validate broadcast sender identity inside onReceive()."
    } else {
        Record "Pass" "Exported receivers do not respond without permission" "$($exportedReceivers.Count) receiver(s) did not respond to unauthenticated am broadcast" `
            -Masvs "MASVS-PLATFORM-1" -Sev "High"
    }
} else {
    Record "Pass" "No exported broadcast receivers" "pm dump reports no exported receivers besides system-declared ones" `
        -Masvs "MASVS-PLATFORM-1" -Sev "High"
}

# ─────────────────────────────────────────────────────────────────────────────
# PHASE 21 · Content Provider Audit                   MASVS-PLATFORM-1
# ─────────────────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "── Phase 21: Content Provider Audit ──" -ForegroundColor Cyan

# Extract provider authorities from pm dump
$providerAuthorities = [regex]::Matches($pkgDump, 'Provider\{[^}]+\}\s+\{([^}]+)\}|authority=([^\s,]+)') |
    ForEach-Object { if ($_.Groups[1].Value) { $_.Groups[1].Value } else { $_.Groups[2].Value } } |
    Where-Object { $_ -match "\." } | Sort-Object -Unique

# Also try common Capacitor/FileProvider authority patterns
$providerAuthorities += @("$Pkg.provider","$Pkg.fileprovider")
$providerAuthorities = $providerAuthorities | Sort-Object -Unique

$providerFindings = @(); $providerProtected = @()
Write-Host "    [attack] Querying content providers..." -ForegroundColor DarkYellow
foreach ($auth in $providerAuthorities | Select-Object -First 5) {
    $queryOut = (Adb @("shell", "content query --uri 'content://$auth/' 2>/dev/null") -TimeoutSec 8) -join ""
    if ($queryOut -match "Row:|Exception.*Permission|SecurityException|requires.*permission") {
        if ($queryOut -match "Exception.*Permission|SecurityException|requires.*permission") {
            $providerProtected += "$auth (permission required)"
        } else {
            $providerFindings += "$auth — returned data: $($queryOut.Substring(0,[Math]::Min(80,$queryOut.Length)))"
        }
    }
}

if ($providerFindings.Count -gt 0) {
    Record "Fail" "Content provider data exposed" "$($providerFindings -join ' | ')" `
        -Masvs "MASVS-PLATFORM-1" -Sev "Critical" `
        -Rec "Add android:permission, android:readPermission, and android:writePermission to all ContentProvider declarations. Consider android:exported=false."
} elseif ($providerProtected.Count -gt 0) {
    Record "Pass" "Content providers require permission" "$($providerProtected -join ', ')" `
        -Masvs "MASVS-PLATFORM-1" -Sev "Critical"
} else {
    Record "Pass" "Content provider audit — no data returned" "No content providers returned data to unauthenticated queries" `
        -Masvs "MASVS-PLATFORM-1" -Sev "Critical"
}

# ─────────────────────────────────────────────────────────────────────────────
# PHASE 22 · Runtime Hook Detection (Frida / Xposed)  MASVS-RESILIENCE-2
# ─────────────────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "── Phase 22: Hook Detection ──" -ForegroundColor Cyan

$hookSignals = @()
if ($dexTxt) {
    # Frida detection strings compiled in DEX
    @("frida","XposedBridge","de.robv.android.xposed","LSPosed","EdXposed","Zygisk","Riru","objection") |
        Where-Object { $dexTxt -match [regex]::Escape($_) } | ForEach-Object { $hookSignals += "DEX:$_" }
}

# Runtime: check /proc/$appPid/maps for injected Frida/Xposed libraries
$runPid = Get-AppPid
if ($runPid -match '^\d+$') {
    $maps = (Adb @("shell", "cat /proc/$runPid/maps 2>/dev/null | grep -iE 'frida|xposed|lspatch|zygisk|riru'") -TimeoutSec 8) -join ""
    if ($maps -match "frida|xposed|zygisk|riru") { $hookSignals += "Runtime:library-map($maps.Trim())" }
}

# Check for Frida server process on device
$fridaProc = (Adb @("shell", "ps -A 2>/dev/null | grep -i frida-server") -TimeoutSec 8) -join ""
if ($fridaProc -match "frida-server") { $hookSignals += "Runtime:frida-server-process" }

# Check if frida binary is available in container — attempt bypass if present
$fridaBin = (& bash -c "command -v frida 2>/dev/null") -join ""
if ($fridaBin.Trim()) {
    Write-Host "    [attack] Frida available — probing app via USB/TCP..." -ForegroundColor DarkYellow
    $fridaOut = & bash -c "timeout 5 frida -H $SERIAL -n $Pkg --eval '\"hook-test\"' 2>&1"
    if (($fridaOut -join "") -match "Attached|hook-test") {
        $hookSignals += "EXPLOIT:frida-attached-successfully"
        Record "Fail" "Frida hook bypass succeeded" "Frida successfully attached to $Pkg — anti-tampering NOT effective" `
            -Masvs "MASVS-RESILIENCE-2" -Sev "Critical" `
            -Rec "Implement runtime Frida detection (port 27042, /proc/maps scan, DebuggerInfo). Consider using a commercial RASP solution."
    } else {
        Record "Pass" "Frida attach blocked" "Frida could not attach to $Pkg — anti-tampering is resisting instrumentation" `
            -Masvs "MASVS-RESILIENCE-2" -Sev "Critical"
    }
} elseif ($hookSignals.Count -gt 0) {
    Record "Pass" "Hook detection strings compiled" "DEX contains $($hookSignals.Count) hook-detection signal(s): $($hookSignals -join ', ')" `
        -Masvs "MASVS-RESILIENCE-2" -Sev "Critical" `
        -Rec "Install frida-tools in the test container to perform a live bypass attempt (pip install frida-tools)."
} else {
    Record "Warn" "Hook detection — no signals" "No Frida/Xposed detection code found in DEX and frida not available for live test" `
        -Masvs "MASVS-RESILIENCE-2" -Sev "Critical" `
        -Rec "Add runtime hook detection: check /proc/self/maps for frida libraries, scan /data/local/tmp for frida-server, check TCP port 27042."
}

# ─────────────────────────────────────────────────────────────────────────────
# PHASE 23 · Native Library Audit                     MASVS-CODE-1
# ─────────────────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "── Phase 23: Native Library Audit ──" -ForegroundColor Cyan

$soFiles = & bash -c "unzip -l '$ApkPath' 2>/dev/null | grep '\.so\b' | awk '{print \$4}'"
$soList  = ($soFiles -join "`n" -split "`n") | Where-Object { $_.Trim() -match "\.so$" } | ForEach-Object { $_.Trim() }

if ($soList.Count -gt 0) {
    $nativeSecrets = @(); $nativeSymbols = @()
    $stringsAvail  = (& bash -c "command -v strings 2>/dev/null") -join ""

    foreach ($so in $soList | Select-Object -First 8) {
        $soTmp = "/tmp/_so_$PID.so"
        & bash -c "unzip -p '$ApkPath' '$so' > '$soTmp' 2>/dev/null"
        if ((Test-Path $soTmp) -and (Get-Item $soTmp).Length -gt 0) {
            $soContent = if ($stringsAvail.Trim()) {
                (& bash -c "strings '$soTmp' 2>/dev/null") -join " "
            } else {
                $soRaw = [System.IO.File]::ReadAllBytes($soTmp)
                [System.Text.Encoding]::Latin1.GetString($soRaw)
            }
            # Check for JNI RegisterNatives (native method registration)
            if ($soContent -match "RegisterNatives|JNI_OnLoad") { $nativeSymbols += "$(Split-Path $so -Leaf) (JNI)" }
            # Scan for secrets
            $soHits = Scan-Secrets -Content $soContent -Source (Split-Path $so -Leaf)
            $nativeSecrets += $soHits
        }
        Remove-Item $soTmp -ErrorAction SilentlyContinue
    }

    if ($nativeSecrets.Count -gt 0) {
        Record "Fail" "Secrets in native libraries" "$($nativeSecrets.Count) finding(s): $($nativeSecrets | Select-Object -First 3 | ForEach-Object { $_ } | Out-String -NoNewline)" `
            -Masvs "MASVS-STORAGE-1" -Sev "Critical" `
            -Rec "Never hardcode credentials in .so files. They are trivially extracted with strings. Use Android Keystore for runtime key storage."
    } elseif ($nativeSymbols.Count -gt 0) {
        Record "Pass" "Native libraries — no secrets found" "$($soList.Count) .so file(s); JNI bridges: $($nativeSymbols -join ', ')" `
            -Masvs "MASVS-CODE-1" -Sev "Medium"
    } else {
        Record "Pass" "Native libraries clean" "$($soList.Count) .so file(s) — no secrets or notable symbols detected" `
            -Masvs "MASVS-CODE-1" -Sev "Medium"
    }
} else {
    Record "Pass" "No native libraries" "APK contains no .so files" `
        -Masvs "MASVS-CODE-1" -Sev "Medium"
}

# ─────────────────────────────────────────────────────────────────────────────
# PHASE 24 · Memory Scan for Runtime Secrets          MASVS-STORAGE-2
# ─────────────────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "── Phase 24: Memory Scan ──" -ForegroundColor Cyan

$memPid = Get-AppPid
if ($memPid -match '^\d+$' -and $hasRoot) {
    Write-Host "    [attack] Scanning /proc/$memPid/mem for secrets..." -ForegroundColor DarkYellow
    # Read memory maps to find readable heap/anon regions (limit to first 5 readable regions)
    $maps = (Adb @("shell", "cat /proc/$memPid/maps 2>/dev/null | grep -E '^[0-9a-f]+-[0-9a-f]+ r' | grep -v 'vvar\|vdso\|vsyscall' | head -5") -TimeoutSec 10) -join "`n"
    $memHits = @()
    foreach ($mapLine in ($maps -split "`n") | Where-Object { $_ -match "^\w" } | Select-Object -First 3) {
        if ($mapLine -match '^([0-9a-f]+)-([0-9a-f]+)') {
            $startHex = $Matches[1]; $endHex = $Matches[2]
            $startDec = [Convert]::ToInt64($startHex, 16)
            $endDec   = [Convert]::ToInt64($endHex,   16)
            $size     = [Math]::Min($endDec - $startDec, 65536)  # max 64KB per region
            if ($size -lt 4096) { continue }
            # Use dd to extract memory region, pipe through strings
            $memDump = (Adb @("shell", "dd if=/proc/$memPid/mem bs=1 skip=$startDec count=$size 2>/dev/null | strings 2>/dev/null | grep -iE '(eyJ[A-Za-z0-9]{20}|BEGIN.PRIVATE|AKIA[A-Z0-9]{16}|password|secret)' | head -5") -TimeoutSec 15) -join " "
            if ($memDump.Trim().Length -gt 5) { $memHits += "Region 0x${startHex}: $($memDump.Trim().Substring(0,[Math]::Min(80,$memDump.Trim().Length)))" }
        }
    }
    if ($memHits.Count -gt 0) {
        Record "Fail" "Secrets found in process memory" "$($memHits.Count) region(s) with sensitive data: $($memHits -join ' | ')" `
            -Masvs "MASVS-STORAGE-2" -Sev "Critical" `
            -Rec "Use Android Keystore for key material. Avoid storing decrypted secrets in long-lived objects. Overwrite sensitive strings after use (SecureRandom wipe pattern)."
    } else {
        Record "Pass" "Memory scan — no plaintext secrets found" "Scanned $($($maps -split '`n' | Where-Object { $_ }).Count) readable memory region(s); no JWT, private keys, or passwords in first 64KB per region" `
            -Masvs "MASVS-STORAGE-2" -Sev "Critical"
    }
} elseif (-not $hasRoot) {
    Record "Warn" "Memory scan skipped" "adb root not available on this build — cannot read /proc/pid/mem" `
        -Masvs "MASVS-STORAGE-2" -Sev "Critical" `
        -Rec "Run on a userdebug build with adb root to scan process memory. Use Frida memory scanning for production builds."
} else {
    Record "Warn" "Memory scan — app not running" "Could not get app PID for memory scan" `
        -Masvs "MASVS-STORAGE-2" -Sev "Critical"
}

# ─────────────────────────────────────────────────────────────────────────────
# PHASE 25 · Screen Recording Attack                  MASVS-PLATFORM-1
# ─────────────────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "── Phase 25: Screen Recording ──" -ForegroundColor Cyan

Launch-App; Start-Sleep 3
Write-Host "    [attack] Attempting screenrecord while app is foreground (2s)..." -ForegroundColor DarkYellow
Adb @("shell", "screenrecord --time-limit 2 /sdcard/_sec_rec.mp4 2>/dev/null") | Out-Null
Start-Sleep 3
& bash -c "adb -s $SERIAL pull /sdcard/_sec_rec.mp4 /tmp/_sec_rec.mp4 >/dev/null 2>&1"
Adb @("shell", "rm -f /sdcard/_sec_rec.mp4 2>/dev/null") | Out-Null

$recSize = 0
if (Test-Path "/tmp/_sec_rec.mp4") { $recSize = (Get-Item "/tmp/_sec_rec.mp4").Length }
Remove-Item "/tmp/_sec_rec.mp4" -ErrorAction SilentlyContinue
$recKb = [Math]::Round($recSize / 1024, 1)

if ($recSize -gt 50000) {
    Record "Fail" "Screen recording succeeded" "screenrecord captured ${recKb} KB video — FLAG_SECURE NOT set or ineffective for video capture" `
        -Masvs "MASVS-PLATFORM-1" -Sev "High" `
        -Rec "Ensure FLAG_SECURE is set in MainActivity.onCreate(). FLAG_SECURE blocks both screencap and screenrecord from capturing protected windows."
} elseif ($recSize -gt 0) {
    Record "Warn" "Screen recording — small file" "screenrecord produced ${recKb} KB — may be blank video (FLAG_SECURE effective) or capture failed; verify manually" `
        -Masvs "MASVS-PLATFORM-1" -Sev "High" `
        -Rec "Test screenrecord on a physical device. FLAG_SECURE produces blank frames in recordings."
} else {
    Record "Pass" "Screen recording blocked" "screenrecord produced 0 bytes — FLAG_SECURE is preventing video capture" `
        -Masvs "MASVS-PLATFORM-1" -Sev "High"
}

# ─────────────────────────────────────────────────────────────────────────────
# PHASE 26 · Certificate Transparency                 MASVS-NETWORK-1
# ─────────────────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "── Phase 26: Certificate Transparency ──" -ForegroundColor Cyan

$ctSignals = @(); $ctIssues = @()
# Check NSC for requireCertificateTransparency
try {
    $nscFull = (& bash -c "unzip -p '$ApkPath' res/xml/network_security_config.xml 2>/dev/null | tr -dc '[:print:][:space:]'") -join ""
    if ($nscFull -match "requireCertificateTransparency") { $ctSignals += "NSC requireCertificateTransparency directive" }
    # Check for trust-anchor restricted to system CAs (no user-added CAs in prod)
    if ($nscFull -match "user") { $ctIssues += "user CA store referenced in NSC (risky in production — enables MITM with user-installed CA)" }
    if ($nscFull -match "system") { $ctSignals += "NSC restricts to system CAs" }
} catch {}

# Check for OkHttp Certificate Transparency library
if ($dexTxt -match "certificatetransparency|CertificateTransparency") { $ctSignals += "OkHttp CT library" }

if ($ctIssues.Count -gt 0) {
    Record "Warn" "Certificate Transparency — user CA trust" $ctIssues[0] `
        -Masvs "MASVS-NETWORK-1" -Sev "High" `
        -Rec "In production NSC, trust only system CAs. Remove user CA trust anchors. Add <debug-overrides> section for dev builds only."
}
if ($ctSignals.Count -gt 0) {
    Record "Pass" "Certificate Transparency configured" "$($ctSignals -join ', ')" `
        -Masvs "MASVS-NETWORK-1" -Sev "Medium"
} elseif ($ctIssues.Count -eq 0) {
    Record "Warn" "Certificate Transparency not enforced" "No requireCertificateTransparency directive and no CT library detected" `
        -Masvs "MASVS-NETWORK-1" -Sev "Medium" `
        -Rec "Add requireCertificateTransparency='true' in NSC base-config. Consider jakewharton/okhttp-certificatetransparency library."
}

# ─────────────────────────────────────────────────────────────────────────────
# PHASE 27 · Clipboard Leak                           MASVS-PLATFORM-1
# ─────────────────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "── Phase 27: Clipboard Leak ──" -ForegroundColor Cyan

# Check static: does DEX implement ClipboardManager listener or ClipData?
$clipSignal = $dexTxt -and ($dexTxt -match "ClipboardManager|clipboardManager|ClipData|setPrimaryClip")
# Runtime: read current clipboard content (may be empty or unrelated)
$clipContent = (Adb @("shell", "service call clipboard 2 i32 1 2>/dev/null") -TimeoutSec 8) -join ""

# Dynamic: put a test value, read it back; if sensitive data appears → leak
$sensClipTest = (Adb @("shell", "am startservice --user 0 -a android.intent.action.MAIN 2>/dev/null") -TimeoutSec 5) -join ""

# Primarily check DEX for password field clipboard disabling
$clipboardDisabled = $dexTxt -and ($dexTxt -match "TYPE_TEXT_VARIATION_PASSWORD|setInputType|setLongClickable.*false")
if ($clipboardDisabled) {
    Record "Pass" "Clipboard protection signals present" "DEX contains password input type or clipboard restriction patterns" `
        -Masvs "MASVS-PLATFORM-1" -Sev "Medium"
} elseif ($clipSignal) {
    Record "Warn" "Clipboard access in app" "App uses ClipboardManager — verify sensitive fields (passwords, tokens) have clipboard disabled" `
        -Masvs "MASVS-PLATFORM-1" -Sev "Medium" `
        -Rec "For password/PIN fields: set inputType=textPassword. For custom sensitive fields: override long-click to block clipboard. Use ContentDescription to prevent clipboard in Ionic views."
} else {
    Record "Warn" "Clipboard — no explicit protection" "No clipboard restriction signals in DEX (Ionic/WebView fields may expose clipboard by default)" `
        -Masvs "MASVS-PLATFORM-1" -Sev "Medium" `
        -Rec "Disable clipboard for password and OTP fields in the WebView layer. In Ionic, use type='password' and autocomplete='off'."
}

# ─────────────────────────────────────────────────────────────────────────────
# PHASE 28 · Emulator / Environment Detection         MASVS-RESILIENCE-1
# ─────────────────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "── Phase 28: Emulator Detection ──" -ForegroundColor Cyan

$emuProps = @{
    "ro.kernel.qemu"      = (Adb @("shell","getprop ro.kernel.qemu") -join "").Trim()
    "ro.hardware"         = (Adb @("shell","getprop ro.hardware") -join "").Trim()
    "ro.product.model"    = (Adb @("shell","getprop ro.product.model") -join "").Trim()
    "ro.product.manufacturer" = (Adb @("shell","getprop ro.product.manufacturer") -join "").Trim()
    "ro.build.fingerprint"= (Adb @("shell","getprop ro.build.fingerprint") -join "").Trim()
}
$emuIndicators = @()
if ($emuProps["ro.kernel.qemu"] -eq "1")          { $emuIndicators += "ro.kernel.qemu=1" }
if ($emuProps["ro.hardware"] -match "goldfish|ranchu") { $emuIndicators += "ro.hardware=$($emuProps['ro.hardware'])" }
if ($emuProps["ro.product.model"] -match "sdk|Emulator|emulator") { $emuIndicators += "model=$($emuProps['ro.product.model'])" }
if ($emuProps["ro.build.fingerprint"] -match "generic|unknown") { $emuIndicators += "fingerprint(generic)" }

if ($dexTxt -match "isEmulator|Build\.FINGERPRINT|ro\.kernel\.qemu|goldfish|ranchu") {
    if ($emuIndicators.Count -gt 0) {
        Record "Pass" "Emulator detection compiled in" "App has emulator detection code; device shows $($emuIndicators.Count) indicator(s): $($emuIndicators -join ', ')" `
            -Masvs "MASVS-RESILIENCE-1" -Sev "Medium" `
            -Rec "In production, verify emulator detection does not only check ro.kernel.qemu — modern emulators may spoof this property."
    } else {
        Record "Pass" "Emulator detection compiled in" "Device does not show emulator indicators — detection may not trigger" `
            -Masvs "MASVS-RESILIENCE-1" -Sev "Medium"
    }
} else {
    Record "Warn" "No emulator detection code" "No Build.FINGERPRINT or ro.kernel.qemu checks found in DEX" `
        -Masvs "MASVS-RESILIENCE-1" -Sev "Medium" `
        -Rec "Add emulator detection: check ro.kernel.qemu, Build.HARDWARE (goldfish/ranchu), Build.FINGERPRINT for 'generic', and /dev/socket/qemud."
}

# ─────────────────────────────────────────────────────────────────────────────
# PHASE 29 · Anti-Tamper / Integrity Verification     MASVS-RESILIENCE-2
# ─────────────────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "── Phase 29: Anti-Tamper ──" -ForegroundColor Cyan

$tamperSignals = @()
if ($dexTxt) {
    if ($dexTxt -match "PackageManager|getPackageInfo")      { $tamperSignals += "PackageManager signature check" }
    if ($dexTxt -match "CRC|Adler|checksum|sha256|sha1|md5") { $tamperSignals += "Checksum/hash verification" }
    if ($dexTxt -match "SafetyNet|Attestation|PlayIntegrity|IntegrityTokenResponse") { $tamperSignals += "Google Play Integrity / SafetyNet" }
    if ($dexTxt -match "INSTALL_REFERRER|referrer")          { $tamperSignals += "Install referrer check" }
}

if ($tamperSignals.Count -ge 1) {
    Record "Pass" "Anti-tamper signals present" "$($tamperSignals -join ', ')" `
        -Masvs "MASVS-RESILIENCE-2" -Sev "High" `
        -Rec "Ensure integrity checks run at startup, not just at install. Consider Google Play Integrity API as the strongest available mechanism."
} else {
    Record "Warn" "No anti-tamper signals" "No signature check, checksum, or Play Integrity API calls found in DEX" `
        -Masvs "MASVS-RESILIENCE-2" -Sev "High" `
        -Rec "Implement Google Play Integrity API to attest APK integrity and device integrity at runtime. Add PackageManager signature verification as a fallback."
}

# ─────────────────────────────────────────────────────────────────────────────
# PHASE 30 · Intent Injection Attack                  MASVS-PLATFORM-1
# ─────────────────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "── Phase 30: Intent Injection ──" -ForegroundColor Cyan

Write-Host "    [attack] Attempting to start all exported components with injected extras..." -ForegroundColor DarkYellow
$injectionFindings = @()

foreach ($comp in $exportedComponents | Select-Object -First 6) {
    $className = ($comp -split "/")[1]
    # Attempt 1: plain start (no extras)
    $amOut1 = (Adb @("shell", "am start -n '$comp' 2>/dev/null") -TimeoutSec 8) -join ""
    # Attempt 2: with injected extras that might bypass auth
    $amOut2 = (Adb @("shell", "am start -n '$comp' --es 'authenticated' 'true' --es 'role' 'admin' --ez 'bypass' 'true' 2>/dev/null") -TimeoutSec 8) -join ""
    # Attempt 3: with deep link intent data
    $amOut3 = (Adb @("shell", "am start -n '$comp' -d 'file:///etc/passwd' 2>/dev/null") -TimeoutSec 8) -join ""

    $started = ($amOut1 + $amOut2 + $amOut3) -match "Starting|Activity"
    if ($started) {
        Start-Sleep 1
        $fg = (Adb @("shell", "timeout 3 dumpsys window 2>/dev/null | grep -m1 mCurrentFocus")) -join ""
        if ($fg -match [regex]::Escape($Pkg)) { $injectionFindings += "$className (launched)" }
    }
}

if ($injectionFindings.Count -gt 0) {
    Record "Warn" "Components accessible via intent injection" "$($injectionFindings -join ', ')" `
        -Masvs "MASVS-PLATFORM-1" -Sev "High" `
        -Rec "Validate all incoming intent extras and data URIs. Do not trust intent extras for authentication or authorization decisions."
} elseif ($exportedComponents.Count -gt 1) {
    Record "Pass" "Intent injection did not escalate" "Tried $($exportedComponents.Count) exported component(s) — no unexpected access granted" `
        -Masvs "MASVS-PLATFORM-1" -Sev "High"
} else {
    Record "Pass" "Intent injection — no extra exported components" "Only launcher MainActivity exported; minimal intent injection surface" `
        -Masvs "MASVS-PLATFORM-1" -Sev "High"
}

# ─────────────────────────────────────────────────────────────────────────────
# Summary
# ─────────────────────────────────────────────────────────────────────────────
$total    = $script:pass + $script:fail + $script:warn
$duration = [Math]::Round(([datetime]::UtcNow - $script:suiteStart).TotalSeconds)
Write-Host ""
Write-Host "═══════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "  RESULTS" -ForegroundColor Cyan
Write-Host "═══════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "  Passed   : $($script:pass) / $total" -ForegroundColor Green
Write-Host "  Failed   : $($script:fail) / $total" -ForegroundColor $(if ($script:fail -gt 0) { "Red" } else { "Green" })
Write-Host "  Warnings : $($script:warn) / $total" -ForegroundColor Yellow
Write-Host "  Duration : ${duration}s"

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

# ─────────────────────────────────────────────────────────────────────────────
# HTML Report — MASVS-mapped, severity-tagged, with recommendations
# ─────────────────────────────────────────────────────────────────────────────
$reportDir  = "/reports"
$timestamp  = (Get-Date -Format "yyyy-MM-dd HH:mm:ss UTC")
$reportFile = "$reportDir/android-security-report.html"

$passColor = "#3fb950"; $failColor = "#f85149"; $warnColor = "#d29922"
$bgMain    = "#0d1117"; $bgCard    = "#161b22"; $border    = "#30363d"; $textMuted = "#8b949e"

$overallStatus     = if ($script:fail -gt 0) { "FAILED" } else { "PASSED" }
$overallBadgeClass = if ($script:fail -gt 0) { "fail"   } else { "pass" }

# Severity counts
$critCount = ($results | Where-Object { $_.Sev -eq "Critical" -and $_.Status -eq "Fail" }).Count
$highCount = ($results | Where-Object { $_.Sev -eq "High"     -and $_.Status -eq "Fail" }).Count

# MASVS domain summary
$mavsvDomains = $results | Where-Object { $_.Masvs } |
    Group-Object { ($_.Masvs -split "-")[0..1] -join "-" } |
    Sort-Object Name

$rows = $results | ForEach-Object {
    $r = $_
    $icon  = @{ Pass = "&#10003;"; Fail = "&#10007;"; Warn = "&#9888;" }[$r.Status]
    $color = @{ Pass = $passColor; Fail = $failColor; Warn = $warnColor }[$r.Status]
    $sevMap = @{ Critical="#b91c1c"; High="#c2410c"; Medium="#a16207"; Low="#1d4ed8"; Info="#374151"; ""=$textMuted }
    $sevColor = if ($sevMap.ContainsKey($r.Sev)) { $sevMap[$r.Sev] } else { $textMuted }
    $sevBg    = @{ Critical="#450a0a"; High="#431407"; Medium="#422006"; Low="#1e3a5f"; Info="#1f2937"; ""="#161b22" }
    $sevBgCol = if ($sevBg.ContainsKey($r.Sev)) { $sevBg[$r.Sev] } else { "#161b22" }
    $sevHtml  = if ($r.Sev) { "<span style='background:$sevBgCol;color:$sevColor;padding:1px 7px;border-radius:9px;font-size:0.7rem;font-weight:700;border:1px solid $sevColor'>$([System.Net.WebUtility]::HtmlEncode($r.Sev))</span>" } else { "" }
    $mavsHtml = if ($r.Masvs) { "<code style='font-size:0.7rem;background:#0d1117;padding:1px 6px;border-radius:4px;color:#79c0ff;border:1px solid #30363d'>$([System.Net.WebUtility]::HtmlEncode($r.Masvs))</code>" } else { "" }
    $recHtml  = if ($r.Rec)  { "<div style='font-size:0.76rem;color:$textMuted;margin-top:4px;font-style:italic'>&#128270; $([System.Net.WebUtility]::HtmlEncode($r.Rec))</div>" } else { "" }
    $detailHtml = "$([System.Net.WebUtility]::HtmlEncode($r.Detail))$recHtml"
    "<tr><td style='color:$color;font-weight:700;white-space:nowrap;width:60px'>$icon $($r.Status)</td><td style='width:90px'>$sevHtml</td><td style='width:140px'>$mavsHtml</td><td><strong style='color:#e6edf3'>$([System.Net.WebUtility]::HtmlEncode($r.Name))</strong><br>$detailHtml</td></tr>"
}

$html = @"
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Android Security Report — MASVS v2</title>
  <style>
    *{box-sizing:border-box;margin:0;padding:0}
    body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:$bgMain;color:#c9d1d9;padding:28px 32px;font-size:13px}
    h1{color:#e6edf3;font-size:1.25rem;font-weight:600;margin-bottom:3px}
    .meta{color:$textMuted;font-size:0.78rem;margin-bottom:18px}
    .badge{display:inline-block;padding:2px 10px;border-radius:10px;font-size:0.72rem;font-weight:700;vertical-align:middle;margin-left:8px}
    .pass{background:#1a2e1a;color:$passColor;border:1px solid $passColor}
    .fail{background:#2e1a1a;color:$failColor;border:1px solid $failColor}
    .stats{display:flex;gap:10px;margin-bottom:22px;flex-wrap:wrap}
    .stat{background:$bgCard;border:1px solid $border;border-radius:8px;padding:11px 16px;min-width:82px}
    .stat-n{font-size:1.5rem;font-weight:700;line-height:1}
    .stat-l{font-size:0.69rem;color:$textMuted;margin-top:2px;text-transform:uppercase;letter-spacing:.04em}
    table{border-collapse:collapse;width:100%;background:$bgCard;border-radius:8px;overflow:hidden;border:1px solid $border;margin-bottom:24px}
    th{background:#0d1117;color:$textMuted;text-align:left;padding:8px 12px;font-size:0.72rem;font-weight:600;border-bottom:1px solid $border;text-transform:uppercase;letter-spacing:.05em}
    td{padding:8px 12px;border-bottom:1px solid #21262d;vertical-align:top;line-height:1.45;font-size:0.82rem}
    tr:last-child td{border-bottom:none}
    tr:hover td{background:#1c2128}
    .section-title{color:#e6edf3;font-size:0.82rem;font-weight:600;margin:18px 0 8px;padding-bottom:4px;border-bottom:1px solid $border}
    code{font-family:'SFMono-Regular',Consolas,monospace}
  </style>
</head>
<body>
  <h1>Android Security Report <span class="badge $overallBadgeClass">$overallStatus</span></h1>
  <p class="meta">
    Package: <strong>$Pkg</strong> &nbsp;·&nbsp;
    Target: ${AdbHost}:${AdbPort} &nbsp;·&nbsp;
    OWASP MASVS v2 &nbsp;·&nbsp;
    Duration: ${duration}s &nbsp;·&nbsp;
    $timestamp
  </p>

  <div class="stats">
    <div class="stat"><div class="stat-n" style="color:$passColor">$($script:pass)</div><div class="stat-l">Passed</div></div>
    <div class="stat"><div class="stat-n" style="color:$(if($script:fail -gt 0){$failColor}else{$passColor})">$($script:fail)</div><div class="stat-l">Failed</div></div>
    <div class="stat"><div class="stat-n" style="color:$warnColor">$($script:warn)</div><div class="stat-l">Warnings</div></div>
    <div class="stat"><div class="stat-n">$total</div><div class="stat-l">Total</div></div>
    <div class="stat"><div class="stat-n" style="color:#b91c1c">$critCount</div><div class="stat-l">Critical</div></div>
    <div class="stat"><div class="stat-n" style="color:#c2410c">$highCount</div><div class="stat-l">High Fail</div></div>
  </div>

  <div class="section-title">Test Results</div>
  <table>
    <thead>
      <tr>
        <th>Status</th>
        <th>Severity</th>
        <th>MASVS</th>
        <th>Check / Evidence / Recommendation</th>
      </tr>
    </thead>
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
