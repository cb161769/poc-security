package io.ionic.starter;

import android.accessibilityservice.AccessibilityServiceInfo;
import android.app.AlertDialog;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.os.Build;
import android.os.Bundle;
import android.view.WindowManager;
import android.view.accessibility.AccessibilityManager;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.widget.Toast;

import com.getcapacitor.BridgeActivity;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.security.MessageDigest;
import java.util.List;

public class MainActivity extends BridgeActivity {

    /**
     * SHA-256 fingerprint of the expected release signing certificate.
     * Generate with: keytool -printcert -jarfile app-release.apk
     * Leave empty to skip check in development builds.
     */
    private static final String EXPECTED_CERT_SHA256 = "";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        // Block screenshots and screen recording of sensitive financial data
        getWindow().setFlags(
            WindowManager.LayoutParams.FLAG_SECURE,
            WindowManager.LayoutParams.FLAG_SECURE
        );

        runSecurityChecks();
        hardenWebView();
    }

    // ── Security Checks ──────────────────────────────────────────────────────

    private void runSecurityChecks() {
        if (isRooted()) {
            block("Dispositivo comprometido",
                "Se detectó acceso root en este dispositivo. Por seguridad, la aplicación no puede ejecutarse.");
            return;
        }
        if (isFridaPresent()) {
            block("Instrumentación detectada",
                "Se detectó un agente de análisis dinámico (Frida/Xposed). La sesión ha sido terminada.");
            return;
        }
        if (!isSignatureValid()) {
            block("Aplicación modificada",
                "La integridad de la aplicación no pudo verificarse. Descárgala desde la fuente oficial.");
            return;
        }
        if (hasThirdPartyAccessibilityService()) {
            // Warn but don't block — accessibility services have legitimate uses
            Toast.makeText(this,
                "Advertencia: servicio de accesibilidad de terceros activo. " +
                "Puede acceder al contenido de la pantalla.",
                Toast.LENGTH_LONG).show();
        }
    }

    /** Root detection without third-party libraries. */
    private boolean isRooted() {
        // 1. su binary in common paths
        String[] suPaths = {
            "/sbin/su", "/system/bin/su", "/system/xbin/su",
            "/data/local/xbin/su", "/data/local/bin/su",
            "/system/sd/xbin/su", "/system/bin/.ext/.su",
            "/system/usr/we-need-root/su-backup"
        };
        for (String path : suPaths) {
            if (new File(path).exists()) return true;
        }

        // 2. non-release build tags (test-keys = unofficial/rooted ROM)
        String buildTags = Build.TAGS;
        if (buildTags != null && buildTags.contains("test-keys")) return true;

        // 3. known root management apps
        String[] rootPackages = {
            "com.topjohnwu.magisk",
            "eu.chainfire.supersu",
            "com.noshufou.android.su",
            "com.koushikdutta.superuser",
            "com.thirdparty.superuser",
            "com.zachspong.temprootremovejb",
            "com.ramdroid.appquarantine"
        };
        PackageManager pm = getPackageManager();
        for (String pkg : rootPackages) {
            try {
                pm.getPackageInfo(pkg, 0);
                return true;
            } catch (PackageManager.NameNotFoundException ignored) {}
        }

        // 4. try executing su (catches some Magisk hidden installations)
        try {
            Process p = Runtime.getRuntime().exec(new String[]{"/system/xbin/which", "su"});
            return p.waitFor() == 0;
        } catch (Exception ignored) {}

        return false;
    }

    /**
     * Frida detection via filesystem artifacts and /proc/self/maps.
     * Note: socket-based port scan (27042) should be run off the main thread
     * in production to avoid StrictMode violations.
     */
    private boolean isFridaPresent() {
        // 1. frida server / gadget artifacts on disk
        String[] fridaArtifacts = {
            "/data/local/tmp/frida-server",
            "/data/local/tmp/re.frida.server",
            "/data/local/tmp/libfrida-gadget.so",
            "/data/local/tmp/libfrida-agent.so"
        };
        for (String path : fridaArtifacts) {
            if (new File(path).exists()) return true;
        }

        // 2. frida agent injected in memory maps
        try (BufferedReader reader = new BufferedReader(new FileReader("/proc/self/maps"))) {
            String line;
            while ((line = reader.readLine()) != null) {
                if (line.contains("frida")
                        || line.contains("gum-js-loop")
                        || line.contains("frida-agent")
                        || line.contains("linjector")) {
                    return true;
                }
            }
        } catch (Exception ignored) {}

        return false;
    }

    /**
     * Verify APK signing certificate matches the expected production fingerprint.
     * Configure EXPECTED_CERT_SHA256 with the release keystore SHA-256.
     */
    @SuppressWarnings("deprecation")
    private boolean isSignatureValid() {
        if (EXPECTED_CERT_SHA256.isEmpty()) return true; // skip check in dev

        try {
            PackageManager pm = getPackageManager();
            Signature[] signatures;

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                PackageInfo info = pm.getPackageInfo(getPackageName(),
                    PackageManager.GET_SIGNING_CERTIFICATES);
                signatures = info.signingInfo.getApkContentsSigners();
            } else {
                PackageInfo info = pm.getPackageInfo(getPackageName(),
                    PackageManager.GET_SIGNATURES);
                signatures = info.signatures;
            }

            MessageDigest md = MessageDigest.getInstance("SHA-256");
            for (Signature sig : signatures) {
                byte[] digest = md.digest(sig.toByteArray());
                StringBuilder sb = new StringBuilder();
                for (byte b : digest) sb.append(String.format("%02X", b));
                if (EXPECTED_CERT_SHA256.equalsIgnoreCase(sb.toString())) return true;
            }
        } catch (Exception ignored) {}

        return false;
    }

    /** Detect third-party accessibility services that can read screen content. */
    private boolean hasThirdPartyAccessibilityService() {
        AccessibilityManager am =
            (AccessibilityManager) getSystemService(ACCESSIBILITY_SERVICE);
        if (am == null) return false;

        List<AccessibilityServiceInfo> services = am.getEnabledAccessibilityServiceList(
            AccessibilityServiceInfo.FEEDBACK_ALL_MASK);
        for (AccessibilityServiceInfo svc : services) {
            String id = svc.getId();
            if (id == null) continue;
            // Allow known system / manufacturer accessibility services
            if (!id.startsWith("com.android")
                    && !id.startsWith("com.google")
                    && !id.startsWith("com.samsung.android")
                    && !id.startsWith("com.sec.android")) {
                return true;
            }
        }
        return false;
    }

    private void block(String title, String message) {
        new AlertDialog.Builder(this)
            .setTitle(title)
            .setMessage(message)
            .setCancelable(false)
            .setPositiveButton("Cerrar", (d, w) -> finishAndRemoveTask())
            .show();
    }

    // ── WebView Hardening ────────────────────────────────────────────────────

    private void hardenWebView() {
        try {
            // Disable Chrome DevTools remote debugging over USB (chrome://inspect)
            // Must be called before WebView is instantiated; Capacitor's super.onCreate() handles that,
            // so we call it here to override any debug-build default.
            WebView.setWebContentsDebuggingEnabled(false);

            WebView webView = getBridge().getWebView();
            WebSettings s = webView.getSettings();

            // Prevent file:// cross-origin access
            s.setAllowFileAccessFromFileURLs(false);
            s.setAllowUniversalAccessFromFileURLs(false);

            // Block HTTP resources inside HTTPS pages
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
                s.setMixedContentMode(WebSettings.MIXED_CONTENT_NEVER_ALLOW);
            }

            // Disable content:// URIs (no file picker plugins in this POC)
            s.setAllowContentAccess(false);

            // Tapjacking: reject taps when a window is obscuring this view
            webView.setFilterTouchesWhenObscured(true);

        } catch (Exception ignored) {}
    }

    // ── Lifecycle ────────────────────────────────────────────────────────────

    @Override
    protected void onPause() {
        super.onPause();
        // Clear clipboard when app goes to background to prevent
        // financial data (account numbers, amounts) from leaking to other apps
        ClipboardManager clipboard =
            (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
        if (clipboard != null) {
            clipboard.setPrimaryClip(ClipData.newPlainText("", ""));
        }
    }
}
