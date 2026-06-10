-optimizationpasses 5
-repackageclasses ''
-allowaccessmodification

# ── Obfuscation dictionary ────────────────────────────────────────────────────
# Uses sequences of lowercase-l and uppercase-I: visually identical in most
# monospace fonts (jadx, dex2jar output), making decompiled code unreadable.
-obfuscationdictionary         obfuscation-dict.txt
-classobfuscationdictionary    obfuscation-dict.txt
-packageobfuscationdictionary  obfuscation-dict.txt

# ── Strip debug metadata ──────────────────────────────────────────────────────
# Removes original source file names and line numbers from DEX.
# Without these, jadx/apktool cannot show "at Foo.java:42" hints.
-renamesourcefileattribute SourceFile
-keepattributes !SourceFile,!LineNumberTable

# ── Strip all log calls (including error/wtf which leak stack traces) ─────────
-assumenosideeffects class android.util.Log {
    public static *** d(...);
    public static *** v(...);
    public static *** i(...);
    public static *** w(...);
    public static *** e(...);
    public static *** wtf(...);
}

# ── Capacitor bridge ──────────────────────────────────────────────────────────
-keep class com.getcapacitor.** { *; }
-keepattributes *Annotation*
-keep class io.ionic.** { *; }
-keep class io.ionic.starter.MainActivity { *; }

# Keep WebView JavaScript interface methods (used by Capacitor bridge)
-keepclassmembers class * {
    @android.webkit.JavascriptInterface <methods>;
}

# ── Prevent reflection-based class enumeration ────────────────────────────────
-keepattributes Signature
-keepattributes Exceptions
