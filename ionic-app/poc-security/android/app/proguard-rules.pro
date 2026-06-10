-optimizationpasses 5
-repackageclasses ''
-allowaccessmodification

# Strip verbose logs in release builds
-assumenosideeffects class android.util.Log {
    public static *** d(...);
    public static *** v(...);
    public static *** i(...);
    public static *** w(...);
}

# Capacitor bridge
-keep class com.getcapacitor.** { *; }
-keepattributes *Annotation*
-keep class io.ionic.** { *; }

# Keep WebView JavaScript interface
-keepclassmembers class * {
    @android.webkit.JavascriptInterface <methods>;
}
