# MamadVPN ProGuard Rules
# Keep native methods used by the Rust API crate
-keep class com.mamadvpn.** { *; }

# Keep JNI methods
-keepclasseswithmembernames class * {
    native <methods>;
}

# Keep Flutter embedding
-keep class io.flutter.** { *; }
-dontwarn io.flutter.**
