# Proguard rules for Sentinel Companion
-keepattributes Signature
-keepattributes *Annotation*
-keepclassmembers class * {
    @androidx.room.* *;
}
