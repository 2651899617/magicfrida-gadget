#!/system/bin/sh
SKIPUNZIP=0
[ "$ARCH" = "arm64" ] || abort "nianchu Gadget requires arm64"
[ "$API" -ge 26 ] || abort "nianchu Gadget requires Android API 26 or newer"
ui_print "No app selected by default. Edit targets.conf before testing."
ui_print "No APK install, property changes, KPM load or auto-reboot is performed."
set_perm_recursive "$MODPATH" 0 0 0755 0644
