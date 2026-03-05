#!/usr/bin/with-contenv sh
echo "[fonts] Rebuilding font cache..."
fc-cache -fv /usr/share/fonts/truetype/nerdfonts
echo "[fonts] Done."
