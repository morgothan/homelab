FROM ghcr.io/butlerx/wetty:latest

# Bundle the DroidSansM Nerd Font so web clients render Nerd glyphs (powerline
# separators, icons, etc.) even when the font is not installed locally.
COPY DroidSansMNerdFont-Regular.otf /usr/src/app/build/client/fonts/DroidSansMNerdFont-Regular.otf

# Expose the font through the page CSS as a web font.
RUN printf '\n@font-face {\n  font-family: "DroidSansM Nerd Font";\n  src: url("/client/fonts/DroidSansMNerdFont-Regular.otf") format("opentype");\n  font-weight: normal;\n  font-style: normal;\n  font-display: block;\n}\n' >> /usr/src/app/build/client/wetty.css

# Make the Nerd Font the default terminal font (Xterm options). Clients that
# already saved an option set in localStorage keep their own choice until they
# clear site data / reset options; new/incognito sessions pick this up.
# Upstream now ships this minified in functionality.js (was xterm_defaults.js,
# single-quoted; now double-quoted). Family name is left unquoted — a
# space-separated sequence is a valid CSS font-family, which avoids escaping
# nested quotes inside the minified string. The smoke-check below fails the
# build loudly if upstream shuffles this string again.
RUN sed -i 's/fontFamily:"courier-new, courier, monospace"/fontFamily:"DroidSansM Nerd Font, courier-new, courier, monospace"/' /usr/src/app/build/client/xterm_config/functionality.js

# Smoke-check the patch landed.
RUN grep -q "DroidSansM Nerd Font" /usr/src/app/build/client/xterm_config/functionality.js

# tmux probes the outer terminal for device attributes (DA1/DA2) and treats
# replies arriving after its 5s TTY_QUERY_TIMEOUT as keyboard input, which the
# pane shell then echoes as garbage ("62;4;9;22c0;276;0c"). Strip those replies
# in the client, and never emit terminal input while the socket is
# disconnected, so a stalled or reconnecting tab cannot inject them.
COPY patch-session.mjs /tmp/patch-session.mjs
RUN node /tmp/patch-session.mjs

# tmux refuses to draw a sixel image when the client pty reports zero pixel
# dimensions; it substitutes a "SIXEL IMAGE (WxH)" placeholder plus '+' lines.
# node-pty hardcodes ws_xpixel/ws_ypixel to 0, so tmux never sees a pixel size
# over SSH. Report 8x16 per cell (close to xterm.js's default cell) on spawn
# and resize, then rebuild the native addon (build/Release is loaded before
# prebuilds).
RUN cd /usr/src/app/node_modules/node-pty && \
    sed -i 's/winp.ws_xpixel = 0;/winp.ws_xpixel = winp.ws_col * 8;/g; s/winp.ws_ypixel = 0;/winp.ws_ypixel = winp.ws_row * 16;/g' src/unix/pty.cc && \
    test "$(grep -c 'winp.ws_xpixel = winp.ws_col \* 8' src/unix/pty.cc)" = 3 && \
    /usr/local/lib/node_modules/npm/node_modules/node-gyp/bin/node-gyp.js rebuild --nodedir=/usr/local && \
    test -f build/Release/pty.node
