FROM ghcr.io/butlerx/wetty:latest

# Bundle the DroidSansM Nerd Font so web clients render Nerd glyphs (powerline
# separators, icons, etc.) even when the font is not installed locally.
COPY DroidSansMNerdFont-Regular.otf /usr/src/app/build/client/fonts/DroidSansMNerdFont-Regular.otf

# Expose the font through the page CSS as a web font.
RUN printf '\n@font-face {\n  font-family: "DroidSansM Nerd Font";\n  src: url("/client/fonts/DroidSansMNerdFont-Regular.otf") format("opentype");\n  font-weight: normal;\n  font-style: normal;\n  font-display: block;\n}\n' >> /usr/src/app/build/client/wetty.css

# Make the Nerd Font the default terminal font (Xterm options). Clients that
# already saved an option set in localStorage keep their own choice until they
# clear site data / reset options; new/incognito sessions pick this up.
RUN sed -i "s/fontFamily: 'courier-new, courier, monospace'/fontFamily: '\\\"DroidSansM Nerd Font\\\", courier-new, courier, monospace'/" /usr/src/app/build/client/xterm_config/xterm_defaults.js

# Smoke-check the patch landed.
RUN grep -n "DroidSansM Nerd Font" /usr/src/app/build/client/xterm_config/xterm_defaults.js
