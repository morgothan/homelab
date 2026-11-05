#!/usr/bin/env node
/**
 * Patch WeTTY's built client bundle for the tmux device-attributes issue.
 *
 * tmux asks the outer terminal for DA1/DA2 (CSI c / CSI > c) and waits five
 * seconds (`TTY_QUERY_TIMEOUT`). Any reply that arrives after that window is
 * treated as keyboard input and forwarded to the pane shell, which echoes it
 * as `62;4;9;22c0;276;0c` (the BELs are invisible). A stalled browser tab, a
 * socket reconnect, or a buffered reply can delay those bytes past the timeout.
 *
 * The fix has two parts in the client's session controller:
 *   1. Never emit terminal input while the socket is disconnected, so a
 *      reconnect cannot replay stale keystrokes/replies into a new pty.
 *   2. Strip DA replies from terminal input entirely: the terminal emulator
 *      answers tmux's probe, but the answer must never be forwarded. tmux then
 *      falls back to terminfo after its timeout instead of seeing stray keys.
 *
 * The bundle is minified, so match the two exact `emit("input")` functions and
 * fail loudly if upstream changes them (a silent miss would reintroduce the
 * garbage).
 */
import { readFile, writeFile } from 'node:fs/promises';

const BUNDLE = '/usr/src/app/build/client/wetty.js';

const replacements = [
  {
    name: 'terminal text input',
    from: 'function L(C){A.status==="active"&&f.emit("input",C)}',
    to: 'function L(C){if(A.status==="active"&&f.connected){let D=C.replace(/\\x1b\\[[?>][0-9;]*c/g,"");D&&f.emit("input",D)}}',
  },
  {
    name: 'terminal binary input',
    from: 'function k(C){A.status==="active"&&f.emit("input",C,!0)}',
    to: 'function k(C){A.status==="active"&&f.connected&&f.emit("input",C,!0)}',
  },
];

let source = await readFile(BUNDLE, 'utf8');
for (const { name, from, to } of replacements) {
  const occurrences = source.split(from).length - 1;
  if (occurrences !== 1) {
    throw new Error(
      `expected exactly one match for ${name} in ${BUNDLE}, found ${occurrences}`,
    );
  }
  source = source.replace(from, to);
}

await writeFile(BUNDLE, source);
console.log('WeTTY client patched: terminal input gated on socket state, DA replies dropped');
