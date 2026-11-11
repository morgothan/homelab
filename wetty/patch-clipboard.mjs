#!/usr/bin/env node
/**
 * Patch WeTTY's built client bundle for Firefox clipboard support.
 *
 * Firefox refuses navigator.clipboard.writeText() unless the call happens from
 * an activation-triggering event (keydown, mousedown, click, ...). mouseup is
 * not one of them, so WeTTY's copy-on-select silently fails in Firefox while
 * working in Chrome (which also honours clipboard-write permission for the
 * active tab). Verified against Firefox 159: writeText from mouseup rejects
 * with NotAllowedError, while document.execCommand("copy") from the same
 * handler succeeds.
 *
 * WeTTY also copies document.getSelection() for Ctrl+Shift+C, which is the
 * page's DOM selection, not xterm's internal terminal selection, and it lets
 * xterm encode Ctrl+V as ^V (cancelling the browser paste).
 *
 * Patches:
 *   1. The copy helper uses a temporary textarea + document.execCommand(
 *      "copy") synchronously inside the user gesture, falling back to the
 *      async Clipboard API. This works in Firefox and Chrome.
 *   2. Ctrl+Shift+C copies the actual xterm selection via window.wetty_term.
 *   3. Ctrl+V returns false from WeTTY's custom key handler so xterm does not
 *      consume it; the browser's native paste event then reaches xterm.
 *
 * The bundle is minified, so match exact strings and fail loudly if upstream
 * changes them (a silent miss would reintroduce broken Firefox clipboard).
 */
import { readFile, writeFile } from 'node:fs/promises';

const BUNDLE = process.argv[2] || '/usr/src/app/build/client/wetty.js';

const copyHelper = `function j5(e){if(!e)return;const t=document.createElement("textarea");t.value=e;t.setAttribute("readonly","");t.style.position="fixed";t.style.top="-1000px";t.style.left="-1000px";t.style.opacity="0";document.body.appendChild(t);const n=document.activeElement;t.select();try{t.setSelectionRange(0,e.length)}catch(o){}let s=false;try{s=document.execCommand("copy")}catch(o){}t.remove();if(n&&n!==t&&typeof n.focus==="function")n.focus();if(!s)try{navigator.clipboard.writeText(e).catch(()=>{})}catch(o){}}`;

const shortcutHandler = `function $5(e){if(e.ctrlKey&&e.shiftKey&&e.key==="C"){e.preventDefault();let t=window.wetty_term?.getSelection()??"";t&&j5(t);return!1}if(e.type==="keydown"&&e.ctrlKey&&!e.shiftKey&&!e.altKey&&!e.metaKey&&(e.key==="v"||e.key==="V"))return!1;return!0}`;

const replacements = [
  {
    name: 'copy helper',
    from: 'function j5(e){navigator.clipboard.writeText(e).catch(()=>{})}',
    to: copyHelper,
  },
  {
    name: 'copy shortcut / paste passthrough',
    from: 'function $5(e){if(e.ctrlKey&&e.shiftKey&&e.key==="C"){e.preventDefault();let t=document.getSelection()?.toString()??"";return navigator.clipboard.writeText(t).catch(()=>{}),!1}return!0}',
    to: shortcutHandler,
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
console.log(
  'WeTTY client patched: copy uses execCommand inside the user gesture, Ctrl+Shift+C reads the terminal selection, Ctrl+V reaches native paste',
);
