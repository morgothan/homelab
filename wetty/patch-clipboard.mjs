#!/usr/bin/env node
/**
 * Patch WeTTY's built client bundle for Firefox clipboard support.
 *
 * Firefox gates navigator.clipboard.writeText() on transient activation. A
 * write consumes that activation, so a later mouseup write can reject with
 * NotAllowedError while Chrome, which grants clipboard-write for the active
 * tab, succeeds. Verified against Firefox 159: writeText succeeds in mousedown
 * and in delayed tasks within the activation window, but rejects from mouseup
 * after an earlier write consumed activation; document.execCommand("copy")
 * from that same mouseup handler succeeds.
 *
 * WeTTY also copies document.getSelection() for Ctrl+Shift+C, which is the
 * page's DOM selection, not xterm's internal terminal selection, and it lets
 * xterm encode Ctrl+V as ^V (cancelling the browser paste).
 *
 * With tmux mouse mode on, a plain drag is handled by tmux (xterm selection is
 * disabled), and tmux writes the selection to the outer terminal via OSC 52.
 * xterm.js ignores OSC 52, so that selection never reaches the browser
 * clipboard. The OSC handler below writes it through the Clipboard API, which
 * works because the payload arrives shortly after the drag's mousedown while
 * transient activation is still fresh.
 *
 * Patches:
 *   1. The copy helper uses a temporary textarea + document.execCommand(
 *      "copy") synchronously inside the user gesture, falling back to the
 *      async Clipboard API. This works in Firefox and Chrome.
 *   2. Ctrl+Shift+C copies the actual xterm selection via window.wetty_term.
 *   3. Ctrl+V returns false from WeTTY's custom key handler so xterm does not
 *      consume it; the browser's native paste event then reaches xterm.
 *   4. OSC 52 is handled: tmux selections (plain drag, copy mode) land on the
 *      browser clipboard. Writes are accepted only within 10s of a user input
 *      event, narrowing clipboard hijacking by terminal output.
 *
 * The bundle is minified, so match exact strings and fail loudly if upstream
 * changes them (a silent miss would reintroduce broken Firefox clipboard).
 */
import { readFile, writeFile } from 'node:fs/promises';

const BUNDLE = process.argv[2] || '/usr/src/app/build/client/wetty.js';

const copyHelper = `function j5(e){if(!e)return;const t=document.createElement("textarea");t.value=e;t.setAttribute("readonly","");t.style.position="fixed";t.style.top="-1000px";t.style.left="-1000px";t.style.opacity="0";document.body.appendChild(t);const n=document.activeElement;t.select();try{t.setSelectionRange(0,e.length)}catch(o){}let s=false;try{s=document.execCommand("copy")}catch(o){}t.remove();if(n&&n!==t&&typeof n.focus==="function")n.focus();if(!s)try{navigator.clipboard.writeText(e).catch(()=>{})}catch(o){}}`;

const shortcutHandler = `function $5(e){if(e.ctrlKey&&e.shiftKey&&e.key==="C"){e.preventDefault();let t=window.wetty_term?.getSelection()??"";t&&j5(t);return!1}if(e.type==="keydown"&&e.ctrlKey&&!e.shiftKey&&!e.altKey&&!e.metaKey&&(e.key==="v"||e.key==="V"))return!1;return!0}`;

const osc52Registration = `this.parser.registerOscHandler(52,r=>{try{if(!(window.__wettyLastInput>=0)||performance.now()-window.__wettyLastInput>10000)return!0;const p=r.indexOf(";");if(p<0)return!0;const t=r.slice(0,p),a=r.slice(p+1);if((t!=="c"&&t!=="")||!a||a==="?")return!0;const n=atob(a);n&&navigator.clipboard.writeText(n).catch(()=>{})}catch(n){}return!0}),window.__wettyClipGuard||(window.__wettyClipGuard=!0,["mousedown","keydown","click"].forEach(n=>document.addEventListener(n,()=>{window.__wettyLastInput=performance.now()},!0))),this.onTitleChange(La)`;

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
  {
    name: 'OSC 52 clipboard handler',
    from: 'this.parser.registerOscHandler(9,r=>i.osc9(r)),this.parser.registerOscHandler(777,r=>i.osc777(r)),this.onTitleChange(La)',
    to: osc52Registration,
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
  'WeTTY client patched: copy uses execCommand inside the user gesture, Ctrl+Shift+C reads the terminal selection, Ctrl+V reaches native paste, tmux OSC 52 selections reach the clipboard',
);
