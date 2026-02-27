const express = require('express');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = 3000;
const MEDIA_DIR = path.join(__dirname, './media');
const VIDEO_EXTS = new Set(['.mp4', '.avi', '.mov', '.mkv', '.wmv']);

async function getVideoFiles() {
    const files = await fs.promises.readdir(MEDIA_DIR);
    return files.filter(f => VIDEO_EXTS.has(path.extname(f).toLowerCase()));
}

function pickRandom(arr, exclude) {
    if (arr.length <= 1) return arr[0];
    const choices = arr.filter(f => f !== exclude);
    return choices[Math.floor(Math.random() * choices.length)];
}

app.use(express.static(MEDIA_DIR));

// JSON endpoint: GET /api/random?current=filename
app.get('/api/random', async (req, res) => {
    try {
        const files = await getVideoFiles();
        if (!files.length) return res.status(404).json({ error: 'No videos found' });
        const video = pickRandom(files, req.query.current);
        console.log(`Picked: ${video}`);
        res.json({ video });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Server error' });
    }
});

app.get('/', async (req, res) => {
    try {
        const files = await getVideoFiles();
        if (!files.length) return res.status(500).send('No videos found');
        const initial = files[Math.floor(Math.random() * files.length)];
        console.log(`Initial: ${initial}`);
        res.send(html(initial));
    } catch (err) {
        console.error(err);
        res.status(500).send('Server error');
    }
});

app.listen(PORT, () => console.log(`heyshutup running on :${PORT}`));

function html(initial) {
    return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>HEY SHUT UP!</title>
  <style>
    @import url('https://fonts.googleapis.com/css2?family=Black+Ops+One&display=swap');

    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

    body {
      background: #0a0a0a;
      color: #fff;
      font-family: 'Black Ops One', Impact, 'Arial Black', sans-serif;
      min-height: 100vh;
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      overflow: hidden;
      user-select: none;
    }

    /* CRT scanline overlay */
    body::after {
      content: '';
      position: fixed;
      inset: 0;
      background: repeating-linear-gradient(
        0deg,
        transparent,
        transparent 2px,
        rgba(0,0,0,0.08) 2px,
        rgba(0,0,0,0.08) 4px
      );
      pointer-events: none;
      z-index: 100;
    }

    header {
      text-align: center;
      padding: 18px 20px 10px;
      position: relative;
      z-index: 10;
    }

    h1 {
      font-size: clamp(2.4rem, 8vw, 5.5rem);
      letter-spacing: 0.05em;
      line-height: 1;
      color: #ff2200;
      text-shadow:
        0 0 10px #ff2200,
        0 0 30px #ff4400,
        3px 3px 0 #7a0000,
        -1px -1px 0 #000;
      animation: flicker 4s infinite;
    }

    @keyframes flicker {
      0%, 95%, 100% { opacity: 1; }
      96%            { opacity: 0.85; }
      97%            { opacity: 1; }
      98%            { opacity: 0.7; }
      99%            { opacity: 1; }
    }

    .subtitle {
      font-size: clamp(0.6rem, 2vw, 0.9rem);
      letter-spacing: 0.35em;
      color: #888;
      text-transform: uppercase;
      margin-top: 4px;
    }

    .stage {
      position: relative;
      width: min(85vw, 900px);
      aspect-ratio: 16/9;
      background: #000;
      border: 3px solid #ff2200;
      box-shadow:
        0 0 0 1px #7a0000,
        0 0 30px rgba(255,34,0,0.4),
        inset 0 0 20px rgba(0,0,0,0.8);
      z-index: 10;
      margin: 10px 0;
    }

    video {
      width: 100%;
      height: 100%;
      display: block;
      object-fit: contain;
      background: #000;
    }

    /* Mute overlay — shown until user clicks */
    #unmute-overlay {
      position: absolute;
      inset: 0;
      background: rgba(0,0,0,0.75);
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      cursor: pointer;
      z-index: 20;
      gap: 12px;
    }

    #unmute-overlay.hidden { display: none; }

    #unmute-overlay span {
      font-size: clamp(1.6rem, 5vw, 3rem);
      color: #ff2200;
      text-shadow: 0 0 20px #ff4400;
      animation: pulse 1.2s ease-in-out infinite;
    }

    #unmute-overlay small {
      font-family: monospace;
      font-size: 0.75rem;
      color: #666;
      letter-spacing: 0.2em;
    }

    @keyframes pulse {
      0%, 100% { transform: scale(1); }
      50%       { transform: scale(1.08); }
    }

    /* Loading flash */
    .stage.loading::before {
      content: '';
      position: absolute;
      inset: 0;
      background: #ff2200;
      opacity: 0;
      animation: flash 0.25s ease-out;
      z-index: 5;
      pointer-events: none;
    }

    @keyframes flash {
      0%   { opacity: 0.5; }
      100% { opacity: 0; }
    }

    footer {
      display: flex;
      align-items: center;
      gap: 16px;
      padding: 10px 20px 18px;
      z-index: 10;
    }

    button {
      font-family: inherit;
      font-size: clamp(0.75rem, 2.5vw, 1rem);
      letter-spacing: 0.15em;
      background: transparent;
      color: #ff2200;
      border: 2px solid #ff2200;
      padding: 8px 20px;
      cursor: pointer;
      text-transform: uppercase;
      transition: background 0.15s, color 0.15s, box-shadow 0.15s;
    }

    button:hover, button:focus-visible {
      background: #ff2200;
      color: #000;
      box-shadow: 0 0 15px rgba(255,34,0,0.6);
      outline: none;
    }

    .hint {
      font-family: monospace;
      font-size: 0.65rem;
      color: #444;
      letter-spacing: 0.2em;
    }
  </style>
</head>
<body>

  <header>
    <h1>HEY SHUT UP!</h1>
    <p class="subtitle">heyshutup.com &nbsp;|&nbsp; est. forever</p>
  </header>

  <div class="stage" id="stage">
    <div id="unmute-overlay">
      <span>&#128266; CLICK TO UNMUTE</span>
      <small>[ sound required for full experience ]</small>
    </div>
    <video id="vid" playsinline autoplay muted loop>
      <source src="/${initial}" type="video/mp4">
    </video>
  </div>

  <footer>
    <button id="next-btn">&#9654; NEXT</button>
    <span class="hint">SPACE / N / CLICK &rarr; next video</span>
  </footer>

  <script>
    const vid     = document.getElementById('vid');
    const stage   = document.getElementById('stage');
    const overlay = document.getElementById('unmute-overlay');
    const nextBtn = document.getElementById('next-btn');

    let current  = '${initial}';
    let loading  = false;
    let unmuted  = false;

    // Try autoplay with sound first; fall back to muted
    vid.muted = false;
    vid.play().catch(() => {
      vid.muted = true;
      vid.play();
      overlay.classList.remove('hidden');
    });

    function unmute() {
      if (unmuted) return;
      unmuted = true;
      vid.muted = false;
      overlay.classList.add('hidden');
      vid.play();
    }

    overlay.addEventListener('click', unmute);

    async function nextVideo() {
      if (loading) return;
      loading = true;

      // Flash effect
      stage.classList.remove('loading');
      void stage.offsetWidth; // reflow
      stage.classList.add('loading');

      try {
        const res  = await fetch('/api/random?current=' + encodeURIComponent(current));
        const data = await res.json();
        current = data.video;

        const src = vid.querySelector('source');
        src.src = '/' + current;
        vid.load();
        vid.muted = !unmuted;
        vid.play().catch(() => {});
      } catch (e) {
        console.error('Failed to load next video', e);
      } finally {
        loading = false;
      }
    }

    // Auto-advance when video ends (only if not looping — remove "loop" attr to enable)
    // vid.addEventListener('ended', nextVideo);

    nextBtn.addEventListener('click', nextVideo);

    // Keyboard: Space or N
    document.addEventListener('keydown', e => {
      if (e.code === 'Space' || e.key === 'n' || e.key === 'N') {
        e.preventDefault();
        nextVideo();
      }
    });
  </script>
</body>
</html>`;
}
