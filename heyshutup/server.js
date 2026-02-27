const express = require('express');
const app = express();
const fs = require('fs');
const path = require('path');
// Serve static files from media directory
app.use(express.static('./media', {
    logger: (locals, file) => {
        console.log(`Serving video file: ${file}`);
    }
}));
// Main route to serve a random video on each request
app.get('/', async (req, res) => {
    try {
        const mediaDir = path.join(__dirname, './media');
        
        // Read directory contents fresh for each request
        const files = await fs.promises.readdir(mediaDir);
        
        // Filter only video files (adjust extensions as needed)
        const videoFiles = files.filter(file => {
            const ext = path.extname(file).toLowerCase();
            return ['.mp4', '.avi', '.mov', '.mkv', '.wmv'].includes(ext);
        });
        if (videoFiles.length === 0) {
            throw new Error('No video files found in the media directory');
        }
        // Get random index for selection
        const randomIndex = Math.floor(Math.random() * videoFiles.length);
        const randomVideo = videoFiles[randomIndex];
	console.log(req.headers);
        console.log(`Serving video file: ${randomVideo}`);
        
        // Small delay to ensure different videos on refresh
        setTimeout(() => {
            res.send(`
                <!DOCTYPE html>
                <html>
                    <head>
                        <title>Hey Shut Up!</title>
                        <style>
                            body { margin: 0; padding: 0; width: 100%; height: 100vh; overflow: hidden; }
                            video {
                                position: fixed;
                                top: 0;
                                left: 0;
                                width: 100%;
                                height: 100%;
                                object-fit: contain;
                                background-color: black;
                                webkit-playsinline: yes;
                            }
                        </style>
                    </head>
                    <body>
                        <video id="mainVideo" loop autoplay playsinline controls width="100%" height="100%">
                            <source src="/${randomVideo}" type="video/mp4">
                            Your browser does not support the video element.
                        </video>
                        <script>
                            document.addEventListener('DOMContentLoaded', () => {
                                const video = document.getElementById('mainVideo');
                                // Enter fullscreen on load
                                if (video.requestFullscreen) {
                                    video.requestFullscreen();
                                }
                                video.play();
                                
                                // Handle play/pause button click
                                const playButton = document.createElement('button');
                                playButton.innerHTML = '⏸';
                                playButton.style.position = 'fixed';
                                playButton.style.top = '20px';
                                playButton.style.left = '20px';
                                playButton.style.zIndex = 1;
                                playButton.addEventListener('click', () => {
                                    if (video.paused) {
                                        video.play();
                                        playButton.textContent = '⏸';
                                    } else {
                                        video.pause();
                                        playButton.textContent = '▶';
                                    }
                                });
                                document.body.appendChild(playButton);
                                
                                // Toggle fullscreen on button click
                                const toggleFullscreen = () => {
                                    if (document.fullscreenElement === video) {
                                        document.exitFullscreen();
                                    } else {
                                        video.requestFullscreen();
                                    }
                                };
                                // Add event listener for Esc key to exit fullscreen
                                document.addEventListener('keydown', (e) => {
                                    if (e.key === 'Escape' && document.fullscreenElement === video) {
                                        document.exitFullscreen();
                                    }
                                });
                            });
                        </script>
                    </body>
                </html>
            `);
        }, 10); // Adjust delay here if needed
    } catch (error) {
        console.error('Error:', error);
        res.status(500).send('Error serving video');
    }
});
// Start the server on port 3000
const PORT = 3000;
app.listen(PORT, () => {
    console.log(`Server running at http://localhost:${PORT}`);
});
