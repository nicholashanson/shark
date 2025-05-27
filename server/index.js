const http = require('http');
const fs = require('fs');
const path = require('path');

const server = http.createServer((req, res) => {
    if (req.url === '/bitmap') {
        const filePath = path.join(__dirname, '../assets/tiny_cross.bmp');
        
        fs.readFile(filePath, (err, data) => {
            if (err) {
                res.writeHead(500, {'Content-Type': 'text/plain'});
                res.end('Internal Server Error');
                return;
            }

            res.writeHead(200, {'Content-Type': 'image/bmp'});
            res.end(data);
        });
    } else if (req.url === '/lena') {
        const filePath = path.join(__dirname, '../assets/lena.bmp');
        
        fs.readFile(filePath, (err, data) => {
            if (err) {
                res.writeHead(500, {'Content-Type': 'text/plain'});
                res.end('Internal Server Error');
                return;
            }

            res.writeHead(200, {'Content-Type': 'image/bmp'});
            res.end(data);
        });
    } else if (req.url === '/checkerboard') {
        const filePath = path.join(__dirname, '../assets/checkerboard.bmp');
        
        fs.readFile(filePath, (err, data) => {
            if (err) {
                res.writeHead(500, {'Content-Type': 'text/plain'});
                res.end('Internal Server Error');
                return;
            }

            res.writeHead(200, {'Content-Type': 'image/bmp'});
            res.end(data);
        });
    } else if (req.url === '/color') {
        const filePath = path.join(__dirname, '../assets/color.mp4');

        fs.stat(filePath, (err, stats) => {
            if (err) {
                res.writeHead(404, { 'Content-Type': 'text/plain' });
                res.end('Video not found');
                return;
            }

            const range = req.headers.range;

            if (range) {
                // Stream partial content
                const positions = range.replace(/bytes=/, "").split("-");
                const start = parseInt(positions[0], 10);
                const total = stats.size;
                const end = positions[1] ? parseInt(positions[1], 10) : total - 1;
                const chunksize = (end - start) + 1;

                const file = fs.createReadStream(filePath, { start, end });
                res.writeHead(206, {
                    'Content-Range': `bytes ${start}-${end}/${total}`,
                    'Accept-Ranges': 'bytes',
                    'Content-Length': chunksize,
                    'Content-Type': 'video/mp4'
                });
                file.pipe(res);
            } else {
                // Stream entire file if no range is given
                res.writeHead(200, {
                    'Content-Length': stats.size,
                    'Content-Type': 'video/mp4'
                });
                fs.createReadStream(filePath).pipe(res);
            }
        });
    } else if (req.url === '/video') {
        // Serve HTML page that embeds the video
        const html = `
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="utf-8">
                <title>Algeria Video</title>
            </head>
            <body>
                <h1>Algeria Video</h1>
                <video controls width="640">
                    <source src="/algeria" type="video/mp4">
                    Your browser does not support the video tag.
                </video>
            </body>
            </html>
        `;
        res.writeHead(200, { 'Content-Type': 'text/html' });
        res.end(html);
    } else if (req.url === '/algeria') {
        const filePath = path.join(__dirname, '../assets/algeria_720p_fast.mp4');

        fs.stat(filePath, (err, stats) => {
            if (err) {
                res.writeHead(404, { 'Content-Type': 'text/plain' });
                res.end('Video not found');
                return;
            }

            const range = req.headers.range;
            console.log('Request headers:', req.headers);

            if (range) {
                console.log("byte-range request");
                // Stream partial content
                const positions = range.replace(/bytes=/, "").split("-");
                const start = parseInt(positions[0], 10);
                const total = stats.size;
                const end = positions[1] ? parseInt(positions[1], 10) : total - 1;
                const chunksize = (end - start) + 1;

                const file = fs.createReadStream(filePath, { start, end });
                res.writeHead(206, {
                    'Content-Range': `bytes ${start}-${end}/${total}`,
                    'Accept-Ranges': 'bytes',
                    'Content-Length': chunksize,
                    'Content-Type': 'video/mp4'
                });
                file.pipe(res);
            } else {
                console.log("full video requested");
                // Stream entire file if no range is given
                res.writeHead(200, {
                    'Content-Length': stats.size,
                    'Accept-Ranges': 'bytes',
                    'Content-Type': 'video/mp4'
                });
                fs.createReadStream(filePath).pipe(res);
            }
        });
    } else {
        res.writeHead(200, {'Content-Type': 'text/plain'});
        res.end('Hello, World from Node.js HTTP server!\n');
    }
});

server.listen(3000, '0.0.0.0', () => {
    console.log('Listening on port 3000');
});
