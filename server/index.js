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
    } else {
        res.writeHead(200, {'Content-Type': 'text/plain'});
        res.end('Hello, World from Node.js HTTP server!\n');
    }
});

server.listen(3000, '0.0.0.0', () => {
    console.log('Listening on port 3000');
});
