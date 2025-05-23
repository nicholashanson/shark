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
    } else {
        res.writeHead(200, {'Content-Type': 'text/plain'});
        res.end('Hello, World from Node.js HTTP server!\n');
    }
});

server.listen(3000, '0.0.0.0', () => {
    console.log('Listening on port 3000');
});
