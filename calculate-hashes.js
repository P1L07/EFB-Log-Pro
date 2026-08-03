// save as calculate-hashes.js
const fs = require('fs');
const crypto = require('crypto');

// Calculate SHA-384 for PDF worker
const pdfWorker = fs.readFileSync('./pdf.worker.min.js');
const pdfHash384 = crypto.createHash('sha384').update(pdfWorker).digest('base64');
console.log('PDF Worker SHA-384 (base64):', `sha384-${pdfHash384}`);

// Calculate SHA-256 for service worker (if exists)
if (fs.existsSync('./sw.js')) {
    const swContent = fs.readFileSync('./sw.js', 'utf8');
    const swHash256 = crypto.createHash('sha256').update(swContent).digest('hex');
    console.log('Service Worker SHA-256 (hex):', swHash256);
} else {
    console.log('No sw.js file found');
}