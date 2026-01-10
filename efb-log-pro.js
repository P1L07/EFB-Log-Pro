(function() {

const APP_VERSION = "1.4.23";

// 1. Fix XSS vulnerability
function sanitizeHTML(str) {
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
}

window.debugPDF = async function() {
    if (!ofpPdfBytes) {
        console.log("No PDF loaded");
        return;
    }
    
    // Try with PDF.js first
    const pdf = await pdfjsLib.getDocument(ofpPdfBytes).promise;
    console.log(`PDF.js sees ${pdf.numPages} pages`);
    
    // Try with PDFLib
    try {
        const pdfDoc = await PDFLib.PDFDocument.load(ofpPdfBytes);
        console.log(`PDFLib sees ${pdfDoc.getPageCount()} pages`);
    } catch(e) {
        console.log(`PDFLib error: ${e.message}`);
    }
    
    // Download the current ofpPdfBytes
    const blob = new Blob([ofpPdfBytes], {type: 'application/pdf'});
    const link = document.createElement('a');
    link.href = URL.createObjectURL(blob);
    link.download = 'DEBUG_current_ofpPdfBytes.pdf';
    link.click();
};


// 3. Clean up event listeners
window.addEventListener('beforeunload', () => {
    // Remove all event listeners
});

// ==========================================
// 1. CONFIGURATION & UPDATE LOGIC
// ==========================================
if ('serviceWorker' in navigator && (window.location.protocol === 'https:' || window.location.protocol === 'http:')) {
    
    navigator.serviceWorker.register('sw.js')
    .then(reg => {
        
        // 1. Check on Load
        reg.update();

        // 2. AUTO-CHECK: Check for updates every 15 minutes
        setInterval(() => {
            console.log("Checking for app updates...");
            reg.update();
        }, 15 * 60 * 1000);

        // 3. Listen for a new worker
        reg.onupdatefound = () => {
            const installingWorker = reg.installing;
            installingWorker.onstatechange = () => {
                if (installingWorker.state === 'installed' && navigator.serviceWorker.controller) {
                    if(confirm("New version available! Reload now?")) {
                        installingWorker.postMessage({ type: 'SKIP_WAITING' });
                        // Provide a small fallback reload in case controllerchange misses
                        setTimeout(() => window.location.reload(), 500);
                    }
                }
            };
        };
    });

    navigator.serviceWorker.addEventListener('controllerchange', () => {
        window.location.reload();
    });
}

    // --- JOURNEY LOG PDF MAPPING ---
    const JOURNEY_CONFIG = {
        fontSize: 10,
        
        // Vertical positioning for the leg list
        rowStartMain: 525, 
        rowStartFuel: 420,
        rowStartCrew: 350, 
        rowGap: 17, 
        
        // Signature Position
        sig: { x: 570, y: 125, width: 200, height: 50 },


        headers: {
            // Empty to prevent drawing summary info
        },

        // Leg Columns -> Mapped to internal Data Keys (X Coordinates)
        cols: {
            'j-out': 315,      // Block Out
            'j-in': 355,       // Block In
            'j-off': 395,      // Takeoff
            'j-on': 435,       // Landing
            'j-block': 475,    // Block Time
            'j-night': 515,   // Night Time 
            'j-flight': 555,   // Flight Time
            'j-to': 595,   // TO PF  
            'j-ldg': 635,   // LDG PF
            'j-ldg-type': 675,   // Manual/Automatic landing
            'j-flt-alt': 710,   // Flight Altitude
            'j-ldg-detail': 750,   // LDG Detail
            'j-init': 36,     // Init Fuel
            'j-uplift-w': 76, // Uplift Weight
            'j-calc-ramp': 116, // Calculated Ramp
            'j-act-ramp': 156, // Actual Ramp
            'j-shut': 196, // Shutdown
            'j-burn': 236,     // Trip Burn
            'j-uplift-vol': 276, // Uplift Volume
            'j-disc': 318,      // Discrepancy
            'j-slip': 350,      // Fuel Slip
            'j-slip-2': 410,      // Fuel Slip 2
            'j-adl': 475,      // Loadsheet ADL
            'j-chl': 515,      // Loadsheet CHL
            'j-inf': 556,      // Loadsheet INF
            'j-cargo': 595,      // Loadsheet Cargo
            'j-mail': 635,      // Loadsheet Mail
            'j-bag': 675,      // Loadsheet BAG
            'j-zfw': 714,      // Loadsheet ZFW
            'j-duty-operating': 205,      // Operating Crew
            'j-duty-time': 245,      // Duty Time
            'j-duty-night': 285,      // Duty Night
            'j-duty-allowed': 325,      // Duty Allowed
        },
        // Which columns use the 'rowStartFuel' Y-offset
        fuelKeys: ['j-init', 'j-uplift-w', 'j-calc-ramp', 'j-act-ramp', 'j-shut', 'j-burn', 'j-uplift-vol', 'j-disc', 'j-slip', 'j-slip-2', 'j-adl', 'j-chl', 'j-inf', 'j-cargo', 'j-mail', 'j-bag', 'j-zfw']
    };

    // --- PDF DRAWING CONSTANTS (OFP) ---
    const TIME_X = 485, ATO_X = 485, FOB_X = 445, NOTES_X = 160;
    const V_LIFT = 2;       
    const LINE_HEIGHT = 12;

    // ==========================================
    // 2. STATE & VARIABLES
    // ==========================================
    let ofpPdfBytes = null, originalFileName = "Logged_OFP.pdf";
    let journeyLogTemplateBytes = null;
    let waypoints = [], alternateWaypoints = [], dailyLegs = [], signaturePad = null; let savedSignatureData = null;
    let fuelData = [];
    let blockFuelValue = 0;
    let dutyStartTime = null;
    window.cutoffPageIndex = -1; 


    
    let frontCoords = {  
        atis: null, atcLabel: null, altm1: null, stby: null, altm2: null, picBlockLabel: null, reasonLabel: null 
    };

    const el = (id) => document.getElementById(id);

    function safeSet(id, val) { 
        const e = el(id); 
        if(!e) return;
        
        // If it's an input field, set .value
        if (e.tagName === 'INPUT' || e.tagName === 'SELECT' || e.tagName === 'TEXTAREA') {
            e.value = val || '';
        } 
        // If it's a div/span/label, set .innerText
        else {
            e.innerText = val || ''; 
        }
    }
    
    function safeText(id, val) { 
        const e = el(id); 
        if(e) e.innerText = val || ''; 
    }

// ==========================================
// 3. INITIALIZATION & LISTENERS
// ==========================================
async function runAnalysis(fileOrEvent) {
    let blob = null;
    let isAutoLoad = false;

    // 1. Determine source
    if (fileOrEvent instanceof Blob) {
        blob = fileOrEvent;
        isAutoLoad = true;
    } else {
        const fileInput = document.getElementById('ofp-file-in');
        if (fileInput && fileInput.files.length > 0) {
            blob = fileInput.files[0];
            // Force reset stored data on new manual upload
            window.savedWaypointData = [];
            localStorage.removeItem('efb_log_state'); 
        }
    }

    if (!blob) return;

    // 2. GLOBAL VARIABLE UPDATE (Crucial!)
    // We explicitly set window.ofpPdfBytes to ensure global scope sees the new file
    window.ofpPdfBytes = await blob.arrayBuffer(); 
    window.originalFileName = blob.name || "Logged_OFP.pdf";

    // 3. Initialize Viewer
    const pdf = await pdfjsLib.getDocument(window.ofpPdfBytes).promise;
    console.log(`[ANALYSIS] New PDF Loaded. Total Pages: ${pdf.numPages}`);

    // --- VISIBILITY FIX ---
    if (!isAutoLoad) {
        if (typeof clearOFPInputs === 'function') clearOFPInputs();
        const legForm = document.getElementById('leg-input-form');
        if(legForm) legForm.style.display = 'block';
    }

    // 4. Render Preview
    const container = document.getElementById('pdf-render-container');
    const fallback = document.getElementById('pdf-fallback');
    
    if (container && pdf) {
        if(fallback) fallback.style.display = 'none';
        container.innerHTML = '';
        
        // Only render first 3 pages for performance preview
        const previewLimit = Math.min(pdf.numPages, 3);
        for (let pageNum = 1; pageNum <= previewLimit; pageNum++) {
            const page = await pdf.getPage(pageNum);
            const scale = 1.5;
            const viewport = page.getViewport({ scale });
            const canvas = document.createElement('canvas');
            const context = canvas.getContext('2d');
            canvas.height = viewport.height;
            canvas.width = viewport.width;
            canvas.style.width = '100%'; 
            canvas.style.height = 'auto';
            canvas.style.maxWidth = '800px';
            canvas.style.marginBottom = '20px';
            container.appendChild(canvas);
            await page.render({ canvasContext: context, viewport: viewport }).promise;
        }
    }

    // 5. Reset Parsing Variables
    waypoints = []; 
    alternateWaypoints = []; 
    fuelData = []; 
    blockFuelValue = 0;
    window.cutoffPageIndex = -1;
    
    // Reset Coordinates
    frontCoords = { atis: null, atcLabel: null, altm1: null, stby: null, altm2: null, picBlockLabel: null, reasonLabel: null };

    // Helper for Coordinates
    function extractFrontCoords(items) {
        items.forEach(item => {
            const raw = item.str.toUpperCase();
            if (raw.includes('ALTM1')) frontCoords.altm1 = item;
            if (raw.includes('ALTM2')) frontCoords.altm2 = item;
            if (raw.includes('ATIS')) frontCoords.atis = item;
            if (raw.includes('CLRNC')) frontCoords.atcLabel = item;
            if (raw.includes('STBY')) frontCoords.stby = item;
            if (raw.includes('PIC') && raw.includes('BLOCK')) frontCoords.picBlockLabel = item;
            if (raw.includes('REASON')) frontCoords.reasonLabel = item;
        });
    }

    // 6. Parse Pages
    for (let i = 1; i <= pdf.numPages; i++) {
        const page = await pdf.getPage(i);
        const content = await page.getTextContent();
        const items = content.items;
        const textContent = items.map(x=>x.str).join(' ');

        // --- Page 1 Analysis ---
        if (i === 1) {
            extractFrontCoords(items);
            const match2 = textContent.match(/([A-Z]{3}\d{3,4})\s+([A-Z0-9-]{3,7})\s+(\d{2}\/\d{2}\/\d{2})\s+([A-Z]{4})\s+([A-Z]{4})\s+CI(\w+)\s+(\d{4})\s+\S+\s+(\d{4})\s+\S+\s+([A-Z]{4})/);

            if(match2) {
                const flt=match2[1], reg=match2[2], date=match2[3], dep=match2[4], dest=match2[5], ci=match2[6];
                const stdRaw=match2[7], staRaw=match2[8], altn=match2[9];
                const stdFmt = stdRaw.length===4 ? stdRaw.substring(0,2)+":"+stdRaw.substring(2,4) : stdRaw;
                const staFmt = staRaw.length===4 ? staRaw.substring(0,2)+":"+staRaw.substring(2,4) : staRaw;
                
                safeText('view-flt', flt); safeText('view-reg', reg); safeText('view-date', date);
                safeText('view-dep', dep); safeText('view-dest', dest); safeText('view-ci', 'CI'+ci);
                safeText('view-std-text', stdFmt); safeText('view-sta-text', staFmt);
                safeText('view-altn', altn);
                
                safeSet('j-flt', flt); safeSet('j-reg', reg); safeSet('j-date', date);
                safeSet('j-dep', dep); safeSet('j-dest', dest); safeSet('j-altn', altn);
                safeSet('j-std', stdFmt);

                extractRoutes(textContent);
                extractFuelDataSimple(textContent);
                extractWeights(textContent);
            }
        }
        
        // --- Flight Log Analysis (Pages 2+) ---
        if (i >= 2) {
            const rows = buildRows(items);
            rows.sort((a,b) => b.y - a.y); 
            
            let headerY = null;
            for(const row of rows) {
                const rowText = row.items.map(item => item.str).join(' ');
                if((rowText.includes("TO") && rowText.includes("FUEL")) || (rowText.includes("AWY") && rowText.includes("ETE"))) {
                    headerY = row.y; break; 
                }
            }
            
            if(!headerY) continue; 
            
            for(let r = 0; r < rows.length; r++) {
                const row = rows[r];
                if(row.y >= headerY) continue;
                if(row.items.length < 3) continue;
                
                let timeValue = null, fuelValue = null;
                for(const item of row.items) {
                    const str = item.str.trim();
                    if(/^\d+[\.:]\d{2}$/.test(str)) timeValue = str;
                    if(/^\d{3,5}$/.test(str) && !str.includes('.') && !str.includes(':')) {
                        const num = parseInt(str);
                        if(num >= 100 && num <= 50000 && !row.items.map(x=>x.str).join(' ').includes('FL ')) fuelValue = str;
                    }
                }
                
                if(timeValue && fuelValue) {
                    let data = { name: "?", awy: "-", level: "-", track: "-", wind: "-", tas: "-", gs: "-" };
                    if(r > 0) {
                        const prevRow = rows[r-1];
                        if(Math.abs(row.y - prevRow.y) < 25) {
                            const parts = prevRow.items.map(x => x.str).join(' ').trim().split(/\s+/);
                            if (parts.length > 0) data.name = parts[0];
                        }
                    }

                    if(data.name !== "?") {
                        const wpObj = {
                            ...data,
                            totalMins: parseTimeString(timeValue),
                            eto: "",
                            fob: parseInt(fuelValue) || 0,
                            page: i-1, 
                            y_anchor: row.y,
                            isTakeoff: false,
                            isAlternate: false,
                            rawTime: timeValue
                        };
                        waypoints.push(wpObj); 
                    }
                }
            }
        }
    } 
    
    // 7. Finalize
    waypoints.forEach(wp => { wp.baseFuel = parseInt(wp.fob) || 0; wp.fuel = wp.baseFuel; });
    processWaypointsList();
    
    if (document.getElementById('view-pic-block')) {
        const elPic = document.getElementById('view-pic-block');
        const val = blockFuelValue || 0;
        if(elPic.tagName === 'INPUT') elPic.value = val; else elPic.innerText = val; 
    }
    
    runCalc(); 
    validateInputs(); 
    renderFuelTable(); 
    renderTables();

    // Logic for loading state vs saving new state
    if (isAutoLoad) { 
        loadState(); 
        // Restore Waypoints
        if (window.savedWaypointData && window.savedWaypointData.length > 0) {
            window.savedWaypointData.forEach((data, i) => {
                if (i < waypoints.length) {
                    if(data.ato) safeSet(`o-a-${i}`, data.ato);
                    if(data.fuel) safeSet(`o-f-${i}`, data.fuel);
                    if(data.notes) safeSet(`o-n-${i}`, data.notes);
                    if(data.agl) safeSet(`o-agl-${i}`, data.agl);
                }
            });
            syncLastWaypoint(); 
            updateAlternateETOs();
        }
    } else { 
        saveState(); 
    }
}



// Clear signature function
function clearSignature() {
    if (signaturePad) {
        signaturePad.clear();
        updateSaveButtonState();
    }
}

// Update save button state based on whether signature exists
function updateSaveButtonState() {
    const saveButton = document.getElementById('btn-save-ofp');
    if (!signaturePad || saveButton === null) return;
    
    saveButton.disabled = signaturePad.isEmpty();
}

// Get signature as data URL (for saving/sending)
function getSignatureDataURL() {
    if (!signaturePad || signaturePad.isEmpty()) {
        return null;
    }
    return signaturePad.toDataURL(); // returns PNG image as base64
}

// Get signature as blob (for file upload)
function getSignatureBlob() {
    if (!signaturePad || signaturePad.isEmpty()) {
        return null;
    }
    
    return new Promise((resolve) => {
        signaturePad.toBlob((blob) => {
            resolve(blob);
        });
    });
}

window.saveSignatureToMemory = function() {
    if (signaturePad && !signaturePad.isEmpty()) {
        savedSignatureData = signaturePad.toDataURL(); 
    }
};

window.addEventListener('resize', function() {
    if (signaturePad) {
        const canvas = document.getElementById('sig-canvas');
        canvas.width = canvas.offsetWidth;
        signaturePad.clear();
    }
});

// Make functions available globally if needed
window.clearSignature = clearSignature;
window.getSignatureDataURL = getSignatureDataURL;
    
// --- VALIDATION HELPERS ---
window.validateAltimeter = function(el) {
    // Allow only 4 digits
    el.value = el.value.replace(/[^0-9]/g, '').substring(0, 4);
    validateInputs();
};

window.validateExtraFuel = function(el) {
    // Allow only digits
    el.value = el.value.replace(/[^0-9]/g, '');
    // Update calculations immediately
    calculatePICBlock(); 
    renderTables(); // Re-render table to update FOB figures
    validateInputs();
};

window.calculateExtraFromTotal = function() {
    const totalInput = el('view-pic-block');
    const extraInput = el('front-extra-kg');
    
    // Ensure we have the base Block Fuel from the OFP
    if (typeof blockFuelValue === 'undefined' || blockFuelValue === 0) return;
        const picTotal = parseInt(totalInput.value) || 0;
    
    // Calculation: Extra = User Total - OFP Block
    let diff = picTotal - blockFuelValue;
    
    // Optional: Don't allow negative extra
    if (diff < 0) diff = 0;

    extraInput.value = diff;
    
    // Update the Flight Log Table immediately ---
    runCalc();
    validateInputs();
};

    
window.onload = async function() {
    if (typeof pdfjsLib !== 'undefined') {
        pdfjsLib.GlobalWorkerOptions.workerSrc = './pdf.worker.min.js';
    }
        
    // OFP Upload
    const ofpFileInput = el('ofp-file-in');
    if (ofpFileInput) ofpFileInput.onchange = runAnalysis;
        // Journey Log Template Upload
        const journeyLogFile = el('journey-log-file');
        if (journeyLogFile) {
            journeyLogFile.addEventListener('change', async function(e) {
                const file = e.target.files[0];
                if (file) {
                    journeyLogTemplateBytes = await file.arrayBuffer();
                }
            });
        }
        
    // --- REAL-TIME CALCULATION LISTENERS ---

    // 1. Time fields
    ['j-out','j-off','j-on','j-in'].forEach(id => {
        const e = el(id);
        if (e) e.addEventListener('input', calcJourneyTimes);
    });
        
    // 2. Fuel fields
    ['j-init', 'j-uplift-w', 'j-calc-ramp', 'j-act-ramp', 'j-shut', 'j-burn', 'j-uplift-vol', 'j-disc', 'j-slip', 'j-slip-2'].forEach(id => {
        const e = el(id);
        if (e) e.addEventListener('input', calcFuel);
    });

    // 3. Loadsheet fields
    ['j-adl', 'j-chl', 'j-inf', 'j-cargo', 'j-mail', 'j-bag', 'j-zfw'].forEach(id => {
        const e = el(id);
        if (e) e.addEventListener('input', calcFuel);
    });

     // 4. OFP Sync
    const ofpAtdInput = el('ofp-atd-in');
    if (ofpAtdInput) {
        ofpAtdInput.addEventListener('input', (e) => {
            safeSet('j-off', e.target.value); 
            runCalc(); 
            calcJourneyTimes();
            validateInputs();
        });
    }
        
    // 5. Extra Fuel Sync
    const extraKgInput = el('front-extra-kg');
    if (extraKgInput) {
        extraKgInput.addEventListener('input', function() {
           calculatePICBlock();
            renderTables();
            validateInputs(); 
        });
    }

    // 6. Validation Triggers
    const altm1Input = el('front-altm1');
    if(altm1Input) altm1Input.addEventListener('input', validateInputs);
        ['j-flt', 'j-date'].forEach(id => {
            const e = el(id);
            if(e) e.addEventListener('input', validateInputs);
        });

        validateInputs();

        // --- NEW: OFFLINE AUTO-LOAD LOGIC ---
        try {
            // 1. Check if we have a saved PDF in the database
            const savedPdf = await loadPdfFromDB();
            
            if (savedPdf) {
                console.log("Auto-loading saved PDF...");
                await runAnalysis(savedPdf); 
            } else {
                // If no PDF, just load the text inputs from LocalStorage
                loadState();
            }
        } catch (e) {
            console.error("Auto-load error:", e);
            // Fallback if DB fails
            loadState();
        }
    };

// ==========================================
// 4. OFP PARSING LOGIC
// ==========================================

    // --- PARSING HELPERS ---
    
    function buildRows(items) {
        const rows = {};
        items.forEach(item => {
            const y = Math.round(item.transform[5]);
            if (!rows[y]) rows[y] = [];
            rows[y].push(item);
        });
        return Object.entries(rows).map(([y, items]) => ({
            y: parseFloat(y),
            items: items.sort((a, b) => a.transform[4] - b.transform[4])
        }));
    }

    function extractWaypointNameFromRowItems(items) {
        for(const item of items) {
            let str = item.str.trim();
            str = str.replace(/^-/, ''); 
            if(!str || str === '' || str === 'N/A' || str === '-----') continue;

            if(/^[A-Z]{4}$/.test(str)) return str;
            if(/^[A-Z]{3,5}$/.test(str)) {
                const skipList = ['TO', 'AWY', 'ET', 'FUEL', 'TOC', 'TOD', 'DES', 'FL', 'PLAN', 'BURN', 'ETE', 'COST', 'PROFILE', 'WIND'];
                if(!skipList.includes(str)) return str;
            }
            if(/^[A-Z]\d{3}[A-Z]$/.test(str)) return str;
            if(/^\d{5}[NSEW]$/.test(str)) return str;
            if(/^\d{4}[NSEW]\d?$/.test(str)) return str;
            if(/^AA\d{2,3}$/.test(str)) return str;
            if(/^[A-Z]{2,5}\d{0,2}[A-Z]?$/.test(str) && str.length >= 3) return str;
        }
        for(const item of items) {
            const str = item.str.trim();
            if(str.includes('N') && str.includes('E') && /\d{5}[NSEW]/.test(str)) {
                const parts = str.split(' ');
                for(const part of parts) { if(/^\d{5}[NSEW]$/.test(part)) return part; }
            }
        }
        return null;
    }

    function isFuelBurnAdjustmentRow(items) {
        const rowText = items.map(item => item.str.trim()).join(' ');
        const patterns = [ /FL\s+TOC\s+BURN/i, /FUEL BURN ADJUSTMENT/ ];
        return patterns.some(pattern => pattern.test(rowText));
    }

    function processWaypointsList() {
        const dest = el('view-dest')?.innerText || "ZZZZ";
        let splitIndex = -1;
        for(let i = 0; i < waypoints.length; i++) {
            if(waypoints[i].name === dest) { splitIndex = i + 1; break; }
        }
        if(splitIndex === -1) {
            for(let i = 1; i < waypoints.length; i++) {
                const fuelDrop = waypoints[i-1].fob - waypoints[i].fob;
                if(fuelDrop > 1000 && fuelDrop > (waypoints[i-1].fob * 0.1)) { splitIndex = i; break; }
                if(waypoints[i].name.includes('TOD') || waypoints[i].name.includes('DES')) { splitIndex = i + 1; break; }
            }
        }
        const all = [...waypoints];
        if(splitIndex > 0 && splitIndex < all.length) {
            waypoints = all.slice(0, splitIndex);
            alternateWaypoints = all.slice(splitIndex);
        } else {
            waypoints = all;
            alternateWaypoints = [];
        }
        if(waypoints.length > 0) {
            waypoints.unshift({ name: "TAKEOFF", totalMins: 0, eto: "", fob: waypoints[0].fob, page: 0, y_anchor: 0, isTakeoff: true });
        }
    }

    function extractRoutes(text) {
        const dr = text.match(/DEST\s+ROUTE[:\s]+([^\n]+?)(?=\s+ALTN\s+ROUTE|\s+FUEL|\s+$)/i);
        safeText('view-dest-route', dr ? dr[1].trim() : '-');
        const ar = text.match(/ALTN\s+ROUTE[:\s]+([^\n]+?)(?=\s+FUEL|\s+$)/i);
        safeText('view-altn-route', ar ? ar[1].trim() : '-');
    }

    function extractFuelDataSimple(text) {
        fuelData = []; blockFuelValue = 0;
        const patterns = [
            { name: "ALTN", regex: /ALTN\s+([A-Z]{3,4})\s+([\d.]+)\s+(\d+)/ },
            { name: "FINAL RESERVE", regex: /FINAL\s+RESERVE\s+([\d.]+)\s+(\d+)/ },
            { name: "MIN DIVERSION", regex: /MIN\s+DIVERSION\s+([\d.]+)\s+(\d+)/ },
            { name: "CONTINGENCY", regex: /CONTINGENCY\s+5M\s+([\d.]+)\s+(\d+)/ },
            { name: "MIN ADDITIONAL", regex: /MIN\s+ADDITIONAL\s+([\d.]+)\s+(\d+)/ },
            { name: "TOTAL RESERVE", regex: /TOTAL\s+RESERVE\s+([\d.]+)\s+(\d+)/ },
            { name: "TRIP", regex: /TRIP\s+([\d.]+)\s+(\d+)/ },
            { name: "ENDURANCE", regex: /ENDURANCE\s+([\d.]+)\s+(\d+)/ },
            { name: "TAXI", regex: /TAXI\s+(\d+)/ },
            { name: "MINIMUM BLOCK", regex: /MINIMUM\s+BLOCK\s+(\d+)/ },
            { name: "EXTRA", regex: /EXTRA\s+([\d.]+)\s+(\d+)/ },
            { name: "TANKERING", regex: /TANKERING\s+([\d.]+)\s+(\d+)/ },
            { name: "BLOCK FUEL", regex: /BLOCK\s+FUEL\s+([\d.]+)\s+(\d+)/ }
        ];
        
        patterns.forEach(p => {
            const m = text.match(p.regex);
            if (m) {
                if (p.name === "TAXI") fuelData.push({ name: p.name, time: "-", fuel: m[1], remarks: "" });
                else if (p.name === "MINIMUM BLOCK") safeText('view-min-block', m[1] + " kg");
                else if (p.name === "ALTN") fuelData.push({ name: p.name, time: m[2], fuel: m[3], remarks: m[1] });
                else {
                    fuelData.push({ name: p.name, time: m[1], fuel: m[2], remarks: "" });
                    if (p.name === "BLOCK FUEL") blockFuelValue = parseInt(m[2]);
                }
            }
        });
    }

    function extractWeights(text) {
        // Updated Regex to ensure captures for MPLD(4), FCAP(5), DOW(6)
        const m = text.match(/MTOW\s+(\d+)\s+MLW\s+(\d+)\s+MZFW\s+(\d+)\s+MPLD\s+(\d+)\s+FCAP\s+(\d+)\s+DOW\s+(\d+)\s+TOW\s+(\d+)\s+LW\s+(\d+)\s+ZFW\s+(\d+)\s+PLD\s+(\d+)/);
        if(m) {
            safeText('view-mtow', m[1]); 
            safeText('view-mlw', m[2]);
            safeText('view-mzfw', m[3]); 
            safeText('view-mpld', m[4]); 
            safeText('view-fcap', m[5]); 
            safeText('view-dow', m[6]); 
            safeText('view-tow', m[7]);
            safeText('view-lw', m[8]); 
            safeText('view-zfw', m[9]);
        }
    }

// ==========================================
// 5. CALCULATION LOGIC
// ==========================================
function parseTimeString(timeStr) {
    if(!timeStr) return 0;
        const separator = timeStr.includes(':') ? ':' : '.';
        const [hStr, mStr] = timeStr.split(separator);
        let h = parseInt(hStr)||0;
        let m = parseInt(mStr)||0;
        if(mStr && mStr.length === 1 && separator === '.') m *= 10; 
        return h*60 + m;
    }

window.testPDFLib = async function() {
    const pdfLibDoc = await PDFLib.PDFDocument.load(ofpPdfBytes);
    console.log(`PDFLib says: ${pdfLibDoc.getPageCount()} pages`);
    
    // Try to get each page
    for (let i = 0; i < pdfLibDoc.getPageCount(); i++) {
        try {
            const page = pdfLibDoc.getPage(i);
            console.log(`Page ${i} size: ${page.getWidth()}x${page.getHeight()}`);
        } catch(e) {
            console.log(`Page ${i} error: ${e.message}`);
        }
    }
};

window.runDownload = async function(mode = 'download') {
    // 1. Safety Check
    if(!window.ofpPdfBytes) return alert("Please Upload the OFP PDF first.");
    
    try {
        // 2. Load the SOURCE PDF
        const sourcePdf = await PDFLib.PDFDocument.load(window.ofpPdfBytes);
        const totalPages = sourcePdf.getPageCount();
        
        console.log(`[DOWNLOAD] Source PDF has ${totalPages} pages.`);
        
        // Safety Alert if the file is still the "ghost" file
        if (totalPages < 10) {
            if(!confirm(`WARNING: The loaded PDF only has ${totalPages} pages (it should be 50+). It might be corrupted. Do you want to continue?`)) return;
        }

        // 3. Create a NEW, CLEAN PDF (Cloning repairs internal structure)
        const newPdf = await PDFLib.PDFDocument.create();
        
        // 4. Determine Pages to Copy
        // We calculate exactly which page indices to copy [0, 1, 2, ... N]
        let lastPageIndex = totalPages - 1; 
        const cutoff = typeof window.cutoffPageIndex === 'number' ? window.cutoffPageIndex : -1;

        // Truncation Logic
        if (cutoff > 2 && cutoff < totalPages - 1) {
             console.log(`[DOWNLOAD] Truncating: Keeping pages 1 to ${cutoff + 1}`);
             lastPageIndex = cutoff;
        } else {
             console.log(`[DOWNLOAD] Keeping ALL ${totalPages} pages.`);
        }

        const indices = [];
        for (let i = 0; i <= lastPageIndex; i++) indices.push(i);

        // 5. Perform the Copy (Vector Method = Sharp Text)
        const copiedPages = await newPdf.copyPages(sourcePdf, indices);
        copiedPages.forEach(page => newPdf.addPage(page));

        // 6. Embed Fonts
        const fontB = await newPdf.embedFont(PDFLib.StandardFonts.HelveticaBold);
        const fontR = await newPdf.embedFont(PDFLib.StandardFonts.Helvetica);
        const pages = newPdf.getPages();

        // 7. iPad Rotation Fix
        const isIpadMode = el('chk-ipad-mode') ? el('chk-ipad-mode').checked : false;
        if(!isIpadMode && pages.length > 0) pages[0].setRotation(PDFLib.degrees(0));

        // ===============================================
        // DRAWING PHASE (Sharp Text Overlay)
        // ===============================================

        // --- Front Page ---
        if (pages.length > 0) {
            const p0 = pages[0];
            
            // Header Items
            const frontItems = [ 
                {id:'front-atis', offset:40, coord:frontCoords.atis}, 
                {id:'front-atc', offset:50, coord:frontCoords.atcLabel}
            ];
            frontItems.forEach(f => {
                const v = el(f.id)?.value;
                if(f.coord && v) p0.drawText(v.toUpperCase(), { x: f.coord.transform[4] + f.offset, y: f.coord.transform[5] + V_LIFT, size: 12, font: fontB });
            });

            // PIC Block & Reason
            const picBlockText = el('view-pic-block')?.innerText || "";
            if(frontCoords.picBlockLabel && picBlockText && picBlockText !== '-') {
                p0.drawText(picBlockText, { x: frontCoords.picBlockLabel.transform[4] + 65, y: frontCoords.picBlockLabel.transform[5] + V_LIFT, size: 12, font: fontB });
            }
            const reasonText = el('front-extra-reason')?.value || "";
            if(frontCoords.reasonLabel && reasonText) {
                p0.drawText(reasonText.toUpperCase(), { x: frontCoords.reasonLabel.transform[4] + 175, y: frontCoords.reasonLabel.transform[5] + V_LIFT, size: 12, font: fontB });
            }

            // Altimeters
            ['altm1','stby','altm2'].forEach(k => {
                const v = el('front-'+k)?.value;
                const coord = frontCoords[k];
                if(coord && v) {
                    p0.drawText(v, { x: coord.transform[4] + (k==='stby'?40:50), y: coord.transform[5] + V_LIFT, size: 12, font: fontB });
                }
            });

            // Signature
            if (signaturePad && !signaturePad.isEmpty() && frontCoords.reasonLabel) {
                try {
                    const sigImageBase64 = signaturePad.toDataURL();
                    const sigImage = await newPdf.embedPng(sigImageBase64);
                    p0.drawImage(sigImage, { x: frontCoords.reasonLabel.transform[4], y: frontCoords.reasonLabel.transform[5] + 40, width: 100, height: 35 });
                } catch (sigError) { console.error("Signature Error:", sigError); }
            }
        }

        // --- Waypoints (Flight Log) ---
        const draw = (list, pre) => {
            list.forEach((wp, i) => {
                if (wp.isTakeoff) return;
                
                // Only draw if the page exists in our new document
                if (wp.page >= 0 && wp.page < pages.length) {
                    const page = pages[wp.page];
                    const mainY = wp.y_anchor;
                    
                    const a = el(`${pre}-a-${i}`)?.value.replace(':','') || "";
                    const f = el(`${pre}-f-${i}`)?.value || "";
                    const n = el(`${pre}-n-${i}`)?.value || "";
                    const agl = el(`${pre}-agl-${i}`)?.value || ""; 

                    if(wp.eto) page.drawText(wp.eto, { x: TIME_X, y: mainY + LINE_HEIGHT + V_LIFT, size: 12, font: fontB, color: PDFLib.rgb(0,0,0.5) });
                    if(a) page.drawText(a, { x: ATO_X, y: mainY + V_LIFT, size: 12, font: fontR });
                    if(f) page.drawText(f, { x: FOB_X, y: mainY - LINE_HEIGHT + V_LIFT, size: 10, font: fontB });
                    if(n) page.drawText(n.toUpperCase(), { x: NOTES_X, y: mainY - LINE_HEIGHT + V_LIFT, size: 10, font: fontB });
                    if(agl) page.drawText(agl, { x: 115, y: mainY - LINE_HEIGHT + V_LIFT, size: 10, font: fontB });
                }
            });
        };
        draw(waypoints, 'o'); 
        draw(alternateWaypoints, 'a');

        // ===============================================
        // SAVE
        // ===============================================
        const bytes = await newPdf.save({ useObjectStreams: false });
        
        const filename = (window.originalFileName || "Logged_OFP.pdf").replace(".pdf", "_Logged.pdf");
        const isMobile = /iPhone|iPad|iPod|Android/i.test(navigator.userAgent);

        if (mode === 'email' && isMobile) {
            const flt = el('j-flt')?.value || "FLT";
            const date = el('j-date')?.value || "DATE";
            const subject = `OFP: ${flt} ${date}`;
            await sharePdf(bytes, filename, subject, "Please find attached the OFP.");
        } else {
            downloadBlob(bytes, filename);
        }
        
    } catch (error) { 
        console.error(error); 
        alert("Error saving PDF: " + error.message); 
    }
};

// Helper function to compress PDF
async function compressPDF(pdfBytes) {
    try {
        // Simple compression by re-saving with optimization
        const pdfDoc = await PDFLib.PDFDocument.load(pdfBytes);
        return await pdfDoc.save({
            useObjectStreams: true,
            addDefaultPage: false,
        });
    } catch(e) {
        console.log("Compression failed, using original:", e);
        return pdfBytes;
    }
}
window.runCalc = function() {
    const atd = el('ofp-atd-in')?.value;
    
    // ==========================================
    // 1. FIND TAXI FUEL (FROM PARSED DATA)
    // ==========================================
    let taxiFuel = 200; // Default fallback
    
    // Check if fuelData exists and has the TAXI entry
    if (typeof fuelData !== 'undefined' && Array.isArray(fuelData)) {
        const taxiEntry = fuelData.find(item => item.name === "TAXI");
        if (taxiEntry && taxiEntry.fuel) {
            taxiFuel = parseInt(taxiEntry.fuel);
        }
    }

    // ==========================================
    // 2. FIND LATEST ATO (Actual Time Over)
    // ==========================================
    let lastAtoMins = -1;
    let lastAtoIndex = -1;

    for (let i = waypoints.length - 1; i >= 0; i--) {
        const atoInput = el(`o-a-${i}`);
        if (atoInput && atoInput.value) {
            const [h, m] = atoInput.value.split(':').map(Number);
            lastAtoMins = h * 60 + m;
            lastAtoIndex = i;
            break; 
        }
    }

    // ==========================================
    // 3. DETERMINE START FUEL (PIC - TAXI)
    // ==========================================
    const pdfTakeoffFuel = waypoints[0] ? (waypoints[0].baseFuel || parseInt(waypoints[0].fob)) : 0;
    
    let startFuelInput = el('o-f-0');
    
    // Get PIC Block Fuel (from the box or the variable)
    const picBlock = parseInt(el('view-pic-block')?.value || el('view-pic-block')?.innerText) || blockFuelValue || 0;
    
    // Logic: If user typed a value in Waypoint 0 (Takeoff), use it.
    // Otherwise calculate: PIC BLOCK - TAXI FUEL
    let currentStartFuel = (startFuelInput && startFuelInput.value) 
        ? parseInt(startFuelInput.value) 
        : (picBlock - taxiFuel); 

    const delta = currentStartFuel - pdfTakeoffFuel;

// ==========================================
// 4. UPDATE WAYPOINTS LOOP
// ==========================================
    waypoints.forEach((wp, index) => {
        // --- FUEL CALC ---
        if (wp.baseFuel === undefined) wp.baseFuel = parseInt(wp.fob) || 0;
        
        // Apply delta
        if (wp.baseFuel > 0) wp.fuel = wp.baseFuel + delta;

        // --- TIME CALC ---
        if (index === 0 && wp.name === "TAKEOFF") {
            wp.eto = atd ? atd.replace(':', '') : "";
        } 
        else if (lastAtoIndex !== -1 && index > lastAtoIndex) {
            // Ripple Calculation
            const minutesFromLatest = wp.totalMins - waypoints[lastAtoIndex].totalMins;
            const newEtoMins = lastAtoMins + minutesFromLatest;
            
            const h = Math.floor((newEtoMins / 60) % 24).toString().padStart(2, '0');
            const m = Math.floor(newEtoMins % 60).toString().padStart(2, '0');
            wp.eto = h + m;
        } 
        else {
            // Standard Calculation
            if(!atd) wp.eto = "";
            else {
                const [h, m] = atd.split(':').map(Number);
                const targetMins = (h * 60 + m) + wp.totalMins;
                const hh = Math.floor((targetMins / 60) % 24).toString().padStart(2, '0');
                const mm = Math.floor(targetMins % 60).toString().padStart(2, '0');
                wp.eto = hh + mm;
            }
        }

        // --- UPDATE SCREEN ---
        const etoCell = el(`o-eto-${index}`);
        if (etoCell) etoCell.innerText = wp.eto || "--";
        const fuelCell = el(`o-calcfuel-${index}`);
        if (fuelCell) fuelCell.innerText = Math.round(wp.fuel) || "-";
    });
    
    updateAlternateETOs();
    updateFuelMonitor();
    syncLastWaypoint();
};

function calculatePICBlock() {
    const extra = parseInt(el('front-extra-kg')?.value) || 0;
    if(blockFuelValue > 0 || extra > 0) {
        safeText('view-pic-block', (blockFuelValue + extra) + " kg");
    } else {
        safeText('view-pic-block', '-');
        }
    }

// --- Journey Log Calculations ---
window.calcJourneyTimes = function() {
    const outT = el('j-out')?.value;
    const inT = el('j-in')?.value;
    const offT = el('j-off')?.value;
    const onT = el('j-on')?.value;

    if(outT && inT) safeSet('j-block', getDiff(outT, inT));
        else safeSet('j-block', ''); // Clear if inputs missing
        
    if(offT && onT) safeSet('j-flight', getDiff(offT, onT));
        else safeSet('j-flight', '');
        calcDutyLogic();
    };

window.updateCruiseLevel = function() {
let finalLevel = "";
    // 1. Default: Find Planned Level from OFP
    if(waypoints.length > 0) {
        const cruiseWP = waypoints.find(w => /^\d{3}$/.test(w.level) && w.level !== "000");
        if(cruiseWP) finalLevel = "FL" + cruiseWP.level;
    }

    // 2. Priority: Check if User entered an Actual Level
    // We scan all "ACT FL" inputs and take the highest value found
    let maxAct = 0;
    const inputs = document.querySelectorAll('[id^="o-agl-"]'); // Select all Flight Log FL inputs
    inputs.forEach(input => {
        const val = parseInt(input.value);
        if(val && val > maxAct) maxAct = val;
    });

    if(maxAct > 0) {
        finalLevel = "FL" + maxAct;
    }

    // 3. Update the Journey Log FL
        safeSet('j-flt-alt', finalLevel);
    };

    window.calcFuel = function() {
        // Safely get numeric values
        const val = (id) => { 
            const e = el(id); 
            return e && e.value !== "" ? parseFloat(e.value) : 0; 
        };
        const has = (id) => { const e = el(id); return e && e.value !== ""; };

        const init = val('j-init');
        const uplift = val('j-uplift-w');
        const act = val('j-act-ramp');
        const shut = val('j-shut');

        // Calc Ramp
        if(has('j-init') || has('j-uplift-w')) {
            const cr = init + uplift;
            safeSet('j-calc-ramp', cr);
            
            // Discrepancy
            if(has('j-act-ramp')) {
                safeSet('j-disc', act - cr);
            } else {
                safeSet('j-disc', '');
            }
        } else {
            safeSet('j-calc-ramp', '');
            safeSet('j-disc', '');
        }

        // Trip Burn
        if(has('j-act-ramp') && has('j-shut')) {
            safeSet('j-burn', act - shut);
        } else {
            safeSet('j-burn', '');
        }
    };

    function getDiff(s, e) {
        if(!s || !e) return "";
        let [sh,sm] = s.split(':').map(Number);
        let [eh,em] = e.split(':').map(Number);
        if(isNaN(sh) || isNaN(eh)) return "";
        
        let diff = (eh*60+em) - (sh*60+sm);
        if(diff<0) diff+=1440;
        return `${Math.floor(diff/60).toString().padStart(2,'0')}:${(diff%60).toString().padStart(2,'0')}`;
    }

// --- DUTY CALCULATION LOGIC ---
window.calcDutyLogic = function() {
    // 1. GATHER DATA
    let flt = (el('j-flt')?.value || "").trim();
    let dep = (el('j-dep')?.value || "").trim();
    let dest = (el('j-dest')?.value || "").trim();
    
    // FIX: Define 'std' by getting the value from the input field
    let std = (el('j-std')?.value || "").trim();

    // Fallback: If inputs are empty, try looking at the first saved leg
    if ((!std || !flt) && dailyLegs.length > 0) {
        flt = (dailyLegs[0]['j-flt'] || "").trim();
        dep = (dailyLegs[0]['j-dep'] || "").trim();
        dest = (dailyLegs[0]['j-dest'] || "").trim();
        std = (dailyLegs[0]['j-std'] || "").trim();
    }

    if (!std) return; // Now 'std' is defined, we can safely check it

    // 2. IDENTIFY AIRLINE & ROUTE
    const fltUpper = flt.toUpperCase();
    const isKZR = fltUpper.includes('KZR') || fltUpper.includes('KC');
    const isAYN = fltUpper.includes('AYN') || fltUpper.includes('FS'); 
    
    // Check if Departure/Destination is in Kazakhstan (ICAO code starts with UA)
    const isDepUA = dep.toUpperCase().startsWith('UA');  
    const isDestUA = dest.toUpperCase().startsWith('UA');

    // 3. CALCULATE FC OFFSET (Minutes before STD)
    let fcOffset = 60; // Default: 1h (Inbound/Return)

    if (isDepUA) { 
        // OUTBOUND from Kazakhstan
        if (isKZR) {
            // Air Astana
            if (!isDestUA) fcOffset = 90; // Int'l -> 1h 30m
            else fcOffset = 75;           // Domestic -> 1h 15m
        } 
        else if (isAYN) {
            // FlyArystan
            if (!isDestUA) fcOffset = 75; // Int'l -> 1h 15m
            else fcOffset = 60;           // Domestic -> 1h 00m
        }
    } 

    // 4. CALCULATE FC START TIME
    const stdMins = parseTimeString(std);
    let fcStartMins = stdMins - fcOffset;
    if (fcStartMins < 0) fcStartMins += 1440;

    // 5. CALCULATE CC START TIME (Relative to FC)
    // Rule: KZR CC reports 15m earlier. AYN CC reports same time.
    let ccDiff = 0;
    if (isKZR) {
        ccDiff = 15; // KZR: Cabin Crew report 15 mins BEFORE Flight Crew
    }
    
    let ccStartMins = fcStartMins - ccDiff;
    if (ccStartMins < 0) ccStartMins += 1440;

    // 6. UPDATE UI (Only if the field exists)
    safeSet('j-duty-start', minsToTime(fcStartMins));
    safeSet('j-cc-duty-start', minsToTime(ccStartMins));

    // Update Global Duty Start
    dutyStartTime = fcStartMins;
    
    // Recalculate Max FDP
    if(typeof recalcMaxFDP === 'function') recalcMaxFDP();
};

window.recalcMaxFDP = function() {
    // 1. Get FC and CC Start Times
    const fcTimeStr = el('j-duty-start')?.value;
    const ccTimeStr = el('j-cc-duty-start')?.value;
    if (!fcTimeStr) return;

    // Update global for other functions
    const fcMins = parseTimeString(fcTimeStr);
    const ccMins = ccTimeStr ? parseTimeString(ccTimeStr) : fcMins;
    dutyStartTime = fcMins; 

    // 2. Count Sectors
    const sectors = dailyLegs.length;

    // 3. Helper function to calculate max FDP with sector reductions
    const calculateMaxFDPWithSectors = (startMins, isCabinCrew = false) => {
        let maxFDP = 0;
        
        // EASA Time Band Logic
        if (isCabinCrew) {
            // CABIN CREW: 14 hours base
            if (startMins >= 360 && startMins <= 809) maxFDP = 840;
            else if (startMins >= 810 && startMins <= 839) maxFDP = 825;
            else if (startMins >= 840 && startMins <= 869) maxFDP = 810;
            else if (startMins >= 870 && startMins <= 899) maxFDP = 795;
            else if (startMins >= 900 && startMins <= 929) maxFDP = 780;
            else if (startMins >= 930 && startMins <= 959) maxFDP = 765;
            else if (startMins >= 960 && startMins <= 989) maxFDP = 750;
            else if (startMins >= 990 && startMins <= 1019) maxFDP = 735;
            else if (startMins >= 1020 || startMins <= 299) maxFDP = 660;
            else if (startMins >= 300 && startMins <= 314) maxFDP = 720;
            else if (startMins >= 315 && startMins <= 329) maxFDP = 735;
            else if (startMins >= 330 && startMins <= 344) maxFDP = 750;
            else if (startMins >= 345 && startMins <= 359) maxFDP = 765;
        } else {
            // FLIGHT CREW: 13 hours base
            if (startMins >= 360 && startMins <= 809) maxFDP = 780;
            else if (startMins >= 810 && startMins <= 839) maxFDP = 765;
            else if (startMins >= 840 && startMins <= 869) maxFDP = 750;
            else if (startMins >= 870 && startMins <= 899) maxFDP = 735;
            else if (startMins >= 900 && startMins <= 929) maxFDP = 720;
            else if (startMins >= 930 && startMins <= 959) maxFDP = 705;
            else if (startMins >= 960 && startMins <= 989) maxFDP = 690;
            else if (startMins >= 990 && startMins <= 1019) maxFDP = 675;
            else if (startMins >= 1020 || startMins <= 299) maxFDP = 660;
            else if (startMins >= 300 && startMins <= 314) maxFDP = 720;
            else if (startMins >= 315 && startMins <= 329) maxFDP = 735;
            else if (startMins >= 330 && startMins <= 344) maxFDP = 750;
            else if (startMins >= 345 && startMins <= 359) maxFDP = 765;
        }

        // Apply Sector Reductions
        if (sectors === 2) {
            // 2 sectors: no reduction
        } else if (sectors === 3) {
            maxFDP -= 30; // 3 Sectors: -30 mins
        } else if (sectors === 4) {
            maxFDP -= 60; // 4 Sectors: -60 mins
        } else if (sectors >= 5) {
            maxFDP -= 90; // 5+ Sectors: -90 mins
        }

        // Ensure minimum 660 minutes (11 hours)
        if (maxFDP < 660) maxFDP = 660;

        return maxFDP;
    };

    // 4. Calculate for both FC and CC
    const fcMax = calculateMaxFDPWithSectors(fcMins, false);
    const ccMax = calculateMaxFDPWithSectors(ccMins, true);

    // 5. Update both fields
    safeSet('j-max-fdp', minsToTime(fcMax));
    
    // Update hidden cabin crew max FDP
    const ccMaxInput = document.getElementById('j-cc-max-fdp-hidden');
    if (ccMaxInput) {
        ccMaxInput.value = minsToTime(ccMax);
    }
    
    // 6. Update FDP alerts for all legs
    updateAllLegFDPAlerts();
};

// Helper function for night calculation in Kazakhstan
function calculateNightTimeKZ(startMinsUTC, endMinsUTC) {
    if (startMinsUTC === null || endMinsUTC === null) return 0;
    
    // Kazakhstan night: 02:00-04:59 local = 21:00-23:59 UTC (previous day) and 00:00-01:59 UTC
    let nightOverlap = 0;
    
    // Adjust for midnight crossing
    let start = startMinsUTC;
    let end = endMinsUTC;
    if (end < start) end += 1440;
    
    // Night windows in UTC
    const nightWindows = [
        { start: 0, end: 119 },    // 00:00-01:59 UTC
        { start: 1260, end: 1439 }  // 21:00-23:59 UTC
    ];
    
    for (let i = start; i < end; i++) {
        const minuteOfDay = i % 1440;
        
        for (const window of nightWindows) {
            if (minuteOfDay >= window.start && minuteOfDay <= window.end) {
                nightOverlap++;
                break; // Count each minute only once
            }
        }
    }
    
    return nightOverlap;
}

// Helper function to update FDP alerts for all legs
function updateAllLegFDPAlerts() {
    const fcStartStr = el('j-duty-start')?.value;
    const ccStartStr = el('j-cc-duty-start')?.value;
    const fcMaxStr = el('j-max-fdp')?.value;
    const ccMaxStr = getCCMaxFDP();
    
    if (!fcStartStr || !ccStartStr) return;
    
    const fcStartMins = parseTimeString(fcStartStr);
    const ccStartMins = parseTimeString(ccStartStr);
    const fcLimit = parseTimeString(fcMaxStr || "13:00");
    const ccLimit = parseTimeString(ccMaxStr || "14:00");
    
    dailyLegs.forEach((leg, index) => {
        const onBlockStr = leg['j-in'];
        if (onBlockStr) {
            // Calculate FC FDP
            let fcMins = parseTimeString(onBlockStr) - fcStartMins;
            if (fcMins < 0) fcMins += 1440;
            leg.fdp = minsToTime(fcMins);
            leg.fdpAlert = (fcMins > fcLimit);
            
            // Calculate CC FDP
            let ccMins = parseTimeString(onBlockStr) - ccStartMins;
            if (ccMins < 0) ccMins += 1440;
            leg.ccFdpAlert = (ccMins > ccLimit);
        }
    });
    
    // Re-render the journey list with updated alerts
    renderJourneyList();
}


function minsToTime(m) {
    if(m<0) m+=1440;
        return `${Math.floor(m/60).toString().padStart(2,'0')}:${(m%60).toString().padStart(2,'0')}`;
}

// ==========================================
// 6. UI RENDERING & VALIDATION
// ==========================================
function renderTables() {
    // IMPORTANT: Calculate the latest fuel/times BEFORE drawing the HTML
    runCalc(); 

    const fill = (list, id, pre) => {
        const tb = el(id); 
        if(!tb) return;
        
        if (list.length === 0) {
            tb.innerHTML = '<tr><td colspan="13" style="text-align:center;color:gray;padding:20px">No waypoints found</td></tr>';
            return;
        }

        tb.innerHTML = list.map((wp, i) => {
            const isTO = (i === 0 && wp.name === "TAKEOFF");
            const atdVal = el('ofp-atd-in')?.value || '';
            
            const onInputFn = (pre === 'o') ? "runCalc(); syncLastWaypoint();" : "syncLastWaypoint()";
            
            const timeInput = isTO 
                ? `<input type="time" id="${pre}-a-${i}" class="input" style="padding:8px" oninput="updateTakeoffTime(this.value)" value="${atdVal}">`
                : `<input type="time" id="${pre}-a-${i}" class="input" style="padding:8px" oninput="${onInputFn}">`;
            
            let fuelEvent = "syncLastWaypoint(); updateFuelMonitor();"; // Default for all rows
            if (isTO) {
                fuelEvent = "runCalc(); syncLastWaypoint(); updateFuelMonitor();";
            }
            const actFuelInput = `<input type="number" id="${pre}-f-${i}" class="input" 
            style="width:70px; padding:8px; background:rgba(255,255,255,0.05); border:1px solid var(--border); color:var(--text); text-align:center;" 
            oninput="${fuelEvent}">`;
            
            const actFlInput = `<input type="number" id="${pre}-agl-${i}" class="input" maxlength="3" style="width:50px;padding:8px;text-align:center;color:var(--accent)" oninput="updateCruiseLevel()">`;
            const notesInput = `<input type="text" id="${pre}-n-${i}" class="input" style="padding:8px; width:100%" placeholder="...">`;

            return `<tr>
                <td style="font-weight:bold">${wp.name}</td>
                <td style="font-size:12px">${wp.awy || "-"}</td>
                <td style="font-size:12px; font-weight:bold; color:var(--text)">${wp.level || "-"}</td>
                <td style="font-size:12px">${wp.track || "-"}</td>
                <td style="font-size:12px">${wp.wind || "-"}</td>
                <td style="font-size:12px">${wp.tas || "-"}</td>
                <td style="font-size:12px">${wp.gs || "-"}</td>
                <td>${notesInput}</td>
                <td id="${pre}-eto-${i}">${wp.eto || "--"}</td>
                <td>${timeInput}</td>
                
                <td id="${pre}-calcfuel-${i}">${Math.round(wp.fuel) || "-"}</td>
                
                <td>${actFuelInput}</td>
                <td>${actFlInput}</td>
            </tr>`;
        }).join('');
    };
    
    fill(waypoints, 'ofp-tbody', 'o'); 
    fill(alternateWaypoints, 'altn-tbody', 'a');
    updateCruiseLevel();
}

window.updateLevel = function(type, index, value) {
    // 1. Update the internal data model (Keep this)
    if(type === 'o' && waypoints[index]) waypoints[index].level = value;
    if(type === 'a' && alternateWaypoints[index]) alternateWaypoints[index].level = value;
    
    // 2. Update the UI using the new SMART logic
    if(type === 'o') {
        updateCruiseLevel();
    }
};

function renderFuelTable() {
    const tb = el('fuel-tbody');
    if(!tb) return;
        if(fuelData.length === 0) {
            tb.innerHTML = '<tr><td colspan="4" style="text-align:center;">No Fuel Data</td></tr>';
            return;
        }
        const order = ["ALTN", "FINAL RESERVE", "MIN DIVERSION", "CONTINGENCY", "MIN ADDITIONAL", "TOTAL RESERVE", "TRIP", "ENDURANCE", "TAXI", "EXTRA", "TANKERING", "BLOCK FUEL"];
        const sorted = fuelData.filter(i => i.name !== "MINIMUM BLOCK").sort((a,b) => {
            let ia = order.indexOf(a.name), ib = order.indexOf(b.name);
            if(ia===-1) ia=99; if(ib===-1) ib=99;
            return ia - ib;
        });
        
        tb.innerHTML = sorted.map(i => `<tr><td>${i.name}</td><td>${i.time}</td><td>${i.fuel}</td><td>${i.remarks}</td></tr>`).join('');
    }

window.validateInputs = function() {
        const flt = el('j-flt')?.value;
        const date = el('j-date')?.value;
        const alt1 = el('front-altm1')?.value;
        const summaryOK = !!flt && !!date && !!alt1;
        
        const extra = el('front-extra-kg')?.value;
        const fuelOK = (blockFuelValue > 0);
        
        const flightLogOK = (waypoints.length > 0);
        
        const journeyOK = dailyLegs.length > 0;

        const checks = [
            { label: "Flight Summary", valid: summaryOK },
            { label: "Fuel", valid: fuelOK },
            { label: "Flight Log", valid: flightLogOK },
            { label: "Journey Log", valid: journeyOK }
        ];

        const list = el('validation-list');
        if(list) {
            list.innerHTML = checks.map(c => 
                `<div class="checklist-item"><span>${c.label}</span><span class="${c.valid?'status-ok':'status-fail'}">${c.valid?'✔':'✖'}</span></div>`
            ).join('');
            
            const valid = checks.every(c => c.valid);
            if(el('btn-save-ofp')) el('btn-save-ofp').disabled = !valid;
            if(el('btn-send-ofp')) el('btn-send-ofp').disabled = !valid;
        }
    };

    window.updateTakeoffTime = function(v) {
        if(el('ofp-atd-in')) el('ofp-atd-in').value = v;
        if(el('j-off')) el('j-off').value = v;
        runCalc(); calcJourneyTimes();
    };


    window.updateAlternateETOs = function() {
        if (waypoints.length === 0 || alternateWaypoints.length === 0) return;

        const lastPrimaryIdx = waypoints.length - 1;
        
        // 1. Determine Base Time (Destination Arrival)
        // Priority: Actual ATO -> Estimated ETO
        let baseTimeStr = el(`o-a-${lastPrimaryIdx}`)?.value; // Try Actual Input
        
        if (!baseTimeStr) {
             // Fallback to Estimated ETO if no Actual entered
             const destEto = waypoints[lastPrimaryIdx].eto; 
             if(destEto && destEto.length === 4) {
                 baseTimeStr = destEto.substring(0,2) + ":" + destEto.substring(2,4);
             }
        }

        if (!baseTimeStr) return; // No time to calc from

        // 2. Calculate Alternate Times
        const [bh, bm] = baseTimeStr.includes(':') 
            ? baseTimeStr.split(':').map(Number) 
            : [parseInt(baseTimeStr.substring(0,2)), parseInt(baseTimeStr.substring(2,4))];
        
        const baseDate = new Date(Date.UTC(2000,0,1,bh,bm));
        
        // Assuming OFP totalMins is cumulative from Takeoff.
        // We calculate the delta from the Destination.
        const destMins = waypoints[lastPrimaryIdx].totalMins;

        alternateWaypoints.forEach((wp, i) => {
            let delta = wp.totalMins - destMins;
            // Handle cases where alternate mins might reset to 0 in OFP
            if (delta < 0) delta = wp.totalMins; 

            const target = new Date(baseDate.getTime() + (delta * 60000));
            const newEto = target.getUTCHours().toString().padStart(2,'0') + 
                           target.getUTCMinutes().toString().padStart(2,'0');
            
            // 3. Update Data & UI
            wp.eto = newEto; // Update internal data for PDF
            const cell = el(`a-eto-${i}`); // Update visual table
            if (cell) cell.innerText = newEto;
        });
    };

    window.syncLastWaypoint = function() {
    if(waypoints.length === 0) return;
    const lastIdx = waypoints.length - 1;
    const wp = waypoints[lastIdx];

    // 1. Handle Landing Time (ATO or ETO)
    const lastATO = el(`o-a-${lastIdx}`)?.value;
    const currentETO = wp.eto ? (wp.eto.substring(0,2) + ":" + wp.eto.substring(2,4)) : "";
    
    // Priority: Actual Time > Calculated Estimate
    const finalTime = lastATO || currentETO;
    if(finalTime && el('j-on')) el('j-on').value = finalTime;

    // 2. Handle Shutdown Fuel (AFOB or EFOB)
    const lastFuel = el(`o-f-${lastIdx}`)?.value;
    const currentEFOB = Math.round(wp.fuel) || "";

    // Priority: Actual Fuel > Calculated Estimate
    const finalFuel = lastFuel || currentEFOB;
    if(finalFuel && el('j-shut')) el('j-shut').value = finalFuel;

    // 3. Trigger Journey Log math
    calcJourneyTimes(); 
    calcFuel();
    };

    window.updateFuelMonitor = function() {
    let latestIndex = -1;
    let fuelDiff = 0;
    let scheduleDiff = 0;
    const statusBlock = el('nav-status-block');

    // 1. FUEL MONITORING
    for (let i = waypoints.length - 1; i >= 0; i--) {
        const fInput = el(`o-f-${i}`);
        if (fInput && fInput.value) {
            fuelDiff = parseInt(fInput.value) - waypoints[i].fuel;
            latestIndex = i;
            break; 
        }
    }

    // 2. TIME MONITORING (ETA vs STA)
    const lastWp = waypoints[waypoints.length - 1];
    const staStr = el('view-sta-text')?.innerText.replace(':', '');
    let hasTimeData = false;

    if (lastWp && lastWp.eto && staStr && staStr !== "-") {
        const etaMins = parseInt(lastWp.eto.substring(0,2)) * 60 + parseInt(lastWp.eto.substring(2,4));
        const staMins = parseInt(staStr.substring(0,2)) * 60 + parseInt(staStr.substring(2,4));
        
        scheduleDiff = etaMins - staMins;
        if (scheduleDiff > 720) scheduleDiff -= 1440;
        if (scheduleDiff < -720) scheduleDiff += 1440;

        const timeEl = el('time-status-nav');
        if (timeEl) {
            hasTimeData = true;
            if (scheduleDiff > 0) {
                timeEl.innerText = `${scheduleDiff} MIN LATE`;
                timeEl.style.color = "#e74c3c";
            } else if (scheduleDiff < 0) {
                timeEl.innerText = `${Math.abs(scheduleDiff)} MIN EARLY`;
                timeEl.style.color = "#2ecc71";
            } else {
                timeEl.innerText = `ON TIME`;
                timeEl.style.color = "var(--dim)";
            }
        }
    }

    // 3. SHOW/HIDE LOGIC
    // Only show the block if we have a fuel entry OR a valid schedule calculation
    if (statusBlock) {
        if (latestIndex !== -1 || hasTimeData) {
            statusBlock.style.display = 'block';
        } else {
            statusBlock.style.display = 'none';
        }
    }

    // 4. UPDATE FUEL TEXT
    const fuelEl = el('fuel-status-nav');
    if (fuelEl) {
        if (latestIndex !== -1) {
            const prefix = fuelDiff >= 0 ? "+" : "";
            fuelEl.innerText = `FUEL: ${prefix}${Math.round(fuelDiff)} KG`;
            fuelEl.style.color = fuelDiff >= 0 ? "#2ecc71" : "#e74c3c";
            fuelEl.style.display = 'block';
        } else {
            fuelEl.style.display = 'none'; // Hide individual row if no fuel data
        }
    }
};


function clearOFPInputs() {
    // 1. Clear Front Page / Summary Inputs
    ['front-atis', 'front-atc', 'front-altm1', 'front-stby', 'front-altm2', 'front-extra-kg', 'front-extra-reason'].forEach(id => safeSet(id, ''));
        
    // 2. Clear Time / ATD Input
    safeSet('ofp-atd-in', '');
        
    // 3. Reset internal calculated variables
    waypoints = []; 
    alternateWaypoints = []; 
    fuelData = []; 
    blockFuelValue = 0;
        
    // 4. Clear the UI tables immediately (so they don't show old data while processing)
    const tables = ['ofp-tbody', 'altn-tbody', 'fuel-tbody'];
    tables.forEach(id => {
        const tb = el(id);
        if(tb) tb.innerHTML = '';
    });

    // 5. Reset Summary Text placeholders
        ['view-flt', 'view-reg', 'view-dep', 'view-dest'].forEach(id => safeText(id, '-'));
    }

    function clearJourneyInputs(transferFuel = "") {
        // Clear Times
        ['j-out', 'j-off', 'j-on', 'j-in', 'j-night'].forEach(id => safeSet(id, ''));
        
        // Clear Counts and Selects
        ['j-to', 'j-ldg'].forEach(id => safeSet(id, ''));
        safeSet('j-ldg-type', '');
        safeSet('j-ldg-detail', '');
        
        // Clear Fuel/Load specific to that leg
        ['j-uplift-w', 'j-uplift-vol', 'j-act-ramp', 'j-shut', 'j-slip', 'j-slip-2', 'j-adl', 'j-chl', 'j-inf', 'j-bag', 'j-cargo', 'j-mail', 'j-zfw'].forEach(id => safeSet(id, ''));
        
        // Mobe Shutdown Fuel to Inital Fuel on the next leg
        if (transferFuel) {
            safeSet('j-init', transferFuel);
        } else {
            safeSet('j-init', '');
        }

        // Reset Calculated Displays
        safeText('j-block', '00:00');
        safeText('j-flight', '00:00');
        safeText('j-calc-ramp', '0');
        safeText('j-burn', '0');
        safeText('j-disc', '0');
    }

    let journeyLog = [];

// Journey Log Leg Management
window.addLeg = function() {
    // Validation: Prevent adding empty legs
    const dest = el('j-dest')?.value;
    const dep = el('j-dep')?.value;
    
    // If Destination is empty, stop immediately.
    if (!dest || !dep) {
        return alert("No legs to insert");
    }

    // Maximum 4 legs
    if(dailyLegs.length >= 4) return alert("Max 4 legs.");

    // 1. Force hide immediately to test
    const form = document.getElementById('leg-input-form');
    if (form) {
        form.style.setProperty("display", "none", "important");
    }

    // ============================================================
    // 1. AUTO-CALCULATE DUTY (READ ONCE ON LEG 1)
    // ============================================================
    if (dailyLegs.length === 0) {
        // Check if user has ALREADY entered a manual time
        const currentFC = el('j-duty-start')?.value;
        const currentCC = el('j-cc-duty-start')?.value;

        // Only auto-calculate if fields are empty or "00:00"
        if (!currentFC || currentFC === "00:00" || !currentCC || currentCC === "00:00") {
            
            const std = el('j-std')?.value || "";
            const flt = el('j-flt')?.value || "";
            
            const dutyValues = calculateDutyValues(std, flt, dep, dest);
            
            // Only overwrite if the specific field was empty
            if (!currentFC || currentFC === "00:00") safeSet('j-duty-start', dutyValues.fc);
            if (!currentCC || currentCC === "00:00") safeSet('j-cc-duty-start', dutyValues.cc);
            
            // Always calc Max FDP if it's empty
            if (!el('j-max-fdp')?.value || el('j-max-fdp')?.value === "00:00") {
                safeSet('j-max-fdp', dutyValues.max);
            }
            
            // Set the hidden cabin crew max FDP
            setCCMaxFDP(dutyValues.ccMax);
        }
        
        // Ensure the global variable is synced with whatever ended up in the box
        dutyStartTime = parseTimeString(el('j-duty-start')?.value);
    }

    // ============================================================
    // 2. FDP CHECK (BOTH FC AND CC) - FIXED CALCULATION
    // ============================================================
    const onBlock = el('j-in')?.value;
    let fdp = "", alertFdp = false, ccFdpAlert = false;

    // Calculate FDP for display (sector time vs cumulative)
    if(onBlock) {
        if (dailyLegs.length === 0) {
            // First leg: FDP = reporting to this leg's block
            const fcStartStr = el('j-duty-start')?.value;
            if (fcStartStr) {
                let fcMins = parseTimeString(onBlock) - parseTimeString(fcStartStr);
                if (fcMins < 0) fcMins += 1440; 
                fdp = minsToTime(fcMins);
            }
        } else {
            // Subsequent legs: FDP = previous leg block to this leg block
            const prevLeg = dailyLegs[dailyLegs.length - 1];
            const prevOnBlock = prevLeg['j-in'];
            if (prevOnBlock) {
                fdp = getDiff(prevOnBlock, onBlock);
            }
        }

        // Check alerts (cumulative from reporting)
        const fcStartStr = el('j-duty-start')?.value;
        const ccStartStr = el('j-cc-duty-start')?.value;
        
        if (fcStartStr) {
            let fcCumulativeMins = parseTimeString(onBlock) - parseTimeString(fcStartStr);
            if (fcCumulativeMins < 0) fcCumulativeMins += 1440; 
            const fcLimit = parseTimeString(el('j-max-fdp')?.value || '13:00');
            if(fcCumulativeMins > fcLimit) alertFdp = true;
        }
        
        // Check cabin crew FDP
        if (ccStartStr) {
            const ccMaxFDPStr = getCCMaxFDP();
            
            let ccCumulativeMins = parseTimeString(onBlock) - parseTimeString(ccStartStr);
            if (ccCumulativeMins < 0) ccCumulativeMins += 1440; 
            const ccLimit = parseTimeString(ccMaxFDPStr);
            if(ccCumulativeMins > ccLimit) ccFdpAlert = true;
        }
    }

    // ============================================================
    // 3. NIGHT DUTY CALCULATION (Kazakhstan UTC+5)
    // ============================================================
    let nightTime = "00:00";
    const onBlockTime = el('j-in')?.value;
    const offBlockTime = el('j-off')?.value;
    
    if (offBlockTime && onBlockTime) {
        // Kazakhstan night: 02:00-04:59 local = 21:00-23:59 UTC (previous day) and 00:00-01:59 UTC
        const depMins = parseTimeString(offBlockTime);
        const arrMins = parseTimeString(onBlockTime);
        
        // Convert to Kazakhstan time (UTC+5) by subtracting 5 hours
        // But our times are in UTC, so for night calculation we need to check UTC times
        // Night in UTC = 21:00-23:59 and 00:00-01:59
        
        let nightOverlap = 0;
        let currentMins = depMins;
        const arrAdjusted = arrMins < depMins ? arrMins + 1440 : arrMins;
        
        while (currentMins < arrAdjusted) {
            // Check first night window: 21:00-23:59 UTC
            if (currentMins >= 1260 && currentMins <= 1439) {
                nightOverlap += Math.min(arrAdjusted, 1439) - currentMins + 1;
            }
            // Check second night window: 00:00-01:59 UTC
            else if (currentMins >= 0 && currentMins <= 119) {
                nightOverlap += Math.min(arrAdjusted, 119) - currentMins + 1;
            }
            
            currentMins += 60; // Check next minute
            if (currentMins > 1440) currentMins -= 1440;
        }
        
        // Convert minutes back to time format
        const hours = Math.floor(nightOverlap / 60);
        const minutes = nightOverlap % 60;
        nightTime = `${hours.toString().padStart(2, '0')}:${minutes.toString().padStart(2, '0')}`;
    }
    
    safeSet('j-night', nightTime);
    safeSet('j-night-calc', nightTime);

    // ============================================================
    // 4. CAPTURE DATA
    // ============================================================
    const d = {};
    const getValue = (id) => {
        const e = el(id);
        if (!e) return "";
        return (e.tagName === 'INPUT' || e.tagName === 'SELECT' || e.tagName === 'TEXTAREA') 
                ? e.value : e.innerText;
    };

    ['j-flt','j-reg','j-dep','j-dest','j-altn','j-out','j-off','j-on','j-in','j-block','j-flight', 'j-night', 'j-to', 'j-ldg', 'j-ldg-type', 'j-flt-alt', 'j-ldg-detail', 'j-init','j-uplift-w', 'j-calc-ramp', 'j-act-ramp','j-shut','j-burn', 'j-uplift-vol', 'j-slip', 'j-slip-2', 'j-disc','j-adl', 'j-chl', 'j-inf', 'j-cargo', 'j-mail', 'j-bag', 'j-zfw','j-date', 'j-std'].forEach(k => {
        d[k] = getValue(k);
    });

    d.fdp = fdp; 
    d.fdpAlert = alertFdp;
    d.ccFdpAlert = ccFdpAlert;
    
    dailyLegs.push(d);
    
    // ============================================================
    // 5. RECALCULATE MAX FDP WITH SECTOR REDUCTIONS
    // ============================================================
    setTimeout(() => {
        if (typeof recalcMaxFDP === 'function') {
            recalcMaxFDP();
        }
    }, 100);

    // ============================================================
    // 6. UPDATE NIGHT DUTY FOR ALL CREW
    // ============================================================
    // Update the journey list with calculated values
    renderJourneyList();
    validateInputs();

    // ============================================================
    // 7. PREPARE NEXT LEG
    // ============================================================
    const nextInitFuel = d['j-shut'];
    clearJourneyInputs(nextInitFuel);
    safeSet('j-dep', '');   
    safeSet('j-dest', '');
    
    // Auto-save immediately
    saveState();
};

window.removeLeg = function(i) {
    dailyLegs.splice(i,1);
    
    // If we deleted the last leg, reset the duty fields
    if(dailyLegs.length === 0) { 
        safeSet('j-duty-start', "00:00");
        safeSet('j-cc-duty-start', "00:00");
        safeSet('j-max-fdp', "00:00");
        const ccMaxHidden = document.getElementById('j-cc-max-fdp-hidden');
        if (ccMaxHidden) {
            ccMaxHidden.value = "00:00";
        }
        dutyStartTime = null;
    }
        renderJourneyList(); 
        validateInputs();
        saveState();
    };
    
window.clearLegs = async function() {
    if(!confirm("Warning: This will delete ALL data (OFP, Flight Log, and Journey Log). Continue?")) return;

    // ===========================================
    // 1. RESET INTERNAL VARIABLES
    // ===========================================
    dailyLegs = [];
    waypoints = [];
    alternateWaypoints = [];
    fuelData = [];
    window.savedWaypointData = [];
    dutyStartTime = null;
    blockFuelValue = 0;
    savedSignatureData = null;
    window.cutoffPageIndex = -1;

    // ===========================================
    // 2. CLEAR TABLES (VISUALS)
    // ===========================================
    renderJourneyList(); // Wipes Journey Log table
    
    // Wipe Flight Log & Fuel Table
    ['ofp-tbody', 'altn-tbody', 'fuel-tbody'].forEach(id => {
        const tb = document.getElementById(id);
        if(tb) tb.innerHTML = '';
    });
    
    // Set Fuel Table to "Empty" state
    const fuelTb = document.getElementById('fuel-tbody');
    if(fuelTb) fuelTb.innerHTML = '<tr><td colspan="4" style="text-align:center;">No Fuel Data</td></tr>';

    //Remove canvas
    const pdfContainer = document.getElementById('pdf-render-container');
    const pdfFallback = document.getElementById('pdf-fallback');

    if (pdfFallback) pdfFallback.style.display = 'block'; // Show the "Drop PDF Here" box again

    if (pdfContainer) pdfContainer.innerHTML = ''; // Remove the canvas elements

    // ===========================================
    // 3. CLEAR TEXT DISPLAYS (spans/divs)
    // ===========================================
    // These are the fields you mentioned were sticking around
    const textIDs = [
        'view-flt', 'view-reg', 'view-date', 'view-dep', 'view-dest', 
        'view-std-text', 'view-sta-text', 'view-altn', 'view-ci',
        'view-dest-route', 'view-altn-route', 
        'view-min-block', 'view-pic-block', // Fuel Headers
        // Weights
        'view-mtow', 'view-mlw', 'view-mzfw', 'view-mpld', 'view-fcap', 
        'view-dow', 'view-tow', 'view-lw', 'view-zfw'
    ];
    
    textIDs.forEach(id => {
        const e = document.getElementById(id);
        if(e) {
            // If it's an input, clear value; otherwise clear text
            if(e.tagName === 'INPUT' || e.tagName === 'TEXTAREA') e.value = "";
            else e.innerText = "-"; 
        }
    });

    // ===========================================
    // 4. CLEAR INPUT FIELDS (Values)
    // ===========================================
    const inputIDs = [
        // Front Page & OFP Inputs
        'front-atis', 'front-atc', 'front-altm1', 'front-stby', 'front-altm2', 
        'front-extra-kg', 'front-extra-reason', 'ofp-atd-in',
        
        // Hidden/Sync Inputs (Crucial for syncing)
        'j-flt', 'j-reg', 'j-date', 'j-dep', 'j-dest', 'j-altn', 'j-std',
        
        // Journey Log Inputs
        'j-out', 'j-off', 'j-on', 'j-in', 'j-night', 'j-night-calc',
        'j-to', 'j-ldg', 'j-ldg-type', 'j-flt-alt', 'j-ldg-detail',
        'j-init', 'j-uplift-w', 'j-uplift-vol', 'j-act-ramp', 'j-shut', 'j-slip', 'j-slip-2',
        'j-adl', 'j-chl', 'j-inf', 'j-bag', 'j-cargo', 'j-mail', 'j-zfw'
    ];

    inputIDs.forEach(id => {
        const e = document.getElementById(id);
        if(e) e.value = "";
    });

// ===========================================
// 5. RESET DUTY & DEFAULTS
// ===========================================
    safeSet('j-duty-start', "00:00");
    safeSet('j-cc-duty-start', "00:00");
    safeSet('j-max-fdp', "00:00");
    safeSet('j-fc-count', "2"); 
    safeSet('j-cc-count', "4");
    // Reset hidden CC max FDP
    const ccMaxHidden = document.getElementById('j-cc-max-fdp-hidden');
    if (ccMaxHidden) {
        ccMaxHidden.value = "00:00";
    }

    // Reset Signature Pad
    if (window.signaturePad) {
        window.signaturePad.clear();
    }
    
    // Reset File Input (allows re-uploading same file)
    const fileInput = document.getElementById('ofp-file-in');
    if(fileInput) fileInput.value = "";
    
    // ===========================================
    // 6. CLEAR STORAGE & VALIDATION
    // ===========================================
    localStorage.removeItem('efb_log_state');
    
    try {
        if (typeof clearPdfDB === 'function') {
            await clearPdfDB();
        }
    } catch(e) { 
        console.log("Database clear error:", e); 
    }

    if (typeof validateInputs === 'function') validateInputs();
    
    console.log("App completely reset.");
};

// Helper to get hidden CC max FDP
function getCCMaxFDP() {
    const ccMaxHidden = document.getElementById('j-cc-max-fdp-hidden');
    return ccMaxHidden ? ccMaxHidden.value : "00:00";
}

// Helper to set hidden CC max FDP
function setCCMaxFDP(value) {
    const ccMaxHidden = document.getElementById('j-cc-max-fdp-hidden');
    if (ccMaxHidden) {
        ccMaxHidden.value = value || "00:00";
    }
}

    // --- MOVE LEG (Re-order Sequence) ---
window.moveLeg = function(index, direction) {
    const newIndex = index + direction;
    
    // Safety check boundaries
    if (newIndex < 0 || newIndex >= dailyLegs.length) return;

    // 1. Swap the elements in the array
    const temp = dailyLegs[index];
    dailyLegs[index] = dailyLegs[newIndex];
    dailyLegs[newIndex] = temp;

    // 2. RECALCULATE DUTY LOGIC (Always run this to ensure sync)
    if (dailyLegs.length > 0) {
        const firstLeg = dailyLegs[0];

        // A. Calculate new Duty Start/Max based on the NEW first leg's data
        // We read directly from the saved leg data, not the input boxes
        const newDutyValues = calculateDutyValues(
            firstLeg['j-std'], 
            firstLeg['j-flt'], 
            firstLeg['j-dep'], 
            firstLeg['j-dest']
        );

        // B. Update the screen inputs
        safeSet('j-duty-start', newDutyValues.fc);
        safeSet('j-cc-duty-start', newDutyValues.cc);
        safeSet('j-max-fdp', newDutyValues.max);

        // C. Update the global variable used for calculations
        dutyStartTime = parseTimeString(newDutyValues.fc);
        const maxLimitMins = parseTimeString(newDutyValues.max);

        // Update hidden cabin crew max FDP
        const ccMaxHidden = document.getElementById('j-cc-max-fdp-hidden');
        if (ccMaxHidden) {
            ccMaxHidden.value = newDutyValues.ccMax;
        }

        // D. Re-calculate FDP Duration & Alerts for ALL legs
        // (Because if the start time changed, every leg's FDP duration changes)
        dailyLegs.forEach(leg => {
            const onBlockStr = leg['j-in'];
            if (onBlockStr && dutyStartTime !== null) {
                let m = parseTimeString(onBlockStr) - dutyStartTime;
                
                // Handle midnight crossing (e.g. Start 23:00, In 02:00)
                if (m < 0) m += 1440; 

                leg.fdp = minsToTime(m);
                leg.fdpAlert = (m > maxLimitMins);
            } else {
                leg.fdp = "";
                leg.fdpAlert = false;
            }
        });
    }

    // Recalculate both max FDPs
    if (typeof recalcMaxFDP === 'function') recalcMaxFDP();
    renderJourneyList();
    saveState();
};

// --- MODIFY LEG (Edit Data) ---
window.modifyLeg = function(index) {
    const leg = dailyLegs[index];
    if (!leg) return;

    // 1. Load data back into inputs
    Object.keys(leg).forEach(key => {
        const e = el(key);
        if (e) {
            if (e.tagName === 'INPUT' || e.tagName === 'SELECT') e.value = leg[key];
            else e.innerText = leg[key];
        }
    });

    // 2. Remove from list so "Add Leg" updates it instead of duplicating
    dailyLegs.splice(index, 1);
    
    renderJourneyList();
    
    // 3. Reset duty logic if we are editing the first leg
    if (index === 0) {
        // Clear the locked start time so the edited STD can generate a new one
        safeText('j-duty-start', '00:00'); 
        dutyStartTime = null; 
    }

    // SHOW THE FORM
    document.getElementById('leg-input-form').style.display = 'block';

    // Scroll to the form so the user sees it
    document.getElementById('leg-input-form').scrollIntoView({ behavior: 'smooth' });
    
    alert("Leg loaded. Make changes and click '+ Add Leg'.");
};

window.renderJourneyList = function() {
    const tb = el('journey-list-body');
    if(!tb) return;

    if(dailyLegs.length === 0) {
        tb.innerHTML = '<tr><td colspan="6" style="text-align:center; padding: 15px; color: #888;">No legs added.</td></tr>';
    } else {
        tb.innerHTML = dailyLegs.map((l, i) => {
            // Check if we can move Up or Down
            const canMoveUp = i > 0; 
            const canMoveDown = i < dailyLegs.length - 1;

            // Calculate display FDP correctly
            let displayFDP = l.fdp;
            if (i > 0) {
                // For legs after first: show sector time (previous on block to current on block)
                const prevLeg = dailyLegs[i-1];
                if (prevLeg['j-in'] && l['j-in']) {
                    displayFDP = getDiff(prevLeg['j-in'], l['j-in']);
                }
            }

            return `
            <tr>
                <td style="text-align:center; font-weight:bold;">${i+1}</td>
                <td>${l['j-flt']}</td>
                <td>${l['j-dep']} - ${l['j-dest']}</td>
                <td style="${l.fdpAlert ? 'color:red; font-weight:bold;' : ''}">${displayFDP || '-'}</td>
                <td style="${l.ccFdpAlert ? 'color:orange; font-weight:bold;' : ''}">${l['j-night'] || '00:00'}</td>
                
                <td style="white-space: nowrap; text-align: right;">
                    <button onclick="moveLeg(${i}, -1)" class="btn-icon" ${!canMoveUp ? 'disabled style="opacity:0.3"' : ''} title="Move Up">
                        ▲
                    </button>
                    
                    <button onclick="moveLeg(${i}, 1)" class="btn-icon" ${!canMoveDown ? 'disabled style="opacity:0.3"' : ''} title="Move Down">
                        ▼
                    </button>

                    <button onclick="modifyLeg(${i})" class="btn-action modify" style="margin-left: 8px;">
                        Edit
                    </button>
                    
                    <button onclick="removeLeg(${i})" class="btn-action delete" style="margin-left: 5px;">
                        Del
                    </button>
                </td>
            </tr>
            `;
        }).join('');
    }
};

    window.showTab = function(id, btn) {
    // 1. SAVE before leaving
    const activeSection = document.querySelector('.tool-section.active');
    if (activeSection && activeSection.id === 'section-confirm' && signaturePad) {
        if (!signaturePad.isEmpty()) {
            savedSignatureData = signaturePad.toDataURL(); 
        }
    }

    // Standard tab switching
    document.querySelectorAll('.tool-section').forEach(s => s.classList.remove('active'));
    document.querySelectorAll('.nav-btn').forEach(b => b.classList.remove('active'));
    if(el('section-'+id)) el('section-'+id).classList.add('active');
    if(btn) btn.classList.add('active');

    // 2. RESTORE when entering Confirm
    if(id === 'confirm') {
    validateInputs();
    
    setTimeout(() => {
        const canvas = el('sig-canvas');
        if (canvas) {
            const ratio = Math.max(window.devicePixelRatio || 1, 1);
            
            // 1. Capture current size
            const newWidth = canvas.offsetWidth;
            const newHeight = canvas.offsetHeight;

            // 2. Only perform resize logic if size is different to prevent shrinking loop
            if (canvas.width !== newWidth * ratio || canvas.height !== newHeight * ratio) {
                canvas.width = newWidth * ratio;
                canvas.height = newHeight * ratio;
                canvas.getContext("2d").scale(ratio, ratio);
                
                // If we resize, we MUST re-init the pad
                if (signaturePad) signaturePad.off(); // Kill old listeners
                signaturePad = new SignaturePad(canvas, {
                    backgroundColor: 'rgba(0,0,0,0)',
                    penColor: getComputedStyle(document.documentElement).getPropertyValue('--accent').trim()
                });
            }

            // 3. Initialize if first time
            if (!signaturePad) {
                signaturePad = new SignaturePad(canvas, {
                    backgroundColor: 'rgba(0,0,0,0)',
                    penColor: getComputedStyle(document.documentElement).getPropertyValue('--accent').trim()
                });
            }

            // 4. Restore Ink - USE 'fromData' instead of 'fromDataURL' if possible
            // but if using DataURL, this check prevents the shrinking feedback loop
            if (savedSignatureData) {
                signaturePad.fromDataURL(savedSignatureData, { ratio: ratio });
            }
        }
    }, 50);
}
};

// Helper: Calculates the values based on a specific leg's data
window.calculateDutyValues = function(std, flt, dep, dest) {
    if (!std) return { fc: "00:00", cc: "00:00", max: "00:00", ccMax: "00:00" };

    // 1. Identify Airline & Route
    const fltUpper = (flt || "").toUpperCase();
    const isKZR = fltUpper.includes('KZR') || fltUpper.includes('KC');
    const isAYN = fltUpper.includes('AYN') || fltUpper.includes('FS'); 
    
    const isDepUA = (dep || "").toUpperCase().startsWith('UA');
    const isDestUA = (dest || "").toUpperCase().startsWith('UA');

    // 2. FC Offset Logic
    let fcOffset = 60; // Default (International Return)
    if (isDepUA) { 
        if (isKZR) fcOffset = (!isDestUA) ? 90 : 75; // KZR: 90 Int'l, 75 Dom
        else if (isAYN) fcOffset = (!isDestUA) ? 75 : 60; // AYN: 75 Int'l, 60 Dom
    } 

    // 3. FC Start Time
    const stdMins = parseTimeString(std);
    let fcStartMins = stdMins - fcOffset;
    if (fcStartMins < 0) fcStartMins += 1440;

    // 4. CC Start Time
    let ccDiff = (isKZR) ? 15 : 0; // KZR CC reports 15m earlier
    let ccStartMins = fcStartMins - ccDiff;
    if (ccStartMins < 0) ccStartMins += 1440;

    // 5. Helper function to calculate max FDP based on start time (EASA TABLE)
    const calculateMaxFDP = (startMins, isCabinCrew = false) => {
        // CABIN CREW has different limits - 14 hours base instead of 13
        let baseMax = isCabinCrew ? 840 : 780; // 14:00 for CC, 13:00 for FC
        
        if (startMins >= 360 && startMins <= 809) baseMax = isCabinCrew ? 840 : 780; // 06:00-13:29
        else if (startMins >= 810 && startMins <= 839) baseMax = isCabinCrew ? 825 : 765;
        else if (startMins >= 840 && startMins <= 869) baseMax = isCabinCrew ? 810 : 750;
        else if (startMins >= 870 && startMins <= 899) baseMax = isCabinCrew ? 795 : 735;
        else if (startMins >= 900 && startMins <= 929) baseMax = isCabinCrew ? 780 : 720;
        else if (startMins >= 930 && startMins <= 959) baseMax = isCabinCrew ? 765 : 705;
        else if (startMins >= 960 && startMins <= 989) baseMax = isCabinCrew ? 750 : 690;
        else if (startMins >= 990 && startMins <= 1019) baseMax = isCabinCrew ? 735 : 675;
        else if (startMins >= 1020 || startMins <= 299) baseMax = isCabinCrew ? 660 : 660; // Both 11:00 for night
        else if (startMins >= 300 && startMins <= 314) baseMax = isCabinCrew ? 720 : 720; // 05:00-05:14
        else if (startMins >= 315 && startMins <= 329) baseMax = isCabinCrew ? 735 : 735; // 05:15-05:29
        else if (startMins >= 330 && startMins <= 344) baseMax = isCabinCrew ? 750 : 750; // 05:30-05:44
        else if (startMins >= 345 && startMins <= 359) baseMax = isCabinCrew ? 765 : 765; // 05:45-05:59

        return baseMax;
    };

    // 6. Calculate max FDP for both FC and CC (without sector reductions)
    const fcMaxFDP = calculateMaxFDP(fcStartMins, false);
    const ccMaxFDP = calculateMaxFDP(ccStartMins, true);

    return {
        fc: minsToTime(fcStartMins),
        cc: minsToTime(ccStartMins),
        max: minsToTime(fcMaxFDP),     // Flight Crew max FDP (base)
        ccMax: minsToTime(ccMaxFDP)    // Cabin Crew max FDP (base)
    };
};


window.initializeDutyCalculations = function() {
    // Recalculate everything when app loads or leg is added
    if (dailyLegs.length > 0) {
        const firstLeg = dailyLegs[0];
        if (firstLeg['j-std']) {
            calcDutyLogic();
            recalcMaxFDP();
        }
    }
};

// ==========================================
// 8. PDF GENERATION (JOURNEY LOG)
// ==========================================
window.downloadJourneyLog = async function(mode = 'download') {
    if (!journeyLogTemplateBytes) return alert("Please upload Journey Log first.");
    if (dailyLegs.length === 0) return alert("No legs to print.");

    console.log("=== DEBUG: Starting downloadJourneyLog ===");
    console.log("fcMaxFDPStr from j-max-fdp:", el('j-max-fdp')?.value);
    console.log("ccMaxFDPStr from hidden input:", document.getElementById('j-cc-max-fdp-hidden')?.value);
    console.log("fcDutyStartStr:", el('j-duty-start')?.value);
    console.log("ccDutyStartStr:", el('j-cc-duty-start')?.value);
    console.log("dailyLegs length:", dailyLegs.length);

    try {
        const pdfDoc = await PDFLib.PDFDocument.load(journeyLogTemplateBytes);
        const page = pdfDoc.getPages()[0];
        const font = await pdfDoc.embedFont(PDFLib.StandardFonts.HelveticaBold);
        
        // Check for iPad mode rotation
        const isIpadMode = el('chk-ipad-mode') ? el('chk-ipad-mode').checked : false;
        if(!isIpadMode) page.setRotation(PDFLib.degrees(0));

        // --- 1. HEADERS & LEG DATA ---

        const { width, height } = page.getSize();

        page.drawText("75/125", { 
            x: width - 280, 
            y: height - 40, 
            size: 10,
            font: font, 
            color: PDFLib.rgb(0,0,0) 
        });

        const headers = JOURNEY_CONFIG.headers;
        Object.keys(headers).forEach(id => {
            const val = el(id)?.value;
            const cfg = headers[id];
            if(val && cfg) page.drawText(String(val).toUpperCase(), { x: cfg.x, y: cfg.y, size: JOURNEY_CONFIG.fontSize, font: font, color: PDFLib.rgb(0,0,0) });
        });

        const cols = JOURNEY_CONFIG.cols;
        const fuelKeys = JOURNEY_CONFIG.fuelKeys;
        
        dailyLegs.forEach((leg, idx) => {
            Object.keys(leg).forEach(key => {
                const colX = cols[key];
                if(colX) {
                    let startRow = JOURNEY_CONFIG.rowStartMain;
                    if (fuelKeys.includes(key)) startRow = JOURNEY_CONFIG.rowStartFuel;
                    const rowY = startRow - (idx * JOURNEY_CONFIG.rowGap);
                    const val = leg[key];
                    if(val !== undefined && val !== null && val !== "") {
                        page.drawText(String(val).toUpperCase(), { x: colX, y: rowY, size: JOURNEY_CONFIG.fontSize, font: font, color: PDFLib.rgb(0,0,0) });
                    }
                }
            });
        });

        // --- 2. SIGNATURE DRAWING SECTION ---
        if (signaturePad && !signaturePad.isEmpty()) {
            try {
                const sigImageBase64 = signaturePad.toDataURL();
                const sigImage = await pdfDoc.embedPng(sigImageBase64);
                
                page.drawImage(sigImage, {
                    x: 570,        
                    y: 120,        
                    width: 200,    
                    height: 50,    
                });
            } catch (sigError) {
                console.error("Signature Embedding Error:", sigError);
            }
        }

        // --- 3. CREW DUTY DATA (CORRECTED) ---
        const crewStart = 333; 
        const crewGap = 17;    
        
        const numFC = parseInt(el('j-fc-count')?.value || 2);
        const numCC = parseInt(el('j-cc-count')?.value || 4);
        const totalRows = numFC + numCC;

        // Get duty start times
        const fcDutyStartStr = el('j-duty-start')?.value || "00:00";
        const ccDutyStartStr = el('j-cc-duty-start')?.value || "00:00";
        
        // Get max FDP values - FIXED VARIABLE NAMES
        const fcMaxFDPStr = el('j-max-fdp')?.value || "00:00"; 
        
        // Get cabin crew max FDP from hidden input
        const ccMaxFDPInput = document.getElementById('j-cc-max-fdp-hidden');
        const ccMaxFDPStr = ccMaxFDPInput ? ccMaxFDPInput.value : "00:00";

        // Convert strings to minutes for math
        const fcStartMins = parseTimeString(fcDutyStartStr);
        const ccStartMins = parseTimeString(ccDutyStartStr);

        // Get End Time from the LAST leg to calculate Duty Duration
        const lastLeg = dailyLegs[dailyLegs.length - 1];
        const onBlocksMins = lastLeg ? parseTimeString(lastLeg['j-in']) : 0;

        // HELPER: Calculate FDP Duration
        const getFDP = (startMins) => {
            if(!onBlocksMins && onBlocksMins !== 0) return ""; 
            let diff = onBlocksMins - startMins;
            
            // Handle midnight crossing properly
            if (diff < 0) diff += 1440; 
            
            // If duty spans more than 24 hours (unlikely but handle)
            if (diff > 1440) diff = diff % 1440;
            
            return minsToTime(diff);
        };

        // HELPER: Calculate Night Overlap
        const getNightOverlap = (startMins) => {
            if(!onBlocksMins && onBlocksMins !== 0) return "00:00"; 
            
            // Night window: 21:00-05:59 UTC (1260 to 1439 and 0 to 359)
            const nightStart1 = 1260; // 21:00
            const nightEnd1 = 1439;   // 23:59
            const nightStart2 = 0;    // 00:00
            const nightEnd2 = 359;    // 05:59
            
            let overlap = 0;
            
            // Check first night window
            if (startMins <= nightEnd1) {
                const startInWindow = Math.max(startMins, nightStart1);
                const endInWindow = Math.min(onBlocksMins, nightEnd1);
                if (endInWindow > startInWindow) {
                    overlap += (endInWindow - startInWindow);
                }
            }
            
            // Check second night window (next day)
            if (onBlocksMins >= nightStart2) {
                const startInWindow = Math.max(startMins, nightStart2 - 1440);
                const endInWindow = Math.min(onBlocksMins, nightEnd2);
                if (endInWindow > startInWindow) {
                    overlap += (endInWindow - startInWindow);
                }
            }
            
            // Handle case where duty spans multiple days (very rare)
            if (overlap < 0) overlap = 0;
            
            return minsToTime(overlap);
        };

        // DRAW ROWS
        for(let i = 0; i < totalRows; i++) {
            const y = crewStart - (i * crewGap);
            const isFlightCrew = (i < numFC);
            
            // Select Start Time based on role
            const myStart = isFlightCrew ? fcStartMins : ccStartMins;
            const myMaxFDP = isFlightCrew ? fcMaxFDPStr : ccMaxFDPStr;
            
            // Calculate Duration & Night based on that start time
            const myFDP = getFDP(myStart);
            const myNight = getNightOverlap(myStart);

            // 1. OP (Always)
            if(cols['j-duty-operating']) 
                page.drawText("OP", { x: cols['j-duty-operating'], y: y, size: JOURNEY_CONFIG.fontSize, font: font, color: PDFLib.rgb(0,0,0) });

            // 2. Duty Time (Duration)
            if(myFDP && cols['j-duty-time']) 
                page.drawText(myFDP, { x: cols['j-duty-time'], y: y, size: JOURNEY_CONFIG.fontSize, font: font, color: PDFLib.rgb(0,0,0) });

            // 3. Night Duty
            if(myNight !== null && myNight !== undefined && cols['j-duty-night']) {
                page.drawText(myNight, { x: cols['j-duty-night'], y: y, size: JOURNEY_CONFIG.fontSize, font: font, color: PDFLib.rgb(0,0,0) });
            }

            // 4. Allowed FDP (READ FROM CORRECT VARIABLE)
            if(myMaxFDP && cols['j-duty-allowed']) 
                page.drawText(myMaxFDP, { x: cols['j-duty-allowed'], y: y, size: JOURNEY_CONFIG.fontSize, font: font, color: PDFLib.rgb(0,0,0) });
        }

        // --- 4. SAVE & DOWNLOAD ---
        const out = await pdfDoc.save();
        const flt = (el('j-flt')?.value || "FLT").replace(/\s+/g, '');
        const filename = `JOURNEY_LOG_${flt}.pdf`;
        
        const isMobile = /iPhone|iPad|iPod|Android/i.test(navigator.userAgent) || 
                         (navigator.maxTouchPoints && navigator.maxTouchPoints > 2);

        if (mode === 'email' && isMobile) {
            const subject = `Journey Log: ${flt}`;
            await sharePdf(out, filename, subject, "Journey Log attached.");
        } else {
            downloadBlob(out, filename);
        }

    } catch(e) { 
        console.error("Journey Log Generation Error:", e); 
        console.error("Error stack:", e.stack);
        alert("Error generating Log: " + e.message); 
    }
};

    function downloadBlob(bytes, name) {
        const link = document.createElement('a');
        link.href = URL.createObjectURL(new Blob([bytes], {type:'application/pdf'}));
        link.download = name;
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
    }

window.detectReportOffset = function() {
    // Helper to get value from input OR text from span
    const getVal = (id) => {
        const e = el(id);
        if (!e) return "";
        return (e.value || e.innerText || "").trim();
    };

    const flt = getVal('j-flt');
    const dep = getVal('j-dep');
    const dest = getVal('j-dest');
    
    if (!flt || !dep) return 90; 

    if (flt.startsWith("AYN")) return 60;

    const depIsKZ = dep.startsWith("UA");
    if (!depIsKZ) {
        return 60; // International Return
    } else {
        const destIsKZ = dest.startsWith("UA");
        return destIsKZ ? 75 : 90; // Domestic : International Outbound
    }
    };

async function sharePdf(pdfBytes, filename, subject, body) {
    // 1. Create a "File" object from the PDF bytes
    const blob = new Blob([pdfBytes], { type: 'application/pdf' });
    const file = new File([blob], filename, { type: 'application/pdf' });

    // 2. Copy the target email to clipboard automatically
    try {
        await navigator.clipboard.writeText("ofp@airastana.com");
    } catch (err) {
        console.log("Clipboard write failed", err);
    }

    // 3. Check if the device supports native file sharing (iPad/iPhone do)
    if (navigator.canShare && navigator.canShare({ files: [file] })) {
        try {
            await navigator.share({
                files: [file],
                title: subject,
                text: body || subject
            });
        } catch (err) {
            console.log("Share cancelled or failed", err);
        }
    } else {
        // Fallback for computers (just download it)
        downloadBlob(pdfBytes, filename);
    }
    }

    window.resetApp = async function() {
    if(confirm("Start new flight? This will clear all saved data.")) {
        localStorage.removeItem('efb_log_state');
        await clearPdfDB();
        location.reload(); 
    }
    };

    
    window.triggerEmailOnly = function() { 
        // Get the values from the hidden inputs or summary fields
        const flt = document.getElementById('j-flt')?.value || "";
        const date = document.getElementById('j-date')?.value || "";
        const subject = `OFP: ${flt} ${date}`;
        
        // Open the mail client with the subject pre-filled
        window.location.href = `mailto:ops@airastana.com?subject=${encodeURIComponent(subject)}`; 
    };
    
    document.addEventListener('DOMContentLoaded', () => {
    const dropZone = document.getElementById('upload-btn');
    const fileInput = document.getElementById('ofp-file-in');

    // 1. Drag Enter/Over (Highlight)
    ['dragenter', 'dragover'].forEach(eventName => {
        dropZone.addEventListener(eventName, (e) => {
            e.preventDefault();
            e.stopPropagation();
            dropZone.classList.add('drag-over');
            dropZone.innerText = "⬇️ Drop PDF Here";
        }, false);
    });

    // 2. Drag Leave (Remove Highlight)
    ['dragleave', 'drop'].forEach(eventName => {
        dropZone.addEventListener(eventName, (e) => {
            e.preventDefault();
            e.stopPropagation();
            dropZone.classList.remove('drag-over');
            dropZone.innerHTML = "📁 Upload OFP"; // Reset text
        }, false);
    });

    // 3. Drop (Process File)
    dropZone.addEventListener('drop', (e) => {
        const dt = e.dataTransfer;
        const files = dt.files;

        if (files.length > 0) {
            // Assign the dropped file to the hidden input
            fileInput.files = files;
            // Manually trigger the analysis function
            runAnalysis(); 
        }
    }, false);
    });

    // ==========================================
    // 9. LOCAL STORAGE (AUTO-SAVE)
    // ==========================================

    // A list of simple input IDs we want to save automatically
    const SAVE_IDS = [
        'j-flt', 'j-reg', 'j-date', 'j-dep', 'j-dest', 'j-altn', 'j-std','front-extra-kg',
        'j-out', 'j-off', 'j-on', 'j-in', 'j-night', 'j-night-calc',
        'j-to', 'j-ldg', 'j-ldg-type', 'j-flt-alt', 'j-ldg-detail',
        'j-init', 'j-uplift-w', 'j-uplift-vol', 'j-act-ramp', 'j-shut', 'j-slip', 'j-slip-2',
        'j-adl', 'j-chl', 'j-inf', 'j-bag', 'j-cargo', 'j-mail', 'j-zfw',
        'j-report-type', 'j-fc-count', 'j-cc-count', 'front-extra-reason',
        'front-atis', 'front-atc', 'front-altm1', 'front-stby', 'front-altm2', 'view-pic-block',
    ];

    function saveState() {
    // 1. Capture the "User Inputs" (Actuals, Notes, AGL) from the DOM
    const userInputs = waypoints.map((wp, i) => ({
        ato: el(`o-a-${i}`)?.value || "",
        fuel: el(`o-f-${i}`)?.value || "",
        notes: el(`o-n-${i}`)?.value || "",
        agl: el(`o-agl-${i}`)?.value || ""
    }));

    let savedTaxi = 200;
    if (typeof fuelData !== 'undefined') {
        const t = fuelData.find(x => x.name === 'TAXI');
        if(t) savedTaxi = t.fuel;
    }

    const state = {
        inputs: {},
        dailyLegs: dailyLegs, 
        dutyStartTime: dutyStartTime,
        savedTaxiValue: savedTaxi,
        routeStructure: waypoints, 
        waypointUserValues: userInputs 
    };

    // 2. Save simple inputs
    SAVE_IDS.forEach(id => {
        const e = el(id);
        if(e) state.inputs[id] = e.value;
    });

    localStorage.setItem('efb_log_state', JSON.stringify(state));
    console.log("Auto-saved");
}

function loadState() {
    const raw = localStorage.getItem('efb_log_state');
    if(!raw) return; 

    try {
        const state = JSON.parse(raw);
        
        // 1. Restore Route Structure (The backbone)
        if(state.routeStructure && Array.isArray(state.routeStructure) && state.routeStructure.length > 0) {
            waypoints = state.routeStructure;
            
            // A. Draw the empty table first
            if (typeof renderTables === 'function') {
                renderTables(); 
            }
            
            // B. Restore Waypoint Inputs (ATO, Fuel, Notes) into the table
            // This MUST happen before runCalc()
            if(state.waypointUserValues && Array.isArray(state.waypointUserValues)) {
                state.waypointUserValues.forEach((data, i) => {
                    if (i < waypoints.length) {
                        if(data.ato) safeSet(`o-a-${i}`, data.ato);
                        if(data.fuel) safeSet(`o-f-${i}`, data.fuel);
                        if(data.notes) safeSet(`o-n-${i}`, data.notes);
                        if(data.agl) safeSet(`o-agl-${i}`, data.agl);
                    }
                });
            }
        }

        // 2. Restore Simple Inputs (Includes ATD 'ofp-atd-in')
        if(state.inputs) {
            Object.keys(state.inputs).forEach(id => {
                const val = state.inputs[id];
                if (val !== "" && val !== null) safeSet(id, val);
            });
        }
        
        // 3. Restore Daily Legs (Journey Log)
        if(state.dailyLegs && Array.isArray(state.dailyLegs)) {
            dailyLegs = state.dailyLegs;
            renderJourneyList(); 
        }

        // 4. Restore Taxi Fuel (To prevent jump to 200)
        if (state.savedTaxiValue) {
            if (typeof fuelData === 'undefined') fuelData = [];
            if (!fuelData.find(x => x.name === 'TAXI')) {
                fuelData.push({ name: "TAXI", fuel: state.savedTaxiValue });
            }
        }

        // 5. Restore Duty Start
        if(state.dutyStartTime !== undefined) {
            dutyStartTime = state.dutyStartTime;
            calcDutyLogic(); 
        }

        // 6. FINALLY: Run Calculations
        // Now that ATD is restored (Step 2) AND ATOs are restored (Step 1B),
        // runCalc will see the data and generate the ETOs correctly.
        runCalc();
        updateFuelMonitor();
        if (typeof syncLastWaypoint === 'function') syncLastWaypoint();

        validateInputs();

    } catch(e) { console.error("Load error", e); }
}

    // Trigger Save on any input change
    window.addEventListener('input', (e) => {
        // Debounce simple inputs (wait 500ms before saving to save performance)
        if(window.saveTimeout) clearTimeout(window.saveTimeout);
        window.saveTimeout = setTimeout(saveState, 500);
    });

    // ==========================================
    // 10. PDF STORAGE (IndexedDB)
    // ==========================================
    
    // Open the Database
    function openDB() {
        return new Promise((resolve, reject) => {
            const request = indexedDB.open("EFB_PDF_DB", 1);
            request.onupgradeneeded = function(e) {
                const db = e.target.result;
                if (!db.objectStoreNames.contains("files")) {
                    db.createObjectStore("files");
                }
            };
            request.onsuccess = e => resolve(e.target.result);
            request.onerror = e => reject(e);
        });
    }

    // Save PDF Blob
    async function savePdfToDB(fileBlob) {
        const db = await openDB();
        const tx = db.transaction("files", "readwrite");
        tx.objectStore("files").put(fileBlob, "currentOFP");
    }

    // Load PDF Blob
    async function loadPdfFromDB() {
        const db = await openDB();
        return new Promise((resolve, reject) => {
            const tx = db.transaction("files", "readonly");
            const req = tx.objectStore("files").get("currentOFP");
            req.onsuccess = () => resolve(req.result);
            req.onerror = () => resolve(null);
        });
    }

    // Delete PDF (for Reset)
    async function clearPdfDB() {
        const db = await openDB();
        const tx = db.transaction("files", "readwrite");
        tx.objectStore("files").delete("currentOFP");
    }

    window.addEventListener('load', function() {
    setTimeout(() => {
        const verEl = document.getElementById('app-version-display');
        if (verEl && typeof APP_VERSION !== 'undefined') {
            verEl.innerText = `v${APP_VERSION}`;
            verEl.style.color = '#007aff'; // Turn blue so we know JS touched it
        }
    }, 500); // Wait 0.5s just to be sure

    window.addEventListener('load', function() {
        setTimeout(() => {
            const verEl = document.getElementById('app-version-display');
            if (verEl) {
                // Check if APP_VERSION is defined
                if (typeof APP_VERSION !== 'undefined') {
                    verEl.innerText = `v${APP_VERSION}`;
                    verEl.style.color = '#007aff'; 
                } else {
                    // If offline/error and variable is missing
                    verEl.innerText = " (Offline)";
                    verEl.style.color = '#8e8e93';
                }
            }
        }, 500);
    });
});
})();