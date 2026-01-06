(function() {
    // ==========================================
    // 1. CONFIGURATION
    // ==========================================
    
    // --- JOURNEY LOG PDF MAPPING ---
    const JOURNEY_CONFIG = {
        fontSize: 10,
        
        // Vertical positioning for the leg list
        rowStartMain: 525, 
        rowStartFuel: 420,
        rowStartCrew: 350, 
        rowGap: 17, 
        
        // Signature Position
        sig: { x: 570, y: 120, width: 200, height: 50 },


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


    
    let frontCoords = { 
        atis: null, atcLabel: null, altm1: null, stby: null, altm2: null, picBlockLabel: null 
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

window.addEventListener('resize', function() {
    if (signaturePad) {
        const canvas = document.getElementById('sig-canvas');
        canvas.width = canvas.offsetWidth;
        signaturePad.clear(); // Clearing redraws with new dimensions
    }
});

// Make functions available globally if needed
window.clearSignature = clearSignature;
window.getSignatureDataURL = getSignatureDataURL;

    // --- VALIDATION HELPERS ---
    window.validateAltimeter = function(el) {
        // Allow only 4 digits
        el.value = el.value.replace(/[^0-9]/g, '').substring(0, 4);
        validateInputs(); // Re-check the "Confirm" tab status
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
    // (blockFuelValue is the global variable set when parsing the PDF)
    if (typeof blockFuelValue === 'undefined' || blockFuelValue === 0) return;

    const picTotal = parseInt(totalInput.value) || 0;
    
    // Calculation: Extra = User Total - OFP Block
    let diff = picTotal - blockFuelValue;
    
    // Optional: Don't allow negative extra (unless you want to undercut block fuel)
    if (diff < 0) diff = 0;

    extraInput.value = diff;
    
    // --- NEW: Update the Flight Log Table immediately ---
    runCalc();       // Re-run the fuel math for all waypoints
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
                // If found, run analysis on the blob. 
                // NOTE: runAnalysis() now calls loadState() internally at the end.
                await runAnalysis(savedPdf); 
            } else {
                // 2. If no PDF, just load the text inputs from LocalStorage
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
async function runAnalysis(fileOrEvent) {
    let blob = null;
    let isAutoLoad = false;

    if (fileOrEvent instanceof Blob) {
        // Auto-load on startup
        blob = fileOrEvent;
        isAutoLoad = true; 
    } else {
        // Manual Upload via Button
        const fileInput = el('ofp-file-in');
        if (fileInput && fileInput.files.length > 0) {
            blob = fileInput.files[0];
            savePdfToDB(blob); 
            
            // --- SMART RESET LOGIC ---
            // We want to clear old OFP inputs but KEEP the Journey Log legs.
            
            // 1. Read current saved data
            let stored = {};
            try { stored = JSON.parse(localStorage.getItem('efb_log_state')) || {}; } catch(e){}
            
            // 2. Wipe ONLY the OFP inputs and Waypoints
            stored.inputs = {}; 
            stored.waypoints = [];
            // NOTE: We do NOT touch 'stored.dailyLegs'. They are safe!
            
            // 3. Save the cleaned state back to storage
            localStorage.setItem('efb_log_state', JSON.stringify(stored));
            
            // 4. Clear the memory variable so old data doesn't ghost in
            window.savedWaypointData = [];
        }
    }

    if (!blob) return;

    // Only clear visual inputs if it's a MANUAL upload
    if (!isAutoLoad) {
        clearOFPInputs();
    }

    // 3. Process the file
    originalFileName = blob.name || "Logged_OFP.pdf";
    ofpPdfBytes = await blob.arrayBuffer();

    const pdf = await pdfjsLib.getDocument(ofpPdfBytes).promise;
        
        // --- NEW: RENDER PDF FOR IPAD (Canvas Method) ---
        const container = document.getElementById('pdf-render-container');
        const fallback = document.getElementById('pdf-fallback');
        
        if (container && pdf) {
            // Hide fallback
            if(fallback) fallback.style.display = 'none';
            
            // Clear any old pages
            container.innerHTML = '';

            // Loop through ALL pages
            for (let pageNum = 1; pageNum <= pdf.numPages; pageNum++) {
                try {
                    const page = await pdf.getPage(pageNum);
                    
                    // Scale 1.5 makes it crisp on Retina screens
                    const scale = 1.5;
                    const viewport = page.getViewport({ scale });

                    // Create a canvas for this page
                    const canvas = document.createElement('canvas');
                    const context = canvas.getContext('2d');
                    canvas.height = viewport.height;
                    canvas.width = viewport.width;
                    
                    // Style it to fit the screen width
                    canvas.style.width = '100%'; 
                    canvas.style.height = 'auto';
                    canvas.style.maxWidth = '800px'; // Prevent it from getting too huge
                    canvas.style.marginBottom = '20px';
                    canvas.style.boxShadow = '0 4px 10px rgba(0,0,0,0.5)'; // Nice shadow
                    
                    container.appendChild(canvas);

                    // Render the page
                    await page.render({
                        canvasContext: context,
                        viewport: viewport
                    }).promise;
                    
                } catch (err) {
                    console.error("Error rendering page " + pageNum, err);
                }
            }
        }

        waypoints = []; alternateWaypoints = []; fuelData = []; blockFuelValue = 0;
        
        function extractFrontCoords(items) {
            items.forEach(item => {
                const raw = item.str.toUpperCase();
                const t = raw.trim();
                if (t.includes('ATIS')) frontCoords.atis = item;
                if (t.includes('CLRNC')) frontCoords.atcLabel = item;
                if (t.includes('ALT M1') || (t.includes('ALT') && t.includes('1'))) frontCoords.altm1 = item;
                if (t.includes('STBY')) frontCoords.stby = item;
                if (t.includes('ALT M2') || (t.includes('ALT') && t.includes('2'))) frontCoords.altm2 = item;
                if (t.includes('PIC') && t.includes('BLOCK')) frontCoords.picBlockLabel = item;
                if (t.includes('REASON')) frontCoords.reasonLabel = item;
            });
        }
        
        for (let i = 1; i <= pdf.numPages; i++) {
            const page = await pdf.getPage(i);
            const content = await page.getTextContent();
            const items = content.items;

            if (i === 1) {
                extractFrontCoords(items);
                const textContent = items.map(x=>x.str).join(' ');
                
                // --- FIXED REGEX FOR STA ---
                // Replaced strict \d{4} with \S+ (non-whitespace) for block times
                // This handles cases like "05:30" or "----" between the times
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

                    if (dailyLegs.length === 0) {
                        safeSet('j-std', stdFmt)
                        calcDutyLogic();
                    }
                    
                    calcDutyLogic();
                    extractRoutes(textContent);
                    extractFuelDataSimple(textContent);
                    extractWeights(textContent);
                }
            }
            
            if (i >= 2) {
                const rows = buildRows(items);
                rows.sort((a,b) => b.y - a.y); 
                
                let headerY = null;
                for(const row of rows) {
                    const rowText = row.items.map(item => item.str).join(' ');
                    let headerCount = 0;
                    if(rowText.includes("TO") || rowText.includes("TO:")) headerCount++;
                    if(rowText.includes("AWY") || rowText.includes("AWY:")) headerCount++;
                    if(rowText.includes("ET") || rowText.includes("ETE")) headerCount++;
                    if(rowText.includes("FUEL") || rowText.includes("FOB")) headerCount++;
                    if(headerCount >= 2) { headerY = row.y; break; }
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
                            if(num >= 100 && num <= 50000) {
                                const ctx = row.items.map(i=>i.str).join(' ');
                                if(!ctx.includes('FL ') && !/^\s*\d{3}\s*$/.test(str)) fuelValue = str;
                            }
                        }
                    }
                    
                    if(timeValue && fuelValue) {
                        let data = { name: "?", awy: "-", level: "-", track: "-", wind: "-", tas: "-", gs: "-" };
                        
                        if(r > 0) {
                            const prevRow = rows[r-1];
                            if(Math.abs(row.y - prevRow.y) < 25) {
                                const fullString = prevRow.items.map(x => x.str).join(' ');
                                const parts = fullString.trim().split(/\s+/);
                                if (parts.length >= 7) {
                                    data.name = parts[0];
                                    data.awy = parts[1];
                                    data.level = parts[2];
                                    data.track = parts[3];
                                    data.wind = parts[4];
                                    data.tas = parts[5];
                                    data.gs = parts[6];
                                } else if (parts.length > 0) {
                                    data.name = parts[0];
                                }
                            }
                        }

                        if(data.name !== "?") {
                            const absTime = parseTimeString(timeValue);
                            const fobValue = parseInt(fuelValue) || 0;
                            const wpObj = {
                                ...data,
                                totalMins: absTime,
                                eto: "",
                                fob: fobValue,
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
        
        waypoints.forEach(wp => {
            // Your parser uses 'fob' to store the PDF value, 
            // so we save that into 'baseFuel' for our math.
            wp.baseFuel = parseInt(wp.fob) || 0; 
            wp.fuel = wp.baseFuel; // Set initial estimated fuel
        });

        processWaypointsList();
        
        // --- AUTO-FILL PIC BLOCK ---
        // Ensure the input field shows the OFP block fuel immediately
        if (el('view-pic-block')) {
            el('view-pic-block').value = blockFuelValue || 0;
        }

        runCalc(); 
        validateInputs();
        renderFuelTable();
        // calculatePICBlock(); // You can remove this if you deleted the function earlier
        renderTables();

        // RESTORE USER INPUTS (Keep the rest of your logic below)
        loadState();
        
        // Also re-apply the Waypoint Table data specifically
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
    }

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

window.runCalc = function() {
    const atd = el('ofp-atd-in')?.value;
    
    // 1. Find the LATEST ATO (Actual Time Over) entered by the pilot
    let lastAtoMins = -1;
    let lastAtoIndex = -1;

    for (let i = waypoints.length - 1; i >= 0; i--) {
        const atoInput = el(`o-a-${i}`);
        if (atoInput && atoInput.value) {
            const [h, m] = atoInput.value.split(':').map(Number);
            lastAtoMins = h * 60 + m;
            lastAtoIndex = i;
            break; // We found the most recent actual time
        }
    }

    // 2. Determine Baseline & Start Fuel (Your existing fuel logic)
    const pdfTakeoffFuel = waypoints[0] ? (waypoints[0].baseFuel || parseInt(waypoints[0].fob)) : 0;
    let startFuelInput = el('o-f-0');
    let currentStartFuel = (startFuelInput && startFuelInput.value) 
        ? parseInt(startFuelInput.value) 
        : (parseInt(el('view-pic-block')?.value) || blockFuelValue || 0) - 200;
    const delta = currentStartFuel - pdfTakeoffFuel;

    // 3. Update Waypoints Loop
    waypoints.forEach((wp, index) => {
        // --- FUEL CALC ---
        if (wp.baseFuel === undefined) wp.baseFuel = parseInt(wp.fob) || 0;
        if (wp.baseFuel > 0) wp.fuel = wp.baseFuel + delta;

        // --- TIME CALC (The Ripple Fix) ---
        if (index === 0 && wp.name === "TAKEOFF") {
            wp.eto = atd ? atd.replace(':', '') : "";
        } 
        else if (lastAtoIndex !== -1 && index > lastAtoIndex) {
            // If we are AFTER the latest actual waypoint, calculate ETO based on that ATO
            // New ETO = Latest ATO + (This WP Planned Leg Time - Latest WP Planned Leg Time)
            const minutesFromLatest = wp.totalMins - waypoints[lastAtoIndex].totalMins;
            const newEtoMins = lastAtoMins + minutesFromLatest;
            
            const h = Math.floor((newEtoMins / 60) % 24).toString().padStart(2, '0');
            const m = Math.floor(newEtoMins % 60).toString().padStart(2, '0');
            wp.eto = h + m;
        } 
        else {
            // Default: Calculate from Original ATD (Standard OFP profile)
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
    updateFuelMonitor(); // This will now compare the NEW Destination ETO vs STA
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

    // 3. Update the Journey Log Summary
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
    // --- 1. HELPER: Auto-Detect Report Time ---
    window.detectReportOffset = function() {
        const flt = el('j-flt')?.value || "";
        const dep = el('j-dep')?.value || "";
        const dest = el('j-dest')?.value || "";
        
        if (!flt || !dep) return 90; // Default fallback

        // 1. FlyArystan (AYN) -> Always 60
        if (flt.startsWith("AYN")) return 60;

        // 2. Air Astana (KZR)
        const depIsKZ = dep.startsWith("UA");
        
        if (!depIsKZ) {
            // Dep is NOT KZ (e.g. EGLL) -> Int'l Return -> 60
            return 60; 
        } else {
            // Dep IS KZ (e.g. UAAA) -> Check Dest
            const destIsKZ = dest.startsWith("UA");
            if (destIsKZ) {
                // Dest IS KZ -> Domestic -> 75
                return 75;
            } else {
                // Dest NOT KZ -> Int'l Outbound -> 90
                return 90;
            }
        }
    };

    // --- 2. MAIN LOGIC: Duty & Night Calc ---
    window.calcDutyLogic = function() {
    const stdSources = ['j-std', 'view-std-text', 'ofp-std-in'];
    let stdStr = "";

    for (let id of stdSources) {
        const element = el(id);
        if (element) {
            // Priority: .value (input), then .innerText (span/div), then .textContent
            let val = (element.value || element.innerText || element.textContent || "").trim();
            // Basic check to ensure it looks like a time (HH:MM or HHMM)
            if (val && val !== "-" && val !== "----" && /\d/.test(val)) {
                stdStr = val;
                break; 
            }
        }
    }

    if (!stdStr) {
        return; 
    }

    // Update global variable for addLeg validation
    // Ensure this matches the time string exactly
    const stdMinsForVariable = parseTimeString(stdStr);

    // 2. Handle Reporting Type Selection
    // We force a refresh of the detection logic here
    const detectedOffset = detectReportOffset();
    const select = el('j-report-type');
    
    // Only auto-change if user hasn't manually selected something else 
    // or if we are during the initial OFP load
    if(select && dailyLegs.length === 0) {
        select.value = detectedOffset;
    }

    const reportOffset = parseInt(select?.value || 90);
    
    // Get Sectors (Default to 2 if not found)
    const sectorsInput = el('j-sectors');
    const sectors = Math.max(dailyLegs.length + 1, 1);

    // ==========================================
    // 2. CALCULATE DUTY START (UTC)
    // ==========================================
    const stdMins = parseTimeString(stdStr);
    let startMins = stdMins - reportOffset;
    if(startMins < 0) startMins += 1440; // Normalize to 0-1439 UTC
    
    dutyStartTime = startMins; // <--- ADD THIS LINE TO FIX THE addLeg ERROR
    // Update UI for Start Times
    safeText('j-duty-start', minsToTime(startMins)); 
    
    let ccStart = startMins - (reportOffset === 60 ? 0 : 15);
    if(ccStart < 0) ccStart += 1440;
    safeText('j-cc-duty-start', minsToTime(ccStart));

    // ==========================================
    // 3. EASA MAX FDP CALCULATION (NEW!)
    // ==========================================
    
    // We need Local Time for the table lookup.
    // Your location (KZ) is UTC+5. 
    // If you fly elsewhere, this logic might need a 'Timezone' input, 
    // but for now we assume Base Time = UTC+5 as per previous context.
    
    let localStartMins = startMins + 300; // +5 hours in minutes
    if (localStartMins >= 1440) localStartMins -= 1440;

    // Convert minutes to HHMM integer for easy table lookup (e.g. 0630)
    const hh = Math.floor(localStartMins / 60);
    const mm = localStartMins % 60;
    const timeVal = (hh * 100) + mm;

    // The EASA Table Data
    // Format: [Start, End, Limit_1-2, Limit_3, Limit_4]
    // Note: 1700-0459 is handled as a catch-all else/if block
    const limits = [
        { s: 500,  e: 514,  v: ["12:00", "11:30", "11:00"] },
        { s: 515,  e: 529,  v: ["12:15", "11:45", "11:15"] },
        { s: 530,  e: 544,  v: ["12:30", "12:00", "11:30"] },
        { s: 545,  e: 559,  v: ["12:45", "12:15", "11:45"] },
        { s: 600,  e: 1329, v: ["13:00", "12:30", "12:00"] },
        { s: 1330, e: 1359, v: ["12:45", "12:15", "11:45"] },
        { s: 1400, e: 1429, v: ["12:30", "12:00", "11:30"] },
        { s: 1430, e: 1459, v: ["12:15", "11:45", "11:15"] },
        { s: 1500, e: 1529, v: ["12:00", "11:30", "11:00"] },
        { s: 1530, e: 1559, v: ["11:45", "11:15", "10:45"] },
        { s: 1600, e: 1629, v: ["11:30", "11:00", "10:30"] },
        { s: 1630, e: 1659, v: ["11:15", "10:45", "10:15"] }
    ];

    let maxFDP = "11:00"; // Default to the lowest night value (1700-0459) for 1-2 sectors

    // 1. Check the specific day ranges
    let found = false;
    for (let r of limits) {
        if (timeVal >= r.s && timeVal <= r.e) {
            // Index 0 = 1-2 sectors, 1 = 3 sectors, 2 = 4 sectors
            let idx = (sectors === 3) ? 1 : (sectors === 4) ? 2 : 0;
            maxFDP = r.v[idx];
            found = true;
            break;
        }
    }

    // 2. If not found, it falls into the 1700 - 0459 Night Block
    if (!found) {
        if (sectors === 3) maxFDP = "10:30";
        else if (sectors === 4) maxFDP = "10:00";
        else maxFDP = "11:00"; // 1-2 sectors
    }

    // Set the Max FDP Input
    safeSet('j-max-fdp', maxFDP);


    // ==========================================
    // 4. NIGHT DUTY CALCULATION (UTC 21:00-23:59)
    // ==========================================
    // Calculate Duty End (UTC) based on actual legs or default
    let lastInStr = el('j-in')?.value; 
    if (!lastInStr && dailyLegs.length > 0) {
        lastInStr = dailyLegs[dailyLegs.length - 1]['j-in'];
    }

    let endMins = startMins + 600; // Default 10h
    if (lastInStr) {
        const inMins = parseTimeString(lastInStr);
        // Linear logic: If In < Start, it's next day
        if (inMins < startMins) endMins = inMins + 1440;
        else endMins = inMins;
    }

    // Check overlap with 21:00-23:59 UTC (Day 1 and Day 2)
    const wStart = 1260; const wEnd = 1439;
    let overlap = 0;
    overlap += Math.max(0, Math.min(endMins, wEnd) - Math.max(startMins, wStart));
    overlap += Math.max(0, Math.min(endMins, wEnd + 1440) - Math.max(startMins, wStart + 1440));

    safeSet('j-night-calc', minsToTime(overlap));
};

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
        const fuelOK = (blockFuelValue > 0) && (extra !== "");
        
        const atd = el('ofp-atd-in')?.value;
        const flightLogOK = (waypoints.length > 0) && !!atd;
        
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

    function clearJourneyInputs() {
        // Clear Times
        ['j-out', 'j-off', 'j-on', 'j-in', 'j-night'].forEach(id => safeSet(id, ''));
        
        // Clear Counts and Selects
        ['j-to', 'j-ldg'].forEach(id => safeSet(id, ''));
        safeSet('j-ldg-type', '');
        safeSet('j-ldg-detail', '');
        
        // Clear Fuel/Load specific to that leg
        ['j-uplift-w', 'j-uplift-vol', 'j-init', 'j-act-ramp', 'j-shut', 'j-slip', 'j-slip-2', 'j-adl', 'j-chl', 'j-inf', 'j-bag', 'j-cargo', 'j-mail', 'j-zfw'].forEach(id => safeSet(id, ''));
        
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
        if(dailyLegs.length >= 4) return alert("Max 4 legs.");
        if(dailyLegs.length === 0 && !dutyStartTime) {
            // Try to calc it one more time just in case
            calcDutyLogic();
            if(!dutyStartTime) return alert("Please ensure STD is set in Summary to calculate Duty Start.");
        }
        
        // FDP Check
        const onBlock = el('j-in')?.value;
        let fdp = "", alertFdp = false;
        if(onBlock && dutyStartTime !== null) {
            let m = parseTimeString(onBlock) - dutyStartTime;
            if(m<0) m+=1440;
            fdp = minsToTime(m);
            const limit = parseTimeString(el('j-max-fdp')?.value||'13:00');
            if(m > limit) alertFdp = true;
        }

        const d = {};
        
        const getValue = (id) => {
            const e = el(id);
            if (!e) return "";
            return (e.tagName === 'INPUT' || e.tagName === 'SELECT' || e.tagName === 'TEXTAREA') 
                   ? e.value : e.innerText;
        };

        ['j-flt','j-reg','j-dep','j-dest','j-altn','j-out','j-off','j-on','j-in','j-block','j-flight', 'j-night', 'j-to', 'j-ldg', 'j-ldg-type', 'j-flt-alt', 'j-ldg-detail', 'j-init','j-uplift-w', 'j-calc-ramp', 'j-act-ramp','j-shut','j-burn', 'j-uplift-vol', 'j-slip', 'j-slip-2', 'j-disc','j-adl', 'j-chl', 'j-inf', 'j-cargo', 'j-mail', 'j-bag', 'j-zfw','j-date'].forEach(k => {
            d[k] = getValue(k);
        });

        d.fdp = fdp; d.fdpAlert = alertFdp;
        
        dailyLegs.push(d);
        renderJourneyList();
        validateInputs();

        calcDutyLogic(); // Recalculate night duty now that we have a new leg/end time

        // AUTO CLEAR & PRE-FILL NEXT LEG ---
        const previousDest = d['j-dest']; // Remember where we landed
        clearJourneyInputs();             // Clear inputs
        safeSet('j-dep', previousDest);   // Set Dep to previous Dest
        safeSet('j-dest', '');            // Clear Dest
    };

    window.removeLeg = function(i) {
        dailyLegs.splice(i,1);
        if(dailyLegs.length === 0) { 
            calcDutyLogic(); 
        }
        renderJourneyList(); 
        validateInputs();
        calcDutyLogic(); // Recalculate based on remaining legs
    };
    
    window.clearLegs = function() {
        if(confirm("Clear All Legs?")) { dailyLegs=[]; removeLeg(0); }
    };

    window.renderJourneyList = function() {
        const tb = el('journey-list-body');
        if(!tb) return;
        if(dailyLegs.length === 0) tb.innerHTML = '<tr><td colspan="5" style="text-align:center;">No legs added.</td></tr>';
        else tb.innerHTML = dailyLegs.map((l,i) => `<tr><td>${i+1}</td><td>${l['j-flt']}</td><td>${l['j-dep']}-${l['j-dest']}</td><td style="${l.fdpAlert?'color:red':''}">${l.fdp}</td><td><button onclick="removeLeg(${i})">Del</button></td></tr>`).join('');
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
                // Adjust canvas resolution to match its display size
                canvas.width = canvas.offsetWidth;
                canvas.height = canvas.offsetHeight;

                // Initialize or Re-initialize the pad
                if (!signaturePad) {
                    signaturePad = new SignaturePad(canvas, {
                        backgroundColor: 'rgba(255, 255, 255, 0)', // Transparent
                        penColor: getComputedStyle(document.documentElement).getPropertyValue('--accent').trim() || 'rgb(10, 132, 255)'
                    });
                }

                // If we have saved ink, put it back
                if (savedSignatureData) {
                    signaturePad.fromDataURL(savedSignatureData);
                }
            }
        }, 50);
    }
};


    window.toggleTheme = function() {
        const b = document.body;
        b.setAttribute('data-theme', b.getAttribute('data-theme') === 'light' ? 'dark' : 'light');
    };

    // ==========================================
    // 7. PDF GENERATION (OFP)
    // ==========================================
    window.runDownload = async function(mode = 'download') {
        if(!ofpPdfBytes) return;
        try {
            const pdf = await PDFLib.PDFDocument.load(ofpPdfBytes);
            const pages = pdf.getPages();
            const fontB = await pdf.embedFont(PDFLib.StandardFonts.HelveticaBold);
            const fontR = await pdf.embedFont(PDFLib.StandardFonts.Helvetica);

            // 1. Front Page (ATIS, Altimeter, PIC Block)
            const frontItems = [ 
                {id:'front-atis', offset:40, coord:frontCoords.atis}, 
                {id:'front-atc', offset:50, coord:frontCoords.atcLabel}
            ];
            frontItems.forEach(f => {
                const v = el(f.id)?.value;
                if(f.coord && v) pages[0].drawText(v.toUpperCase(), { x: f.coord.transform[4] + f.offset, y: f.coord.transform[5] + V_LIFT, size: 8, font: fontB });
            });

            // PIC Block
            const picBlockText = el('view-pic-block')?.innerText || "";
            if(frontCoords.picBlockLabel && picBlockText && picBlockText !== '-') {
                pages[0].drawText(picBlockText, { x: frontCoords.picBlockLabel.transform[4] + 65, y: frontCoords.picBlockLabel.transform[5] + V_LIFT, size: 9, font: fontB });
            }
            
            // Reason for Extra Fuel
            const reasonText = el('front-extra-reason')?.value || "";
            if(frontCoords.reasonLabel && reasonText) {
                // Draw 30px to the right of the "REASON" label
                pages[0].drawText(reasonText.toUpperCase(), { 
                    x: frontCoords.reasonLabel.transform[4] + 175, 
                    y: frontCoords.reasonLabel.transform[5] + V_LIFT, 
                    size: 9, 
                    font: fontB 
                });
            }

            // Altimeters
            ['altm1','stby','altm2'].forEach(k => {
                const v = el('front-'+k)?.value;
                if(frontCoords[k] && v) {
                    pages[0].drawText(v, { x: frontCoords[k].transform[4] + (k==='stby'?40:50), y: frontCoords[k].transform[5] + V_LIFT, size: 9, font: fontB });
                }
            });

            // 2. Waypoints
            const draw = (list, pre) => {
                list.forEach((wp, i) => {
                    if (wp.isTakeoff) return;
                    
                    const a = el(`${pre}-a-${i}`)?.value.replace(':','') || "";
                    const f = el(`${pre}-f-${i}`)?.value || "";
                    const n = el(`${pre}-n-${i}`)?.value || "";
                    // FIX: Define the variable 'agl' here by reading the input
                    const agl = el(`${pre}-agl-${i}`)?.value || ""; 
                    
                    if (wp.page >= 0 && wp.page < pages.length) {
                        const page = pages[wp.page];
                        const mainY = wp.y_anchor;

                        // ETO (Shifted UP)
                        if(wp.eto) page.drawText(wp.eto, { x: TIME_X, y: mainY + LINE_HEIGHT + V_LIFT, size: 9, font: fontB, color: PDFLib.rgb(0,0,0.5) });
                        // ATO (Main Row)
                        if(a) page.drawText(a, { x: ATO_X, y: mainY + V_LIFT, size: 9, font: fontR });
                        // Fuel (Main Row, Size 10)
                        if(f) page.drawText(f, { x: FOB_X, y: mainY - LINE_HEIGHT + V_LIFT, size: 10, font: fontB });
                        // Notes (Main Row, Size 10)
                        if(n) page.drawText(n.toUpperCase(), { x: NOTES_X, y: mainY - LINE_HEIGHT + V_LIFT, size: 10, font: fontB });
                        // Actual FL 
                        if(agl) page.drawText(agl, { x: 115, y: mainY - LINE_HEIGHT + V_LIFT, size: 10, font: fontB });
                    }
                });
            };
            
            draw(waypoints, 'o'); 
            draw(alternateWaypoints, 'a');

            const bytes = await pdf.save();
            const filename = originalFileName.replace(".pdf", "_Logged.pdf");

            if (mode === 'email') {
                const flt = el('j-flt')?.value || "FLT";
                const date = el('j-date')?.value || "DATE";
                const subject = `OFP: ${flt} ${date}`;
                
                await sharePdf(bytes, filename, subject, "Please find attached the OFP.");
            } else {
                downloadBlob(bytes, filename);
            }
            
        } catch (error) { console.error(error); alert("Error saving PDF: " + error.message); }
    };

    // ==========================================
    // 8. PDF GENERATION (JOURNEY LOG)
    // ==========================================
    window.downloadJourneyLog = async function(mode = 'download') {
        if (!journeyLogTemplateBytes) return alert("Please upload Journey Log first.");
        if (dailyLegs.length === 0) return alert("No legs to print.");

        try {
            const pdfDoc = await PDFLib.PDFDocument.load(journeyLogTemplateBytes);
            const page = pdfDoc.getPages()[0];
            const font = await pdfDoc.embedFont(PDFLib.StandardFonts.HelveticaBold);
            const isIpadMode = el('chk-ipad-mode') ? el('chk-ipad-mode').checked : false;
            if(!isIpadMode) page.setRotation(PDFLib.degrees(0));

            // --- HEADERS & LEG DATA (Same as before) ---
            const headers = JOURNEY_CONFIG.headers;
            Object.keys(headers).forEach(id => {
                const val = el(id)?.value;
                const cfg = headers[id];
                if(val && cfg) page.drawText(String(val).toUpperCase(), { x: cfg.x, y: cfg.y, size: JOURNEY_CONFIG.fontSize, font: font, color: PDFLib.rgb(0,0,0) });
            });

            const cols = JOURNEY_CONFIG.cols;
            const fuelKeys = JOURNEY_CONFIG.fuelKeys;
            let totalNightMins = 0;

            dailyLegs.forEach((leg, idx) => {
                if(leg['j-night']) totalNightMins += parseTimeString(leg['j-night']);
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

            // --- CREW DATA SECTION (UPDATED) ---
            const crewStart = 333; 
            const crewGap = 17;    
            
            // Get Counts
            const numFC = parseInt(el('j-fc-count')?.value || 2);
            const numCC = parseInt(el('j-cc-count')?.value || 4);
            const totalRows = numFC + numCC;

            // Get Duty Calculation Vars
            const lastLeg = dailyLegs[dailyLegs.length - 1];
            const onBlocksMins = lastLeg ? parseTimeString(lastLeg['j-in']) : 0;
            const nCalcEl = el('j-night-calc');
            const nightDutyStr = nCalcEl ? (nCalcEl.value || nCalcEl.innerText || "") : "";
            const maxFDP = el('j-max-fdp')?.value || ""; 

            // Get Duty Starts (calculated in calcDutyLogic)
            const fcDutyStartStr = el('j-duty-start')?.innerText || "00:00";
            const ccDutyStartStr = el('j-cc-duty-start')?.innerText || "00:00";
            
            const fcStartMins = parseTimeString(fcDutyStartStr);
            const ccStartMins = parseTimeString(ccDutyStartStr);

            // Helper to calc FDP for specific crew type
            const getFDP = (startMins) => {
                if(!onBlocksMins) return "";
                let diff = onBlocksMins - startMins;
                if(diff < 0) diff += 1440;
                return minsToTime(diff);
            };

            const calculatedNightDuty = el('j-night-calc')?.value || (el('j-night-calc')?.innerText) || "";

            for(let i = 0; i < totalRows; i++) {
                const y = crewStart - (i * crewGap);
                
                // Determine if this row is Flight Crew or Cabin Crew
                const isFlightCrew = (i < numFC);
                
                // Select correct FDP
                const myFDP = isFlightCrew ? getFDP(fcStartMins) : getFDP(ccStartMins);

                // 1. OP (Always)
                if(cols['j-duty-operating']) 
                    page.drawText("OP", { x: cols['j-duty-operating'], y: y, size: JOURNEY_CONFIG.fontSize, font: font });

                // 2. Duty Time (Calculated per row type)
                if(myFDP && cols['j-duty-time']) 
                    page.drawText(myFDP, { x: cols['j-duty-time'], y: y, size: JOURNEY_CONFIG.fontSize, font: font });

                // 3. Night Duty
                if(calculatedNightDuty && cols['j-duty-night']) {
                    page.drawText(calculatedNightDuty, { x: cols['j-duty-night'], y: y, size: JOURNEY_CONFIG.fontSize, font: font });
                }

                // 4. Allowed FDP (Input box)
                if(maxFDP && cols['j-duty-allowed']) 
                    page.drawText(maxFDP, { x: cols['j-duty-allowed'], y: y, size: JOURNEY_CONFIG.fontSize, font: font });
            }

            const out = await pdfDoc.save();
            const filename = "Journey_Log_Filled.pdf";
            
            if (mode === 'email') {
                // Generate Subject
                const flt = el('j-flt')?.value || "FLT";
                const date = el('j-date')?.value || "DATE";
                const subject = `Journey Log: ${flt} ${date}`;
                
                // Use new share function
                await sharePdf(out, filename, subject, "Journey Log.");
            } else {
                // Default: Save to files
                downloadBlob(out, filename);
            }

        } catch(e) { console.error(e); alert("Error generating Log: " + e.message); }
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

    // New Helper: Share PDF natively on iPad without the Blob URL
async function sharePdf(pdfBytes, filename, subject, body) {
    // 1. Create a "File" object from the PDF bytes
    const blob = new Blob([pdfBytes], { type: 'application/pdf' });
    const file = new File([blob], filename, { type: 'application/pdf' });

    // 2. Copy the target email to clipboard automatically
    try {
        await navigator.clipboard.writeText("ofp@airastana.com");
        // Optional: Alert the user so they know
        // alert("Email 'ofp@airastana.com' copied to clipboard! Paste it in the To: field.");
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
                // CRITICAL: We do NOT add a 'url' property here, which stops the blob link appearing
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
        'j-flt', 'j-reg', 'j-date', 'j-dep', 'j-dest', 'j-altn', 'j-std',
        'j-out', 'j-off', 'j-on', 'j-in', 'j-night', 'j-night-calc',
        'j-to', 'j-ldg', 'j-ldg-type', 'j-flt-alt', 'j-ldg-detail',
        'j-init', 'j-uplift-w', 'j-uplift-vol', 'j-act-ramp', 'j-shut', 'j-slip', 'j-slip-2',
        'j-adl', 'j-chl', 'j-inf', 'j-bag', 'j-cargo', 'j-mail', 'j-zfw',
        'j-report-type', 'j-fc-count', 'j-cc-count', 'front-extra-reason',
        'front-atis', 'front-atc', 'front-altm1', 'front-stby', 'front-altm2', 'view-pic-block',
    ];

    function saveState() {
        const state = {
            inputs: {},
            dailyLegs: dailyLegs, // Save the legs array
            dutyStartTime: dutyStartTime // Save the calculated duty start
        };

        // 1. Save all simple inputs
        SAVE_IDS.forEach(id => {
            const e = el(id);
            if(e) state.inputs[id] = e.value;
        });

        // 2. Save Waypoint Data (User entered ATOs/Fuel)
        // We map just the user-editable fields from the table
        const waypointData = waypoints.map((wp, i) => ({
            ato: el(`o-a-${i}`)?.value || "",
            fuel: el(`o-f-${i}`)?.value || "",
            notes: el(`o-n-${i}`)?.value || "",
            agl: el(`o-agl-${i}`)?.value || ""
        }));
        state.waypoints = waypointData;

        // Save to browser storage
        localStorage.setItem('efb_log_state', JSON.stringify(state));
        console.log("Auto-saved");
    }

    function loadState() {
        const raw = localStorage.getItem('efb_log_state');
        if(!raw) return; 

        try {
            const state = JSON.parse(raw);
            
            // 1. Restore simple inputs
            if(state.inputs) {
                Object.keys(state.inputs).forEach(id => {
                    const val = state.inputs[id];
                    // SMART RESTORE: 
                    // Only overwrite if the saved value is NOT empty.
                    // This prevents empty storage from erasing PDF data (like Flight No).
                    if (val !== "" && val !== null) {
                        safeSet(id, val);
                    }
                });
            }

            // 2. Restore Daily Legs
            if(state.dailyLegs && Array.isArray(state.dailyLegs)) {
                dailyLegs = state.dailyLegs;
                renderJourneyList(); 
            }

            // 3. Restore Duty Start Time
            if(state.dutyStartTime !== undefined) {
                dutyStartTime = state.dutyStartTime;
                calcDutyLogic(); 
            }
            
            // 4. Restore Waypoints (Temp storage)
            window.savedWaypointData = state.waypoints;
            calculateExtraFromTotal();
            runCalc();
            updateFuelMonitor();

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

})();