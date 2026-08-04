(function() {
// ==========================================
// 1. CONFIGURATION
// ==========================================

    const APP_VERSION = "2.2.2";
const RELEASE_NOTES = {
        "2.2.2": {
            title: "Release Notes",
            notes: [
                "🔑 Improved Skyplan token prompt with auto-quote cleaning & smooth background refresh",
                "📋 Updated ATIS and Clearance popups",
                "✍️ Journey log data downloaded directly from the server",
                "📁 Download OFPs directly from the server",
            ]
        }
    };
    const ENCRYPTION_KEY_NAME = 'efb_encryption_key';
    const ENCRYPTION_ALGO = {
        name: 'AES-GCM',
        length: 256
    };
    const AUTH_KEY = 'efb_auth_hash';
    const PERSIST_AUTH_KEY = 'efb_authenticated_persist';
    const MAX_ATTEMPTS = 5;
    const LOCKOUT_TIME = 15 * 60 * 1000; // 15 minutes
    const AUDIT_LOG_KEY = 'efb_audit_log';
    const MAX_LOG_ENTRIES = 1000;
    const EXPECTED_SW_HASH = '399ec11ca161fdbff795aafcfea7cc1e035eb1f312555643a438b7c0a6694023';
    const SW_HASH_STORAGE_KEY = 'efb_sw_hash_cache';
    const PERSISTENT_INPUT_IDS = [
        'front-atis', 'front-atc', 'front-altm1', 'front-stby', 'front-altm2',
        'front-extra-kg', 'front-extra-reason', 'view-pic-block'
    ];

    const FLIGHT_THREAT_DICTIONARY = {
        notams: [
            { regex: /\b(?:AD|AERODROME|APPT)\s+(?:CLSD|CLOSED)\b/i, level: 'critical', type: 'ARPT CLSD' },
            { regex: /\bRWY\s+([0-9]{2}[LRC]?)\s+(?:CLSD|CLOSED)\b/i, level: 'critical', type: 'RWY CLSD' },
            { regex: /\b(?:ILS|LOC|GP|GLIDEPATH|VOR|NDB|DME|RNP|RNAV|GPS)\s+.*?(?:U\/S|UNSERVICEABLE|NOT AVBL|OUT OF SERVICE)\b/i, level: 'warning', type: 'NAVAID' },
            { regex: /\bTWY\s+([A-Z0-9]+(?:\s+AND\s+[A-Z0-9]+)*)\s+(?:CLSD|CLOSED)\b/i, level: 'warning', type: 'TWY CLSD' },
            { regex: /\bFCT\s+(?:U\/S|NOT AVBL)\b|\b(?:FIRE AND RESCUE|RFFS)\s+DOWNGRADED\b/i, level: 'critical', type: 'RFFS' },
            { regex: /\bBA\s+(?:POOR|1|2)\b|\b(?:ICE|SNOW|SLUSH)\s+ON\s+RWY\b/i, level: 'warning', type: 'BRAKING' },
            { regex: /\bBIRD\b/i, level: 'info', type: 'BIRDS' },
            { regex: /\b(?:WIP|WORK IN PROGRESS)\b/i, level: 'info', type: 'WIP' },
            { regex: /\b\d\/\d\/\d\b.*?(?:FROST|ICE|SNOW|SLUSH|WATER|POOR|COMPACTED|DRY|WET)/i, level: 'warning', type: 'RWY CC' },
            { regex: /\bRWY\s+CC\s+([0-3])\b/i, level: 'critical', type: 'RWY CC' },
            { regex: /\bRWY\s+CC\s+\d\/\d\/\d\b/i, level: 'info', type: 'RWY CC' },
            { regex: /\bRWY\s+COND(?:ITION)?\s+.*?(?:POOR|SLIPPERY|ICE|SNOW|SLUSH|WATER|STANDING)/i, level: 'warning', type: 'RWY CC' },
            { regex: /\bBRAKING ACTION\s+(?:POOR|MEDIUM POOR|NIL)\b/i, level: 'warning', type: 'BRAKING' },
            { regex: /\b(?:FIC|AIRMET|SIGMET)\b/i, level: 'warning', type: 'INFO' },
        ],
        weather: [
            { regex: /\b(?:TS|TSRA|VCTS|\+TSRA)\b/i, level: 'critical', type: 'THUNDERSTORM' },
            { regex: /\b(?:FZRA|FZDZ|\+SN|BLSN)\b/i, level: 'critical', type: 'FREEZING' },
            { regex: /\b(?:\+SN|BLSN)\b/i, level: 'critical', type: '+SNOW' },
            { regex: /\b(?:WS\s+RWY|WINDSHEAR)\b/i, level: 'critical', type: 'WINDSHEAR' },
            { regex: /\b(?:OVC|BKN|VV)00[0-2]\b/i, level: 'critical', type: 'CEILING' },
            { regex: /\b(?:OVC|BKN|VV)00[3-6]\b/i, level: 'warning', type: 'CEILING' },
            { regex: /\bR[0-9]{2}[LRC]?\/0[0-5][0-9]{2}/i, level: 'critical', type: 'RVR' }
        ]
    };

    const JOURNEY_CONFIG = {
        fontSize: 8,
        rowGap: 17, 
        headers: {}
    };

    const TIME_X = 485, ATO_X = 485, FOB_X = 445, NOTES_X = 160;
    const V_LIFT = 2;       
    const LINE_HEIGHT = 12;
    const SAVE_STATE_DEBOUNCE = 1000;
    const pads = {
        main: { canvasId: 'sig-canvas', pad: null, lastWidth: 0, lastHeight: 0, lastRatio: 1 },
        atis: { canvasId: 'front-atis-canvas', pad: null, lastWidth: 0, lastHeight: 0, lastRatio: 1 },
        atc:  { canvasId: 'front-atc-canvas', pad: null, lastWidth: 0, lastHeight: 0, lastRatio: 1 }
    };
    let ofpCache = null; let cacheTime = 0; const CACHE_TTL = 5000;
    let waypointATOCache = [];   // array of input elements for o-a-*
    let alternateATOCache = [];  // array for a-a-*
    let isActivating = false;
    let isReordering = false;
    let signaturePad = null;
    let savedSignatureData = null;
    let takeoffFuelInput = null;
    let waypointFuelCache = [];
    let pdfFallbackElement = null;
    let isOFPLoaded = false;
    let journeyLogTemplateBytes = null;
    let waypoints = [], alternateWaypoints = [], dailyLegs = [];
    let fuelData = [];
    let crewData = [];
    let blockFuelValue = 0;
    let dutyStartTime = null;
    let autoLockTimer = null;
    let currentAtisInputMode = 'typing';
    let waypointTableCache = {
        waypoints: [],
        alternateWaypoints: [],
        lastUpdate: 0
    };
    let frontCoords = {  
        atis: null, atcLabel: null, altm1: null, stby: null, altm2: null, picBlockLabel: null, reasonLabel: null 
    };
    let dbPromise = null;
    let depAlertsByAirport = {};
    let destAlertsByAirport = {};
    let altnAlertsByAirport = {};

// ==========================================
// 2. UTILITY SECURITY AND UPDATE
// ==========================================

    // Show release notes for the current version
    function showReleaseNotes() {
        const releaseData = RELEASE_NOTES[APP_VERSION] || {
            title: `Version ${APP_VERSION}`,
            notes: ["No release notes available."]
        };
        createModal({
            title: releaseData.title,
            showVersion: APP_VERSION,
            listItems: releaseData.notes,
            confirmText: 'Close',
            icon: '📋',
            type: 'info'
        });
    }

    function verifyUpdateOrigin(registration) {
        // During initial installation, registration.active might be null
        const scriptURL = registration.active ? registration.active.scriptURL : registration.scope || '';
        
        // If no scriptURL (first install), allow it
        if (!scriptURL) {
            console.log('No active service worker - allowing first install');
            return true;
        }
        
        // Only allow updates from same origin
        try {
            const url = new URL(scriptURL);
            if (url.origin !== window.location.origin) {
                console.error('Service worker from different origin:', url.origin, 'expected:', window.location.origin);
                return false;
            }
            return true;
        } catch (error) {
            console.error('Error parsing service worker URL:', error);
            return false; // Better safe than sorry
        }
    }

    // Audit logging function
    async function logSecurityEvent(eventType, details = {}) {
        try {
            const logEntry = {
                timestamp: new Date().toISOString(),
                event: eventType,
                details: details,
                userAgent: navigator.userAgent,
                version: APP_VERSION
            };
            
            // Get existing log
            const encryptedLog = localStorage.getItem(AUDIT_LOG_KEY);
            let log = [];
            
            if (encryptedLog) {
                try {
                    log = await decryptData(encryptedLog);
                    // Ensure log is an array (fallback might return non‑array)
                    if (!Array.isArray(log)) {
                        console.warn('Audit log is not an array, resetting');
                        log = [];
                    }
                } catch {
                    // Start fresh if decryption fails
                    log = [];
                }
            }
            
            // Add new entry
            log.push(logEntry);
            
            // Keep only recent entries
            if (log.length > MAX_LOG_ENTRIES) {
                log = log.slice(-MAX_LOG_ENTRIES);
            }
            
            // Encrypt and save
            const encrypted = await encryptData(log);
            localStorage.setItem(AUDIT_LOG_KEY, encrypted);
            
        } catch (error) {
            console.error('Failed to log security event:', error);
        }
    }

    window.viewAuditLog = async function() {
            try {
                const encryptedLog = localStorage.getItem(AUDIT_LOG_KEY);
                if (!encryptedLog) {
                    alert('No audit logs found');
                    return;
                }
                
                const log = await decryptData(encryptedLog);
                const logText = log.map(entry => 
                    `${entry.timestamp} - ${entry.event}\n${JSON.stringify(entry.details, null, 2)}`
                ).join('\n\n---\n\n');
                
                const win = window.open('', '_blank');
                if (!win) {
                    alert('Pop-up blocked. Please allow pop-ups');
                    return;
                }

                win.document.title = "Audit Log Viewer";
                const pre = win.document.createElement('pre');
                pre.textContent = logText;
                pre.style.padding = "20px";
                pre.style.fontFamily = "monospace";
                pre.style.whiteSpace = "pre-wrap"; 

                win.document.body.appendChild(pre);
                
            } catch (error) {
                console.error('Failed to view audit log:', error);
                alert('Error accessing audit log');
            }
        };

    async function setupAuthentication() {
        // Check if already authenticated in this session
        if (sessionStorage.getItem('efb_authenticated') === 'true') {
            return true;
        }

        // Check if persistent authentication is enabled (auto-lock = Never)
        const settings = JSON.parse(localStorage.getItem('efb_settings') || '{}');
        const autoLockSetting = settings.autoLockTime;

        // Use == to accept both string '0' and number 0
        if (autoLockSetting == 0 && localStorage.getItem(PERSIST_AUTH_KEY) === 'true') {
            // Restore authenticated session silently
            sessionStorage.setItem('efb_authenticated', 'true');
            resetAutoLockTimer();
            setupActivityTracking();
            console.log('Persistent authentication restored');
            return true;
        }
        
        // Check lockout status
        const lockoutUntil = parseInt(localStorage.getItem('efb_lockout_until') || '0');
        if (Date.now() < lockoutUntil) {
            const minutes = Math.ceil((lockoutUntil - Date.now()) / 60000);
            alert(`Account locked. Try again in ${minutes} minutes.`);
            return false;
        }
        
        // Get stored hash
        const storedHash = localStorage.getItem(AUTH_KEY);
        const failedAttempts = parseInt(localStorage.getItem('efb_failed_attempts') || '0');
        
        // If no PIN is set, prompt to create one
        if (!storedHash) {
            return await setupNewPIN();
        }
        
        // Show authentication dialog
        return new Promise((resolve) => {
            const dialog = document.createElement('div');
            dialog.style.cssText = `
                position: fixed;
                top: 0;
                left: 0;
                right: 0;
                bottom: 0;
                background: rgba(0,0,0,0.9);
                display: flex;
                justify-content: center;
                align-items: center;
                z-index: 99999;
                backdrop-filter: blur(10px);
            `;
            
            dialog.innerHTML = `
                <div style="
                    background: var(--panel);
                    border-radius: 15px;
                    padding: 30px;
                    max-width: 400px;
                    width: 90%;
                    border: 2px solid var(--accent);
                    box-shadow: 0 20px 60px rgba(0,0,0,0.5);
                    text-align: center;
                ">
                    <h2 style="color: var(--accent); margin-top: 0; margin-bottom: 10px;">
                        🔐 EFB Log Pro
                    </h2>
                    <p style="color: var(--dim); margin-bottom: 25px;">
                        Enter PIN to continue
                    </p>
                    
                    <input type="password" 
                        id="auth-pin-input" 
                        maxlength="6" 
                        inputmode="numeric"
                        pattern="[0-9]*"
                        style="
                            width: 200px;
                            padding: 15px;
                            font-size: 24px;
                            text-align: center;
                            letter-spacing: 8px;
                            border: 2px solid var(--border);
                            border-radius: 10px;
                            background: var(--input);
                            color: var(--text);
                            margin-bottom: 20px;
                        "
                        placeholder="••••••">
                    
                    <div id="auth-error" style="color: var(--error); min-height: 20px; margin-bottom: 20px;"></div>
                    
                    <div style="display: flex; gap: 15px;">
                        <button id="auth-cancel" style="
                            flex: 1;
                            padding: 12px;
                            background: transparent;
                            border: 1px solid var(--border);
                            color: var(--text);
                            border-radius: 10px;
                            cursor: pointer;
                        ">Cancel</button>
                        
                        <button id="auth-submit" style="
                            flex: 1;
                            padding: 12px;
                            background: var(--accent);
                            border: none;
                            color: white;
                            border-radius: 10px;
                            font-weight: bold;
                            cursor: pointer;
                        ">Unlock</button>
                    </div>
                    
                    <p style="color: var(--dim); font-size: 12px; margin-top: 20px;">
                        ${failedAttempts > 0 ? `${failedAttempts} failed attempts` : ''}
                    </p>
                </div>
            `;
            
            document.body.appendChild(dialog);
            const pinInput = document.getElementById('auth-pin-input');
            pinInput.focus();
            
            // Handle PIN entry
            pinInput.addEventListener('input', (e) => {
                // Auto-submit on 6 digits
                if (e.target.value.length === 6) {
                    document.getElementById('auth-submit').click();
                }
            });
            
            // Submit handler
            document.getElementById('auth-submit').onclick = async () => {
                const pin = pinInput.value;
                const errorDiv = document.getElementById('auth-error');
                
                if (!pin || pin.length !== 6) {
                    errorDiv.textContent = 'PIN must be 6 digits';
                    return;
                }
                
                // Simple hash function (in production)
                const hash = await simpleHash(pin);
                
                if (hash === storedHash) {
                    // Successful login
                    localStorage.setItem('efb_failed_attempts', '0');
                    sessionStorage.setItem('efb_authenticated', 'true');
                    // If auto-lock is set to Never, persist authentication across reloads
                    const settings = JSON.parse(localStorage.getItem('efb_settings') || '{}');
                    if (settings.autoLockTime == 0) { 
                        localStorage.setItem(PERSIST_AUTH_KEY, 'true');
                    }
                    resetAutoLockTimer();
                    setupActivityTracking();
                    // Log successful authentication
                    try {
                        await logSecurityEvent('AUTH_SUCCESS', {
                            method: 'pin',
                            timestamp: new Date().toISOString()
                        });
                    } catch (logError) {
                        console.error('Failed to log auth success:', logError);
                    }
                    
                    document.body.removeChild(dialog);
                    resolve(true);
                } else {
                    // Failed attempt
                    const newAttempts = failedAttempts + 1;
                    localStorage.setItem('efb_failed_attempts', newAttempts.toString());
                    
                    // Log failed authentication
                    try {
                        await logSecurityEvent('AUTH_FAILED', {
                            attempts: newAttempts,
                            locked: newAttempts >= MAX_ATTEMPTS,
                            timestamp: new Date().toISOString()
                        });
                    } catch (logError) {
                        console.error('Failed to log auth failure:', logError);
                    }
                    
                    if (newAttempts >= MAX_ATTEMPTS) {
                        // Lockout
                        const lockoutUntil = Date.now() + LOCKOUT_TIME;
                        localStorage.setItem('efb_lockout_until', lockoutUntil.toString());
                        errorDiv.textContent = `Too many attempts. Locked for 15 minutes.`;
                        
                        setTimeout(() => {
                            document.body.removeChild(dialog);
                            resolve(false);
                        }, 3000);
                    } else {
                        errorDiv.textContent = `Invalid PIN. ${MAX_ATTEMPTS - newAttempts} attempts remaining.`;
                        pinInput.value = '';
                        pinInput.focus();
                    }
                }
            };
            
            // Cancel handler
            document.getElementById('auth-cancel').onclick = () => {
                document.body.removeChild(dialog);
                resolve(false);
            };
        });
    }

    function autoLockApp() {
        // Clear authentication
        sessionStorage.removeItem('efb_authenticated');
        localStorage.removeItem(PERSIST_AUTH_KEY);
        
        // Clear timer
        if (autoLockTimer) {
            clearTimeout(autoLockTimer);
            autoLockTimer = null;
        }
        
        // Show auth dialog
        setupAuthentication().then(authenticated => {
            if (authenticated) {
                // User re-authenticated successfully
                resetAutoLockTimer();
            }
        });
    }

    function resetAutoLockTimer() {
        // Clear existing timer
        if (autoLockTimer) {
            clearTimeout(autoLockTimer);
            autoLockTimer = null;
        }
        
        // Get settings
        const settings = JSON.parse(localStorage.getItem('efb_settings') || '{}');
        let setting = parseInt(settings.autoLockTime);
        const autoLockMinutes = isNaN(setting) ? 15 : setting;
        
        // Only set timer if auto-lock is enabled (not 0)
        if (autoLockMinutes > 0) {
            const lockTimeMs = autoLockMinutes * 60 * 1000;
            
            autoLockTimer = setTimeout(() => {
                if (sessionStorage.getItem('efb_authenticated') === 'true') {
                    console.log('Auto-locking due to inactivity');
                    autoLockApp();
                }
            }, lockTimeMs);
        }
    }

    function setupActivityTracking() {
        const activityEvents = ['mousedown', 'mousemove', 'keydown', 'scroll', 'touchstart', 'click'];
        
        activityEvents.forEach(eventName => {
            document.addEventListener(eventName, resetAutoLockTimer, { passive: true });
        });
    }

    // Simple hash function
    async function simpleHash(pin) {
        const encoder = new TextEncoder();
        const data = encoder.encode(pin + 'efb_salt'); // Add salt
        const hashBuffer = await crypto.subtle.digest('SHA-256', data);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        return hashArray.map(b => b.toString(16).padStart(2, '0')).join('').substring(0, 32);
    }

    // Setup new PIN
    async function setupNewPIN() {
        return new Promise((resolve) => {
            const dialog = document.createElement('div');
            dialog.style.cssText = `
                position: fixed;
                top: 0;
                left: 0;
                right: 0;
                bottom: 0;
                background: rgba(0,0,0,0.9);
                display: flex;
                justify-content: center;
                align-items: center;
                z-index: 99999;
            `;
            
            dialog.innerHTML = `
                <div style="
                    background: var(--panel);
                    border-radius: 15px;
                    padding: 30px;
                    max-width: 400px;
                    width: 90%;
                    text-align: center;
                ">
                    <h2 style="color: var(--accent); margin-top: 0;">
                        🔐 Set PIN
                    </h2>
                    <p style="color: var(--dim); margin-bottom: 20px;">
                        Create a 6-digit PIN to secure your flight data
                    </p>
                    
                    <input type="password" 
                        id="new-pin-input" 
                        maxlength="6" 
                        inputmode="numeric"
                        placeholder="Enter 6-digit PIN"
                        style="width: 200px; padding: 12px; margin-bottom: 15px; text-align: center;">
                    
                    <input type="password" 
                        id="confirm-pin-input" 
                        maxlength="6" 
                        inputmode="numeric"
                        placeholder="Confirm PIN"
                        style="width: 200px; padding: 12px; margin-bottom: 20px; text-align: center;">
                    
                    <div id="pin-error" style="color: var(--error); min-height: 20px; margin-bottom: 20px;"></div>
                    
                    <button id="set-pin-btn" style="
                        padding: 12px 30px;
                        background: var(--accent);
                        border: none;
                        color: white;
                        border-radius: 10px;
                        font-weight: bold;
                        cursor: pointer;
                    ">Set PIN</button>
                </div>
            `;
            
            document.body.appendChild(dialog);
            
            document.getElementById('set-pin-btn').onclick = async () => {
                const pin1 = document.getElementById('new-pin-input').value;
                const pin2 = document.getElementById('confirm-pin-input').value;
                const errorDiv = document.getElementById('pin-error');
                
                if (pin1.length !== 6 || pin2.length !== 6) {
                    errorDiv.textContent = 'PIN must be 6 digits';
                    return;
                }
                
                if (pin1 !== pin2) {
                    errorDiv.textContent = 'PINs do not match';
                    return;
                }
                
                if (/^(\d)\1{5}$/.test(pin1)) { // Simple pattern check
                    errorDiv.textContent = 'Avoid simple patterns (like 111111)';
                    return;
                }
                
                // Save hash
                const hash = await simpleHash(pin1);
                localStorage.setItem(AUTH_KEY, hash);
                sessionStorage.setItem('efb_authenticated', 'true');
                
                // Log PIN setup
                try {
                    await logSecurityEvent('AUTH_SETUP', {
                        method: 'pin_setup',
                        timestamp: new Date().toISOString()
                    });
                } catch (logError) {
                    console.error('Failed to log auth setup:', logError);
                }
                
                document.body.removeChild(dialog);
                resolve(true);
            };
        });
    }

    async function changePIN() {
        return new Promise((resolve) => {
            const dialog = document.createElement('div');
            dialog.className = 'settings-modal';
            
            dialog.innerHTML = `
                <div class="settings-modal-content">
                    <h3>🔒 Change PIN</h3>
                    <p style="color: var(--dim); margin-bottom: 20px;">
                        Enter your current PIN, then create a new 6-digit PIN.
                    </p>
                    
                    <div style="margin-bottom: 15px;">
                        <label style="display: block; margin-bottom: 5px; color: var(--text); font-size: 14px;">
                            Current PIN
                        </label>
                        <input type="password" id="current-pin" maxlength="6" inputmode="numeric"
                            style="width: 100%; padding: 12px; border-radius: 8px; border: 1px solid var(--border);
                                background: var(--input); color: var(--text); text-align: center; letter-spacing: 8px;"
                            placeholder="••••••">
                    </div>
                    
                    <div style="margin-bottom: 15px;">
                        <label style="display: block; margin-bottom: 5px; color: var(--text); font-size: 14px;">
                            New PIN
                        </label>
                        <input type="password" id="new-pin" maxlength="6" inputmode="numeric"
                            style="width: 100%; padding: 12px; border-radius: 8px; border: 1px solid var(--border);
                                background: var(--input); color: var(--text); text-align: center; letter-spacing: 8px;"
                            placeholder="••••••">
                    </div>
                    
                    <div style="margin-bottom: 20px;">
                        <label style="display: block; margin-bottom: 5px; color: var(--text); font-size: 14px;">
                            Confirm New PIN
                        </label>
                        <input type="password" id="confirm-pin" maxlength="6" inputmode="numeric"
                            style="width: 100%; padding: 12px; border-radius: 8px; border: 1px solid var(--border);
                                background: var(--input); color: var(--text); text-align: center; letter-spacing: 8px;"
                            placeholder="••••••">
                    </div>
                    
                    <div id="pin-error" style="color: var(--error); min-height: 20px; margin-bottom: 20px;"></div>
                    
                    <div class="settings-modal-actions">
                        <button class="btn-cancel" id="pin-cancel-btn">Cancel</button>
                        <button class="btn-confirm" id="pin-submit-btn">Change PIN</button>
                    </div>
                </div>
            `;
            
            document.body.appendChild(dialog);
            
            // Add event listeners for modal buttons
            document.getElementById('pin-cancel-btn').addEventListener('click', () => {
                dialog.remove();
                resolve(false);
            });
            
            document.getElementById('pin-submit-btn').addEventListener('click', async () => {
                await submitPINChange(dialog);
            });
            
            document.getElementById('current-pin').focus();
        });
    }

    async function submitPINChange(dialog) {
        const currentPIN = document.getElementById('current-pin').value;
        const newPIN = document.getElementById('new-pin').value;
        const confirmPIN = document.getElementById('confirm-pin').value;
        const errorDiv = document.getElementById('pin-error');
        
        // Validate inputs
        if (!currentPIN || !newPIN || !confirmPIN) {
            errorDiv.textContent = 'All fields are required';
            return;
        }
        
        if (newPIN.length !== 6 || confirmPIN.length !== 6) {
            errorDiv.textContent = 'PIN must be 6 digits';
            return;
        }
        
        if (newPIN !== confirmPIN) {
            errorDiv.textContent = 'New PINs do not match';
            return;
        }
        
        if (/^(\d)\1{5}$/.test(newPIN)) {
            errorDiv.textContent = 'Avoid simple patterns (like 111111)';
            return;
        }
        
        // Verify current PIN
        const storedHash = localStorage.getItem(AUTH_KEY);
        const currentHash = await simpleHash(currentPIN);
        
        if (currentHash !== storedHash) {
            errorDiv.textContent = 'Current PIN is incorrect';
            return;
        }
        
        // Save new PIN
        const newHash = await simpleHash(newPIN);
        localStorage.setItem(AUTH_KEY, newHash);
        
        // Log security event
        await logSecurityEvent('PIN_CHANGED', {
            timestamp: new Date().toISOString()
        });
        
        // Close dialog and show success
        dialog.remove();
        showToast('PIN changed successfully');
    }

    async function getEncryptionKey() {
        // Try to get existing key from storage
        const storedKey = localStorage.getItem(ENCRYPTION_KEY_NAME);
        
        if (storedKey) {
            // Import existing key
            const keyBuffer = Uint8Array.from(atob(storedKey), c => c.charCodeAt(0));
            return await crypto.subtle.importKey(
                'raw',
                keyBuffer,
                ENCRYPTION_ALGO,
                false,
                ['encrypt', 'decrypt']
            );
        } else {
            // Generate new key
            const key = await crypto.subtle.generateKey(
                ENCRYPTION_ALGO,
                true,
                ['encrypt', 'decrypt']
            );
            
            // Export and store
            const exported = await crypto.subtle.exportKey('raw', key);
            const keyStr = btoa(String.fromCharCode(...new Uint8Array(exported)));
            localStorage.setItem(ENCRYPTION_KEY_NAME, keyStr);
            
            return key;
        }
    }

    async function encryptData(data) {
        try {
            const key = await getEncryptionKey();
            const iv = crypto.getRandomValues(new Uint8Array(12)); // 12 bytes for GCM

            // Safely stringify the data – catch circular references
            let jsonString;
            try {
                jsonString = JSON.stringify(data);
            } catch (stringifyError) {
                console.error('encryptData: JSON.stringify failed:', stringifyError);
                // Return a minimal fallback that will not cause another error
                return btoa(JSON.stringify({
                    encrypted: false,
                    error: 'Data too complex to stringify',
                    timestamp: new Date().toISOString()
                }));
            }

            const encoded = new TextEncoder().encode(jsonString);
            const encrypted = await crypto.subtle.encrypt(
                { name: 'AES-GCM', iv },
                key,
                encoded
            );

            // Combine IV + encrypted data
            const result = new Uint8Array(iv.length + encrypted.byteLength);
            result.set(iv, 0);
            result.set(new Uint8Array(encrypted), iv.length);

            return btoa(String.fromCharCode(...result));
        } catch (error) {
            console.error('Encryption failed:', error);
            // Ultimate fallback – store only a placeholder
            return btoa(JSON.stringify({
                encrypted: false,
                error: 'Encryption failed',
                timestamp: new Date().toISOString()
            }));
        }
    }

    async function decryptData(encryptedBase64) {
        try {
            // Check if it's unencrypted fallback
            const decoded = JSON.parse(atob(encryptedBase64));
            if (decoded.encrypted === false) {
                console.warn('Using unencrypted fallback data');
                return decoded.data;
            }
        } catch {
            // Proceed with decryption
        }
        
        try {
            const key = await getEncryptionKey();
            const encryptedData = Uint8Array.from(atob(encryptedBase64), c => c.charCodeAt(0));
            
            // Extract IV (first 12 bytes) and ciphertext
            const iv = encryptedData.slice(0, 12);
            const ciphertext = encryptedData.slice(12);
            
            const decrypted = await crypto.subtle.decrypt(
                { name: 'AES-GCM', iv },
                key,
                ciphertext
            );
            
            return JSON.parse(new TextDecoder().decode(decrypted));
        } catch (error) {
            console.error('Decryption failed:', error);
            throw new Error('Failed to decrypt data. It may be corrupted or from a different device.');
        }
    }

    // Service worker
    if ('serviceWorker' in navigator && (window.location.protocol === 'https:' || window.location.protocol === 'http:')) {
    
    // Only register if HTTPS (or localhost for development)
    const isSecure = window.location.protocol === 'https:' || 
                    window.location.hostname === 'localhost' ||
                    window.location.hostname === '127.0.0.1';
    
    if (!isSecure) {
        console.warn('Service worker registration skipped: not HTTPS');
        return;
    }
    
    // Add a pre-verification check before registering
    async function preVerifyServiceWorker() {
        try {
            let response;
            
            // Try to fetch from network first
            try {
                response = await fetch('sw.js', {
                    cache: 'no-store',
                    headers: {
                        'Cache-Control': 'no-cache'
                    }
                });
                
                if (!response.ok) throw new Error('Failed to fetch service worker');
            } catch (networkError) {
                console.log('Network fetch failed, device may be offline:', networkError);
                
                // Check if we have a cached hash for offline verification
                const cachedHashData = localStorage.getItem(SW_HASH_STORAGE_KEY);
                if (cachedHashData) {
                    try {
                        const { hash, timestamp, version } = JSON.parse(cachedHashData);
                        
                        // Check if cache is not too old (e.g., less than 30 days)
                        const cacheAge = Date.now() - timestamp;
                        const MAX_CACHE_AGE = 30 * 24 * 60 * 60 * 1000; // 30 days
                        
                        if (cacheAge < MAX_CACHE_AGE && hash === EXPECTED_SW_HASH) {
                            console.log('Using cached service worker hash for offline verification');
                            return true; // Accept cached verification
                        } else {
                            console.log('Cached hash is expired or invalid');
                        }
                    } catch (e) {
                        console.log('Failed to parse cached hash:', e);
                    }
                }
                
                // If we get here, we can't verify
                const shouldContinue = confirm(
                    'Cannot verify service worker while offline.\n\n' +
                    'Continue without service worker verification?\n\n' +
                    'Note: Some offline features may not work properly.'
                );
                
                if (shouldContinue) {
                    return false; // Don't register service worker
                }
                throw new Error('Service worker verification failed: Device is offline');
            }
            
            // We have a response, calculate hash
            const swText = await response.text();
            const encoder = new TextEncoder();
            const data = encoder.encode(swText);
            const hashBuffer = await crypto.subtle.digest('SHA-256', data);
            const hashArray = Array.from(new Uint8Array(hashBuffer));
            const calculatedHash = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
            
            // Cache the hash for future offline use
            try {
                localStorage.setItem(SW_HASH_STORAGE_KEY, JSON.stringify({
                    hash: calculatedHash,
                    timestamp: Date.now(),
                    version: APP_VERSION
                }));
            } catch (e) {
                console.log('Failed to cache service worker hash:', e);
            }
            
            if (calculatedHash !== EXPECTED_SW_HASH) {
                console.error('Service worker integrity check failed');
                throw new Error('Service worker has been modified');
            }
            
            return true;
        } catch (error) {
            console.error('Service worker verification failed:', error);
            
            // Ask user if they want to continue without verification
            const shouldContinue = confirm(`Service worker verification failed: ${error.message}\n\nContinue without service worker?`);
            if (shouldContinue) {
                return false; // Don't register service worker
            }
            throw error;
        }
    }
    
    // Pre-verify before registering
    preVerifyServiceWorker().then(shouldRegister => {
        if (!shouldRegister) {
            console.log('Service worker registration skipped due to verification failure');
            return;
        }
        
        navigator.serviceWorker.register('sw.js')
        .then(reg => {
            
            // Verify origin first
            if (!verifyUpdateOrigin(reg)) {
                console.error('Service worker origin verification failed');
                reg.unregister();
                return;
            }
            
            // 1. Check on Load
            reg.update();

            // 2. AUTO-CHECK: Check for updates every 15 minutes
            setInterval(() => {
                console.log("Checking for app updates...");
                
                // Verify before updating
                if (verifyUpdateOrigin(reg)) {
                    reg.update();
                } else {
                    console.error('Skipping update: origin verification failed');
                }
            }, 15 * 60 * 1000);

            // 3. Listen for a new worker
            reg.onupdatefound = () => {
                const installingWorker = reg.installing;
                installingWorker.onstatechange = async () => {
                    if (installingWorker.state === 'installed' && navigator.serviceWorker.controller) {
                        console.log('New service worker installed and waiting');
                        try {
                            // Fetch the new service worker script
                            const response = await fetch(installingWorker.scriptURL, { cache: 'no-store' });
                            const swText = await response.text();
                            
                            // Hash Verification
                            const encoder = new TextEncoder();
                            const data = encoder.encode(swText);
                            const hashBuffer = await crypto.subtle.digest('SHA-256', data);
                            const hashArray = Array.from(new Uint8Array(hashBuffer));
                            const calculatedHash = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
                            
                            const hashValid = (calculatedHash === EXPECTED_SW_HASH);
                            
                            if (!hashValid) {
                                console.error('New service worker failed hash check:', { calculatedHash, expected: EXPECTED_SW_HASH });
                                installingWorker.postMessage({ type: 'UNINSTALL' });
                                alert('Update verification failed. Update rejected.');
                                
                                if (typeof logSecurityEvent === 'function') {
                                    await logSecurityEvent('SERVICE_WORKER_HASH_MISMATCH', {
                                        calculatedHash,
                                        expectedHash: EXPECTED_SW_HASH,
                                        scriptURL: installingWorker.scriptURL
                                    });
                                }
                                return;
                            }
                            
                            // EXTRACT VERSION from sw.js
                            const versionMatch = swText.match(/SW_VERSION\s*=\s*['"]([^'"]+)['"]/);
                            const newVersion = versionMatch ? versionMatch[1] : '0.0';
                            console.log('📦 New version extracted:', newVersion);
                            console.log('📦 Current app version:', APP_VERSION);
                            
                            // COMPARE with current app version
                            if (isNewerVersion(newVersion, APP_VERSION)) {
                                // Get release notes (fallback to generic)
                                const releaseData = RELEASE_NOTES[newVersion] || {
                                    title: "New Version Available",
                                    notes: ["Improvements and bug fixes"]
                                };
                                console.log('🎯 Showing update modal for version', newVersion);
                                showUpdateModal(newVersion, releaseData, () => {
                                    installingWorker.postMessage({ type: 'SKIP_WAITING' });
                                    setTimeout(() => window.location.reload(), 500);
                                });
                            }
                            // else: silently ignore – already up to date
                            
                        } catch(err) {
                            console.error('Failed to verify/parse update:', err);
                        }
                    }
                };
            };
        })
        .catch(err => {
            console.error('Service worker registration failed:', err);
            // Log the error
            if (typeof logSecurityEvent === 'function') {
                logSecurityEvent('SERVICE_WORKER_REGISTRATION_FAILED', {
                    error: err.message,
                    protocol: window.location.protocol
                });
            }
        });

        navigator.serviceWorker.addEventListener('controllerchange', () => {
            window.location.reload();
        });
        }).catch(err => {
            console.error('Service worker pre-verification failed, not registering:', err);
        });
    }

// ==========================================
// 3. INITIALIZATION
// ==========================================
    // Fast ID selector
    const el = (id) => document.getElementById(id);

    // Fast, reflow-free text setter
    function safeText(id, val) { 
        const e = el(id); 
        // Use textContent instead of innerText to prevent expensive CSS layout recalculations
        if (e) e.textContent = val || ''; 
    }

    // Smart input/text setter
    function safeSet(id, val) { 
        const e = el(id); 
        if (!e) return;
        
        if (e.tagName === 'INPUT' || e.tagName === 'SELECT' || e.tagName === 'TEXTAREA') {
            e.value = val || '';
        } else {
            e.textContent = val || ''; 
        }
    }

    // High-speed string sanitization (avoids DOM creation and memory leaks)
    function sanitizeHTML(str) {
        if (!str) return '';
        const escapeMap = {
            '&': '&amp;',
            '<': '&lt;',
            '>': '&gt;',
            '"': '&quot;',
            "'": '&#39;'
        };
        return String(str).replace(/[&<>"']/g, match => escapeMap[match]);
    }

    // Standard high-performance debounce
    function debounce(func, wait, immediate = false) {
        let timeout;
        const debounced = function(...args) {
            const context = this;
            const later = () => {
                timeout = null;
                if (!immediate) func.apply(context, args);
            };
            const callNow = immediate && !timeout;
            clearTimeout(timeout);
            timeout = setTimeout(later, wait);
            if (callNow) func.apply(context, args);
        };
        debounced.cancel = () => {
            clearTimeout(timeout);
            timeout = null;
        };
        return debounced;
    }

    window.onload = async function() {
        const authenticated = await setupAuthentication();
        
        if (!authenticated) {
            document.body.innerHTML = `
                <div style="display:flex; justify-content:center; align-items:center; height:100vh; background:var(--background); color:var(--text); text-align:center; padding:20px;">
                    <div>
                        <h1>🔒 Access Denied</h1>
                        <p>Authentication required to use EFB Log Pro</p>
                        <button onclick="location.reload()" style="margin-top:20px; padding:10px 20px; background:var(--accent); color:white; border:none; border-radius:5px; cursor:pointer;">Try Again</button>
                    </div>
                </div>`;
            return;
        }

        const bootSequence = async () => {
            await initializeApp();
            setTimeout(initializeSettings, 2000);
        };

        if ('requestIdleCallback' in window) {
            requestIdleCallback(bootSequence);
        } else {
            setTimeout(bootSequence, 1000);
        }
    };

    window.clearAtisCanvas = () => typeof clearPad === 'function' && clearPad('atis');
    window.clearAtcCanvas = () => typeof clearPad === 'function' && clearPad('atc');
    window.clearSignature = () => typeof clearPad === 'function' && clearPad('main');

    // One-time migration of legacy localStorage state (Parallelized)
    async function migrateLegacyState() {
        const MIGRATION_KEY = 'efb_state_migration_v2';
        if (localStorage.getItem(MIGRATION_KEY) === 'done') return;

        const storages = [
            { key: 'efb_log_state', encrypted: true },
            { key: 'efb_log_state_fallback', encrypted: false },
            { key: 'efb_log_state_plain', encrypted: false }
        ];

        // Process all storage migrations concurrently for speed
        await Promise.all(storages.map(async ({ key, encrypted }) => {
            const raw = localStorage.getItem(key);
            if (!raw) return;

            try {
                let state;
                if (encrypted) {
                    state = await decryptData(raw).catch(() => null);
                } else {
                    state = JSON.parse(raw);
                }
                
                if (!state) return;

                if (state.routeStructure !== undefined || state.waypointUserValues !== undefined) {
                    delete state.routeStructure;
                    delete state.waypointUserValues;
                    
                    const toSave = encrypted ? await encryptData(state) : JSON.stringify(state);
                    localStorage.setItem(key, toSave);
                }
            } catch (e) {
                console.warn(`Failed to migrate ${key}:`, e);
            }
        }));

        localStorage.setItem(MIGRATION_KEY, 'done');
    }

    // High-speed Database cleanup utility
    async function cleanupOrphanedOrders() {
        try {
            const db = await getDB();
            if (!db.objectStoreNames.contains('ofp_orders') || !db.objectStoreNames.contains('ofps')) return;
            
            const tx = db.transaction(["ofps", "ofp_orders"], "readwrite");
            const ofpsStore = tx.objectStore("ofps");
            const ordersStore = tx.objectStore("ofp_orders");
            
            // Get ALL valid IDs instantly (No heavy PDF data fetching)
            const validIds = new Set(await new Promise(res => {
                const req = ofpsStore.getAllKeys();
                req.onsuccess = () => res(req.result);
            }));

            // Get all orders
            const orders = await new Promise(res => {
                const req = ordersStore.getAll();
                req.onsuccess = () => res(req.result);
            });
            
            if (Array.isArray(orders)) {
                orders.forEach(order => {
                    if (!validIds.has(order.id)) ordersStore.delete(order.id);
                });
            }
            
            await new Promise(res => { tx.oncomplete = res; });
        } catch (e) {
            console.warn('Order cleanup failed', e);
        }
    }

    async function initializeApp() {
        // 1. PDF.js Worker Setup
        if (typeof pdfjsLib !== 'undefined') {
            pdfjsLib.GlobalWorkerOptions.workerSrc = './pdf.worker.min.js';
            const workerScript = document.createElement('script');
            workerScript.src = './pdf.worker.min.js';
            workerScript.integrity = 'sha384-cdzss87ZwpiG252tPQexupMwS1W1lTzzgy/UlNUHXW6h8aaJpBizRQk9j8Vj3zw9';
            workerScript.crossOrigin = 'anonymous';
            document.head.appendChild(workerScript);
        }

        // 2. Setup Inputs and Delegates
        addTimeInputMasks();
        if (typeof setupWaypointDelegation === 'function') setupWaypointDelegation();

        // 3. Streamlined File Upload Handler
        const fileInput = document.getElementById('ofp-file-in');
        if (fileInput) {
            fileInput.onchange = async (e) => {
                const files = Array.from(e.target.files);
                if (files.length === 0) return;
                
                setOFPLoadedState(true);
                
                if (files.length === 1) {
                    await runAnalysis(files[0], false);
                }
                
                e.target.value = ''; // Reset input
            };
        }
        
        // 4. Efficient Event Binding for Real-Time Calculations
        const bindGroup = (ids, handler) => {
            ids.forEach(id => {
                const el = document.getElementById(id);
                if (el) el.addEventListener('input', handler);
            });
        };

        bindGroup(['j-out','j-off','j-on','j-in'], debounce(calculateTripTimeForJourneyLog, 300));
        bindGroup(['j-init', 'j-uplift-w', 'j-calc-ramp', 'j-act-ramp', 'j-shut', 'j-burn', 'j-uplift-vol', 'j-disc', 'j-slip', 'j-slip-2'], debounce(calculateFuelForJourneyLog, 300));
        
        const ofpAtdInput = document.getElementById('ofp-atd-in');
        if (ofpAtdInput && typeof debouncedFullRecalc === 'function') {
            ofpAtdInput.addEventListener('input', debouncedFullRecalc);
        }
            
        const extraKgInput = document.getElementById('front-extra-kg');
        if (extraKgInput) {
            extraKgInput.addEventListener('input', debounce(() => {
                if (typeof calculatePICBlock === 'function') calculatePICBlock();
                if (typeof updateFlightLogTablesIncremental === 'function') updateFlightLogTablesIncremental();
            }, 300));
        }

        // 5. Load Journey Template
        try {
            const templateBlob = typeof loadJourneyTemplateFromDB === 'function' ? await loadJourneyTemplateFromDB() : null;
            if (templateBlob) journeyLogTemplateBytes = await templateBlob.arrayBuffer();
        } catch (e) {
            if (typeof deleteJourneyTemplateFromDB === 'function') await deleteJourneyTemplateFromDB().catch(() => {});
        }
        
        // 6. OFFLINE AUTO-LOAD LOGIC
        try {
            const activeId = localStorage.getItem('activeOFPId');
            if (activeId) {
                // Let the robust activateOFP function do all the heavy lifting
                await activateOFP(activeId, false).catch(e => {
                    console.warn("Failed to auto-activate OFP on startup:", e);
                    localStorage.removeItem('activeOFPId');
                    setOFPLoadedState(false);
                });
            } else {
                // Fallback for legacy single-store data
                const legacyBlob = typeof loadPdfFromDB === 'function' ? await loadPdfFromDB().catch(() => null) : null;
                if (!legacyBlob || legacyBlob.size === 0) {
                    setOFPLoadedState(false);
                }
            }
            // Load user persistent state (duty times, dark mode, etc)
            if (typeof loadState === 'function') await loadState();
        } catch (e) {
            console.error("Auto-load error:", e);
            if (typeof loadState === 'function') await loadState();
            setOFPLoadedState(false);
        }

        // 7. Background Cleanup & UI Routing
        await migrateLegacyState();
        await cleanupOrphanedOrders();

        const allOFPs = await getCachedOFPs();
        if (allOFPs.length > 0 && !localStorage.getItem('activeOFPId')) {
            setOFPLoadedState(false);
            const sectorsBtn = document.querySelector('.nav-btn[data-tab="sectors"], .nav-btn[onclick*="sectors"]');
            if (sectorsBtn) sectorsBtn.click();
        }

        if (typeof updateFloatingButtonVisibility === 'function') updateFloatingButtonVisibility();
    }

    async function getOFPById(id) {
        const db = await getDB();
        return new Promise((resolve, reject) => {
            const request = db.transaction("ofps", "readonly").objectStore("ofps").get(Number(id));
            request.onsuccess = () => request.result ? resolve(request.result) : reject(new Error(`OFP ${id} not found`));
            request.onerror = (e) => reject(e.target.error);
        });
    }

    window.deleteOFP = async function(id) {
        const confirmed = await showConfirmDialog('Delete OFP', 'Are you sure you want to delete this OFP?', 'Delete', 'Cancel', 'error');
        if (!confirmed) return;
        
        try {
            await deleteOFPFromDB(id);
            // Fetch cached list ONCE instead of multiple times
            const remainingOFPs = await getCachedOFPs(true); 
            
            if (localStorage.getItem('activeOFPId') === String(id)) {
                localStorage.removeItem('activeOFPId');
                
                if (remainingOFPs.length == 0) {
                    setOFPLoadedState(false);
                    clearOFPInputs();
                    window.ofpPdfBytes = null;
                }
            }
            
            await renumberOFPOrders();
            await renderOFPMangerTable();
            showToast("OFP deleted", 'success');
            if (typeof updateUploadButtonVisibility === 'function') updateUploadButtonVisibility();
        } catch (error) {
            console.error("Error deleting OFP:", error);
            showToast("Failed to delete OFP", 'error');
        }
    };

    window.clearAllOFPs = async function() {
        const confirmed = await showConfirmDialog('Clear All OFPs', 'This will delete ALL stored OFPs. Continue?', 'Clear All', 'Cancel', 'error');
        if (!confirmed) return;
        
        try {
            await clearAllOFPsFromDB();
            await getCachedOFPs(true);
            setOFPLoadedState(false);
            localStorage.removeItem('activeOFPId'); // Ensure active ID is wiped
            clearOFPInputs();
            await renderOFPMangerTable();
            showToast("All OFPs cleared", 'success');
        } catch (error) {
            console.error("Error clearing OFPs:", error);
            showToast("Failed to clear OFPs", 'error');
        }
    };

    window.activateOFP = async function(id, switchTab = true) {
        if (isActivating) return showToast('Activation in progress', 'info');
        isActivating = true;

        try {
            const numericId = Number(id);
            if (isNaN(numericId)) throw new Error('Invalid OFP ID');

            // Single unified retry loop to grab the full OFP data
            let ofp = null;
            for (let attempt = 1; attempt <= 3; attempt++) {
                try {
                    ofp = await getOFPById(numericId);
                    if (ofp && ofp.data) break;
                } catch (err) {
                    if (attempt === 3) throw new Error(`OFP ${numericId} data not found after 3 attempts`);
                }
                await new Promise(r => setTimeout(r, 200));
            }

            if (ofp.finalized) return; // Ignore locked OFPs

            // Lock in active state and prep UI
            localStorage.setItem('activeOFPId', numericId);
            if (typeof clearOFPInputs === 'function') clearOFPInputs();
            setOFPLoadedState(true);

            window.ofpPdfBytes = await ofp.data.arrayBuffer();
            window.originalFileName = ofp.fileName || "Logged_OFP.pdf";
            
            // Run analysis to rebuild the base PDF parameters
            await runAnalysis(ofp.data, true);

            // Fetch user inputs (handles new database store AND legacy fallback)
            const userData = await loadOFPUserData(numericId) || {};
            const waypointsToRestore = userData.userWaypoints || ofp.userWaypoints || [];
            const inputsToRestore = userData.userInputs || ofp.userInputs || {};

            // 1. Restore Waypoint Logs
            if (waypointsToRestore.length > 0 && typeof waypoints !== 'undefined') {
                waypointsToRestore.forEach((data, i) => {
                    if (i < waypoints.length) {
                        if (data.ato) safeSet(`o-a-${i}`, data.ato);
                        if (data.fuel) safeSet(`o-f-${i}`, data.fuel);
                        if (data.notes) safeSet(`o-n-${i}`, data.notes);
                        if (data.agl) safeSet(`o-agl-${i}`, data.agl);
                    }
                });
                if (typeof runFlightLogCalculations === 'function') runFlightLogCalculations();
                if (typeof syncLastWaypoint === 'function') syncLastWaypoint();
            }

            // 2. Restore Standard Inputs
            if (Object.keys(inputsToRestore).length > 0) {
                const drawings = ['signature', 'front-atis-drawing', 'front-atc-drawing'];
                Object.keys(inputsToRestore).forEach(inputId => {
                    if (!drawings.includes(inputId)) safeSet(inputId, inputsToRestore[inputId]);
                });

                // 3. Restore Drawings (Needs brief delay for Canvas to render)
                setTimeout(() => {
                    if (inputsToRestore.signature && pads?.main?.pad) pads.main.pad.fromDataURL(inputsToRestore.signature);
                    if (inputsToRestore['front-atis-drawing'] && pads?.atis?.pad) pads.atis.pad.fromDataURL(inputsToRestore['front-atis-drawing']);
                    if (inputsToRestore['front-atc-drawing'] && pads?.atc?.pad) pads.atc.pad.fromDataURL(inputsToRestore['front-atc-drawing']);
                }, 200);
            }

            // MIGRATION CLEAR-OUT: Move legacy data to the new DB format and wipe it from the main object
            if (ofp.userWaypoints || ofp.userInputs) {
                await saveOFPUserData(numericId, waypointsToRestore, inputsToRestore);
                await updateOFP(numericId, { userWaypoints: undefined, userInputs: undefined });
            }

            // Final UI Switch
            await renderOFPMangerTable();
            if (switchTab) {
                const summaryBtn = document.querySelector('.nav-btn[data-tab="summary"], .nav-btn[onclick*="summary"]');
                if (summaryBtn) (typeof window.showTab === 'function') ? window.showTab('summary', summaryBtn) : summaryBtn.click();
            }

            showToast(`Activated: ${ofp.flight}`, 'success');
            if (typeof updateUploadButtonVisibility === 'function') updateUploadButtonVisibility();
            if (typeof updateEmptyStates === 'function') await updateEmptyStates();

        } catch (error) {
            showToast(`Failed to activate OFP: ${error.message}`, 'error');
        } finally {
            isActivating = false;
        }
    };

    async function prepareForManualUpload() {
        if (typeof clearOFPInputs === 'function') clearOFPInputs();
        const legForm = document.getElementById('leg-input-form');
        if (legForm) legForm.style.display = 'block';
    }

    async function handleReplacement(existingOFP, blob, metadata, previouslyActiveId, isBatch) {
        const wasActive = existingOFP.isActive || false;
        const isActiveState = isBatch ? false : wasActive; // Batches never activate

        await updateOFP(existingOFP.id, {
            data: blob,
            fileName: blob.name || "Logged_OFP.pdf",
            uploadTime: new Date().toISOString(),
            ...metadata,
            finalized: false,
            loggedPdfData: null,
            isActive: isActiveState,
            order: existingOFP.order
        });

        if (isBatch && wasActive) localStorage.removeItem('activeOFPId');
        await getCachedOFPs(true);

        // If a single file upload bumped out an inactive file, re-activate the real active file.
        if (!wasActive && !isBatch && previouslyActiveId && previouslyActiveId !== String(existingOFP.id)) {
            await activateOFP(previouslyActiveId, false);
        }

        setOFPLoadedState(isActiveState);
        showToast(`OFP updated: ${metadata.flight} ${isActiveState ? '(active)' : '(inactive)'}`, 'success');
    }

    async function handleNewOFP(blob, metadata, isBatch) {
        const currentActiveId = localStorage.getItem('activeOFPId');
        const shouldActivate = !currentActiveId && !isBatch; // Only auto-activate if nothing else is active AND it's not a batch

        await saveOFPToDB(blob, metadata, shouldActivate);
        await getCachedOFPs(true);

        setOFPLoadedState(shouldActivate);
        
        if (shouldActivate) {
            showToast(`OFP saved & activated: ${metadata.flight}`, 'success');
        } else {
            // Restore previous active if it wasn't a batch upload
            if (currentActiveId && !isBatch) await activateOFP(currentActiveId, false);
            showToast(`OFP saved ${currentActiveId ? '(inactive)' : ''}: ${metadata.flight}`, 'success');
        }
    }

    function clearOFPInputs() {
        if (typeof PERSISTENT_INPUT_IDS !== 'undefined') {
            PERSISTENT_INPUT_IDS.forEach(id => safeSet(id, ''));
        }
        safeSet('ofp-atd-in', '');

        waypoints = []; 
        alternateWaypoints = []; 
        fuelData = []; 
        blockFuelValue = 0;
            
        // Reset Tables
        ['ofp-tbody', 'altn-tbody', 'fuel-tbody'].forEach(id => {
            const tb = document.getElementById(id);
            if(tb) tb.innerHTML = '';
        });
        
        // Reset Text Displays (-)
        ['view-min-block', 'view-pic-block', 'view-mtow', 'view-mlw', 'view-mzfw', 'view-mpld', 'view-fcap', 'view-dow', 'view-tow', 'view-lw', 'view-zfw', 'view-flt', 'view-reg', 'view-date', 'view-std-text', 'view-sta-text', 'view-dep', 'view-dest', 'view-altn', 'view-altn2', 'view-dest-route', 'view-altn-route', 'view-ci', 'view-etd-text', 'view-eta-text', 'view-era', 'view-crz-wind-temp', 'view-seats-stn-jmp'].forEach(id => safeText(id, '-'));

        if (pads?.atis?.pad) pads.atis.pad.clear();
        if (pads?.atc?.pad) pads.atc.pad.clear();
        
        waypointATOCache = [];
        alternateATOCache = [];
        waypointFuelCache = [];
        takeoffFuelInput = null;
        waypointTableCache = { waypoints: [], alternateWaypoints: [], lastUpdate: 0 };
    }

// ==========================================
// 4. VALIDATIONS
// ==========================================
    
    window.validateOFPInputs = function() {
        const flt = el('j-flt')?.value;
        const date = el('j-date')?.value;
        const alt1 = el('front-altm1')?.value;
        const summaryOK = !!flt && !!date && !!alt1;
        const fuelOK = (blockFuelValue > 0);

        let flightLogOK = false;
        const atoInputs = document.querySelectorAll('[id^="o-a-"]');
        for (let input of atoInputs) {
            if (input.value && input.value.trim() !== '') {
                flightLogOK = true;
                break;
            }
        }

        let journeyOK = false;
        const currentFlight = el('j-flt')?.value || el('view-flt')?.innerText;
        // Verify that the journey table specifically contains this flight AND has valid out/in times
        if (currentFlight && dailyLegs && dailyLegs.length > 0) {
            journeyOK = dailyLegs.some(leg => 
                leg['j-flt'] === currentFlight && leg['j-out'] && leg['j-in']
            );
        }

        const signatureOK = pads.main.pad && !pads.main.pad.isEmpty();

        const checks = [
            { label: "Flight Summary", valid: summaryOK },
            { label: "Fuel", valid: fuelOK },
            { label: "Flight Log", valid: flightLogOK },
            { label: "Journey Log (current flight)", valid: journeyOK },
            { label: "Signature", valid: signatureOK }
        ];

        const list = el('validation-list');
        if (list) {
            list.innerHTML = checks.map(c => 
                `<div class="checklist-item">
                    <span>${sanitizeHTML(c.label)}</span>
                    <span class="${c.valid ? 'status-ok' : 'status-fail'}">${c.valid ? '✔' : '✖'}</span>
                </div>`
            ).join('');
            
            const valid = checks.every(c => c.valid);
            const sendBtn = el('btn-send-ofp');
            if (sendBtn) {
                sendBtn.disabled = !valid;
            }
        }
    };

    window.validateAltimeter = function(el) {
        // Allows negative signs and up to 4 digits cleanly
        const match = el.value.match(/^-?\d{0,4}/);
        if (match) el.value = match[0];
    };

    function validateTimeInputs(timeStr, fieldName = '') {
        if (!timeStr) return { valid: true, value: '' };
        
        const isTimeField = /(Time|ATD|ATO|STD|STA|DUTY|FDP|out|off|on|in)/i.test(fieldName);
        
        if (!isTimeField) return { valid: true, value: timeStr };
        
        let cleanTime = timeStr.replace(/[^0-9:]/g, '');
        
        // Auto-insert colon for exactly 4 digits
        if (cleanTime.length === 4 && !cleanTime.includes(':')) {
            cleanTime = cleanTime.substring(0, 2) + ':' + cleanTime.substring(2, 4);
        }
        
        // Final sanity check before parsing
        const timeRegex = /^(\d{1,2}):([0-5]\d)$/;
        const match = cleanTime.match(timeRegex);
        
        if (!match) {
            throw new Error(`Invalid time format${fieldName ? ' for ' + fieldName : ''}. Use HH:MM`);
        }
        
        const hours = parseInt(match[1], 10);
        const minutes = parseInt(match[2], 10);
        
        // Ensure standard clock times (STD/STA/ATD/ATO) stay under 24
        const isClockTime = /(STD|STA|ATD|ATO|out|off|on|in)/i.test(fieldName);
        if (isClockTime && hours >= 24) {
            throw new Error(`${fieldName} time must be between 00:00 and 23:59`);
        }
        
        // Ensure cumulative duty times stay realistic
        const isDutyTime = /(DUTY|FDP)/i.test(fieldName);
        if (isDutyTime && hours > 48) {
            throw new Error(`${fieldName} cannot exceed 48 hours`);
        }
        
        // Re-pad the string nicely (e.g., "5:30" becomes "05:30")
        return { 
            valid: true, 
            value: `${hours.toString().padStart(2, '0')}:${minutes.toString().padStart(2, '0')}` 
        };
    }

    function addTimeInputMasks() {
        const timeElements = new Set();
        
        document.querySelectorAll('input[type="time"]').forEach(el => timeElements.add(el));
        
        ['j-out', 'j-off', 'j-on', 'j-in', 'j-night', 'j-night-calc', 'j-duty-start', 'j-cc-duty-start', 'j-max-fdp', 'j-std'].forEach(id => {
            const el = document.getElementById(id);
            if (el) timeElements.add(el);
        });
        
        for (let i = 0; i < 20; i++) {
            ['o-a-', 'a-a-'].forEach(prefix => {
                const el = document.getElementById(`${prefix}${i}`);
                if (el) timeElements.add(el);
            });
        }
        
        timeElements.forEach(input => {
            if (!input.placeholder) input.placeholder = 'HH:MM';
            
            // Allow numeric keyboards to trigger natively on mobile
            input.pattern = '[0-9]*'; 
            input.inputMode = 'numeric';
            
            input.addEventListener('input', function(e) {
                // Ignore formatting if user is explicitly deleting characters
                if (e.inputType === 'deleteContentBackward') return;
                
                let value = e.target.value.replace(/[^0-9]/g, '');
                
                if (value.length > 4) value = value.substring(0, 4);
                if (value.length > 2) value = value.substring(0, 2) + ':' + value.substring(2);
                
                e.target.value = value;
            });
        });
    }

    function handleWaypointInput(e) {
        const target = e.target;
        const id = target.id;
        if (!id) return;

        if (id.startsWith('o-a-') || id.startsWith('a-a-')) {
            const [prefix, , idx] = id.split('-');
            const index = parseInt(idx, 10);
            const isTO = (index === 0 && prefix === 'o');
            
            if (isTO) {
                try {
                    const validated = validateTimeInputs(target.value, 'Takeoff Time');
                    target.value = validated.value;
                    updateTakeoffTime(validated.value);
                    debouncedFullRecalc();
                } catch (error) {
                    alert(error.message);
                    target.value = '';
                }
            } else {
                debouncedSyncLastWaypoint();
            }
            debouncedSave();
        }
        else if (id.startsWith('o-f-') || id.startsWith('a-f-')) {
            const [prefix, , idx] = id.split('-');
            const index = parseInt(idx, 10);
            const isTO = (index === 0 && prefix === 'o');
            
            if (isTO) runFlightLogCalculations();
            
            debouncedSyncLastWaypoint();
            debouncedSave();
        }
        else if (id.startsWith('o-n-') || id.startsWith('a-n-')) {
            debouncedSave();
        }
        else if (id.startsWith('o-agl-') || id.startsWith('a-agl-')) {
            debouncedUpdateCruiseLevel();
            debouncedSave();
        }
    }

    function handleWaypointChange(e) {
        const target = e.target;
        const id = target.id;
        if (!id) return;

        if (id.startsWith('o-a-') || id.startsWith('a-a-')) {
            try {
                // Ensure fieldName is passed so the validation knows to check the hours!
                const validated = validateTimeInputs(target.value, 'ATO');
                target.value = validated.value;
            } catch (error) {
                alert(error.message);
                target.value = '';
            }
        }
    }

    function setupWaypointDelegation() {
        // Grouping listeners onto the shared parent tables
        ['ofp-tbody', 'altn-tbody'].forEach(id => {
            const tbody = document.getElementById(id);
            if (tbody) {
                tbody.addEventListener('input', handleWaypointInput);
                tbody.addEventListener('change', handleWaypointChange);
            }
        });
    }

// ==========================================
// 5. DATA EXTRACTION FROM OFP
// ==========================================
    
    async function getLinesFromPDFPage(page) {
        const content = await page.getTextContent();
        const items = content.items;
        
        // Group items by their vertical Y coordinate
        const linesObj = {};
        items.forEach(item => {
            const y = Math.round(item.transform[5]); 
            if (!linesObj[y]) linesObj[y] = [];
            linesObj[y].push(item);
        });

        // Sort Y coordinates top to bottom
        const yCoords = Object.keys(linesObj).sort((a, b) => b - a);

        // Sort items left-to-right and join into clean string lines
        return yCoords.map(y => {
            const lineItems = linesObj[y].sort((a, b) => a.transform[4] - b.transform[4]);
            return lineItems.map(item => item.str).join(' ').replace(/\s+/g, ' ').trim();
        });
    }

    function extractFuelData(lines) {
        fuelData = []; blockFuelValue = 0;
        
        lines.forEach(line => {
            if (line.startsWith('ALTN ')) {
                const m = line.match(/ALTN\s+([A-Z]{3,4})\s+([\d.]+)\s+(\d+)/);
                if (m) fuelData.push({ name: "ALTN", time: m[2], fuel: m[3], remarks: m[1] });
            } 
            else if (line.startsWith('FINAL RESERVE')) {
                const m = line.match(/FINAL RESERVE\s+([\d.]+)\s+(\d+)/);
                if (m) fuelData.push({ name: "FINAL RESERVE", time: m[1], fuel: m[2], remarks: "" });
            } 
            else if (line.startsWith('MIN DIVERSION')) {
                const m = line.match(/MIN DIVERSION\s+([\d.]+)\s+(\d+)/);
                if (m) fuelData.push({ name: "MIN DIVERSION", time: m[1], fuel: m[2], remarks: "" });
            } 
            else if (line.startsWith('CONTINGENCY')) {
                const m = line.match(/CONTINGENCY\s+(?:(\d+%\s*(?:ERA)?|5M)\s+)?([\d.]+)\s+(\d+)/);
                if (m) fuelData.push({ name: "CONTINGENCY", time: m[2], fuel: m[3], remarks: m[1] || "" });
            } 
            else if (line.startsWith('MIN ADDITIONAL')) {
                const m = line.match(/MIN ADDITIONAL\s+([\d.]+)\s+(\d+)/);
                if (m) fuelData.push({ name: "MIN ADDITIONAL", time: m[1], fuel: m[2], remarks: "" });
            } 
            else if (line.startsWith('TOTAL RESERVE')) {
                const m = line.match(/TOTAL RESERVE\s+([\d.]+)\s+(\d+)/);
                if (m) fuelData.push({ name: "TOTAL RESERVE", time: m[1], fuel: m[2], remarks: "" });
            } 
            else if (line.startsWith('TRIP')) {
                const m = line.match(/TRIP\s+([\d.]+)\s+(\d+)/);
                if (m) fuelData.push({ name: "TRIP", time: m[1], fuel: m[2], remarks: "" });
            } 
            else if (line.startsWith('ENDURANCE')) {
                const m = line.match(/ENDURANCE\s+([\d.]+)\s+(\d+)/);
                if (m) fuelData.push({ name: "ENDURANCE", time: m[1], fuel: m[2], remarks: "" });
            } 
            else if (line.startsWith('TAXI')) {
                const m = line.match(/TAXI\s+(\d+)/);
                if (m) fuelData.push({ name: "TAXI", time: "-", fuel: m[1], remarks: "" });
            } 
            else if (line.startsWith('EXTRA')) {
                const m = line.match(/EXTRA\s+([\d.]+)\s+(\d+)/);
                if (m) fuelData.push({ name: "EXTRA", time: m[1], fuel: m[2], remarks: "" });
            } 
            else if (line.startsWith('TANKERING')) {
                const m = line.match(/TANKERING\s+([\d.]+)\s+(\d+)/);
                if (m) fuelData.push({ name: "TANKERING", time: m[1], fuel: m[2], remarks: "" });
            } 
            else if (line.startsWith('BLOCK FUEL')) {
                const m = line.match(/BLOCK FUEL\s+([\d.]+)\s+(\d+)/);
                if (m) {
                    fuelData.push({ name: "BLOCK FUEL", time: m[1], fuel: m[2], remarks: "" });
                    blockFuelValue = parseInt(m[2]);
                }
            } 
            else if (line.startsWith('MINIMUM BLOCK')) {
                const m = line.match(/MINIMUM BLOCK\s+(\d+)/);
                if (m) safeText('view-min-block', m[1] + " kg");
            }
        });
    }

    function extractWeights(lines) {
        if (!lines || !Array.isArray(lines)) return;

        // Join lines into a single searchable string
        const fullText = lines.map(l => l.replace(/[\u200B-\u200D\uFEFF]/g, '').trim()).join(' ');

        const weightMap = {
            'view-mtow': '-', 'view-mlw': '-', 'view-mzfw': '-', 'view-mpld': '-', 'view-fcap': '-', 'view-dow': '-',
            'view-tow': '-', 'view-lw': '-', 'view-zfw': '-', 'view-pld': '-'
        };

        // Key-Value map matching exact headers to their numbers on the same line
        const mappings = [
            { id: 'view-mtow', key: 'MTOW' },
            { id: 'view-mlw',  key: 'MLW'  },
            { id: 'view-mzfw', key: 'MZFW' },
            { id: 'view-mpld', key: 'MPLD' },
            { id: 'view-fcap', key: 'FCAP' },
            { id: 'view-dow',  key: 'DOW'  },
            { id: 'view-tow',  key: 'TOW'  },
            { id: 'view-lw',   key: 'LW'   },
            { id: 'view-zfw',  key: 'ZFW'  },
            { id: 'view-pld',  key: 'PLD'  }
        ];

        mappings.forEach(item => {
            // Match word boundary + Label + optional space/colon + 4-to-5 digit number
            // Using negative lookbehind (?<!M) for TOW so it doesn't trigger on MTOW
            let pattern;
            if (item.key === 'TOW') {
                pattern = /(?<!M)\bTOW\s+(\d{4,5})\b/i;
            } else if (item.key === 'ZFW') {
                pattern = /(?<!M)\bZFW\s+(\d{4,5})\b/i;
            } else if (item.key === 'PLD') {
                pattern = /(?<!M)\bPLD\s+(\d{4,5})\b/i;
            } else if (item.key === 'LW') {
                pattern = /(?<!M)\bLW\s+(\d{4,5})\b/i;
            } else {
                pattern = new RegExp(`\\b${item.key}\\s+(\\d{4,5})\\b`, 'i');
            }

            const match = fullText.match(pattern);
            if (match) {
                weightMap[item.id] = match[1];
            }
        });

        // Safe DOM Injection
        Object.keys(weightMap).forEach(id => {
            safeText(id, weightMap[id]);
        });
    }

    function extractRoutes(lines) {
        if (!lines || !Array.isArray(lines)) return;

        // Reconstruct the full text block so split line tokens don't break string matching
        const fullText = lines.map(l => l.replace(/[\u200B-\u200D\uFEFF]/g, '').trim()).join(' ');

        let destRoute = '-', altnRoute = '-', altn2Route = '-';

        // 1. Extract DEST ROUTE
        // Matches "DEST ROUTE:" up until ALTN ROUTE, FUEL, or REMARKS
        const destMatch = fullText.match(/\bDEST\s+ROUTE[:\s]+([\s\S]*?)(?=\bALTN\s*1?\s+ROUTE\b|\bALTN\s*2\s+ROUTE\b|\bFUEL\b|\bRMK\b|\bREMARKS?\b|$)/i);
        if (destMatch && destMatch[1]) {
            destRoute = destMatch[1].replace(/\s+/g, ' ').trim();
        }

        // 2. Extract ALTN / ALTN1 ROUTE
        const altnMatch = fullText.match(/\bALTN\s*1?\s+ROUTE[:\s]+([\s\S]*?)(?=\bALTN\s*2\s+ROUTE\b|\bFUEL\b|\bRMK\b|\bREMARKS?\b|$)/i);
        if (altnMatch && altnMatch[1]) {
            altnRoute = altnMatch[1].replace(/\s+/g, ' ').trim();
        }

        // 3. Extract ALTN2 ROUTE (if present)
        const altn2Match = fullText.match(/\bALTN\s*2\s+ROUTE[:\s]+([\s\S]*?)(?=\bFUEL\b|\bRMK\b|\bREMARKS?\b|$)/i);
        if (altn2Match && altn2Match[1]) {
            altn2Route = altn2Match[1].replace(/\s+/g, ' ').trim();
        }

        // Clean up any stray trailing colons or punctuation
        const clean = (str) => {
            if (!str || str === '-') return '-';
            let s = str.trim();
            if (s.startsWith(':')) s = s.substring(1).trim();
            return s || '-';
        };

        // DOM Injection
        safeText('view-dest-route', clean(destRoute));
        safeText('view-altn-route', clean(altnRoute));

        const altn2Id = document.getElementById('view-altn2-route') ? 'view-altn2-route' : 'view-altn2';
        safeText(altn2Id, clean(altn2Route));
    }
    
    function extractAdditionalFlightInfo(lines) {
        let row1Text = "-", row2Text = "-", maxSR = "";
        
        const row1Line = lines.find(l => l.includes('CRZ WIND') && l.includes('AVG TEMP'));
        if (row1Line) {
            const match = row1Line.match(/CRZ WIND\s+(.*?)\s+AVG TEMP\s+(.*?)\s+ISA DEV\s+(.*?)\s+LOWEST TEMP\s+(.*?)\s+MAX SR\s+(\d+)/i);
            if (match) {
                maxSR = match[5];
                row1Text = `CRZ WIND ${match[1]} AVG TEMP ${match[2]} ISA DEV ${match[3]} LOWEST TEMP ${match[4]} MAX SR ${match[5]}`;
            }
        }
        
        const row2Line = lines.find(l => l.includes('IDLE/PERF') && l.includes('SEATS'));
        if (row2Line) {
            const match = row2Line.match(/IDLE\/PERF\s+(.*?)\s+SEATS\s+(.*?)\s+STN\s+(.*?)\s+JMP\s+(\d+)/i);
            if (match) {
                row2Text = `IDLE/PERF ${match[1]} SEATS ${match[2]} STN ${match[3]} JMP ${match[4]}`;
            } else {
                row2Text = row2Line; // Fallback to raw line
            }
        }
        
        safeText('view-crz-wind-temp', row1Text);
        safeText('view-seats-stn-jmp', row2Text);
        
        return { row1: row1Text, row2: row2Text, maxSR: maxSR };
    }

    function extractMetadataFromUI() {
        let tripTime = '';
        
        // Try getting trip time from fuelData array first
        const tripEntry = fuelData.find(item => item.name === "TRIP");
        if (tripEntry && tripEntry.time) {
            tripTime = tripEntry.time.replace('.', ':');
        } else {
            // Fallback to DOM only if array is empty
            const tripRow = Array.from(document.querySelectorAll('#fuel-tbody tr'))
                                 .find(row => row.cells[0]?.innerText === 'TRIP');
            if (tripRow) tripTime = tripRow.cells[1].innerText;
        }

        // Clean DOM extraction for the rest
        const crzEl = document.getElementById('view-crz-wind-temp');
        const maxSR = (crzEl?.innerText || '').match(/MAX SR\s+(\d{1,2})/i)?.[1] || '';

        return {
            flight: document.getElementById('view-flt')?.innerText || 'N/A',
            date: document.getElementById('view-date')?.innerText || 'N/A',
            dep: document.getElementById('view-dep')?.innerText || 'N/A',
            dest: document.getElementById('view-dest')?.innerText || 'N/A',
            tripTime,
            maxSR
        };
    }

    function extractMainPageCoordinates(items) {
        // Optimized to stop checking once it finds a match for a specific item
        items.forEach(item => {
            const raw = item.str.toUpperCase();
            if (raw.includes('ALTM1')) frontCoords.altm1 = item;
            else if (raw.includes('ALTM2')) frontCoords.altm2 = item;
            else if (raw.includes('ATIS')) frontCoords.atis = item;
            else if (raw.includes('CLRNC')) frontCoords.atcLabel = item;
            else if (raw.includes('STBY')) frontCoords.stby = item;
            else if (raw.includes('PIC') && raw.includes('BLOCK')) frontCoords.picBlockLabel = item;
            else if (raw.includes('REASON')) frontCoords.reasonLabel = item;
        });
    }

    function processWaypointsList() {
        const dest = document.getElementById('view-dest')?.innerText || "ZZZZ";
        let splitIndex = -1;

        // Attempt 1: Split at Destination Name
        splitIndex = waypoints.findIndex(wp => wp.name === dest);
        if (splitIndex !== -1) splitIndex += 1; // Include the dest waypoint

        // Attempt 2: Mathematical / Phase fallback
        if (splitIndex === -1) {
            for (let i = 1; i < waypoints.length; i++) {
                const fuelDrop = waypoints[i-1].fob - waypoints[i].fob;
                // If fuel drops dramatically, or we hit Top Of Descent
                if ((fuelDrop > 1000 && fuelDrop > (waypoints[i-1].fob * 0.1))) {
                    splitIndex = i; break;
                }
                if (waypoints[i].name.includes('TOD') || waypoints[i].name.includes('DES')) {
                    splitIndex = i + 1; break;
                }
            }
        }

        // Apply the split
        if (splitIndex > 0 && splitIndex < waypoints.length) {
            alternateWaypoints = waypoints.slice(splitIndex);
            waypoints = waypoints.slice(0, splitIndex);
        } else {
            alternateWaypoints = [];
        }
    }

    function extractRequestNumber(textOrLines) {
        // Accepts either our new array format or legacy strings
        const lines = Array.isArray(textOrLines) ? textOrLines : textOrLines.split('\n');
        
        // Find the line holding the request, then extract it instantly
        const reqLine = lines.find(line => /REQUEST\s*#\s*\d+/i.test(line));
        if (reqLine) {
            const match = reqLine.match(/REQUEST\s*#\s*(\d+)/i);
            return match ? match[1] : '';
        }
        return '';
    }

    function extractNOTAMs(fullText) {
        // Convert to array if passed as legacy string
        const lines = Array.isArray(fullText) ? fullText : fullText.split('\n');
        const notams = [];
        let currentNotam = null;

        // Triggers to start/stop saving a NOTAM block
        const notamStartRegex = /^(?:-\s*)?([A-Z]{4})\s+([A-Z]{1,2}\d{4}\/\d{2})|^NOTAM\s*([A-Z]{4})\s+([A-Z]{1,2}\d{4}\/\d{2})/i;
        const stopMarkers = ['ARRIVAL:', 'OTHER:', 'DEPARTURE:', '---', 'PAGE', 'FLY ARYSTAN BRIEF', 'AIR ASTANA BRIEF', 'FIR:', 'REGION:', 'NOT CLASSIFIED', 'FIRE AND RESCUE'];

        lines.forEach(line => {
            const trimmed = line.trim();
            if (!trimmed) return;
            const upper = trimmed.toUpperCase();

            // 1. Did we hit a stop marker? Dump the buffer and stop tracking.
            if (stopMarkers.some(m => upper.startsWith(m))) {
                if (currentNotam) { notams.push(currentNotam.join('\n')); currentNotam = null; }
                return;
            }

            // 2. Did we find the start of a new NOTAM? Save the old one and start a new buffer.
            if (notamStartRegex.test(trimmed)) {
                if (currentNotam) notams.push(currentNotam.join('\n'));
                currentNotam = [trimmed];
            } 
            // 3. Are we currently inside a NOTAM? Keep saving lines to the buffer.
            else if (currentNotam) {
                currentNotam.push(trimmed);
            }
        });
        
        // Push the final one in the buffer
        if (currentNotam) notams.push(currentNotam.join('\n'));

        // Filter valid NOTAMs based on strict aviation keywords
        const keywords = ['RWY', 'TWY', 'CLSD', 'U/S', 'NOT AVBL', 'WIP', 'FIRE', 'BIRD', 'BA', 'ICE', 'SNOW', 'SLUSH', 'ILS', 'VOR', 'NDB', 'DME', 'RNAV', 'GPS', 'RNP', 'APU', 'DE-ICING', 'STAND', 'ACFT', 'RWYCC', 'FROST', 'POOR', 'MEDIUM', 'NIL'];
        
        return notams.filter(n => {
            const up = n.toUpperCase();
            return n.length > 20 && keywords.some(kw => up.includes(kw));
        });
    }

    function extractWeather(fullText) {
        // Convert to array if passed as legacy string
        const lines = Array.isArray(fullText) ? fullText : fullText.split('\n');
        const weather = [];
        let currentWx = null;

        const wxStartRegex = /^(METAR|SPECI|TAF(?:\s+AMD)?)\s+([A-Z]{4})\b/i;
        const stopMarkers = ['OTHER:', 'DEPARTURE:', 'ARRIVAL:', '---', 'AIR ASTANA BRIEF', 'PAGE', 'NO AIRMET', 'NO PIREP', 'AIRMET', 'PIREP', 'FIR:', 'REGION:', 'NO TAF'];

        lines.forEach(line => {
            const trimmed = line.trim();
            if (!trimmed) return;
            const upper = trimmed.toUpperCase();

            // Stop markers or explicit "NO TAF" declarations
            if (stopMarkers.some(m => upper.startsWith(m)) || upper.includes('NO TAF')) {
                if (currentWx) { weather.push(currentWx.join('\n')); currentWx = null; }
                return;
            }

            if (wxStartRegex.test(trimmed)) {
                if (currentWx) weather.push(currentWx.join('\n'));
                currentWx = [trimmed];
            } else if (currentWx) {
                currentWx.push(trimmed);
            }
        });

        if (currentWx) weather.push(currentWx.join('\n'));

        // Drop any that are too short to be real weather
        return weather.filter(w => w.length > 20);
    }

    function cleanNOTAMText(text) {
        // Condense the 3 legacy regex passes into 1 smart sweep
        const match = text.match(/NOTAM\s*([A-Z]{4})/i) || 
                      text.match(/^[-–—\s]*([A-Z]{4})\b/) || 
                      text.match(/([A-Z]{4})$/);
                      
        if (match) {
            const airport = match[1].toUpperCase();
            // Dynamically rip the airport code out of the text, regardless of where it is
            const regexToRemove = new RegExp(`(?:NOTAM\\s*|^[-–—\\s]*|\\s*)${airport}(?:\\b|$)`, 'i');
            const cleaned = text.replace(regexToRemove, '').trim();
            return { airport, text: cleaned };
        }
        
        return { airport: 'Unknown', text };
    }

// ==========================================
// 5. CALCULATION LOGIC
// ==========================================
    
    window.runFlightLogCalculations = function() {
        const atd = el('ofp-atd-in')?.value || el('o-a-0')?.value || el('j-off')?.value;
        
        // 1. Find Taxi Fuel efficiently
        let taxiFuel = 200;
        if (typeof fuelData !== 'undefined' && Array.isArray(fuelData)) {
            const taxiEntry = fuelData.find(item => item.name === "TAXI");
            if (taxiEntry && taxiEntry.fuel) taxiFuel = parseInt(taxiEntry.fuel) || 200;
        }

        // 2. Find the latest ATO using our cache (no DOM lookups)
        let lastAtoMins = -1;
        let lastAtoIndex = -1;
        for (let i = waypoints.length - 1; i >= 0; i--) {
            const atoValue = waypointATOCache[i]?.value;
            if (atoValue) {
                const [h, m] = atoValue.split(':').map(Number);
                lastAtoMins = h * 60 + m;
                lastAtoIndex = i;
                break;
            }
        }

        // 3. Determine start fuel
        const pdfTakeoffFuel = waypoints[0]?.baseFuel ?? parseInt(waypoints[0]?.fob) ?? 0;
        const picBlockEl = el('view-pic-block');
        const picBlock = parseInt(picBlockEl?.value || picBlockEl?.textContent) || blockFuelValue || 0;
        
        const currentStartFuel = (takeoffFuelInput && takeoffFuelInput.value) 
            ? parseInt(takeoffFuelInput.value) || 0
            : (picBlock - taxiFuel);

        const delta = currentStartFuel - pdfTakeoffFuel;

        // 4. Update Waypoints Calculation
        waypoints.forEach((wp, index) => {
            if (wp.baseFuel === undefined) wp.baseFuel = parseInt(wp.fob) || 0;
            if (wp.baseFuel > 0) wp.fuel = wp.baseFuel + delta;

            if (index === 0 && wp.name === "TAKEOFF") {
                wp.eto = atd ? atd.replace(':', '') : "";
            } 
            else if (lastAtoIndex !== -1 && index > lastAtoIndex) {
                // Ripple Calculation
                const newEtoMins = lastAtoMins + (wp.totalMins - waypoints[lastAtoIndex].totalMins);
                const h = Math.floor((newEtoMins / 60) % 24).toString().padStart(2, '0');
                const m = Math.floor(newEtoMins % 60).toString().padStart(2, '0');
                wp.eto = h + m;
            } 
            else if (atd) {
                // Standard Calculation
                const [h, m] = atd.split(':').map(Number);
                const targetMins = (h * 60 + m) + wp.totalMins;
                const hh = Math.floor((targetMins / 60) % 24).toString().padStart(2, '0');
                const mm = Math.floor(targetMins % 60).toString().padStart(2, '0');
                wp.eto = hh + mm;
            } else {
                wp.eto = "";
            }
        });

        if (typeof updateAlternateETOs === 'function') updateAlternateETOs();
        if (typeof updateFlightLogTablesIncremental === 'function') updateFlightLogTablesIncremental();
        if (typeof updateAlternateTableIncremental === 'function') updateAlternateTableIncremental();
        
        if (typeof waypointTableCache !== 'undefined') waypointTableCache.lastUpdate = Date.now();
    };

    function calculatePICBlock() {
        const extraInput = el('front-extra-kg');
        const extra = parseInt(extraInput?.value) || 0;
        
        if (blockFuelValue > 0 || extra > 0) {
            safeSet('view-pic-block', (blockFuelValue + extra));
        } else {
            safeSet('view-pic-block', '');
        }
    }

    window.calculateExtraFromTotal = function() {
        const totalInput = el('view-pic-block');
        const extraInput = el('front-extra-kg');
        
        if (typeof blockFuelValue === 'undefined' || blockFuelValue === 0) return;
        
        const picTotal = parseInt(totalInput?.value) || 0;
        
        // Update the extra input field directly
        if (extraInput) extraInput.value = (picTotal - blockFuelValue) || '';
        
        runFlightLogCalculations();
    };

    async function getOFPCount() {
        const db = await getDB();
        if (!db.objectStoreNames.contains('ofps')) return 0;
        return new Promise((resolve, reject) => {
            const req = db.transaction('ofps', 'readonly').objectStore('ofps').count();
            req.onsuccess = () => resolve(req.result);
            req.onerror = (e) => reject(e.target.error);
        });
    }

    function minsToTime(m) {
        // Normalizes negative minutes seamlessly
        const total = m < 0 ? m + (1440 * Math.ceil(Math.abs(m) / 1440)) : m;
        
        const days = Math.floor(total / 1440);
        const rm = total % 1440;
        const h = Math.floor(rm / 60).toString().padStart(2, '0');
        const min = (rm % 60).toString().padStart(2, '0');
        
        return days > 0 ? `${h}:${min} (+${days}d)` : `${h}:${min}`;
    }

    function getDiff(start, end) {
        if (!start || !end) return "";
        
        // Extremely fast, single-pass Regex parser for both "HH:MM" and "HHMM"
        const parseTime = str => {
            const match = String(str).match(/^(\d{1,2}):?(\d{2})$/);
            return match ? { h: parseInt(match[1]), m: parseInt(match[2]) } : null;
        };
        
        const t1 = parseTime(start);
        const t2 = parseTime(end);
        if (!t1 || !t2) return "";
        
        const startMins = t1.h * 60 + t1.m;
        let endMins = t2.h * 60 + t2.m;
        
        // Auto-correct for midnight rollover (e.g., 23:00 to 02:00)
        if (endMins < startMins) endMins += 1440;
        
        const diffMins = endMins - startMins;
        const h = Math.floor(diffMins / 60).toString().padStart(2, '0');
        const m = (diffMins % 60).toString().padStart(2, '0');
        
        return `${h}:${m}`;
    }

    function getCCMaxFDP() {
        return document.getElementById('j-cc-max-fdp-hidden')?.value || "00:00";
    }

    // Fast inline time parser (HH:MM -> minutes)
    const parseTimeStr = (str) => {
        if (!str || !str.includes(':')) return 0;
        const [h, m] = str.split(':').map(Number);
        return (h * 60) + m;
    };

    window.calculateFuelForJourneyLog = function() {
        // High-speed DOM reader helpers
        const v = (id) => parseFloat(el(id)?.value) || 0;
        const has = (id) => !!el(id)?.value;

        const init = v('j-init'), uplift = v('j-uplift-w');
        const act = v('j-act-ramp'), shut = v('j-shut');

        // Calc Ramp & Discrepancy
        if (has('j-init') || has('j-uplift-w')) {
            const cr = init + uplift;
            safeSet('j-calc-ramp', cr);
            safeSet('j-disc', has('j-act-ramp') ? (act - cr) : '');
        } else {
            safeSet('j-calc-ramp', '');
            safeSet('j-disc', '');
        }

        // Trip Burn
        safeSet('j-burn', (has('j-act-ramp') && has('j-shut')) ? (act - shut) : '');
    };

    window.calculateTripTimeForJourneyLog = function() {
        const outT = el('j-out')?.value, inT = el('j-in')?.value;
        const offT = el('j-off')?.value, onT = el('j-on')?.value;

        safeSet('j-block', (outT && inT) ? getDiff(outT, inT) : '');
        safeSet('j-flight', (offT && onT) ? getDiff(offT, onT) : '');

        calcDutyLogic();
    };

    window.calculateDutyValues = function(std, flt, dep, dest) {
        if (!std) return { fc: "00:00", cc: "00:00", max: "00:00", ccMax: "00:00" };

        const fltUpper = (flt || "").toUpperCase();
        const isKZR = fltUpper.includes('KZR') || fltUpper.includes('KC');
        const isAYN = fltUpper.includes('AYN') || fltUpper.includes('FS');

        const isDepKZ = (dep || "").toUpperCase().startsWith('UA');
        const isDestKZ = (dest || "").toUpperCase().startsWith('UA');

        // 1. Flight Crew offset
        let fcOffset = 60;
        if (isDepKZ) {
            if (isKZR) fcOffset = isDestKZ ? 75 : 90;
            else if (isAYN) fcOffset = isDestKZ ? 60 : 75;
        }

        // 2. Cabin Crew offset
        const ccOffset = (isKZR && isDepKZ) ? 15 : 0;

        const stdMins = parseTimeStr(std);

        // Calculate UTC reports
        const fcStartUTC = (stdMins - fcOffset + 1440) % 1440;
        const ccStartUTC = (fcStartUTC - ccOffset + 1440) % 1440;

        // Convert UTC to local Kazakhstan (UTC+5 = +300 mins) for FDP table
        const localStart = (fcStartUTC + 300) % 1440;
        const baseFDP = calculateBaseMaxFDP(localStart);
        const ccMaxFDP = baseFDP + Math.min(ccOffset, 60);

        return {
            fc: minsToTime(fcStartUTC),
            cc: minsToTime(ccStartUTC),
            max: minsToTime(baseFDP),
            ccMax: minsToTime(ccMaxFDP)
        };
    };

    window.calcDutyLogic = function() {
        let flt = (el('j-flt')?.value || "").trim();
        let dep = (el('j-dep')?.value || "").trim();
        let dest = (el('j-dest')?.value || "").trim();
        let std = (el('j-std')?.value || "").trim();

        // Fallback to daily legs array if UI is empty
        if ((!std || !flt) && dailyLegs && dailyLegs.length > 0) {
            const leg = dailyLegs[0];
            flt = leg['j-flt'] || "";
            dep = leg['j-dep'] || "";
            dest = leg['j-dest'] || "";
            std = leg['j-std'] || "";
        }

        if (!std) return;

        const dutyValues = calculateDutyValues(std, flt, dep, dest);

        const fcEl = el('j-duty-start');
        const ccEl = el('j-cc-duty-start');

        if (!fcEl?.value) safeSet('j-duty-start', dutyValues.fc);
        if (!ccEl?.value) safeSet('j-cc-duty-start', dutyValues.cc);

        dutyStartTime = parseTimeStr(el('j-duty-start')?.value);
        recalcMaxFDP();
    };

    function calculateBaseMaxFDP(localStartMins) {
        const t = localStartMins % 1440;
        
        if (t < 300 || t >= 1020) return 660; // 17:00-04:59 (Flat lowest limit)
        if (t >= 360 && t < 810) return 780;  // 06:00-13:29 (Flat max limit)
        
        // 05:00 to 05:59: Increases by 15 mins every 15-minute step
        if (t >= 300 && t < 360) return 720 + (Math.floor((t - 300) / 15) * 15);
        
        // 13:30 to 16:59: Decreases by 15 mins every 30-minute step
        if (t >= 810 && t < 1020) return 765 - (Math.floor((t - 810) / 30) * 15);
        
        return 780; // Failsafe
    }

    window.recalcMaxFDP = function() {
        const fcTimeStr = el('j-duty-start')?.value;
        if (!fcTimeStr) return;

        const ccTimeStr = el('j-cc-duty-start')?.value || fcTimeStr;
        const fcMinsUTC = parseTimeStr(fcTimeStr);
        const ccMinsUTC = parseTimeStr(ccTimeStr);
        
        dutyStartTime = fcMinsUTC;
        const sectors = dailyLegs?.length || 1;

        // Convert UTC to local KZ (+300)
        const localFcMins = (fcMinsUTC + 300) % 1440;
        const baseFDP = calculateBaseMaxFDP(localFcMins);

        // Cap reporting difference at 60 mins max
        const reportingDiff = (fcMinsUTC - ccMinsUTC + 1440) % 1440;
        const cappedDiff = Math.min(reportingDiff, 60);

        // Sector reduction math
        const sectorDrop = sectors >= 5 ? 90 : (sectors === 4 ? 60 : (sectors === 3 ? 30 : 0));
        
        const fcMax = Math.max(baseFDP - sectorDrop, 660);
        const ccMax = Math.max(baseFDP + cappedDiff - sectorDrop, 660);

        safeSet('j-max-fdp', minsToTime(fcMax));
        const ccMaxInput = el('j-cc-max-fdp-hidden');
        if (ccMaxInput) ccMaxInput.value = minsToTime(ccMax);
    };

    function setCCMaxFDP(value) {
        safeSet('j-cc-max-fdp-hidden', value || "00:00");
    }

    function calculateNightDuty(startMinsUTC, endMinsUTC) {
        if (startMinsUTC == null || endMinsUTC == null) return "00:00";

        const start = startMinsUTC;
        const end = endMinsUTC < start ? endMinsUTC + 1440 : endMinsUTC;

        // Night window UTC: 21:00 to 24:00 (1260 to 1440)
        // Check overlap for current day and potential next day (if duty crosses midnight twice)
        const windows = [
            { s: 1260, e: 1440 },
            { s: 2700, e: 2880 } // Next day window
        ];

        let overlap = 0;
        for (const w of windows) {
            const overlapStart = Math.max(start, w.s);
            const overlapEnd = Math.min(end, w.e);
            if (overlapStart < overlapEnd) {
                overlap += (overlapEnd - overlapStart);
            }
        }

        return minsToTime(overlap);
    }

    function getNightDutyForCrew(startMinsUTC) {
        if (startMinsUTC == null || !dailyLegs || dailyLegs.length === 0) return "00:00";
        
        const lastLeg = dailyLegs[dailyLegs.length - 1];
        if (!lastLeg || !lastLeg['j-in']) return "00:00";
        
        const endMinsUTC = parseTimeStr(lastLeg['j-in']);
        return calculateNightDuty(startMinsUTC, endMinsUTC);
    }

    function renderFlightLogTables(forceRedraw = false) {
        // 1. Calculate the latest fuel, ETOs, and cumulative times
        if (typeof runFlightLogCalculations === 'function') {
            runFlightLogCalculations(); 
        }

        // 2. Incremental update check (Fast-path if only typing ATOs or fuel)
        const canIncrementalUpdate = !forceRedraw && 
            typeof waypointTableCache !== 'undefined' &&
            waypointTableCache.waypoints && 
            waypointTableCache.waypoints.length === waypoints.length &&
            waypointTableCache.alternateWaypoints &&
            waypointTableCache.alternateWaypoints.length === alternateWaypoints.length &&
            (Date.now() - waypointTableCache.lastUpdate) < 1000;
        
        if (canIncrementalUpdate) {
            if (typeof updateFlightLogTablesIncremental === 'function') updateFlightLogTablesIncremental();
            if (typeof updateAlternateTableIncremental === 'function') updateAlternateTableIncremental();
            return;
        }

        // 3. Full DOM Render Helper
        const fillTable = (list, tableId, prefix) => {
            const tb = document.getElementById(tableId); 
            if (!tb) return;
            
            if (!list || list.length === 0) {
                tb.innerHTML = '<tr><td colspan="14" style="text-align:center;color:gray;padding:20px">No waypoints found</td></tr>';
                return;
            }

            let rowsHtml = '';
            list.forEach((wp, index) => {
                rowsHtml += createWaypointRowHtml(wp, index, prefix);
            });
            
            tb.innerHTML = rowsHtml;
        };
        
        // Populate Main Flight Log (prefix 'o') and Alternates Log (prefix 'a')
        fillTable(waypoints, 'ofp-tbody', 'o'); 
        fillTable(alternateWaypoints, 'altn-tbody', 'a');
    
        // 4. Cache DOM Element references for fast O(1) lookups during typing
        waypointATOCache = Array.from(document.querySelectorAll('[id^="o-a-"]'));
        alternateATOCache = Array.from(document.querySelectorAll('[id^="a-a-"]'));
        takeoffFuelInput = document.getElementById('o-f-0');
        waypointFuelCache = Array.from(document.querySelectorAll('[id^="o-f-"]'));
        
        waypointTableCache = {
            waypoints: Array.isArray(waypoints) ? [...waypoints] : [],
            alternateWaypoints: Array.isArray(alternateWaypoints) ? [...alternateWaypoints] : [],
            lastUpdate: Date.now()
        };
        
        // 5. Update cruise level for Journey Log if present
        if (typeof updateCruiseLevelForJourneyLog === 'function') {
            updateCruiseLevelForJourneyLog();
        }
    }

    // High-speed O(1) Incremental Updates for Main Table
    function updateFlightLogTablesIncremental() {
        if (!waypoints || waypoints.length === 0) return;
        
        waypoints.forEach((wp, i) => {
            const etoCell = document.getElementById(`o-eto-${i}`);
            if (etoCell) {
                const newEto = wp.eto || "--";
                if (etoCell.textContent !== newEto) etoCell.textContent = newEto;
            }
            
            const fuelCell = document.getElementById(`o-calcfuel-${i}`);
            if (fuelCell) {
                const newFuel = wp.fuel ? Math.round(wp.fuel) : "-";
                if (fuelCell.textContent !== String(newFuel)) fuelCell.textContent = newFuel;
            }
        });
    }

    // High-speed O(1) Incremental Updates for Alternate Table
    function updateAlternateTableIncremental() {
        if (!alternateWaypoints || alternateWaypoints.length === 0) return;
        
        alternateWaypoints.forEach((wp, i) => {
            const etoCell = document.getElementById(`a-eto-${i}`);
            if (etoCell) {
                const newEto = wp.eto || "--";
                if (etoCell.textContent !== newEto) etoCell.textContent = newEto;
            }
            
            const fuelCell = document.getElementById(`a-calcfuel-${i}`);
            if (fuelCell) {
                const newFuel = wp.fuel ? Math.round(wp.fuel) : "-";
                if (fuelCell.textContent !== String(newFuel)) fuelCell.textContent = newFuel;
            }
        });
    }

    window.updateTakeoffTime = function(v) {
        try {
            const validated = validateTimeInputs(v, 'Takeoff Time');
            const newTime = validated.value;
            
            const ofpInput = el('ofp-atd-in');
            const jInput = el('j-off');
            
            if (ofpInput && ofpInput.value !== newTime) ofpInput.value = newTime;
            if (jInput && jInput.value !== newTime) jInput.value = newTime;
            
            if (typeof debouncedFullRecalc === 'function') debouncedFullRecalc();
        } catch (error) {
            alert(error.message);
            // Revert gently
            const current = el('ofp-atd-in')?.value || '';
            if (el('ofp-atd-in')) el('ofp-atd-in').value = current;
            if (el('j-off')) el('j-off').value = current;
        }
    };

    window.updateAlternateETOs = function() {
        if (!waypoints || waypoints.length === 0 || !alternateWaypoints || alternateWaypoints.length === 0) return;

        const lastPrimaryIdx = waypoints.length - 1;
        const destWp = waypoints[lastPrimaryIdx];
        
        // 1. Determine Base Time (Destination Arrival)
        let baseTimeStr = waypointATOCache[lastPrimaryIdx]?.value;
        if (!baseTimeStr && destWp.eto && destWp.eto.length === 4) {
             baseTimeStr = destWp.eto.substring(0,2) + ":" + destWp.eto.substring(2,4);
        }

        if (!baseTimeStr) return;

        // Fast integer math for time calculation
        const [bh, bm] = baseTimeStr.includes(':') 
            ? baseTimeStr.split(':').map(Number) 
            : [parseInt(baseTimeStr.substring(0,2)), parseInt(baseTimeStr.substring(2,4))];
            
        const baseMinsFromMidnight = (bh * 60) + bm;
        const destMins = destWp.totalMins;

        // 2. Calculate Alternate Times
        alternateWaypoints.forEach((wp) => {
            let delta = wp.totalMins - destMins;
            // Handle cases where alternate mins might reset to 0 in OFP
            if (delta < 0) delta = wp.totalMins; 

            const targetMins = baseMinsFromMidnight + delta;
            
            const newH = Math.floor((targetMins / 60) % 24).toString().padStart(2, '0');
            const newM = Math.floor(targetMins % 60).toString().padStart(2, '0');
            
            wp.eto = newH + newM; 
            
            // We NO LONGER update the DOM here, because updateAlternateTableIncremental() 
            // runs immediately after this function and handles the DOM injection cleanly.
        });
    };


// ==========================================
// 6. PARSING
// ==========================================

    // Analyze OFP (parses PDF and populates waypoints etc.)
    async function runAnalysis(fileOrEvent, isAutoLoad = false) {
        const isBatchUpload = !isAutoLoad && document.getElementById('upload-progress-modal')?.style.display === 'block';
        let blob = null;

        if (fileOrEvent instanceof Blob) {
            blob = fileOrEvent;
        } else {
            const fileInput = document.getElementById('ofp-file-in');
            if (fileInput && fileInput.files.length > 0) {
                blob = fileInput.files[0];
                localStorage.removeItem('efb_log_state');
            }
        }
        if (!blob) return;

        window.ofpPdfBytes = await blob.arrayBuffer();
        window.originalFileName = blob.name || "Logged_OFP.pdf";
        renderPDFPreview(window.ofpPdfBytes).catch(console.error);

        if (!isAutoLoad && !isBatchUpload) {
            await prepareForManualUpload();
        }

        let parseResult;
        try {
            parseResult = await parsePDFData(window.ofpPdfBytes, isAutoLoad);
            window.ofpFullText = parseResult.fullText;
            window.ofpRequestNumber = parseResult.requestNumber;
            if (window.ofpRequestNumber) {
                const flightDateStr = (document.getElementById('view-date')?.innerText || '').trim();
                const flightNumber = (document.getElementById('view-flt')?.innerText || '').replace(/^KC/i, '');
                const depIcao = (document.getElementById('view-dep')?.innerText || '').trim().toUpperCase();
                fetchFlightIdFromRoster(flightDateStr, flightNumber, depIcao).then(id => {
                    if (id) window.currentExternalFlightId = id;
                });
            }
            const btn = document.getElementById('btn-send-tripinfo');
            if (btn) btn.style.display = 'block';
        } catch (error) {
            console.error('PDF parsing failed:', error);
            setOFPLoadedState(false);
            if (!isAutoLoad) {
                const fileInput = document.getElementById('ofp-file-in');
                if (fileInput) fileInput.value = '';
            }
            await logSecurityEvent('PDF_UPLOAD', {
                fileName: blob.name,
                fileSize: blob.size,
                fileType: blob.type,
                success: false,
                error: error.message
            }).catch(console.error);
            return;
        }

        if (!isAutoLoad) {
            const metadata = parseResult.metadata;
            const { flight, date } = metadata;
            const previouslyActiveId = localStorage.getItem('activeOFPId');
            const existingOFP = await findOFPByFlightAndDate(flight, date);

            try {
                let newlySavedId = null;
                if (existingOFP) {
                    await handleReplacement(existingOFP, blob, metadata, previouslyActiveId, isBatchUpload);
                    newlySavedId = existingOFP.id;
                } else {
                    await handleNewOFP(blob, metadata, isBatchUpload);
                    const freshlySaved = await findOFPByFlightAndDate(flight, date);
                    if (freshlySaved) newlySavedId = freshlySaved.id;
                }

                if (newlySavedId && !isBatchUpload) {
                    localStorage.setItem('activeOFPId', newlySavedId);
                    const summaryBtn = document.querySelector('.nav-btn[data-tab="summary"], .nav-btn[onclick*="summary"]');
                    if (summaryBtn) {
                        if (typeof window.showTab === 'function') window.showTab('summary', summaryBtn);
                        else summaryBtn.click();
                    }
                    showToast(`Activated: ${flight}`, 'success');
                    if (typeof updateUploadButtonVisibility === 'function') updateUploadButtonVisibility();
                }

                if (!isBatchUpload && document.querySelector('.tool-section.active')?.id === 'section-sectors') {
                    await renderOFPMangerTable();
                }
            } catch (error) {
                console.error("Unexpected error during save:", error);
                const emergencyResult = await emergencySaveOFP(blob, metadata, existingOFP || null);
                
                if (emergencyResult.ofpsRecordCreated && !isBatchUpload) {
                    const emergencySaved = await findOFPByFlightAndDate(flight, date);
                    if (emergencySaved) localStorage.setItem('activeOFPId', emergencySaved.id);
                }

                let toastMessage = existingOFP ? "OFP replaced (emergency mode)" : "OFP saved (emergency mode)";
                if (!emergencyResult.pdfSaved) toastMessage += " – PDF not saved";
                if (!emergencyResult.ofpsRecordCreated) toastMessage += " – record not created";
                showToast(toastMessage, emergencyResult.ofpsRecordCreated ? 'warning' : 'error');
                setOFPLoadedState(true);
            }
        }

        if (!isAutoLoad && !isBatchUpload) {
            const activeId = localStorage.getItem('activeOFPId');
            if (activeId) {
                const userData = await loadOFPUserData(Number(activeId));
                if (userData) {
                    if (userData.userWaypoints && Array.isArray(userData.userWaypoints)) {
                        userData.userWaypoints.forEach((data, i) => {
                            if (i < waypoints.length) {
                                if (data.ato) safeSet(`o-a-${i}`, data.ato);
                                if (data.fuel) safeSet(`o-f-${i}`, data.fuel);
                                if (data.notes) safeSet(`o-n-${i}`, data.notes);
                                if (data.agl) safeSet(`o-agl-${i}`, data.agl);
                            }
                        });
                        if (typeof runFlightLogCalculations === 'function') runFlightLogCalculations();
                        if (typeof syncLastWaypoint === 'function') syncLastWaypoint();
                    }
                    if (userData.userInputs && typeof userData.userInputs === 'object') {
                        Object.keys(userData.userInputs).forEach(id => {
                            const val = userData.userInputs[id];
                            if (id === 'signature' || id === 'front-atis-drawing' || id === 'front-atc-drawing') return;
                            if (val !== undefined && val !== null) safeSet(id, val);
                        });
                    }
                }
            }
        }

        if (!isAutoLoad && !isBatchUpload && typeof renderFlightLogTables === 'function') {
            renderFlightLogTables(true);
        }

        try {
            await logSecurityEvent('PDF_UPLOAD', {
                fileName: blob.name,
                fileSize: blob.size,
                fileType: blob.type,
                success: true
            });
        } catch (logError) {
            console.error('Failed to log upload:', logError);
        }

        if (!isAutoLoad && typeof saveState === 'function') {
            saveState();
        }
    }

    async function parsePDFData(pdfBytes, isAutoLoad) {
        try {
            resetParsingState();
            const pdf = await pdfjsLib.getDocument(pdfBytes).promise;

            // Extract Page 1
            const { requestNumber, page1Lines } = await parsePage1(pdf);

            // Waypoints
            const extractedWaypoints = await parseAllWaypoints(pdf);
            waypoints = extractedWaypoints;

            // Collect full text nicely line-by-line for NOTAM/Weather parsers
            let allLines = [...page1Lines];
            for (let i = 2; i <= pdf.numPages; i++) {
                const page = await pdf.getPage(i);
                const lines = await getLinesFromPDFPage(page);
                allLines.push(...lines);

                // Detect cutoff
                if (i >= 4) {
                    const pageText = lines.join('\n');
                    const cutoff = detectCutoffPage(pageText, i);
                    if (cutoff !== null) window.cutoffPageIndex = cutoff;
                }
            }

            if (waypoints.length === 0) console.warn('No waypoints found in PDF');
            waypoints.forEach(wp => {
                wp.baseFuel = parseInt(wp.fob) || 0;
                wp.fuel = wp.baseFuel;
            });
            if (typeof processWaypointsList === 'function') processWaypointsList();

            let { flight, date, dep, dest, tripTime, maxSR } = extractMetadataFromUI();

            // Filename metadata fallback
            if (!flight || flight === "N/A" || flight === "Unknown") {
                if (window.originalFileName) {
                    const match = window.originalFileName.match(/^([A-Za-z0-9]+)_(\d{4}-?\d{2}-?\d{2})/);
                    if (match) {
                        flight = match[1];
                        let rawDate = match[2];
                        if (rawDate.length === 8 && !rawDate.includes('-')) {
                            rawDate = `${rawDate.substring(0,4)}-${rawDate.substring(4,6)}-${rawDate.substring(6,8)}`;
                        }
                        date = rawDate;
                        if (document.getElementById('view-flt')) document.getElementById('view-flt').innerText = flight;
                        if (document.getElementById('view-date')) document.getElementById('view-date').innerText = date;
                    }
                }
            }

            const metadata = {
                flight,
                date,
                departure: dep || 'TBA',
                destination: dest || 'TBA',
                tripTime: tripTime || '',
                maxSR: maxSR || '',
                requestNumber: requestNumber || ''
            };

            updateUIAfterParsing();

            return {
                success: true,
                metadata,
                tripTime,
                maxSR,
                requestNumber,
                fullText: allLines.join('\n') // Preserves compatibility with NOTAM/WX
            };

        } catch (error) {
            console.error('Error in parsePDFData:', error);
            throw error;
        }
    }

function parsePageOne(lines) {
        try {
            let foundFlight = false;

            for (let i = 0; i < lines.length; i++) {
                // Strip invisible PDF formatting characters (Zero-width spaces, BOMs) that break Regex
                const line = lines[i].replace(/[\u200B-\u200D\uFEFF]/g, '').trim();
                
                // Fast-check: Does this line contain a Date and two ICAO airport codes?
                if (/\d{2}\/\d{2}\/\d{2}/.test(line) && /[A-Z]{4}\s+[A-Z]{4}/.test(line)) {
                    
                    // Split the line into tokens by ANY whitespace boundary
                    const tokens = line.split(/\s+/);
                    
                    // Find the exact index of the Date to use as our anchor pivot
                    const dateIdx = tokens.findIndex(t => /^\d{2}\/\d{2}\/\d{2}$/.test(t));
                    
                    if (dateIdx >= 2) {
                        const flt = tokens[dateIdx - 2];
                        const reg = tokens[dateIdx - 1];
                        const date = tokens[dateIdx];
                        const dep = tokens[dateIdx + 1];
                        const dest = tokens[dateIdx + 2];
                        const ci = tokens[dateIdx + 3];
                        const stdRaw = tokens[dateIdx + 4];
                        const etdRaw = tokens[dateIdx + 5];
                        const staRaw = tokens[dateIdx + 6];
                        const etaRaw = tokens[dateIdx + 7];
                        
                        // Smart Alternate Extraction (Grabs any remaining 4-letter codes)
                        const remainingTokens = tokens.slice(dateIdx + 8);
                        const altApts = remainingTokens.filter(t => /^[A-Z]{4}$/.test(t));
                        
                        const altn = altApts[0] || '';
                        const era = altApts[1] || '';
                        const altn2 = altApts[2] || '';

                        const formatTime = (t) => (t && /^\d{4}$/.test(t)) ? t.substring(0,2) + ":" + t.substring(2,4) : "-";

                        safeText('view-flt', flt); 
                        safeText('view-reg', reg); 
                        safeText('view-date', date);
                        safeText('view-dep', dep); 
                        safeText('view-dest', dest); 
                        safeText('view-ci', ci);
                        safeText('view-std-text', formatTime(stdRaw));
                        safeText('view-etd-text', formatTime(etdRaw));
                        safeText('view-sta-text', formatTime(staRaw));
                        safeText('view-eta-text', formatTime(etaRaw));
                        safeText('view-altn', altn);
                        safeText('view-era-text', era);
                        safeText('view-altn2', altn2);
                        
                        safeSet('j-flt', flt);
                        safeSet('j-reg', reg);
                        safeSet('j-date', date);
                        safeSet('j-dep', dep);
                        safeSet('j-dest', dest);
                        safeSet('j-altn', altn);
                        
                        if (era && document.getElementById('j-era')) document.getElementById('j-era').value = era;
                        if (altn2 && document.getElementById('j-altn2')) document.getElementById('j-altn2').value = altn2;
                        if (!document.getElementById('j-std')?.value) safeSet('j-std', formatTime(stdRaw));

                        foundFlight = true;
                        break;
                    }
                }
            }
            
            // Extreme Fallback (In case PDF.js completely merged the spaces e.g. "UACCUAAA")
            if (!foundFlight) {
                console.warn("Token-Pivot parser failed, attempting strict Regex fallback...");
                const fallbackRegex = /([A-Z0-9]{3,8})\s+([A-Z0-9-]{3,8})\s+(\d{2}\/\d{2}\/\d{2})\s+([A-Z]{4})\s*([A-Z]{4})\s+(\S+)\s+(\d{4})\s+(\d{4})\s+(\d{4})\s+(\d{4})(?:\s+([A-Z]{4}))?/;
                
                for (let i = 0; i < lines.length; i++) {
                    const match = lines[i].replace(/[\u200B-\u200D\uFEFF]/g, '').match(fallbackRegex);
                    if (match) {
                        const [, flt, reg, date, dep, dest, ci, stdRaw, etdRaw, staRaw, etaRaw, altn] = match;
                        const formatTime = (t) => (t && /^\d{4}$/.test(t)) ? t.substring(0,2) + ":" + t.substring(2,4) : "-";
                        
                        safeText('view-flt', flt); safeText('view-reg', reg); safeText('view-date', date);
                        safeText('view-dep', dep); safeText('view-dest', dest); safeText('view-ci', ci);
                        safeText('view-std-text', formatTime(stdRaw)); safeText('view-etd-text', formatTime(etdRaw));
                        safeText('view-sta-text', formatTime(staRaw)); safeText('view-eta-text', formatTime(etaRaw));
                        safeText('view-altn', altn || '');
                        
                        safeSet('j-flt', flt); safeSet('j-reg', reg); safeSet('j-date', date);
                        safeSet('j-dep', dep); safeSet('j-dest', dest); safeSet('j-altn', altn || '');
                        if (!document.getElementById('j-std')?.value) safeSet('j-std', formatTime(stdRaw));

                        foundFlight = true;
                        break;
                    }
                }
            }

            if (!foundFlight) {
                throw new Error('Could not parse flight information from OFP. Layout unrecognized.');
            }

            if (typeof extractAdditionalFlightInfo === 'function') extractAdditionalFlightInfo(lines);
            if (typeof extractRoutes === 'function') extractRoutes(lines);
            if (typeof extractFuelData === 'function') extractFuelData(lines);
            if (typeof extractWeights === 'function') extractWeights(lines);
            
            return true;
            
        } catch (error) {
            console.error('Error in parsePageOne:', error);
            ['view-flt', 'view-reg', 'view-date', 'view-dep', 'view-dest', 'view-altn', 'view-std-text', 'view-sta-text', 'view-ci', 'view-era-text', 'view-altn2'].forEach(id => safeText(id, '-'));
            if (typeof setOFPLoadedState === 'function') setOFPLoadedState(false);
            throw error; 
        }
    }

    async function parsePage1(pdf) {
        const page = await pdf.getPage(1);
        const lines = await getLinesFromPDFPage(page);
        
        // Extract raw coordinates for PDF mapping
        const content = await page.getTextContent();
        if (typeof extractMainPageCoordinates === 'function') {
            extractMainPageCoordinates(content.items);
        }

        try {
            parsePageOne(lines);
        } catch (parseError) {
            console.warn('Failed to parse page 1 components:', parseError);
            if (typeof setOFPLoadedState === 'function') setOFPLoadedState(false);
            throw parseError;
        }

        const textContent = lines.join('\n');
        let requestNumber = '';
        if (typeof extractRequestNumber === 'function') {
            requestNumber = extractRequestNumber(textContent);
        }
        
        return { requestNumber, page1Lines: lines, textContent };
    }

    function parseTimeString(timeStr) {
        if(!timeStr) return 0;
        
        // Handle "HHMM" format (no colon)
        if (timeStr.length === 4 && /^\d{4}$/.test(timeStr)) {
            const h = parseInt(timeStr.substring(0, 2)) || 0;
            const m = parseInt(timeStr.substring(2, 4)) || 0;
            return h * 60 + m;
        }
        
        // Handle "HH:MM" format
        if (timeStr.includes(':')) {
            const [hStr, mStr] = timeStr.split(':');
            const h = parseInt(hStr) || 0;
            const m = parseInt(mStr) || 0;
            return h * 60 + m;
        }
        
        // Handle "H.M" or "H:MM" formats
        const separator = timeStr.includes(':') ? ':' : '.';
        const [hStr, mStr] = timeStr.split(separator);
        let h = parseInt(hStr) || 0;
        let m = parseInt(mStr) || 0;
        
        if(mStr && mStr.length === 1 && separator === '.') m *= 10; 
        return h * 60 + m;
    }
    
    async function parseWaypoints(page, pageNum) {
        const textContent = await page.getTextContent();
        const rows = typeof buildRows === 'function' 
            ? buildRows(textContent.items) 
            : []; // Fallback to your original buildRows builder
            
        if (!rows || rows.length === 0) return [];

        rows.sort((a, b) => b.y - a.y); 

        // 1. Locate the Table Header Y boundary
        let headerY = null;
        for (const row of rows) {
            const rowText = row.items.map(item => item.str).join(' ');
            if ((rowText.includes("TO") && rowText.includes("FUEL")) || 
                (rowText.includes("AWY") && rowText.includes("ETE")) ||
                (rowText.includes("FREQ") && rowText.includes("FL"))) {
                headerY = row.y; 
                break; 
            }
        }

        if (!headerY) return [];

        const waypoints = [];

        // 2. Parse Waypoint Rows
        for (let r = 0; r < rows.length; r++) {
            const row = rows[r];
            if (row.y >= headerY) continue;
            if (!row.items || row.items.length < 2) continue;

            let timeValue = null, fuelValue = null;

            // Search for Time and Fuel within the row's items
            for (const item of row.items) {
                const str = (item.str || '').trim();
                
                // Time regex matching (e.g. 01:23 or 01.23)
                if (/^\d{1,3}[\.:]\d{2}$/.test(str)) {
                    timeValue = str;
                }
                
                // Fuel regex matching (standalone numbers, avoiding FL references)
                if (/^\d{3,5}$/.test(str) && !str.includes('.') && !str.includes(':')) {
                    const num = parseInt(str, 10);
                    const fullRowStr = row.items.map(x => x.str).join(' ');
                    if (num >= 100 && num <= 99999 && !fullRowStr.includes('FL ')) {
                        fuelValue = str;
                    }
                }
            }

            if (timeValue && fuelValue) {
                let data = { 
                    name: "?", awy: "-", level: "-", track: "-", 
                    wind: "-", tas: "-", gs: "-", sr: "-" 
                };

                // ---- FIRST ROW: Waypoint Name, Airway, Level, etc. ----
                if (r > 0) {
                    const prevRow = rows[r - 1];
                    // Relaxed delta gap from 25 to 35 to prevent dropping rows on scaled PDFs
                    if (Math.abs(row.y - prevRow.y) < 35) {
                        const fullString = prevRow.items.map(x => x.str).join(' ').trim();
                        const parts = fullString.split(/\s+/);

                        if (parts.length > 0 && parts[0]) {
                            // Strip out stray non-alphanumeric artifacts except stars/dashes
                            data.name = parts[0].replace(/[^a-zA-Z0-9*-]/g, '') || parts[0];
                            if (parts[1]) data.awy = parts[1];
                            if (parts[2]) data.level = parts[2];
                            if (parts[3]) data.track = parts[3];
                            if (parts[4]) data.wind = parts[4];
                            if (parts[5]) data.tas = parts[5];
                            if (parts[6]) data.gs = parts[6];
                        }
                    }
                }

                // ---- SECOND ROW: Shear Rate (SR) extraction ----
                let sr = '-';
                for (let i = 0; i < row.items.length - 1; i++) {
                    const token = (row.items[i].str || '').trim();
                    const nextToken = (row.items[i + 1].str || '').trim();
                    if (/^\d{3}$/.test(token) && !token.includes('/') && 
                        /^\d{2}$/.test(nextToken) && !nextToken.includes('/')) {
                        sr = nextToken;
                        break;
                    }
                }

                // Combined 5-digit token fallback (e.g. "74702")
                if (sr === '-') {
                    for (let i = 0; i < row.items.length; i++) {
                        const token = (row.items[i].str || '').trim();
                        if (/^\d{5}$/.test(token)) {
                            const possibleSR = token.substring(3, 5);
                            if (/^\d{2}$/.test(possibleSR)) {
                                sr = possibleSR;
                                break;
                            }
                        }
                    }
                }

                // Spaced token fallback
                if (sr === '-') {
                    for (let i = 0; i < row.items.length; i++) {
                        const token = (row.items[i].str || '').trim();
                        const spaceIndex = token.indexOf(' ');
                        if (spaceIndex !== -1) {
                            const beforeSpace = token.substring(0, spaceIndex).trim();
                            const afterSpace = token.substring(spaceIndex + 1).trim();
                            if (/^[A-Z0-9]{3}$/.test(beforeSpace) && /^\d{2}$/.test(afterSpace)) {
                                sr = afterSpace;
                                break;
                            }
                        }
                    }
                }

                if (data.name !== "?") {
                    waypoints.push({
                        ...data,
                        totalMins: typeof parseTimeString === 'function' ? parseTimeString(timeValue) : 0,
                        eto: "",
                        fob: parseInt(fuelValue, 10) || 0,
                        page: pageNum - 1, 
                        y_anchor: row.y,
                        isTakeoff: false,
                        isAlternate: false,
                        rawTime: timeValue,
                        sr: sr
                    }); 
                }
            }
        }

        return waypoints;
    }

    async function parseAllWaypoints(pdf) {
        const allWaypoints = [];
        for (let i = 2; i <= pdf.numPages; i++) {
            try {
                const page = await pdf.getPage(i);
                const pageWaypoints = await parseWaypoints(page, i);
                if (pageWaypoints && pageWaypoints.length > 0) {
                    allWaypoints.push(...pageWaypoints);
                }
            } catch (e) {
                console.warn(`Error parsing waypoints on page ${i}:`, e);
            }
        }
        return allWaypoints;
    }

    function resetParsingState() {
        waypoints = [];
        alternateWaypoints = [];
        fuelData = [];
        blockFuelValue = 0;
        window.cutoffPageIndex = -1;
        frontCoords = {
            atis: null, atcLabel: null, altm1: null, stby: null,
            altm2: null, picBlockLabel: null, reasonLabel: null
        };
    }

    function detectCutoffPage(textContent, pageIndex) {
        const upper = textContent.toUpperCase();
        if (upper.includes("END OF ALTERNATE FLIGHT PLAN") ||
            (upper.includes("END") && upper.includes("FLIGHT") && upper.includes("PLAN")) ||
            (upper.includes("WEATHER") && upper.includes("CHART")) ||
            (upper.includes("NOTAM") && upper.includes("BRIEFING"))) {
            return pageIndex - 1; // page before this one
        }
        return null;
    }
    
    window.analyzeNotamsAndWeather = function() {
        const resultsDiv = document.getElementById('notam-results');
        if (!resultsDiv) return;

        const fullText = window.ofpFullText;
        if (!fullText) {
            resultsDiv.innerHTML = '<div class="error">No OFP loaded or parsed. Please upload an OFP first.</div>';
            return;
        }

        // Get flight times and date
        const flightDateStr = (document.getElementById('view-date')?.innerText || '').trim();
        const etdStr = (document.getElementById('view-etd-text')?.innerText || '').trim();
        const etaStr = (document.getElementById('view-eta-text')?.innerText || '').trim();

        if (!flightDateStr || !etdStr || !etaStr) {
            resultsDiv.innerHTML = '<div class="error">Flight date or times not available. Please ensure OFP is fully parsed.</div>';
            return;
        }

        // Parse flight date (format "DD/MM/YY")
        const [day, month, year] = flightDateStr.split('/').map(Number);
        const flightDate = new Date(Date.UTC(2000 + year, month - 1, day));
        const parseTime = (timeStr) => {
            const [h, m] = (timeStr || '').split(':').map(Number);
            return (isNaN(h) ? 0 : h) * 60 + (isNaN(m) ? 0 : m);
        };
        const etdMinutes = parseTime(etdStr);
        const etaMinutes = parseTime(etaStr);

        // Time windows in minutes since midnight UTC
        const depStart = etdMinutes;
        const depEnd = etdMinutes + 60;
        const arrStart = Math.max(0, etaMinutes - 60);
        const arrEnd = etaMinutes + 60;
        let otherStart = 0;
        let otherEnd = 1440;
        if (etaMinutes < etdMinutes) otherEnd += 1440;

        // Convert windows to UTC timestamps
        const getWindowTimes = (startMin, endMin) => {
            let start = Date.UTC(flightDate.getUTCFullYear(), flightDate.getUTCMonth(), flightDate.getUTCDate(),
                Math.floor(startMin / 60), startMin % 60);
            let end = Date.UTC(flightDate.getUTCFullYear(), flightDate.getUTCMonth(), flightDate.getUTCDate(),
                Math.floor(endMin / 60), endMin % 60);
            if (endMin >= 1440) end += 86400000;
            return { start, end };
        };

        const depWindow = getWindowTimes(depStart, depEnd);
        const arrWindow = getWindowTimes(arrStart, arrEnd);
        const otherWindow = getWindowTimes(otherStart, otherEnd);

        // Airport codes
        const depAirport = (document.getElementById('view-dep')?.innerText || '').trim().toUpperCase();
        const destAirport = (document.getElementById('view-dest')?.innerText || '').trim().toUpperCase();
        const altnAirport = (document.getElementById('view-altn')?.innerText || '').trim().toUpperCase();
        const altn2Airport = (document.getElementById('view-altn2')?.innerText || '').trim().toUpperCase();
        const eraAirport = (document.getElementById('view-era-text')?.innerText || '').trim().toUpperCase();
        const alternates = [altnAirport, altn2Airport, eraAirport].filter(code => code && /^[A-Z]{4}$/.test(code));
        const uniqueAlternates = [...new Set(alternates)];

        resultsDiv.innerHTML = '<div class="loading">Analyzing NOTAMs and weather...</div>';

        setTimeout(() => {
            try {
                // Helper functions for date parsing
                const parseNotamDateTime = (str, baseYear) => {
                    const match = str.match(/(\d{2})([A-Z]{3})(\d{2})(\d{2})/i);
                    if (!match) return null;
                    const d = parseInt(match[1], 10);
                    const monthStr = match[2].toUpperCase();
                    const hour = parseInt(match[3], 10);
                    const minute = parseInt(match[4], 10);
                    const months = { JAN:0, FEB:1, MAR:2, APR:3, MAY:4, JUN:5, JUL:6, AUG:7, SEP:8, OCT:9, NOV:10, DEC:11 };
                    const m = months[monthStr];
                    if (m === undefined) return null;

                    return { year: baseYear, month: m, day: d, hour, minute };
                };

                const getNotamValidity = (text) => {
                    const match = text.match(/(\d{2}[A-Z]{3}\d{4})\s*[-/]\s*(\d{2}[A-Z]{3}\d{4})/i);
                    if (!match) return null;
                    const startStr = match[1];
                    const endStr = match[2];

                    const startParsed = parseNotamDateTime(startStr, flightDate.getUTCFullYear());
                    const endParsed = parseNotamDateTime(endStr, flightDate.getUTCFullYear());
                    if (!startParsed || !endParsed) return null;

                    let start = new Date(Date.UTC(startParsed.year, startParsed.month, startParsed.day, startParsed.hour, startParsed.minute));
                    let end = new Date(Date.UTC(endParsed.year, endParsed.month, endParsed.day, endParsed.hour, endParsed.minute));

                    if (end < start) {
                        end.setUTCFullYear(end.getUTCFullYear() + 1);
                    }

                    if (end < flightDate) {
                        start.setUTCFullYear(start.getUTCFullYear() + 1);
                        end.setUTCFullYear(end.getUTCFullYear() + 1);
                    }

                    return { start, end };
                };

                // Extract NOTAMs and Weather
                const notams = typeof extractNOTAMs === 'function' ? extractNOTAMs(fullText) : [];
                const weather = typeof extractWeather === 'function' ? extractWeather(fullText) : [];

                // Store latest METAR for each airport
                const airportMetars = {};
                weather.forEach(report => {
                    const upper = report.toUpperCase();
                    if (upper.includes('METAR')) {
                        const match = report.match(/\bMETAR\s+([A-Z]{4})\b/i);
                        if (match) {
                            const apt = match[1].toUpperCase();
                            if (!airportMetars[apt]) {
                                airportMetars[apt] = report;
                            }
                        }
                    }
                });
                window.airportMetars = airportMetars;

                // Extract latest METAR for departure and destination
                let depMetar = '';
                let destMetar = '';
                weather.forEach(report => {
                    if (!depMetar && report.includes('METAR') && report.includes(depAirport)) {
                        depMetar = report;
                    }
                    if (!destMetar && report.includes('METAR') && report.includes(destAirport)) {
                        destMetar = report;
                    }
                });
                window.currentWeather = { dep: depMetar, dest: destMetar };

                // Extract runway info safely for all airports (Fixes un-scoped regex leaks)
                const airportRunways = {};
                const runwayRegex = /([A-Z]{4})(?:\s+[A-Z]{3})?\s+((?:RWY\d{2}[LRC]?\s+\d+M\s*)+)/gi;
                let rwyMatch;
                while ((rwyMatch = runwayRegex.exec(fullText)) !== null) {
                    const apt = rwyMatch[1].toUpperCase();
                    const runwayText = rwyMatch[2].trim().replace(/\s+/g, ' ');
                    airportRunways[apt] = runwayText;
                }
                window.airportRunways = airportRunways;

                // Generate alerts
                let alerts = typeof runRulesOnText === 'function' ? runRulesOnText(notams, weather) : [];
                if (!alerts) alerts = [];

                // Helper to parse weather validity
                const parseWeatherValidity = (report, baseDate) => {
                    let match = report.match(/TAF(?:\s+AMD)?\s+[A-Z]{4}\s+(\d{2})(\d{2})(\d{2})Z\s+(\d{2})(\d{2})\/(\d{2})(\d{2})/i);
                    if (match) {
                        const startDay = parseInt(match[4], 10);
                        const startHour = parseInt(match[5], 10);
                        const endDay = parseInt(match[6], 10);
                        const endHour = parseInt(match[7], 10);
                        const start = new Date(Date.UTC(baseDate.getUTCFullYear(), baseDate.getUTCMonth(), startDay, startHour, 0));
                        const end = new Date(Date.UTC(baseDate.getUTCFullYear(), baseDate.getUTCMonth(), endDay, endHour, 0));
                        if (start < baseDate) start.setUTCMonth(start.getUTCMonth() + 1);
                        if (end < baseDate) end.setUTCMonth(end.getUTCMonth() + 1);
                        return { start, end };
                    }
                    match = report.match(/(?:METAR|SPECI)\s+[A-Z]{4}\s+(\d{2})(\d{2})(\d{2})Z/i);
                    if (match) {
                        const day = parseInt(match[1], 10);
                        const hour = parseInt(match[2], 10);
                        const minute = parseInt(match[3], 10);
                        const obsTime = new Date(Date.UTC(baseDate.getUTCFullYear(), baseDate.getUTCMonth(), day, hour, minute));
                        const start = new Date(obsTime.getTime() - 60 * 60000);
                        const end = new Date(obsTime.getTime() + 60 * 60000);
                        return { start, end };
                    }
                    return null;
                };

                // Apply time filtering
                const filteredAlerts = [];
                alerts.forEach(alert => {
                    const airport = alert.airport ? alert.airport.toUpperCase() : '';
                    let include = true;
                    let validity = null;

                    if (alert.type && alert.type.includes('NOTAM')) {
                        validity = getNotamValidity(alert.message);
                    } else if (alert.type && alert.type.includes('Weather')) {
                        validity = parseWeatherValidity(alert.message, flightDate);
                    }

                    if (validity && validity.start && validity.end) {
                        const startTime = validity.start.getTime();
                        const endTime = validity.end.getTime();

                        let windowStart, windowEnd;
                        if (airport === depAirport) {
                            windowStart = depWindow.start;
                            windowEnd = depWindow.end;
                        } else if (airport === destAirport || uniqueAlternates.includes(airport)) {
                            windowStart = arrWindow.start;
                            windowEnd = arrWindow.end;
                        } else {
                            windowStart = otherWindow.start;
                            windowEnd = otherWindow.end;
                        }

                        if (endTime < windowStart || startTime > windowEnd) {
                            include = false;
                        }
                    }
                    if (include) filteredAlerts.push(alert);
                });

                // Fallback if all filtered out
                const finalAlerts = (filteredAlerts.length === 0 && alerts.length > 0) ? alerts : filteredAlerts;

                // Track airports with alerts
                const airportsWithAlerts = new Set();
                finalAlerts.forEach(a => {
                    if (a.airport && a.airport !== 'Unknown') {
                        airportsWithAlerts.add(a.airport.toUpperCase());
                    }
                });

                // Add placeholders for key airports with no alerts
                [depAirport, destAirport, ...uniqueAlternates].forEach(apt => {
                    if (apt && !airportsWithAlerts.has(apt)) {
                        finalAlerts.push({
                            severity: 'info',
                            type: 'INFO',
                            airport: apt,
                            message: 'No relevant WX/NOTAM to report.'
                        });
                        airportsWithAlerts.add(apt);
                    }
                });

                // Sort by priority and severity
                const getAirportRank = (airportCode) => {
                    if (!airportCode || airportCode === 'Unknown') return 4;
                    const code = airportCode.toUpperCase();
                    if (code === depAirport) return 0;
                    if (code === destAirport) return 1;
                    if (uniqueAlternates.includes(code)) return 2;
                    return 3;
                };

                // Sort by Airport Priority FIRST (DEP -> DEST -> ALTN -> OTHER), then Severity
                finalAlerts.sort((a, b) => {
                    // 1. Primary: Airport Rank
                    const rankA = getAirportRank(a.airport);
                    const rankB = getAirportRank(b.airport);
                    if (rankA !== rankB) return rankA - rankB;

                    // 2. Secondary: Severity
                    const severityOrder = { critical: 0, warning: 1, info: 2 };
                    const sevA = severityOrder[(a.severity || '').toLowerCase()] ?? 3;
                    const sevB = severityOrder[(b.severity || '').toLowerCase()] ?? 3;
                    if (sevA !== sevB) return sevA - sevB;

                    // 3. Tertiary: Type
                    return (a.type || '').localeCompare(b.type || '');
                });

                window.notamFullAlerts = finalAlerts.slice();

                // Render table safely
                if (typeof renderNotamsWXTable === 'function') {
                    renderNotamsWXTable(finalAlerts);
                }

            } catch (error) {
                console.error('Analysis error:', error);
                resultsDiv.innerHTML = `<div class="error">Analysis failed: ${error.message}</div>`;
            }
        }, 100);
    };

    function runRulesOnText(notams, weather) {
        const alerts = [];

        // Process NOTAMs
        notams.forEach(rawText => {
            const { airport, text: cleaned } = cleanNOTAMText(rawText);
            if (cleaned.length < 10) return;

            let matched = false;
            if (typeof FLIGHT_THREAT_DICTIONARY !== 'undefined' && FLIGHT_THREAT_DICTIONARY.notams) {
                FLIGHT_THREAT_DICTIONARY.notams.forEach(rule => {
                    if (rule.regex.test(cleaned)) {
                        alerts.push({
                            severity: rule.level,
                            type: rule.type, // Removed "NOTAM: " prefix
                            airport: airport,
                            message: cleaned.substring(0, 2000) + (cleaned.length > 2000 ? '...' : '')
                        });
                        matched = true;
                    }
                });
            }

            if (!matched) {
                alerts.push({
                    severity: 'info',
                    type: 'NOTAM',
                    airport: airport,
                    message: cleaned.substring(0, 2000) + (cleaned.length > 2000 ? '...' : '')
                });
            }
        });

        // Process WX (METAR / TAF / SPECI)
        weather.forEach(report => {
            let airportMatch = report.match(/\b(?:METAR|SPECI|TAF(?:\s+AMD)?)\s+([A-Z]{4})\b/i);
            if (!airportMatch) {
                airportMatch = report.match(/\b([A-Z]{4})\b/);
            }
            const airport = airportMatch ? airportMatch[1] : 'Unknown';
            
            if (typeof FLIGHT_THREAT_DICTIONARY !== 'undefined' && FLIGHT_THREAT_DICTIONARY.weather) {
                FLIGHT_THREAT_DICTIONARY.weather.forEach(rule => {
                    if (rule.regex.test(report)) {
                        alerts.push({
                            severity: rule.level,
                            type: rule.type, // Removed "Weather: " prefix (e.g. outputs "THUNDERSTORM")
                            airport: airport,
                            message: report.substring(0, 2000) + (report.length > 2000 ? '...' : '')
                        });
                    }
                });
            }
        });

        return alerts;
    }

// ==========================================
// 7. UI RENDERING
// ==========================================

    // High-performance, GPU-accelerated Toast Notifications
    function showToast(message, type = 'success') {
        const toast = document.createElement('div');
        const bgColors = {
            'error': 'var(--error)',
            'info': 'var(--accent)',
            'success': 'var(--success)'
        };
        
        // Use GPU-accelerated transforms instead of expensive top/left animations
        toast.style.cssText = `
            position: fixed;
            top: 20px;
            right: 20px;
            background: ${bgColors[type] || bgColors['success']};
            color: white;
            padding: 15px 20px;
            border-radius: 10px;
            z-index: 10000;
            box-shadow: 0 5px 15px rgba(0,0,0,0.2);
            transition: opacity 0.3s ease, transform 0.3s cubic-bezier(0.175, 0.885, 0.32, 1.275);
            opacity: 0;
            transform: translateY(-20px) scale(0.95);
            pointer-events: none;
        `;
        
        toast.textContent = message;
        document.body.appendChild(toast);
        
        // Trigger GPU render next frame
        requestAnimationFrame(() => {
            toast.style.opacity = '1';
            toast.style.transform = 'translateY(0) scale(1)';
        });
        
        setTimeout(() => {
            toast.style.opacity = '0';
            toast.style.transform = 'translateY(-20px) scale(0.95)';
            setTimeout(() => toast.remove(), 300); // Wait for transition to finish
        }, 3000);
    }

    function showConfirmDialog(title, message, confirmText = 'Continue', cancelText = 'Cancel', type = 'warning', centered = false) {
        return createModal({
            title, message, confirmText, cancelText,
            type: type === 'error' ? 'error' : 'info',
            icon: type === 'error' ? '⚠️' : '❓',
            centered
        });
    }

    function showUpdateModal(version, releaseData, onReload) {
        createModal({
            title: 'Update Available',
            showVersion: version,
            message: releaseData.title,
            listItems: releaseData.notes,
            confirmText: 'Reload Now',
            cancelText: 'Later',
            icon: '🚀',
            type: 'info',
            onConfirm: onReload
        });
    }

    // Unified Modal Builder (Optimized layout rendering)
    function createModal({ title, message = '', confirmText = 'OK', cancelText = null, onConfirm, onCancel, type = 'info', icon = '📋', showVersion = null, listItems = null, bodyHTML = '', centered = true, compact = false, maxWidth = null }) {
        return new Promise((resolve) => {
            const dialog = document.createElement('div');
            dialog.style.cssText = `position: fixed; inset: 0; background: rgba(0,0,0,0.8); display: flex; justify-content: center; align-items: center; z-index: 10001; backdrop-filter: blur(5px); animation: fadeIn 0.2s ease;`;

            const color = type === 'error' ? 'var(--error)' : 'var(--accent)';
            const align = centered ? 'text-align: center;' : 'text-align: left;';
            const width = maxWidth || (compact ? '400px' : '500px');

            const listHTML = (listItems && listItems.length) 
                ? `<div style="margin-bottom: 25px; max-height: 400px; overflow-y: auto; ${align}">
                    <ul style="list-style: none; padding: 0; margin: 0;">
                        ${listItems.map(item => `<li style="margin-bottom: 8px; color: var(--text);">${item}</li>`).join('')}
                    </ul>
                   </div>` 
                : '';

            dialog.innerHTML = `
                <div style="background: var(--panel); border-radius: 20px; padding: ${compact ? '15px' : '30px'}; max-width: ${width}; width: 90%; border: 2px solid ${color}; box-shadow: 0 20px 40px rgba(0,0,0,0.5); text-align: left;">
                    <div style="display: flex; align-items: center; gap: 15px; margin-bottom: 20px;">
                        <span style="font-size: 40px;">${icon}</span>
                        <div>
                            <h2 style="color: ${color}; margin: 0; font-size: 24px;">${title}</h2>
                            ${showVersion ? `<p style="color: var(--dim); margin: 5px 0 0 0;">Version ${showVersion}</p>` : ''}
                        </div>
                    </div>
                    ${message ? `<div style="color: var(--text); margin-bottom: 25px; line-height: 1.5; ${align}">${message}</div>` : ''}
                    ${listHTML}
                    ${bodyHTML ? `<div style="margin-bottom: 25px;">${bodyHTML}</div>` : ''}
                    <div style="display: flex; gap: 15px; margin-top: 25px;">
                        ${cancelText ? `<button id="modal-cancel" style="flex:1; padding:14px; background:var(--input); border:1px solid var(--border); color:var(--text); border-radius:12px; font-weight:600; cursor:pointer;">${cancelText}</button>` : ''}
                        <button id="modal-confirm" style="flex:1; padding:14px; background:${color}; border:none; color:white; border-radius:12px; font-weight:800; cursor:pointer;">${confirmText}</button>
                    </div>
                </div>
            `;

            document.body.appendChild(dialog);

            dialog.querySelector('#modal-confirm').onclick = () => { 
                if (onConfirm) onConfirm(); 
                dialog.remove(); 
                resolve(true); 
            };
            
            if (cancelText) {
                dialog.querySelector('#modal-cancel').onclick = () => { 
                    if (onCancel) onCancel(); 
                    dialog.remove(); 
                    resolve(false); 
                };
            }
        });
    }

    // Fast-path Overlay Manager
    async function updateUploadButtonVisibility() {
        const overlay = document.getElementById('upload-overlay');
        if (!overlay) return;

        const activeSection = document.querySelector('.tool-section.active');
        const activeTabId = activeSection ? activeSection.id.replace('section-', '') : '';
        const hiddenTabs = new Set(['journey', 'sectors', 'settings', 'assigned']);

        // Early exit: Hide overlay if an OFP is loaded or if on a system tab
        if (isOFPLoaded || hiddenTabs.has(activeTabId)) {
            overlay.classList.add('hidden');
            return;
        }

        // Check IndexedDB for saved OFPs
        try {
            const count = typeof getOFPCount === 'function' ? await getOFPCount() : 0;
            if (count > 0 && isOFPLoaded) {
                overlay.classList.add('hidden');
            } else {
                overlay.classList.remove('hidden');
            }
        } catch (e) {
            console.warn('Failed to check OFP count', e);
            overlay.classList.remove('hidden');
        }
    }

    // Safely neutralized to prevent destructive innerHTML overwrites of form panels
    async function updateEmptyStates() {
        await updateUploadButtonVisibility();
    }

    window.goToAssignedAndActivate = function() {
        const assignedBtn = document.querySelector('.nav-btn[data-tab="assigned"], .nav-btn[onclick*="assigned"]');
        if (assignedBtn) {
            typeof window.showTab === 'function' ? window.showTab('assigned', assignedBtn) : assignedBtn.click();
        }
    };

    // Optimized array allocation for coordinate grouping
    function buildRows(items) {
        const rows = {};
        for (let i = 0; i < items.length; i++) {
            const item = items[i];
            const y = Math.round(item.transform[5]);
            if (!rows[y]) rows[y] = [];
            rows[y].push(item);
        }
        
        return Object.keys(rows).map(y => ({
            y: parseFloat(y),
            items: rows[y].sort((a, b) => a.transform[4] - b.transform[4])
        }));
    }

    function setOFPLoadedState(loaded) {
        isOFPLoaded = loaded;
        updateUploadButtonVisibility();
        
        if (loaded) {
            const pdfContainer = document.getElementById('pdf-render-container');
            if (typeof pdfFallbackElement !== 'undefined' && pdfFallbackElement) {
                pdfFallbackElement.innerHTML = `No OFP uploaded yet`;
                pdfFallbackElement.style.display = 'flex';
            }
            if (pdfContainer) pdfContainer.style.display = 'block';
        }
    }

    // Direct DOM Theme Toggler
    window.toggleTheme = function() {
        const html = document.documentElement;
        const themeButton = document.querySelector('.theme-toggle');
        
        const isDark = html.getAttribute('data-theme') === 'dark';
        const newTheme = isDark ? 'light' : 'dark';
        
        html.setAttribute('data-theme', newTheme);
        localStorage.setItem('data-theme', newTheme);
        
        if (themeButton) {
            themeButton.textContent = isDark ? 'Night Mode' : 'Day Mode';
        }
    };

    window.renderOFPMangerTable = async function() {
        const tbody = document.getElementById('ofp-manager-tbody');
        if (!tbody) return;

        try {
            const ofps = await getCachedOFPs();
            const filterText = document.getElementById('ofp-search-input')?.value.toLowerCase() || '';
            const activeId = localStorage.getItem('activeOFPId');

            if (ofps.length === 0) {
                tbody.innerHTML = `<tr><td colspan="9" style="text-align: center; padding: 30px; color: var(--dim);">No OFPs uploaded yet.</td></tr>`;
                return;
            }

            const filtered = ofps.filter(ofp => {
                if (!filterText) return true;
                const searchStr = `${ofp.flight || ''} ${ofp.date || ''} ${ofp.departure || ''} ${ofp.destination || ''}`.toLowerCase();
                return searchStr.includes(filterText);
            });

            if (filtered.length === 0) {
                tbody.innerHTML = `<tr><td colspan="9" style="text-align: center; padding: 30px; color: var(--dim);">No matching OFPs found.</td></tr>`;
                return;
            }

            tbody.innerHTML = filtered.map(ofp => {
                const isActive = String(ofp.id) === String(activeId);
                const statusBadge = ofp.finalized 
                    ? `<span class="status-badge status-finalized">✓ Finalized</span>`
                    : `<span class="status-badge ${isActive ? 'status-active' : 'status-inactive'}">${isActive ? '✓ Active' : 'Inactive'}</span>`;

                const actionButtons = ofp.finalized 
                    ? `<button onclick="downloadSavedOFP(${ofp.id})" class="btn-icon download" title="Download Logged OFP">⬇️</button>`
                    : `<button class="btn-icon download" disabled style="opacity:0.3" title="Finalize OFP first">⬇️</button>`;

                return `
                    <tr data-ofp-id="${ofp.id}" ${isActive ? 'class="active-ofp-row"' : ''}>
                        <td><strong>${sanitizeHTML(ofp.flight || '—')}</strong></td>
                        <td>${sanitizeHTML(ofp.date || '—')}</td>
                        <td>${sanitizeHTML(ofp.departure || '—')}</td>
                        <td>${sanitizeHTML(ofp.destination || '—')}</td>
                        <td>${sanitizeHTML(ofp.tripTime || '—')}</td>
                        <td>${sanitizeHTML(ofp.maxSR || '—')}</td>
                        <td>${sanitizeHTML(ofp.requestNumber || '—')}</td>
                        <td>${statusBadge}</td>
                        <td style="white-space: nowrap;">
                            ${actionButtons}
                            <button onclick="deleteOFP(${ofp.id})" class="btn-icon delete" title="Delete OFP">🗑️</button>
                        </td>
                    </tr>
                `;
            }).join('');
        } catch (error) {
            tbody.innerHTML = `<tr><td colspan="9" style="text-align: center; padding: 30px; color: var(--error);">Error loading OFPs: ${sanitizeHTML(error.message)}</td></tr>`;
        }
    };

    function initFileManagerTabs() {
        const tabOfp = document.getElementById('tab-ofp');
        const tabJourney = document.getElementById('tab-journey');
        const ofpContainer = document.getElementById('ofp-table-container');
        const journeyContainer = document.getElementById('journey-table-container');

        if (!tabOfp || !tabJourney || !ofpContainer || !journeyContainer) return;

        // Prevent attaching listeners multiple times
        if (tabOfp.dataset.initialized) return;
        tabOfp.dataset.initialized = "true";

        // Initial setup
        ofpContainer.style.display = 'block';
        journeyContainer.style.display = 'none';
        tabOfp.classList.add('active');
        tabJourney.classList.remove('active');

        tabOfp.addEventListener('click', () => {
            tabOfp.classList.add('active');
            tabJourney.classList.remove('active');
            ofpContainer.style.display = 'block';
            journeyContainer.style.display = 'none';
            renderOFPMangerTable();
        });

        tabJourney.addEventListener('click', () => {
            tabJourney.classList.add('active');
            tabOfp.classList.remove('active');
            ofpContainer.style.display = 'none';
            journeyContainer.style.display = 'block';
            if (typeof renderJourneyLogTable === 'function') renderJourneyLogTable();
        });
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', initFileManagerTabs);
    } else {
        initFileManagerTabs();
    }

    // High-speed parallelized database rewrite
    async function renumberOFPOrders() {
        const db = await getDB();
        const tx = db.transaction("ofps", "readwrite");
        const store = tx.objectStore("ofps");

        // 1. Scan lightweight metadata first
        const ofpsLight = await new Promise((resolve, reject) => {
            const items = [];
            const req = store.openCursor();
            req.onsuccess = (e) => {
                const cursor = e.target.result;
                if (cursor) {
                    items.push({ id: cursor.value.id, order: cursor.value.order || 0 });
                    cursor.continue();
                } else {
                    resolve(items);
                }
            };
            req.onerror = () => reject(req.error);
        });

        // 2. Sort accurately
        ofpsLight.sort((a, b) => a.order - b.order);

        // 3. Process the heavy get/put operations concurrently 
        await Promise.all(ofpsLight.map((item, index) => {
            return new Promise((res, rej) => {
                const getReq = store.get(item.id);
                getReq.onsuccess = () => {
                    const ofp = getReq.result;
                    ofp.order = index + 1;
                    const putReq = store.put(ofp);
                    putReq.onsuccess = res;
                    putReq.onerror = rej;
                };
                getReq.onerror = rej;
            });
        }));

        await new Promise((resolve, reject) => {
            tx.oncomplete = resolve;
            tx.onerror = () => reject(tx.error);
        });
    }

    function renderFuelTable() {
        const tb = document.getElementById('fuel-tbody');
        if (!tb) return;
        
        if (!fuelData || fuelData.length === 0) {
            tb.innerHTML = '<tr><td colspan="4" style="text-align:center;">No Fuel Data</td></tr>';
            return;
        }

        const orderMap = new Map(["ALTN", "FINAL RESERVE", "MIN DIVERSION", "CONTINGENCY", "MIN ADDITIONAL", "TOTAL RESERVE", "TRIP", "ENDURANCE", "TAXI", "EXTRA", "TANKERING", "BLOCK FUEL"].map((name, i) => [name, i]));
        
        const sorted = fuelData.filter(i => i.name !== "MINIMUM BLOCK").sort((a, b) => {
            const ia = orderMap.has(a.name) ? orderMap.get(a.name) : 99;
            const ib = orderMap.has(b.name) ? orderMap.get(b.name) : 99;
            return ia - ib;
        });
        
        // Single DOM injection
        tb.innerHTML = sorted.map(i => `<tr><td>${sanitizeHTML(i.name)}</td><td>${sanitizeHTML(i.time)}</td><td>${sanitizeHTML(i.fuel)}</td><td>${sanitizeHTML(i.remarks)}</td></tr>`).join('');
    }

    async function renderJourneyLogTable() {
        const tbody = document.getElementById('journey-log-tbody');
        if (!tbody) return;
        
        try {
            const logs = await getAllJourneyLogs();
            if (!logs || logs.length === 0) {
                tbody.innerHTML = '<tr><td colspan="5" style="text-align:center; padding:20px; color:var(--dim);">No finalized journey logs.</td></tr>';
                return;
            }
            
            tbody.innerHTML = logs.map(log => `
                <tr>
                    <td><strong>${sanitizeHTML(log.flight || '—')}</strong></td>
                    <td>${sanitizeHTML(log.date || '—')}</td>
                    <td>${log.legCount || '—'}</td>
                    <td>${log.finalizedAt ? new Date(log.finalizedAt).toLocaleString(undefined, {month:'short', day:'numeric', hour:'2-digit', minute:'2-digit'}) : '—'}</td>
                    <td style="white-space: nowrap;">
                        <button class="btn-icon download" onclick="downloadSavedJourneyLog(${log.id})" title="Download Log">⬇️</button>
                        <button class="btn-icon delete" onclick="deleteJourneyLog(${log.id})" title="Delete Log">🗑️</button>
                    </td>
                </tr>
            `).join('');
        } catch (error) {
            console.error("Failed to render journey logs:", error);
            tbody.innerHTML = '<tr><td colspan="5" style="text-align:center; color:var(--error);">Error loading logs.</td></tr>';
        }
    }

    function renderNotamsWXTable(alerts) {
        const container = document.getElementById('notam-results');
        if (!container) return;

        const runwaysMap = window.airportRunways || {};
        const metarsMap = window.airportMetars || {};

        if (!alerts || alerts.length === 0) {
            container.innerHTML = `
                <div class="airport-block">
                    <div class="alert-item info">
                        <span class="alert-message">No weather or NOTAM alerts to report.</span>
                    </div>
                </div>`;
            return;
        }

        // Preserve flight order: DEP -> DEST -> ALTN -> OTHER
        const grouped = new Map();
        alerts.forEach(alert => {
            const apt = (alert.airport || 'UNKNOWN').toUpperCase();
            if (!grouped.has(apt)) grouped.set(apt, []);
            grouped.get(apt).push(alert);
        });

        let html = '';

        for (const [apt, aptAlerts] of grouped.entries()) {
            const runway = runwaysMap[apt] || '';
            const metar = metarsMap[apt] || '';

            // Common pill style for Runway and METAR badges
            const pillStyle = `font-size: 13px; font-weight: normal; color: var(--text); background: var(--input); padding: 3px 10px; border-radius: 12px; border: 1px solid var(--border); display: inline-block;`;

            html += `
                <div class="airport-block">
                    <div class="airport-header" style="display: flex; align-items: center; gap: 10px; flex-wrap: wrap; margin-bottom: 12px;">
                        <span class="airport-code">${apt}</span>
                        ${runway ? `<span class="runway-info" style="${pillStyle}"><strong>RWY:</strong> ${runway}</span>` : ''}
                        ${metar ? `<span class="metar-info" style="${pillStyle}"><strong>METAR:</strong> ${metar}</span>` : ''}
                    </div>
                    <div class="alerts-list">
            `;

            aptAlerts.forEach(alert => {
                const severity = (alert.severity || 'info').toLowerCase();
                
                html += `
                    <div class="alert-item ${severity}">
                        <div class="alert-type">${alert.type || 'NOTAM'}</div>
                        <div class="alert-message">${alert.message}</div>
                    </div>
                `;
            });

            html += `
                    </div>
                </div>
            `;
        }

        container.innerHTML = html;
    }
    
    // Debounced search filtering to prevent UI lag while typing
    window.filterOFPs = debounce(function() {
        renderOFPMangerTable();
    }, 250);

    // Ultra-clean, reflow-optimized tab switcher
    window.showTab = window.showTab || function(id, btn) {
        // 1. Instantly swap active classes with a single DOM pass
        document.querySelectorAll('.tool-section.active, .nav-btn.active').forEach(el => el.classList.remove('active'));
        
        const targetSection = document.getElementById(`section-${id}`);
        if (targetSection) targetSection.classList.add('active');
        if (btn) btn.classList.add('active');
        
        // 2. Route specific logic
        switch(id) {
            case 'sectors':
                const tabOfp = document.getElementById('tab-ofp');
                const tabJourney = document.getElementById('tab-journey');
                const ofpContainer = document.getElementById('ofp-table-container');
                const journeyContainer = document.getElementById('journey-table-container');
                
                if (tabOfp && tabJourney && ofpContainer && journeyContainer) {
                    tabOfp.classList.add('active');
                    tabJourney.classList.remove('active');
                    ofpContainer.style.display = 'block';
                    journeyContainer.style.display = 'none';
                }
                
                // Allow CSS transition to fire before rendering heavy tables
                requestAnimationFrame(() => {
                    renderOFPMangerTable();
                    if (typeof renderJourneyLogTable === 'function') renderJourneyLogTable();
                });
                break;

            case 'assigned':
                if (typeof loadAssignedFlights === 'function') loadAssignedFlights();
                break;

            case 'summary':
                const savedMode = document.body.getAttribute('data-atis-mode') || (typeof currentAtisInputMode !== 'undefined' ? currentAtisInputMode : 'typing');
                if (typeof applyInputMode === 'function') applyInputMode(savedMode);
                
                // Delay canvas init until container is fully visible
                setTimeout(() => {
                    if (savedMode === 'writing') {
                        if (typeof pads !== 'undefined') {
                            if (!pads.atis.pad && typeof initPad === 'function') initPad('atis');
                            if (!pads.atc.pad && typeof initPad === 'function') initPad('atc');
                            if (pads.atis.pad) pads.atis.pad.onEnd = () => typeof debouncedSave === 'function' && debouncedSave();
                            if (pads.atc.pad) pads.atc.pad.onEnd = () => typeof debouncedSave === 'function' && debouncedSave();
                        }
                    } else if (typeof pads !== 'undefined') {
                        if (pads.atis.pad) { pads.atis.pad.off(); pads.atis.pad = null; }
                        if (pads.atc.pad) { pads.atc.pad.off(); pads.atc.pad = null; }
                    }
                }, 100);
                break;

            case 'confirm':
                if (typeof validateOFPInputs === 'function') validateOFPInputs();
                setTimeout(() => {
                    if (typeof resizePad === 'function') resizePad('main');
                    if (typeof restorePadDrawing === 'function') restorePadDrawing('main', 'signature');
                    if (typeof updateEmptyStates === 'function') updateEmptyStates(); 
                }, 50);
                break;

            case 'flight-analysis':
                if (typeof analyzeNotamsAndWeather === 'function') analyzeNotamsAndWeather();
                break;
        }

        // 3. Final UI cleanup
        if (typeof updateUploadButtonVisibility === 'function') updateUploadButtonVisibility();
    };

// ==========================================
// 8. NAVIGATION MENU
// ==========================================

    function initializeTabNavigation() {
        const buttons = document.querySelectorAll('.nav-btn');
        
        buttons.forEach(button => {
            // High-speed native event router instead of regex parsing
            const tabId = button.dataset.tab || button.getAttribute('onclick')?.match(/showTab\('([^']+)'/)?.[1];
            
            if (tabId) {
                // Remove inline onclick to prevent double-firing
                button.removeAttribute('onclick');
                
                button.addEventListener('click', function(e) {
                    e.preventDefault();
                    if (typeof window.showTab === 'function') {
                        window.showTab(tabId, this);
                    }
                });
            }
        });
    }

    async function renderPDFPreview(pdfBytes) {
        const container = document.getElementById('pdf-render-container');
        const fallback = document.getElementById('pdf-fallback');
        
        if (!container || !pdfBytes) return;
        
        // --- MEMORY LEAK FIX ---
        // Explicitly clear old canvases to force garbage collection before destroying DOM
        const oldCanvases = container.querySelectorAll('canvas');
        oldCanvases.forEach(c => {
            c.width = 0; 
            c.height = 0;
        });
        container.innerHTML = '';
        container.style.display = 'none';

        if (fallback) {
            fallback.style.display = 'flex';
            fallback.innerHTML = `<span style="font-size:30px; margin-bottom:10px;">⏳</span><span>Loading PDF preview...</span>`;
        }
        
        try {
            const settings = JSON.parse(localStorage.getItem('efb_settings') || '{}');
            const pdfQuality = settings.pdfQuality || '1.0';

            const qualityMultipliers = { '0.8': 1.0, '1.0': 1.5, '1.5': 2.0, '2.0': 3.0 };
            const multiplier = qualityMultipliers[pdfQuality] || 1.5;

            const deviceScale = window.devicePixelRatio || 1;
            let scale = Math.max(Math.min(deviceScale * multiplier, 5.0), 1.0);

            const pdf = await pdfjsLib.getDocument(pdfBytes).promise;
            const totalPages = pdf.numPages;

            if (fallback) fallback.style.display = 'none';
            container.style.display = 'block';

            const progressDiv = document.createElement('div');
            progressDiv.style.cssText = `position: sticky; top: 0; background: var(--accent); color: white; padding: 10px; text-align: center; font-size: 14px; z-index: 100; border-radius: 5px; margin-bottom: 10px; box-shadow: 0 4px 6px rgba(0,0,0,0.1);`;
            progressDiv.textContent = `Rendering page 1 of ${totalPages}...`;
            container.appendChild(progressDiv);

            const pagesWrapper = document.createElement('div');
            pagesWrapper.style.cssText = `display: flex; flex-direction: column; align-items: center; gap: 15px;`;
            container.appendChild(pagesWrapper);

            for (let pageNum = 1; pageNum <= totalPages; pageNum++) {
                try {
                    progressDiv.textContent = `Rendering page ${pageNum} of ${totalPages}...`;
                    
                    // Allow UI thread to breathe to prevent iPad freezing
                    await new Promise(resolve => requestAnimationFrame(resolve));

                    const page = await pdf.getPage(pageNum);
                    const viewport = page.getViewport({ scale });

                    const canvas = document.createElement('canvas');
                    const context = canvas.getContext('2d');
                    canvas.width = viewport.width;
                    canvas.height = viewport.height;
                    
                    canvas.style.cssText = `width: 100%; height: auto; margin-bottom: 5px; background: white; border-radius: 4px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); display: block;`;

                    const pageContainer = document.createElement('div');
                    pageContainer.style.cssText = `text-align: center; width: 100%;`;
                    
                    const pageLabel = document.createElement('div');
                    pageLabel.style.cssText = `font-size: 12px; color: #666; font-family: monospace; background: #f5f5f5; padding: 3px 10px; border-radius: 3px; display: inline-block; margin-bottom: 5px;`;
                    pageLabel.textContent = `Page ${pageNum}`;

                    pageContainer.appendChild(pageLabel);
                    pageContainer.appendChild(canvas);
                    pagesWrapper.appendChild(pageContainer);

                    await page.render({ canvasContext: context, viewport }).promise;
                } catch (pageError) {
                    console.warn(`Error rendering page ${pageNum}:`, pageError);
                    const errorDiv = document.createElement('div');
                    errorDiv.style.cssText = `background: #fff3cd; border: 1px solid #ffeaa7; padding: 15px; color: #856404; text-align: center; width: 100%; border-radius: 4px;`;
                    errorDiv.innerHTML = `<strong>Page ${pageNum}:</strong> Failed to render`;
                    pagesWrapper.appendChild(errorDiv);
                }
            }

            progressDiv.remove();

            const summary = document.createElement('div');
            summary.style.cssText = `text-align: center; color: var(--dim); font-size: 12px; padding: 15px; border-top: 1px solid var(--border); width: 100%; margin-top: 10px;`;
            const qualityLabels = { '0.8': 'Low', '1.0': 'Medium', '1.5': 'High', '2.0': 'Maximum' };
            summary.textContent = `Rendered ${totalPages} pages at ${qualityLabels[pdfQuality] || 'Medium'} Quality (${(scale * 100).toFixed(0)}% scale)`;
            pagesWrapper.appendChild(summary);

        } catch (error) {
            console.error("Critical error rendering PDF:", error);
            container.style.display = 'none';
            if (fallback) {
                fallback.style.display = 'flex';
                fallback.innerHTML = `
                    <div style="text-align: center;">
                        <span style="font-size:30px; margin-bottom:10px;">❌</span>
                        <h3 style="color: var(--error);">Rendering Failed</h3>
                        <p style="color: var(--dim); margin: 10px 0;">${error.message || 'Unable to process PDF'}</p>
                        <button onclick="retryPDFRender()" style="padding: 10px 20px; background: var(--accent); color: white; border: none; border-radius: 6px; cursor: pointer; margin-top: 10px;">Try Again</button>
                    </div>`;
            }
        }
    }

    window.retryPDFRender = async function() {
        if (window.ofpPdfBytes) {
            await renderPDFPreview(window.ofpPdfBytes);
        } else {
            showToast("No PDF loaded. Please upload an OFP first.", "error");
        }
    };

    function updateUIAfterParsing() {
        const val = blockFuelValue || 0;
        safeSet('view-pic-block', val); // Uses smart DOM logic
        
        if (typeof runFlightLogCalculations === 'function') runFlightLogCalculations();
        renderFuelTable();
        if (typeof renderFlightLogTables === 'function') renderFlightLogTables();
    }

    
// ==========================================
// 8. DRAWING PAD ENGINE
// ==========================================
// Attaches the save listener natively
    function attachPadOnEnd(pad, name) {
        if (!pad) return;

        pad.onEnd = () => {
            if (typeof debouncedSave === 'function') debouncedSave();
            if (name === 'main' && typeof validateOFPInputs === 'function') {
                validateOFPInputs();
            }
        };
    }

    function initPad(name) {
        const p = pads[name];
        if (!p) return;
        
        const canvas = document.getElementById(p.canvasId);
        if (!canvas) return;

        const container = canvas.parentElement || canvas.parentNode;
        
        // Always measure the PARENT container box width (fixes 200px narrow collapse)
        const containerWidth = (container ? container.clientWidth : 0) || canvas.offsetWidth || 300;
        const containerHeight = (container ? container.clientHeight : 0) || canvas.offsetHeight || 150;

        // Don't initialize if container is completely hidden (0 width)
        if (containerWidth === 0) return;

        const ratio = Math.max(window.devicePixelRatio || 1, 1);

        // Set actual internal dimensions for Retina crispness
        canvas.width = containerWidth * ratio;
        canvas.height = containerHeight * ratio;
        
        // CSS dimensions dictate physical size (force 100% parent match)
        canvas.style.width = '100%';
        canvas.style.height = `${containerHeight}px`;

        const ctx = canvas.getContext('2d');
        ctx.scale(ratio, ratio);

        // Fetch user's CSS accent color dynamically
        const penColor = window.getComputedStyle(document.documentElement).getPropertyValue('--accent').trim() || '#007aff';

        p.pad = new SignaturePad(canvas, {
            backgroundColor: 'rgba(0,0,0,0)',
            penColor: penColor,
            minWidth: 1,
            maxWidth: 3
        });

        attachPadOnEnd(p.pad, name);

        // Restore saved drawings mapping
        const saveKeys = {
            'main': 'signature',
            'atis': 'front-atis-drawing',
            'atc': 'front-atc-drawing'
        };
        
        if (saveKeys[name]) restorePadDrawing(name, saveKeys[name]);

        p.lastWidth = containerWidth;
        p.lastHeight = containerHeight;
        p.lastRatio = ratio;

        return p.pad;
    }

    // Resize handler for iPad rotation / window resizing
    function resizePad(name) {
        const p = pads[name];
        if (!p || !p.pad) return;
        
        const canvas = p.pad.canvas;
        const container = canvas ? canvas.parentElement : null;
        if (!canvas || !container || container.clientWidth === 0) return;

        const ratio = Math.max(window.devicePixelRatio || 1, 1);
        const containerWidth = container.clientWidth;
        const containerHeight = container.clientHeight || canvas.offsetHeight;

        // Only resize if physical dimensions actually changed
        if (containerWidth === p.lastWidth && containerHeight === p.lastHeight && ratio === p.lastRatio) {
            return;
        }

        // Cache the current drawing data before wiping the canvas
        const currentData = p.pad.isEmpty() ? null : p.pad.toDataURL();

        // Re-scale internal resolution
        canvas.width = containerWidth * ratio;
        canvas.height = containerHeight * ratio;
        canvas.style.width = '100%';
        canvas.style.height = `${containerHeight}px`;

        const ctx = canvas.getContext('2d');
        ctx.scale(ratio, ratio);

        // Re-initialize pad to recalculate bounding boxes
        const penColor = window.getComputedStyle(document.documentElement).getPropertyValue('--accent').trim() || '#007aff';
        
        p.pad.clear();
        p.pad.penColor = penColor;

        // Restore drawing safely
        if (currentData) {
            p.pad.fromDataURL(currentData);
        }

        p.lastWidth = containerWidth;
        p.lastHeight = containerHeight;
        p.lastRatio = ratio;
    }

    async function restorePadDrawing(padName, drawingKey) {
        const activeId = localStorage.getItem('activeOFPId');
        if (!activeId) return;

        try {
            // First check the database for the active flight
            const userData = typeof loadOFPUserData === 'function' ? await loadOFPUserData(Number(activeId)) : null;
            let data = userData?.userInputs?.[drawingKey];

            // If not found, check the temporary legacy fallback in LocalStorage
            if (!data) {
                const legacyMap = { 'front-atis-drawing': 'atis', 'front-atc-drawing': 'atc', 'signature': 'signature' };
                const backupKey = `drawing_backup_${activeId}_${legacyMap[drawingKey]}`;
                data = localStorage.getItem(backupKey);
            }

            // Only attempt to load valid, non-empty base64 PNGs
            if (!data || !data.startsWith('data:image/png;base64,') || data.length < 100) return;

            const pad = pads[padName]?.pad;
            if (!pad) {
                setTimeout(() => restorePadDrawing(padName, drawingKey), 100);
                return;
            }

            const canvas = pad.canvas;
            if (canvas.offsetWidth === 0 || canvas.offsetHeight === 0) {
                setTimeout(() => restorePadDrawing(padName, drawingKey), 200);
                return;
            }

            // Load drawing directly (REMOVED the recursive resizePad call here!)
            await pad.fromDataURL(data);
            
        } catch (e) {
            console.error(`Failed to restore ${drawingKey} to ${padName}:`, e);
        }
    }

    function clearPad(padName) {
        const pad = pads[padName]?.pad;
        if (!pad) return;
        
        pad.clear();
        
        if (padName === 'main' && typeof validateOFPInputs === 'function') {
            validateOFPInputs();
        }

        const activeId = localStorage.getItem('activeOFPId');
        if (activeId) {
            const legacyMap = { 'main': 'signature', 'atis': 'atis', 'atc': 'atc' };
            localStorage.removeItem(`drawing_backup_${activeId}_${legacyMap[padName]}`);
        }

        if (typeof debouncedSave === 'function') debouncedSave();
    }

    // Toggle UI between Text Inputs and Drawing Canvases
    function applyInputMode(mode) {
        if (mode === currentAtisInputMode) return;
        currentAtisInputMode = mode;

        const uiElements = {
            atis: { input: document.getElementById('front-atis'), canvas: document.getElementById('front-atis-canvas') },
            atc: { input: document.getElementById('front-atc'), canvas: document.getElementById('front-atc-canvas') }
        };

        if (mode === 'typing') {
            if (typeof debouncedSave === 'function') debouncedSave.cancel();
            if (typeof saveState === 'function') saveState();

            ['atis', 'atc'].forEach(key => {
                if (uiElements[key].input) uiElements[key].input.style.display = 'block';
                if (uiElements[key].canvas) uiElements[key].canvas.style.display = 'none';
                
                if (pads[key]?.pad) {
                    pads[key].pad.off();
                    pads[key].pad = null;
                }
            });

        } else { // 'writing' mode
            ['atis', 'atc'].forEach(key => {
                if (uiElements[key].input) uiElements[key].input.style.display = 'none';
                if (uiElements[key].canvas) uiElements[key].canvas.style.display = 'block';
            });

            requestAnimationFrame(() => {
                setTimeout(() => {
                    if (!pads.atis.pad) initPad('atis');
                    if (!pads.atc.pad) initPad('atc');
                }, 100);
            });
        }
        
        document.body.setAttribute('data-atis-mode', mode);
    }

// ==========================================
// 9. Journey Log
// ==========================================

    function updateFloatingButtonVisibility() {
        const floatingBtn = el('floating-upload-btn');
        const floatingGroup = el('floating-btn-group');
        if (!floatingBtn || !floatingGroup) return;
        
        const activeSection = document.querySelector('.tool-section.active');
        const isJourney = activeSection && activeSection.id === 'section-journey';
        
        // Collapse the logic: Hide if on Journey tab OR if OFP is loaded
        const action = (isJourney || isOFPLoaded) ? 'add' : 'remove';
        floatingBtn.classList[action]('hidden');
        floatingGroup.classList[action]('hidden');
    }

    function createWaypointRowHtml(wp, i, pre) {
        const timeInput = `<input type="time" id="${pre}-a-${i}" class="input" style="padding:8px" inputmode="numeric" pattern="[0-9]*">`;
        const actFuelInput = `<input type="number" id="${pre}-f-${i}" class="input" style="width:70px; padding:8px; background:rgba(255,255,255,0.05); border:1px solid var(--border); color:var(--text); text-align:center;">`;
        const actFlInput = `<input type="number" id="${pre}-agl-${i}" class="input" maxlength="3" style="width:50px;padding:8px;text-align:center;color:var(--accent)">`;
        const notesInput = `<input type="text" id="${pre}-n-${i}" class="input" style="padding:8px; width:100%" placeholder="...">`;

        return `<tr data-index="${i}" data-type="${pre}">
            <td style="font-weight:bold">${sanitizeHTML(wp.name)}</td>
            <td style="font-size:12px">${sanitizeHTML(wp.awy || "-")}</td>
            <td style="font-size:12px">${sanitizeHTML(wp.sr || "-")}</td> 
            <td style="font-size:12px; font-weight:bold; color:var(--text)">${sanitizeHTML(wp.level || "-")}</td>
            <td style="font-size:12px">${sanitizeHTML(wp.track || "-")}</td>
            <td style="font-size:12px">${sanitizeHTML(wp.wind || "-")}</td>
            <td style="font-size:12px">${sanitizeHTML(wp.tas || "-")}</td>
            <td style="font-size:12px">${sanitizeHTML(wp.gs || "-")}</td>
            <td>${notesInput}</td>
            <td id="${pre}-eto-${i}" class="eto-cell">${sanitizeHTML(wp.eto || "--")}</td>
            <td>${timeInput}</td>
            <td id="${pre}-calcfuel-${i}" class="fuel-cell">${wp.fuel ? Math.round(wp.fuel) : "-"}</td>
            <td>${actFuelInput}</td>
            <td>${actFlInput}</td>
        </tr>`;
    }

    window.renderJourneyList = function() {
        const tb = el('journey-list-body');
        if (!tb) return;

        if (!dailyLegs || dailyLegs.length === 0) {
            tb.innerHTML = '<tr><td colspan="4" style="text-align:center; padding: 15px; color: var(--dim);">No legs added.</td></tr>';
            return;
        }

        tb.innerHTML = dailyLegs.map((l, i) => {
            const canMoveUp = i > 0; 
            const canMoveDown = i < dailyLegs.length - 1;
            return `
            <tr>
                <td style="text-align:center; font-weight:bold;">${i + 1}</td>
                <td>${sanitizeHTML(l['j-flt'])}</td>
                <td>${sanitizeHTML(l['j-dep'])} - ${sanitizeHTML(l['j-dest'])}</td>
                <td style="white-space: nowrap; text-align: right;">
                    <button onclick="moveLeg(${i}, -1)" class="btn-icon" ${!canMoveUp ? 'disabled style="opacity:0.3"' : ''} title="Move Up">▲</button>
                    <button onclick="moveLeg(${i}, 1)" class="btn-icon" ${!canMoveDown ? 'disabled style="opacity:0.3"' : ''} title="Move Down">▼</button>
                    <button onclick="modifyLeg(${i})" class="btn-action modify" style="margin-left: 8px;">Edit</button>
                    <button onclick="removeLeg(${i})" class="btn-action delete" style="margin-left: 5px;">Delete</button>
                </td>
            </tr>`;
        }).join('');
    };

    function clearJourneyInputs(transferFuel = "") {
        ['j-out', 'j-off', 'j-on', 'j-in', 'j-night', 'j-to', 'j-ldg', 'j-ldg-type', 'j-ldg-detail',
         'j-uplift-w', 'j-uplift-vol', 'j-act-ramp', 'j-shut', 'j-slip', 'j-slip-2', 'j-adl', 
         'j-chl', 'j-inf', 'j-bag', 'j-cargo', 'j-mail', 'j-zfw', 'j-std', 'j-sta'].forEach(id => safeSet(id, ''));
        
        safeSet('j-init', transferFuel || '');
        
        ['j-flight','j-block'].forEach(id => safeSet(id, '00:00'));
        ['j-calc-ramp','j-burn','j-disc'].forEach(id => safeSet(id, '0'));
    }

    window.addLeg = function() {
        const dest = el('j-dest')?.value;
        const dep = el('j-dep')?.value;
        if (!dest || !dep) return showToast("No legs to insert", "error");
        if (dailyLegs.length >= 4) return showToast("Max 4 legs allowed.", "error");

        const form = el('leg-input-form');
        if (form) form.style.setProperty("display", "none", "important");

        // Duty calculation for first leg
        if (dailyLegs.length === 0) {
            const currentFC = el('j-duty-start')?.value;
            const currentCC = el('j-cc-duty-start')?.value;

            if (!currentFC || currentFC === "00:00" || !currentCC || currentCC === "00:00") {
                const dutyValues = calculateDutyValues(el('j-std')?.value || "", el('j-flt')?.value || "", dep, dest);
                
                if (!currentFC || currentFC === "00:00") safeSet('j-duty-start', dutyValues.fc);
                if (!currentCC || currentCC === "00:00") safeSet('j-cc-duty-start', dutyValues.cc);
                if (!el('j-max-fdp')?.value || el('j-max-fdp')?.value === "00:00") safeSet('j-max-fdp', dutyValues.max);
                
                setCCMaxFDP(dutyValues.ccMax);
            }
            dutyStartTime = parseTimeStr(el('j-duty-start')?.value);
        }

        // Night Block calculation
        const offBlock = el('j-off')?.value;
        const onBlock = el('j-in')?.value;
        if (offBlock && onBlock) {
            const nightBlockTime = calculateNightDuty(parseTimeStr(offBlock), parseTimeStr(onBlock));
            safeSet('j-night-calc', nightBlockTime);
            if (!el('j-night')?.value) safeSet('j-night', nightBlockTime);
        } else {
            safeSet('j-night-calc', '00:00');
        }

        // Optimized data collection
        const d = {};
        const keysToSave = [
            'j-date', 'j-std', 'j-sta', 'j-flt', 'j-reg', 'j-dep', 'j-dest', 'j-altn', 'j-out', 'j-off', 'j-on', 'j-in', 
            'j-block', 'j-flight', 'j-night', 'j-to', 'j-ldg', 'j-ldg-type', 'j-flt-alt', 'j-ldg-detail', 'j-init', 
            'j-uplift-w', 'j-calc-ramp', 'j-act-ramp', 'j-shut', 'j-burn', 'j-uplift-vol', 'j-slip', 'j-slip-2', 'j-disc', 
            'j-adl', 'j-chl', 'j-inf', 'j-cargo', 'j-mail', 'j-bag', 'j-zfw',
            'view-date', 'view-reg', 'view-dep', 'view-arr', 'view-std-text', 'view-sta-text'
        ];

        keysToSave.forEach(k => {
            const e = el(k);
            d[k] = e ? (e.tagName === 'INPUT' || e.tagName === 'SELECT' || e.tagName === 'TEXTAREA' ? e.value : (e.innerText || e.textContent)) : "";
        });

        // Cross-map keys safely
        d['view-date'] = d['view-date'] || d['j-date'];
        d['view-reg'] = d['view-reg'] || d['j-reg'];
        d['view-dep'] = d['view-dep'] || d['j-dep'];
        d['view-arr'] = d['view-arr'] || d['j-dest'];
        d['view-std-text'] = d['view-std-text'] || d['j-std'];
        d['view-sta-text'] = d['view-sta-text'] || d['j-sta'];

        d['j-date'] = d['j-date'] || d['view-date'];
        d['j-arr'] = d['j-arr'] || d['view-arr'] || d['j-dest'];
        d['j-atd'] = d['j-out']; 
        d['j-sta'] = d['view-sta-text'] || d['j-sta']; 
        d.nightTime = d['j-night'] || "00:00"; 
        
        dailyLegs.push(d);
        
        if (typeof recalcMaxFDP === 'function') requestAnimationFrame(recalcMaxFDP);

        renderJourneyList();
        clearJourneyInputs(d['j-shut']);
        ['j-dep', 'j-dest'].forEach(id => safeSet(id, ''));
        
        saveState();
    };

    window.moveLeg = function(index, direction) {
        const newIndex = index + direction;
        if (newIndex < 0 || newIndex >= dailyLegs.length) return;

        // Swap array elements
        [dailyLegs[index], dailyLegs[newIndex]] = [dailyLegs[newIndex], dailyLegs[index]];

        // Recalculate duty if first leg changed
        if (index === 0 || newIndex === 0) {
            const firstLeg = dailyLegs[0];
            const newDutyValues = calculateDutyValues(firstLeg['j-std'], firstLeg['j-flt'], firstLeg['j-dep'], firstLeg['j-dest']);
            
            safeSet('j-duty-start', newDutyValues.fc);
            safeSet('j-cc-duty-start', newDutyValues.cc);
            safeSet('j-max-fdp', newDutyValues.max);
            setCCMaxFDP(newDutyValues.ccMax);
            
            dutyStartTime = parseTimeStr(newDutyValues.fc);
        }

        if (typeof recalcMaxFDP === 'function') recalcMaxFDP();
        renderJourneyList();
        saveState();
    };

    window.modifyLeg = function(index) {
        const leg = dailyLegs[index];
        if (!leg) return;

        Object.keys(leg).forEach(key => safeSet(key, leg[key]));

        dailyLegs.splice(index, 1);
        renderJourneyList();
        
        if (index === 0) {
            safeSet('j-duty-start', '00:00'); 
            dutyStartTime = null; 
        }

        const form = el('leg-input-form');
        if (form) {
            form.style.display = 'block';
            form.scrollIntoView({ behavior: 'smooth' });
        }
        showToast("Leg loaded for editing. Click '+ Add Leg' when finished.", "info");
    };

    window.removeLeg = function(i) {
        dailyLegs.splice(i, 1);
        
        if (dailyLegs.length === 0) { 
            ['j-duty-start', 'j-cc-duty-start', 'j-max-fdp'].forEach(id => safeSet(id, "00:00"));
            setCCMaxFDP("00:00");
            dutyStartTime = null;
            
            const form = el('leg-input-form');
            if (form) form.style.display = 'block';
        }
        
        renderJourneyList(); 
        saveState();
    };

    window.updateCruiseLevelForJourneyLog = function() {
        let finalLevel = "";
        
        // Default: Planned from OFP
        if (waypoints && waypoints.length > 0) {
            const cruiseWP = waypoints.find(w => /^\d{3}$/.test(w.level) && w.level !== "000");
            if (cruiseWP) finalLevel = "FL" + cruiseWP.level;
        }

        // O(1) Check Actual Levels via precise IDs instead of querySelectorAll
        let maxAct = 0;
        if (waypoints && waypoints.length > 0) {
            for (let i = 0; i < waypoints.length; i++) {
                const input = el(`o-agl-${i}`);
                if (input && input.value) {
                    const val = parseInt(input.value);
                    if (val > maxAct) maxAct = val;
                }
            }
        }

        if (maxAct > 0) finalLevel = "FL" + maxAct;
        safeSet('j-flt-alt', finalLevel);
    };

    window.syncLastWaypoint = function() {
        if (!waypoints || waypoints.length === 0) return;
        const lastIdx = waypoints.length - 1;
        const wp = waypoints[lastIdx];

        const lastATO = el(`o-a-${lastIdx}`)?.value;
        const currentETO = wp.eto ? (wp.eto.substring(0,2) + ":" + wp.eto.substring(2,4)) : "";
        
        const finalTime = lastATO || currentETO;
        if (finalTime) safeSet('j-on', finalTime);

        const lastFuel = el(`o-f-${lastIdx}`)?.value;
        const currentEFOB = Math.round(wp.fuel) || "";

        const finalFuel = lastFuel || currentEFOB;
        if (finalFuel) safeSet('j-shut', finalFuel);

        calculateTripTimeForJourneyLog(); 
        calculateFuelForJourneyLog();
    };

// ==========================================
// 11. Download Managment
// ==========================================

    async function sharePdf(pdfBytes, filename, subject, body) {
        // Create Blob and File in one clean line
        const file = new File([new Blob([pdfBytes], { type: 'application/pdf' })], filename, { type: 'application/pdf' });

        // Fire-and-forget clipboard copy (silently handles failure if permissions are denied)
        if (navigator.clipboard && navigator.clipboard.writeText) {
            navigator.clipboard.writeText("ofp@airastana.com").catch(() => {});
        }

        // Try native iOS/iPadOS Share Sheet
        if (navigator.canShare && navigator.canShare({ files: [file] })) {
            try {
                await navigator.share({
                    files: [file],
                    title: subject,
                    text: body || subject
                });
                return; // Native share successful
            } catch (err) {
                console.warn("Share cancelled or failed, falling back to download.");
                // Let it fall through to downloadBlob
            }
        }
        
        // Fallback for Desktop browsers or unsupported devices
        downloadBlob(pdfBytes, filename);
    }

    // High-performance download with Memory Leak protection
    function downloadBlob(bytes, name) {
        const blob = new Blob([bytes], { type: 'application/pdf' });
        const url = URL.createObjectURL(blob);
        
        const link = document.createElement('a');
        link.href = url;
        link.download = name;
        
        // Modern DOM appending and clicking
        document.body.appendChild(link);
        link.click();
        link.remove(); 
        
        // CRITICAL: Release the memory back to the iPad after a short delay
        setTimeout(() => URL.revokeObjectURL(url), 100);
    }

// ==========================================
// 9. Journey Log Download
// ==========================================

    async function loadBuiltInTemplate() {
        try {
            const response = await fetch(`./journey_log_template.pdf?v=${Date.now()}`, { cache: 'no-store' });
            if (!response.ok) throw new Error(`HTTP ${response.status}`);
            return await response.arrayBuffer();
        } catch (error) {
            console.error("Failed to load built-in template:", error);
            if (typeof showToast === 'function') showToast("Could not load Journey Log template.", "error");
            return null;
        }
    }

    // High-speed array scanner (O(N) instead of parsing the whole PDF)
    function findAnchor(textItems, searchText) {
        if (!textItems || !searchText) return null;
        const searchTarget = searchText.toLowerCase();
        const found = textItems.find(item => item.str && item.str.toLowerCase().includes(searchTarget));
        return found ? found.transform : null; // Returns [scaleX, skewX, skewY, scaleY, x, y]
    }

    window.downloadJourneyLog = async function(mode = 'download') {
        if (!dailyLegs || dailyLegs.length === 0) return showToast("No legs to print.", "error");

        try {
            if (typeof logSecurityEvent === 'function') {
                await logSecurityEvent('JOURNEY_LOG_GENERATE', { mode, legCount: dailyLegs.length });
            }

            if (!journeyLogTemplateBytes || journeyLogTemplateBytes.byteLength === 0) {
                journeyLogTemplateBytes = await loadBuiltInTemplate();
                if (!journeyLogTemplateBytes) {
                    if (typeof isFinalizingJourneyLog !== 'undefined') isFinalizingJourneyLog = false;
                    return; 
                }
            }

            // 1. EXTRACT TEXT ITEMS
            const loadingTask = pdfjsLib.getDocument({ data: journeyLogTemplateBytes });
            const textPdf = await loadingTask.promise;
            const textPage = await textPdf.getPage(1);
            const textContent = await textPage.getTextContent();
            const textItems = textContent.items;

            // 2. SETUP DRAWING CANVAS
            const pdfDoc = await PDFLib.PDFDocument.load(journeyLogTemplateBytes);
            const page = pdfDoc.getPages()[0];
            const font = await pdfDoc.embedFont(PDFLib.StandardFonts.HelveticaBold);
            
            const isIpadMode = document.getElementById('chk-ipad-mode')?.checked;
            if (!isIpadMode) page.setRotation(PDFLib.degrees(0));

            const templateRows = parseInt(document.getElementById('j-template-rows')?.value || "4");
            const rowGap = JOURNEY_CONFIG?.rowGap || 15; 
            const nameFontSize = JOURNEY_CONFIG?.fontSize || 8; 

            // 3. FETCH CREW IF NEEDED
            const settings = JSON.parse(localStorage.getItem('efb_settings') || '{}');
            const shouldHideAll = settings.hideAllDuty === true;
            
            if ((!window.crewData || window.crewData.length === 0) && !shouldHideAll) {
                try {
                    const token = typeof getValidSkyplanToken === 'function' ? await getValidSkyplanToken() : null;
                    if (token) {
                        let extId = window.currentExternalFlightId;
                        if (!extId && dailyLegs[0]) {
                            const fltRaw = el('j-flt')?.value || '';
                            const dateRaw = el('j-date')?.value || '';
                            const depRaw = dailyLegs[0]['j-dep'] || '';
                            if (fltRaw && dateRaw && depRaw && typeof fetchFlightIdFromRoster === 'function') {
                                extId = await fetchFlightIdFromRoster(dateRaw, fltRaw, depRaw);
                                window.currentExternalFlightId = extId;
                            }
                        }
                        
                        if (extId) {
                            const resp = await fetch('https://kcskyplanapi.airastana.com/api/v1/flights-crew-members', {
                                method: 'POST',
                                headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` },
                                body: JSON.stringify({ FlightIDs: [extId] })
                            });
                            if (resp.ok) {
                                const data = await resp.json();
                                const members = data.FlightsCrewMembers?.[0]?.CrewMembers || [];
                                const flightDeck = members.filter(m => ['CP', 'FO', 'P1', 'P2', 'SO'].includes(m.Position));
                                const cabinCrew = members.filter(m => !flightDeck.includes(m));
                                window.crewData = [...flightDeck, ...cabinCrew];
                            }
                        }
                    }
                } catch(e) {
                    console.warn("Failed to fetch crew manifest:", e);
                }
            }
            const activeCrewList = window.crewData || [];

            // 4. DRAW STATIC HEADERS
            const catAnchor = findAnchor(textItems, "L/T");
            if (catAnchor) page.drawText("75/125", { x: catAnchor[4] - 30, y: catAnchor[5], size: nameFontSize, font });

            let captainNameStr = localStorage.getItem('efb_captain_name') || activeCrewList.find(m => m.Position === 'CP') 
                ? `${activeCrewList.find(m => m.Position === 'CP').FirstName || ''} ${activeCrewList.find(m => m.Position === 'CP').LastName || ''}`.trim().toUpperCase() 
                : "";

            if (captainNameStr) {
                const capAnchor = findAnchor(textItems, "Captain/KBC:");
                if (capAnchor) {
                    page.drawText(captainNameStr, { x: capAnchor[4] + 30, y: capAnchor[5], size: nameFontSize, font });
                }
            }

            // 5. DRAW DYNAMIC HEADERS & LEGS
            const headerDrop = 16; 
            const drawLegData = (anchor, shiftX, keys, baselineY, isFuelCol = false) => {
                if (!anchor) return;
                const colX = anchor[4] + shiftX;
                const baseY = baselineY ?? (anchor[5] - headerDrop);

                dailyLegs.forEach((leg, idx) => {
                    if (idx >= templateRows) return;
                    
                    let val = keys.map(k => leg[k]).find(v => v !== undefined && v !== null && v !== "");
                    
                    if (!val && idx === 0) { // Fallback to DOM for first leg
                        for (const key of keys) {
                            const domEl = document.getElementById(key);
                            if (domEl) {
                                val = domEl.value || domEl.textContent;
                                if (val) break;
                            }
                        }
                    }

                    if (val && String(val).trim() !== "") {
                        page.drawText(String(val).trim().toUpperCase(), { 
                            x: colX, 
                            y: baseY - (idx * rowGap), 
                            size: nameFontSize, 
                            font 
                        });
                    }
                });
            };

            // Top Headers
            [
                { search: 'Date', shiftX: -10, keys: ['j-date'] },
                { search: 'flight', shiftX: -8, keys: ['j-flt'] },
                { search: 'Ac.Reg', shiftX: -5, keys: ['j-reg'] },
                { search: 'Dep', shiftX: -5, keys: ['j-dep'] },
                { search: 'Arr', shiftX: -5, keys: ['j-arr'] },
                { search: 'STD', shiftX: -5, keys: ['j-std'] },
                { search: 'STA', shiftX: -5, keys: ['j-sta'] }
            ].forEach(h => drawLegData(findAnchor(textItems, h.search), h.shiftX, h.keys));

            // Main & Fuel Tables
            const mainRefY = (findAnchor(textItems, 'ATD') || findAnchor(textItems, 'TKOF') || [0,0,0,0,0, 680 + headerDrop])[5] - headerDrop;
            const fuelRefY = (findAnchor(textItems, 'Init') || findAnchor(textItems, 'UplfW') || [0,0,0,0,0, 480 + headerDrop])[5] - headerDrop;

            const logColumnDefs = [
                { search: 'ATD', keys: ['j-atd'], shiftX: -5, category: 'main' },
                { search: 'ATA', keys: ['j-in'], shiftX: -5, category: 'main' },
                { search: 'Off-Block', keys: ['j-out'], shiftX: -5, category: 'main' },
                { search: 'TKOF', keys: ['j-off'], shiftX: -5, category: 'main' },
                { search: 'TDWN', keys: ['j-on'], shiftX: -5, category: 'main' },
                { search: 'Blk', keys: ['j-block'], shiftX: -5, category: 'main' },
                { search: 'Flt', keys: ['j-flight'], shiftX: -5, category: 'main' },
                { search: 'NtBLK', keys: ['j-night'], shiftX: -5, category: 'main' },
                { search: 'TO', keys: ['j-to'], shiftX: -5, category: 'main' },
                { search: 'LD', keys: ['j-ldg'], shiftX: -5, category: 'main' },
                { search: 'MA', keys: ['j-ldg-type'], shiftX: -5, category: 'main' },
                { search: 'FlAlt', keys: ['j-flt-alt'], shiftX: -5, category: 'main' },
                { search: 'DETAIL', keys: ['j-ldg-detail'], shiftX: -5, category: 'main' },
                { search: 'Init', keys: ['j-init'], shiftX: -5, category: 'fuel' },
                { search: 'UplfW', keys: ['j-uplift-w'], shiftX: -5, category: 'fuel' },
                { search: 'UplfV', keys: ['j-uplift-vol'], shiftX: -5, category: 'fuel' },
                { search: 'Calc Ramp', keys: ['j-calc-ramp'], shiftX: -2, category: 'fuel' },
                { search: 'Act Ramp', keys: ['j-act-ramp'], shiftX: -2, category: 'fuel' },
                { search: 'Stdn', keys: ['j-shut'], shiftX: -5, category: 'fuel' },
                { search: 'Burn', keys: ['j-burn'], shiftX: -5, category: 'fuel' },
                { search: 'Fuel Disc', keys: ['j-disc'], shiftX: -2, category: 'fuel' },
                { search: 'Slip 1', keys: ['j-slip'], shiftX: -5, category: 'fuel' },
                { search: 'Slip 2', keys: ['j-slip-2'], shiftX: -5, category: 'fuel' },
                { search: 'ADL', keys: ['j-adl'], shiftX: -5, category: 'fuel' },
                { search: 'CHL', keys: ['j-chl'], shiftX: -5, category: 'fuel' },
                { search: 'INF', keys: ['j-inf'], shiftX: -5, category: 'fuel' },
                { search: 'Cargo', keys: ['j-cargo'], shiftX: -5, category: 'fuel' },
                { search: 'Mail', keys: ['j-mail'], shiftX: -5, category: 'fuel' },
                { search: 'BAG', keys: ['j-bag'], shiftX: -5, category: 'fuel' },
                { search: 'ZFW', keys: ['j-zfw'], shiftX: -5, category: 'fuel' }
            ];

            logColumnDefs.forEach(col => {
                drawLegData(findAnchor(textItems, col.search), col.shiftX, col.keys, col.category === 'fuel' ? fuelRefY : mainRefY);
            });

            // 6. DRAW SIGNATURE
            const sigAnchor = findAnchor(textItems, "Captain's Signature");
            if (sigAnchor && pads?.main?.pad && !pads.main.pad.isEmpty()) {
                try {
                    const sigImage = await pdfDoc.embedPng(pads.main.pad.toDataURL());
                    page.drawImage(sigImage, { x: sigAnchor[4] + 120, y: sigAnchor[5] - 15, width: 200, height: 50 });
                } catch (e) { console.warn("Signature skipped"); }
            }

            // 7. DRAW CREW DUTY
            if (!shouldHideAll) {
                const crewCols = {};
                ['DUTY', 'Duty time', 'Night duty', 'Alwd. time', 'LEGS'].forEach(k => {
                    const a = findAnchor(textItems, k);
                    if (a) crewCols[k] = a[4];
                });

                let crewBaselineY = (findAnchor(textItems, 'DUTY') || findAnchor(textItems, 'OP') || [0,0,0,0,0, 333 + headerDrop])[5] - headerDrop;
                
                const numFC = parseInt(el('j-fc-count')?.value || 2);
                const numCC = parseInt(el('j-cc-count')?.value || 7);
                const sectorsString = 'x'.repeat(dailyLegs.filter(l => l['j-flt'] || l['j-dep']).length);

                const getFDP = (startMins) => {
                    const onBlocksMins = dailyLegs[dailyLegs.length-1] ? (typeof parseTimeString === 'function' ? parseTimeString(dailyLegs[dailyLegs.length-1]['j-in']) : 0) : null;
                    if (onBlocksMins == null) return "";
                    let diff = onBlocksMins - startMins;
                    if (diff < 0) diff += 1440;
                    return typeof minsToTime === 'function' ? minsToTime(diff) : "";
                };

                const fcStartMins = typeof parseTimeString === 'function' ? parseTimeString(el('j-duty-start')?.value) : 0;
                const ccStartMins = typeof parseTimeString === 'function' ? parseTimeString(el('j-cc-duty-start')?.value) : 0;
                
                for(let i = 0; i < (numFC + numCC); i++) {
                    const y = crewBaselineY - (i * (JOURNEY_CONFIG?.rowGap || 17));
                    const isFC = (i < numFC);
                    const myStart = isFC ? fcStartMins : ccStartMins;

                    const member = activeCrewList[i];
                    if (member && crewCols['DUTY']) {
                        const opX = crewCols['DUTY'];
                        page.drawText(String(member.EmployeeID || '').toUpperCase(), { x: opX - 175, y, size: nameFontSize, font });
                        page.drawText(String(member.Position || '').toUpperCase(), { x: opX - 140, y, size: nameFontSize, font });
                        page.drawText(`${member.FirstName || ''} ${member.LastName || ''}`.trim().toUpperCase(), { x: opX - 125, y, size: nameFontSize, font });
                        page.drawText("OP", { x: opX, y, size: nameFontSize, font });
                    }
                    
                    if (crewCols['Duty time']) page.drawText(getFDP(myStart), { x: crewCols['Duty time'], y, size: nameFontSize, font });
                    if (crewCols['Night duty']) page.drawText(typeof getNightDutyForCrew === 'function' ? getNightDutyForCrew(myStart) : '', { x: crewCols['Night duty'], y, size: nameFontSize, font });
                    if (crewCols['Alwd. time']) page.drawText(isFC ? (el('j-max-fdp')?.value || '') : (el('j-cc-max-fdp-hidden')?.value || ''), { x: crewCols['Alwd. time'], y, size: nameFontSize, font });
                    if (crewCols['LEGS']) page.drawText(sectorsString, { x: crewCols['LEGS'], y, size: nameFontSize, font });
                }
            }

            // 8. FINAL SAVE AND EXPORT
            const outBytes = await pdfDoc.save();
            const fltStr = (el('j-flt')?.value || "FLT").replace(/\s+/g, '');
            const filename = `JOURNEY_LOG_${fltStr}.pdf`;

            if (mode === 'email' && /iPhone|iPad|iPod|Android/i.test(navigator.userAgent)) {
                await sharePdf(outBytes, filename, `Journey Log: ${fltStr}`, "Journey Log attached.");
            } else {
                if (typeof downloadBlob === 'function') downloadBlob(outBytes, filename);
            }

            const userChoice = await showConfirmDialog('Journey Log Generated', '<div style="text-align:center;">Save this log and start a new day?<br>Click <strong>Save Log</strong> to store it permanently and clear leg data.<br>Click <strong>Keep Data</strong> to make changes and generate again.</div>', 'Save Log', 'Keep Data', 'info', true);

            if (userChoice) {
                const blob = new Blob([outBytes], { type: 'application/pdf' });
                if (typeof saveJourneyLog === 'function') await saveJourneyLog(blob, { flight: fltStr, date: el('j-date')?.value || new Date().toISOString().slice(0,10), legCount: dailyLegs.length });
                if (typeof showToast !== 'undefined') showToast('Journey log saved', 'success');
                if (typeof performDataReset === 'function') await performDataReset(false, false);
            }

        } catch (e) {
            console.error("Log Gen Error:", e);
            if (typeof logSecurityEvent === 'function') await logSecurityEvent('JOURNEY_LOG_ERROR', { error: e.message, mode });
            alert("Error generating Log: " + e.message);
        }
    };


// ==========================================
// 10. OFP Download
// ==========================================
    
    function generateOFPDFilename(flight, date, suffix = '') {
        // Condensed regex and fallback logic
        const cleanFlight = (flight || 'OFP').replace(/[^a-zA-Z0-9-]/g, '') || 'OFP';
        const cleanDate = (date || '').replace(/\//g, '-').replace(/[^a-zA-Z0-9-]/g, '') || 'nodate';
        
        return `${cleanFlight}_${cleanDate}${suffix ? '_' + suffix : ''}.pdf`;
    }

    window.DownloadOFP = async function(mode = 'download') {
        const container = document.getElementById('download-progress-container');
        if (container) container.style.display = 'block';

        try {
            if (typeof logSecurityEvent === 'function') {
                await logSecurityEvent('OFP_DOWNLOAD', { mode, fileName: window.originalFileName, timestamp: new Date().toISOString() });
            }

            if (!window.ofpPdfBytes) {
                if (container) container.style.display = 'none';
                return alert("Please Upload the OFP PDF first.");
            }

            // 1. Load the original vector PDF directly (Keeps file size tiny!)
            const sourcePdfDoc = await PDFLib.PDFDocument.load(window.ofpPdfBytes);
            const totalPages = sourcePdfDoc.getPageCount();

            // 2. Create the output PDF
            const newPdf = await PDFLib.PDFDocument.create();

            // 3. Determine Cutoff
            const cutoff = typeof window.cutoffPageIndex === 'number' ? window.cutoffPageIndex : -1;
            const lastPageIndex = (cutoff > 2 && cutoff < totalPages - 1) ? cutoff : totalPages - 1;

            // 4. Copy the vector pages (Fast and clean)
            const pagesToCopy = Array.from({ length: lastPageIndex + 1 }, (_, i) => i);
            const copiedPages = await newPdf.copyPages(sourcePdfDoc, pagesToCopy);
            
            const fontB = await newPdf.embedFont(PDFLib.StandardFonts.HelveticaBold);
            const fontR = await newPdf.embedFont(PDFLib.StandardFonts.Helvetica);

            copiedPages.forEach((page, i) => {
                newPdf.addPage(page);
                
                // Front Page Overlays
                if (i === 0) {
                    if (typeof currentAtisInputMode !== 'undefined' && currentAtisInputMode === 'typing') {
                        const lineHeight = 16;
                        
                        const drawWrappedField = (id, offset, coord) => {
                            const rawText = document.getElementById(id)?.value;
                            if (!coord || !rawText) return;

                            const lines = rawText.toUpperCase().match(/.{1,50}/g) || [rawText.toUpperCase()];
                            const baseX = coord.transform[4] + offset;
                            let baseY = coord.transform[5] + (typeof V_LIFT !== 'undefined' ? V_LIFT : 0);

                            lines.forEach((line, idx) => {
                                page.drawText(line.trim(), {
                                    x: baseX, y: baseY - (idx * lineHeight), size: 12, font: fontB
                                });
                            });
                        };

                        drawWrappedField('front-atis', 40, typeof frontCoords !== 'undefined' ? frontCoords.atis : null);

                        const atcText = document.getElementById('front-atc')?.value;
                        if (typeof frontCoords !== 'undefined' && frontCoords.atcLabel && atcText) {
                            page.drawText(atcText.toUpperCase(), {
                                x: frontCoords.atcLabel.transform[4] + 50,
                                y: frontCoords.atcLabel.transform[5] + (typeof V_LIFT !== 'undefined' ? V_LIFT : 0),
                                size: 12, font: fontB
                            });
                        }
                    }

                    if (typeof currentAtisInputMode !== 'undefined' && currentAtisInputMode === 'writing' && typeof pads !== 'undefined') {
                        const embedPad = async (padName, coord, xOffset, yOffset, width, height) => {
                            if (pads[padName]?.pad && !pads[padName].pad.isEmpty() && coord) {
                                try {
                                    const img = await newPdf.embedPng(pads[padName].pad.toDataURL());
                                    page.drawImage(img, {
                                        x: coord.transform[4] + xOffset,
                                        y: coord.transform[5] + yOffset,
                                        width, height
                                    });
                                } catch (e) { console.error(`${padName} drawing error`, e); }
                            }
                        };
                        
                        if (typeof frontCoords !== 'undefined') {
                            embedPad('atis', frontCoords.atis, 40, -15, 150, 40);
                            embedPad('atc', frontCoords.atcLabel, 50, -15, 150, 40);
                        }
                    }

                    // PIC Block, Reason, Altimeters
                    if (typeof frontCoords !== 'undefined') {
                        const vLift = typeof V_LIFT !== 'undefined' ? V_LIFT : 0;
                        const drawTextSafely = (id, coord, shiftX) => {
                            const val = document.getElementById(id)?.value || document.getElementById(id)?.innerText || "";
                            if (coord && val && val !== '-') {
                                page.drawText(val.toUpperCase(), { x: coord.transform[4] + shiftX, y: coord.transform[5] + vLift, size: 12, font: fontB });
                            }
                        };

                        drawTextSafely('view-pic-block', frontCoords.picBlockLabel, 65);
                        drawTextSafely('front-extra-reason', frontCoords.reasonLabel, 175);
                        drawTextSafely('front-altm1', frontCoords.altm1, 50);
                        drawTextSafely('front-stby', frontCoords.stby, 40);
                        drawTextSafely('front-altm2', frontCoords.altm2, 50);

                        // Signature
                        if (typeof pads !== 'undefined' && pads.main?.pad && !pads.main.pad.isEmpty() && frontCoords.reasonLabel) {
                            newPdf.embedPng(pads.main.pad.toDataURL()).then(sigImg => {
                                page.drawImage(sigImg, {
                                    x: frontCoords.reasonLabel.transform[4],
                                    y: frontCoords.reasonLabel.transform[5] + 40,
                                    width: 100, height: 35
                                });
                            }).catch(e => console.warn('Failed to embed signature', e));
                        }
                    }
                }

                // Flight Log Overlays
                const drawWp = (list, pre) => {
                    if (!list) return;
                    const vLift = typeof V_LIFT !== 'undefined' ? V_LIFT : 0;
                    const lHeight = typeof LINE_HEIGHT !== 'undefined' ? LINE_HEIGHT : 12;
                    
                    list.forEach((wp, idx) => {
                        if (wp.page === i && !wp.isTakeoff) {
                            const mainY = wp.y_anchor;
                            const getVal = id => document.getElementById(id)?.value || "";
                            
                            const a = getVal(`${pre}-a-${idx}`).replace(':','');
                            const f = getVal(`${pre}-f-${idx}`);
                            const n = getVal(`${pre}-n-${idx}`);
                            const agl = getVal(`${pre}-agl-${idx}`);

                            if (wp.eto && typeof TIME_X !== 'undefined') page.drawText(wp.eto, { x: TIME_X, y: mainY + lHeight + vLift, size: 12, font: fontB, color: PDFLib.rgb(0,0,0.5) });
                            if (a && typeof ATO_X !== 'undefined') page.drawText(a, { x: ATO_X, y: mainY + vLift, size: 12, font: fontR });
                            if (f && typeof FOB_X !== 'undefined') page.drawText(f, { x: FOB_X, y: mainY - lHeight + vLift, size: 10, font: fontB });
                            if (n && typeof NOTES_X !== 'undefined') page.drawText(n.toUpperCase(), { x: NOTES_X, y: mainY - lHeight + vLift, size: 10, font: fontB });
                            if (agl) page.drawText(agl, { x: 115, y: mainY - lHeight + vLift, size: 10, font: fontB });
                        }
                    });
                };

                if (typeof waypoints !== 'undefined') drawWp(waypoints, 'o');
                if (typeof alternateWaypoints !== 'undefined') drawWp(alternateWaypoints, 'a');
            });

            // 5. Save and Export
            const bytes = await newPdf.save();
            const flt = document.getElementById('view-flt')?.innerText || document.getElementById('j-flt')?.value || 'OFP';
            const date = document.getElementById('view-date')?.innerText || document.getElementById('j-date')?.value || '';
            const filename = typeof generateOFPDFilename === 'function' ? generateOFPDFilename(flt, date) : `OFP_${flt}.pdf`;
            
            window.lastGeneratedOFPPdfBytes = bytes;

            if (mode === 'email' && /iPhone|iPad|iPod|Android/i.test(navigator.userAgent)) {
                const subject = `OFP: ${flt} ${date}`;
                if (typeof sharePdf === 'function') await sharePdf(bytes, filename, subject, `Please find attached the OFP for flight ${flt} on ${date}`);
            } else {
                if (typeof downloadBlob === 'function') downloadBlob(bytes, filename);
            }
            
            if (typeof resetOFPAfterSend === 'function') await resetOFPAfterSend();

        } catch (error) {
            window.lastGeneratedOFPPdfBytes = null;
            console.error("Download Error:", error);
            if (typeof logSecurityEvent === 'function') await logSecurityEvent('OFP_DOWNLOAD_ERROR', { error: error.message, mode });
            alert("Error generating PDF: " + error.message);
        } finally {
            if (container) container.style.display = 'none';
        }
    };

    async function resetOFPAfterSend() {
        const userConfirmed = typeof showConfirmDialog === 'function' 
            ? await showConfirmDialog('OFP Generated', '<div style="text-align:center;">Click Finalize to wipe the form.<br>Click Modify to make changes.</div>', 'Finalize', 'Modify', 'info', true)
            : confirm("Finalize and wipe the form?");

        if (!userConfirmed) {
            window.lastGeneratedOFPPdfBytes = null;
            return;
        }

        try {
            const activeId = localStorage.getItem('activeOFPId');
            if (activeId && window.lastGeneratedOFPPdfBytes) {
                const loggedBlob = new Blob([window.lastGeneratedOFPPdfBytes], { type: 'application/pdf' });
                if (typeof updateOFP === 'function') {
                    await updateOFP(activeId, { finalized: true, isActive: false, loggedPdfData: loggedBlob, finalizedAt: new Date().toISOString() });
                }
                if (typeof showToast !== 'undefined') showToast("OFP finalized", 'success');
            }
        } catch (error) {
            console.error("Failed to save logged OFP:", error);
        } finally {
            window.lastGeneratedOFPPdfBytes = null;
        }

        if (typeof performDataReset === 'function') await performDataReset(true, false);

        const settings = JSON.parse(localStorage.getItem('efb_settings') || '{}');
        const autoActivate = settings.autoActivateNext !== false;

        const allOFPs = typeof getCachedOFPs === 'function' ? await getCachedOFPs(true) : [];
        const nonFinalizedOFPs = allOFPs.filter(ofp => !ofp.finalized);

        if (nonFinalizedOFPs.length === 0) {
            if (typeof showToast !== 'undefined') showToast("Do not forget to send your Journey Log", 'info');
            const journeyBtn = document.querySelector('.nav-btn[data-tab="journey"], .nav-btn[onclick*="journey"]');
            if (journeyBtn) (typeof window.showTab === 'function') ? window.showTab('journey', journeyBtn) : journeyBtn.click();
            return;
        }

        let nextOFP = null;
        if (autoActivate && allOFPs.length > 0) {
            const currentActiveId = localStorage.getItem('activeOFPId');
            if (currentActiveId) {
                const currentIndex = allOFPs.findIndex(o => o.id === Number(currentActiveId));
                if (currentIndex !== -1 && currentIndex < allOFPs.length - 1) nextOFP = allOFPs[currentIndex + 1];
            }
            if (!nextOFP && nonFinalizedOFPs.length > 0) nextOFP = nonFinalizedOFPs[0];
        }

        if (nextOFP) {
            if (typeof activateOFP === 'function') await activateOFP(nextOFP.id);
        } else {
            if (typeof setOFPLoadedState === 'function') setOFPLoadedState(false);
            localStorage.removeItem('activeOFPId');
            setTimeout(() => {
                if (typeof updateEmptyStates === 'function') updateEmptyStates();
                if (document.querySelector('.tool-section.active')) {
                    if (typeof runFlightLogCalculations === 'function') runFlightLogCalculations();
                    if (typeof validateOFPInputs === 'function') validateOFPInputs();
                }
            }, 100);
        }
    }

    window.downloadSavedOFP = async function(id) {
        try {
            const db = await (typeof getDB === 'function' ? getDB() : null);
            if (!db) return;
            
            const tx = db.transaction("ofps", "readonly");
            const store = tx.objectStore("ofps");
            const request = store.get(Number(id));
            
            request.onsuccess = () => {
                const ofp = request.result;
                if (ofp && ofp.loggedPdfData) {
                    const url = URL.createObjectURL(ofp.loggedPdfData);
                    const a = document.createElement('a');
                    a.href = url;
                    a.download = typeof generateOFPDFilename === 'function' ? generateOFPDFilename(ofp.flight, ofp.date) : `OFP_${ofp.flight}.pdf`;
                    
                    document.body.appendChild(a);
                    a.click();
                    a.remove();
                    
                    setTimeout(() => URL.revokeObjectURL(url), 100); // Memory leak fix
                    if (typeof showToast !== 'undefined') showToast("Logged OFP downloaded", 'success');
                } else {
                    if (typeof showToast !== 'undefined') showToast("No logged version found", 'error');
                }
            };
        } catch (error) {
            console.error("Error downloading logged OFP:", error);
            if (typeof showToast !== 'undefined') showToast("Download failed", 'error');
        }
    };

// ==========================================
// 12. LOCAL STORAGE
// ==========================================

    const SAVE_IDS = [
        'j-flt', 'j-reg', 'j-date', 'j-dep', 'j-dest', 'j-altn', 'j-alt2', 'j-std','front-extra-kg',
        'j-out', 'j-off', 'j-on', 'j-in', 'j-night', 'j-night-calc',
        'j-to', 'j-ldg', 'j-ldg-type', 'j-flt-alt', 'j-ldg-detail',
        'j-init', 'j-uplift-w', 'j-uplift-vol', 'j-act-ramp', 'j-shut', 'j-slip', 'j-slip-2',
        'j-adl', 'j-chl', 'j-inf', 'j-bag', 'j-cargo', 'j-mail', 'j-zfw',
        'j-duty-start', 'j-cc-duty-start', 'j-max-fdp', 'j-fc-count', 'j-cc-count','j-report-type', 'front-extra-reason',
        'front-atis', 'front-atc', 'front-altm1', 'front-stby', 'front-altm2', 'view-pic-block'
    ];

    // 1. HIGH-SPEED SAVE FUNCTION 
    async function saveState() {
        if (!isAppLoaded) return;

        const activeId = localStorage.getItem('activeOFPId');
        if (!activeId) return;

        // O(n) Waypoint Extractor
        const userWaypoints = waypoints.map((_, i) => ({
            ato: el(`o-a-${i}`)?.value || "",
            fuel: el(`o-f-${i}`)?.value || "",
            notes: el(`o-n-${i}`)?.value || "",
            agl: el(`o-agl-${i}`)?.value || ""
        }));

        const combinedInputs = {};
        
        // Grab persistent text inputs instantly
        if (typeof PERSISTENT_INPUT_IDS !== 'undefined') {
            PERSISTENT_INPUT_IDS.forEach(id => {
                const element = el(id);
                if (element) combinedInputs[id] = element.value;
            });
        }

        // Helper to extract Canvas data cleanly without blocking UI
        const extractPadData = (padDef, backupKey) => {
            if (padDef?.pad && !padDef.pad.isEmpty()) {
                const data = padDef.pad.toDataURL();
                if (typeof data === 'string' && data.startsWith('data:image/png') && data.length > 100) {
                    localStorage.setItem(`drawing_backup_${activeId}_${backupKey}`, data);
                    return data;
                }
            }
            return null;
        };

        // Extract Drawings
        if (currentAtisInputMode === 'writing') {
            combinedInputs['front-atis-drawing'] = extractPadData(pads.atis, 'atis');
            combinedInputs['front-atc-drawing'] = extractPadData(pads.atc, 'atc');
        } else {
            combinedInputs['front-atis-drawing'] = null;
            combinedInputs['front-atc-drawing'] = null;
        }
        
        combinedInputs.signature = extractPadData(pads.main, 'signature');

        // Fire-and-forget IndexedDB save
        if (typeof saveOFPUserData === 'function') {
            saveOFPUserData(Number(activeId), userWaypoints, combinedInputs).catch(e => console.warn('Failed to save user data', e));
        }

        // Build base app state
        const state = {
            inputs: {},
            dailyLegs: dailyLegs || [],
            dutyStartTime: dutyStartTime,
            version: typeof APP_VERSION !== 'undefined' ? APP_VERSION : '1.0',
            timestamp: new Date().toISOString(),
            savedTaxiValue: (typeof fuelData !== 'undefined' ? fuelData.find(x => x.name === "TAXI")?.fuel : null) || 200
        };

        SAVE_IDS.forEach(id => {
            const element = el(id);
            if (element) state.inputs[id] = element.value;
        });

        // Save Fallback Sync
        try {
            localStorage.setItem('efb_log_state_fallback', JSON.stringify(state));
        } catch (e) {
            console.error('Storage full or error:', e);
        }

        // Save Encrypted Async
        if (typeof encryptData === 'function') {
            encryptData(state)
                .then(encryptedState => localStorage.setItem('efb_log_state', encryptedState))
                .catch(err => console.warn('Encryption save failed, relying on fallback.', err));
        }
    }

    // 2. STREAMLINED LOAD FUNCTION 
    async function loadState() {
        let raw = localStorage.getItem('efb_log_state');
        let state = null;

        try {
            // 1. Try Encrypted First
            if (raw && typeof decryptData === 'function') {
                try {
                    state = await decryptData(raw);
                } catch (e) {
                    console.warn("Decryption failed, falling back to plain storage.");
                }
            }

            // 2. Try Fallbacks
            if (!state) {
                raw = localStorage.getItem('efb_log_state_fallback') || localStorage.getItem('efb_log_state_plain');
                if (raw) state = JSON.parse(raw);
            }

            // 3. Exit if empty
            if (!state) {
                console.log("No saved app state found.");
                return;
            }

            // 4. Restore Data
            if (state.inputs) {
                Object.keys(state.inputs).forEach(id => {
                    const val = state.inputs[id];
                    if (val != null && val !== "") safeSet(id, val);
                });
            }

            if (state.dailyLegs) {
                dailyLegs = state.dailyLegs;
                if (typeof renderJourneyList === 'function') renderJourneyList();
            }

            if (state.dutyStartTime !== undefined) {
                dutyStartTime = state.dutyStartTime;
                if (typeof calcDutyLogic === 'function') calcDutyLogic();
            }

            // 5. Trigger Calculations
            if (typeof runFlightLogCalculations === 'function') runFlightLogCalculations();
            if (typeof syncLastWaypoint === 'function') syncLastWaypoint();

        } catch (e) {
            console.error("Fatal Load Error:", e);
        } finally {
            isAppLoaded = true;
        }
    }

// ==========================================
// 13. IndexedDB
// ==========================================

    // One connection reused across the app.
    function getDB() {
        if (!dbPromise) {
            dbPromise = new Promise((resolve, reject) => {
                const request = indexedDB.open("EFB_PDF_DB", 11);

                request.onupgradeneeded = function(e) {
                    const db = e.target.result;
                    const oldVersion = e.oldVersion;
                    const tx = e.target.transaction;

                    if (!db.objectStoreNames.contains("ofp_user_data")) {
                        db.createObjectStore("ofp_user_data", { keyPath: "ofpId" });
                    }
                    if (!db.objectStoreNames.contains("ofps")) {
                        const ofpStore = db.createObjectStore("ofps", { keyPath: "id", autoIncrement: true });
                        ofpStore.createIndex("flight", "flight", { unique: false });
                        ofpStore.createIndex("date", "date", { unique: false });
                        ofpStore.createIndex("uploadTime", "uploadTime", { unique: false });
                        ofpStore.createIndex("isActive", "isActive", { unique: false });
                        ofpStore.createIndex("order", "order", { unique: false });
                    }
                    if (oldVersion < 2 && !db.objectStoreNames.contains("files")) {
                        db.createObjectStore("files");
                    }
                    if (oldVersion < 4 && oldVersion >= 3) {
                        const store = tx.objectStore("ofps");
                        store.openCursor().onsuccess = (evt) => {
                            const cursor = evt.target.result;
                            if (cursor) {
                                const ofp = cursor.value;
                                let needsUpdate = false;
                                if (ofp.finalized === undefined) { ofp.finalized = false; needsUpdate = true; }
                                if (ofp.loggedPdfData === undefined) { ofp.loggedPdfData = null; needsUpdate = true; }
                                if (needsUpdate) cursor.update(ofp);
                                cursor.continue();
                            }
                        };
                    }
                    if (oldVersion < 5) {
                        const store = tx.objectStore("ofps");
                        if (!store.indexNames.contains("order")) store.createIndex("order", "order", { unique: false });
                    }
                    if (oldVersion < 6) {
                        const store = tx.objectStore("ofps");
                        store.openCursor().onsuccess = (evt) => {
                            const cursor = evt.target.result;
                            if (cursor) {
                                const ofp = cursor.value;
                                let needsUpdate = false;
                                if (ofp.tripTime === undefined) { ofp.tripTime = ''; needsUpdate = true; }
                                if (ofp.maxSR === undefined) { ofp.maxSR = ''; needsUpdate = true; }
                                if (needsUpdate) cursor.update(ofp);
                                cursor.continue();
                            }
                        };
                    }
                    if (oldVersion < 7) {
                        const store = tx.objectStore("ofps");
                        store.openCursor().onsuccess = (evt) => {
                            const cursor = evt.target.result;
                            if (cursor) {
                                if (cursor.value.requestNumber === undefined) {
                                    const ofp = cursor.value;
                                    ofp.requestNumber = '';
                                    cursor.update(ofp);
                                }
                                cursor.continue();
                            }
                        };
                    }
                    if (oldVersion < 8 && !db.objectStoreNames.contains("ofp_orders")) {
                        const orderStore = db.createObjectStore("ofp_orders", { keyPath: "id" });
                        tx.objectStore("ofps").openCursor().onsuccess = (evt) => {
                            const cursor = evt.target.result;
                            if (cursor) {
                                orderStore.put({ id: cursor.value.id, order: cursor.value.order || 0 });
                                cursor.continue();
                            }
                        };
                    }
                    if (!db.objectStoreNames.contains("journey_logs")) {
                        db.createObjectStore("journey_logs", { keyPath: "id", autoIncrement: true });
                    }
                };

                request.onsuccess = e => resolve(e.target.result);
                request.onerror = e => reject(e);
            });
        }
        return dbPromise;
    }

    // High-speed Metadata Extractor (Prevents mass RAM spikes)
    async function getAllOFPMetadata() {
        const db = await getDB();
        if (!db.objectStoreNames.contains('ofps')) return [];

        return new Promise((resolve, reject) => {
            const tx = db.transaction(["ofps", "ofp_orders"], "readonly");
            const ofpsStore = tx.objectStore("ofps");
            const ordersStore = tx.objectStore("ofp_orders");
            
            const metadata = [];
            const orderMap = {};

            ordersStore.getAll().onsuccess = (e) => {
                e.target.result.forEach(o => { orderMap[o.id] = o.order; });
                
                // Use a cursor to strip Blobs instantly before they accumulate in RAM
                const req = ofpsStore.openCursor();
                req.onsuccess = (evt) => {
                    const cursor = evt.target.result;
                    if (cursor) {
                        const { data, loggedPdfData, userWaypoints, userInputs, ...rest } = cursor.value;
                        rest.order = orderMap[rest.id] || 0;
                        metadata.push(rest);
                        cursor.continue();
                    } else {
                        metadata.sort((a, b) => a.order - b.order);
                        resolve(metadata);
                    }
                };
                req.onerror = (err) => reject(err);
            };
        });
    }

    async function saveOFPToDB(fileBlob, metadata, activate = true) {
        const db = await getDB();
        return new Promise((resolve, reject) => {
            const tx = db.transaction(["ofps", "ofp_orders"], "readwrite");
            const ofpsStore = tx.objectStore("ofps");
            const ordersStore = tx.objectStore("ofp_orders");

            ordersStore.getAll().onsuccess = (e) => {
                const orders = e.target.result;
                const nextOrder = (orders.length > 0 ? Math.max(...orders.map(o => o.order || 0)) : 0) + 1;

                // O(1) Active Toggling: Only update the exact ID that was previously active
                if (activate) {
                    const prevActiveId = localStorage.getItem('activeOFPId');
                    if (prevActiveId) {
                        const prevReq = ofpsStore.get(Number(prevActiveId));
                        prevReq.onsuccess = () => {
                            if (prevReq.result) {
                                prevReq.result.isActive = false;
                                ofpsStore.put(prevReq.result);
                            }
                        };
                    }
                }

                const ofpRecord = {
                    ...metadata,
                    data: fileBlob,
                    loggedPdfData: null,
                    finalized: false,
                    isActive: activate,
                    order: nextOrder,
                    uploadTime: new Date().toISOString(),
                    fileName: fileBlob.name || "Unknown",
                    tripTime: metadata.tripTime || '',
                    maxSR: metadata.maxSR || '',
                    requestNumber: metadata.requestNumber || ''
                };

                const addReq = ofpsStore.add(ofpRecord);
                addReq.onsuccess = (evt) => {
                    const newId = evt.target.result;
                    ordersStore.put({ id: newId, order: nextOrder });
                    if (activate) localStorage.setItem('activeOFPId', newId);
                    
                    tx.oncomplete = () => resolve(newId);
                };
                addReq.onerror = (err) => reject(err.target.error);
            };
            tx.onerror = (err) => reject(err.target.error);
        });
    }

    async function emergencySaveOFP(blob, metadata, existingOFP = null) {
        const results = { pdfSaved: false, ofpsRecordCreated: false, recordId: null };

        try {
            await savePdfToDB(blob);
            results.pdfSaved = true;
        } catch (e) { console.error('Emergency PDF save failed', e); }

        try {
            const minimalMetadata = {
                flight: metadata.flight || 'N/A', date: metadata.date || 'N/A',
                departure: metadata.departure || 'N/A', destination: metadata.destination || 'N/A',
                tripTime: metadata.tripTime || '', maxSR: metadata.maxSR || '', requestNumber: metadata.requestNumber || ''
            };

            if (existingOFP?.id) {
                await updateOFP(existingOFP.id, {
                    ...minimalMetadata, data: null, loggedPdfData: null,
                    finalized: false, isActive: existingOFP.isActive || false,
                    order: existingOFP.order, uploadTime: new Date().toISOString(), fileName: blob.name || "Unknown"
                });
                results.recordId = existingOFP.id;
                results.ofpsRecordCreated = true;
            } else {
                const db = await getDB();
                const tx = db.transaction("ofps", "readwrite");
                const store = tx.objectStore("ofps");
                
                const maxOrder = await new Promise(res => {
                    const req = store.index("order").openCursor(null, "prev");
                    req.onsuccess = (e) => res(e.target.result ? e.target.result.value.order : 0);
                });

                const addReq = store.add({
                    ...minimalMetadata, data: null, loggedPdfData: null,
                    finalized: false, isActive: false, order: maxOrder + 1,
                    uploadTime: new Date().toISOString(), fileName: blob.name || "Unknown"
                });

                await new Promise((res, rej) => {
                    addReq.onsuccess = (e) => { results.recordId = e.target.result; results.ofpsRecordCreated = true; res(); };
                    addReq.onerror = (e) => rej(e.target.error);
                    tx.oncomplete = res;
                });
            }
        } catch (e2) { console.error('Emergency record update failed', e2); }

        return results;
    }

    async function getCachedOFPs(force = false) {
        if (force || !ofpCache || Date.now() - cacheTime > CACHE_TTL) {
            ofpCache = await getAllOFPMetadata(); 
            cacheTime = Date.now();
        }
        return ofpCache;
    }

    async function updateOFP(id, updates) {
        const db = await getDB();
        return new Promise((resolve, reject) => {
            const tx = db.transaction("ofps", "readwrite");
            const store = tx.objectStore("ofps");

            const getReq = store.get(Number(id));
            getReq.onsuccess = () => {
                if (!getReq.result) return reject(new Error("OFP not found"));
                const putReq = store.put(Object.assign(getReq.result, updates));
                putReq.onerror = (e) => reject(e.target.error);
                tx.oncomplete = () => resolve(getReq.result);
            };
            getReq.onerror = (e) => reject(e.target.error);
        });
    }

    async function findOFPByFlightAndDate(flight, date) {
        if (!flight || !date || flight === 'N/A' || date === 'N/A') return null;
        const db = await getDB();
        return new Promise((resolve, reject) => {
            const req = db.transaction("ofps", "readonly").objectStore("ofps").index("flight").getAll(IDBKeyRange.only(String(flight)));
            req.onsuccess = () => resolve(req.result.find(ofp => ofp.date === date) || null);
            req.onerror = (e) => reject(e);
        });
    }

    async function getActiveOFPFromDB() {
        const activeId = localStorage.getItem('activeOFPId');
        return activeId ? getOFPById(Number(activeId)) : null;
    }

    async function deleteOFPFromDB(id) {
        const db = await getDB();
        const numericId = Number(id);
        const stores = ['ofps', 'ofp_orders'];
        if (db.objectStoreNames.contains('ofp_user_data')) stores.push('ofp_user_data');

        return new Promise((resolve, reject) => {
            const tx = db.transaction(stores, "readwrite");
            stores.forEach(s => tx.objectStore(s).delete(numericId));
            
            tx.oncomplete = () => {
                if (localStorage.getItem('activeOFPId') === String(numericId)) localStorage.removeItem('activeOFPId');
                resolve();
            };
            tx.onerror = (e) => reject(e.target.error);
        });
    }

    async function clearAllOFPsFromDB() {
        const db = await getDB();
        const stores = ['ofps', 'ofp_orders', 'ofp_user_data'].filter(s => db.objectStoreNames.contains(s));
        if (stores.length === 0) return localStorage.removeItem('activeOFPId');

        return new Promise((resolve, reject) => {
            const tx = db.transaction(stores, "readwrite");
            stores.forEach(s => tx.objectStore(s).clear());
            tx.oncomplete = () => {
                localStorage.removeItem('activeOFPId');
                resolve();
            };
            tx.onerror = (e) => reject(e.target.error);
        });
    }

    // --- Core Legacy File Store ---
    async function checkPdfInDB() {
        try {
            const db = await getDB();
            return new Promise(res => {
                const req = db.transaction("files", "readonly").objectStore("files").get("currentOFP");
                req.onsuccess = () => res(!!req.result);
                req.onerror = () => res(false);
            });
        } catch { return false; }
    }

    async function savePdfToDB(fileBlob) {
        const db = await getDB();
        return new Promise((res, rej) => {
            const tx = db.transaction("files", "readwrite");
            tx.objectStore("files").put(fileBlob, "currentOFP");
            tx.oncomplete = res;
            tx.onerror = () => rej(tx.error);
        });
    }

    async function loadPdfFromDB() {
        const db = await getDB();
        return new Promise(res => {
            const req = db.transaction("files", "readonly").objectStore("files").get("currentOFP");
            req.onsuccess = () => res(req.result);
            req.onerror = () => res(null);
        });
    }

    async function clearPdfDB() {
        const db = await getDB();
        db.transaction("files", "readwrite").objectStore("files").delete("currentOFP");
    }

    // --- Auxiliary Stores ---
    async function saveOFPUserData(ofpId, userWaypoints, userInputs) {
        const db = await getDB();
        if (!db.objectStoreNames.contains('ofp_user_data')) return;
        return new Promise((res, rej) => {
            const tx = db.transaction("ofp_user_data", "readwrite");
            tx.objectStore("ofp_user_data").put({ ofpId, userWaypoints, userInputs });
            tx.oncomplete = res;
            tx.onerror = (e) => rej(e.target.error);
        });
    }

    async function loadOFPUserData(ofpId) {
        const db = await getDB();
        if (!db.objectStoreNames.contains('ofp_user_data')) return { userWaypoints: [], userInputs: {} };
        return new Promise((res, rej) => {
            const req = db.transaction("ofp_user_data", "readonly").objectStore("ofp_user_data").get(ofpId);
            req.onsuccess = () => res(req.result || { userWaypoints: [], userInputs: {} });
            req.onerror = (e) => rej(e.target.error);
        });
    }

    async function saveJourneyLog(pdfBlob, metadata) {
        const db = await getDB();
        return new Promise((res, rej) => {
            const tx = db.transaction("journey_logs", "readwrite");
            const req = tx.objectStore("journey_logs").add({ ...metadata, data: pdfBlob, finalizedAt: new Date().toISOString() });
            req.onsuccess = () => res(req.result);
            req.onerror = (e) => rej(e.target.error);
        });
    }

    async function getAllJourneyLogs() {
        const db = await getDB();
        return new Promise((res, rej) => {
            const req = db.transaction("journey_logs", "readonly").objectStore("journey_logs").getAll();
            req.onsuccess = () => res(req.result);
            req.onerror = () => rej(req.error);
        });
    }

    window.deleteJourneyLog = async function(id) {
        try {
            const db = await getDB();
            await new Promise((res, rej) => {
                const req = db.transaction("journey_logs", "readwrite").objectStore("journey_logs").delete(id);
                req.onsuccess = res;
                req.onerror = (e) => rej(e.target.error);
            });
            if (typeof showToast !== 'undefined') showToast('Journey log deleted', 'success');
            
            const container = document.getElementById('journey-table-container');
            if (container && !container.hidden && typeof renderJourneyLogTable === 'function') await renderJourneyLogTable();
        } catch (error) {
            console.error('Error deleting journey log:', error);
        }
    };

    window.downloadSavedJourneyLog = async function(id) {
        try {
            const db = await getDB();
            const req = db.transaction("journey_logs", "readonly").objectStore("journey_logs").get(id);
            req.onsuccess = () => {
                const log = req.result;
                if (log && log.data) {
                    const url = URL.createObjectURL(log.data);
                    const a = document.createElement('a');
                    a.href = url;
                    a.download = `JOURNEY_LOG_${log.flight || 'unknown'}_${log.date || 'nodate'}.pdf`;
                    document.body.appendChild(a);
                    a.click();
                    a.remove();
                    
                    // Prevent Memory Leaks via proper setTimeout revocation
                    setTimeout(() => URL.revokeObjectURL(url), 100);
                    if (typeof showToast !== 'undefined') showToast("Journey log downloaded", 'success');
                } else {
                    if (typeof showToast !== 'undefined') showToast("No data found", 'error');
                }
            };
        } catch (error) {
            console.error("Error downloading journey log:", error);
        }
    };

    async function saveJourneyTemplateToDB(fileBlob) {
        const db = await getDB();
        return new Promise((res, rej) => {
            const tx = db.transaction("files", "readwrite");
            tx.objectStore("files").put(fileBlob, "journeyTemplate");
            tx.oncomplete = res;
            tx.onerror = (e) => rej(e.target.error);
        });
    }

    async function loadJourneyTemplateFromDB() {
        const db = await getDB();
        return new Promise(res => {
            const req = db.transaction("files", "readonly").objectStore("files").get("journeyTemplate");
            req.onsuccess = () => res(req.result || null);
            req.onerror = () => res(null);
        });
    }

    async function deleteJourneyTemplateFromDB() {
        const db = await getDB();
        return new Promise((res, rej) => {
            const tx = db.transaction("files", "readwrite");
            tx.objectStore("files").delete("journeyTemplate");
            tx.oncomplete = res;
            tx.onerror = rej;
        });
    }

// ==========================================
// 14. DATA HANDLING
// ==========================================

    async function exportAllData() {
        try {
            const data = {
                version: typeof APP_VERSION !== 'undefined' ? APP_VERSION : '1.0',
                exportDate: new Date().toISOString(),
                flightData: {
                    dailyLegs: dailyLegs || [],
                    waypoints: waypoints || [],
                    alternateWaypoints: alternateWaypoints || [],
                    fuelData: fuelData || []
                },
                settings: JSON.parse(localStorage.getItem('efb_settings') || '{}'),
                state: JSON.parse(localStorage.getItem('efb_log_state_fallback') || localStorage.getItem('efb_log_state_plain') || '{}')
            };
            
            const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `efb-backup-${new Date().toISOString().split('T')[0]}.json`;
            document.body.appendChild(a);
            a.click();
            a.remove();
            
            setTimeout(() => URL.revokeObjectURL(url), 100); // Memory leak prevention
            
            if (typeof showToast !== 'undefined') showToast('Data exported successfully');
            
        } catch (error) {
            console.error('Export failed:', error);
            if (typeof showToast !== 'undefined') showToast('Export failed: ' + error.message, 'error');
        }
    }

    window.recoverLostData = async function() {
        const confirmed = typeof showConfirmDialog === 'function' 
            ? await showConfirmDialog('Data Recovery', 'This will attempt to recover any lost data.<br>Continue?', 'Recover', 'Cancel', 'error')
            : confirm("Attempt to recover lost data?");
            
        if (!confirmed) return;

        const methods = [
            { key: 'efb_log_state', encrypted: true },
            { key: 'efb_log_state_fallback', encrypted: false },
            { key: 'efb_log_state_plain', encrypted: false }
        ];
        
        for (const method of methods) {
            try {
                const data = localStorage.getItem(method.key);
                if (!data) continue;
                
                let state;
                if (method.encrypted && typeof decryptData === 'function') {
                    state = await decryptData(data);
                } else {
                    state = JSON.parse(data);
                }
                
                if (state && state.inputs) {
                    Object.keys(state.inputs).forEach(id => {
                        if (state.inputs[id]) safeSet(id, state.inputs[id]);
                    });
                    
                    if (typeof showToast !== 'undefined') showToast(`Recovered data from ${method.encrypted ? 'encrypted' : 'unencrypted'} storage`, 'success');
                    
                    // Trigger UI updates
                    if (typeof runFlightLogCalculations === 'function') runFlightLogCalculations();
                    return;
                }
            } catch (e) {
                console.warn(`Recovery from ${method.key} failed:`, e);
            }
        }
        if (typeof showToast !== 'undefined') showToast("No recoverable data found", 'info');
    };

    async function confirmFactoryReset() {
        const confirmed = typeof showConfirmDialog === 'function'
            ? await showConfirmDialog('Factory Reset', 'WARNING: This will delete ALL data including flight data, settings, PIN, and audit logs.<br><br>This action cannot be undone. Continue?', 'Reset', 'Cancel', 'error')
            : confirm("WARNING: This deletes ALL data. Continue?");

        if (!confirmed) return;

        try {
            // 1. Clear Local/Session Storage completely
            localStorage.clear();
            sessionStorage.clear();

            // 2. Clear IndexedDB (Awaiting strictly to prevent race conditions during reload)
            const db = await getDB();
            const storesToClear = ['ofps', 'files', 'ofp_orders', 'ofp_user_data', 'journey_logs'].filter(s => db.objectStoreNames.contains(s));
            
            if (storesToClear.length > 0) {
                await new Promise((resolve, reject) => {
                    const tx = db.transaction(storesToClear, 'readwrite');
                    storesToClear.forEach(s => tx.objectStore(s).clear());
                    tx.oncomplete = resolve;
                    tx.onerror = reject;
                });
            }

            // 3. Unregister Service Workers (Wipes app cache)
            if ('serviceWorker' in navigator) {
                const registrations = await navigator.serviceWorker.getRegistrations();
                await Promise.all(registrations.map(reg => reg.unregister()));
            }

            if (typeof showToast !== 'undefined') showToast('All data reset. Reloading app...', 'info');
            
            // Force Hard Reload
            setTimeout(() => window.location.replace(window.location.href), 1500);

        } catch (e) {
            console.error('Factory Reset encountered errors:', e);
            alert("Reset partially failed. Please manually clear your browser data.");
        }
    }

    async function performDataReset(preserveDailyLegs = true, setLoadedState = true) {

        // 1. Reset Arrays & App State
        waypoints = [];
        alternateWaypoints = [];
        fuelData = [];
        blockFuelValue = 0;
        window.cutoffPageIndex = -1;
        window.ofpPdfBytes = null;
        window.lastGeneratedOFPPdfBytes = null;
        window.originalFileName = "Logged_OFP.pdf";
        
        frontCoords = { atis: null, atcLabel: null, altm1: null, stby: null, altm2: null, picBlockLabel: null, reasonLabel: null };

        if(typeof clearPdfDB === 'function') await clearPdfDB();

        // 2. Wipe UI Components efficiently
        const wipeText = ids => ids.forEach(id => { const e = document.getElementById(id); if (e) e.textContent = "-"; });
        const wipeInput = ids => ids.forEach(id => { const e = document.getElementById(id); if (e) e.value = ""; });
        const wipeZero = ids => ids.forEach(id => { const e = document.getElementById(id); if (e) e.textContent = "00:00"; });
        
        wipeText(['view-flt', 'view-reg', 'view-date', 'view-dep', 'view-dest', 'view-std-text', 'view-sta-text', 'view-altn', 'view-ci', 'view-dest-route', 'view-altn-route', 'view-altn2', 'view-min-block', 'view-pic-block', 'view-mtow', 'view-mlw', 'view-mzfw', 'view-mpld', 'view-fcap', 'view-dow', 'view-tow', 'view-lw', 'view-zfw','view-era','view-crz-wind-temp', 'view-seats-stn-jmp']);
        
        const inputsToWipe = ['front-atis', 'front-atc', 'front-altm1', 'front-stby', 'front-altm2', 'front-extra-kg', 'front-extra-reason', 'ofp-atd-in', 'view-pic-block', 'j-flt', 'j-reg', 'j-date', 'j-dep', 'j-dest', 'j-altn', 'j-std', 'j-out', 'j-off', 'j-on', 'j-in', 'j-night', 'j-night-calc', 'j-to', 'j-ldg', 'j-ldg-type', 'j-flt-alt', 'j-ldg-detail', 'j-init', 'j-uplift-w', 'j-uplift-vol', 'j-act-ramp', 'j-shut', 'j-slip', 'j-slip-2', 'j-adl', 'j-chl', 'j-inf', 'j-bag', 'j-cargo', 'j-mail', 'j-zfw', 'ofp-file-in', 'journey-log-file'];
        
        if (!preserveDailyLegs) {
            inputsToWipe.push('j-duty-start', 'j-cc-duty-start', 'j-max-fdp', 'j-fc-count', 'j-cc-count');
            if (typeof PERSIST_AUTH_KEY !== 'undefined') localStorage.removeItem(PERSIST_AUTH_KEY);
        }
        
        wipeInput(inputsToWipe);
        wipeZero(['j-block', 'j-flight', 'j-burn', 'j-calc-ramp', 'j-disc']);

        // 3. Clear Dynamic Tables
        ['ofp-tbody', 'altn-tbody', 'fuel-tbody'].forEach(id => {
            const tb = document.getElementById(id);
            if(tb) tb.innerHTML = '<tr><td colspan="13" style="text-align:center;color:gray;padding:20px">No data</td></tr>';
        });

        // 4. End-of-Day Logic
        if (!preserveDailyLegs) {
            const journeyList = document.getElementById('journey-list-body');
            if (journeyList) journeyList.innerHTML = '<tr><td colspan="5" style="text-align:center; color:gray; padding:20px;">No legs.</td></tr>';
            dailyLegs = []; 
            dutyStartTime = null;
            
            localStorage.removeItem('efb_log_state');
            localStorage.removeItem('efb_log_state_fallback'); 
            localStorage.removeItem('efb_log_state_plain');
            localStorage.removeItem('activeOFPId');
        }

        // 5. Reset UI View States
        const container = document.getElementById('pdf-render-container');
        const fallback = document.getElementById('pdf-fallback');
        if (container) { container.innerHTML = ''; container.style.display = 'none'; }
        if (fallback) { fallback.innerHTML = '<span style="font-size:30px; margin-bottom:10px;">📄</span>No OFP uploaded yet.'; fallback.style.display = 'flex'; }

        // 6. Clear Memory Pads
        ['main', 'atis', 'atc'].forEach(padName => {
            if (typeof pads !== 'undefined' && pads[padName]?.pad) pads[padName].pad.clear();
        });

        // 7. DB State Sync
        if (preserveDailyLegs) {
            try {
                const savedState = localStorage.getItem('efb_log_state');
                const fallbackState = localStorage.getItem('efb_log_state_fallback');
                let stateObj = {};

                if (savedState && typeof decryptData === 'function') {
                    try { stateObj = await decryptData(savedState); } catch(e) { stateObj = JSON.parse(savedState); }
                } else if (fallbackState) {
                    stateObj = JSON.parse(fallbackState);
                }

                const newState = { dailyLegs: stateObj.dailyLegs || [], dutyStartTime: stateObj.dutyStartTime || null, inputs: {} };
                
                ['j-duty-start', 'j-cc-duty-start', 'j-max-fdp', 'j-fc-count', 'j-cc-count'].forEach(key => {
                    if (stateObj?.inputs?.[key]) newState.inputs[key] = stateObj.inputs[key];
                });

                if (typeof encryptData === 'function') {
                    localStorage.setItem('efb_log_state', await encryptData(newState));
                } else {
                    localStorage.setItem('efb_log_state_fallback', JSON.stringify(newState));
                }
            } catch (e) {
                console.error("Error processing preserved state:", e);
                localStorage.removeItem('efb_log_state');
            }
        }

        // 8. UI Finalization
        if (setLoadedState && typeof setOFPLoadedState === 'function') setOFPLoadedState(false);
        if (typeof validateOFPInputs === 'function') validateOFPInputs();
    }

// ==========================================
// 15. DEBOUNCED FUNCTION INSTANCES
// ==========================================

    const debouncedSave = debounce(saveState, SAVE_STATE_DEBOUNCE);
    const debouncedFullRecalc = debounce(() => {
        runFlightLogCalculations();
        syncLastWaypoint();
    }, 300);
    const debouncedSyncLastWaypoint = debounce(syncLastWaypoint, 300);
    const debouncedUpdateCruiseLevel = debounce(updateCruiseLevelForJourneyLog, 300);

// ==========================================
// 16. SETTINGS
// ==========================================
    
    async function calculateStorageUsage() {
        try {
            // High-speed reduction of LocalStorage size
            let bytes = Object.entries(localStorage).reduce((acc, [k, v]) => acc + k.length + (v?.length || 0), 0);

            // Fetch IndexedDB size without blocking
            if ('indexedDB' in window) {
                try {
                    const db = await getDB();
                    if (db.objectStoreNames.contains('files')) {
                        const dbBytes = await new Promise(res => {
                            const req = db.transaction("files", "readonly").objectStore("files").get("currentOFP");
                            req.onsuccess = () => res(req.result?.size || 0);
                            req.onerror = () => res(0);
                        });
                        bytes += dbBytes;
                    }
                } catch (e) { /* Ignore DB read errors to allow LocalStorage calc to render */ }
            }

            const storageEl = document.getElementById('settings-storage');
            if (storageEl) {
                const mb = bytes / 1048576; // 1024 * 1024
                storageEl.textContent = mb >= 1 ? `${mb.toFixed(2)} MB` : `${(bytes / 1024).toFixed(1)} KB`;
            }
        } catch (error) {
            console.error('Failed to calculate storage:', error);
            const storageEl = document.getElementById('settings-storage');
            if (storageEl) storageEl.textContent = 'Error';
        }
    }

    function initializeSettingsTab() {
        // Fast dictionary mapping for button bindings
        const binds = {
            'btn-change-pin': typeof changePIN !== 'undefined' ? changePIN : null,
            'btn-view-audit': typeof viewAuditLog !== 'undefined' ? viewAuditLog : null,
            'btn-export-data': typeof exportAllData !== 'undefined' ? exportAllData : null,
            'btn-factory-reset': typeof confirmFactoryReset !== 'undefined' ? confirmFactoryReset : null,
            'btn-recover-data': typeof recoverLostData !== 'undefined' ? recoverLostData : null,
            'btn-release-notes': typeof showReleaseNotes !== 'undefined' ? showReleaseNotes : null,
        };
        
        Object.entries(binds).forEach(([id, handler]) => {
            if (handler) document.getElementById(id)?.addEventListener('click', handler);
        });
        
        // Auto-save triggers
        ['auto-lock-time', 'pdf-quality', 'hide-all-duty', 'auto-activate-next'].forEach(id => {
            document.getElementById(id)?.addEventListener('change', saveSettings);
        });

        // Special ATIS Mode trigger
        document.getElementById('atis-input-mode')?.addEventListener('change', (e) => {
            if (typeof applyInputMode === 'function') applyInputMode(e.target.value);
            saveSettings();
        });
    }

    async function initializeSettings() {
        initializeSettingsTab();
        loadSettings();
        
        // Render UI updates safely
        const versionEl = document.getElementById('settings-version');
        const updatedEl = document.getElementById('settings-updated');
        
        if (versionEl && typeof APP_VERSION !== 'undefined') versionEl.textContent = `v${APP_VERSION}`;
        if (updatedEl) updatedEl.textContent = new Date().toLocaleDateString();
        
        // Calculate storage off the main thread
        setTimeout(calculateStorageUsage, 1000);
    }

    function loadSettings() {
        try {
            // 1. Restore Tokens First
            const tokenIn = document.getElementById('skyplan_token');
            const refreshIn = document.getElementById('skyplan_refresh_token');
            if (tokenIn) tokenIn.value = localStorage.getItem('skyplan_token') || '';
            if (refreshIn) refreshIn.value = localStorage.getItem('skyplan_refresh_token') || '';

            // 2. Restore Standard Settings
            const settings = JSON.parse(localStorage.getItem('efb_settings') || '{}');
            
            const autoLock = document.getElementById('auto-lock-time');
            const pdfQual = document.getElementById('pdf-quality');
            const hideDuty = document.getElementById('hide-all-duty');
            const autoAct = document.getElementById('auto-activate-next');
            const atisMode = document.getElementById('atis-input-mode');

            if (autoLock && settings.autoLockTime) autoLock.value = settings.autoLockTime;
            if (pdfQual && settings.pdfQuality) pdfQual.value = settings.pdfQuality;
            if (hideDuty) hideDuty.checked = settings.hideAllDuty === true;
            if (autoAct) autoAct.checked = settings.autoActivateNext !== false;

            if (atisMode) {
                const mode = settings.atisInputMode || 'typing';
                atisMode.value = mode;
                if (typeof applyInputMode === 'function') applyInputMode(mode);
            }
        } catch (error) {
            console.error('Failed to load settings:', error);
        }
    }

    function saveSettings() {
        const autoLockVal = document.getElementById('auto-lock-time')?.value || '15';
        
        const settings = {
            autoLockTime: autoLockVal,
            pdfQuality: document.getElementById('pdf-quality')?.value || '2.0',
            hideAllDuty: document.getElementById('hide-all-duty')?.checked || false,
            autoActivateNext: document.getElementById('auto-activate-next')?.checked !== false,
            atisInputMode: document.getElementById('atis-input-mode')?.value || 'typing',
            lastSaved: new Date().toISOString()
        };

        // Persistent Authentication Logic
        if (typeof PERSIST_AUTH_KEY !== 'undefined') {
            if (autoLockVal === "0" && sessionStorage.getItem('efb_authenticated') === 'true') {
                localStorage.setItem(PERSIST_AUTH_KEY, 'true');
            } else {
                localStorage.removeItem(PERSIST_AUTH_KEY);
            }
        }

        localStorage.setItem('efb_settings', JSON.stringify(settings));

        // Token Management
        const tokenVal = document.getElementById('skyplan_token')?.value.trim();
        const refreshVal = document.getElementById('skyplan_refresh_token')?.value.trim();

        if (tokenVal) {
            localStorage.setItem('skyplan_token', tokenVal);
            try {
                const decoded = typeof decodeJWT === 'function' ? decodeJWT(tokenVal) : null;
                if (decoded?.preferred_username) localStorage.setItem('efb_user', decoded.preferred_username);
            } catch (err) { /* Silent fail if invalid token */ }
        } else {
            localStorage.removeItem('skyplan_token');
            localStorage.removeItem('efb_user');
        }

        if (refreshVal) {
            localStorage.setItem('skyplan_refresh_token', refreshVal);
        } else {
            localStorage.removeItem('skyplan_refresh_token');
        }

        if (sessionStorage.getItem('efb_authenticated') === 'true' && typeof resetAutoLockTimer === 'function') {
            resetAutoLockTimer();
        }
        
        if (typeof showToast !== 'undefined') showToast('Settings saved successfully');
    }

    // Fast SemVer (Semantic Versioning) array comparator
    function isNewerVersion(latest, current) {
        const l = latest.split('.').map(Number);
        const c = current.split('.').map(Number);
        const maxLen = Math.max(l.length, c.length);
        
        for (let i = 0; i < maxLen; i++) {
            const lVal = l[i] || 0;
            const cVal = c[i] || 0;
            if (lVal > cVal) return true;  // Instant exit if newer
            if (lVal < cVal) return false; // Instant exit if older
        }
        return false; // Exactly the same
    }

// ==========================================
// 17. EVENT LISTENERS
// ==========================================

    window.addEventListener('DOMContentLoaded', function() {
        // 1. Initialize UI Defaults
        pdfFallbackElement = document.getElementById('pdf-fallback');
        if (typeof setOFPLoadedState === 'function') setOFPLoadedState(!!window.ofpPdfBytes);
        
        // 2. High-Speed Drag & Drop Overlay
        const overlay = document.getElementById('upload-overlay');
        const ofpFileInput = document.getElementById('ofp-file-in');
        
        if (overlay && ofpFileInput) {
            const preventDefaults = e => { e.preventDefault(); e.stopPropagation(); };
            ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(evt => overlay.addEventListener(evt, preventDefaults));
            
            ['dragenter', 'dragover'].forEach(evt => overlay.addEventListener(evt, () => overlay.style.background = 'rgba(0, 132, 255, 0.3)'));
            ['dragleave', 'drop'].forEach(evt => overlay.addEventListener(evt, () => overlay.style.background = 'rgba(0, 0, 0, 0.9)'));
            
            overlay.addEventListener('drop', (e) => {
                if (e.dataTransfer.files.length > 0) {
                    ofpFileInput.files = e.dataTransfer.files;
                    ofpFileInput.dispatchEvent(new Event('change'));
                }
            });
        }
        
        // 3. Fast Theme Initialization
        const savedTheme = localStorage.getItem('data-theme') || 'light';
        document.documentElement.setAttribute('data-theme', savedTheme);
        const themeButton = document.querySelector('.theme-toggle');
        if (themeButton) themeButton.textContent = savedTheme === 'dark' ? 'Day Mode' : 'Night Mode';
        
        // 4. Initialize Core Modules
        if (typeof initializeTabNavigation === 'function') initializeTabNavigation();
        if (typeof updateUploadButtonVisibility === 'function') updateUploadButtonVisibility();
        if (typeof initFileManagerTabs === 'function') initFileManagerTabs();
        if (typeof addTimeInputMasks === 'function') addTimeInputMasks();
        
        // 5. Initialize Main Drawing Pad
        setTimeout(() => {
            if (typeof initPad === 'function') {
                initPad('main');
                if (typeof pads !== 'undefined' && pads.main?.pad) {
                    pads.main.pad.onEnd = () => typeof debouncedSave === 'function' && debouncedSave();
                    if (typeof savedSignatureData !== 'undefined' && savedSignatureData) {
                        pads.main.pad.fromDataURL(savedSignatureData, { ratio: pads.main.lastRatio });
                    }
                }
            }
        }, 100);

        // 6. Bind Canvas Clear Buttons
        document.getElementById('clear-atis-btn')?.addEventListener('click', () => typeof clearPad === 'function' && clearPad('atis'));
        document.getElementById('clear-atc-btn')?.addEventListener('click', () => typeof clearPad === 'function' && clearPad('atc'));
    
        // 7. Token Listeners (Dynamic Extraction)
        const tokenInput = document.getElementById('input-token');
        if (tokenInput) {
            tokenInput.value = localStorage.getItem('skyplan_token') || '';
            tokenInput.addEventListener('input', (e) => {
                const newToken = e.target.value.trim();
                if (newToken) {
                    localStorage.setItem('skyplan_token', newToken);
                    try {
                        const decoded = typeof decodeJWT === 'function' ? decodeJWT(newToken) : null;
                        if (decoded?.preferred_username) {
                            localStorage.setItem('efb_user', decoded.preferred_username);
                        }
                    } catch (err) { console.warn("Could not extract username from token."); }
                } else {
                    localStorage.removeItem('skyplan_token');
                    localStorage.removeItem('efb_user');
                }
            });
        }

        const refreshTokenInput = document.getElementById('refresh-token');
        if (refreshTokenInput) {
            refreshTokenInput.value = localStorage.getItem('skyplan_refresh_token') || '';
            refreshTokenInput.addEventListener('input', (e) => {
                const newRef = e.target.value.trim();
                newRef ? localStorage.setItem('skyplan_refresh_token', newRef) : localStorage.removeItem('skyplan_refresh_token');
            });
        }

        // 8. Debounced NOTAM Filter (Prevents UI freezing)
        document.getElementById('notam-filter')?.addEventListener('input', typeof debounce === 'function' ? debounce(function() {
            if (!window.notamFullAlerts) return;
            const filterText = this.value.toLowerCase().trim();
            
            if (filterText === '') {
                renderNotamsWXTable(window.notamFullAlerts);
            } else {
                const filtered = window.notamFullAlerts.filter(a => 
                    (a.airport || '').toLowerCase().includes(filterText) || 
                    (a.message || '').toLowerCase().includes(filterText) || 
                    (a.type || '').toLowerCase().includes(filterText)
                );
                renderNotamsWXTable(filtered);
            }
        }, 250) : function() {}); // Fallback if debounce missing

        // 9. High-Speed Popups for ATIS/ATC
        const isTypingMode = () => document.body.getAttribute('data-atis-mode') !== 'writing';

        const atisField = document.getElementById('front-atis');
        if (atisField) {
            atisField.addEventListener('focus', function(e) {
                if (isTypingMode()) {
                    e.preventDefault();
                    atisField.blur();
                    if (typeof showAtisPopup === 'function') showAtisPopup();
                }
            });
        }

        const atcField = document.getElementById('front-atc');
        if (atcField) {
            atcField.addEventListener('focus', function(e) {
                if (isTypingMode()) {
                    e.preventDefault();
                    atcField.blur();
                    if (typeof showClearancePopup === 'function') showClearancePopup();
                }
            });
        }

        // 10. Final Binds & State Load
        document.getElementById('btn-send-tripinfo')?.addEventListener('click', typeof sendTripInfo === 'function' ? sendTripInfo : null);

        if (sessionStorage.getItem('efb_authenticated') === 'true') {
            if (typeof setupActivityTracking === 'function') setupActivityTracking();
            if (typeof resetAutoLockTimer === 'function') resetAutoLockTimer();
        }
        
        if (typeof loadState === 'function') loadState();
    });

    // --- GLOBAL LIFECYCLE EVENTS ---

    // Prevent redundant simultaneous saves
    let isSavingOnExit = false;
    const triggerExitSave = () => {
        if (isSavingOnExit) return;
        isSavingOnExit = true;
        if (typeof debouncedSave !== 'undefined' && debouncedSave.cancel) debouncedSave.cancel();
        if (typeof saveState === 'function') saveState();
        setTimeout(() => isSavingOnExit = false, 500);
    };

    window.addEventListener('beforeunload', triggerExitSave);
    window.addEventListener('pagehide', triggerExitSave);
    
    document.addEventListener('visibilitychange', () => {
        if (document.visibilityState === 'hidden') triggerExitSave();
    });

    // Debounced Resize to prevent canvas stretching & CPU overload during rotation
    window.addEventListener('resize', typeof debounce === 'function' ? debounce(() => {
        if (typeof resizePad === 'function') {
            resizePad('main');
            if (typeof currentAtisInputMode !== 'undefined' && currentAtisInputMode === 'writing') {
                resizePad('atis');
                resizePad('atc');
            }
        }
    }, 200) : () => {});

// ==========================================
// ATIS Structured Popup (compact + smart fields)
// ==========================================

function showAtisPopup() {
    const bodyHTML = `
        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 10px 15px;">

            <!-- Column 1 -->
            <div>
                <label style="font-size: 11px; font-weight: 600; color: var(--dim);">Info Letter</label>
                <input type="text" id="atis-info" maxlength="1" placeholder="A" 
                       style="width: 100%; padding: 8px; border-radius: 6px; background: var(--input); color: var(--text); border: 1px solid var(--border); font-size: 16px; margin-top: 2px;">
            </div>

            <div>
                <label style="font-size: 11px; font-weight: 600; color: var(--dim);">Wind (dir/spd/gust)</label>
                <input type="tel" id="atis-wind" placeholder="240/5" maxlength="9"
                    style="width: 100%; padding: 8px; border-radius: 6px; background: var(--input); color: var(--text); border: 1px solid var(--border); font-size: 16px; margin-top: 2px;">
            </div>

            <div>
                <label style="font-size: 11px; font-weight: 600; color: var(--dim); display: block;">Visibility</label>
                <div style="margin-top: 2px;">
                    <input type="text" id="atis-vis" maxlength="4" placeholder="10KM" value="10"
                        style="width: 100%; padding: 8px; border-radius: 6px; background: var(--input); color: var(--text); border: 1px solid var(--border); font-size: 16px;">
                </div>
            </div>

            <div>
                <label style="font-size: 11px; font-weight: 600; color: var(--dim); display: block;">Cloud</label>
                <div style="margin-top: 2px; display: flex; gap: 6px; flex-wrap: wrap; align-items: center;">
                    <label style="display: flex; align-items: center; gap: 3px; font-size: 13px;">
                        <input type="checkbox" id="cloud-few"> FEW
                        <input type="text" id="cloud-few-alt" placeholder="040" maxlength="3" inputmode="numeric" pattern="[0-9]*"
                            style="width: 42px; padding: 4px; border-radius: 4px; background: var(--input); color: var(--text); border: 1px solid var(--border); font-size: 13px; display: none;">
                    </label>
                    <label style="display: flex; align-items: center; gap: 3px; font-size: 13px;">
                        <input type="checkbox" id="cloud-sct"> SCT
                        <input type="text" id="cloud-sct-alt" placeholder="040" maxlength="3" inputmode="numeric" pattern="[0-9]*"
                            style="width: 42px; padding: 4px; border-radius: 4px; background: var(--input); color: var(--text); border: 1px solid var(--border); font-size: 13px; display: none;">
                    </label>
                    <label style="display: flex; align-items: center; gap: 3px; font-size: 13px;">
                        <input type="checkbox" id="cloud-bkn"> BKN
                        <input type="text" id="cloud-bkn-alt" placeholder="040" maxlength="3" inputmode="numeric" pattern="[0-9]*"
                            style="width: 42px; padding: 4px; border-radius: 4px; background: var(--input); color: var(--text); border: 1px solid var(--border); font-size: 13px; display: none;">
                    </label>
                    <label style="display: flex; align-items: center; gap: 3px; font-size: 13px;">
                        <input type="checkbox" id="cloud-ovc"> OVC
                        <input type="text" id="cloud-ovc-alt" placeholder="040" maxlength="3" inputmode="numeric" pattern="[0-9]*"
                            style="width: 42px; padding: 4px; border-radius: 4px; background: var(--input); color: var(--text); border: 1px solid var(--border); font-size: 13px; display: none;">
                    </label>
                </div>
            </div>

            <div>
                <label style="font-size: 11px; font-weight: 600; color: var(--dim);">Temp/Dew</label>
                <input type="tel" id="atis-temp" placeholder="15/10" maxlength="5"
                    style="width: 100%; padding: 8px; border-radius: 6px; background: var(--input); color: var(--text); border: 1px solid var(--border); font-size: 16px; margin-top: 2px;">
            </div>

            <div>
                <label style="font-size: 11px; font-weight: 600; color: var(--dim);">QNH (digits only)</label>
                <input type="tel" id="atis-qnh" maxlength="4" placeholder="1013"
                       style="width: 100%; padding: 8px; border-radius: 6px; background: var(--input); color: var(--text); border: 1px solid var(--border); font-size: 16px; margin-top: 2px;">
            </div>

            <!-- RWY Condition (full width) -->
            <div style="grid-column: 1 / -1;">
                <label style="font-size: 11px; font-weight: 600; color: var(--dim);">RWY Condition</label>
                <select id="atis-rwy-cond" style="width: 100%; padding: 8px; border-radius: 6px; background: var(--input); color: var(--text); border: 1px solid var(--border); font-size: 16px; margin-top: 2px;">
                    <option value="DRY" selected>DRY</option>
                    <option value="WET">WET</option>
                    <option value="CONTAMINATED">CONTAMINATED</option>
                </select>
                <div id="atis-cc-wrapper" style="display: none; margin-top: 5px;">
                    <input type="text" id="atis-rwy-cc" placeholder="5/5/5 100/100/100" maxlength="30"
                           style="width: 100%; padding: 8px; border-radius: 6px; background: var(--input); color: var(--text); border: 1px solid var(--border); font-size: 14px;">
                </div>
            </div>

            <!-- Sig WX & Remarks row (full width) -->
            <div style="grid-column: 1 / -1; display: flex; gap: 15px; align-items: center; flex-wrap: wrap;">
                <div style="display: flex; gap: 8px; align-items: center;">
                    <span style="font-size: 11px; font-weight: 600; color: var(--dim);">Sig WX</span>
                    <label style="display: flex; align-items: center; gap: 4px; font-size: 13px;">
                        <input type="checkbox" id="atis-nsc"> NSC
                    </label>
                    <label style="display: flex; align-items: center; gap: 4px; font-size: 13px;">
                        <input type="checkbox" id="atis-ts"> TS
                    </label>
                    <input type="text" id="atis-sigwx-other" placeholder="Other" maxlength="20"
                           style="width: 80px; padding: 6px; border-radius: 6px; background: var(--input); color: var(--text); border: 1px solid var(--border); font-size: 14px;">
                </div>
                <div style="display: flex; gap: 8px; align-items: center;">
                    <span style="font-size: 11px; font-weight: 600; color: var(--dim);">Remarks</span>
                    <label style="display: flex; align-items: center; gap: 4px; font-size: 13px;">
                        <input type="checkbox" id="atis-nosig"> NOSIG
                    </label>
                    <input type="text" id="atis-remarks-other" placeholder="Other" maxlength="50"
                           style="width: 120px; padding: 6px; border-radius: 6px; background: var(--input); color: var(--text); border: 1px solid var(--border); font-size: 14px;">
                </div>
            </div>
        </div>
    `;

    // Modal call – now with custom maxWidth
    const modalPromise = createModal({
        title: 'ATIS',
        icon: '📡',
        type: 'info',
        confirmText: 'Done',
        cancelText: 'Cancel',
        centered: false,
        compact: true,
        maxWidth: '600px',   // ← wider popup
        bodyHTML: bodyHTML,
        onConfirm: () => {
            const parts = [];

            const info = document.getElementById('atis-info')?.value.trim().toUpperCase();
            if (info) parts.push(info);

            const wind = document.getElementById('atis-wind')?.value.trim();
            if (wind) parts.push(wind);

            const vis = document.getElementById('atis-vis')?.value.trim();
            if (vis) parts.push(vis);

            // Sig WX
            const nsc = document.getElementById('atis-nsc')?.checked;
            const ts = document.getElementById('atis-ts')?.checked;
            const otherSig = document.getElementById('atis-sigwx-other')?.value.trim();
            if (nsc) parts.push('NSC');
            if (ts) parts.push('TS');
            if (otherSig) parts.push(otherSig);

            // Cloud – only include if checkbox is checked and altitude is provided
            const cloudTypes = ['FEW', 'SCT', 'BKN', 'OVC'];
            cloudTypes.forEach(type => {
                const cb = document.getElementById(`cloud-${type.toLowerCase()}`);
                const altInput = document.getElementById(`cloud-${type.toLowerCase()}-alt`);
                if (cb && cb.checked && altInput && altInput.value.trim() !== '') {
                    const alt = altInput.value.trim().padStart(3, '0'); // ensure 3 digits (e.g., "040")
                    parts.push(`${type}${alt}`);
                }
            });

            const temp = document.getElementById('atis-temp')?.value.trim();
            if (temp) parts.push(temp);

            const qnhDigits = document.getElementById('atis-qnh')?.value.trim();
            if (qnhDigits) parts.push('Q' + qnhDigits);

            // RWY Cond
            const rwyCond = document.getElementById('atis-rwy-cond')?.value;
            if (rwyCond === 'DRY') {
                parts.push('DRY');
            } else {
                const cc = document.getElementById('atis-rwy-cc')?.value.trim();
                if (cc) parts.push(rwyCond + ' ' + cc);
                else parts.push(rwyCond);
            }

            // Remarks
            const nosig = document.getElementById('atis-nosig')?.checked;
            const otherRem = document.getElementById('atis-remarks-other')?.value.trim();
            if (nosig) parts.push('NOSIG');
            if (otherRem) parts.push(otherRem);

            document.getElementById('front-atis').value = parts.join(' ');
        }
    });


    // After DOM insertion, set up dynamic behaviour
    requestAnimationFrame(() => {
        // Define the field order for auto-advance
        const fieldOrder = [
            'atis-info',
            'atis-wind',
            'atis-vis',
            'atis-temp',
            'atis-qnh'
        ];

        // Helper to focus next field in the list
        function focusNext(currentId) {
            const idx = fieldOrder.indexOf(currentId);
            if (idx !== -1 && idx < fieldOrder.length - 1) {
                const nextField = document.getElementById(fieldOrder[idx + 1]);
                if (nextField) nextField.focus();
            } else {
                // If no more text inputs, maybe focus Done button
                const doneBtn = document.getElementById('modal-confirm');
                if (doneBtn) doneBtn.focus();
            }
        }

        // Auto-advance when a field is "full" (value length equals its maxlength)
        fieldOrder.forEach(id => {
            const el = document.getElementById(id);
            if (!el) return;
            el.addEventListener('input', function() {
                const max = parseInt(this.getAttribute('maxlength'), 10);
                if (max && this.value.length >= max) {
                    focusNext(id);
                }
            });
        });

        // Wind mask – correctly formats DDD/SS/GG
        const windInput = document.getElementById('atis-wind');
        if (windInput) {
            windInput.addEventListener('input', function() {
                let digits = this.value.replace(/[^\d]/g, '');
                let formatted = '';
                if (digits.length > 0) {
                    formatted += digits.slice(0, 3); // direction
                }
                if (digits.length > 3) {
                    formatted += '/' + digits.slice(3, 5); // speed (2 digits)
                }
                if (digits.length > 5) {
                    formatted += '/' + digits.slice(5, 7); // gust (max 2 digits)
                }
                this.value = formatted;
            });
        }

        // ----- Temp mask (unchanged) -----
        const tempInput = document.getElementById('atis-temp');
        if (tempInput) {
            tempInput.addEventListener('input', function() {
                let val = this.value.replace(/[^\d]/g, '');
                if (val.length > 2) {
                    val = val.slice(0, 2) + '/' + val.slice(2, 4);
                }
                this.value = val;
            });
        }

        // ----- QNH digits only (unchanged) -----
        const qnhInput = document.getElementById('atis-qnh');
        if (qnhInput) {
            qnhInput.addEventListener('input', function() {
                this.value = this.value.replace(/\D/g, '');
            });
        }

        // ----- RWY condition toggle (unchanged) -----
        const rwyCondSelect = document.getElementById('atis-rwy-cond');
        const ccWrapper = document.getElementById('atis-cc-wrapper');
        if (rwyCondSelect && ccWrapper) {
            const toggle = () => {
                ccWrapper.style.display = rwyCondSelect.value !== 'DRY' ? 'block' : 'none';
            };
            rwyCondSelect.addEventListener('change', toggle);
            toggle();
        }

        // Cloud checkbox toggles – show/hide altitude input
        ['few', 'sct', 'bkn', 'ovc'].forEach(type => {
            const cb = document.getElementById(`cloud-${type}`);
            const alt = document.getElementById(`cloud-${type}-alt`);
            if (cb && alt) {
                cb.addEventListener('change', () => {
                    alt.style.display = cb.checked ? 'inline-block' : 'none';
                    if (cb.checked) alt.focus(); // focus altitude input immediately
                });
            }
        });

        // ----- Enter key to move to next field (unchanged) -----
        const allInputs = Array.from(document.querySelectorAll('#atis-info, #atis-wind, #atis-vis, #atis-cloud, #atis-temp, #atis-qnh, #atis-sigwx-other, #atis-remarks-other, #atis-rwy-cc'));
        allInputs.forEach((input, idx) => {
            input.addEventListener('keydown', function(e) {
                if (e.key === 'Enter') {
                    e.preventDefault();
                    const next = allInputs[idx + 1];
                    if (next) next.focus();
                    else document.getElementById('modal-confirm')?.focus();
                }
            });
        });

        // Focus first field
        document.getElementById('atis-info')?.focus();
    });

    return modalPromise;
}

// ==========================================
// CLEARANCE Structured Popup (compact + smart fields)
// ==========================================

function extractFirstWaypoint(routeStr) {
    if (!routeStr) return '';
    const tokens = routeStr.trim().split(/\s+/);
    // Skip tokens that are:
    // - exactly 4 uppercase letters (likely an ICAO airport)
    // - start with '-' (speed/altitude group like -N0440F300)
    // - contain digits only
    // - are a known airway format (letter+digits, e.g., M75)
    for (const token of tokens) {
        const upper = token.toUpperCase();
        // Skip airport codes (exactly 4 letters) if it's the first token
        if (upper === token && /^[A-Z]{4}$/.test(upper)) continue;
        // Skip speed/altitude groups
        if (token.startsWith('-')) continue;
        // Skip all-digit tokens
        if (/^\d+$/.test(token)) continue;
        // Skip airway identifiers (letter followed by digits)
        if (/^[A-Z]\d+$/.test(upper)) continue;
        // Accept anything that looks like a waypoint: 2-5 letters
        if (/^[A-Z]{2,5}$/.test(upper)) return upper;
    }
    return '';
}

function showClearancePopup() {
    const dest = (document.getElementById('view-dest')?.innerText || '').trim().toUpperCase();
    const routeStr = (document.getElementById('view-dest-route')?.innerText || '').trim();
    const firstWpt = extractFirstWaypoint(routeStr);

    const bodyHTML = `
        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 10px 15px;">

            <!-- Cleared to -->
            <div>
                <label style="font-size: 11px; font-weight: 600; color: var(--dim); display: block;">Cleared to</label>
                <div style="margin-top: 2px;">
                    <input type="text" id="clr-dest" maxlength="4" value="${dest}"
                           style="width: 100%; padding: 8px; border-radius: 6px; background: var(--input); color: var(--text); border: 1px solid var(--border); font-size: 16px;">
                </div>
            </div>

            <!-- Via (FPLN route checkbox) -->
            <div>
                <label style="font-size: 11px; font-weight: 600; color: var(--dim); display: block;">Via</label>
                <div style="margin-top: 2px; display: flex; align-items: center; height: 36px;">
                    <label style="display: flex; align-items: center; gap: 6px; font-size: 14px;">
                        <input type="checkbox" id="clr-fpln" checked> FPLN route
                    </label>
                </div>
            </div>

            <!-- SID -->
            <div>
                <label style="font-size: 11px; font-weight: 600; color: var(--dim); display: block;">SID</label>
                <div style="margin-top: 2px;">
                    <input type="text" id="clr-sid" maxlength="10" value="${firstWpt}"
                           style="width: 100%; padding: 8px; border-radius: 6px; background: var(--input); color: var(--text); border: 1px solid var(--border); font-size: 16px;">
                </div>
            </div>

            <!-- Runway (NEW) -->
            <div>
                <label style="font-size: 11px; font-weight: 600; color: var(--dim); display: block;">Runway</label>
                <div style="margin-top: 2px;">
                    <input type="text" id="clr-rwy" maxlength="2" inputmode="numeric" pattern="[0-9]*" placeholder="04"
                           style="width: 100%; padding: 8px; border-radius: 6px; background: var(--input); color: var(--text); border: 1px solid var(--border); font-size: 16px;">
                </div>
            </div>

            <!-- Climb initially -->
            <div>
                <label style="font-size: 11px; font-weight: 600; color: var(--dim); display: block;">Climb initially</label>
                <div style="margin-top: 2px;">
                    <input type="text" id="clr-climb" maxlength="5" inputmode="numeric" pattern="[0-9]*" placeholder="5000"
                           style="width: 100%; padding: 8px; border-radius: 6px; background: var(--input); color: var(--text); border: 1px solid var(--border); font-size: 16px;">
                </div>
            </div>

            <!-- Squawk -->
            <div>
                <label style="font-size: 11px; font-weight: 600; color: var(--dim); display: block;">Squawk</label>
                <div style="margin-top: 2px;">
                    <input type="text" id="clr-squawk" maxlength="4" inputmode="numeric" pattern="[0-9]*" placeholder="1234"
                           style="width: 100%; padding: 8px; border-radius: 6px; background: var(--input); color: var(--text); border: 1px solid var(--border); font-size: 16px;">
                </div>
            </div>

            <!-- Remarks (full width) -->
            <div style="grid-column: 1 / -1;">
                <label style="font-size: 11px; font-weight: 600; color: var(--dim); display: block;">Remarks</label>
                <div style="margin-top: 2px;">
                    <input type="text" id="clr-remarks" maxlength="100" placeholder="Any additional instructions"
                           style="width: 100%; padding: 8px; border-radius: 6px; background: var(--input); color: var(--text); border: 1px solid var(--border); font-size: 16px;">
                </div>
            </div>
        </div>
    `;

    const modalPromise = createModal({
        title: 'ATC Clearance',
        icon: '📡',
        type: 'info',
        confirmText: 'Done',
        cancelText: 'Cancel',
        centered: false,
        compact: true,
        maxWidth: '600px',
        bodyHTML: bodyHTML,
        onConfirm: () => {
            const parts = [];

            const dest = document.getElementById('clr-dest')?.value.trim().toUpperCase();
            if (dest) parts.push('Cleared to ' + dest);

            if (document.getElementById('clr-fpln')?.checked) {
                parts.push('via FPLN route');
            }

            const sid = document.getElementById('clr-sid')?.value.trim().toUpperCase();
            if (sid) parts.push('SID ' + sid);

            const rwy = document.getElementById('clr-rwy')?.value.trim();
            if (rwy) parts.push('RWY ' + rwy);

            const climb = document.getElementById('clr-climb')?.value.trim();
            if (climb) parts.push('climb initially ' + climb + 'ft');

            const squawk = document.getElementById('clr-squawk')?.value.trim();
            if (squawk) parts.push('squawk ' + squawk);

            const remarks = document.getElementById('clr-remarks')?.value.trim();
            if (remarks) parts.push(remarks);

            document.getElementById('front-atc').value = parts.join(', ');
        }
    });

    // Dynamic behaviour
    requestAnimationFrame(() => {
        // Digits only for climb and squawk and runway
        const climbInput = document.getElementById('clr-climb');
        if (climbInput) {
            climbInput.addEventListener('input', function() {
                this.value = this.value.replace(/\D/g, '');
            });
        }
        const squawkInput = document.getElementById('clr-squawk');
        if (squawkInput) {
            squawkInput.addEventListener('input', function() {
                this.value = this.value.replace(/\D/g, '');
            });
        }
        const rwyInput = document.getElementById('clr-rwy');
        if (rwyInput) {
            rwyInput.addEventListener('input', function() {
                this.value = this.value.replace(/\D/g, '').slice(0,2);
            });
        }

        // Auto‑advance field order (including new runway)
        const fieldOrder = [
            'clr-dest',
            'clr-sid',
            'clr-rwy',
            'clr-climb',
            'clr-squawk',
            'clr-remarks'
        ];
        const allInputs = Array.from(document.querySelectorAll(
            '#clr-dest, #clr-sid, #clr-rwy, #clr-climb, #clr-squawk, #clr-remarks'
        ));

        // Enter key
        allInputs.forEach((input, idx) => {
            input.addEventListener('keydown', function(e) {
                if (e.key === 'Enter') {
                    e.preventDefault();
                    const next = allInputs[idx + 1];
                    if (next) next.focus();
                    else document.getElementById('modal-confirm')?.focus();
                }
            });
        });

        // Auto‑advance when maxlength reached
        fieldOrder.forEach(id => {
            const el = document.getElementById(id);
            if (!el) return;
            el.addEventListener('input', function() {
                const max = parseInt(this.getAttribute('maxlength'), 10);
                if (max && this.value.length >= max) {
                    const idx = fieldOrder.indexOf(id);
                    const nextId = fieldOrder[idx + 1];
                    if (nextId) {
                        const next = document.getElementById(nextId);
                        if (next) next.focus();
                    } else {
                        document.getElementById('modal-confirm')?.focus();
                    }
                }
            });
        });

        // Focus first field
        document.getElementById('clr-dest')?.focus();
    });

    return modalPromise;
}

// ==========================================
// Aircraft Defects (ADD / CDD) Management
// ==========================================

window.fetchAircraftDefects = async function(tailNumber) {
    if (!tailNumber || tailNumber === '-' || tailNumber === 'TBA') {
        renderADDTable([], tailNumber || '-');
        return [];
    }

    const cleanTail = tailNumber.trim().toUpperCase();
    const tailEl = document.getElementById('add-tail-number');
    if (tailEl) tailEl.textContent = cleanTail;

    const token = await getValidSkyplanToken();
    if (!token) return [];

    try {
        
        const response = await fetch('https://kcskyplanapi.airastana.com/api/v1/defect-reports', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`
            },
            body: JSON.stringify({ TailNumbers: [cleanTail] })
        });

        if (!response.ok) {
            throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }

        const data = await response.json();
        const defects = data.DefectReports || [];

        window.currentAircraftADDs = defects;
        window.currentADDRegistration = cleanTail;

        renderADDTable(defects, cleanTail);
        return defects;

    } catch (error) {
        if (typeof showToast === 'function') {
            showToast(`Failed to load ADDs for ${cleanTail}: ${error.message}`, 'error');
        }
        renderADDTable([], cleanTail, error.message);
        return [];
    }
};

function renderADDTable(defects, tailNumber, errorMessage = null) {
    const tbody = document.getElementById('add-tbody');
    const tailEl = document.getElementById('add-tail-number');
    if (tailEl) tailEl.textContent = tailNumber || '-';
    if (!tbody) return;

    if (errorMessage) {
        tbody.innerHTML = `<tr><td colspan="7" style="text-align:center; color:var(--error); padding:25px;">Error loading ADDs: ${errorMessage}</td></tr>`;
        return;
    }

    if (!defects || defects.length === 0) {
        tbody.innerHTML = `<tr><td colspan="7" style="text-align:center; color:var(--dim); padding:25px;">No active ADD / CDD items for ${tailNumber}.</td></tr>`;
        return;
    }

    const formatDate = (dateStr) => {
        if (!dateStr) return '-';
        const d = new Date(dateStr);
        if (isNaN(d.getTime())) return dateStr.split('T')[0];
        const day = String(d.getDate()).padStart(2, '0');
        const month = String(d.getMonth() + 1).padStart(2, '0');
        const year = String(d.getFullYear()).slice(-2);
        return `${day}/${month}/${year}`;
    };

    let html = '';
    defects.forEach(item => {
        const type = item.DefectType || 'ADD';
        const typeClass = type === 'CDD' ? 'badge warning' : 'badge critical';
        const ata = item.Chapter ? `ATA ${item.Chapter}` : '-';
        const mel = item.Mel || item.MelNumber || '-';
        const defectTitle = item.Defect ? `<strong>${item.Defect}:</strong> ` : '';
        const desc = item.Description || '-';
        const deferDate = formatDate(item.DeferDate);
        const dueDate = formatDate(item.DeferToDate);
        const notes = item.DeferNotes || '-';

        html += `
            <tr>
                <td><span class="${typeClass}">${type}</span></td>
                <td style="font-weight: 600; color: var(--accent);">${ata}</td>
                <td style="font-weight: 600;">${mel}</td>
                <td style="word-break: break-word;">${defectTitle}${desc}</td>
                <td style="font-family: monospace; font-size: 13px;">${deferDate}</td>
                <td style="font-family: monospace; font-size: 13px; color: var(--error); font-weight: bold;">${dueDate}</td>
                <td style="word-break: break-word; color: var(--dim); font-size: 13px;">${notes}</td>
            </tr>
        `;
    });

    tbody.innerHTML = html;
}

window.refreshCurrentAircraftADDs = function() {
    const reg = window.currentADDRegistration || (document.getElementById('view-reg')?.innerText || '').trim();
    if (reg && reg !== '-') {
        window.fetchAircraftDefects(reg);
    } else {
        if (typeof showToast === 'function') showToast('No active aircraft registration available.', 'info');
    }
};

// ==========================================
// Trip Info
// ==========================================

function convertTripTime(timeStr) {
    if (!timeStr || timeStr === '-') return '';
    // Expect "HH.MM"
    const [h, m] = timeStr.split('.');
    return (h || '00').padStart(2,'0') + (m || '00').padStart(2,'0');
}

async function fetchFlightIdFromRoster(flightDateStr, flightNumberRaw, depIcaoRaw) {

    const token = await getValidSkyplanToken();
    if (!token) {
        console.error('Valid Skyplan token unavailable (token missing, expired, or prompt dismissed).');
        return null;
    }

    let employeeId = null;
    try {
        const employee = decodeJWT(token);
        employeeId = employee.employeeid || null;
    } catch (e) {
        console.warn('Failed to decode JWT', e);
    }

    // Clean inputs
    const flightNumber = String(parseInt(flightNumberRaw.replace(/\D/g, ''), 10)); 
    const depIcao = depIcaoRaw.replace(/[^A-Z]/ig, '').toUpperCase(); 

    // Date Parsing
    let flightDate;
    if (flightDateStr.includes('-')) {
        flightDate = flightDateStr;
    } else {
        const parts = (flightDateStr || '').split(/[\/\.]/);
        const day = (parts[0] || '01').trim();
        const month = (parts[1] || '01').trim();
        let year = (parts[2] || '2026').trim();
        if (year.length === 2) year = `20${year}`; 
        flightDate = `${year}-${month.padStart(2,'0')}-${day.padStart(2,'0')}`;
    }
    const baseDate = new Date(flightDate);
    if (isNaN(baseDate.getTime())) {
        console.error("Date parsing failed completely.");
        return null;
    }

    // Date Window
    const fromDate = new Date(baseDate);
    fromDate.setDate(fromDate.getDate() - 1);
    const toDate = new Date(baseDate);
    toDate.setDate(toDate.getDate() + 1); 

    const payload = {
        EmployeeID: employeeId,
        From: fromDate.toISOString().slice(0,10),
        To: toDate.toISOString().slice(0,10)
    };
    
    try {
        const resp = await fetch('https://kcskyplanapi.airastana.com/api/v1/crew-roster-flights-details', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`
            },
            body: JSON.stringify(payload)
        });
        
        
        if (!resp.ok) {
            if (resp.status === 401) {
                console.error('401 Unauthorized - Your Skyplan token has expired or is invalid.');
            }
            const errText = await resp.text();
            console.error(`Error Response Body:`, errText);
            throw new Error(`Status ${resp.status}`);
        }
        
        const data = await resp.json();
        const flights = data.Flights || [];

        const match = flights.find(f => {
            const apiFltNum = f.FlightNumber.toString();
            const apiIcao = (f.DepartureStationIcaoCode || '').toUpperCase();
            const apiIata = (f.DepartureStationCode || '').toUpperCase();
            
            const isMatch = ['KC', 'FS'].includes(f.CarrierCode) && 
                            apiFltNum === flightNumber && 
                            (apiIcao === depIcao || apiIata === depIcao);
            
            return isMatch;
        });

        if (match) {
            return match.ID;
        } else {
            return null;
        }

    } catch (e) {
        return null;
    }
}

async function fetchCrewInfo(flightId, token) {
    try {
        const resp = await fetch('https://kcskyplanapi.airastana.com/api/v1/flights-crew-members', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`
            },
            body: JSON.stringify({ FlightIDs: [flightId] })
        });

        if (!resp.ok) throw new Error(`Status ${resp.status}`);

        const data = await resp.json();
        const flightData = data.FlightsCrewMembers?.[0];

        if (!flightData || !Array.isArray(flightData.CrewMembers)) {
            // No crew data – clear the cache and return safe defaults
            window.crewData = [];
            return null;
        }

        const members = flightData.CrewMembers;

        // ── Identify flight deck positions (all other positions are cabin crew) ──
        const flightDeckPositions = ['CP', 'FO', 'P1', 'P2', 'SO'];
        const flightDeck = members.filter(m => flightDeckPositions.includes(m.Position));
        const cabinCrew = members.filter(m => !flightDeckPositions.includes(m.Position));

        // ── Cache the ordered crew list globally for Journey Log ──
        window.crewData = [
            ...flightDeck.map(m => ({
                FirstName: m.FirstName,
                LastName: m.LastName,
                Position: m.Position
            })),
            ...cabinCrew.map(m => ({
                FirstName: m.FirstName,
                LastName: m.LastName,
                Position: m.Position
            }))
        ];

        // ── Captain name ──
        const captain = members.find(m => m.Position === 'CP');
        const captainName = captain
            ? `${captain.FirstName} ${captain.LastName}`.trim()
            : '';

        // ── Counts (with fallback to API-provided PilotCount / CrewCount) ──
        const fcCount = flightDeck.length > 0
            ? flightDeck.length
            : (flightData.PilotCount || 2);

        const ccCount = cabinCrew.length > 0
            ? cabinCrew.length
            : Math.max(0, (flightData.CrewCount || 6) - (flightData.PilotCount || 2));

        return {
            captainName,
            fcCount,
            ccCount
        };
    } catch (e) {
        console.error('[Crew Fetch] Failed:', e);
        window.crewData = [];   // ensure it's empty on error
        return null;
    }
}

async function sendTripInfo() {
    const token = await getValidSkyplanToken();
    if (!token) {
        showToast('Missing Skyplan token. Set it via console.', 'error');
        return;
    }

    const flightDateStr = (document.getElementById('view-date')?.innerText || '').trim();
    const flightNumberRaw = (document.getElementById('view-flt')?.innerText || '').trim();
    const flightNumber = flightNumberRaw.replace(/^KC/i, '').replace(/^AYN/i, ''); 
    const depIcao = (document.getElementById('view-dep')?.innerText || '').trim();

    let externalFlightId = window.currentExternalFlightId;

    if (!externalFlightId) {
        showToast('Fetching flight ID from roster…', 'info');
        externalFlightId = await fetchFlightIdFromRoster(flightDateStr, flightNumber, depIcao);
        
        if (!externalFlightId) {
            showToast('Could not find flight in roster.', 'error');
            return;
        }
        window.currentExternalFlightId = externalFlightId;
    }

    showToast('Fetching crew manifest…', 'info');
    const crewInfo = await fetchCrewInfo(externalFlightId, token);

    const mtow = parseInt(document.getElementById('view-mtow')?.innerText) || 0;
    const mlw  = parseInt(document.getElementById('view-mlw')?.innerText) || 0;

    const activeFuelData = window.fuelData || (typeof fuelData !== 'undefined' ? fuelData : []);
    const tripItem = activeFuelData.find(i => i.name === 'TRIP');
    const tripTimeRaw = tripItem ? tripItem.time : '';
    const tripTime = tripTimeRaw ? tripTimeRaw.replace('.', ':') : '00:00';

    // Robust extraction for view-pic-block (handles both inputs and text blocks)
    const picBlockElem = document.getElementById('view-pic-block');
    let picBlockVal = NaN;
    if (picBlockElem) {
        const rawText = picBlockElem.value !== undefined ? picBlockElem.value : picBlockElem.innerText;
        picBlockVal = parseInt(rawText.replace(/\D/g, ''), 10);
    }
    const rampFuel = !isNaN(picBlockVal) && picBlockVal > 0 ? picBlockVal : (window.blockFuelValue || (typeof blockFuelValue !== 'undefined' ? blockFuelValue : 0));

    const taxiItem = activeFuelData.find(i => i.name === 'TAXI');
    const taxiFuel = taxiItem ? parseInt(taxiItem.fuel) || 0 : 0;
    const tripFuel = tripItem ? parseInt(tripItem.fuel) || 0 : 0;
    const takeOffFuel = rampFuel - taxiFuel;

    const ofpRequest = window.ofpRequestNumber || (typeof ofpRequestNumber !== 'undefined' ? ofpRequestNumber : '');
    
    let fcCount = parseInt(document.getElementById('j-fc-count')?.value) || 2;
    let ccCount = parseInt(document.getElementById('j-cc-count')?.value) || 4;
    let defaultCaptain = localStorage.getItem('efb_captain_name') || '';

    if (crewInfo) {
        if (crewInfo.captainName) defaultCaptain = crewInfo.captainName;
        if (crewInfo.fcCount) {
            fcCount = crewInfo.fcCount;
            const fcInput = document.getElementById('j-fc-count');
            if (fcInput) fcInput.value = fcCount;
        }
        if (crewInfo.ccCount >= 0) {
            ccCount = crewInfo.ccCount;
            const ccInput = document.getElementById('j-cc-count');
            if (ccInput) ccInput.value = ccCount;
        }
    }

    const bodyHTML = `
        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 10px 15px;">
            <div style="grid-column: 1 / -1;">
                <label style="font-size: 11px; font-weight: 600; color: var(--dim); display: block;">Captain Name</label>
                <input type="text" id="sp-capt" value="${defaultCaptain}" placeholder="JOHN DOE"
                       style="width: 100%; padding: 8px; border-radius: 6px; background: var(--input); color: var(--text); border: 1px solid var(--border); font-size: 16px;">
            </div>
            <div>
                <label style="font-size: 11px; font-weight: 600; color: var(--dim); display: block;">MTOW (kg)</label>
                <input type="number" id="sp-mtow" value="${mtow}" style="width: 100%; padding: 8px; border-radius: 6px; background: var(--input); color: var(--text); border: 1px solid var(--border); font-size: 16px;">
            </div>
            <div>
                <label style="font-size: 11px; font-weight: 600; color: var(--dim); display: block;">MLW (kg)</label>
                <input type="number" id="sp-mlw" value="${mlw}" style="width: 100%; padding: 8px; border-radius: 6px; background: var(--input); color: var(--text); border: 1px solid var(--border); font-size: 16px;">
            </div>
            <div>
                <label style="font-size: 11px; font-weight: 600; color: var(--dim); display: block;">Ramp Fuel (kg)</label>
                <input type="number" id="sp-ramp" value="${rampFuel}" style="width: 100%; padding: 8px; border-radius: 6px; background: var(--input); color: var(--text); border: 1px solid var(--border); font-size: 16px;">
            </div>
            <div>
                <label style="font-size: 11px; font-weight: 600; color: var(--dim); display: block;">Taxi Fuel (kg)</label>
                <input type="number" id="sp-taxi" value="${taxiFuel}" style="width: 100%; padding: 8px; border-radius: 6px; background: var(--input); color: var(--text); border: 1px solid var(--border); font-size: 16px;">
            </div>
            <div>
                <label style="font-size: 11px; font-weight: 600; color: var(--dim); display: block;">TakeOff Fuel (kg)</label>
                <input type="number" id="sp-tof" value="${takeOffFuel}" style="width: 100%; padding: 8px; border-radius: 6px; background: var(--input); color: var(--text); border: 1px solid var(--border); font-size: 16px;">
            </div>
            <div>
                <label style="font-size: 11px; font-weight: 600; color: var(--dim); display: block;">Trip Fuel (kg)</label>
                <input type="number" id="sp-tripfuel" value="${tripFuel}" style="width: 100%; padding: 8px; border-radius: 6px; background: var(--input); color: var(--text); border: 1px solid var(--border); font-size: 16px;">
            </div>
            <div>
                <label style="font-size: 11px; font-weight: 600; color: var(--dim); display: block;">Trip Time</label>
                <input type="text" id="sp-triptime" value="${tripTime}" placeholder="HH:MM" maxlength="5" style="width: 100%; padding: 8px; border-radius: 6px; background: var(--input); color: var(--text); border: 1px solid var(--border); font-size: 16px;">
            </div>
            <div>
                <label style="font-size: 11px; font-weight: 600; color: var(--dim); display: block;">OFP Request</label>
                <input type="text" id="sp-ofp" value="${ofpRequest}" style="width: 100%; padding: 8px; border-radius: 6px; background: var(--input); color: var(--text); border: 1px solid var(--border); font-size: 16px;">
            </div>
            <div>
                <label style="font-size: 11px; font-weight: 600; color: var(--dim); display: block;">Flight Crew</label>
                <input type="number" id="sp-fc" value="${fcCount}" style="width: 100%; padding: 8px; border-radius: 6px; background: var(--input); color: var(--text); border: 1px solid var(--border); font-size: 16px;">
            </div>
            <div>
                <label style="font-size: 11px; font-weight: 600; color: var(--dim); display: block;">Cabin Crew</label>
                <input type="number" id="sp-cc" value="${ccCount}" style="width: 100%; padding: 8px; border-radius: 6px; background: var(--input); color: var(--text); border: 1px solid var(--border); font-size: 16px;">
            </div>
        </div>
    `;

    createModal({
        title: 'Trip Info',
        icon: '✈️',
        type: 'info',
        confirmText: 'Confirm',
        cancelText: 'Cancel',
        centered: false,
        compact: true,
        maxWidth: '600px',
        bodyHTML: bodyHTML,
        onConfirm: async () => {
            const finalCapt = document.getElementById('sp-capt')?.value.trim().toUpperCase() || '';
            const finalMTOW = parseInt(document.getElementById('sp-mtow')?.value) || 0;
            const finalMLW = parseInt(document.getElementById('sp-mlw')?.value) || 0;
            const finalRamp = parseInt(document.getElementById('sp-ramp')?.value) || 0;
            const finalTaxi = parseInt(document.getElementById('sp-taxi')?.value) || 0;
            const finalTOF = parseInt(document.getElementById('sp-tof')?.value) || 0;
            const finalTripF = parseInt(document.getElementById('sp-tripfuel')?.value) || 0;
            const finalTime = document.getElementById('sp-triptime')?.value.trim() || '00:00';
            const finalOFP = document.getElementById('sp-ofp')?.value.trim() || '';
            const finalFC = parseInt(document.getElementById('sp-fc')?.value) || 2;
            const finalCC = parseInt(document.getElementById('sp-cc')?.value) || 4;

            if (finalCapt) localStorage.setItem('efb_captain_name', finalCapt);

            const payload = {
                ExternalFlightID: externalFlightId,
                CaptainFullName: finalCapt,
                MaximumTakeOffWeightKg: finalMTOW,
                MaximumLandingWeightKg: finalMLW,
                TripTimeDuration: finalTime,
                RampFuelKg: finalRamp,
                TaxiFuelKg: finalTaxi,
                TakeOffFuelKg: finalTOF,
                TripFuelKg: finalTripF,
                OperationalFlightPlanRequestNumber: finalOFP,
                DeadheadQuantity: "0/0",
                CrewQuantity: `${finalFC}/${finalCC}`,
                CaptainCrewQuantity: finalFC,
                OtherCrewQuantity: finalCC,
                CaptainDeadheadQuantity: 0,
                OtherDeadheadQuantity: 0,
                CreatedBy: (() => {
                    let user = localStorage.getItem('efb_user');
                    if (!user) {
                        try {
                            const decoded = decodeJWT(token);
                            user = decoded.preferred_username;
                        } catch(e) {}
                    }
                    return user || 'unknown_user';
                })(),
                CreatedDateTime: new Date().toISOString(),
                Base64SignImage: ''
            };

            showToast('Sending data to Skyplan...', 'info');

            try {
                const response = await fetch('https://kcskyplanapi.airastana.com/api/v1/trip-info', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': `Bearer ${token}`
                    },
                    body: JSON.stringify(payload)
                });

                if (response.ok) {
                    showToast('Fuel data sent to Skyplan ✅', 'success');
                } else {
                    const errText = await response.text();
                    throw new Error(`Server error ${response.status}: ${errText}`);
                }
            } catch (error) {
                console.error('Skyplan upload failed:', error);
                showToast('Failed to send: ' + error.message, 'error');
            }
        }
    });

    requestAnimationFrame(() => {
        const rampInput = document.getElementById('sp-ramp');
        const taxiInput = document.getElementById('sp-taxi');
        const tofInput = document.getElementById('sp-tof');

        const updateTOF = () => {
            const r = parseInt(rampInput.value) || 0;
            const t = parseInt(taxiInput.value) || 0;
            tofInput.value = r - t;
        };

        if (rampInput && taxiInput && tofInput) {
            rampInput.addEventListener('input', updateTOF);
            taxiInput.addEventListener('input', updateTOF);
        }
    });
}

function decodeJWT(token) {
    try {
        let payload = token.split('.')[1];
        // 3. Fix Base64 decoding (Make it URL-safe and pad it correctly)
        payload = payload.replace(/-/g, '+').replace(/_/g, '/');
        const pad = payload.length % 4;
        if (pad) {
            payload += new Array(5 - pad).join('=');
        }
        return JSON.parse(atob(payload));
    } catch (e) {
        console.error('Failed to decode JWT:', e);
        return {};
    }
}


function getDepartureICAO(routeStr) {
    const tokens = routeStr.trim().split(/\s+/);
    for (const token of tokens) {
        if (/^[A-Z]{4}$/.test(token)) return token;
    }
    return '';
}

// ==========================================
// Server connection
// ==========================================

// Singleton promise lock: Ensures only ONE modal opens even if multiple requests trigger simultaneously
let tokenModalPromise = null;

function promptForTokenModal() {
    if (tokenModalPromise) return tokenModalPromise;

    tokenModalPromise = new Promise((resolve) => {
        const bodyHTML = `
            <div style="display: flex; flex-direction: column; gap: 10px;">
                <label style="font-size: 12px; font-weight: 600; color: var(--dim);">Paste New Skyplan Access Token</label>
                <textarea id="modal-skyplan-token" placeholder='eyJhbGciOi...' 
                    style="width: 100%; height: 120px; padding: 10px; border-radius: 8px; background: var(--input); color: var(--text); border: 1px solid var(--border); font-size: 13px; font-family: monospace; resize: vertical; word-break: break-all; outline: none;"></textarea>
            </div>
        `;

        const finish = (resultToken) => {
            tokenModalPromise = null;
            resolve(resultToken);
        };

        if (typeof createModal === 'function') {
            createModal({
                title: 'Skyplan Token Expired',
                icon: '🔑',
                type: 'info',
                confirmText: 'Save Token',
                cancelText: 'Disregard',
                centered: true,
                compact: true,
                maxWidth: '500px',
                bodyHTML: bodyHTML,
                onConfirm: async () => {
                    const inputElem = document.getElementById('modal-skyplan-token');
                    let rawToken = inputElem ? inputElem.value.trim() : '';

                    // Automatically strip double quotes from beginning/end
                    rawToken = rawToken.replace(/^"+|"+$/g, '').trim();

                    if (rawToken) {
                        localStorage.setItem('skyplan_token', rawToken);
                        const settingInput = document.getElementById('skyplan_token');
                        if (settingInput) settingInput.value = rawToken;
                        if (typeof showToast === 'function') showToast('Skyplan token updated!', 'success');
                        finish(rawToken);
                    } else {
                        finish(null);
                    }
                },
                onCancel: () => {
                    finish(null);
                }
            });
        } else {
            let rawToken = prompt("Skyplan Access Token expired. Please paste new token:");
            if (rawToken) {
                rawToken = rawToken.trim().replace(/^"+|"+$/g, '').trim();
                localStorage.setItem('skyplan_token', rawToken);
                finish(rawToken);
            } else {
                finish(null);
            }
        }
    });

    return tokenModalPromise;
}

window.getValidSkyplanToken = async function() {
    let token = localStorage.getItem('skyplan_token');
    if (token) {
        token = token.trim().replace(/^"+|"+$/g, '').trim();
        localStorage.setItem('skyplan_token', token);
    }

    // 1. Missing Token -> Open Modal directly
    if (!token) {
        return await promptForTokenModal();
    }

    // 2. Invalid JWT Format -> Open Modal directly
    const decoded = typeof decodeJWT === 'function' ? decodeJWT(token) : null;
    if (!decoded || typeof decoded.exp !== 'number') {
        return await promptForTokenModal();
    }

    // 3. Check Expiration (with 5-minute buffer)
    const now = Math.floor(Date.now() / 1000);
    if (decoded.exp <= now + 300) {
        console.warn("Skyplan token expired. Requesting new token...");
        // Bypasses fetch() to avoid ERR_NAME_NOT_RESOLVED browser console noise
        return await promptForTokenModal();
    }

    // 4. Token is valid -> Return token immediately
    return token;
};

window.loadAssignedFlights = async function() {
    const container = document.getElementById('assigned-flights-container');
    if (!container) return;

    const token = await getValidSkyplanToken();
    if (!token) {
        container.innerHTML = '<div style="color: #ff6b6b; text-align: center; padding: 40px; font-family: sans-serif;">⚠️ No Skyplan token found. Please add it in Settings.</div>';
        return;
    }

    container.innerHTML = '<div style="color: white; text-align: center; padding: 40px; font-family: sans-serif;">⏳ Syncing with Skyplan...</div>';

    try {
        // 1. Dynamic Employee ID extraction
        let employeeId = null;
        try {
            const employee = decodeJWT(token);
            employeeId = employee.employeeid;
        } catch (e) {
            console.warn('Failed to decode JWT for employee ID.');
        }

        if (!employeeId) {
            container.innerHTML = '<div style="color: #ff6b6b; text-align: center; padding: 40px; font-family: sans-serif;">⚠️ Could not find Employee ID in your token. Please generate a new token.</div>';
            return;
        }

        // 2. Set Time Window (-3 to +3 days)
        const today = new Date();
        const fromDate = new Date(today);
        fromDate.setDate(today.getDate() - 3);
        const toDate = new Date(today);
        toDate.setDate(today.getDate() + 3);

        const payload = {
            EmployeeID: employeeId,
            From: fromDate.toISOString().slice(0, 10),
            To: toDate.toISOString().slice(0, 10)
        };

        // 3. Fetch Roster
        const resp = await fetch('https://kcskyplanapi.airastana.com/api/v1/crew-roster-flights-details', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`
            },
            body: JSON.stringify(payload)
        });

        if (!resp.ok) {
            if (resp.status === 401) throw new Error("Token expired. Please update it in settings.");
            throw new Error(`API Error: ${resp.status}`);
        }

        const data = await resp.json();
        let flights = data.Flights || [];

        // 4. Filter and Sort
        flights = flights.filter(f => ['KC', 'AYN', 'FS'].includes(f.CarrierCode));
        flights.sort((a, b) => new Date(a.StdLt) - new Date(b.StdLt));

        if (flights.length === 0) {
            container.innerHTML = '<div style="color: white; text-align: center; padding: 40px; font-family: sans-serif;">No assigned flights found in the next 3 days.</div>';
            return;
        }

        console.log("Here is everything Skyplan knows about your first flight:", flights[0]);

        // 5. Build the UI Table
        let html = `
            <table style="width: 100%; border-collapse: collapse; color: white; font-family: sans-serif; text-align: left; font-size: 14px;">
                <thead style="background: #202124; position: sticky; top: 0; z-index: 10;">
                    <tr>
                        <th style="padding: 12px 15px; border-bottom: 1px solid #525659;">Date</th>
                        <th style="padding: 12px 15px; border-bottom: 1px solid #525659;">Flight</th>
                        <th style="padding: 12px 15px; border-bottom: 1px solid #525659;">Routing</th>
                        <th style="padding: 12px 15px; border-bottom: 1px solid #525659;">STD</th>
                        <th style="padding: 12px 15px; border-bottom: 1px solid #525659;">STA</th>
                        <th style="padding: 12px 15px; border-bottom: 1px solid #525659;">Block</th>
                        <th style="padding: 12px 15px; border-bottom: 1px solid #525659;">Aircraft</th>
                        <th style="padding: 12px 15px; border-bottom: 1px solid #525659; text-align: right;">Action</th>
                    </tr>
                </thead>
                <tbody>
        `;

        flights.forEach(f => {
            // Parse Strings safely
            const dateStr = f.StdLt ? f.StdLt.split('T')[0] : 'Unknown';
            const flightNum = `${f.CarrierCode}${f.FlightNumber}`;
            const routing = `${f.DepartureStationIcaoCode || f.DepartureStationCode} ➔ ${f.ArrivalStationIcaoCode || f.ArrivalStationCode}`;
            
            // Times (LT)
            const stdStr = f.StdLt ? f.StdLt.split('T')[1].substring(0, 5) : '--:--';
            const staStr = f.StaLt ? f.StaLt.split('T')[1].substring(0, 5) : '--:--';
            
            // Aircraft 
            const aircraft = f.RegistrationNumber || f.AircraftDescription || 'TBA';

            // Calculate Block Time using DurationMinutes
            let blockTime = '--:--';
            if (f.DurationMinutes) {
                const hrs = Math.floor(f.DurationMinutes / 60);
                const mins = f.DurationMinutes % 60;
                blockTime = `${hrs}h ${mins.toString().padStart(2, '0')}m`;
            } else if (f.Std && f.Sta) {
                // Fallback math just in case DurationMinutes is missing
                const diffMs = new Date(f.Sta) - new Date(f.Std);
                if (diffMs > 0) {
                    const hrs = Math.floor(diffMs / 3600000);
                    const mins = Math.floor((diffMs % 3600000) / 60000);
                    blockTime = `${hrs}h ${mins.toString().padStart(2, '0')}m`;
                }
            }

            // Sync Button now passes f.ID, flightNum, and dateStr
            html += `
                <tr style="border-bottom: 1px solid #525659; transition: background 0.2s;" onmouseover="this.style.background='#4c5155'" onmouseout="this.style.background='transparent'">
                    <td style="padding: 15px;">${dateStr}</td>
                    <td style="padding: 15px; font-weight: bold; color: #4fc3f7; font-size: 15px;">${flightNum}</td>
                    <td style="padding: 15px; letter-spacing: 1px;">${routing}</td>
                    <td style="padding: 15px; font-family: monospace; font-size: 14px;">${stdStr}</td>
                    <td style="padding: 15px; font-family: monospace; font-size: 14px; color: #9aa0a6;">${staStr}</td>
                    <td style="padding: 15px; font-size: 13px; color: #fbbc04;">${blockTime}</td>
                    <td style="padding: 15px; font-size: 13px; color: #b3e5fc;">${aircraft}</td>
                    <td style="padding: 15px; text-align: right;">
                        <button onclick="importOFPFromSkyplan('${f.ID}', '${flightNum}', '${dateStr}', '${f.RegistrationNumber || ''}')" 
                                style="background: #81c995; color: #000; border: none; padding: 6px 12px; border-radius: 4px; font-weight: bold; cursor: pointer;">
                            Activate OFP
                        </button>
                    </td>
                </tr>
            `;
        });

        html += `</tbody></table>`;
        container.innerHTML = html;

    } catch (e) {
        console.error("Schedule fetch failed:", e);
        container.innerHTML = `<div style="color: #ff6b6b; text-align: center; padding: 40px; font-family: sans-serif;">Error: ${e.message}</div>`;
    }
};

window.importOFPFromSkyplan = async function(flightId, flightNum, dateStr, tailNumber) {
    try {
        const token = await getValidSkyplanToken();
        if (!token) {
            return alert("No Skyplan token found. Please add it in settings.");
        }

        if (typeof showToast === 'function') showToast("Downloading OFP from Skyplan...", "info");

        // 1. Fetch the OFP JSON from Skyplan
        const url = `https://kcskyplanapi.airastana.com/api/v1/flights/${flightId}/ofp`;
        const response = await fetch(url, {
            method: 'GET',
            headers: { 'Authorization': `Bearer ${token}` }
        });

        if (!response.ok) throw new Error(`HTTP Error: ${response.status}`);
        
        const data = await response.json();
        
        if (!data.FileContent) {
            throw new Error("No PDF content found for this flight.");
        }

        // 2. Decode the Base64 string into raw binary PDF data
        const binaryString = atob(data.FileContent);
        const bytes = new Uint8Array(binaryString.length);
        for (let i = 0; i < binaryString.length; i++) {
            bytes[i] = binaryString.charCodeAt(i);
        }

        // 3. Force correct filename for parser
        const safeDate = dateStr ? dateStr.replace(/-/g, '') : 'UnknownDate';
        const safeFlight = flightNum ? flightNum.replace(/\s+/g, '') : 'UnknownFlight';
        const fileName = `${safeFlight}_${safeDate}_OFP.pdf`;
        
        const file = new File([bytes], fileName, { type: 'application/pdf' });

        if (typeof showToast === 'function') showToast("OFP Downloaded! Extracting data...", "success");

        // 4. Send to PDF analyzer pipeline
        if (typeof runAnalysis === 'function') {
            await runAnalysis(file, false);
        } else {
            alert("Error: Core PDF analyzer is missing.");
        }

        // 5. Fetch Aircraft ADDs safely using passed tail number or fallback to DOM
        const aircraftReg = (tailNumber && tailNumber !== 'TBA') 
            ? tailNumber 
            : (document.getElementById('view-reg')?.innerText || '').trim();

        if (aircraftReg && aircraftReg !== '-' && aircraftReg !== 'TBA' && typeof window.fetchAircraftDefects === 'function') {
            window.fetchAircraftDefects(aircraftReg);
        }

    } catch (error) {
        console.error("Failed to import OFP:", error);
        alert("Error syncing OFP: " + error.message);
    }
};

})();