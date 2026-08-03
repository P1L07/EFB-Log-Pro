(function() {
// ==========================================
// 1. CONFIGURATION
// ==========================================

    const APP_VERSION = "2.2.1";
    const RELEASE_NOTES = {
        "2.2.1": {
            title: "Release Notes",
            notes: [
                "📋 Updated ATIS and Clearance popups",
                "✍️ Journey log data donwloaded directly from the server",
                "📁 Download OFPs directly from the server",
            ]
        },
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
    const EXPECTED_SW_HASH = 'dd7ebeeb684d9015b8a50e4dba1885cb52e880ffd4601912a23729b702e1f824';
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

    // SET COLUMN VALUES
    const el = (id) => document.getElementById(id);
    function safeSet(id, val) { 
        const e = el(id); 
        if(!e) return;
        
        // 1. If it's an input field, set .value
        if (e.tagName === 'INPUT' || e.tagName === 'SELECT' || e.tagName === 'TEXTAREA') {
            e.value = val || '';
        } 
        // 2. If it's a div/span/label, set .innerText
        else {
            e.innerText = val || ''; 
        }
    }
    
    function safeText(id, val) { 
        const e = el(id); 
        if(e) e.innerText = val || ''; 
    }

    function sanitizeHTML(str) {
        const div = document.createElement('div');
        div.textContent = str;
        return div.innerHTML;
    }

// ==========================================
// 3. INITIALIZATION
// ==========================================

    window.onload = async function() {
        // Show authentication first
        const authenticated = await setupAuthentication();
        
        if (!authenticated) {
            // Block access if not authenticated
            document.body.innerHTML = `
                <div style="
                    display: flex;
                    justify-content: center;
                    align-items: center;
                    height: 100vh;
                    background: var(--background);
                    color: var(--text);
                    text-align: center;
                    padding: 20px;
                ">
                    <div>
                        <h1>🔒 Access Denied</h1>
                        <p>Authentication required to use EFB Log Pro</p>
                        <button onclick="location.reload()" style="
                            margin-top: 20px;
                            padding: 10px 20px;
                            background: var(--accent);
                            color: white;
                            border: none;
                            border-radius: 5px;
                            cursor: pointer;
                        ">
                            Try Again
                        </button>
                    </div>
                </div>
            `;
            return;
        }
        // Use requestIdleCallback for non-critical initialization
        if ('requestIdleCallback' in window) {
            requestIdleCallback(async () => {
                await initializeApp();
                setTimeout(initializeSettings, 2000);
            });
        } else {
            setTimeout(async () => {
                await initializeApp();
                setTimeout(initializeSettings, 2000);
            }, 1000);
        }
    };

    window.clearAtisCanvas = () => clearPad('atis');
    window.clearAtcCanvas = () => clearPad('atc');
    window.clearSignature = () => clearPad('main');

    // Upload multiple OFPs sequentially with progress indicator
    async function uploadMultipleOFPs(files) {
        const modal = document.getElementById('upload-progress-modal');
        const progressBar = document.getElementById('upload-progress-bar');
        const progressText = document.getElementById('upload-progress-text');
        const progressDetail = document.getElementById('upload-progress-detail');
        const closeBtn = document.getElementById('upload-progress-close');

        // Reset and show modal
        progressDetail.innerHTML = '';
        progressBar.style.width = '0%';
        progressText.textContent = `Processing 0 of ${files.length}...`;
        closeBtn.style.display = 'none';
        modal.style.display = 'block';

        let successCount = 0;
        let failCount = 0;

        for (let i = 0; i < files.length; i++) {
            const file = files[i];
            const fileInfo = `${file.name} (${(file.size / 1024).toFixed(1)} KB)`;
            progressText.textContent = `Processing ${i + 1} of ${files.length}: ${file.name}`;
            
            // Add log entry
            const logEntry = document.createElement('div');
            logEntry.style.padding = '4px 0';
            logEntry.style.borderBottom = '1px solid var(--border)';
            logEntry.innerHTML = `⏳ ${fileInfo} – uploading...`;
            progressDetail.appendChild(logEntry);
            progressDetail.scrollTop = progressDetail.scrollHeight;

            try {
                // Call the existing runAnalysis with the file
                await runAnalysis(file, false, { isBatch: true });
                
                // Update log on success
                logEntry.innerHTML = `✅ ${fileInfo} – success`;
                successCount++;
            } catch (error) {
                console.error(`Failed to upload ${file.name}:`, error);
                logEntry.innerHTML = `❌ ${fileInfo} – failed: ${error.message || 'Unknown error'}`;
                failCount++;
            }

            // Update progress bar
            const percent = ((i + 1) / files.length) * 100;
            progressBar.style.width = `${percent}%`;
        }

        // Final summary
        progressText.textContent = `Completed: ${successCount} succeeded, ${failCount} failed`;
        closeBtn.style.display = 'block';
        
        // Refresh OFP Manager table if visible
        if (document.getElementById('section-sectors')?.classList.contains('active')) {
            await renderOFPMangerTable();
        }

        // Close button handler
        closeBtn.onclick = () => {
            modal.style.display = 'none';
        };

        // After the loop
        await getCachedOFPs(true);
        const sectorsBtn = document.querySelector('.nav-btn[data-tab="sectors"], .nav-btn[onclick*="sectors"]');
        if (sectorsBtn) {
            if (typeof window.showTab === 'function') {
                window.showTab('sectors', sectorsBtn);
            } else {
                sectorsBtn.click();
            }
        }

        updateUploadButtonVisibility();
        await updateEmptyStates();

    }

    async function validateOFP(file) {
        try {
            // 1. BASIC CHECKS
            if (!file.type.includes('pdf') && !file.name.toLowerCase().endsWith('.pdf')) {
                alert('Invalid file type. Please upload a PDF file.');
                return false;
            }
            
            if (file.size > 10 * 1024 * 1024) {
                alert('File too large. Maximum size is 10MB.');
                return false;
            }
            
            if (file.size < 100) {
                alert('File too small to be a valid PDF.');
                return false;
            }
            
            // 2. HEADER CHECKS
            const headerBuffer = await file.slice(0, 5).arrayBuffer();
            const header = new Uint8Array(headerBuffer);
            const pdfHeader = new TextEncoder().encode('%PDF-');
            
            for (let i = 0; i < 4; i++) {
                if (header[i] !== pdfHeader[i]) {
                    alert('Invalid file signature. Not a PDF.');
                    return false;
                }
            }
            
            // 3. CONTENT VALIDATION
            const arrayBuffer = await file.arrayBuffer();
            const loadingTask = pdfjsLib.getDocument({ data: arrayBuffer });
            const pdf = await loadingTask.promise;
            
            if (pdf.numPages < 1) {
                alert('PDF has no pages.');
                return false;
            }

            const page = await pdf.getPage(1);
            const textContent = await page.getTextContent();
            const pageText = textContent.items.map(item => item.str).join(' ').toUpperCase();

            if (!pageText.includes('OPERATIONAL FLIGHT PLAN')) {
                alert('This does not look like an Operational Flight Plan.');
                return false;
            }
            
            return true; 

        } catch (e) {
            console.error("PDF Validation Error:", e);
            alert('Error validating OFP: ' + e.message);
            return false;
        }
    }

    // One‑time migration of legacy localStorage state
    async function migrateLegacyState() {
        const MIGRATION_KEY = 'efb_state_migration_v2';
        if (localStorage.getItem(MIGRATION_KEY) === 'done') return;

        const storages = [
            { key: 'efb_log_state', encrypted: true },
            { key: 'efb_log_state_fallback', encrypted: false },
            { key: 'efb_log_state_plain', encrypted: false }
        ];

        for (const { key, encrypted } of storages) {
            const raw = localStorage.getItem(key);
            if (!raw) continue;

            try {
                let state;
                if (encrypted) {
                    try {
                        state = await decryptData(raw);
                    } catch {
                        continue; // skip if can't decrypt
                    }
                } else {
                    state = JSON.parse(raw);
                }

                // Remove obsolete fields
                let modified = false;
                if (state.routeStructure !== undefined) {
                    delete state.routeStructure;
                    modified = true;
                }
                if (state.waypointUserValues !== undefined) {
                    delete state.waypointUserValues;
                    modified = true;
                }

                if (modified) {
                    if (encrypted) {
                        const encryptedNew = await encryptData(state);
                        localStorage.setItem(key, encryptedNew);
                    } else {
                        localStorage.setItem(key, JSON.stringify(state));
                    }
                }
            } catch (e) {
                console.warn(`Failed to migrate ${key}:`, e);
            }
        }

        localStorage.setItem(MIGRATION_KEY, 'done');
    }

    async function initializeApp() {
        // Debugging if IndexedDB is working
        const hasPdf = await checkPdfInDB();
        // PDF.js worker setup
        if (typeof pdfjsLib !== 'undefined') {
            // Set worker source synchronously – no need to wait for script load
            pdfjsLib.GlobalWorkerOptions.workerSrc = './pdf.worker.min.js';
            // Optional: still load with integrity for future use, but workerSrc is already set
            const WORKER_HASH = 'sha384-cdzss87ZwpiG252tPQexupMwS1W1lTzzgy/UlNUHXW6h8aaJpBizRQk9j8Vj3zw9';
            const workerScript = document.createElement('script');
            workerScript.src = './pdf.worker.min.js';
            workerScript.integrity = WORKER_HASH;
            workerScript.crossOrigin = 'anonymous';
            document.head.appendChild(workerScript);
        }

        addTimeInputMasks();

        // OFP Upload
        const ofpFileInput = el('ofp-file-in');
        if (ofpFileInput) {
            ofpFileInput.onchange = async function(e) {
                const files = Array.from(e.target.files);
                if (files.length === 0) return;
                
                if (files.length === 1) {
                    // Single file – use original flow
                    await runAnalysis(files[0], false);
                } else {
                    // Multiple files – use batch upload
                    await uploadMultipleOFPs(files);
                }
                // Clear the input so same files can be uploaded again
                e.target.value = '';
            };
        }
        
        // Restore journey log template from IndexedDB if available
        try {
            const templateBlob = await loadJourneyTemplateFromDB();
            if (templateBlob) {
                journeyLogTemplateBytes = await templateBlob.arrayBuffer();
            } else {
            }
        } catch (e) {
            alert('Failed to load journey template from DB', e);
            // If corrupted, delete it
            await deleteJourneyTemplateFromDB().catch(() => {});
        }
        
        // REAL-TIME CALCULATION LISTENERS (debounced)
        ['j-out','j-off','j-on','j-in'].forEach(id => {
            const e = el(id);
            if (e) e.addEventListener('input', debounce(calculateTripTimeForJourneyLog, 300))
        });
            
        ['j-init', 'j-uplift-w', 'j-calc-ramp', 'j-act-ramp', 'j-shut', 'j-burn', 'j-uplift-vol', 'j-disc', 'j-slip', 'j-slip-2'].forEach(id => {
            const e = el(id);
            if (e) e.addEventListener('input', debounce(calculateFuelForJourneyLog, 300));
        });

        ['j-adl', 'j-chl', 'j-inf', 'j-cargo', 'j-mail', 'j-bag', 'j-zfw'].forEach(id => {
            const e = el(id);
        });

        const ofpAtdInput = el('ofp-atd-in');
        if (ofpAtdInput) {
            // Use debouncedFullRecalc instead of a custom debounce
            ofpAtdInput.addEventListener('input', debouncedFullRecalc);
        }
            
        const extraKgInput = el('front-extra-kg');
        if (extraKgInput) {
            extraKgInput.addEventListener('input', debounce(() => {
                calculatePICBlock();
                updateFlightLogTablesIncremental();
            }, 300));
        }

        // OFFLINE AUTO‑LOAD LOGIC
        try {
            const activeOFP = await getActiveOFPFromDB();
            if (activeOFP && activeOFP.data) {
                setOFPLoadedState(true);
                window.ofpPdfBytes = await activeOFP.data.arrayBuffer();
                window.originalFileName = activeOFP.fileName || "Logged_OFP.pdf";

                // Parse the OFP (populates waypoints, alternateWaypoints, etc.)
                await runAnalysis(activeOFP.data, true);

                // Load user data from separate store
                const userData = await loadOFPUserData(activeOFP.id);
                if (userData) {
                    // Restore waypoint inputs
                    if (userData.userWaypoints && Array.isArray(userData.userWaypoints)) {
                        userData.userWaypoints.forEach((data, i) => {
                            if (i < waypoints.length) {
                                if (data.ato) safeSet(`o-a-${i}`, data.ato);
                                if (data.fuel) safeSet(`o-f-${i}`, data.fuel);
                                if (data.notes) safeSet(`o-n-${i}`, data.notes);
                                if (data.agl) safeSet(`o-agl-${i}`, data.agl);
                            }
                        });
                        runFlightLogCalculations();
                        syncLastWaypoint();
                    }

                    // Restore persistent text inputs (excluding drawings)
                    if (userData.userInputs && typeof userData.userInputs === 'object') {
                        Object.keys(userData.userInputs).forEach(id => {
                            const val = userData.userInputs[id];
                            // Skip drawings – they will be handled by restorePadDrawing
                            if (id === 'signature' || id === 'front-atis-drawing' || id === 'front-atc-drawing') return;
                            if (val !== undefined && val !== null) {
                                safeSet(id, val);
                            }
                        });
                    }

                }

                // Restore other non‑OFP state (dailyLegs, dutyStartTime, etc.) from localStorage
                await loadState();

            } else {
                // Fallback to old single‑OFP store and migrate
                const savedPdfBlob = await loadPdfFromDB();
                if (savedPdfBlob && savedPdfBlob.size > 0) {
                    // ... (migration code) ...
                } else {
                    loadState();
                    setOFPLoadedState(false);
                }
            }
        } catch (e) {
            console.error("Auto‑load error:", e);
            loadState();
            setOFPLoadedState(false);
        }

        await migrateLegacyState();

        // Clean up orphaned order entries (if any)
        try {
            const db = await getDB();
            if (db.objectStoreNames.contains('ofp_orders') && db.objectStoreNames.contains('ofps')) {
                const tx = db.transaction(["ofps", "ofp_orders"], "readwrite");
                const ofpsStore = tx.objectStore("ofps");
                const ordersStore = tx.objectStore("ofp_orders");
                
                // Get all orders
                const orders = await new Promise((resolve, reject) => {
                    const req = ordersStore.getAll();
                    req.onsuccess = () => resolve(req.result);
                    req.onerror = (e) => reject(e);
                });
                
                if (!Array.isArray(orders)) {
                    console.warn('Orders is not an array, skipping cleanup');
                    return;
                }
                
                for (let order of orders) {
                    const ofp = await new Promise((resolve) => {
                        const req = ofpsStore.get(order.id);
                        req.onsuccess = () => resolve(req.result);
                    });
                    if (!ofp) {
                        ordersStore.delete(order.id);
                    }
                }
                
                await new Promise((resolve) => {
                    tx.oncomplete = resolve;
                });
            }
        } catch (e) {
            console.warn('Order cleanup failed', e);
        }

        // Check for Active OFP and set Sectors tab active
        const allOFPs = await getCachedOFPs();
        if (allOFPs.length > 0 && !localStorage.getItem('activeOFPId')) {
            setOFPLoadedState(false);  // Ensure no OFP is loaded
            // Switch to Sectors tab
            const sectorsBtn = document.querySelector('.nav-btn[data-tab="sectors"], .nav-btn[onclick*="sectors"]');
            if (sectorsBtn) {
                sectorsBtn.click();  // This will call the existing tab switching logic
            }
        }

        // Add event listener for file input change
        const fileInput = document.getElementById('ofp-file-in');
        if (fileInput) {
            fileInput.addEventListener('change', function() {
                setOFPLoadedState(true);
            });
        }
        
        // Initial floating button update
        updateFloatingButtonVisibility();
        setupWaypointDelegation()
    }

    async function getOFPById(id) {
        const db = await getDB();
        return new Promise((resolve, reject) => {
            const tx = db.transaction("ofps", "readonly");
            const store = tx.objectStore("ofps");
            const request = store.get(Number(id));
            request.onsuccess = () => {
                const ofp = request.result;
                if (!ofp) {
                    reject(new Error(`OFP with id ${id} not found`));
                } else {
                    resolve(ofp);
                }
            };
            request.onerror = (e) => reject(e.target.error);
        });
    }

    function clearOFPInputs() {
        // 1. Clear all persistent user inputs (Flight Summary & Weights)
        PERSISTENT_INPUT_IDS.forEach(id => safeSet(id, ''));
            
        // 2. Clear Time / ATD Input
        safeSet('ofp-atd-in', '');
            
        // 3. Reset internal calculated variables
        waypoints = []; 
        alternateWaypoints = []; 
        fuelData = []; 
        blockFuelValue = 0;
            
        // 4. Clear the UI tables immediately
        const tables = ['ofp-tbody', 'altn-tbody', 'fuel-tbody'];
        tables.forEach(id => {
            const tb = el(id);
            if(tb) tb.innerHTML = '';
        });
        
        // 5. Reset 'Flight Summary' & 'Weights & Fuel' Tab Text placeholders
        ['view-min-block', 'view-pic-block', 'view-mtow', 'view-mlw', 'view-mzfw', 'view-mpld', 'view-fcap', 'view-dow', 'view-tow', 'view-lw', 'view-zfw'].forEach(id => safeText(id, '-'));
        ['view-flt', 'view-reg', 'view-date','view-std-text', 'view-sta-text', 'view-dep', 'view-dest', 'view-altn', 'view-altn2', 'view-dest-route', 'view-altn-route', 'view-ci','view-etd-text', 'view-eta-text', 'view-era','view-crz-wind-temp', 'view-seats-stn-jmp'].forEach(id => safeText(id, '-'));
        

        if (pads.atis.pad) {
            pads.atis.pad.clear();
        }
        if (pads.atc.pad) {
            pads.atc.pad.clear();
        }
        
        // Reset DOM caches to prevent stale references
        waypointATOCache = [];
        alternateATOCache = [];
        waypointFuelCache = [];
        takeoffFuelInput = null;

        // Reset the incremental update cache to force a full redraw next time
        waypointTableCache = { waypoints: [], alternateWaypoints: [], lastUpdate: 0 };
    }

    window.deleteOFP = async function(id) {
        const confirmed = await showConfirmDialog(
            'Delete OFP',
            'Are you sure you want to delete this OFP? This action cannot be undone.',
            'Delete',
            'Cancel',
            'error'
        );
        if (!confirmed) return;
        
        try {
            const activeId = localStorage.getItem('activeOFPId');
            const wasActive = (activeId && Number(activeId) === id);
            
            await deleteOFPFromDB(id);
            await getCachedOFPs(true);
            
            if (wasActive) {
                // Remove active ID from storage
                localStorage.removeItem('activeOFPId');
                
                // Try to find the most recent remaining OFP and activate it
                const remainingOFPs = await getCachedOFPs();
                if (remainingOFPs.length > 0) {
                    const newest = remainingOFPs[0]; // already sorted by uploadTime desc
                    await activateOFP(newest.id);
                } else {
                    // No OFPs left – clear app state
                    setOFPLoadedState(false);
                    clearOFPInputs();
                    window.ofpPdfBytes = null;
                }
            }
            await renumberOFPOrders();
            await renderOFPMangerTable();
            showToast("OFP deleted", 'success');
            updateUploadButtonVisibility();
        } catch (error) {
            console.error("Error deleting OFP:", error);
            showToast("Failed to delete OFP", 'error');
        }
    };

    window.clearAllOFPs = async function() {
        const confirmed = await showConfirmDialog(
            'Clear All OFPs',
            'This will delete ALL stored OFPs. Continue?',
            'Clear All',
            'Cancel',
            'error'
        );
        if (!confirmed) return;
        try {
            await clearAllOFPsFromDB();
            await getCachedOFPs(true);
            setOFPLoadedState(false);
            clearOFPInputs();
            await renderOFPMangerTable();
            showToast("All OFPs cleared", 'success');
        } catch (error) {
            console.error("Error clearing OFPs:", error);
            showToast("Failed to clear OFPs", 'error');
        }
    };

    window.activateOFP = async function(id, switchTab = true) {
        if (isActivating) {
            showToast('Activation in progress, please wait...', 'info');
            return;
        }
        isActivating = true;

        try {
            const numericId = Number(id);
            if (isNaN(numericId)) throw new Error('Invalid OFP ID');

            // Refresh cache
            await getCachedOFPs(true);

            // Retrieve the OFP with retries
            let ofpToActivate = null;
            const maxRetries = 3;
            for (let attempt = 1; attempt <= maxRetries; attempt++) {
                try {
                    ofpToActivate = await getOFPById(numericId);
                    break;
                } catch (err) {
                    console.warn(`Attempt ${attempt} failed: ${err.message}`);
                    if (attempt === maxRetries) {
                        const allOFPs = await getCachedOFPs();
                        const found = allOFPs.find(o => o.id === numericId);
                        if (found) {
                            ofpToActivate = found;
                            break;
                        } else {
                            throw new Error(`OFP with id ${numericId} not found after ${maxRetries} attempts`);
                        }
                    }
                    await new Promise(resolve => setTimeout(resolve, 200));
                }
            }

            if (ofpToActivate.finalized) {
                return;
            }

            // Set active ID in localStorage only
            localStorage.setItem('activeOFPId', numericId);

            // Retrieve the full active OFP with retries
            let ofp = null;
            for (let attempt = 1; attempt <= maxRetries; attempt++) {
                ofp = await getOFPById(numericId);
                if (ofp && ofp.data) {
                    break;
                }
                if (attempt === maxRetries) {
                    throw new Error('Failed to load OFP data after multiple attempts');
                }
                alert(`Active OFP not ready, retry ${attempt} in 200ms...`);
                await new Promise(resolve => setTimeout(resolve, 200));
            }

            // Clear UI
            if (typeof clearOFPInputs === 'function') clearOFPInputs();

            setOFPLoadedState(true);
            window.ofpPdfBytes = await ofp.data.arrayBuffer();
            window.originalFileName = ofp.fileName || "Logged_OFP.pdf";

            await runAnalysis(ofp.data, true);

            // Load user data from new store
            const userData = await loadOFPUserData(numericId);
            if (userData) {
                // Restore waypoints
                if (userData.userWaypoints && Array.isArray(userData.userWaypoints)) {
                    userData.userWaypoints.forEach((data, i) => {
                        if (i < waypoints.length) {
                            if (data.ato) safeSet(`o-a-${i}`, data.ato);
                            if (data.fuel) safeSet(`o-f-${i}`, data.fuel);
                            if (data.notes) safeSet(`o-n-${i}`, data.notes);
                            if (data.agl) safeSet(`o-agl-${i}`, data.agl);
                        }
                    });
                    runFlightLogCalculations();
                    syncLastWaypoint();
                }

                // Restore inputs and drawings
                if (userData.userInputs && typeof userData.userInputs === 'object') {
                    Object.keys(userData.userInputs).forEach(id => {
                        const val = userData.userInputs[id];
                        if (id === 'signature' || id === 'front-atis-drawing' || id === 'front-atc-drawing') {
                            // Handle later after pads are ready
                        } else {
                            safeSet(id, val);
                        }
                    });
                    // Restore drawings after a short delay (pads may not be ready)
                    setTimeout(() => {
                        if (userData.userInputs.signature && pads.main.pad) {
                            pads.main.pad.fromDataURL(userData.userInputs.signature);
                        }
                        if (userData.userInputs['front-atis-drawing'] && pads.atis.pad) {
                            pads.atis.pad.fromDataURL(userData.userInputs['front-atis-drawing']);
                        }
                        if (userData.userInputs['front-atc-drawing'] && pads.atc.pad) {
                            pads.atc.pad.fromDataURL(userData.userInputs['front-atc-drawing']);
                        }
                    }, 200);
                }
            }

            // MIGRATION: If the OFP still has old userWaypoints/userInputs in the main record, move them to new store and remove from main
            if (ofp.userWaypoints || ofp.userInputs) {
                const oldWaypoints = ofp.userWaypoints || [];
                const oldInputs = ofp.userInputs || {};
                await saveOFPUserData(numericId, oldWaypoints, oldInputs);
                // Remove from main record
                await updateOFP(numericId, { userWaypoints: undefined, userInputs: undefined });
            }

            await renderOFPMangerTable();

            if (switchTab) {
                const summaryBtn = document.querySelector('.nav-btn[data-tab="summary"], .nav-btn[onclick*="summary"]');
                if (summaryBtn) {
                    if (typeof window.showTab === 'function') {
                        window.showTab('summary', summaryBtn);
                    } else {
                        summaryBtn.click();
                    }
                }
            }

            showToast(`Activated: ${ofp.flight || 'OFP'}`, 'success');
            updateUploadButtonVisibility();
            await updateEmptyStates();

        } catch (error) {
            showToast(`Failed to activate OFP: ${error.message}`, 'error');
        } finally {
            isActivating = false;
        }
    };

    // Shared manual upload preparation
    async function prepareForManualUpload() {
        if (typeof clearOFPInputs === 'function') clearOFPInputs();
        const legForm = document.getElementById('leg-input-form');
        if (legForm) legForm.style.display = 'block';
    }

    // Handle replacement of an existing OFP
    async function handleReplacement(existingOFP, blob, metadata, previouslyActiveId, isBatch) {
        const wasActive = existingOFP.isActive; // This field is no longer used but may exist in old records
        const originalOrder = existingOFP.order;
        const replacedId = existingOFP.id;

        const updatedData = {
            data: blob,
            fileName: blob.name || "Logged_OFP.pdf",
            uploadTime: new Date().toISOString(),
            flight: metadata.flight,
            date: metadata.date,
            departure: metadata.departure,
            destination: metadata.destination,
            tripTime: metadata.tripTime,
            maxSR: metadata.maxSR,
            requestNumber: metadata.requestNumber,
            finalized: false,
            loggedPdfData: null,
            order: originalOrder
        };

        if (isBatch) {
            // Batch mode: never activate the replacement, and if it was active, clear active ID.
            updatedData.isActive = false;
            await updateOFP(replacedId, updatedData);
            if (wasActive) {
                localStorage.removeItem('activeOFPId');
            }
            showToast(`OFP updated: ${metadata.flight} (inactive)`, 'success');
            setOFPLoadedState(false);
        } else {
            // Normal (single) upload: preserve active state
            updatedData.isActive = wasActive;
            await updateOFP(replacedId, updatedData);
            if (wasActive) {
                setOFPLoadedState(true);
                showToast(`OFP updated: ${metadata.flight} (active)`, 'success');
            } else {
                setOFPLoadedState(false);
                showToast(`OFP updated: ${metadata.flight} (inactive)`, 'success');
            }
        }

        await getCachedOFPs(true);

        // After a single replacement, if the replaced OFP was not active, restore the previously active one.
        if (!wasActive && !isBatch && previouslyActiveId && previouslyActiveId !== String(replacedId)) {
            await activateOFP(previouslyActiveId, false);
        }
    }

    // Handle brand‑new OFP
    async function handleNewOFP(blob, metadata, isBatch) {
        const currentActiveId = localStorage.getItem('activeOFPId');
        // In batch mode, never auto‑activate, even if no active OFP exists.
        const shouldActivate = !currentActiveId && !isBatch;

        const ofpId = await saveOFPToDB(blob, metadata, shouldActivate);
        await getCachedOFPs(true);

        if (shouldActivate) {
            setOFPLoadedState(true);
            showToast(`OFP saved & activated: ${metadata.flight}`, 'success');
        } else {
            setOFPLoadedState(false);
            if (currentActiveId) {
                await activateOFP(currentActiveId, false);
                showToast(`OFP saved (inactive): ${metadata.flight}`, 'success');
            } else {
                showToast(`OFP saved: ${metadata.flight}`, 'success');
            }
        }
    }

    // Analyze OFP (parses PDF and populates waypoints etc.)
    async function runAnalysis(fileOrEvent, isAutoLoad = false) {
        // Determine if this is a batch upload (multiple files) by checking if the progress modal is visible.
        const isBatchUpload = !isAutoLoad && 
            document.getElementById('upload-progress-modal')?.style.display === 'block';
        let blob = null;

        // 1. Determine source
        if (fileOrEvent instanceof Blob) {
            blob = fileOrEvent;
        } else {
            const fileInput = document.getElementById('ofp-file-in');
            if (fileInput && fileInput.files.length > 0) {
                blob = fileInput.files[0];
                try {
                    const isValid = await validateOFP(blob);
                    if (!isValid) {
                        fileInput.value = '';
                        setOFPLoadedState(false);
                        return;
                    }
                } catch (error) {
                    alert(`Invalid PDF: ${error.message}`);
                    fileInput.value = '';
                    setOFPLoadedState(false);
                    return;
                }
                localStorage.removeItem('efb_log_state');
            }
        }
        if (!blob) return;

        // 2. Common preparation (memory + preview)
        window.ofpPdfBytes = await blob.arrayBuffer();
        window.originalFileName = blob.name || "Logged_OFP.pdf";
        renderPDFPreview(window.ofpPdfBytes).catch(console.error);

        // 3. Manual upload: clear UI, show leg form (only for single manual uploads, not batch)
        if (!isAutoLoad && !isBatchUpload) {
            await prepareForManualUpload();
        }

        // 4. PARSE PDF
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

        // 5. Save to INDEXEDDB (manual uploads only)
        if (!isAutoLoad) {
            const metadata = parseResult.metadata;
            const { flight, date } = metadata;
            const previouslyActiveId = localStorage.getItem('activeOFPId');
            const existingOFP = await findOFPByFlightAndDate(flight, date);

            try {
                let newlySavedId = null;

                if (existingOFP) {
                    // Pass isBatchUpload to the handler
                    await handleReplacement(existingOFP, blob, metadata, previouslyActiveId, isBatchUpload);
                    newlySavedId = existingOFP.id;
                } else {
                    // Pass isBatchUpload to the handler
                    await handleNewOFP(blob, metadata, isBatchUpload);
                    
                    // Fetch the newly created record to get its generated ID
                    const freshlySaved = await findOFPByFlightAndDate(flight, date);
                    if (freshlySaved) newlySavedId = freshlySaved.id;
                }

                // --- NEW: AUTO-ACTIVATE THE UPLOADED OFP ---
                if (newlySavedId && !isBatchUpload) {
                    // 1. Tell the app this is the active flight
                    localStorage.setItem('activeOFPId', newlySavedId);
                    
                    // 2. Automatically switch to the Summary tab
                    const summaryBtn = document.querySelector('.nav-btn[data-tab="summary"], .nav-btn[onclick*="summary"]');
                    if (summaryBtn) {
                        if (typeof window.showTab === 'function') window.showTab('summary', summaryBtn);
                        else summaryBtn.click();
                    }
                    
                    // 3. Show success message
                    showToast(`Activated: ${flight}`, 'success');
                    if (typeof updateUploadButtonVisibility === 'function') updateUploadButtonVisibility();
                }
                // ------------------------------------------

                // After replacement or new OFP, refresh OFP manager if sectors tab is active
                if (!isBatchUpload && document.querySelector('.tool-section.active')?.id === 'section-sectors') {
                    await renderOFPMangerTable();
                }
            } catch (error) {
                // Emergency fallback – something went wrong in the handlers
                console.error("Unexpected error during save:", error);
                const emergencyResult = await emergencySaveOFP(blob, metadata, existingOFP || null);
                
                // Try to activate even on emergency save
                if (emergencyResult.ofpsRecordCreated && !isBatchUpload) {
                    const emergencySaved = await findOFPByFlightAndDate(flight, date);
                    if (emergencySaved) localStorage.setItem('activeOFPId', emergencySaved.id);
                }

                let toastMessage = existingOFP
                    ? "OFP replaced (emergency mode)"
                    : "OFP saved (emergency mode)";
                if (!emergencyResult.pdfSaved) toastMessage += " – PDF not saved";
                if (!emergencyResult.ofpsRecordCreated) toastMessage += " – record not created";
                toastMessage += ")";
                showToast(toastMessage, emergencyResult.ofpsRecordCreated ? 'warning' : 'error');
                setOFPLoadedState(true);
            }
        }

        // After saving, reload user data for the currently active OFP
        if (!isAutoLoad && !isBatchUpload) {
            const activeId = localStorage.getItem('activeOFPId');
            if (activeId) {
                const userData = await loadOFPUserData(Number(activeId));
                if (userData) {
                    // Restore waypoint inputs
                    if (userData.userWaypoints && Array.isArray(userData.userWaypoints)) {
                        userData.userWaypoints.forEach((data, i) => {
                            if (i < waypoints.length) {
                                if (data.ato) safeSet(`o-a-${i}`, data.ato);
                                if (data.fuel) safeSet(`o-f-${i}`, data.fuel);
                                if (data.notes) safeSet(`o-n-${i}`, data.notes);
                                if (data.agl) safeSet(`o-agl-${i}`, data.agl);
                            }
                        });
                        runFlightLogCalculations();
                        syncLastWaypoint();
                    }
                    // Restore persistent text inputs (excluding drawings)
                    if (userData.userInputs && typeof userData.userInputs === 'object') {
                        Object.keys(userData.userInputs).forEach(id => {
                            const val = userData.userInputs[id];
                            if (id === 'signature' || id === 'front-atis-drawing' || id === 'front-atc-drawing') return;
                            if (val !== undefined && val !== null) {
                                safeSet(id, val);
                            }
                        });
                    }
                }
            }
        }

        // After manual upload, force a full redraw of flight log tables (only for non‑batch)
        if (!isAutoLoad && !isBatchUpload) {
            renderFlightLogTables(true);
        }

        // 6. Log success event
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

        // 7. Handle state (auto‑save)
        if (!isAutoLoad) {
            saveState();
        }
    }

    // Event delegation for Flight Log tables
    function setupWaypointDelegation() {
        const ofpTbody = document.getElementById('ofp-tbody');
        const altnTbody = document.getElementById('altn-tbody');

        if (ofpTbody) {
            ofpTbody.addEventListener('input', handleWaypointInput);
            ofpTbody.addEventListener('change', handleWaypointChange); // for blur-like behavior
        }
        if (altnTbody) {
            altnTbody.addEventListener('input', handleWaypointInput);
            altnTbody.addEventListener('change', handleWaypointChange);
        }
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
        if (currentFlight && dailyLegs.length > 0) {
            journeyOK = dailyLegs.some(leg => leg['j-flt'] === currentFlight);
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
                `<div class="checklist-item"><span>${sanitizeHTML(c.label)}</span><span class="${c.valid?'status-ok':'status-fail'}">${c.valid?'✔':'✖'}</span></div>`
            ).join('');
            
            const valid = checks.every(c => c.valid);
            const sendBtn = el('btn-send-ofp');
            if (sendBtn) {
                sendBtn.disabled = !valid;
            }
        }
    };

    window.validateAltimeter = function(el) {
        const match = el.value.match(/^-?[0-9]{0,4}/);
        if (match) el.value = match[0];
    };

    function validateTimeInputs(timeStr, fieldName = '') {
        if (!timeStr) return { valid: true, value: '' };
        
        // Check if this is a time field or number field
        const isTimeField = fieldName.includes('Time') || 
                        fieldName.includes('ATD') || 
                        fieldName.includes('ATO') ||
                        fieldName.includes('STD') ||
                        fieldName.includes('STA') ||
                        fieldName.includes('DUTY') ||
                        fieldName.includes('FDP');
        
        // If it's NOT a time field (e.g., fuel/weight), return as-is
        if (!isTimeField) {
            return { valid: true, value: timeStr };
        }
        
        // Accept HH:MM or HHMM format
        let cleanTime = timeStr.replace(/[^0-9:]/g, '');
        
        // Convert HHMM to HH:MM
        if (cleanTime.length === 4 && !cleanTime.includes(':')) {
            cleanTime = cleanTime.substring(0, 2) + ':' + cleanTime.substring(2, 4);
        }
        
        // Validate format
        const timeRegex = /^([01]?[0-9]|2[0-3]):?([0-5][0-9])$/;
        if (!timeRegex.test(cleanTime.replace(':', ''))) {
            throw new Error(`Invalid time format${fieldName ? ' for ' + fieldName : ''}. Use HH:MM (00:00-23:59)`);
        }
        
        // Ensure colon format
        if (!cleanTime.includes(':')) {
            cleanTime = cleanTime.substring(0, 2) + ':' + cleanTime.substring(2, 4);
        }
        
        const [hours, minutes] = cleanTime.split(':').map(Number);
        
        // Validate realistic times
        if (fieldName.includes('STD') || fieldName.includes('STA')) {
            if (hours > 23 || minutes > 59) {
                throw new Error(`${fieldName} time must be between 00:00 and 23:59`);
            }
        }
        
        // For flight times, allow up to 48 hours for multi-day ops
        if (fieldName.includes('DUTY') || fieldName.includes('FDP')) {
            if (hours > 48) {
                throw new Error(`${fieldName} cannot exceed 48 hours`);
            }
        }
        
        return { valid: true, value: cleanTime };
    }

    function addTimeInputMasks() {
        // Create a Set to store unique time input elements
        const timeElements = new Set();
        
        // 1. Add all inputs with type="time"
        document.querySelectorAll('input[type="time"]').forEach(el => {
            timeElements.add(el);
        });
        
        // 2. Add specific journey log time inputs
        const journeyTimeIds = [
            'j-out', 'j-off', 'j-on', 'j-in', 
            'j-night', 'j-night-calc', 
            'j-duty-start', 'j-cc-duty-start', 'j-max-fdp',
            'j-std'
        ];
        
        journeyTimeIds.forEach(id => {
            const el = document.getElementById(id);
            if (el) timeElements.add(el);
        });
        
        // 3. Add waypoint time inputs (flight log)
        // Generate IDs for a reasonable number of waypoints (e.g., 20)
        for (let i = 0; i < 20; i++) {
            const oEl = document.getElementById(`o-a-${i}`);
            const aEl = document.getElementById(`a-a-${i}`);
            if (oEl) timeElements.add(oEl);
            if (aEl) timeElements.add(aEl);
        }
        
        // Now apply the time mask to all collected elements
        timeElements.forEach(input => {
            // Add placeholder
            if (!input.placeholder) {
                input.placeholder = 'HH:MM';
            }
            
            // Add pattern for mobile keyboards
            input.pattern = '[0-9]{2}:[0-9]{2}';
            input.inputMode = 'numeric';
            
            // Auto-format on input
            input.addEventListener('input', function(e) {
                let value = e.target.value.replace(/[^0-9]/g, '');
                
                if (value.length > 4) {
                    value = value.substring(0, 4);
                }
                
                if (value.length >= 3) {
                    value = value.substring(0, 2) + ':' + value.substring(2);
                }
                
                e.target.value = value;
            });
        });
    }

    // Handle input events 
    function handleWaypointInput(e) {
        const target = e.target;
        const id = target.id;
        if (!id) return;

        // ATO input
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
            debouncedSave(); // auto-save
        }

        // Fuel input
        else if (id.startsWith('o-f-') || id.startsWith('a-f-')) {
            const [prefix, , idx] = id.split('-');
            const index = parseInt(idx, 10);
            const isTO = (index === 0 && prefix === 'o');
            
            if (isTO) {
                runFlightLogCalculations();
                debouncedSyncLastWaypoint();
            } else {
                debouncedSyncLastWaypoint();
            }
            debouncedSave();
        }

        // Notes input
        else if (id.startsWith('o-n-') || id.startsWith('a-n-')) {
            debouncedSave();
        }

        // Actual FL input
        else if (id.startsWith('o-agl-') || id.startsWith('a-agl-')) {
            debouncedUpdateCruiseLevel();
            debouncedSave();
        }
    }

    // Handle change events 
    function handleWaypointChange(e) {
        const target = e.target;
        const id = target.id;
        if (!id) return;

        // Validate ATO on blur
        if (id.startsWith('o-a-') || id.startsWith('a-a-')) {
            try {
                const validated = validateTimeInputs(target.value, 'Waypoint Time');
                target.value = validated.value;
            } catch (error) {
                alert(error.message);
                target.value = '';
            }
        }
    }

// ==========================================
// 5. DATA EXTRACTION FROM OFP
// ==========================================

    function extractMetadataFromUI() {
        // Trip Time
        let tripTime = '';
        const tripEntry = fuelData.find(item => item.name === "TRIP");
        if (tripEntry && tripEntry.time) {
            tripTime = tripEntry.time;
            if (tripTime.includes('.')) tripTime = tripTime.replace('.', ':');
        }
        // Fallback: read from rendered fuel table
        if (!tripTime) {
            const fuelRows = document.querySelectorAll('#fuel-tbody tr');
            fuelRows.forEach(row => {
                const cells = row.querySelectorAll('td');
                if (cells.length >= 2 && cells[0].innerText === 'TRIP') {
                    tripTime = cells[1].innerText;
                }
            });
        }

        // Max SR
        let maxSR = '';
        const crzWindTempEl = document.getElementById('view-crz-wind-temp');
        if (crzWindTempEl) {
            const text = crzWindTempEl.innerText || crzWindTempEl.textContent;
            const match = text?.match(/MAX SR\s+(\d{1,2})/i);
            if (match) maxSR = match[1];
        }

        // Basic flight info
        const flight = document.getElementById('view-flt')?.innerText || 'N/A';
        const date = document.getElementById('view-date')?.innerText || 'N/A';
        const dep = document.getElementById('view-dep')?.innerText || 'N/A';
        const dest = document.getElementById('view-dest')?.innerText || 'N/A';

        return { flight, date, dep, dest, tripTime, maxSR };
    }

    function extractMainPageCoordinates(items) {
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

    function extractFuelData(text) {
        fuelData = []; blockFuelValue = 0;
        
        // Create a clean text version for pattern matching
        const cleanText = text.replace(/\n/g, ' ').replace(/\s+/g, ' ');
        
        const patterns = [
            // ALTN: ALTN LTAC 00.47 2003
            { name: "ALTN", regex: /ALTN\s+([A-Z]{3,4})\s+([\d.]+)\s+(\d+)/ },
            
            // FINAL RESERVE: FINAL RESERVE 00.30 1095
            { name: "FINAL RESERVE", regex: /FINAL\s+RESERVE\s+([\d.]+)\s+(\d+)/ },
            
            // MIN DIVERSION: MIN DIVERSION 01.17 3098
            { name: "MIN DIVERSION", regex: /MIN\s+DIVERSION\s+([\d.]+)\s+(\d+)/ },
            
            // CONTINGENCY: CONTINGENCY 3% ERA 00.11 423 or CONTINGENCY 5% 00.10 200
            { name: "CONTINGENCY", regex: /CONTINGENCY\s+\d+%\s*(?:ERA)?\s+([\d.]+)\s+(\d+)/ },
            
            // MIN ADDITIONAL: MIN ADDITIONAL 00.00 0
            { name: "MIN ADDITIONAL", regex: /MIN\s+ADDITIONAL\s+([\d.]+)\s+(\d+)/ },
            
            // TOTAL RESERVE: TOTAL RESERVE 01.28 3521
            { name: "TOTAL RESERVE", regex: /TOTAL\s+RESERVE\s+([\d.]+)\s+(\d+)/ },
            
            // TRIP: TRIP 05.27 14114
            { name: "TRIP", regex: /TRIP\s+([\d.]+)\s+(\d+)/ },
            
            // ENDURANCE: ENDURANCE 06.55 17635
            { name: "ENDURANCE", regex: /ENDURANCE\s+([\d.]+)\s+(\d+)/ },
            
            // TAXI: TAXI 227
            { name: "TAXI", regex: /TAXI\s+(\d+)/ },
            
            // MINIMUM BLOCK: MINIMUM BLOCK 17862
            { name: "MINIMUM BLOCK", regex: /MINIMUM\s+BLOCK\s+(\d+)/ },
            
            // EXTRA: EXTRA 00.00 0
            { name: "EXTRA", regex: /EXTRA\s+([\d.]+)\s+(\d+)/ },
            
            // TANKERING: TANKERING 03.27 8162
            { name: "TANKERING", regex: /TANKERING\s+([\d.]+)\s+(\d+)/ },
            
            // BLOCK FUEL: BLOCK FUEL 10.44 26024
            { name: "BLOCK FUEL", regex: /BLOCK\s+FUEL\s+([\d.]+)\s+(\d+)/ }
        ];
        
        // First pass with original patterns
        patterns.forEach(p => {
            const m = text.match(p.regex);
            if (m) {
                
                if (p.name === "TAXI") {
                    fuelData.push({ name: p.name, time: "-", fuel: m[1], remarks: "" });
                } else if (p.name === "MINIMUM BLOCK") {
                    safeText('view-min-block', m[1] + " kg");
                } else if (p.name === "ALTN") {
                    fuelData.push({ name: p.name, time: m[2], fuel: m[3], remarks: m[1] });
                } else {
                    fuelData.push({ name: p.name, time: m[1], fuel: m[2], remarks: "" });
                    if (p.name === "BLOCK FUEL") blockFuelValue = parseInt(m[2]);
                }
            }
        });
        
        // Special handling for CONTINGENCY if not found by first pattern
        if (!fuelData.find(item => item.name === "CONTINGENCY")) {
            
            // Try pattern for "CONTINGENCY 3% ERA 00.11 423"
            const contingencyMatch1 = text.match(/CONTINGENCY\s+(\d+%)\s+ERA\s+([\d.]+)\s+(\d+)/);
            if (contingencyMatch1) {
                fuelData.push({ 
                    name: "CONTINGENCY", 
                    time: contingencyMatch1[2], 
                    fuel: contingencyMatch1[3], 
                    remarks: contingencyMatch1[1] + " ERA" 
                });
            } else {
                // Try pattern for "CONTINGENCY 5% 00.10 200"
                const contingencyMatch2 = text.match(/CONTINGENCY\s+(\d+%)\s+([\d.]+)\s+(\d+)/);
                if (contingencyMatch2) {
                    fuelData.push({ 
                        name: "CONTINGENCY", 
                        time: contingencyMatch2[2], 
                        fuel: contingencyMatch2[3], 
                        remarks: contingencyMatch2[1]
                    });
                } else {
                    // Try pattern for "CONTINGENCY 5M 00.10 200"
                    const contingencyMatch3 = text.match(/CONTINGENCY\s+(5M)\s+([\d.]+)\s+(\d+)/);
                    if (contingencyMatch3) {
                        fuelData.push({ 
                            name: "CONTINGENCY", 
                            time: contingencyMatch3[2], 
                            fuel: contingencyMatch3[3], 
                            remarks: contingencyMatch3[1]
                        });
                    } else {
                        // Try generic pattern as fallback
                        const contingencyMatch4 = text.match(/CONTINGENCY\s+([\d.]+)\s+(\d+)/);
                        if (contingencyMatch4) {
                            fuelData.push({ 
                                name: "CONTINGENCY", 
                                time: contingencyMatch4[1], 
                                fuel: contingencyMatch4[2], 
                                remarks: "" 
                            });
                        }
                    }
                }
            }
        }
        
        // If still no fuel data found, try a more aggressive approach
        if (fuelData.length === 0) {
            console.log("No fuel data found with patterns, trying aggressive extraction...");
            
            // Look for the fuel table section
            const fuelSectionMatch = text.match(/ALTN.*?(?:BLOCK FUEL.*?\d+)/s);
            if (fuelSectionMatch) {
                const fuelSection = fuelSectionMatch[0];
                
                // Extract individual lines
                const lines = fuelSection.split('\n').filter(line => line.trim());
                
                lines.forEach(line => {
                    const trimmed = line.trim();
                    
                    // Try to parse each line
                    if (trimmed.startsWith('ALTN')) {
                        const match = trimmed.match(/ALTN\s+([A-Z]{3,4})\s+([\d.]+)\s+(\d+)/);
                        if (match) {
                            fuelData.push({ name: "ALTN", time: match[2], fuel: match[3], remarks: match[1] });
                        }
                    } else if (trimmed.startsWith('FINAL RESERVE')) {
                        const match = trimmed.match(/FINAL RESERVE\s+([\d.]+)\s+(\d+)/);
                        if (match) {
                            fuelData.push({ name: "FINAL RESERVE", time: match[1], fuel: match[2], remarks: "" });
                        }
                    } else if (trimmed.startsWith('MIN DIVERSION')) {
                        const match = trimmed.match(/MIN DIVERSION\s+([\d.]+)\s+(\d+)/);
                        if (match) {
                            fuelData.push({ name: "MIN DIVERSION", time: match[1], fuel: match[2], remarks: "" });
                        }
                    } else if (trimmed.startsWith('CONTINGENCY')) {
                        const match = trimmed.match(/CONTINGENCY\s+(\d+%)\s+ERA\s+([\d.]+)\s+(\d+)/) ||
                                    trimmed.match(/CONTINGENCY\s+(\d+%)\s+([\d.]+)\s+(\d+)/) ||
                                    trimmed.match(/CONTINGENCY\s+(5M)\s+([\d.]+)\s+(\d+)/) ||
                                    trimmed.match(/CONTINGENCY\s+([\d.]+)\s+(\d+)/);
                        if (match) {
                            let remarks = "";
                            if (match[1] && (match[1].includes('%') || match[1] === '5M')) {
                                remarks = match[1];
                                if (trimmed.includes('ERA')) remarks += ' ERA';
                            }
                            const timeIndex = match[1] && (match[1].includes('%') || match[1] === '5M') ? 2 : 1;
                            const fuelIndex = match[1] && (match[1].includes('%') || match[1] === '5M') ? 3 : 2;
                            fuelData.push({ 
                                name: "CONTINGENCY", 
                                time: match[timeIndex], 
                                fuel: match[fuelIndex], 
                                remarks: remarks 
                            });
                        }
                    } else if (trimmed.startsWith('MIN ADDITIONAL')) {
                        const match = trimmed.match(/MIN ADDITIONAL\s+([\d.]+)\s+(\d+)/);
                        if (match) {
                            fuelData.push({ name: "MIN ADDITIONAL", time: match[1], fuel: match[2], remarks: "" });
                        }
                    } else if (trimmed.startsWith('TOTAL RESERVE')) {
                        const match = trimmed.match(/TOTAL RESERVE\s+([\d.]+)\s+(\d+)/);
                        if (match) {
                            fuelData.push({ name: "TOTAL RESERVE", time: match[1], fuel: match[2], remarks: "" });
                        }
                    } else if (trimmed.startsWith('TRIP')) {
                        const match = trimmed.match(/TRIP\s+([\d.]+)\s+(\d+)/);
                        if (match) {
                            fuelData.push({ name: "TRIP", time: match[1], fuel: match[2], remarks: "" });
                        }
                    } else if (trimmed.startsWith('ENDURANCE')) {
                        const match = trimmed.match(/ENDURANCE\s+([\d.]+)\s+(\d+)/);
                        if (match) {
                            fuelData.push({ name: "ENDURANCE", time: match[1], fuel: match[2], remarks: "" });
                        }
                    } else if (trimmed.startsWith('TAXI')) {
                        const match = trimmed.match(/TAXI\s+(\d+)/);
                        if (match) {
                            fuelData.push({ name: "TAXI", time: "-", fuel: match[1], remarks: "" });
                        }
                    } else if (trimmed.startsWith('MINIMUM BLOCK')) {
                        const match = trimmed.match(/MINIMUM BLOCK\s+(\d+)/);
                        if (match) {
                            safeText('view-min-block', match[1] + " kg");
                        }
                    } else if (trimmed.startsWith('EXTRA')) {
                        const match = trimmed.match(/EXTRA\s+([\d.]+)\s+(\d+)/);
                        if (match) {
                            fuelData.push({ name: "EXTRA", time: match[1], fuel: match[2], remarks: "" });
                        }
                    } else if (trimmed.startsWith('TANKERING')) {
                        const match = trimmed.match(/TANKERING\s+([\d.]+)\s+(\d+)/);
                        if (match) {
                            fuelData.push({ name: "TANKERING", time: match[1], fuel: match[2], remarks: "" });
                        }
                    } else if (trimmed.startsWith('BLOCK FUEL')) {
                        const match = trimmed.match(/BLOCK FUEL\s+([\d.]+)\s+(\d+)/);
                        if (match) {
                            fuelData.push({ name: "BLOCK FUEL", time: match[1], fuel: match[2], remarks: "" });
                            blockFuelValue = parseInt(match[2]);
                        }
                    }
                });
            }
        }
        
    }

    function extractWeights(text) {
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
            safeText('view-pld', m[10]);
        }
    }

    function extractRoutes(text) {
        // Destination Route
        const destRouteMatch = text.match(/DEST\s+ROUTE[:\s]+(.*?)(?=\s+ALTN\d?\s+ROUTE|\s+FUEL|\s+$)/is);
        safeText('view-dest-route', destRouteMatch ? destRouteMatch[1].trim() : '-');

        // Alternate Route
        const altn1Match = text.match(/ALTN1?\s+ROUTE[:\s]+(.*?)(?=\s+ALTN2?\s+ROUTE|\s+FUEL|\s+$)/is);
        safeText('view-altn-route', altn1Match ? altn1Match[1].trim() : '-');

        // Alternate Route 2
        const altn2Match = text.match(/ALTN2\s+ROUTE[:\s]+(.*?)(?=\s+FUEL|\s+$)/is);
        if (altn2Match) {
            safeText('view-altn2-route', altn2Match[1].trim());
        } else {
            safeText('view-altn2-route', '-');
        }
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
    }
    
    function extractAdditionalFlightInfo(textContent) {
        // Join all lines into one string for easier pattern matching
        const singleLine = textContent.replace(/\n/g, ' ').replace(/\s+/g, ' ');
        
        // Pattern for Row 1: CRZ WIND M032 AVG TEMP M54 ISA DEV M08 LOWEST TEMP M60 MAX SR 08
        const row1Pattern = /CRZ WIND\s+(M?\d+)\s+AVG TEMP\s+(M?\d+)\s+ISA DEV\s+(M?\d+)\s+LOWEST TEMP\s+(M?\d+)\s+MAX SR\s+(\d+)/i;
        const row1Match = singleLine.match(row1Pattern);
        
        // Pattern for Row 2: IDLE/PERF -0.1/2.0 SEATS 166 (16/150) STN 7 JMP 2
        const row2Pattern = /IDLE\/PERF\s+([-\d\.]+)\/([\d\.]+)\s+SEATS\s+(\d+)\s*\((\d+)\/(\d+)\)\s+STN\s+(\d+)\s+JMP\s+(\d+)/i;
        const row2Match = singleLine.match(row2Pattern);
        
        let row1Text = "-";
        let row2Text = "-";
        let maxSR = '';
        
        if (row1Match) {
            maxSR = row1Match[5]; // Capture the SR value
            row1Text = `CRZ WIND ${row1Match[1]} AVG TEMP ${row1Match[2]} ISA DEV ${row1Match[3]} LOWEST TEMP ${row1Match[4]} MAX SR ${row1Match[5]}`;
        } else {
            // Try alternative pattern without the M prefix
            const altRow1Pattern = /CRZ WIND\s+(\w+)\s+AVG TEMP\s+(\w+)\s+ISA DEV\s+(\w+)\s+LOWEST TEMP\s+(\w+)\s+MAX SR\s+(\w+)/i;
            const altRow1Match = singleLine.match(altRow1Pattern);
            if (altRow1Match) {
                maxSR = altRow1Match[5];
                row1Text = `CRZ WIND ${altRow1Match[1]} AVG TEMP ${altRow1Match[2]} ISA DEV ${altRow1Match[3]} LOWEST TEMP ${altRow1Match[4]} MAX SR ${altRow1Match[5]}`;
            }
        }
        
        if (row2Match) {
            row2Text = `IDLE/PERF ${row2Match[1]}/${row2Match[2]} SEATS ${row2Match[3]} (${row2Match[4]}/${row2Match[5]}) STN ${row2Match[6]} JMP ${row2Match[7]}`;
        } else {
            const altRow2Pattern = /IDLE\/PERF\s+([^ ]+)\s+SEATS\s+([^ ]+)\s+STN\s+([^ ]+)\s+JMP\s+([^ ]+)/i;
            const altRow2Match = singleLine.match(altRow2Pattern);
            if (altRow2Match) {
                row2Text = `IDLE/PERF ${altRow2Match[1]} SEATS ${altRow2Match[2]} STN ${altRow2Match[3]} JMP ${altRow2Match[4]}`;
            }
        }
        
        // Update the UI
        safeText('view-crz-wind-temp', row1Text);
        safeText('view-seats-stn-jmp', row2Text);
        
        return { row1: row1Text, row2: row2Text, maxSR: maxSR };
    }

    function extractRequestNumber(textContent) {
        if (!textContent) return '';
        // Pattern: REQUEST # 03251  or  REQUEST#03251  or  REQUEST #03251
        const match = textContent.match(/REQUEST\s*#\s*(\d+)/i);
        return match ? match[1] : '';
    }

    function parsePageOne(textContent) {
        try {
            // Clean up the text: replace multiple spaces with single spaces
            const cleanText = textContent.replace(/\s+/g, ' ').trim();
            
            // Look for the flight info pattern in the cleaned text
            // Pattern: FLT REG DATE DEP DEST CI STD ETD STA ETA ALTN
            // Example: KZR622 EI-KDD 10/01/26 UACC UAAA CI013 0210 0210 0400 0409 UACC
            const flightPattern = /([A-Z]{3}\d{3,4})\s+([A-Z0-9-]{3,7})\s+(\d{2}\/\d{2}\/\d{2})\s+([A-Z]{4})\s+([A-Z]{4})\s+(CI\d+)\s+(\d{4})\s+(\d{4})\s+(\d{4})\s+(\d{4})\s+([A-Z]{4})/;
            
            const match = cleanText.match(flightPattern);
            
            if (match) {
                const [
                    , // full match
                    flt, reg, date, dep, dest, ci, 
                    stdRaw, etdRaw, staRaw, etaRaw, altn
                ] = match;
                
                // Now look for ERA and ALTN2 AFTER the flight pattern
                const afterFlight = cleanText.substring(match.index + match[0].length);
                
                // Look for 4-letter airport codes after the flight pattern, but stop at "MET" or "MTOW"
                const nextTokens = afterFlight.trim().split(/\s+/);
                let era = '';
                let altn2 = '';
                
                for (let i = 0; i < nextTokens.length; i++) {
                    const token = nextTokens[i];
                    
                    // Stop if we hit MET, MTOW, or other section headers
                    if (token.startsWith('MET') || token.startsWith('MTOW') || 
                        token.startsWith('TIME') || token.startsWith('ALTN') ||
                        token.startsWith('FINAL') || /^\d/.test(token)) {
                        break;
                    }
                    
                    // Only consider 4-letter uppercase codes as airports
                    if (token.length === 4 && /^[A-Z]{4}$/.test(token)) {
                        if (!era) {
                            era = token;
                        } else if (!altn2) {
                            altn2 = token;
                            break; // Found both, stop
                        }
                    }
                }
                
                // Format times
                const formatTime = (t) => t && t.length === 4 ? t.substring(0,2) + ":" + t.substring(2,4) : "-";
                
                // Set all values
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
                
                if (era) 
                    safeText('view-era-text', era);
                else
                    safeText('view-era-text', '');
                if (altn2) 
                    safeText('view-altn2', altn2);
                else
                    safeText('view-altn2', '');
                
                // Sync to journey log
                safeSet('j-flt', flt);
                safeSet('j-reg', reg);
                safeSet('j-date', date);
                safeSet('j-dep', dep);
                safeSet('j-dest', dest);
                safeSet('j-altn', altn);
                
                if (era && el('j-era')) el('j-era').value = era;
                if (altn2 && el('j-altn2')) el('j-altn2').value = altn2;
                
                if (!el('j-std')?.value) safeSet('j-std', formatTime(stdRaw));

                // Extract other sections
                extractAdditionalFlightInfo(textContent);
                extractRoutes(textContent);
                extractFuelData(textContent);
                extractWeights(textContent);
                
                return true; // Success
                
            } else {
                console.error('Could not find flight info pattern in OFP');
                
                // Fallback: Try to find flight info manually
                const words = cleanText.split(' ');
                let foundFlight = false;
                
                for (let i = 0; i < words.length; i++) {
                    if (/^[A-Z]{3}\d{3,4}$/.test(words[i])) {
                        console.log('Found potential flight number at index', i, ':', words[i]);
                        foundFlight = true;
                        
                        if (i + 5 < words.length) {
                            // Try to extract manually
                            safeText('view-flt', words[i]);
                            if (words[i+1]) safeText('view-reg', words[i+1]);
                            if (words[i+2]) safeText('view-date', words[i+2]);
                            if (words[i+3]) safeText('view-dep', words[i+3]);
                            if (words[i+4]) safeText('view-dest', words[i+4]);
                            
                            // Look for CI pattern in next few words
                            for (let j = i+5; j < Math.min(i+15, words.length); j++) {
                                if (words[j] && words[j].startsWith('CI')) {
                                    safeText('view-ci', words[j]);
                                    break;
                                }
                            }
                        }
                        break;
                    }
                }
                
                if (!foundFlight) {
                    throw new Error('Could not parse flight information from OFP');
                }
                
                return false; // Partial success with fallback
            }
            
        } catch (error) {
            console.error('Error in parsePageOne:', error);
            
            // Clear flight summary to show parsing failed
            ['view-flt', 'view-reg', 'view-date', 'view-dep', 'view-dest', 
            'view-altn', 'view-std-text', 'view-sta-text', 'view-ci',
            'view-era-text', 'view-altn2'].forEach(id => {
                safeText(id, '-');
            });
            
            // Show error message to user
            if (typeof setOFPLoadedState === 'function') {
                setOFPLoadedState(false);
            }
            
            // Show error notification
            setTimeout(() => {
                const errorDiv = document.createElement('div');
                errorDiv.style.cssText = `
                    position: fixed;
                    top: 20px;
                    right: 20px;
                    background: #ff3b30;
                    color: white;
                    padding: 15px 20px;
                    border-radius: 8px;
                    z-index: 10000;
                    box-shadow: 0 4px 12px rgba(0,0,0,0.15);
                `;
                errorDiv.innerHTML = `
                    <strong>⚠️ OFP Parsing Failed</strong><br>
                    <small>${error.message || 'Unknown error'}</small><br>
                    <button onclick="this.parentElement.remove()" style="
                        margin-top: 8px;
                        background: rgba(255,255,255,0.2);
                        border: none;
                        color: white;
                        padding: 5px 10px;
                        border-radius: 4px;
                        cursor: pointer;
                    ">Dismiss</button>
                `;
                document.body.appendChild(errorDiv);
                
                // Auto-remove after 10 seconds
                setTimeout(() => {
                    if (errorDiv.parentElement) {
                        errorDiv.remove();
                    }
                }, 10000);
            }, 100);
            
            throw error; // Re-throw so calling function knows it failed
        }
    }

    async function parsePage1(pdf) {
        const page = await pdf.getPage(1);
        const content = await page.getTextContent();
        const textContent = content.items.map(x => x.str).join(' ');

        extractMainPageCoordinates(content.items);
        try {
            parsePageOne(textContent);
        } catch (parseError) {
            console.warn('Failed to parse page 1:', parseError);
            if (typeof setOFPLoadedState === 'function') {
                setOFPLoadedState(false);
            }
            throw parseError;
        }

        const requestNumber = extractRequestNumber(textContent);
        return { requestNumber, textContent };
    }

    function extractNOTAMs(fullText) {
        const notams = [];
        const notamIdPattern = '[A-Z]{1,2}\\d{4}\\/\\d{2}';
        const notamStartRegex = new RegExp(
            '(?:^|\\s)(?:-)?\\s*([A-Z]{4})\\s+(' + notamIdPattern + ')|NOTAM([A-Z]{4})\\s+(' + notamIdPattern + ')',
            'g'
        );
        
        const stopMarkers = [
            'ARRIVAL:', 'OTHER:', 'DEPARTURE:', '---', 
            'PAGE', 'FLY ARYSTAN BRIEF', 'AIR ASTANA BRIEF',
            'CTR', 'RWY TDZ LGT', 'ACFT STAND', 'APRON',
            'ILS', 'APCH LGT', 'TWY CENTRELINE LGT', 'Fir:', 'Region:',
            'TWY', 'RWY', 'AD', 'TWR', 'STAR', 'SID', 'PJE',
            'NOT CLASSIFIED', 'FIRE AND RESCUE', 'FIREFIGHTING'
        ];

        const matches = [];
        let match;
        while ((match = notamStartRegex.exec(fullText)) !== null) {
            matches.push({ start: match.index });
        }

        for (let i = 0; i < matches.length; i++) {
            const current = matches[i];
            const next = matches[i + 1];
            const end = next ? next.start : fullText.length;
            let rawText = fullText.substring(current.start, end).trim();

            const lines = rawText.split('\n');
            let stopLineIndex = lines.length;
            for (let j = 0; j < lines.length; j++) {
                const trimmed = lines[j].trim();
                if (stopMarkers.some(marker => trimmed.startsWith(marker))) {
                    stopLineIndex = j;
                    break;
                }
            }
            let cleanedText = lines.slice(0, stopLineIndex).join('\n').trim();

            // --- Cleanup: remove inline footer and section headers ---
            cleanedText = cleanedText
                .replace(/\s*FLY\s+ARYSTAN\s+BRIEF\s+PAGE\s+\d+\s+OF\s+\d+(\s+PAGE\s+\d+\s+OF\s+\d+)?.*$/gi, '')
                .replace(/\s+PAGE\s+\d+\s+OF\s+\d+.*$/gi, '')
                .replace(/\s*Fir:\s*.*$/i, '')       // NEW
                .replace(/\s*Region:\s*.*$/i, '')    // NEW
                .trim();

            // Keyword check
            const keywords = [
                'RWY', 'TWY', 'CLSD', 'U/S', 'NOT AVBL', 'WIP', 'FIRE', 'RESCUE', 'BIRD', 'BA',
                'ICE', 'SNOW', 'SLUSH', 'ILS', 'VOR', 'NDB', 'DME', 'RNAV', 'GPS', 'RNP',
                'APU', 'DE-ICING', 'PUSHBACK', 'STAND', 'ACFT',
                'RWYCC', 'DOWNGRADED', 'FROST', 'DRIFTING SNOW', 'CONTAMINATION',
                'BRAKING ACTION', 'POOR', 'MEDIUM', 'NIL', 'CONDITION CODE'
            ];
            const upper = cleanedText.toUpperCase();
            const hasKeyword = keywords.some(kw => upper.includes(kw));

            if (hasKeyword && cleanedText.length > 20) {
                notams.push(cleanedText);
            }
        }

        console.log(`Found ${notams.length} potential NOTAMs after filtering`);
        return notams;
    }

    function extractWeather(fullText) {
        const weather = [];
        const weatherStartRegex = /\b(METAR|SPECI|TAF(?:\s+AMD)?)\s+([A-Z]{4})\b/gi;
        
        const stopMarkers = [
            'OTHER:', 'DEPARTURE:', 'ARRIVAL:', '---', 'AIR ASTANA BRIEF', 'PAGE',
            'NO AIRMET', 'NO PIREP', 'AIRMET', 'PIREP', 'Fir:', 'Region:',
            'NO TAF', 'NO TAF REPORTS', 'NO TAF REPORTS FOUND'
        ];

        const matches = [];
        let match;
        while ((match = weatherStartRegex.exec(fullText)) !== null) {
            matches.push({ start: match.index });
        }

        for (let i = 0; i < matches.length; i++) {
            const start = matches[i].start;
            const end = (i + 1 < matches.length) ? matches[i + 1].start : fullText.length;
            let rawText = fullText.substring(start, end).trim();

            // Truncate at the first stop marker
            let stopIdx = rawText.length;
            for (let marker of stopMarkers) {
                let idx = rawText.indexOf(marker);
                if (idx !== -1 && idx < stopIdx) {
                    stopIdx = idx;
                }
            }
            let cleanedText = rawText.substring(0, stopIdx).trim();

            // Additional regex truncation: cut at any occurrence of "NO TAF" or "AIR ASTANA BRIEF"
            const patterns = [/\bNO\s+TAF\b/i, /\bAIR\s+ASTANA\s+BRIEF\b/i];
            for (let pattern of patterns) {
                let match = cleanedText.match(pattern);
                if (match) {
                    cleanedText = cleanedText.substring(0, match.index).trim();
                }
            }

            if (cleanedText.length > 20) {
                weather.push(cleanedText);
            }
        }

        console.log(`Extracted ${weather.length} weather reports`);
        if (weather.length === 0) {
            console.log('No weather reports found. First 500 chars:', fullText.substring(0, 500));
        }
        return weather;
    }

    function cleanNOTAMText(text) {
        // Case 1: "NOTAM" followed immediately or with space by 4 letters
        let match = text.match(/NOTAM\s*([A-Z]{4})/i);
        if (match) {
            const airport = match[1].toUpperCase();
            // Remove the "NOTAMXXXX" prefix (including optional space)
            let cleaned = text.replace(/NOTAM\s*[A-Z]{4}/i, '').trim();
            return { airport, text: cleaned };
        }
        // Case 2: Leading ICAO code with optional dash/spaces (e.g., "- UAAA" or "UAAA")
        match = text.match(/^[-–—\s]*([A-Z]{4})\b/);
        if (match) {
            const airport = match[1].toUpperCase();
            let cleaned = text.replace(/^[-–—\s]*[A-Z]{4}\s*/, '').trim();
            return { airport, text: cleaned };
        }
        // Case 3: Four letters at the very end (maybe preceded by space)
        match = text.match(/([A-Z]{4})$/);
        if (match) {
            const airport = match[1];
            let cleaned = text.replace(/\s*[A-Z]{4}$/, '').trim();
            return { airport, text: cleaned };
        }
        // Fallback: Unknown
        return { airport: 'Unknown', text };
    }

// ==========================================
// 5. CALCULATION LOGIC
// ==========================================
    
    window.runFlightLogCalculations = function() {
        const atd = el('ofp-atd-in')?.value || el('o-a-0')?.value || el('j-off')?.value;
        
        // 1. Find Taxi Fuel
        let taxiFuel = 200;
        if (typeof fuelData !== 'undefined' && Array.isArray(fuelData)) {
            const taxiEntry = fuelData.find(item => item.name === "TAXI");
            if (taxiEntry && taxiEntry.fuel) {
                taxiFuel = parseInt(taxiEntry.fuel);
            }
        }

        // 2. Find the latest ATO using cache
        let lastAtoMins = -1;
        let lastAtoIndex = -1;

        for (let i = waypoints.length - 1; i >= 0; i--) {
            const atoInput = waypointATOCache[i];
            if (atoInput && atoInput.value) {
                const [h, m] = atoInput.value.split(':').map(Number);
                lastAtoMins = h * 60 + m;
                lastAtoIndex = i;
                break;
            }
        }

        // 3. Determine start fuel
        const pdfTakeoffFuel = waypoints[0] ? (waypoints[0].baseFuel || parseInt(waypoints[0].fob)) : 0;
        const picBlock = parseInt(el('view-pic-block')?.value || el('view-pic-block')?.innerText) || blockFuelValue || 0;
        
        let currentStartFuel = (takeoffFuelInput && takeoffFuelInput.value) 
            ? parseInt(takeoffFuelInput.value) 
            : (picBlock - taxiFuel);

        const delta = currentStartFuel - pdfTakeoffFuel;

        // 4. Update Waypoints 
        waypoints.forEach((wp, index) => {
            if (wp.baseFuel === undefined) wp.baseFuel = parseInt(wp.fob) || 0;
            
            // Apply Delta
            if (wp.baseFuel > 0) wp.fuel = wp.baseFuel + delta;

            // Calculate Time
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
        });
    updateAlternateETOs();
    updateFlightLogTablesIncremental();
    updateAlternateTableIncremental();
    
    waypointTableCache.lastUpdate = Date.now();
    };

    function calculatePICBlock() {
        const extra = parseInt(el('front-extra-kg')?.value) || 0;
        if(blockFuelValue > 0 || extra > 0) {
            safeText('view-pic-block', (blockFuelValue + extra) + " kg");
        } else {
            safeText('view-pic-block', '-');
        }
    }

    window.calculateExtraFromTotal = function() {
        const totalInput = el('view-pic-block');
        const extraInput = el('front-extra-kg');
        
        // Ensure we have the base Block Fuel from the OFP
        if (typeof blockFuelValue === 'undefined' || blockFuelValue === 0) return;
            const picTotal = parseInt(totalInput.value) || 0;
        
        // Calculation: Extra = User Total - OFP Block
        let diff = picTotal - blockFuelValue;

        extraInput.value = diff;
        
        // Update the Flight Log Table immediately
        runFlightLogCalculations();
    };

    async function getOFPCount() {
        const db = await getDB();
        if (!db.objectStoreNames.contains('ofps')) return 0;
        const tx = db.transaction('ofps', 'readonly');
        const store = tx.objectStore('ofps');
        return new Promise((resolve, reject) => {
            const req = store.count();
            req.onsuccess = () => resolve(req.result);
            req.onerror = (e) => reject(e.target.error);
        });
    }

    function minsToTime(m) {
        if(m < 0) m += 1440 * Math.ceil(Math.abs(m) / 1440);
        
        const days = Math.floor(m / 1440);
        const remainingMins = m % 1440;
        
        const h = Math.floor(remainingMins / 60);
        const min = remainingMins % 60;
        
        if (days > 0) {
            return `${h.toString().padStart(2,'0')}:${min.toString().padStart(2,'0')} (+${days}d)`;
        }
        
        return `${h.toString().padStart(2,'0')}:${min.toString().padStart(2,'0')}`;
    }

    function getCCMaxFDP() {
        const ccMaxHidden = document.getElementById('j-cc-max-fdp-hidden');
        return ccMaxHidden ? ccMaxHidden.value : "00:00";
    }

    function getDiff(start, end) {
        if (!start || !end) return "";
        
        const parseTime = (timeStr) => {
            if (!timeStr) return null;
            if (timeStr.length === 4 && /^\d{4}$/.test(timeStr)) {
                return {
                    h: parseInt(timeStr.substring(0, 2)),
                    m: parseInt(timeStr.substring(2, 4))
                };
            }
            if (timeStr.includes(':')) {
                const [h, m] = timeStr.split(':').map(Number);
                return { h, m };
            }
            return null;
        };
        
        const startTime = parseTime(start);
        const endTime = parseTime(end);
        if (!startTime || !endTime) return "";
        
        let startMinutes = startTime.h * 60 + startTime.m;
        let endMinutes = endTime.h * 60 + endTime.m;
        
        let dayOffset = 0;
        if (endMinutes < startMinutes - 720) dayOffset = 1;
        else if (endMinutes < startMinutes) dayOffset = 1;
        
        const totalMinutes = (endMinutes + dayOffset * 1440) - startMinutes;
        
        if (totalMinutes < 0 || totalMinutes > 2880) {
            const diff = endMinutes - startMinutes;
            if (diff < 0) {
                const correctedDiff = diff + 1440;
                const hours = Math.floor(correctedDiff / 60);
                const minutes = correctedDiff % 60;
                return `${hours.toString().padStart(2, '0')}:${minutes.toString().padStart(2, '0')}`;
            }
        }
        
        const hours = Math.floor(totalMinutes / 60);
        const minutes = totalMinutes % 60;
        return `${hours.toString().padStart(2, '0')}:${minutes.toString().padStart(2, '0')}`;
    }

    window.calculateFuelForJourneyLog = function() {
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

    window.calculateTripTimeForJourneyLog = function() {
        const outT = el('j-out')?.value;
        const inT = el('j-in')?.value;
        const offT = el('j-off')?.value;
        const onT = el('j-on')?.value;

        if (outT && inT) safeSet('j-block', getDiff(outT, inT));
        else safeSet('j-block', '');

        if (offT && onT) safeSet('j-flight', getDiff(offT, onT));
        else safeSet('j-flight', '');

        calcDutyLogic();
    };

    window.calculateDutyValues = function(std, flt, dep, dest) {
        if (!std) return { fc: "00:00", cc: "00:00", max: "00:00", ccMax: "00:00" };

        const fltUpper = (flt || "").toUpperCase();
        const isKZR = fltUpper.includes('KZR') || fltUpper.includes('KC');
        const isAYN = fltUpper.includes('AYN') || fltUpper.includes('FS');

        const isDepKZ = (dep || "").toUpperCase().startsWith('UA');
        const isDestKZ = (dest || "").toUpperCase().startsWith('UA');

        // 1. Flight Crew offset (minutes before STD)
        let fcOffset = 60; // default
        if (isDepKZ) {
            if (isKZR) {
                fcOffset = isDestKZ ? 75 : 90;
            } else if (isAYN) {
                fcOffset = isDestKZ ? 60 : 75;
            }
        }

        // 2. Cabin Crew offset (minutes before FC)
        let ccOffset = 0;
        if (isKZR && isDepKZ) {
            ccOffset = 15;
        }

        const stdMins = parseTimeString(std);   // STD in UTC minutes

        // FC report in UTC
        let fcStartUTC = stdMins - fcOffset;
        if (fcStartUTC < 0) fcStartUTC += 1440;

        // CC report in UTC
        let ccStartUTC = fcStartUTC - ccOffset;
        if (ccStartUTC < 0) ccStartUTC += 1440;

        // Convert FC report UTC to local Kazakhstan (UTC+5) for FDP table
        let localStart = (fcStartUTC + 300) % 1440;
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

        if ((!std || !flt) && dailyLegs.length > 0) {
            flt = dailyLegs[0]['j-flt'] || "";
            dep = dailyLegs[0]['j-dep'] || "";
            dest = dailyLegs[0]['j-dest'] || "";
            std = dailyLegs[0]['j-std'] || "";
        }

        if (!std) return;

        const dutyValues = calculateDutyValues(std, flt, dep, dest);

        const currentFc = el('j-duty-start')?.value;
        const currentCc = el('j-cc-duty-start')?.value;

        if (!currentFc || currentFc.trim() === '') {
            safeSet('j-duty-start', dutyValues.fc);
        }
        if (!currentCc || currentCc.trim() === '') {
            safeSet('j-cc-duty-start', dutyValues.cc);
        }

        dutyStartTime = parseTimeString(el('j-duty-start')?.value);
        recalcMaxFDP();
    };

    function calculateBaseMaxFDP(localStartMins) {
        const t = localStartMins % 1440;
        if (t >= 360 && t <= 809) return 780;   // 06:00-13:29
        if (t >= 810 && t <= 839) return 765;   // 13:30-13:59
        if (t >= 840 && t <= 869) return 750;   // 14:00-14:29
        if (t >= 870 && t <= 899) return 735;   // 14:30-14:59
        if (t >= 900 && t <= 929) return 720;   // 15:00-15:29
        if (t >= 930 && t <= 959) return 705;   // 15:30-15:59
        if (t >= 960 && t <= 989) return 690;   // 16:00-16:29
        if (t >= 990 && t <= 1019) return 675;  // 16:30-16:59
        if (t >= 1020 || t <= 299) return 660;  // 17:00-04:59
        if (t >= 300 && t <= 314) return 720;   // 05:00-05:14
        if (t >= 315 && t <= 329) return 735;   // 05:15-05:29
        if (t >= 330 && t <= 344) return 750;   // 05:30-05:44
        if (t >= 345 && t <= 359) return 765;   // 05:45-05:59
        return 780;
    }

    window.recalcMaxFDP = function() {
        const fcTimeStr = el('j-duty-start')?.value;
        const ccTimeStr = el('j-cc-duty-start')?.value;
        if (!fcTimeStr) return;

        const fcMinsUTC = parseTimeString(fcTimeStr);
        const ccMinsUTC = ccTimeStr ? parseTimeString(ccTimeStr) : fcMinsUTC;
        dutyStartTime = fcMinsUTC;

        const sectors = dailyLegs.length;

        // Convert UTC to local Kazakhstan (UTC+5) for FDP table
        const localFcMins = (fcMinsUTC + 300) % 1440;
        const baseFDP = calculateBaseMaxFDP(localFcMins);

        let reportingDiff = fcMinsUTC - ccMinsUTC;
        if (reportingDiff < 0) reportingDiff += 1440;
        const cappedDiff = Math.min(reportingDiff, 60);

        const getMaxFDPWithSectors = (baseMax, sectors) => {
            let finalMax = baseMax;
            if (sectors === 3) finalMax -= 30;
            else if (sectors === 4) finalMax -= 60;
            else if (sectors >= 5) finalMax -= 90;
            return Math.max(finalMax, 660);
        };

        const fcMax = getMaxFDPWithSectors(baseFDP, sectors);
        const ccMax = getMaxFDPWithSectors(baseFDP + cappedDiff, sectors);

        safeSet('j-max-fdp', minsToTime(fcMax));
        const ccMaxInput = document.getElementById('j-cc-max-fdp-hidden');
        if (ccMaxInput) ccMaxInput.value = minsToTime(ccMax);
    };

    function calculateNightDuty(startMinsUTC, endMinsUTC) {
        if (!startMinsUTC && startMinsUTC !== 0 || !endMinsUTC && endMinsUTC !== 0) return "00:00";

        let nightOverlap = 0;
        let start = startMinsUTC;
        let end = endMinsUTC;
        if (end < start) end += 1440;   // handle crossing midnight

        // Night window in UTC: 21:00 (1260) to 23:59 (1439)
        const nightStart = 1260;
        const nightEnd = 1439;

        for (let i = start; i < end; i++) {
            const minuteOfDay = i % 1440;
            if (minuteOfDay >= nightStart && minuteOfDay <= nightEnd) {
                nightOverlap++;
            }
        }

        return minsToTime(nightOverlap);
    }

    function getNightDutyForCrew(startMinsUTC) {
        if(!startMinsUTC && startMinsUTC !== 0) return "00:00";
        
        const lastLeg = dailyLegs[dailyLegs.length - 1];
        if (!lastLeg) return "00:00";
        
        const endMinsUTC = parseTimeString(lastLeg['j-in']);
        if (!endMinsUTC && endMinsUTC !== 0) return "00:00";
        
        return calculateNightDuty(startMinsUTC, endMinsUTC);
    }


// ==========================================
// 6. PARSING
// ==========================================

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
        const rows = buildRows((await page.getTextContent()).items);
        rows.sort((a,b) => b.y - a.y); 

        let headerY = null;
        for(const row of rows) {
            const rowText = row.items.map(item => item.str).join(' ');
            if((rowText.includes("TO") && rowText.includes("FUEL")) || 
            (rowText.includes("AWY") && rowText.includes("ETE"))) {
                headerY = row.y; 
                break; 
            }
        }

        if(!headerY) return [];

        const waypoints = [];

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
                    if(num >= 100 && num <= 50000 && !row.items.map(x=>x.str).join(' ').includes('FL ')) {
                        fuelValue = str;
                    }
                }
            }

            if(timeValue && fuelValue) {
                let data = { 
                    name: "?", awy: "-", level: "-", track: "-", 
                    wind: "-", tas: "-", gs: "-", sr: "-" 
                };

                // ---- FIRST ROW (waypoint info) ----
                if(r > 0) {
                    const prevRow = rows[r-1];
                    if(Math.abs(row.y - prevRow.y) < 25) {
                        const fullString = prevRow.items.map(x => x.str).join(' ');
                        const parts = fullString.trim().split(/\s+/);

                        if (parts.length >= 8) {
                            data.name = parts[0];
                            data.awy = parts[1];
                            data.level = parts[2];
                            data.track = parts[3];
                            data.wind = parts[4];
                            data.tas = parts[5];
                            data.gs = parts[6];
                            // IMT/FTM is parts[7] – we ignore it
                        } else if (parts.length >= 7) {
                            data.name = parts[0];
                            data.awy = parts[1];
                            data.level = parts[2];
                            data.track = parts[3];
                            data.wind = parts[4];
                            data.tas = parts[5];
                            data.gs = parts[6];
                        } else if (parts.length > 0) {
                            data.name = parts[0];
                            if(parts[1]) data.awy = parts[1];
                            if(parts[2]) data.level = parts[2];
                        }
                    }
                }

                // SECOND ROW 
                let sr = '-';

                // Debug: print the entire second row
                const rowText = row.items.map(x => x.str).join(' ');

                // Look for a 3-digit MAC token immediately followed by a 2-digit SR token 
                for (let i = 0; i < row.items.length - 1; i++) {
                    const token = row.items[i].str.trim();
                    const nextToken = row.items[i + 1].str.trim();
                    if (/^\d{3}$/.test(token) && !token.includes('/') && 
                        /^\d{2}$/.test(nextToken) && !nextToken.includes('/')) {
                        sr = nextToken;
                        break;
                    }
                }

                // If not found, try combined 5-digit token (e.g., "74702")
                if (sr === '-') {
                    for (let i = 0; i < row.items.length; i++) {
                        const token = row.items[i].str.trim();
                        if (/^\d{5}$/.test(token)) {
                            const possibleSR = token.substring(3, 5);
                            if (/^\d{2}$/.test(possibleSR)) {
                                sr = possibleSR;
                                break;
                            }
                        }
                    }
                }

                // If still not found, look for a token with space where the first part is clean
                if (sr === '-') {
                    for (let i = 0; i < row.items.length; i++) {
                        const token = row.items[i].str.trim();
                        const spaceIndex = token.indexOf(' ');
                        if (spaceIndex !== -1) {
                            const beforeSpace = token.substring(0, spaceIndex).trim();
                            const afterSpace = token.substring(spaceIndex + 1).trim();
                            const isValidBefore = /^[A-Z0-9]{3}$/.test(beforeSpace);
                            const isValidAfter = /^\d{2}$/.test(afterSpace);
                            
                            if (isValidBefore && isValidAfter) {
                                sr = afterSpace;
                                break;
                            }
                        }
                    }
                }

                if(data.name !== "?") {
                    const wpObj = {
                        ...data,
                        totalMins: parseTimeString(timeValue),
                        eto: "",
                        fob: parseInt(fuelValue) || 0,
                        page: pageNum - 1, 
                        y_anchor: row.y,
                        isTakeoff: false,
                        isAlternate: false,
                        rawTime: timeValue,
                        sr: sr
                    };
                    waypoints.push(wpObj); 
                }
            }
        }

        return waypoints;
    }

    async function parseAllWaypoints(pdf) {
        const allWaypoints = [];
        for (let i = 2; i <= pdf.numPages; i++) {
            const page = await pdf.getPage(i);
            const pageWaypoints = await parseWaypoints(page, i);
            allWaypoints.push(...pageWaypoints);
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

    async function parsePDFData(pdfBytes, isAutoLoad) {
        try {
            // 1. Reset all global parsing state
            resetParsingState();

            // 2. Load PDF document
            const pdf = await pdfjsLib.getDocument(pdfBytes).promise;

            // 3. Parse page 1 (flight info, fuel, weights, front coords)
            const { requestNumber, textContent: page1Text } = await parsePage1(pdf);

            // 4. Parse waypoints (pages 2+)
            const extractedWaypoints = await parseAllWaypoints(pdf);
            waypoints = extractedWaypoints;

            // 5. Collect full text from all pages (starting from page 2) and detect cutoff
            let fullText = page1Text;
            for (let i = 2; i <= pdf.numPages; i++) {
                const page = await pdf.getPage(i);
                const content = await page.getTextContent();
                const pageText = content.items.map(x => x.str).join(' ');
                fullText += ' ' + pageText;

                // Detect cutoff page (starting from page 4)
                if (i >= 4) {
                    const cutoff = detectCutoffPage(pageText, i);
                    if (cutoff !== null) {
                        window.cutoffPageIndex = cutoff;
                        // Do not break – we still want the rest of the text (NOTAMs/weather)
                    }
                }
            }

            // 6. Process waypoints (split into primary/alternate, set baseFuel)
            if (waypoints.length === 0) {
                console.warn('No waypoints found in PDF');
            }
            waypoints.forEach(wp => {
                wp.baseFuel = parseInt(wp.fob) || 0;
                wp.fuel = wp.baseFuel;
            });
            processWaypointsList();

            // 7. Extract metadata from UI (after parsePage1 has populated it)
            const { flight, date, dep, dest, tripTime, maxSR } = extractMetadataFromUI();

            // 8. Build final metadata object
            const metadata = {
                flight,
                date,
                departure: dep,
                destination: dest,
                tripTime: tripTime || '',
                maxSR: maxSR || '',
                requestNumber: requestNumber || ''
            };

            // 9. Update UI tables and calculations
            updateUIAfterParsing();

            // 10. Return everything needed, including full text
            return {
                success: true,
                metadata,
                tripTime,
                maxSR,
                requestNumber,
                fullText  // <-- new
            };

        } catch (error) {
            console.error('Error in parsePDFData:', error);
            throw error;
        }
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

        // Parse flight date (format "06/02/26")
        const [day, month, year] = flightDateStr.split('/').map(Number);
        const flightDate = new Date(Date.UTC(2000 + year, month - 1, day));
        const parseTime = (timeStr) => {
            const [h, m] = timeStr.split(':').map(Number);
            return h * 60 + m;
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
            if (endMin >= 1440) end += 86400000; // next day
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
                    const day = parseInt(match[1], 10);
                    const monthStr = match[2].toUpperCase();
                    const hour = parseInt(match[3], 10);
                    const minute = parseInt(match[4], 10);
                    const months = { JAN:0, FEB:1, MAR:2, APR:3, MAY:4, JUN:5, JUL:6, AUG:7, SEP:8, OCT:9, NOV:10, DEC:11 };
                    const month = months[monthStr];
                    if (month === undefined) return null;

                    // Start with baseYear
                    let year = baseYear;
                    let date = new Date(Date.UTC(year, month, day, hour, minute));
                    // If this date is more than 180 days in the past, it's probably next year
                    // (handles "10JAN" when base is December)
                    const diffDays = (date.getTime() - Date.UTC(baseYear, 0, 1)) / 86400000; // days since Jan 1 of baseYear
                    // Actually, better to compare against baseDate directly:
                    // But we don't have baseDate here, only baseYear. We'll handle it in getNotamValidity.
                    return { year, month, day, hour, minute };
                };

                const getNotamValidity = (text) => {
                    const match = text.match(/(\d{2}[A-Z]{3}\d{4})\s*[-/]\s*(\d{2}[A-Z]{3}\d{4})/i);
                    if (!match) return null;
                    const startStr = match[1];
                    const endStr = match[2];

                    // Parse both with flight's year
                    const startParsed = parseNotamDateTime(startStr, flightDate.getUTCFullYear());
                    const endParsed = parseNotamDateTime(endStr, flightDate.getUTCFullYear());
                    if (!startParsed || !endParsed) return null;

                    let start = new Date(Date.UTC(startParsed.year, startParsed.month, startParsed.day, startParsed.hour, startParsed.minute));
                    let end = new Date(Date.UTC(endParsed.year, endParsed.month, endParsed.day, endParsed.hour, endParsed.minute));

                    // If end is before start, the end is in the next year
                    if (end < start) {
                        end.setUTCFullYear(end.getUTCFullYear() + 1);
                    }

                    // If after all that, the end is still before the flight date, the whole NOTAM is in the past
                    // => shift both start and end forward by one year
                    if (end < flightDate) {
                        start.setUTCFullYear(start.getUTCFullYear() + 1);
                        end.setUTCFullYear(end.getUTCFullYear() + 1);
                    }

                    return { start, end };
                };

                // Extract data
                const notams = extractNOTAMs(fullText);
                console.log('NOTAMs extracted:', notams.length, notams);
                const weather = extractWeather(fullText);

                // Store latest METAR for each airport (only first encountered per airport)
                const airportMetars = {};
                weather.forEach(report => {
                    const upper = report.toUpperCase();
                    if (upper.includes('METAR')) {
                        const match = report.match(/\bMETAR\s+([A-Z]{4})\b/i);
                        if (match) {
                            const apt = match[1].toUpperCase();
                            if (!airportMetars[apt]) {
                                // Keep full report, we'll strip the prefix later
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
                window.currentWeather = {
                    dep: depMetar,
                    dest: destMetar
                };

                // Extract runway info for all airports (format: "UAAA ALA RWY05L 4500M RWY05R 4400M ...")
                const airportRunways = {};
                const runwayRegex = /([A-Z]{4})\s+[A-Z]{3}\s+((?:RWY\d{2}[LRC]?\s+\d+M\s*)+)/gi;
                let match;
                while ((match = runwayRegex.exec(fullText)) !== null) {
                    const apt = match[1].toUpperCase();
                    const runwayText = match[2].trim().replace(/\s+/g, ' ');
                    airportRunways[apt] = runwayText;
                }
                window.airportRunways = airportRunways;

                // Generate alerts (no time filtering yet)
                let alerts = runRulesOnText(notams, weather);
                if (!alerts) alerts = [];

                const filteredAlertsBeforeTime = alerts.filter(alert => {
                    if (alert.type && alert.type.includes('NOTAM')) {
                        const upper = alert.message.toUpperCase();
                    }
                    return true;
                });
                console.log(`Alerts after irrelevant filter: ${filteredAlertsBeforeTime.length}`);

                // Helper to parse weather validity (TAF, METAR, SPECI)
                const parseWeatherValidity = (report, baseDate) => {
                    // TAF pattern: "TAF UAKK 100503Z 1006/1106 ..."
                    let match = report.match(/TAF(?:\s+AMD)?\s+[A-Z]{4}\s+(\d{2})(\d{2})(\d{2})Z\s+(\d{2})(\d{2})\/(\d{2})(\d{2})/i);
                    if (match) {
                        const obsDay = parseInt(match[1], 10);
                        const obsHour = parseInt(match[2], 10);
                        const obsMin = parseInt(match[3], 10);
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
                    // METAR/SPECI pattern: "SPECI UAOO 100547Z ..."
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

                // Apply time filtering to the already irrelevant‑filtered alerts
                const filteredAlerts = [];
                filteredAlertsBeforeTime.forEach(alert => {
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

                        // DEBUG for specific NOTAM (place it here, after windowStart/End are defined)
                        if (alert.message && alert.message.includes('SW0158/26')) {
                            console.log('=== SW0158/26 DEBUG ===');
                            console.log('Airport:', airport);
                            console.log('Raw message:', alert.message);
                            console.log('Parsed validity:', validity ? { start: validity.start.toISOString(), end: validity.end.toISOString() } : null);
                            console.log('Window for this airport:', { start: new Date(windowStart).toISOString(), end: new Date(windowEnd).toISOString() });
                            console.log('Overlap condition:', !(endTime < windowStart || startTime > windowEnd));
                        }

                        if (endTime < windowStart || startTime > windowEnd) {
                            include = false;
                        }
                    }
                    if (include) filteredAlerts.push(alert);
                });
                console.log(`Alerts after time filtering: ${filteredAlerts.length}`);

                // Fallback if all filtered out
                let finalAlerts;
                if (filteredAlerts.length === 0 && alerts.length > 0) {
                    console.warn('Time filtering removed all alerts. Showing unfiltered list.');
                    finalAlerts = alerts;
                } else {
                    finalAlerts = filteredAlerts;
                }

                // Track airports with alerts
                const airportsWithAlerts = new Set();
                finalAlerts.forEach(a => {
                    if (a.airport && a.airport !== 'Unknown') {
                        airportsWithAlerts.add(a.airport.toUpperCase());
                    }
                });

                // Add placeholders for key airports with no alerts
                if (depAirport && !airportsWithAlerts.has(depAirport)) {
                    finalAlerts.push({
                        severity: 'info',
                        type: 'INFO',
                        airport: depAirport,
                        message: 'No relevant WX/NOTAM to report.'
                    });
                }
                if (destAirport && !airportsWithAlerts.has(destAirport)) {
                    finalAlerts.push({
                        severity: 'info',
                        type: 'INFO',
                        airport: destAirport,
                        message: 'No relevant WX/NOTAM to report.'
                    });
                }
                uniqueAlternates.forEach(alt => {
                    if (alt && !airportsWithAlerts.has(alt) && alt !== depAirport && alt !== destAirport) {
                        finalAlerts.push({
                            severity: 'info',
                            type: 'INFO',
                            airport: alt,
                            message: 'No relevant WX/NOTAM to report.'
                        });
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

                finalAlerts.sort((a, b) => {
                    const severityOrder = { critical: 0, warning: 1, info: 2 };
                    const sevA = severityOrder[(a.severity || '').toLowerCase()] ?? 3;
                    const sevB = severityOrder[(b.severity || '').toLowerCase()] ?? 3;
                    if (sevA !== sevB) return sevA - sevB;

                    const rankA = getAirportRank(a.airport);
                    const rankB = getAirportRank(b.airport);
                    if (rankA !== rankB) return rankA - rankB;

                    return (a.type || '').localeCompare(b.type || '');
                });

                console.log('Final alerts count:', finalAlerts.length);
                window.notamFullAlerts = finalAlerts.slice();

                // Render
                renderNotamsWXTable(finalAlerts);

            } catch (error) {
                console.error('Analysis error:', error);
                resultsDiv.innerHTML = `<div class="error">Analysis failed: ${error.message}</div>`;
            }
        }, 100);
    };

    function runRulesOnText(notams, weather) {
        const alerts = [];
        let notamCount = 0;

        // Process NOTAMs
        notams.forEach(rawText => {
            notamCount++;
            const { airport, text: cleaned } = cleanNOTAMText(rawText);
            if (cleaned.length < 10) {
                return;
            }

            let matched = false;
            FLIGHT_THREAT_DICTIONARY.notams.forEach(rule => {
                if (rule.regex.test(cleaned)) {
                    alerts.push({
                        severity: rule.level,
                        type: `NOTAM: ${rule.type}`,
                        airport: airport,
                        message: cleaned.substring(0, 2000) + (cleaned.length > 2000 ? '...' : '')
                    });
                matched = true;
            }
        });

        if (!matched) {
            alerts.push({
                    severity: 'info',
                    type: 'NOTAM',
                    airport: airport,
                    message: cleaned.substring(0, 2000) + (cleaned.length > 2000 ? '...' : '')
                });
            }
        });

        // Process WX
        weather.forEach(report => {
            // Try to find ICAO code after METAR/SPECI/TAF (with optional AMD)
            let airportMatch = report.match(/\b(?:METAR|SPECI|TAF(?:\s+AMD)?)\s+([A-Z]{4})\b/i);
            if (!airportMatch) {
                // Fallback: look for any standalone 4-letter ICAO code (might be the airport)
                airportMatch = report.match(/\b([A-Z]{4})\b/);
            }
            const airport = airportMatch ? airportMatch[1] : 'Unknown';
            
            FLIGHT_THREAT_DICTIONARY.weather.forEach(rule => {
                if (rule.regex.test(report)) {
                    alerts.push({
                        severity: rule.level,
                        type: `Weather: ${rule.type}`,
                        airport: airport,
                        message: report.substring(0, 2000) + (report.length > 2000 ? '...' : '')
                    });
                }
            });
        });
        return alerts;
    }

// ==========================================
// 7. UI RENDERING
// ==========================================

    function showToast(message, type = 'success') {
        const toast = document.createElement('div');
        let bgColor = 'var(--success)';
        if (type === 'error') bgColor = 'var(--error)';
        if (type === 'info') bgColor = 'var(--accent)';
        
        toast.style.cssText = `
            position: fixed;
            top: 20px;
            right: 20px;
            background: ${bgColor};
            color: white;
            padding: 15px 20px;
            border-radius: 10px;
            z-index: 10000;
            box-shadow: 0 5px 15px rgba(0,0,0,0.2);
            animation: slideIn 0.3s ease;
        `;
        
        toast.textContent = message;
        document.body.appendChild(toast);
        
        setTimeout(() => {
            toast.style.animation = 'slideOut 0.3s ease';
            setTimeout(() => toast.remove(), 300);
        }, 3000);
    }

    function showConfirmDialog(title, message, confirmText = 'Continue', cancelText = 'Cancel', type = 'warning', centered = false) {
        return createModal({
            title,
            message,
            confirmText,
            cancelText,
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

    // Unified Modal Builder
    function createModal({ 
        title, 
        message = '', 
        confirmText = 'OK', 
        cancelText = null, 
        onConfirm, 
        onCancel, 
        type = 'info', 
        icon = '📋',
        showVersion = null,
        listItems = null,
        bodyHTML = '',
        centered = true,
        compact = false,
        maxWidth = null,
    }) {
        const dialog = document.createElement('div');
        dialog.style.cssText = `position: fixed; top:0; left:0; right:0; bottom:0; background:rgba(0,0,0,0.8); display:flex; justify-content:center; align-items:center; z-index:10001; backdrop-filter:blur(5px); animation:fadeIn 0.3s ease;`;

        let contentHTML = `
            <div style="background: var(--panel); border-radius: 20px; padding: ${compact ? '15px' : '30px'}; max-width: ${maxWidth || (compact ? '400px' : '500px')}; width: 90%; border: 2px solid ${type === 'error' ? 'var(--error)' : 'var(--accent)'}; box-shadow: 0 20px 40px rgba(0,0,0,0.5); text-align: left;">
                <div style="display: flex; align-items: center; gap: 15px; margin-bottom: 20px;">
                    <span style="font-size: 40px;">${icon}</span>
                    <div>
                        <h2 style="color: ${type === 'error' ? 'var(--error)' : 'var(--accent)'}; margin: 0; font-size: 24px;">${title}</h2>
                        ${showVersion ? `<p style="color: var(--dim); margin: 5px 0 0 0;">Version ${showVersion}</p>` : ''}
                    </div>
                </div>
        `;

        // Message – apply centering if requested
        if (message) {
            const msgStyle = centered ? 'text-align: center;' : '';
            contentHTML += `<div style="color: var(--text); margin-bottom: 25px; line-height: 1.5; ${msgStyle}">${message}</div>`;
        }

        // List items – apply centering if requested
        if (listItems && listItems.length) {
            const listStyle = centered ? 'text-align: center;' : '';
            contentHTML += `<div style="margin-bottom: 25px; max-height: 400px; overflow-y: auto; padding-right: 10px; ${listStyle}">
                <ul style="list-style: none; padding: 0; margin: 0;">
                    ${listItems.map(item => `<li style="margin-bottom: 8px; color: var(--text);">${item}</li>`).join('')}
                </ul>
            </div>`;
        }

        if (bodyHTML) {
            contentHTML += `<div style="margin-bottom: 25px;">${bodyHTML}</div>`;
        }

        // Buttons
        contentHTML += `<div style="display: flex; gap: 15px; margin-top: 25px;">`;
        if (cancelText) {
            contentHTML += `<button id="modal-cancel" style="flex:1; padding:14px; background:var(--input); border:1px solid var(--border); color:var(--text); border-radius:12px; font-weight:600; cursor:pointer;">${cancelText}</button>`;
        }
        contentHTML += `<button id="modal-confirm" style="flex:1; padding:14px; background:${type === 'error' ? 'var(--error)' : 'var(--accent)'}; border:none; color:white; border-radius:12px; font-weight:800; cursor:pointer; box-shadow:${type !== 'error' ? '0 5px 15px rgba(var(--accent-rgb), 0.3)' : 'none'};">${confirmText}</button></div>`;

        contentHTML += `</div>`; // close outer div
        dialog.innerHTML = contentHTML;
        document.body.appendChild(dialog);

        return new Promise((resolve) => {
            const confirmBtn = dialog.querySelector('#modal-confirm');
            const cancelBtn = dialog.querySelector('#modal-cancel');

            confirmBtn.onclick = () => { if (onConfirm) onConfirm(); dialog.remove(); resolve(true); };
            if (cancelBtn) {
                cancelBtn.onclick = () => { dialog.remove(); if (onCancel) onCancel(); resolve(false); };
            }
        });
    }

    // Update upload button visibility
    async function updateUploadButtonVisibility() {
        const overlay = document.getElementById('upload-overlay');
        const activeSection = document.querySelector('.tool-section.active');
        const activeTabId = activeSection ? activeSection.id.replace('section-', '') : '';
        
        // Check if there are any OFPs in storage
        let hasAnyOFP = false;
        try {
            const count = await getOFPCount();
            hasAnyOFP = count > 0;
        } catch (e) {
            console.warn('Failed to get OFP count', e);
        }

        // Show overlay only when:
        // 1. No OFP is loaded (i.e., isOFPLoaded === false)
        // 2. There are no OFPs at all (hasAnyOFP === false)
        // 3. Not on Journey, Sectors, or Settings tab
        if (!isOFPLoaded && !hasAnyOFP && 
            activeTabId !== 'journey' && activeTabId !== 'sectors' && activeTabId !== 'settings' && activeTabId !== 'assigned') {
            overlay.classList.remove('hidden');
        } else {
            overlay.classList.add('hidden');
        }
        
        // Also handle empty states in specific tabs (optional)
        updateEmptyStates();
    }

    window.goToAssignedAndActivate = function() {
        const assignedBtn = document.querySelector('.nav-btn[data-tab="assigned"], .nav-btn[onclick*="assigned"]');
        if (assignedBtn) {
            if (typeof window.showTab === 'function') {
                window.showTab('assigned', assignedBtn);
            } else {
                assignedBtn.click();
            }
        }
    };

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

    // Hides or makes OFP Upload button visible
    function setOFPLoadedState(loaded) {
        isOFPLoaded = loaded;
        updateUploadButtonVisibility();
        
        // Update the Paper Flight Plan tab display
        if (loaded) {
            const pdfContainer = document.getElementById('pdf-render-container');
            if (pdfFallbackElement) {
                // Reset to original fallback content
                pdfFallbackElement.innerHTML = `
                    No OFP uploaded yet
                `;
                pdfFallbackElement.style.display = 'flex';
            }
            if (pdfContainer) pdfContainer.style.display = 'block';
        }
    }

    // Day/Night Mode
    window.toggleTheme = function() {
        const html = document.documentElement;
        const themeButton = document.querySelector('.theme-toggle');
        
        const currentTheme = html.getAttribute('data-theme');
        
        if (currentTheme === 'dark') {
            // Going to light mode
            html.setAttribute('data-theme', 'light');
            if(themeButton) {
                themeButton.textContent = 'Night Mode';
            }
            localStorage.setItem('data-theme', 'light');
        } else {
            // Going to dark mode
            html.setAttribute('data-theme', 'dark');
            if(themeButton) {
                themeButton.textContent = 'Day Mode';
            }
            localStorage.setItem('data-theme', 'dark');
        }
    };

    // SECTORS TAB - Render the OFP table in the Sectors tab
    window.renderOFPMangerTable = async function() {
        try {
            const tbody = document.getElementById('ofp-manager-tbody');
            if (!tbody) return;

            const ofps = await getCachedOFPs();
            const filterText = document.getElementById('ofp-search-input')?.value.toLowerCase() || '';
            const activeId = localStorage.getItem('activeOFPId');

            if (ofps.length === 0) {
                tbody.innerHTML = `<tr><td colspan="9" style="text-align: center; padding: 30px; color: var(--dim);">No OFPs uploaded yet.</td></tr>`;
                return;
            }

            const filtered = ofps.filter(ofp => {
                if (!filterText) return true;
                const flight = (ofp.flight || '').toLowerCase();
                const date = (ofp.date || '').toLowerCase();
                const dep = (ofp.departure || '').toLowerCase();
                const dest = (ofp.destination || '').toLowerCase();
                return flight.includes(filterText) || date.includes(filterText) || dep.includes(filterText) || dest.includes(filterText);
            });

            if (filtered.length === 0) {
                tbody.innerHTML = `<tr><td colspan="9" style="text-align: center; padding: 30px; color: var(--dim);">No matching OFPs found.</td></tr>`;
                return;
            }

            tbody.innerHTML = filtered.map(ofp => {
                const flight = ofp.flight || '—';
                const date = ofp.date || '—';
                const dep = ofp.departure || '—';
                const dest = ofp.destination || '—';
                const isActive = String(ofp.id) === String(activeId);

                let statusBadge = '';
                if (ofp.finalized) {
                    statusBadge = `<span class="status-badge status-finalized">✓ Finalized</span>`;
                } else {
                    statusBadge = `<span class="status-badge ${isActive ? 'status-active' : 'status-inactive'}">
                        ${isActive ? '✓ Active' : 'Inactive'}
                    </span>`;
                }

                const activateDisabled = ofp.finalized || isActive;
                const activateTitle = ofp.finalized 
                    ? 'Cannot activate – OFP is finalized' 
                    : (isActive ? 'Already active' : 'Activate this OFP');

                return `
                    <tr data-ofp-id="${ofp.id}" ${isActive ? 'class="active-ofp-row"' : ''}>
                        <td><strong>${sanitizeHTML(flight)}</strong></td>
                        <td>${sanitizeHTML(date)}</td>
                        <td>${sanitizeHTML(dep)}</td>
                        <td>${sanitizeHTML(dest)}</td>
                        <td>${sanitizeHTML(ofp.tripTime || '—')}</td>
                        <td>${sanitizeHTML(ofp.maxSR || '—')}</td>
                        <td>${sanitizeHTML(ofp.requestNumber || '—')}</td>
                        <td>${statusBadge}</td>
                        <td style="white-space: nowrap;">
                            
                            ${ofp.finalized ? 
                                `<button onclick="downloadSavedOFP(${ofp.id})" 
                                        class="btn-icon download" 
                                        title="Download Logged OFP">
                                    ⬇️
                                </button>` : 
                                `<button class="btn-icon download" disabled style="opacity:0.3" 
                                        title="Finalize OFP first">
                                    ⬇️
                                </button>`
                            }
                            
                            <button onclick="deleteOFP(${ofp.id})" 
                                    class="btn-icon delete" 
                                    title="Delete OFP">
                                🗑️
                            </button>
                        </td>
                    </tr>
                `;
            }).join('');
        } catch (error) {
            const tbody = document.getElementById('ofp-manager-tbody');
            if (tbody) {
                tbody.innerHTML = `<tr><td colspan="9" style="text-align: center; padding: 30px; color: var(--error);">
                    Error loading OFPs: ${sanitizeHTML(error.message)}
                </td></tr>`;
            }
        }
    };

    function initFileManagerTabs() {
        const tabOfp = document.getElementById('tab-ofp');
        const tabJourney = document.getElementById('tab-journey');
        const ofpContainer = document.getElementById('ofp-table-container');
        const journeyContainer = document.getElementById('journey-table-container');

        if (!tabOfp || !tabJourney || !ofpContainer || !journeyContainer) {
            console.warn('File Manager tab elements not found');
            return;
        }

        // Set initial state
        ofpContainer.hidden = false;
        journeyContainer.hidden = true;
        tabOfp.classList.add('active');
        tabJourney.classList.remove('active');

        // Remove old listeners (clone & replace)
        const newTabOfp = tabOfp.cloneNode(true);
        const newTabJourney = tabJourney.cloneNode(true);
        tabOfp.parentNode.replaceChild(newTabOfp, tabOfp);
        tabJourney.parentNode.replaceChild(newTabJourney, tabJourney);

        newTabOfp.addEventListener('click', () => {
            newTabOfp.classList.add('active');
            newTabJourney.classList.remove('active');
            ofpContainer.hidden = false;
            journeyContainer.hidden = true;
            renderOFPMangerTable();
        });

        newTabJourney.addEventListener('click', () => {
            newTabJourney.classList.add('active');
            newTabOfp.classList.remove('active');
            ofpContainer.hidden = true;
            journeyContainer.hidden = false;
            renderJourneyLogTable();
        });
    }

    // Call it after DOM is ready
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', initFileManagerTabs);
    } else {
        initFileManagerTabs();
    }

    // SECTORS TAB - After deleting, renumber orders to be consecutive (1,2,3...)
    async function renumberOFPOrders() {
        const db = await getDB();
        const tx = db.transaction("ofps", "readwrite");
        const store = tx.objectStore("ofps");

        // Use a cursor to get only id and order
        const ofpsLight = [];
        await new Promise((resolve, reject) => {
            const cursorReq = store.openCursor();
            cursorReq.onsuccess = (e) => {
                const cursor = e.target.result;
                if (cursor) {
                    ofpsLight.push({
                        id: cursor.value.id,
                        order: cursor.value.order || 0
                    });
                    cursor.continue();
                } else {
                    resolve();
                }
            };
            cursorReq.onerror = (e) => reject(e);
        });

        ofpsLight.sort((a, b) => a.order - b.order);

        // Now update each record with the new order
        for (let i = 0; i < ofpsLight.length; i++) {
            const ofp = await new Promise((res, rej) => {
                const req = store.get(ofpsLight[i].id);
                req.onsuccess = () => res(req.result);
                req.onerror = (e) => rej(e);
            });
            ofp.order = i + 1;
            store.put(ofp);
        }

        await new Promise((resolve, reject) => {
            tx.oncomplete = resolve;
            tx.onerror = (e) => reject(e.target.error);
        });
    }

    // SECTORS TAB - Search function filtering
    window.filterOFPs = function() {
        renderOFPMangerTable();
    };

    // Handle changing tabs
    window.showTab = window.showTab || function(id, btn) {
        // Standard tab switching logic
        document.querySelectorAll('.tool-section').forEach(s => s.classList.remove('active'));
        document.querySelectorAll('.nav-btn').forEach(b => b.classList.remove('active'));
        if(el('section-'+id)) el('section-'+id).classList.add('active');
        if(btn) btn.classList.add('active');
        
        if (id === 'sectors') {
            // Reset to OFP tab
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
            
            setTimeout(() => {
                renderOFPMangerTable();
                renderJourneyLogTable(); // preload journey logs but they stay hidden
            }, 100);
        }

        if (id === 'assigned') {
            loadAssignedFlights();
        }

        // Refresh ATIS/ATC mode
        if (id === 'summary') {
            const savedMode = document.body.getAttribute('data-atis-mode') || currentAtisInputMode || 'typing';
            applyInputMode(savedMode);
            setTimeout(() => {
                if (currentAtisInputMode === 'writing') {
                    if (!pads.atis.pad) initPad('atis');
                    if (!pads.atc.pad) initPad('atc');
                    // Ensure onEnd listeners
                    if (pads.atis.pad) pads.atis.pad.onEnd = () => debouncedSave();
                    if (pads.atc.pad) pads.atc.pad.onEnd = () => debouncedSave();

                } else {
                    // destroy pads if needed
                    if (pads.atis.pad) { pads.atis.pad.off(); pads.atis.pad = null; }
                    if (pads.atc.pad) { pads.atc.pad.off(); pads.atc.pad = null; }
                }
            }, 100);
        }

        // Confirm tab – restore signature from persistent storage
        if (id === 'confirm') {
            validateOFPInputs();
            setTimeout(() => {
                resizePad('main');
                restorePadDrawing('main', 'signature');
                updateEmptyStates(); 
            }, 50);
        }

        if (id === 'flight-analysis') {
            analyzeNotamsAndWeather();
        }

        // Update upload button visibility
        updateUploadButtonVisibility();
    };

    // Handle Navigation Menu
    function initializeTabNavigation() {
        const buttons = document.querySelectorAll('.nav-btn');
        
        buttons.forEach(button => {
            // Get the original onclick attribute
            const originalOnClick = button.getAttribute('onclick');
            
            // If it has an onclick attribute with showTab, use that
            if (originalOnClick && originalOnClick.includes('showTab')) {
                // Extract the tab ID from the onclick
                const match = originalOnClick.match(/showTab\('([^']+)'/);
                if (match) {
                    const tabId = match[1];
                    button.addEventListener('click', function(e) {
                        e.preventDefault();
                        window.showTab(tabId, this);
                    });
                }
            } else {
                // Fallback to data-tab attribute
                const tabId = button.getAttribute('data-tab');
                if (tabId) {
                    button.addEventListener('click', function(e) {
                        e.preventDefault();
                        if (window.showTab) {
                            window.showTab(tabId, this);
                        }
                    });
                }
            }
        });
    }

    // Update empty states in specific tabs
    async function updateEmptyStates() {
        const activeSection = document.querySelector('.tool-section.active');
        if (!activeSection) return;

        const activeTabId = activeSection.id.replace('section-', '');
        
        // --- ADD THIS LINE: Skip these tabs entirely for empty states ---
        if (['assigned', 'sectors', 'settings', 'journey'].includes(activeTabId)) {
            return; 
        }

        const container = activeSection.querySelector('.scrollable-content') || activeSection;
        
        if (!isOFPLoaded) {
            // Check if there are any OFPs in the database
            let hasAnyOFP = false;
            try {
                const count = await getOFPCount();
                hasAnyOFP = count > 0;
            } catch(e) {}

            if (hasAnyOFP) {
                container.innerHTML = `
                    <div class="empty-state">
                        <div style="font-size: 48px; margin-bottom: 20px;">📂</div>
                        <h3>No Active OFP</h3>
                        <p style="color: var(--dim); margin-bottom: 20px;">You have saved OFPs, but none are currently active.</p>
                        <button onclick="window.showTab('sectors', document.querySelector('.nav-btn[data-tab=\\'sectors\\']'))" 
                                style="background: var(--primary); color: #000; border: none; padding: 10px 20px; border-radius: 6px; font-weight: bold; cursor: pointer;">
                            Go to Sectors to Activate
                        </button>
                    </div>`;
            } else {
                container.innerHTML = `
                    <div class="empty-state">
                        <div style="font-size: 48px; margin-bottom: 20px;">✈️</div>
                        <h3>No Active OFP</h3>
                        <p style="color: var(--dim); margin-bottom: 20px;">Upload an OFP or download one from Skyplan.</p>
                        <button onclick="window.goToAssignedAndActivate()" 
                                style="background: var(--primary); color: #000; border: none; padding: 10px 20px; border-radius: 6px; font-weight: bold; cursor: pointer;">
                            Check Assigned Flights
                        </button>
                    </div>`;
            }
        }
    }
    // Handler for 'Paper Flight Plan' Tab 
    async function renderPDFPreview(pdfBytes) {
        const container = document.getElementById('pdf-render-container');
        const fallback = document.getElementById('pdf-fallback');
        
        if (!container || !pdfBytes) {
            console.error("Missing container or PDF bytes");
            return;
        }
        
        // Show loading state
        container.innerHTML = '';
        container.style.display = 'none';
        if (fallback) {
            fallback.style.display = 'flex';
            fallback.innerHTML = `
                <span style="font-size:30px; margin-bottom:10px;">⏳</span>
                <span>Loading PDF preview...</span>
            `;
        }
        
        try {
            // Get PDF quality setting
            const settings = JSON.parse(localStorage.getItem('efb_settings') || '{}');
            const pdfQuality = settings.pdfQuality || '1.0';

            // Quality multipliers (relative to device pixel ratio)
            const qualityMultipliers = {
                '0.8': 1.0,   // Low = 1x device pixel ratio (standard sharpness)
                '1.0': 1.5,   // Medium = 1.5x
                '1.5': 2.0,   // High = 2x
                '2.0': 3.0    // Maximum = 3x (very sharp, heavy memory)
            };
            const multiplier = qualityMultipliers[pdfQuality] || 1.5;

            // Base scale: device pixel ratio (ensures 1:1 mapping between canvas pixels and screen pixels)
            const deviceScale = window.devicePixelRatio || 1;
            let scale = deviceScale * multiplier;

            // Safety cap: limit the maximum scale to avoid enormous canvases (e.g., 4x for 4K screens)
            const MAX_SCALE = 5.0;
            scale = Math.min(scale, MAX_SCALE);

            // Also ensure it's at least 1.0 for basic readability
            scale = Math.max(scale, 1.0);

            // Load PDF document
            const pdf = await pdfjsLib.getDocument(pdfBytes).promise;
            const totalPages = pdf.numPages;

            // Hide fallback, show container
            if (fallback) fallback.style.display = 'none';
            container.innerHTML = '';
            container.style.display = 'block';

            // Wait a moment for container to be visible and have dimensions
            await new Promise(resolve => setTimeout(resolve, 100));

            // Create a loading progress indicator
            const progressDiv = document.createElement('div');
            progressDiv.style.cssText = `
                position: sticky;
                top: 0;
                background: var(--accent);
                color: white;
                padding: 10px;
                text-align: center;
                font-size: 14px;
                z-index: 100;
                border-radius: 5px;
                margin-bottom: 10px;
            `;
            progressDiv.textContent = `Loading pages: 0/${totalPages}`;
            container.appendChild(progressDiv);

            // Create a wrapper for all pages
            const pagesWrapper = document.createElement('div');
            pagesWrapper.style.cssText = `
                display: flex;
                flex-direction: column;
                align-items: center;
                gap: 10px;
            `;
            container.appendChild(pagesWrapper);

            // Render pages sequentially with small delays to prevent UI freeze
            for (let pageNum = 1; pageNum <= totalPages; pageNum++) {
                try {
                    // Update progress
                    progressDiv.textContent = `Loading pages: ${pageNum}/${totalPages}`;

                    // Small delay for UI responsiveness (50ms between pages)
                    if (pageNum > 1) {
                        await new Promise(resolve => setTimeout(resolve, 50));
                    }

                    const page = await pdf.getPage(pageNum);
                    const viewport = page.getViewport({ scale: scale });

                    // Create canvas for this page
                    const canvas = document.createElement('canvas');
                    const context = canvas.getContext('2d');

                    // Set canvas internal resolution
                    canvas.width = viewport.width;
                    canvas.height = viewport.height;

                    // Apply CSS for responsive sizing – always fill width
                    canvas.style.cssText = `
                        width: 100%;
                        height: auto;
                        margin-bottom: 20px;
                        background: white;
                        border: 1px solid #ccc;
                        border-radius: 4px;
                        box-shadow: 0 2px 8px rgba(0,0,0,0.1);
                        display: block;
                    `;

                    // Add page number label
                    const pageLabel = document.createElement('div');
                    pageLabel.style.cssText = `
                        font-size: 12px;
                        color: #666;
                        text-align: center;
                        margin-bottom: 5px;
                        font-family: monospace;
                        background: #f5f5f5;
                        padding: 3px 10px;
                        border-radius: 3px;
                        display: inline-block;
                    `;
                    pageLabel.textContent = `Page ${pageNum}`;

                    // Create page container
                    const pageContainer = document.createElement('div');
                    pageContainer.style.cssText = `
                        text-align: center;
                        margin-bottom: 20px;
                        width: 100%;
                    `;

                    pageContainer.appendChild(pageLabel);
                    pageContainer.appendChild(canvas);
                    pagesWrapper.appendChild(pageContainer);

                    // Render the page onto the canvas
                    await page.render({ 
                        canvasContext: context, 
                        viewport: viewport 
                    }).promise;

                } catch (pageError) {
                    console.warn(`Error rendering page ${pageNum}:`, pageError);

                    // Add error placeholder for this page
                    const errorDiv = document.createElement('div');
                    errorDiv.style.cssText = `
                        background: #fff3cd;
                        border: 1px solid #ffeaa7;
                        border-radius: 4px;
                        padding: 20px;
                        margin-bottom: 20px;
                        color: #856404;
                        text-align: center;
                        width: 100%;
                    `;
                    errorDiv.innerHTML = `<strong>Page ${pageNum}:</strong> Failed to render`;
                    pagesWrapper.appendChild(errorDiv);
                }
            }

            // Remove progress indicator
            progressDiv.remove();

            // Add completion message with quality info
            const summary = document.createElement('div');
            summary.style.cssText = `
                text-align: center;
                color: #666;
                font-size: 12px;
                margin-top: 20px;
                padding: 10px;
                border-top: 1px solid #eee;
            `;

            const qualityLabels = {
                '0.8': 'Low (Fast Rendering)',
                '1.0': 'Medium (Standard)',
                '1.5': 'High (Better Readability)',
                '2.0': 'Maximum (Best Quality)'
            };
            const qualityLabel = qualityLabels[pdfQuality] || 'Medium (Standard)';
            summary.textContent = `Rendered ${totalPages} page${totalPages !== 1 ? 's' : ''} at ${qualityLabel} (${(scale * 100).toFixed(0)}% scale)`;
            pagesWrapper.appendChild(summary);

        } catch (error) {
            console.error("Critical error rendering PDF:", error);

            if (container) {
                container.style.display = 'none';
                container.innerHTML = '';
            }

            if (fallback) {
                fallback.style.display = 'flex';
                fallback.innerHTML = `
                    <div style="text-align: center;">
                        <span style="font-size:30px; margin-bottom:10px;">❌</span>
                        <h3 style="color: var(--error);">PDF Rendering Failed</h3>
                        <p style="color: var(--dim); margin: 10px 0;">
                            ${error.message || 'Unable to process PDF file'}
                        </p>
                        <button onclick="retryPDFRender()" style="
                            margin-top: 15px;
                            padding: 10px 20px;
                            background: var(--accent);
                            color: white;
                            border: none;
                            border-radius: 6px;
                            cursor: pointer;
                        ">
                            Try Again
                        </button>
                    </div>
                `;
            }
        }
    }

    window.retryPDFRender = async function() {
        if (window.ofpPdfBytes) {
            await renderPDFPreview(window.ofpPdfBytes);
        } else {
            alert("No PDF loaded. Please upload an OFP first.");
        }
    };

    function updateUIAfterParsing() {
        // Set PIC Block Fuel display
        const elPic = document.getElementById('view-pic-block');
        if (elPic) {
            const val = blockFuelValue || 0;
            if (elPic.tagName === 'INPUT') elPic.value = val;
            else elPic.innerText = val;
        }

        runFlightLogCalculations();
        renderFuelTable();
        renderFlightLogTables();
    }

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
            
            tb.innerHTML = sorted.map(i => `<tr><td>${sanitizeHTML(i.name)}</td><td>${sanitizeHTML(i.time)}</td><td>${sanitizeHTML(i.fuel)}</td><td>${sanitizeHTML(i.remarks)}</td></tr>`).join('');
    }

    function renderFlightLogTables(forceRedraw = false) {
        // 1. Calculate the latest fuel/times
        if(typeof runFlightLogCalculations === 'function') runFlightLogCalculations(); 

        // 2. Incremental update check
        const canIncrementalUpdate = !forceRedraw && 
            typeof waypointTableCache !== 'undefined' &&
            waypointTableCache.waypoints && 
            waypointTableCache.waypoints.length === waypoints.length &&
            waypointTableCache.alternateWaypoints.length === alternateWaypoints.length &&
            (Date.now() - waypointTableCache.lastUpdate) < 1000;
        
        if (canIncrementalUpdate && typeof updateFlightLogTablesIncremental === 'function') {
            updateFlightLogTablesIncremental();
            updateAlternateTableIncremental();
            return;
        }

        // 3. Full render
        const fill = (list, id, pre) => {
            const tb = document.getElementById(id); 
            if(!tb) return;
            
            if (list.length === 0) {
                tb.innerHTML = '<tr><td colspan="13" style="text-align:center;color:gray;padding:20px">No waypoints found</td></tr>';
                return;
            }

            let rowsHtml = '';
            
            list.forEach((wp, i) => {
                // Pure 1:1 mapping. Index 0 is Waypoint 0 (Takeoff).
                const index = i;
                
                // Standard render without any ETO shifting
                rowsHtml += createWaypointRowHtml(wp, index, pre);
            });
            
            tb.innerHTML = rowsHtml;

        };
        
        fill(waypoints, 'ofp-tbody', 'o'); 
        fill(alternateWaypoints, 'altn-tbody', 'a');
    
        // Update DOM caches for fast access
        waypointATOCache = Array.from(document.querySelectorAll('[id^="o-a-"]'));
        alternateATOCache = Array.from(document.querySelectorAll('[id^="a-a-"]'));
        takeoffFuelInput = document.getElementById('o-f-0');
        waypointFuelCache = Array.from(document.querySelectorAll('[id^="o-f-"]'));
        
        waypointTableCache = {
            waypoints: [...waypoints],
            alternateWaypoints: [...alternateWaypoints],
            lastUpdate: Date.now()
        };
        
        if(typeof updateCruiseLevelForJourneyLog === 'function') updateCruiseLevelForJourneyLog();
    }

    async function renderJourneyLogTable() {
        const tbody = document.getElementById('journey-log-tbody');
        if (!tbody) return;
        try {
            const logs = await getAllJourneyLogs();
            if (!logs || logs.length === 0) {
                tbody.innerHTML = '<tr><td colspan="5" style="text-align:center; padding:20px;">No finalized journey logs.</td></tr>';
                return;
            }
            tbody.innerHTML = logs.map(log => `
                <tr>
                    <td>${sanitizeHTML(log.flight || '—')}</td>
                    <td>${sanitizeHTML(log.date || '—')}</td>
                    <td>${log.legCount || '—'}</td>
                    <td>${log.finalizedAt ? new Date(log.finalizedAt).toLocaleString() : '—'}</td>
                    <td style="white-space: nowrap;">
                        <button class="btn-icon download" onclick="downloadSavedJourneyLog(${log.id})" title="Download">⬇️</button>
                        <button class="btn-icon delete" onclick="deleteJourneyLog(${log.id})" title="Delete">🗑️</button>
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

        // Get airport codes from UI
        const depAirport = (document.getElementById('view-dep')?.innerText || '').trim().toUpperCase();
        const destAirport = (document.getElementById('view-dest')?.innerText || '').trim().toUpperCase();
        const altnAirport = (document.getElementById('view-altn')?.innerText || '').trim().toUpperCase();
        const altn2Airport = (document.getElementById('view-altn2')?.innerText || '').trim().toUpperCase();
        const eraAirport = (document.getElementById('view-era-text')?.innerText || '').trim().toUpperCase();
        const alternates = [altnAirport, altn2Airport, eraAirport].filter(code => code && /^[A-Z]{4}$/.test(code));
        const uniqueAlternates = [...new Set(alternates)];

        // Get stored METARs and runways
        const metars = window.airportMetars || {};
        const runways = window.airportRunways || {};

        // Helper to get cleaned METAR
        const getCleanMetar = (apt) => {
            if (!apt || !metars[apt]) return null;
            return metars[apt].replace(/^METAR\s+[A-Z]{4}\s+/, '');
        };

        // Group alerts by role and by airport within role
        const depAlertsByAirport = {};
        const destAlertsByAirport = {};
        const altAlertsByAirport = {};
        const otherAlerts = []; // alerts with no airport or unknown airport

        alerts.forEach(alert => {
            const airport = alert.airport ? alert.airport.toString().trim().toUpperCase() : '';
            if (!airport || !/^[A-Z]{4}$/.test(airport)) {
                otherAlerts.push(alert);
                return;
            }
            if (airport === depAirport) {
                if (!depAlertsByAirport[airport]) depAlertsByAirport[airport] = [];
                depAlertsByAirport[airport].push(alert);
            } else if (airport === destAirport) {
                if (!destAlertsByAirport[airport]) destAlertsByAirport[airport] = [];
                destAlertsByAirport[airport].push(alert);
            } else if (uniqueAlternates.includes(airport)) {
                if (!altAlertsByAirport[airport]) altAlertsByAirport[airport] = [];
                altAlertsByAirport[airport].push(alert);
            } else {
                otherAlerts.push(alert);
            }
        });

        // Sorting function for alerts within an airport
        const severityOrder = { critical: 0, warning: 1, info: 2 };
        const sortAlerts = (a, b) => {
            const sevA = severityOrder[(a.severity || '').toLowerCase()] ?? 3;
            const sevB = severityOrder[(b.severity || '').toLowerCase()] ?? 3;
            return sevA - sevB;
        };

        // Helper to render a single airport's block (runways, METAR, alerts)
        const renderAirportBlock = (apt, alertsArray) => {
        if (!apt) return '';
            alertsArray.sort(sortAlerts);
            let html = `<div class="airport-block">`;
            
            // Airport code (large, prominent)
            html += `<div class="airport-code">${apt}</div>`;
            
            // METAR second
            const metar = getCleanMetar(apt);
            if (metar) {
                html += `<div class="metar-info">${metar}</div>`;
            }
            
            // Runways third
            if (runways[apt]) {
                html += `<div class="runway-info">${runways[apt]}</div>`;
            }
            
            // Alerts last
            if (alertsArray.length > 0) {
                html += '<div class="alerts-list">';
                alertsArray.forEach(alert => {
                    const cleanType = alert.type.includes(':') ? alert.type.split(':')[1].trim() : alert.type;
                    html += `
                        <div class="alert-item ${alert.severity}">
                            <span class="alert-type">${cleanType}</span>
                            <span class="alert-message">${alert.message}</span>
                        </div>
                    `;
                });
                html += '</div>';
            }
            html += `</div>`;
            return html;
        };

        let finalHtml = '';

        // Departure
        if (depAirport) {
            finalHtml += `<h3 class="section-title">Departure Airport</h3>`;
            finalHtml += renderAirportBlock(depAirport, depAlertsByAirport[depAirport] || []);
        }

        // Destination
        if (destAirport) {
            finalHtml += `<h3 class="section-title">Destination Airport</h3>`;
            finalHtml += renderAirportBlock(destAirport, destAlertsByAirport[destAirport] || []);
        }

        // Alternates
        if (uniqueAlternates.length > 0) {
            finalHtml += `<h3 class="section-title">Alternate Airports</h3>`;
            uniqueAlternates.forEach(apt => {
                finalHtml += renderAirportBlock(apt, altAlertsByAirport[apt] || []);
            });
        }

        // Other Airports (group all remaining alerts)
        if (otherAlerts.length > 0) {
            finalHtml += `<h3 class="section-title">Other Airports</h3>`;
            // Group other alerts by airport for consistency
            const otherByAirport = {};
            otherAlerts.forEach(alert => {
                const apt = alert.airport ? alert.airport.toString().trim().toUpperCase() : 'Unknown';
                if (!otherByAirport[apt]) otherByAirport[apt] = [];
                otherByAirport[apt].push(alert);
            });
            Object.keys(otherByAirport).sort().forEach(apt => {
                finalHtml += renderAirportBlock(apt, otherByAirport[apt]);
            });
        }

        container.innerHTML = finalHtml || '<div class="info">No data.</div>';
    }

    // DRAWING FUNCTIONS //
    function attachPadOnEnd(pad, name) {
        if (!pad) return;
        const canvas = pad.canvas;
        if (!canvas) {
            console.warn(`attachPadOnEnd: canvas not found for pad ${name}`);
            return;
        }

        // Remove any existing pointer listener to avoid duplicates
        if (pad._pointerUpListener) {
            canvas.removeEventListener('pointerup', pad._pointerUpListener);
        }

        // Save function that also triggers validation for main pad
        const saveFunc = () => {
            saveState();
            if (name === 'main') {
                validateOFPInputs(); // updates button state
            }
        };

        // Primary: library's onEnd
        pad.onEnd = saveFunc;

        // Fallback: direct pointerup event
        const onPointerUp = (e) => {
            setTimeout(() => {
                if (pad && !pad.isEmpty()) {
                    saveFunc();
                }
            }, 10);
        };
        canvas.addEventListener('pointerup', onPointerUp);
        pad._pointerUpListener = onPointerUp;
    }

    function initPad(name) {
        const p = pads[name];
        if (!p) return;
        const canvas = document.getElementById(p.canvasId);
        if (!canvas) return;

        const ratio = Math.max(window.devicePixelRatio || 1, 1);
        const containerWidth = canvas.offsetWidth;
        const containerHeight = canvas.offsetHeight;

        // Fallback if hidden
        let width, height;
        if (containerWidth === 0 || containerHeight === 0) {
            const computed = getComputedStyle(canvas);
            width = parseInt(computed.width) || 200;
            height = parseInt(computed.height) || 80;
        } else {
            width = containerWidth;
            height = containerHeight;
        }

        canvas.width = width * ratio;
        canvas.height = height * ratio;

        const ctx = canvas.getContext('2d');
        ctx.setTransform(1, 0, 0, 1, 0, 0);
        ctx.scale(ratio, ratio);

        p.pad = new SignaturePad(canvas, {
            backgroundColor: 'rgba(0,0,0,0)',
            penColor: getComputedStyle(document.documentElement).getPropertyValue('--accent').trim()
        });

        // Attach onEnd and direct pointerup listener
        attachPadOnEnd(p.pad, name);

        // Restore saved drawing if any
        if (name === 'main') {
            restorePadDrawing('main', 'signature');
        } else if (name === 'atis') {
            restorePadDrawing('atis', 'front-atis-drawing');
        } else if (name === 'atc') {
            restorePadDrawing('atc', 'front-atc-drawing');
        }

        p.lastWidth = width;
        p.lastHeight = height;
        p.lastRatio = ratio;

        return p.pad;
    }

    function resizePad(name) {
        const p = pads[name];
        if (!p || !p.pad) return;
        const canvas = p.pad.canvas;
        if (!canvas) return;

        const ratio = Math.max(window.devicePixelRatio || 1, 1);
        const containerWidth = canvas.offsetWidth;
        const containerHeight = canvas.offsetHeight;

        if (containerWidth === p.lastWidth && containerHeight === p.lastHeight && ratio === p.lastRatio) {
            return;
        }

        const currentData = p.pad.isEmpty() ? null : p.pad.toDataURL();

        canvas.width = containerWidth * ratio;
        canvas.height = containerHeight * ratio;

        const ctx = canvas.getContext('2d');
        ctx.setTransform(1, 0, 0, 1, 0, 0);
        ctx.scale(ratio, ratio);

        p.pad = new SignaturePad(canvas, {
            backgroundColor: 'rgba(0,0,0,0)',
            penColor: getComputedStyle(document.documentElement).getPropertyValue('--accent').trim()
        });

        // Re‑attach onEnd
        attachPadOnEnd(p.pad, name);

        if (currentData) {
            p.pad.fromDataURL(currentData, { ratio });
        }

        p.lastWidth = containerWidth;
        p.lastHeight = containerHeight;
        p.lastRatio = ratio;
    }

    async function restorePadDrawing(padName, drawingKey) {
        const activeId = localStorage.getItem('activeOFPId');
        if (!activeId) return;

        try {
            const userData = await loadOFPUserData(Number(activeId));
            if (!userData || !userData.userInputs) return;

            let data = userData.userInputs[drawingKey];
            if (!data) {
                const backupKey = `drawing_backup_${activeId}_${drawingKey === 'front-atis-drawing' ? 'atis' : drawingKey === 'front-atc-drawing' ? 'atc' : 'signature'}`;
                data = localStorage.getItem(backupKey);
            }

            if (!data || !data.startsWith('data:image/png;base64,') || data.length < 100) return;

            const pad = pads[padName]?.pad;
            if (!pad) {
                setTimeout(() => restorePadDrawing(padName, drawingKey), 100);
                return;
            }

            // Check if canvas is visible and has dimensions
            const canvas = pad.canvas;
            if (canvas.offsetWidth === 0 || canvas.offsetHeight === 0) {
                // Canvas not ready – retry later
                setTimeout(() => restorePadDrawing(padName, drawingKey), 200);
                return;
            }

            try {
                await pad.fromDataURL(data);
                resizePad(padName);
            } catch (e) {
                console.warn(`Signature restore failed for ${padName}:`, e);
            }
        } catch (e) {
            console.error(`Failed to restore ${drawingKey}:`, e);
        }
    }

    function clearPad(padName) {
        const pad = pads[padName]?.pad;
        if (pad) {
            pad.clear();
            if (padName === 'main') {
                validateOFPInputs();
            }
            // Remove backup from localStorage
            const activeId = localStorage.getItem('activeOFPId');
            if (activeId) {
                let backupKey;
                if (padName === 'main') backupKey = `drawing_backup_${activeId}_signature`;
                else if (padName === 'atis') backupKey = `drawing_backup_${activeId}_atis`;
                else if (padName === 'atc') backupKey = `drawing_backup_${activeId}_atc`;
                if (backupKey) localStorage.removeItem(backupKey);
            }
            debouncedSave(); // save cleared state
        }
    }

    // Toggle UI and (re)create canvases
    function applyInputMode(mode) {
        // If already in this mode, skip
        if (mode === currentAtisInputMode) {
            return;
        }
        currentAtisInputMode = mode;
        const atisInput = document.getElementById('front-atis');
        const atcInput = document.getElementById('front-atc');
        const atisCanvas = document.getElementById('front-atis-canvas');
        const atcCanvas = document.getElementById('front-atc-canvas');

        if (mode === 'typing') {
            // Cancel any pending debounced save
            debouncedSave.cancel();
            // Save any pending drawing immediately
            saveState();

            // Show inputs, hide canvases
            if (atisInput) {
                atisInput.style.display = '';
                atisInput.style.visibility = 'visible';
            }
            if (atcInput) {
                atcInput.style.display = '';
                atcInput.style.visibility = 'visible';
            }
            if (atisCanvas) {
                atisCanvas.style.display = 'none';
                atisCanvas.style.visibility = 'hidden';
            }
            if (atcCanvas) {
                atcCanvas.style.display = 'none';
                atcCanvas.style.visibility = 'hidden';
            }
            // Destroy pads
            if (pads.atis.pad) { pads.atis.pad.off(); pads.atis.pad = null; }
            if (pads.atc.pad) { pads.atc.pad.off(); pads.atc.pad = null; }
        } else { // writing mode
            // Hide inputs, show canvases
            if (atisInput) {
                atisInput.style.display = 'none';
                atisInput.style.visibility = 'hidden';
            }
            if (atcInput) {
                atcInput.style.display = 'none';
                atcInput.style.visibility = 'hidden';
            }
            if (atisCanvas) {
                atisCanvas.style.display = 'block';
                atisCanvas.style.visibility = 'visible';
            }
            if (atcCanvas) {
                atcCanvas.style.display = 'block';
                atcCanvas.style.visibility = 'visible';
            }

            const activeSection = document.querySelector('.tool-section.active');
            if (activeSection && activeSection.id === 'section-summary') {
                requestAnimationFrame(() => {
                    setTimeout(() => {
                        if (!pads.atis.pad) {
                            initPad('atis');
                        } else {
                            // Re‑attach onEnd (already attached, but double‑check)
                            attachPadOnEnd(pads.atis.pad, 'atis');
                        }
                        if (!pads.atc.pad) {
                            initPad('atc');
                        } else {
                            attachPadOnEnd(pads.atc.pad, 'atc');
                            console.log('✍️ ATC pad onEnd re‑attached');
                        }
                    }, 50);
                });
            }
        }
        document.body.setAttribute('data-atis-mode', mode);
    }

    // INCREMENTAL UPDATE //
    function updateFlightLogTablesIncremental() {
        const table = el('ofp-tbody');
        if (!table) return;
        
        const rows = table.querySelectorAll('tr[data-type="o"]');
        
        waypoints.forEach((wp, i) => {
            const row = rows[i];
            if (!row) return;
            
            // Update ETO cell
            const etoCell = row.querySelector(`#o-eto-${i}`);
            if (etoCell) {
                const newEto = wp.eto || "--";
                if (etoCell.textContent !== newEto) {
                    etoCell.textContent = newEto;
                }
            }
            
            // Update calculated fuel cell
            const fuelCell = row.querySelector(`#o-calcfuel-${i}`);
            if (fuelCell) {
                const newFuel = Math.round(wp.fuel) || "-";
                if (fuelCell.textContent !== String(newFuel)) {
                    fuelCell.textContent = newFuel;
                }
            }
        });
    }

    function updateAlternateTableIncremental() {
        const table = el('altn-tbody');
        if (!table) return;
        
        const rows = table.querySelectorAll('tr[data-type="a"]');
        
        alternateWaypoints.forEach((wp, i) => {
            const row = rows[i];
            if (!row) return;
            
            // Update ETO cell
            const etoCell = row.querySelector(`#a-eto-${i}`);
            if (etoCell) {
                const newEto = wp.eto || "--";
                if (etoCell.textContent !== newEto) {
                    etoCell.textContent = newEto;
                }
            }
            
            // Update calculated fuel cell
            const fuelCell = row.querySelector(`#a-calcfuel-${i}`);
            if (fuelCell) {
                const newFuel = Math.round(wp.fuel) || "-";
                if (fuelCell.textContent !== String(newFuel)) {
                    fuelCell.textContent = newFuel;
                }
            }
        });
    }

    window.updateTakeoffTime = function(v) {
        try {
            const validated = validateTimeInputs(v, 'Takeoff Time');
            if(el('ofp-atd-in')) el('ofp-atd-in').value = validated.value;
            if(el('j-off')) el('j-off').value = validated.value;
            debouncedFullRecalc();
        } catch (error) {
            alert(error.message);
            // Revert to previous value
            const current = el('ofp-atd-in')?.value || '';
            if(el('ofp-atd-in')) el('ofp-atd-in').value = current;
            if(el('j-off')) el('j-off').value = current;
        }
    };

    window.updateAlternateETOs = function() {
        if (waypoints.length === 0 || alternateWaypoints.length === 0) return;

        const lastPrimaryIdx = waypoints.length - 1;
        
        // 1. Determine Base Time (Destination Arrival)
        let baseTimeStr = waypointATOCache[lastPrimaryIdx]?.value;
        if (!baseTimeStr) {
             // Fallback to ETO
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
        
        // We calculate the delta from the Destination (OFP totalMins is cumulative from Takeoff)
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

    function updateFloatingButtonVisibility() {
        const floatingBtn = document.getElementById('floating-upload-btn');
        const floatingGroup = document.getElementById('floating-btn-group');
        if (!floatingBtn || !floatingGroup) return;
        
        // Get current active tab
        const activeSection = document.querySelector('.tool-section.active');
        if (!activeSection) return;
        
        const activeTabId = activeSection.id.replace('section-', '');
        
        // Hide on Journey Log tab OR if OFP is already loaded
        if (activeTabId === 'journey' || isOFPLoaded) {
            floatingBtn.classList.add('hidden');
            floatingGroup.classList.add('hidden');
        } else {
            floatingBtn.classList.remove('hidden');
            floatingGroup.classList.remove('hidden');
        }
    }

    // Helper function to create HTML for a single row
    function createWaypointRowHtml(wp, i, pre) {
        const timeInput = `<input type="time" id="${pre}-a-${i}" class="input" style="padding:8px">`;
        const actFuelInput = `<input type="number" id="${pre}-f-${i}" class="input" style="width:70px; padding:8px; background:rgba(255,255,255,0.05); border:1px solid var(--border); color:var(--text); text-align:center;">`;
        const actFlInput = `<input type="number" id="${pre}-agl-${i}" class="input" maxlength="3" style="width:50px;padding:8px;text-align:center;color:var(--accent)">`;
        const notesInput = `<input type="text" id="${pre}-n-${i}" class="input" style="padding:8px; width:100%" placeholder="...">`;

        return `<tr data-index="${i}" data-type="${pre}">
            <td style="font-weight:bold">${wp.name}</td>
            <td style="font-size:12px">${wp.awy || "-"}</td>
            <td style="font-size:12px">${wp.sr || "-"}</td> 
            <td style="font-size:12px; font-weight:bold; color:var(--text)">${wp.level || "-"}</td>
            <td style="font-size:12px">${wp.track || "-"}</td>
            <td style="font-size:12px">${wp.wind || "-"}</td>
            <td style="font-size:12px">${wp.tas || "-"}</td>
            <td style="font-size:12px">${wp.gs || "-"}</td>
            <td>${notesInput}</td>
            <td id="${pre}-eto-${i}" class="eto-cell">${wp.eto || "--"}</td>
            <td>${timeInput}</td>
            <td id="${pre}-calcfuel-${i}" class="fuel-cell">${Math.round(wp.fuel) || "-"}</td>
            <td>${actFuelInput}</td>
            <td>${actFlInput}</td>
        </tr>`;
    }

    // JOURNEY LOG TAB //
    window.renderJourneyList = function() {
        const tb = el('journey-list-body');
        if(!tb) return;

        if(dailyLegs.length === 0) {
            tb.innerHTML = '<tr><td colspan="4" style="text-align:center; padding: 15px; color: #888;">No legs added.</td></tr>';
        } else {
            tb.innerHTML = dailyLegs.map((l, i) => {
                const canMoveUp = i > 0; 
                const canMoveDown = i < dailyLegs.length - 1;
                return `
                <tr>
                    <td style="text-align:center; font-weight:bold;">${i+1}</td>
                    <td>${sanitizeHTML(l['j-flt'])}</td>
                    <td>${sanitizeHTML(l['j-dep'])} - ${sanitizeHTML(l['j-dest'])}</td>
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
                            Delete
                        </button>
                    </td>
                </tr>
                `;
            }).join('');
        }
    };

    function clearJourneyInputs(transferFuel = "") {
        // 1. Clear Times
        ['j-out', 'j-off', 'j-on', 'j-in', 'j-night'].forEach(id => safeSet(id, ''));
        
        // 2. Clear Landing Type and ID
        ['j-to', 'j-ldg', 'j-ldg-type', 'j-ldg-detail'].forEach(id => safeSet(id, ''));
        
        // 3. Clear Fuel/Load
        ['j-uplift-w', 'j-uplift-vol', 'j-act-ramp', 'j-shut', 'j-slip', 'j-slip-2', 'j-adl', 'j-chl', 'j-inf', 'j-bag', 'j-cargo', 'j-mail', 'j-zfw'].forEach(id => safeSet(id, ''));
        
        // 4. Transfer 'Shutdown Fuel' to 'Inital Fuel' on the next leg
        if (transferFuel) {
            safeSet('j-init', transferFuel);
        } else {
            safeSet('j-init', '');
        }

        safeSet('j-std', '');
        safeSet('j-sta', '');

        // Reset Calculated Displays
        ['j-flight','j-block'].forEach(id => safeSet(id, '00:00'));
        ['j-calc-ramp','j-burn','j-disc'].forEach(id => safeSet(id, '0'));
    }

    window.addLeg = function() {
        // If Destination is empty, stop immediately
        const dest = el('j-dest')?.value;
        const dep = el('j-dep')?.value;
        if (!dest || !dep) {
            return alert("No legs to insert");
        }

        // Allow only maximum 4 legs
        if(dailyLegs.length >= 4) return alert("Max 4 legs.");

        // 1. Force hide tab
        const form = document.getElementById('leg-input-form');
        if (form) {
            form.style.setProperty("display", "none", "important");
        }

        // 2. Auto-calculate duty (Only on first leg)
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

        // 3. Auto-calculate night block
        const offBlock = el('j-off')?.value;
        const onBlock = el('j-in')?.value;
        
        if (offBlock && onBlock) {
            // Calculate night block time and display it in j-night-calc for reference
            const nightBlockTime = calculateNightDuty(parseTimeString(offBlock), parseTimeString(onBlock));
            safeSet('j-night-calc', nightBlockTime);
            
            // If j-night is empty, we can auto-fill it with the calculated value
            if (!el('j-night')?.value) {
                safeSet('j-night', nightBlockTime);
            }
        } else {
            safeSet('j-night-calc', '00:00');
        }

        // 4. Save current leg data
        const d = {};
        const getValue = (id) => {
            const e = el(id);
            if (!e) return "";
            return (e.tagName === 'INPUT' || e.tagName === 'SELECT' || e.tagName === 'TEXTAREA') 
                    ? e.value : (e.innerText || e.textContent);
        };

        // --- EXPANDED KEYS LIST (Captures all form and view fields) ---
        const keysToSave = [
            'j-date', 'j-std', 'j-sta', 'j-flt', 'j-reg', 'j-dep', 'j-dest', 'j-altn', 'j-out', 'j-off', 'j-on', 'j-in', 
            'j-block', 'j-flight', 'j-night', 'j-to', 'j-ldg', 'j-ldg-type', 'j-flt-alt', 
            'j-ldg-detail', 'j-init', 'j-uplift-w', 'j-calc-ramp', 'j-act-ramp', 'j-shut', 
            'j-burn', 'j-uplift-vol', 'j-slip', 'j-slip-2', 'j-disc', 'j-adl', 'j-chl', 
            'j-inf', 'j-cargo', 'j-mail', 'j-bag', 'j-zfw', 'j-date', 'j-std', 'j-sta',
            // View / Display Elements
            'view-date', 'view-reg', 'view-dep', 'view-arr', 'view-std-text', 'view-sta-text'
        ];

        keysToSave.forEach(k => {
            d[k] = getValue(k);
        });

        // Cross-map keys so both 'j-' and 'view-' references exist inside the saved object
        d['view-date'] = d['view-date'] || d['j-date'];
        d['view-reg'] = d['view-reg'] || d['j-reg'];
        d['view-dep'] = d['view-dep'] || d['j-dep'];
        d['view-arr'] = d['view-arr'] || d['j-dest'];
        d['view-std-text'] = d['view-std-text'] || d['j-std'];
        d['view-sta-text'] = d['view-sta-text'] || d['j-sta'];

        d['j-date'] = d['j-date'] || d['view-date'];
        d['j-arr'] = d['j-arr'] || d['view-arr'] || d['j-dest'];
        d['j-atd'] = d['j-out'];                         // ATD = actual off-block time
        d['j-sta'] = d['view-sta-text'] || d['j-sta'];   // STA = scheduled arrival (from view)

        // Get the nightTime value from the j-night input
        const nightTime = d['j-night'] || "00:00";
        d.nightTime = nightTime; 
        
        dailyLegs.push(d);
        
        // 6. Recalculate Maximum FDP
        setTimeout(() => {
            if (typeof recalcMaxFDP === 'function') {
                recalcMaxFDP();
            }
        }, 100);

        // 7. Prepare next Leg
        renderJourneyList();
        const nextInitFuel = d['j-shut'];
        clearJourneyInputs(nextInitFuel);
        safeSet('j-dep', '');   
        safeSet('j-dest', '');
        
        // 8. Auto-save
        saveState();
    };

    window.moveLeg = function(index, direction) {
        const newIndex = index + direction;
        
        // Safety check boundaries
        if (newIndex < 0 || newIndex >= dailyLegs.length) return;

        // 1. Swap the elements in the array
        const temp = dailyLegs[index];
        dailyLegs[index] = dailyLegs[newIndex];
        dailyLegs[newIndex] = temp;

        // 2. Recalculate duty logic
        if (dailyLegs.length > 0) {
            const firstLeg = dailyLegs[0];

            // 2.1 Calculate new Duty Start/Max based on the NEW first leg's data
            const newDutyValues = calculateDutyValues(
                firstLeg['j-std'], 
                firstLeg['j-flt'], 
                firstLeg['j-dep'], 
                firstLeg['j-dest']
            );

            // 2.2 Update the screen inputs
            safeSet('j-duty-start', newDutyValues.fc);
            safeSet('j-cc-duty-start', newDutyValues.cc);
            safeSet('j-max-fdp', newDutyValues.max);

            // 2.3 Update the global variable used for calculations
            dutyStartTime = parseTimeString(newDutyValues.fc);
            const maxLimitMins = parseTimeString(newDutyValues.max);

            // 2.4 Update hidden cabin crew max FDP
            const ccMaxHidden = document.getElementById('j-cc-max-fdp-hidden');
            if (ccMaxHidden) {
                ccMaxHidden.value = newDutyValues.ccMax;
            }
        }

        // 3. Recalculate both max FDPs
        if (typeof recalcMaxFDP === 'function') recalcMaxFDP();
        renderJourneyList();
        saveState();
    };

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
            safeText('j-duty-start', '00:00'); 
            dutyStartTime = null; 
        }

        // 4. Show the Journey form and scroll to the form so the user sees it
        document.getElementById('leg-input-form').style.display = 'block';
        document.getElementById('leg-input-form').scrollIntoView({ behavior: 'smooth' });
        
        alert("Leg loaded. Make changes and click '+ Add Leg'.");
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
            // Show the Input form again
            const legForm = document.getElementById('leg-input-form');
            if(legForm) legForm.style.display = 'block';
        }
        renderJourneyList(); 
        saveState();
    };

    // Update Cruise Level for Journey Leg
    window.updateCruiseLevelForJourneyLog = function() {
        let finalLevel = "";
        // 1. Default: Find Planned Level from OFP
        if(waypoints.length > 0) {
            const cruiseWP = waypoints.find(w => /^\d{3}$/.test(w.level) && w.level !== "000");
            if(cruiseWP) finalLevel = "FL" + cruiseWP.level;
        }

        // 2. Priority: Check if User entered an Actual Level
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

    // Transfer Last Waypoint for current Leg
    window.syncLastWaypoint = function() {
        if(waypoints.length === 0) return;
        const lastIdx = waypoints.length - 1;
        const wp = waypoints[lastIdx];

        // 1. Handle Landing Time (ATO or ETO)
        const lastATO = waypointATOCache[lastIdx]?.value;
        const currentETO = wp.eto ? (wp.eto.substring(0,2) + ":" + wp.eto.substring(2,4)) : "";
        
        // Priority: Actual Time > Calculated Estimate
        const finalTime = lastATO || currentETO;
        if(finalTime && el('j-on')) el('j-on').value = finalTime;

        // 2. Handle Shutdown Fuel (AFOB or EFOB)
        const lastFuel = waypointFuelCache[lastIdx]?.value;
        const currentEFOB = Math.round(wp.fuel) || "";

        // Priority: Actual Fuel > Calculated Estimate
        const finalFuel = lastFuel || currentEFOB;
        if(finalFuel && el('j-shut')) el('j-shut').value = finalFuel;

        // 3. Trigger Journey Log math
        calculateTripTimeForJourneyLog(); 
        calculateFuelForJourneyLog();
    };

    // Helper to set hidden CC max FDP
    function setCCMaxFDP(value) {
        const ccMaxHidden = document.getElementById('j-cc-max-fdp-hidden');
        if (ccMaxHidden) {
            ccMaxHidden.value = value || "00:00";
        }
    }

// ==========================================
// 11. Download Managment
// ==========================================
    
    function generateOFPDFilename(flight, date, suffix = '') {
        // Clean flight: remove any non‑alphanumeric except hyphen
        let cleanFlight = (flight || 'OFP').replace(/[^a-zA-Z0-9-]/g, '');
        if (cleanFlight === '') cleanFlight = 'OFP';
        
        // Clean date: replace / with - and remove invalid chars
        let cleanDate = (date || '').replace(/\//g, '-').replace(/[^a-zA-Z0-9-]/g, '');
        if (cleanDate === '') cleanDate = 'nodate';
        
        let filename = `${cleanFlight}_${cleanDate}`;
        if (suffix) filename += `_${suffix}`;
        return filename + '.pdf';
    }

    // Share PDF
    async function sharePdf(pdfBytes, filename, subject, body) {
        const blob = new Blob([pdfBytes], { type: 'application/pdf' });
        const file = new File([blob], filename, { type: 'application/pdf' });

        // Optional: copy email to clipboard (silent fail if not possible)
        try {
            await navigator.clipboard.writeText("ofp@airastana.com");
        } catch (err) {
            console.log("Clipboard write failed", err);
        }

        // Try native share if supported and files can be shared
        if (navigator.canShare && navigator.canShare({ files: [file] })) {
            try {
                await navigator.share({
                    files: [file],
                    title: subject,
                    text: body || subject
                });
                return; // success, exit
            } catch (err) {
                console.log("Share cancelled or failed, falling back to download", err);
                // fall through to download
            }
        }
        // Fallback: direct download
        downloadBlob(pdfBytes, filename);
    }

    // Download PDF
    function downloadBlob(bytes, name) {
        const link = document.createElement('a');
        link.href = URL.createObjectURL(new Blob([bytes], {type:'application/pdf'}));
        link.download = name;
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
    }


// ==========================================
// 9. Journey Log Download
// ==========================================

    // Loads the built-in template from the app's folder, bypassing cache
    async function loadBuiltInTemplate() {
        try {
            // The '?v=' + timestamp forces the browser to fetch the newest file
            const response = await fetch('./journey_log_template.pdf?v=' + new Date().getTime(), {
                cache: 'no-store' // Prevents caching
            });
            
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }
            
            return await response.arrayBuffer();
        } catch (error) {
            console.error("Failed to load built-in template:", error);
            alert("Could not load the built-in Journey Log template. Ensure 'journey_log_template.pdf' is in the app folder.");
            return null;
        }
    }

    async function findTextInPDF(pdfBytes, searchText) {
        const loadingTask = pdfjsLib.getDocument(pdfBytes);
        const pdf = await loadingTask.promise;
        const page = await pdf.getPage(1);
        const textContent = await page.getTextContent();
        
        for (const item of textContent.items) {
            if (item.str && item.str.toLowerCase().includes(searchText.toLowerCase())) {
                return item.transform; // [scaleX, skewX, skewY, scaleY, x, y]
            }
        }
        return null; // not found
    }

    async function requestJourneyLogTemplate() {
        const confirmed = await createModal({
            title: 'Journey Log Template Required',
            message: '<div style="text-align:center;">Please select the blank Journey Log PDF template.<br><br>This is the official form that will be filled with your leg data.</div>',
            confirmText: 'Select Template',
            cancelText: 'Cancel',
            type: 'info',
            icon: '📄',
            centered: true
        });

        if (!confirmed) return null;

        return new Promise((resolve) => {
            const input = document.createElement('input');
            input.type = 'file';
            input.accept = 'application/pdf';
            input.style.display = 'none';
            document.body.appendChild(input);

            input.addEventListener('change', async () => {
                const file = input.files[0];
                
                // CLEANUP IMMEDIATELY to free DOM reference
                if (document.body.contains(input)) {
                    document.body.removeChild(input);
                }

                if (file) {
                    try {

                        await saveJourneyTemplateToDB(file);
                        const buffer = await file.arrayBuffer();
                        resolve(buffer); 
                    } catch (e) {
                        alert("Error saving file: " + e.message);
                        resolve(null);
                    }
                } else {
                    resolve(null);
                }
            });

            input.click();
        });
    }

window.downloadJourneyLog = async function(mode = 'download') {
    try {
        await logSecurityEvent('JOURNEY_LOG_GENERATE', {
            mode: mode,
            legCount: dailyLegs.length,
            timestamp: new Date().toISOString()
        });
        
        // If no template is loaded, load the built-in one
        if (!journeyLogTemplateBytes || journeyLogTemplateBytes.byteLength === 0) {
            const templateBuffer = await loadBuiltInTemplate();
            if (!templateBuffer) {
                if (typeof isFinalizingJourneyLog !== 'undefined') isFinalizingJourneyLog = false;
                return; // user cancelled or failed to load
            }
            journeyLogTemplateBytes = templateBuffer; 
        }

        const debugSearches = ['STA', 'ATD', 'ATA', 'STD', 'Blk', 'Flt', 'MA', 'DETAIL', 'DUTY'];
for (const s of debugSearches) {
    const res = await findTextInPDF(journeyLogTemplateBytes, s);
    console.log(`findTextInPDF("${s}"):`, res ? `Found at X=${res[4]}, Y=${res[5]}` : 'NOT FOUND');
}
        if (dailyLegs.length === 0) return alert("No legs to print.");

        // Generate PDF
        const pdfDoc = await PDFLib.PDFDocument.load(journeyLogTemplateBytes);
        const page = pdfDoc.getPages()[0];
        const font = await pdfDoc.embedFont(PDFLib.StandardFonts.HelveticaBold);
        
        const isIpadMode = el('chk-ipad-mode') ? el('chk-ipad-mode').checked : false;
        if(!isIpadMode) page.setRotation(PDFLib.degrees(0));

        // DYNAMIC OFFSET CALCULATION
        const templateRows = parseInt(document.getElementById('j-template-rows')?.value || "4");
        const standardRows = 4;
        const rowGap = JOURNEY_CONFIG?.rowGap || 15; 
        const nameFontSize = JOURNEY_CONFIG?.fontSize || 8; 

        let FUEL_OFFSET = (standardRows - templateRows) * rowGap;
        let CREW_OFFSET = (standardRows - templateRows) * rowGap * 2;

        // --- POPULATE CREW NAMES DYNAMICALLY BEFORE DRAWING HEADERS ---
        const settings = JSON.parse(localStorage.getItem('efb_settings') || '{}');
        const shouldHideAll = settings.hideAllDuty === true;
        
        if ((!window.crewData || window.crewData.length === 0) && !shouldHideAll) {
            try {
                const token = await getValidSkyplanToken();
                if (token) {
                    let extId = window.currentExternalFlightId;
                    if (!extId) {
                        const fltRaw = el('j-flt')?.value || '';
                        const dateRaw = el('j-date')?.value || '';
                        const depRaw = dailyLegs[0] ? dailyLegs[0]['j-dep'] : '';
                        
                        if (fltRaw && dateRaw && depRaw) {
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
                console.error("Failed to fetch crew manifest for PDF printing:", e);
            }
        }
        
        const activeCrewList = window.crewData || [];
        // --------------------------------------------------------------

        // HEADERS (L/T & Captain Name)
        const { width, height } = page.getSize();
        const catAnchor = await findTextInPDF(journeyLogTemplateBytes, "L/T");
        if (catAnchor) {
            const [sx, , , , catX, catY] = catAnchor;
            page.drawText("75/125", { x: catX - 30, y: catY, size: nameFontSize, font: font, color: PDFLib.rgb(0,0,0) });
        }

        let captainNameStr = localStorage.getItem('efb_captain_name') || "";
        if (!captainNameStr && activeCrewList.length > 0) {
            const cap = activeCrewList.find(m => m.Position === 'CP');
            if (cap) captainNameStr = `${cap.FirstName || ''} ${cap.LastName || ''}`.trim().toUpperCase();
        }

        if (captainNameStr) {
            const capAnchor = await findTextInPDF(journeyLogTemplateBytes, "Captain/KBC:");
            if (capAnchor) {
                const [sx, , , , capX, capY] = capAnchor;
                page.drawText(captainNameStr, { x: capX + 30, y: capY, size: nameFontSize, font: font, color: PDFLib.rgb(0,0,0) });
            } else {
                page.drawText(captainNameStr, { x: width - 600, y: height - 40, size: 10, font: font, color: PDFLib.rgb(0,0,0) });
            }
        }

        const headers = JOURNEY_CONFIG?.headers || {};
        Object.keys(headers).forEach(id => {
            const val = el(id)?.value;
            const cfg = headers[id];
            if(val && cfg) page.drawText(String(val).toUpperCase(), { x: cfg.x, y: cfg.y, size: JOURNEY_CONFIG.fontSize, font: font, color: PDFLib.rgb(0,0,0) });
        });


        // ====================================================================
        // 1. FULLY DYNAMIC TOP HEADERS (Date, Flight, Reg, Dep, Arr, STD, STA)
        // ====================================================================
        const dynamicHeaders = [
            { idName: 'date', search: 'Date', shiftX: -10, keys: ['j-date'] },
            { idName: 'flt', search: 'flight', shiftX: -8, keys: ['j-flt'] },
            { idName: 'reg', search: 'Ac.Reg', shiftX: -5, keys: ['j-reg'] },
            { idName: 'dep', search: 'Dep', shiftX: -5, keys: ['j-dep'] },
            { idName: 'arr', search: 'Arr', shiftX: -5, keys: ['j-arr'] },
            { idName: 'std', search: 'STD', shiftX: -5, keys: ['j-std'] },
            { idName: 'sta', search: 'STA', shiftX: -5, keys: ['j-sta'] }
        ];

        const headerDrop = 16; 

        for (const header of dynamicHeaders) {
            const textAnchor = await findTextInPDF(journeyLogTemplateBytes, header.search) || 
                               await findTextInPDF(journeyLogTemplateBytes, header.search.toUpperCase()) ||
                               await findTextInPDF(journeyLogTemplateBytes, header.search.charAt(0).toUpperCase() + header.search.slice(1));

            if (textAnchor) {
                const [,,,, anchorX, anchorY] = textAnchor;

                dailyLegs.forEach((leg, idx) => {
                    if (idx >= templateRows) return;

                    let val = undefined;
                    for (const key of header.keys) {
                        if (leg[key] !== undefined && leg[key] !== null && leg[key] !== "") {
                            val = leg[key];
                            break;
                        }
                    }

                    if ((val === undefined || val === null || val === "") && idx === 0) {
                        for (const key of header.keys) {
                            const domEl = document.getElementById(key);
                            if (domEl) {
                                val = domEl.value !== undefined ? domEl.value : (domEl.innerText || domEl.textContent);
                                if (val) break;
                            }
                        }
                    }

                    if (val !== undefined && val !== null && String(val).trim() !== "") {
                        const printX = anchorX + header.shiftX;
                        const printY = anchorY - headerDrop - (idx * JOURNEY_CONFIG.rowGap);
                        
                        page.drawText(String(val).trim().toUpperCase(), { 
                            x: printX, 
                            y: printY, 
                            size: JOURNEY_CONFIG.fontSize || 8, 
                            font: font, 
                            color: PDFLib.rgb(0,0,0) 
                        });
                    }
                });
            }
        }


        // ====================================================================
        // 2. FULLY DYNAMIC FLIGHT LOG & FUEL COLUMNS (using logColumnDefs)
        // ====================================================================
        const logColumnDefs = [
            // Main
            { search: 'ATD',        keys: ['j-atd'],        shiftX: -5,  category: 'main' },
            { search: 'ATA',        keys: ['j-in'],         shiftX: -5,  category: 'main' },
            { search: 'Off-Block',  keys: ['j-out'],        shiftX: -5,  category: 'main' },
            { search: 'TKOF',       keys: ['j-off'],        shiftX: -5,  category: 'main' },
            { search: 'TDWN',       keys: ['j-on'],         shiftX: -5,  category: 'main' },
            { search: 'Blk',        keys: ['j-block'],      shiftX: -5,  category: 'main' },
            { search: 'Flt',        keys: ['j-flight'],     shiftX: -5,  category: 'main' },
            { search: 'NtBLK',      keys: ['j-night'],      shiftX: -5,  category: 'main' },
            { search: 'TO',         keys: ['j-to'],         shiftX: -5,  category: 'main' },
            { search: 'LD',        keys: ['j-ldg'],        shiftX: -5,  category: 'main' },
            { search: 'MA',         keys: ['j-ldg-type'],   shiftX: -5,  category: 'main' },
            { search: 'FlAlt',      keys: ['j-flt-alt'],    shiftX: -5,  category: 'main' },
            { search: 'DETAIL',     keys: ['j-ldg-detail'], shiftX: -5,  category: 'main' },
            // Fuel
            { search: 'Init',       keys: ['j-init'],       shiftX: -5,  category: 'fuel' },
            { search: 'UplfW',      keys: ['j-uplift-w'],   shiftX: -5,  category: 'fuel' },
            { search: 'UplfV',      keys: ['j-uplift-vol'], shiftX: -5,  category: 'fuel' },
            { search: 'Calc Ramp',  keys: ['j-calc-ramp'],  shiftX: -2,  category: 'fuel' },
            { search: 'Act Ramp',   keys: ['j-act-ramp'],   shiftX: -2,  category: 'fuel' },
            { search: 'Stdn',       keys: ['j-shut'],       shiftX: -5,  category: 'fuel' },
            { search: 'Burn',       keys: ['j-burn'],       shiftX: -5,  category: 'fuel' },
            { search: 'Fuel Disc',  keys: ['j-disc'],       shiftX: -2,  category: 'fuel' },
            { search: 'Slip 1',     keys: ['j-slip'],       shiftX: -5,  category: 'fuel' },
            { search: 'Slip 2',     keys: ['j-slip-2'],     shiftX: -5,  category: 'fuel' },
            // Loadsheet
            { search: 'ADL',     keys: ['j-adl'],     shiftX: -5,  category: 'fuel' },
            { search: 'CHL',     keys: ['j-chl'],     shiftX: -5,  category: 'fuel' },
            { search: 'INF',     keys: ['j-inf'],     shiftX: -5,  category: 'fuel' },
            { search: 'Cargo',   keys: ['j-cargo'],     shiftX: -5,  category: 'fuel' },
            { search: 'Mail',    keys: ['j-mail'],     shiftX: -5,  category: 'fuel' },
            { search: 'BAG',    keys: ['j-bag'],     shiftX: -5,  category: 'fuel' },
            { search: 'ZFW',    keys: ['j-zfw'],     shiftX: -5,  category: 'fuel' },
        ];

        const crewColumnDefs = [
            { search: 'DUTY',      key: 'j-duty-operating' },
            { search: 'Duty time',     key: 'j-duty-time' },
            { search: 'Night duty',   key: 'j-duty-night' },
            { search: 'Alwd. time', key: 'j-duty-allowed' },
            { search: 'LEGS', key: 'sectors-total' },
        ];

        // --- Find crew column positions ---
        const crewCols = {};
        for (const cDef of crewColumnDefs) {
            const anchor = await findTextInPDF(journeyLogTemplateBytes, cDef.search) ||
                        await findTextInPDF(journeyLogTemplateBytes, cDef.search.toUpperCase());
            if (anchor) {
                const [, , , , crewX] = anchor;
                crewCols[cDef.key] = crewX;
            }
        }

        // Determine Y baselines for main and fuel groups
        let mainBaselineY = null;
        let fuelBaselineY = null;

        const mainRefAnchor = await findTextInPDF(journeyLogTemplateBytes, 'ATD') ||
                              await findTextInPDF(journeyLogTemplateBytes, 'TKOF') ||
                              await findTextInPDF(journeyLogTemplateBytes, 'Off-Block');
        if (mainRefAnchor) {
            const [, , , , , mainY] = mainRefAnchor;
            mainBaselineY = mainY - headerDrop;
        }

        const fuelRefAnchor = await findTextInPDF(journeyLogTemplateBytes, 'Init') ||
                              await findTextInPDF(journeyLogTemplateBytes, 'UplfW') ||
                              await findTextInPDF(journeyLogTemplateBytes, 'UplfV');
        if (fuelRefAnchor) {
            const [, , , , , fuelY] = fuelRefAnchor;
            fuelBaselineY = fuelY - headerDrop;
        }

        // Fallback Y positions if nothing found (adjust these to your template)
        if (mainBaselineY === null) mainBaselineY = 680;
        if (fuelBaselineY === null) fuelBaselineY = 480;

        // Draw each dynamic column for every leg
        for (const colDef of logColumnDefs) {
            const anchor = await findTextInPDF(journeyLogTemplateBytes, colDef.search) ||
                           await findTextInPDF(journeyLogTemplateBytes, colDef.search.toUpperCase());
            if (!anchor) continue;   // skip columns not found in the PDF

            const [, , , , headerX, headerY] = anchor;
            const colX = headerX + (colDef.shiftX || 0);
            const baselineY = colDef.category === 'fuel' ? fuelBaselineY : mainBaselineY;
            if (baselineY === null) continue;

            dailyLegs.forEach((leg, idx) => {
                if (idx >= templateRows) return;

                let val;
                for (const key of colDef.keys) {
                    if (leg[key] !== undefined && leg[key] !== null && leg[key] !== "") {
                        val = leg[key];
                        break;
                    }
                }
                // First leg fallback to DOM if missing
                if ((val === undefined || val === null || val === "") && idx === 0) {
                    const domEl = document.getElementById(colDef.keys[0]);
                    if (domEl) {
                        val = domEl.value !== undefined ? domEl.value : (domEl.innerText || domEl.textContent);
                    }
                }

                if (val !== undefined && val !== null && String(val).trim() !== "") {
                    const rowY = baselineY - (idx * JOURNEY_CONFIG.rowGap);
                    page.drawText(String(val).trim().toUpperCase(), {
                        x: colX,
                        y: rowY,
                        size: JOURNEY_CONFIG.fontSize || 8,
                        font: font,
                        color: PDFLib.rgb(0,0,0)
                    });
                }
            });
        }

        // ====================================================================
        // 3. SIGNATURE
        // ====================================================================
        const sigAnchor = await findTextInPDF(journeyLogTemplateBytes, "Captain's Signature");

        if (sigAnchor) {
            const [sx, , , , x, y] = sigAnchor; 
            const sigX = x + 120; 
            const sigY = y - 15;  

            if (pads?.main?.pad && !pads.main.pad.isEmpty()) {
                try {
                    const sigImageBase64 = pads.main.pad.toDataURL();
                    const sigImage = await pdfDoc.embedPng(sigImageBase64);
                    page.drawImage(sigImage, {
                        x: sigX,
                        y: sigY,
                        width: 200,
                        height: 50,
                    });
                } catch (sigError) {
                    console.warn("Signature embedding skipped/failed:", sigError);
                }
            }
        }

        // ====================================================================
        // 4. CREW DUTY & NAME DATA
        // ====================================================================
        // ---- Find the Y position of the crew header row ----
        let crewBaselineY = null;
        const crewHeaderAnchor =
            await findTextInPDF(journeyLogTemplateBytes, 'DUTY') ||
            await findTextInPDF(journeyLogTemplateBytes, 'OP')   ||
            await findTextInPDF(journeyLogTemplateBytes, 'Name');
        if (crewHeaderAnchor) {
            const [, , , , , headerY] = crewHeaderAnchor;
            crewBaselineY = headerY - headerDrop;   // first data row right below the header
        }

        if (crewBaselineY === null) crewBaselineY = 333;

        const crewStart = crewBaselineY;
        const crewGap = JOURNEY_CONFIG?.rowGap || 17;   // use the same gap as the other tables    
        
        const numFC = parseInt(el('j-fc-count')?.value || 2);
        const numCC = parseInt(el('j-cc-count')?.value || 4);
        const totalRows = numFC + numCC;
        // Filter out any empty rows just in case, then count the remaining valid legs
        const validLegsCount = dailyLegs.filter(leg => leg['j-flt'] || leg['j-dep']).length;

        // Create a string that repeats 'x' for every valid leg (e.g., 4 legs = "xxxx")
        const sectorsTotalString = 'x'.repeat(validLegsCount);

        const fcDutyStartStr = el('j-duty-start')?.value || "00:00";
        const ccDutyStartStr = el('j-cc-duty-start')?.value || "00:00";
        const fcMaxFDPStr = el('j-max-fdp')?.value || "00:00"; 
        const ccMaxFDPInput = document.getElementById('j-cc-max-fdp-hidden');
        const ccMaxFDPStr = ccMaxFDPInput ? ccMaxFDPInput.value : "00:00";
        const fcStartMins = parseTimeString(fcDutyStartStr);
        const ccStartMins = parseTimeString(ccDutyStartStr);
        const lastLeg = dailyLegs[dailyLegs.length - 1];
        const onBlocksMins = lastLeg ? parseTimeString(lastLeg['j-in']) : 0;

        const getFDP = (startMins) => {
            if(!onBlocksMins && onBlocksMins !== 0) return ""; 
            let diff = onBlocksMins - startMins;
            if(diff < 0) diff += 1440; 
            return minsToTime(diff);
        };

        // DRAW CREW ROWS (DUTY + NAMES)
        for(let i = 0; i < totalRows; i++) {
            if (shouldHideAll) continue;

            const y = crewStart - (i * crewGap);
            const isFlightCrew = (i < numFC);
            const myStart = isFlightCrew ? fcStartMins : ccStartMins;
            const myMaxFDP = isFlightCrew ? fcMaxFDPStr : ccMaxFDPStr;
            const myFDP = getFDP(myStart);
            const myNightDuty = getNightDutyForCrew(myStart);

            // Print Crew Data: ID, Position, Name
            const member = activeCrewList[i];
            if (member && crewCols['j-duty-operating']) {
                const opX = crewCols['j-duty-operating'];
                
                const empId = String(member.EmployeeID || member.employeeId || '').toUpperCase();
                const pos = String(member.Position || member.position || '').toUpperCase();
                const fullName = `${member.FirstName || member.firstName || ''} ${member.LastName || member.lastName || ''}`.trim().toUpperCase();

                const nameX = opX - 125;
                const posX = opX - 140; 
                const idX = opX - 175;

                page.drawText(empId, { x: idX, y: y, size: nameFontSize, font: font, color: PDFLib.rgb(0,0,0) });
                page.drawText(pos, { x: posX, y: y, size: nameFontSize, font: font, color: PDFLib.rgb(0,0,0) });
                page.drawText(fullName, { x: nameX, y: y, size: nameFontSize, font: font, color: PDFLib.rgb(0,0,0) });
            }

            if(crewCols['j-duty-operating']) 
                page.drawText("OP", { x: crewCols['j-duty-operating'], y: y, size: JOURNEY_CONFIG.fontSize || 8, font: font, color: PDFLib.rgb(0,0,0) });

            if(myFDP && crewCols['j-duty-time']) 
                page.drawText(myFDP, { x: crewCols['j-duty-time'], y: y, size: JOURNEY_CONFIG.fontSize || 8, font: font, color: PDFLib.rgb(0,0,0) });

            if(crewCols['j-duty-night']) {
                page.drawText(myNightDuty, { x: crewCols['j-duty-night'], y: y, size: JOURNEY_CONFIG.fontSize || 8, font: font, color: PDFLib.rgb(0,0,0) });
            }

            if(myMaxFDP && crewCols['j-duty-allowed']) 
                page.drawText(myMaxFDP, { x: crewCols['j-duty-allowed'], y: y, size: JOURNEY_CONFIG.fontSize || 8, font: font, color: PDFLib.rgb(0,0,0) });

            if (crewCols['sectors-total']) {
                page.drawText(sectorsTotalString, { 
                    x: crewCols['sectors-total'], 
                    y: y, 
                    size: JOURNEY_CONFIG.fontSize || 8, 
                    font: font, 
                    color: PDFLib.rgb(0,0,0) 
                });
            }
        }

        // SAVE & DOWNLOAD
        const out = await pdfDoc.save();
        const flt = (el('j-flt')?.value || "FLT").replace(/\s+/g, '');
        const date = el('j-date')?.value || new Date().toISOString().slice(0,10);
        const filename = `JOURNEY_LOG_${flt}.pdf`;
        
        const isMobile = /iPhone|iPad|iPod|Android/i.test(navigator.userAgent);
        if (mode === 'email' && isMobile) {
            const subject = `Journey Log: ${flt}`;
            await sharePdf(out, filename, subject, "Journey Log attached.");
        } else {
            downloadBlob(out, filename);
        }
        
        const userChoice = await showConfirmDialog(
            'Journey Log Generated',
            '<div style="text-align:center;">Save this log and start a new day?<br>Click <strong>Save Log</strong> to store it permanently and clear leg data.<br>Click <strong>Keep Data</strong> to make changes and generate again.</div>',
            'Save Log',
            'Keep Data',
            'info',
            true
        );

        if (userChoice) {
            const blob = new Blob([out], { type: 'application/pdf' });
            await saveJourneyLog(blob, { flight: flt, date, legCount: dailyLegs.length });
            if (typeof showToast !== 'undefined') showToast('Journey log saved', 'success');

            await performDataReset(false, false);
        }

    } catch(e) { 
        console.error("Journey Log Generation Error:", e); 
        await logSecurityEvent('JOURNEY_LOG_ERROR', {
            error: e.message,
            mode: mode
        });
        alert("Error generating Log: " + e.message); 
    }
};
// ==========================================
// 10. OFP Download
// ==========================================

    window.DownloadOFP = async function(mode = 'download') {
        // 1. SAFETY CHECK
        const container = document.getElementById('download-progress-container');
        if (container) container.style.display = 'block';

            try {
                await logSecurityEvent('OFP_DOWNLOAD', { mode, fileName: window.originalFileName, timestamp: new Date().toISOString() });

                // Early return – hide container first
                if (!window.ofpPdfBytes) {
                    if (container) container.style.display = 'none';
                    return alert("Please Upload the OFP PDF first.");
                }

                try {
                    // 2. Load the SOURCE using PDF.js
                    const loadingTask = pdfjsLib.getDocument(window.ofpPdfBytes);
                    const sourceDoc = await loadingTask.promise;
                    const totalPages = sourceDoc.numPages;
                
                    // 3. Create a NEW, CLEAN PDF
                    const newPdf = await PDFLib.PDFDocument.create();

                    // 4. Determine Cutoff
                    let lastPageIndex = totalPages - 1; 
                    const cutoff = typeof window.cutoffPageIndex === 'number' ? window.cutoffPageIndex : -1;

                    if (cutoff > 2 && cutoff < totalPages - 1) {
                        lastPageIndex = cutoff;
                    }

                    // 5. PROCESS PAGES AS IMAGES
                    const SCALE = 2.0; 

                    for (let i = 1; i <= lastPageIndex + 1; i++) {
                        // 5.1. Render Page to Canvas
                        const page = await sourceDoc.getPage(i);
                        const viewport = page.getViewport({ scale: SCALE });
                        
                        const canvas = document.createElement('canvas');
                        const context = canvas.getContext('2d');
                        canvas.width = viewport.width;
                        canvas.height = viewport.height;

                        await page.render({
                            canvasContext: context,
                            viewport: viewport
                        }).promise;

                        // 5.2 Convert to Image
                        const imgData = canvas.toDataURL('image/jpeg', 0.80);
                        const img = await newPdf.embedJpg(imgData);

                        // 5.3 Add Page to PDF
                        const widthPoints = viewport.width / SCALE;
                        const heightPoints = viewport.height / SCALE;
                        
                        const newPage = newPdf.addPage([widthPoints, heightPoints]);

                        // 5.4 Draw the background image to fill the page
                        newPage.drawImage(img, {
                            x: 0,
                            y: 0,
                            width: widthPoints,
                            height: heightPoints
                        });

                        const fontB = await newPdf.embedFont(PDFLib.StandardFonts.HelveticaBold);
                        const fontR = await newPdf.embedFont(PDFLib.StandardFonts.Helvetica);

                        // 5.5 Front Page Overlays
                        if (i === 1) {
                            // ATIS/ATC – only if in typing mode
                            if (currentAtisInputMode === 'typing') {
                                const lineHeight = 16;   // spacing between lines (font size 12 + 2)
                                const maxCharsPerLine = 50;

                                // Helper to draw a field with optional wrapping
                                const drawWrappedField = (id, offset, coord) => {
                                    const rawText = el(id)?.value;
                                    if (!coord || !rawText) return;

                                    const fullText = rawText.toUpperCase();
                                    const lines = fullText.match(new RegExp(`.{1,${maxCharsPerLine}}`, 'g')) || [fullText];
                                    const baseX = coord.transform[4] + offset;
                                    let baseY = coord.transform[5] + V_LIFT;

                                    lines.forEach((line, idx) => {
                                        newPage.drawText(line.trim(), {
                                            x: baseX,
                                            y: baseY - idx * lineHeight,
                                            size: 12,
                                            font: fontB,
                                            color: PDFLib.rgb(0, 0, 0)
                                        });
                                    });
                                };

                                // ATIS – wrap after 50 chars
                                drawWrappedField('front-atis', 40, frontCoords.atis);

                                // ATC – single line (no wrapping)
                                const atcText = el('front-atc')?.value;
                                if (frontCoords.atcLabel && atcText) {
                                    newPage.drawText(atcText.toUpperCase(), {
                                        x: frontCoords.atcLabel.transform[4] + 50,
                                        y: frontCoords.atcLabel.transform[5] + V_LIFT,
                                        size: 12,
                                        font: fontB,
                                        color: PDFLib.rgb(0, 0, 0)
                                    });
                                }
                            }
                            // ATIS/ATC – only if in drawing mode
                            if (currentAtisInputMode === 'writing') {
                                // ATIS canvas
                                if (pads.atis.pad && !pads.atis.pad.isEmpty()) {
                                    try {
                                        const atisData = pads.atis.pad.toDataURL();
                                        const atisImg = await newPdf.embedPng(atisData);
                                        const atisCoord = frontCoords.atis;
                                        if (atisCoord) {
                                            newPage.drawImage(atisImg, {
                                                x: atisCoord.transform[4] + 40,
                                                y: atisCoord.transform[5] - 15, 
                                                width: 150,
                                                height: 40
                                            });
                                        }
                                    } catch(e) { console.error('ATIS drawing error', e); }
                                }
                                // ATC canvas 
                                if (pads.atc.pad && !pads.atc.pad.isEmpty()) {
                                    try {
                                        const atcData = pads.atc.pad.toDataURL();
                                        const atcImg = await newPdf.embedPng(atcData);
                                        const atcCoord = frontCoords.atcLabel;
                                        if (atcCoord) {
                                            newPage.drawImage(atcImg, {
                                                x: atcCoord.transform[4] + 50,
                                                y: atcCoord.transform[5] - 15, 
                                                width: 150,
                                                height: 40
                                            });
                                        }
                                    } catch(e) { console.error('ATC drawing error', e); }
                                }
                            }

                            // PIC Block
                            const picBlockText = el('view-pic-block')?.innerText || "";
                            if(frontCoords.picBlockLabel && picBlockText && picBlockText !== '-') {
                                newPage.drawText(picBlockText, { x: frontCoords.picBlockLabel.transform[4] + 65, y: frontCoords.picBlockLabel.transform[5] + V_LIFT, size: 12, font: fontB });
                            }

                            // Reason
                            const reasonText = el('front-extra-reason')?.value || "";
                            if(frontCoords.reasonLabel && reasonText) {
                                newPage.drawText(reasonText.toUpperCase(), { x: frontCoords.reasonLabel.transform[4] + 175, y: frontCoords.reasonLabel.transform[5] + V_LIFT, size: 12, font: fontB });
                            }

                            // Altimeters
                            ['altm1','stby','altm2'].forEach(k => {
                                const v = el('front-'+k)?.value;
                                const coord = frontCoords[k];
                                if(coord && v) newPage.drawText(v, { x: coord.transform[4] + (k==='stby'?40:50), y: coord.transform[5] + V_LIFT, size: 12, font: fontB });
                            });

                            // Signature
                            if (pads.main.pad && !pads.main.pad.isEmpty() && frontCoords.reasonLabel) {
                                try {
                                    const sigData = pads.main.pad.toDataURL();
                                    const sigImg = await newPdf.embedPng(sigData);
                                    newPage.drawImage(sigImg, {
                                        x: frontCoords.reasonLabel.transform[4],
                                        y: frontCoords.reasonLabel.transform[5] + 40,
                                        width: 100,
                                        height: 35
                                    });
                                } catch(e) {
                                    console.error('Failed to embed signature', e);
                                }
                            }
                        }
                        const pageIndex = i - 1;
            
                        const drawWp = (list, pre) => {
                            list.forEach((wp, idx) => {
                                if (wp.page === pageIndex && !wp.isTakeoff) {
                                    const mainY = wp.y_anchor;
                                    const a = el(`${pre}-a-${idx}`)?.value.replace(':','') || "";
                                    const f = el(`${pre}-f-${idx}`)?.value || "";
                                    const n = el(`${pre}-n-${idx}`)?.value || "";
                                    const agl = el(`${pre}-agl-${idx}`)?.value || "";

                                    // ETO (Blue text)
                                    if(wp.eto) newPage.drawText(wp.eto, { x: TIME_X, y: mainY + LINE_HEIGHT + V_LIFT, size: 12, font: fontB, color: PDFLib.rgb(0,0,0.5) });
                                    // ATO (Regular font)
                                    if(a) newPage.drawText(a, { x: ATO_X, y: mainY + V_LIFT, size: 12, font: fontR });
                                    // Fuel
                                    if(f) newPage.drawText(f, { x: FOB_X, y: mainY - LINE_HEIGHT + V_LIFT, size: 10, font: fontB });
                                    // Notes
                                    if(n) newPage.drawText(n.toUpperCase(), { x: NOTES_X, y: mainY - LINE_HEIGHT + V_LIFT, size: 10, font: fontB });
                                    // AGL
                                    if(agl) newPage.drawText(agl, { x: 115, y: mainY - LINE_HEIGHT + V_LIFT, size: 10, font: fontB });
                                }
                            });
                        };
                        drawWp(waypoints, 'o');
                        drawWp(alternateWaypoints, 'a');
                    }

                    // 6. SAVE
                    const bytes = await newPdf.save();
                    const flight = el('view-flt')?.innerText || el('j-flt')?.value || 'OFP';
                    const date = el('view-date')?.innerText || el('j-date')?.value || '';
                    let filename = generateOFPDFilename(flight, date);
                    const isMobile = /iPhone|iPad|iPod|Android/i.test(navigator.userAgent);
                    window.lastGeneratedOFPPdfBytes = bytes;

                    if (mode === 'email' && isMobile) {
                        const flt = el('j-flt')?.value || "FLT";
                        const date = el('j-date')?.value || "DATE";
                        const subject = `OFP: ${flt} ${date}`;
                        await sharePdf(bytes, filename, subject, "Please find attached the OFP for flight ${flt} on ${date}");
                    } else {
                        downloadBlob(bytes, filename);
                    }
                    
                    if(typeof resetOFPAfterSend === 'function') await resetOFPAfterSend();

                } catch (error) {
                    window.lastGeneratedOFPPdfBytes = null;
                    console.error("Download Error:", error);
                    alert("Error generating PDF: " + error.message);
                } finally {
                    // Hide container after processing (success or inner error)
                    if (container) container.style.display = 'none';
                }
            } catch (error) {
                // Outer catch – also hide container
                if (container) container.style.display = 'none';
            await logSecurityEvent('OFP_DOWNLOAD_ERROR', {
                error: error.message,
                mode: mode
            });
        }
    };

    async function resetOFPAfterSend() {
        // 1. Popup Confirmation (unchanged)
        const userConfirmed = await showConfirmDialog(
            'OFP Generated Successfully',
            '<div style="text-align:center;">Click Finalize to wipe the form for the next flight.<br>' +
            'Click Modify if you need to make changes.</div>',
            'Finalize',
            'Modify',
            true
        );

        if (!userConfirmed) {
            window.lastGeneratedOFPPdfBytes = null;
            return;
        }

        // 2. Save logged PDF to the active OFP (unchanged)
        try {
            const activeId = localStorage.getItem('activeOFPId');
            if (activeId && window.lastGeneratedOFPPdfBytes) {
                const loggedBlob = new Blob([window.lastGeneratedOFPPdfBytes], { type: 'application/pdf' });
                await updateOFP(activeId, {
                    finalized: true,
                    isActive: false,
                    loggedPdfData: loggedBlob,
                    finalizedAt: new Date().toISOString()
                });
                showToast("OFP finalized", 'success');
            }
        } catch (error) {
            console.error("Failed to save logged OFP:", error);
            showToast("Failed to save finalized OFP", 'error');
        } finally {
            window.lastGeneratedOFPPdfBytes = null;
        }

        // 3. Reset UI but do NOT show upload overlay yet (unchanged)
        await performDataReset(true, false);

        // 4. Get settings (unchanged)
        const settings = JSON.parse(localStorage.getItem('efb_settings') || '{}');
        const autoActivate = settings.autoActivateNext !== false; // default true

        // 5. Refresh cache and get all OFPs
        const allOFPs = await getCachedOFPs(true); // force refresh
        const nonFinalizedOFPs = allOFPs.filter(ofp => !ofp.finalized);

        if (nonFinalizedOFPs.length === 0) {
            showToast("Do not forget to send your Journey Log", 'info');
            const journeyBtn = document.querySelector('.nav-btn[data-tab="journey"], .nav-btn[onclick*="journey"]');
            if (journeyBtn) {
                if (typeof window.showTab === 'function') {
                    window.showTab('journey', journeyBtn);
                } else {
                    journeyBtn.click();
                }
            }
            return;
        }

        // THERE ARE NON‑FINALIZED OFPs → PROCEED WITH AUTO‑ACTIVATION (if enabled)
        const currentActiveId = localStorage.getItem('activeOFPId');
        let nextOFP = null;

        if (autoActivate && allOFPs.length > 0) {
            if (currentActiveId) {
                const currentIndex = allOFPs.findIndex(o => o.id === Number(currentActiveId));
                if (currentIndex !== -1 && currentIndex < allOFPs.length - 1) {
                    nextOFP = allOFPs[currentIndex + 1];
                }
            }
            if (!nextOFP && nonFinalizedOFPs.length > 0) {
                nextOFP = nonFinalizedOFPs[0];
            }
        }

        if (nextOFP) {
            await activateOFP(nextOFP.id);
        } else {
            // No OFP to activate – show upload overlay
            setOFPLoadedState(false);
            localStorage.removeItem('activeOFPId');

            // Force empty state update after a short delay
            setTimeout(() => {
                updateEmptyStates();
                // Also refresh the current tab's content (clear any lingering data)
                const activeTab = document.querySelector('.tool-section.active');
                if (activeTab) {
                    // Force re-evaluation of OFP-related UI (e.g., summary fields)
                    if (typeof runFlightLogCalculations === 'function') runFlightLogCalculations();
                    if (typeof validateOFPInputs === 'function') validateOFPInputs();
                }
            }, 100);
        }
    }

    window.downloadSavedOFP = async function(id) {
        try {
            const db = await getDB();
            const tx = db.transaction("ofps", "readonly");
            const store = tx.objectStore("ofps");
            const request = store.get(Number(id));
            
            request.onsuccess = () => {
                const ofp = request.result;
                if (ofp && ofp.loggedPdfData) {
                    const url = URL.createObjectURL(ofp.loggedPdfData);
                    const a = document.createElement('a');
                    a.href = url;
                    a.download = generateOFPDFilename(ofp.flight, ofp.date);
                    document.body.appendChild(a);
                    a.click();
                    document.body.removeChild(a);
                    URL.revokeObjectURL(url);
                    showToast("Logged OFP downloaded", 'success');
                } else {
                    showToast("No logged version found", 'error');
                }
            };
        } catch (error) {
            console.error("Error downloading logged OFP:", error);
            showToast("Download failed", 'error');
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
        'front-atis', 'front-atc', 'front-altm1', 'front-stby', 'front-altm2', 'view-pic-block',
    ];

    // 1. SAVE FUNCTION 
    async function saveState() {
        if (!isAppLoaded) return;

        const activeId = localStorage.getItem('activeOFPId');
        if (!activeId) {
            return;
        }

        // Capture waypoint user inputs
        const userWaypoints = waypoints.map((wp, i) => ({
            ato: el(`o-a-${i}`)?.value || "",
            fuel: el(`o-f-${i}`)?.value || "",
            notes: el(`o-n-${i}`)?.value || "",
            agl: el(`o-agl-${i}`)?.value || ""
        }));

        // Prepare combined user inputs (persistent fields + drawings + signature)
        const combinedInputs = {};

        // Persistent text inputs
        PERSISTENT_INPUT_IDS.forEach(id => {
            const el = document.getElementById(id);
            if (el) combinedInputs[id] = el.value;
        });

        // Helper to validate data URL
        function isValidDataURL(data) {
            return data && typeof data === 'string' && data.startsWith('data:image/png;base64,') && data.length > 100;
        }

        // ATIS/ATC drawings
        if (currentAtisInputMode === 'writing') {
            if (pads.atis.pad && !pads.atis.pad.isEmpty()) {
                const data = pads.atis.pad.toDataURL();
                if (isValidDataURL(data)) {
                    combinedInputs['front-atis-drawing'] = data;
                    localStorage.setItem(`drawing_backup_${activeId}_atis`, data);
                } else {
                    combinedInputs['front-atis-drawing'] = null;
                }
            } else {
                combinedInputs['front-atis-drawing'] = null;
            }

            if (pads.atc.pad && !pads.atc.pad.isEmpty()) {
                const data = pads.atc.pad.toDataURL();
                if (isValidDataURL(data)) {
                    combinedInputs['front-atc-drawing'] = data;
                    localStorage.setItem(`drawing_backup_${activeId}_atc`, data);
                } else {
                    combinedInputs['front-atc-drawing'] = null;
                }
            } else {
                combinedInputs['front-atc-drawing'] = null;
            }
        } else {
            combinedInputs['front-atis-drawing'] = null;
            combinedInputs['front-atc-drawing'] = null;
        }

        // Main signature
        if (pads.main.pad && !pads.main.pad.isEmpty()) {
            const data = pads.main.pad.toDataURL();
            if (isValidDataURL(data)) {
                combinedInputs.signature = data;
                localStorage.setItem(`drawing_backup_${activeId}_signature`, data);
            } else {
                combinedInputs.signature = null;
            }
        } else {
            combinedInputs.signature = null;
        }

        // Save to the new store
        try {
            await saveOFPUserData(Number(activeId), userWaypoints, combinedInputs);
        } catch (e) {
            console.warn('Failed to save user data', e);
        }

        // Save non‑OFP state to localStorage (encrypted + fallback) – unchanged
        const state = {
            inputs: {},
            dailyLegs: dailyLegs,
            dutyStartTime: dutyStartTime,
            version: APP_VERSION,
            timestamp: new Date().toISOString(),
            savedTaxiValue: fuelData.find(x => x.name === "TAXI")?.fuel || 200
        };

        SAVE_IDS.forEach(id => {
            const e = el(id);
            if (e) state.inputs[id] = e.value;
        });

        // Fallback sync save
        try {
            localStorage.setItem('efb_log_state_fallback', JSON.stringify(state));
        } catch (e) {
            console.error('Storage full or error:', e);
        }

        // Encrypted async save
        try {
            if (typeof encryptData === 'function') {
                const encryptedState = await encryptData(state);
                localStorage.setItem('efb_log_state', encryptedState);
            }
        } catch (error) {
            console.warn('Encryption save failed, relying on fallback.', error);
        }
    }

    // 2. LOAD FUNCTION 
    async function loadState() {
        // Try encrypted first, then fallback
        let raw = localStorage.getItem('efb_log_state');
        let isEncrypted = true;

        if (!raw) {
            raw = localStorage.getItem('efb_log_state_fallback');
            isEncrypted = false;

            if (!raw) {
                raw = localStorage.getItem('efb_log_state_plain');
            }

            if (!raw) {
                console.log("No saved data found.");
                isAppLoaded = true;
                return;
            }
        }

        try {
            let state;

            if (isEncrypted) {
                try {
                    state = await decryptData(raw);
                } catch (decryptError) {
                    console.error("Decryption failed, switching to fallback.");
                    raw = localStorage.getItem('efb_log_state_fallback');
                    if (raw) {
                        state = JSON.parse(raw);
                        isEncrypted = false;
                    } else {
                        raw = localStorage.getItem('efb_log_state_plain');
                        if (raw) state = JSON.parse(raw);
                        else throw new Error("Decryption failed and no fallback found.");
                    }
                }
            } else {
                state = JSON.parse(raw);
            }

            // Restore non‑OFP‑specific state (safe)
            if (state.inputs) {
                Object.keys(state.inputs).forEach(id => {
                    const val = state.inputs[id];
                    if (val !== "" && val !== null) safeSet(id, val);
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

            // Recalculate dependent values
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
                const request = indexedDB.open("EFB_PDF_DB", 11); // Version 11

                request.onupgradeneeded = function(e) {
                    const db = e.target.result;
                    const oldVersion = e.oldVersion;
                    const tx = e.target.transaction;

                    // --- ofp_user_data store (added in v10) ---
                    if (!db.objectStoreNames.contains("ofp_user_data")) {
                        db.createObjectStore("ofp_user_data", { keyPath: "ofpId" });
                        console.log('Created ofp_user_data store (upgrade to v10)');
                    }

                    // --- ofps store (main OFP records) ---
                    if (!db.objectStoreNames.contains("ofps")) {
                        console.warn(`getDB: creating ofps store (oldVersion=${oldVersion})`);
                        const ofpStore = db.createObjectStore("ofps", { keyPath: "id", autoIncrement: true });
                        ofpStore.createIndex("flight", "flight", { unique: false });
                        ofpStore.createIndex("date", "date", { unique: false });
                        ofpStore.createIndex("uploadTime", "uploadTime", { unique: false });
                        ofpStore.createIndex("isActive", "isActive", { unique: false });
                        ofpStore.createIndex("order", "order", { unique: false });
                    }

                    // --- legacy files store (v2) ---
                    if (oldVersion < 2) {
                        if (!db.objectStoreNames.contains("files")) {
                            db.createObjectStore("files");
                        }
                    }

                    // --- v4 migration (finalized / loggedPdfData) ---
                    if (oldVersion < 4 && oldVersion >= 3) {
                        const store = tx.objectStore("ofps");
                        const getAll = store.getAll();
                        getAll.onsuccess = () => {
                            getAll.result.forEach(ofp => {
                                let needsUpdate = false;
                                if (ofp.finalized === undefined) { ofp.finalized = false; needsUpdate = true; }
                                if (ofp.loggedPdfData === undefined) { ofp.loggedPdfData = null; needsUpdate = true; }
                                if (needsUpdate) store.put(ofp);
                            });
                        };
                    }

                    // --- v5 migration (order index & default order) ---
                    if (oldVersion < 5) {
                        const store = tx.objectStore("ofps");
                        if (!store.indexNames.contains("order")) {
                            store.createIndex("order", "order", { unique: false });
                        }
                        const getAll = store.getAll();
                        getAll.onsuccess = () => {
                            const ofps = getAll.result;
                            ofps.sort((a, b) => new Date(a.uploadTime) - new Date(b.uploadTime));
                            ofps.forEach((ofp, index) => {
                                if (ofp.order === undefined) {
                                    ofp.order = index + 1;
                                    store.put(ofp);
                                }
                            });
                        };
                    }

                    // --- v6 migration (tripTime / maxSR) ---
                    if (oldVersion < 6) {
                        const store = tx.objectStore("ofps");
                        const getAll = store.getAll();
                        getAll.onsuccess = () => {
                            getAll.result.forEach(ofp => {
                                let needsUpdate = false;
                                if (ofp.tripTime === undefined) { ofp.tripTime = ''; needsUpdate = true; }
                                if (ofp.maxSR === undefined) { ofp.maxSR = ''; needsUpdate = true; }
                                if (needsUpdate) store.put(ofp);
                            });
                        };
                    }

                    // --- v7 migration (requestNumber) ---
                    if (oldVersion < 7) {
                        const store = tx.objectStore("ofps");
                        const getAll = store.getAll();
                        getAll.onsuccess = () => {
                            getAll.result.forEach(ofp => {
                                if (ofp.requestNumber === undefined) {
                                    ofp.requestNumber = '';
                                    store.put(ofp);
                                }
                            });
                        };
                    }

                    // --- v8 migration (ofp_orders store) ---
                    if (oldVersion < 8) {
                        if (!db.objectStoreNames.contains("ofp_orders")) {
                            const orderStore = db.createObjectStore("ofp_orders", { keyPath: "id" });
                            // Copy existing orders from ofps store
                            const ofpsStore = tx.objectStore("ofps");
                            const ordersStore = tx.objectStore("ofp_orders");
                            const getAllReq = ofpsStore.getAll();
                            getAllReq.onsuccess = () => {
                                const ofps = getAllReq.result;
                                ofps.forEach(ofp => {
                                    ordersStore.put({ id: ofp.id, order: ofp.order || 0 });
                                });
                            };
                        }
                    }

                    // --- v9 migration (ofp_user_data – already added at top) ---
                    // (nothing extra needed here, store already created)

                    // --- v11 migration (journey_logs store) ---
                    if (!db.objectStoreNames.contains("journey_logs")) {
                        db.createObjectStore("journey_logs", { keyPath: "id", autoIncrement: true });
                        console.log('Created journey_logs store (upgrade to v11)');
                    }
                };

                request.onsuccess = e => resolve(e.target.result);
                request.onerror = e => reject(e);
            });
        }
        return dbPromise;
    }

    // Save OFP with metadata to the new store
    async function saveOFPToDB(fileBlob, metadata, activate = true) {
        const db = await getDB();
        return new Promise((resolve, reject) => {
            const tx = db.transaction(["ofps", "ofp_orders"], "readwrite");
            const ofpsStore = tx.objectStore("ofps");
            const ordersStore = tx.objectStore("ofp_orders");

            // Get next order number from orders store
            const getAllRequest = ordersStore.getAll();
            getAllRequest.onsuccess = () => {
                const orders = getAllRequest.result;
                const maxOrder = orders.length > 0 ? Math.max(...orders.map(o => o.order || 0)) : 0;
                const nextOrder = maxOrder + 1;

                // Deactivate active OFP if needed
                const deactivateAll = async () => {
                    if (activate) {
                        const allOfps = await new Promise((res) => {
                            const req = ofpsStore.getAll();
                            req.onsuccess = () => res(req.result);
                        });
                        for (let rec of allOfps) {
                            if (rec.isActive) {
                                rec.isActive = false;
                                ofpsStore.put(rec);
                            }
                        }
                    }
                };

                deactivateAll().then(() => {
                    const ofpRecord = {
                        ...metadata,
                        data: fileBlob,
                        loggedPdfData: null,
                        finalized: false,
                        isActive: activate,
                        order: nextOrder, // keep for backward compatibility
                        uploadTime: new Date().toISOString(),
                        fileName: fileBlob.name || "Unknown",
                        tripTime: metadata.tripTime || '',
                        maxSR: metadata.maxSR || '',
                        requestNumber: metadata.requestNumber || '',

                    };

                    const addRequest = ofpsStore.add(ofpRecord);
                    addRequest.onsuccess = (e) => {
                        const newId = e.target.result;
                        // Add order record
                        ordersStore.put({ id: newId, order: nextOrder });

                        if (activate) {
                            localStorage.setItem('activeOFPId', newId);
                        }

                        tx.oncomplete = () => resolve(newId);
                    };
                    addRequest.onerror = (e) => reject(e.target.error);
                }).catch(reject);
            };
            getAllRequest.onerror = (e) => reject(e.target.error);

            tx.onerror = (e) => reject(e.target.error);
        });
    }

    // Emergency fallback: save PDF to old store + create/update minimal ofps record
    async function emergencySaveOFP(blob, metadata, existingOFP = null) {
        const results = {
            pdfSaved: false,
            ofpsRecordCreated: false,
            recordId: null
        };

        // 1. Always try to save PDF to old files store (legacy)
        try {
            await savePdfToDB(blob);
            results.pdfSaved = true;
            console.log('Emergency: PDF saved to old files store');
        } catch (e) {
            console.error('Emergency: failed to save PDF to files store', e);
        }

        // 2. Create or update minimal ofps record (without PDF blob)
        try {
            const minimalMetadata = {
                flight: metadata.flight || 'N/A',
                date: metadata.date || 'N/A',
                departure: metadata.departure || 'N/A',
                destination: metadata.destination || 'N/A',
                tripTime: metadata.tripTime || '',
                maxSR: metadata.maxSR || '',
                requestNumber: metadata.requestNumber || ''
            };

            if (existingOFP && existingOFP.id) {
                // Update existing record (preserve ID, isActive, order)
                const updates = {
                    ...minimalMetadata,
                    data: null,
                    loggedPdfData: null,
                    finalized: false,
                    isActive: existingOFP.isActive || false,
                    order: existingOFP.order,
                    uploadTime: new Date().toISOString(),
                    fileName: blob.name || "Unknown"
                };
                await updateOFP(existingOFP.id, updates);
                results.recordId = existingOFP.id;
                results.ofpsRecordCreated = true;
                console.log(`Emergency: existing ofps record updated, ID = ${existingOFP.id}`);
            } else {
                // Create new minimal record (bottom of order, inactive)
                const all = await getCachedOFPs();
                const maxOrder = all.length > 0 ? Math.max(...all.map(o => o.order || 0)) : 0;
                const ofpRecord = {
                    ...minimalMetadata,
                    data: null,
                    loggedPdfData: null,
                    finalized: false,
                    isActive: false,
                    order: maxOrder + 1,
                    uploadTime: new Date().toISOString(),
                    fileName: blob.name || "Unknown"
                };
                const db = await getDB();
                const tx = db.transaction("ofps", "readwrite");
                const store = tx.objectStore("ofps");
                const addRequest = store.add(ofpRecord);
                await new Promise((resolve, reject) => {
                    addRequest.onsuccess = (e) => {
                        results.recordId = e.target.result;
                        results.ofpsRecordCreated = true;
                        console.log(`Emergency: new minimal ofps record created, ID = ${results.recordId}`);
                        resolve();
                    };
                    addRequest.onerror = (e) => reject(e.target.error);
                    tx.oncomplete = () => resolve();
                    tx.onerror = (e) => reject(e.target.error);
                });
            }
        } catch (e2) {
            console.error('Emergency: ofps record creation/update failed', e2);
        }

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

            const getRequest = store.get(Number(id));
            getRequest.onsuccess = () => {
                const ofp = getRequest.result;
                if (!ofp) {
                    reject(new Error("OFP not found"));
                    return;
                }
                Object.assign(ofp, updates);

                const putRequest = store.put(ofp);
                putRequest.onerror = (e) => {
                    alert('Put error:'+ e.target.error);
                    reject(e.target.error);
                };

                tx.oncomplete = () => resolve(ofp);
                tx.onerror = (e) => reject(e.target.error);
            };
            getRequest.onerror = (e) => reject(e.target.error);
        });
    }

    async function findOFPByFlightAndDate(flight, date) {
        if (!flight || !date || flight === 'N/A' || date === 'N/A') return null;
        const flightStr = String(flight);
        const db = await getDB();
        return new Promise((resolve, reject) => {
            const tx = db.transaction("ofps", "readonly");
            const store = tx.objectStore("ofps");
            const index = store.index("flight");
            // Use IDBKeyRange to query exact flight
            const request = index.getAll(IDBKeyRange.only(flightStr));
            request.onsuccess = () => {
                const ofps = request.result;
                const match = ofps.find(ofp => ofp.date === date);
                resolve(match || null);
            };
            request.onerror = (e) => reject(e);
        });
    }

    async function getActiveOFPFromDB() {
        const activeId = localStorage.getItem('activeOFPId');
        if (!activeId) return null;
        return getOFPById(Number(activeId));
    }

    async function deleteOFPFromDB(id) {
        const db = await getDB();
        const numericId = Number(id);

        const storesToUse = ['ofps', 'ofp_orders'];
        if (db.objectStoreNames.contains('ofp_user_data')) {
            storesToUse.push('ofp_user_data');
        }

        const tx = db.transaction(storesToUse, "readwrite");
        tx.objectStore('ofps').delete(numericId);
        tx.objectStore('ofp_orders').delete(numericId);
        if (storesToUse.includes('ofp_user_data')) {
            tx.objectStore('ofp_user_data').delete(numericId);
        }

        await new Promise((resolve, reject) => {
            tx.oncomplete = () => {
                const activeId = localStorage.getItem('activeOFPId');
                if (activeId && Number(activeId) === numericId) {
                    localStorage.removeItem('activeOFPId');
                }
                resolve();
            };
            tx.onerror = (e) => reject(e.target.error);
        });
        updateUploadButtonVisibility();
        await updateEmptyStates();
    }

    async function clearAllOFPsFromDB() {
        const db = await getDB();
        const storesToClear = [];
        if (db.objectStoreNames.contains('ofps')) storesToClear.push('ofps');
        if (db.objectStoreNames.contains('ofp_orders')) storesToClear.push('ofp_orders');
        if (db.objectStoreNames.contains('ofp_user_data')) storesToClear.push('ofp_user_data');

        if (storesToClear.length === 0) {
            localStorage.removeItem('activeOFPId');
            return;
        }

        const tx = db.transaction(storesToClear, "readwrite");
        storesToClear.forEach(storeName => {
            tx.objectStore(storeName).clear();
        });

        await new Promise((resolve, reject) => {
            tx.oncomplete = () => {
                localStorage.removeItem('activeOFPId');
                updateUploadButtonVisibility();
                resolve();
            };
            tx.onerror = (e) => {
                alert('Transaction error:'+ e.target.error);
                reject(e.target.error);
            };
        });

        await updateEmptyStates();
    }

    async function checkPdfInDB() {
        try {
            const db = await getDB();
            return new Promise((resolve, reject) => {
                const tx = db.transaction("files", "readonly");
                const req = tx.objectStore("files").get("currentOFP");
                req.onsuccess = () => resolve(!!req.result);
                req.onerror = () => resolve(false);
            });
        } catch(e) {
            return false;
        }
    }

    async function savePdfToDB(fileBlob) {
        const db = await getDB();
        return new Promise((resolve, reject) => {
            const tx = db.transaction("files", "readwrite");
            const store = tx.objectStore("files");
            
            // Store the original Blob, not the ArrayBuffer
            store.put(fileBlob, "currentOFP");
            
            tx.oncomplete = () => resolve();
            tx.onerror = () => reject(tx.error);
        });
    }

    async function loadPdfFromDB() {
        const db = await getDB();
        return new Promise((resolve, reject) => {
            const tx = db.transaction("files", "readonly");
            const req = tx.objectStore("files").get("currentOFP");
            req.onsuccess = () => resolve(req.result); // Return the Blob directly
            req.onerror = () => resolve(null);
        });
    }

    async function clearPdfDB() {
        const db = await getDB();
        const tx = db.transaction("files", "readwrite");
        tx.objectStore("files").delete("currentOFP");
    }

    async function getAllOFPMetadata() {
        const db = await getDB();
        if (!db.objectStoreNames.contains('ofps')) return [];

        if (db.objectStoreNames.contains('ofp_orders')) {
            const tx = db.transaction(["ofps", "ofp_orders"], "readonly");
            const ofpsStore = tx.objectStore("ofps");
            const ordersStore = tx.objectStore("ofp_orders");

            const [ofps, orders] = await Promise.all([
                new Promise((res, rej) => {
                    const req = ofpsStore.getAll();
                    req.onsuccess = () => res(req.result);
                    req.onerror = (e) => rej(e);
                }),
                new Promise((res, rej) => {
                    const req = ordersStore.getAll();
                    req.onsuccess = () => res(req.result);
                    req.onerror = (e) => rej(e);
                })
            ]);

            const orderMap = {};
            orders.forEach(o => { orderMap[o.id] = o.order; });

            // Exclude userWaypoints and userInputs – they are no longer in ofps
            const metadata = ofps.map(({ data, loggedPdfData, userWaypoints, userInputs, ...rest }) => ({
                ...rest,
                order: orderMap[rest.id] || 0
            }));
            metadata.sort((a, b) => (a.order || 0) - (b.order || 0));
            return metadata;
        } else {
            // Fallback (should not happen)
            return [];
        }
    }

    // Save user data for a specific OFP
    async function saveOFPUserData(ofpId, userWaypoints, userInputs) {
        const db = await getDB();
        if (!db.objectStoreNames.contains('ofp_user_data')) {
            alert('ofp_user_data store missing – cannot save');
            return;
        }
        const tx = db.transaction("ofp_user_data", "readwrite");
        const store = tx.objectStore("ofp_user_data");
        store.put({ ofpId, userWaypoints, userInputs });
        return new Promise((resolve, reject) => {
            tx.oncomplete = () => resolve();
            tx.onerror = (e) => reject(e.target.error);
        });
    }

    // Load user data for a specific OFP
    async function loadOFPUserData(ofpId) {
        const db = await getDB();
        if (!db.objectStoreNames.contains('ofp_user_data')) {
            alert('ofp_user_data store missing – returning empty');
            return { userWaypoints: [], userInputs: {} };
        }
        const tx = db.transaction("ofp_user_data", "readonly");
        const store = tx.objectStore("ofp_user_data");
        return new Promise((resolve, reject) => {
            const req = store.get(ofpId);
            req.onsuccess = () => resolve(req.result || { userWaypoints: [], userInputs: {} });
            req.onerror = (e) => reject(e.target.error);
        });
    }

    async function saveJourneyLog(pdfBlob, metadata) {
        const db = await getDB();
        const tx = db.transaction("journey_logs", "readwrite");
        const store = tx.objectStore("journey_logs");
        const record = {
            ...metadata,
            data: pdfBlob,
            finalizedAt: new Date().toISOString()
        };
        return new Promise((resolve, reject) => {
            const req = store.add(record);
            req.onsuccess = () => resolve(req.result);
            req.onerror = (e) => reject(e.target.error);
        });
    }

    async function getAllJourneyLogs() {
        const db = await getDB();
        const tx = db.transaction("journey_logs", "readonly");
        const store = tx.objectStore("journey_logs");
        return new Promise((resolve, reject) => {
            const request = store.getAll();
            request.onsuccess = () => resolve(request.result);
            request.onerror = () => reject(request.error);
        });
    }

    window.deleteJourneyLog = async function(id) {
        try {
            const db = await getDB();
            const tx = db.transaction("journey_logs", "readwrite");
            const store = tx.objectStore("journey_logs");
            await new Promise((resolve, reject) => {
                const req = store.delete(id);
                req.onsuccess = () => resolve();
                req.onerror = (e) => reject(e.target.error);
            });
            showToast('Journey log deleted', 'success');
            // Refresh the table if visible
            const journeyContainer = document.getElementById('journey-table-container');
            if (journeyContainer && !journeyContainer.hidden) {
                await renderJourneyLogTable();
            }
        } catch (error) {
            console.error('Error deleting journey log:', error);
            showToast('Failed to delete', 'error');
        }
    };

    window.downloadSavedJourneyLog = async function(id) {
        try {
            const db = await getDB();
            const tx = db.transaction("journey_logs", "readonly");
            const store = tx.objectStore("journey_logs");
            const request = store.get(id);
            request.onsuccess = () => {
                const log = request.result;
                if (log && log.data) {
                    const url = URL.createObjectURL(log.data);
                    const a = document.createElement('a');
                    a.href = url;
                    a.download = `JOURNEY_LOG_${log.flight || 'unknown'}_${log.date || 'nodate'}.pdf`;
                    document.body.appendChild(a);
                    a.click();
                    document.body.removeChild(a);
                    URL.revokeObjectURL(url);
                    showToast("Journey log downloaded", 'success');
                } else {
                    showToast("No data found", 'error');
                }
            };
        } catch (error) {
            console.error("Error downloading journey log:", error);
            showToast("Download failed", 'error');
        }
    };

    async function saveJourneyTemplateToDB(fileBlob) {
        const db = await getDB();
        const tx = db.transaction("files", "readwrite");
        const store = tx.objectStore("files");
        
        store.put(fileBlob, "journeyTemplate");
        
        return new Promise((resolve, reject) => {
            tx.oncomplete = () => {
                resolve();
            };
            tx.onerror = (e) => {
                alert('DB Write Failed: ' + e.target.error);
                reject(e);
            };
        });
    }

    async function loadJourneyTemplateFromDB() {
        const db = await getDB();
        const tx = db.transaction("files", "readonly");
        const store = tx.objectStore("files");
        
        return new Promise((resolve, reject) => {
            const req = store.get("journeyTemplate");
            req.onsuccess = () => {
                if (req.result) {
                    resolve(req.result); 
                } else {
                    resolve(null);
                }
            };
            req.onerror = (e) => reject(e);
        });
    }

    async function deleteJourneyTemplateFromDB() {
        const db = await getDB();
        const tx = db.transaction("files", "readwrite");
        const store = tx.objectStore("files");
        store.delete("journeyTemplate");
        return new Promise((resolve, reject) => {
            tx.oncomplete = () => {
                resolve();
            };
            tx.onerror = (e) => reject(e);
        });
    }

// ==========================================
// 14. DATA HANDLING
// ==========================================

    async function exportAllData() {
        try {
            const data = {
                version: APP_VERSION,
                exportDate: new Date().toISOString(),
                flightData: {
                    dailyLegs: dailyLegs,
                    waypoints: waypoints,
                    alternateWaypoints: alternateWaypoints,
                    fuelData: fuelData
                },
                settings: JSON.parse(localStorage.getItem('efb_settings') || '{}'),
                state: JSON.parse(localStorage.getItem('efb_log_state') || '{}')
            };
            
            const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `efb-backup-${new Date().toISOString().split('T')[0]}.json`;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
            
            showToast('Data exported successfully');
            
        } catch (error) {
            console.error('Export failed:', error);
            showToast('Export failed: ' + error.message, 'error');
        }
    }

    window.recoverLostData = async function() {
        const confirmed = await showConfirmDialog(
            'Data Recovery Mode',
            'This will attempt to recover any lost data.<br>' +
            'Continue?',
            'error'
        );
        
        if (confirmed) {

            // Try all storage methods
            const recoveryMethods = [
                { key: 'efb_log_state', type: 'encrypted' },
                { key: 'efb_log_state_fallback', type: 'unencrypted' },
                { key: 'efb_log_state_plain', type: 'legacy' }
            ];
            
            for (const method of recoveryMethods) {
                try {
                    const data = localStorage.getItem(method.key);
                    if (data) {
                        let state;
                        if (method.type === 'encrypted') {
                            state = await decryptData(data);
                        } else {
                            state = JSON.parse(data);
                        }
                        
                        if (state && state.inputs) {
                            // Restore inputs
                            Object.keys(state.inputs).forEach(id => {
                                if (state.inputs[id]) safeSet(id, state.inputs[id]);
                            });
                            
                            alert(`Recovered data from ${method.type} storage`);
                            return;
                        }
                    }
                } catch (e) {
                    console.log(`Recovery from ${method.key} failed:`, e);
                }
            }
        }
        showToast("No recoverable data found", 'info');
    };

    async function confirmFactoryReset() {
        const confirmed = await showConfirmDialog(
            'Factory Reset',
            'WARNING: This will delete ALL data including:<br>' +
            '• All flight data<br>' +
            '• All app settings<br>' +
            '• PIN and security data<br>' +
            '• Audit logs<br>' +
            '<br>This action cannot be undone. Continue?',
            'Reset'
        );

        if (confirmed) {
            // Clear Local Storage (settings, PIN, audit logs, state)
            localStorage.clear();

            // Clear Session Storage
            sessionStorage.removeItem('efb_authenticated');

            // Clear IndexedDB
            try {

                const db = await getDB();
                // Delete the ofps store (all OFPs, metadata, logged PDFs)
                if (db.objectStoreNames.contains('ofps')) {
                    const tx = db.transaction('ofps', 'readwrite');
                    tx.objectStore('ofps').clear();
                    await new Promise((resolve, reject) => {
                        tx.oncomplete = resolve;
                        tx.onerror = reject;
                    });
                }

                // Delete the old files store (legacy OFP blob)
                if (db.objectStoreNames.contains('files')) {
                    const tx = db.transaction('files', 'readwrite');
                    tx.objectStore('files').clear();
                    await new Promise((resolve, reject) => {
                        tx.oncomplete = resolve;
                        tx.onerror = reject;
                    });
                }

            } catch (e) {
                console.error('Failed to clear IndexedDB:', e);
            }

            // Unregister service worker
            if ('serviceWorker' in navigator) {
                const registrations = await navigator.serviceWorker.getRegistrations();
                for (let reg of registrations) {
                    await reg.unregister();
                }
            }

            // Reload app after short delay
            showToast('All data reset. Reloading app...', 'info');
            setTimeout(() => location.reload(), 2000);
        }
    }

    async function performDataReset(preserveDailyLegs = true, setLoadedState = true) {

        // 1. Reset Internal Variables
        waypoints = [];
        alternateWaypoints = [];
        fuelData = [];
        blockFuelValue = 0;
        window.cutoffPageIndex = -1;
        
        // 2. Reset Coordinates
        frontCoords = { 
            atis: null, atcLabel: null, altm1: null, stby: null, 
            altm2: null, picBlockLabel: null, reasonLabel: null 
        };

        // 3. Clear PDF Database & Memory
        window.ofpPdfBytes = null;
        window.lastGeneratedOFPPdfBytes = null;
        window.originalFileName = "Logged_OFP.pdf";
        if(typeof clearPdfDB === 'function') await clearPdfDB();

        // 3. Clear Text Displays (Summary & Weights)
        const textIDs = [
            'view-flt', 'view-reg', 'view-date', 'view-dep', 'view-dest', 
            'view-std-text', 'view-sta-text', 'view-altn', 'view-ci',
            'view-dest-route', 'view-altn-route', 'view-altn2',
            'view-min-block', 'view-pic-block',
            'view-mtow', 'view-mlw', 'view-mzfw', 'view-mpld', 'view-fcap', 
            'view-dow', 'view-tow', 'view-lw', 'view-zfw','view-era','view-crz-wind-temp', 'view-seats-stn-jmp'
        ];

        textIDs.forEach(id => {
            const e = document.getElementById(id);
            if(e) e.innerText = "-"; 
        });

        // 4. Clear ALL Inputs (OFP + Journey Log)
        const inputIDs = [
            // Front Page
            'front-atis', 'front-atc', 'front-altm1', 'front-stby', 'front-altm2', 
            'front-extra-kg', 'front-extra-reason', 'ofp-atd-in', 'view-pic-block',
            
            // Journey Log
            'j-flt', 'j-reg', 'j-date', 'j-dep', 'j-dest', 'j-altn', 'j-std',
            'j-out', 'j-off', 'j-on', 'j-in', 'j-night', 'j-night-calc',
            'j-to', 'j-ldg', 'j-ldg-type', 'j-flt-alt', 'j-ldg-detail',
            'j-init', 'j-uplift-w', 'j-uplift-vol', 'j-act-ramp', 'j-shut', 
            'j-slip', 'j-slip-2', 'j-adl', 'j-chl', 'j-inf', 'j-bag', 
            'j-cargo', 'j-mail', 'j-zfw'
        ];
        
        // Only clear duty fields if we are Wiping Everything (End of Day)
        if (!preserveDailyLegs) {
            inputIDs.push('j-duty-start', 'j-cc-duty-start', 'j-max-fdp', 'j-fc-count', 'j-cc-count');
            localStorage.removeItem(PERSIST_AUTH_KEY);
        }

        inputIDs.forEach(id => {
            const e = document.getElementById(id);
            if(e) e.value = "";
        });

        // 5. Clear Calculated Displays
        ['j-block', 'j-flight', 'j-burn', 'j-calc-ramp', 'j-disc'].forEach(id => {
            const e = document.getElementById(id);
            if (e) e.innerText = "00:00";
        });

        // 6. Clear Tables
        ['ofp-tbody', 'altn-tbody', 'fuel-tbody'].forEach(id => {
            const tb = document.getElementById(id);
            if(tb) tb.innerHTML = '<tr><td colspan="13" style="text-align:center;color:gray;padding:20px">No data</td></tr>';
        });

        // 7. Clear Journey List (Only if End of Day)
        if (!preserveDailyLegs) {
            const journeyList = document.getElementById('journey-list-body');
            if (journeyList) journeyList.innerHTML = '<tr><td colspan="5" style="text-align:center; color:gray; padding:20px;">No legs.</td></tr>';
            dailyLegs = []; 
            dutyStartTime = null;
            localStorage.removeItem(PERSIST_AUTH_KEY);
        }

        // 8. Clear PDF Preview & Fallback
        const container = document.getElementById('pdf-render-container');
        const fallback = document.getElementById('pdf-fallback');
        if (container) {
            container.innerHTML = '';
            container.style.display = 'none';
        }
        if (fallback) {
            fallback.innerHTML = '<span style="font-size:30px; margin-bottom:10px;">📄</span>No OFP uploaded yet.';
            fallback.style.display = 'flex';
        }

        // 9. Clear Signature
        if (typeof signaturePad !== 'undefined' && signaturePad) {
            signaturePad.clear();
            if(typeof savedSignatureData !== 'undefined') savedSignatureData = null;
        }

        // 10. Clear File Inputs
        ['ofp-file-in', 'journey-log-file'].forEach(id => {
            const e = document.getElementById(id);
            if(e) e.value = '';
        });

        // 12. DATABASE & STATE MANAGEMENT
        if (preserveDailyLegs) {
            const savedState = localStorage.getItem('efb_log_state');
            if (savedState) {
                try {
                    // Try to decrypt first (since state is encrypted)
                    let state;
                    try {
                        state = await decryptData(savedState);
                    } catch (decryptError) {
                        // If decryption fails, try parsing as plain JSON (legacy fallback)
                        console.log("Decryption failed, trying plain JSON:", decryptError);
                        state = JSON.parse(savedState);
                    }
                    
                    const newState = {
                        dailyLegs: state.dailyLegs || [],
                        dutyStartTime: state.dutyStartTime || null,
                        inputs: {} 
                    };
                    
                    // Keep Duty Inputs
                    if (state.inputs) {
                        ['j-duty-start', 'j-cc-duty-start', 'j-max-fdp', 'j-fc-count', 'j-cc-count'].forEach(key => {
                            if (state.inputs[key]) newState.inputs[key] = state.inputs[key];
                        });
                    }
                    
                    // Encrypt and save the new state
                    const encryptedNewState = await encryptData(newState);
                    localStorage.setItem('efb_log_state', encryptedNewState);
                    
                } catch(e) { 
                    console.error("Error processing saved state:", e);
                    // If there's an error, start fresh
                    localStorage.removeItem('efb_log_state');
                }
            }
        } else {

            // 12.1 FULL RESET (End of Day)
            localStorage.removeItem('efb_log_state');
            localStorage.removeItem('efb_log_state_fallback'); 
            localStorage.removeItem('efb_log_state_plain');
            localStorage.removeItem('activeOFPId');
            setOFPLoadedState(false);
        }

        if (setLoadedState && typeof setOFPLoadedState === 'function') {
            setOFPLoadedState(false);
        }
        if (typeof validateOFPInputs === 'function') {
            validateOFPInputs();
        }
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
    
    function updateStorageDisplay(bytes) {

        const storageEl = document.getElementById('settings-storage');
        if (!storageEl) return;
        
        let size, unit;
        
        if (bytes < 1024) {
            size = bytes;
            unit = 'B';
        } else if (bytes < 1024 * 1024) {
            size = (bytes / 1024).toFixed(1);
            unit = 'KB';
        } else {
            size = (bytes / (1024 * 1024)).toFixed(2);
            unit = 'MB';
        }
        
        storageEl.textContent = `${size} ${unit}`;
    }

    async function calculateStorageUsage() {
        try {
            const storageEl = document.getElementById('settings-storage');
            if (!storageEl) return;

            let totalBytes = 0;

            for (let i = 0; i < localStorage.length; i++) {
                const key = localStorage.key(i);
                const value = localStorage.getItem(key);
                if (value) totalBytes += key.length + value.length;
            }

            if ('indexedDB' in window) {
                const db = await getDB(); // use shared connection
                if (db.objectStoreNames.contains('files')) {
                    const tx = db.transaction("files", "readonly");
                    const store = tx.objectStore("files");
                    const request = store.get("currentOFP");
                    request.onsuccess = () => {
                        if (request.result) totalBytes += request.result.size || 0;
                        updateStorageDisplay(totalBytes);
                    };
                    request.onerror = () => updateStorageDisplay(totalBytes);
                } else {
                    updateStorageDisplay(totalBytes);
                }
            } else {
                updateStorageDisplay(totalBytes);
            }
        } catch (error) {
            console.error('Failed to calculate storage:', error);
            const storageEl = document.getElementById('settings-storage');
            if (storageEl) storageEl.textContent = 'Error';
        }
    }

    function initializeSettingsTab() {

        // Bind buttons to their handlers
        const settingsButtons = {
            'btn-change-pin': changePIN,
            'btn-view-audit': viewAuditLog,
            'btn-export-data': exportAllData,
            'btn-factory-reset': confirmFactoryReset,
            'btn-recover-data': recoverLostData,
            'btn-release-notes': showReleaseNotes,
        };
        
        Object.entries(settingsButtons).forEach(([id, handler]) => {
            const button = document.getElementById(id);
            if (button && typeof handler === 'function') {
                button.addEventListener('click', handler);
            }
        });
        
        ['auto-lock-time', 'pdf-quality', 'hide-all-duty', 'auto-activate-next'].forEach(id => {
            const element = document.getElementById(id);
            if (element) {
                element.addEventListener('change', saveSettings);
            }
        });

        // Special handler for ATIS input mode – apply UI change immediately
        const modeSelect = document.getElementById('atis-input-mode');
        if (modeSelect) {
            modeSelect.addEventListener('change', function(e) {
                const newMode = e.target.value;
                applyInputMode(newMode);
                saveSettings();
            });
        }
    }

    async function initializeSettings() {

        // Bind buttons and listeners (only once)
        initializeSettingsTab();
        
        // Load and apply saved settings
        loadSettings();
        
        // Calculate storage usage after a short delay (UI is ready)
        setTimeout(calculateStorageUsage, 1000);
        
        // Set app version
        const versionEl = document.getElementById('settings-version');
        if (versionEl) {
            versionEl.textContent = `v${APP_VERSION}`;
        }
        
        // Set last updated date
        const updatedEl = document.getElementById('settings-updated');
        if (updatedEl) {
            updatedEl.textContent = new Date().toLocaleDateString();
        }
    }

    function loadSettings() {
        try {
            // 1. DO TOKENS FIRST (So they are safe from any UI crashes below)
            const tokenInput = document.getElementById('skyplan_token');
            if (tokenInput) {
                tokenInput.value = localStorage.getItem('skyplan_token') || '';
            }

            const refreshInput = document.getElementById('skyplan_refresh_token');
            if (refreshInput) {
                refreshInput.value = localStorage.getItem('skyplan_refresh_token') || '';
            }

            // 2. Load the rest of the settings
            const settings = JSON.parse(localStorage.getItem('efb_settings') || '{}');
            
            if (settings.autoLockTime) {
                const autoLockSelect = document.getElementById('auto-lock-time');
                if (autoLockSelect) autoLockSelect.value = settings.autoLockTime;
            }
            
            if (settings.pdfQuality) {
                const pdfQualitySelect = document.getElementById('pdf-quality');
                if (pdfQualitySelect) pdfQualitySelect.value = settings.pdfQuality;
            }

            const hideFCDutyBox = document.getElementById('hide-all-duty');
            if (hideFCDutyBox) {
                hideFCDutyBox.checked = settings.hideFCDuty === true; 
            }

            const autoActivateCheckbox = document.getElementById('auto-activate-next');
            if (autoActivateCheckbox) {
                autoActivateCheckbox.checked = settings.autoActivateNext !== false;
            }

            const modeSelect = document.getElementById('atis-input-mode');
            if (modeSelect) {
                modeSelect.value = settings.atisInputMode || 'typing';
                if (typeof applyInputMode === 'function') {
                    applyInputMode(settings.atisInputMode || 'typing');
                }
            }
                
            const versionEl = document.getElementById('settings-version');
            if (versionEl && typeof APP_VERSION !== 'undefined') {
                versionEl.textContent = `v${APP_VERSION}`;
            }
            
            const updatedEl = document.getElementById('settings-updated');
            if (updatedEl) {
                updatedEl.textContent = new Date().toLocaleDateString();
            }
            
        } catch (error) {
            console.error('Failed to load settings:', error);
        }
    }

    function saveSettings() {
        const settings = {
            autoLockTime: document.getElementById('auto-lock-time')?.value || '15',
            pdfQuality: document.getElementById('pdf-quality')?.value || '2.0',
            hideAllDuty: document.getElementById('hide-all-duty')?.checked || false,
            autoActivateNext: document.getElementById('auto-activate-next')?.checked !== false,
            atisInputMode: document.getElementById('atis-input-mode')?.value || 'typing',
            lastSaved: new Date().toISOString()
        };

        // Persistent authentication logic
        if (settings.autoLockTime == 0) {
            // If currently authenticated, set persistent flag
            if (sessionStorage.getItem('efb_authenticated') === 'true') {
                localStorage.setItem(PERSIST_AUTH_KEY, 'true');
            }
        } else {
            // Auto-lock is enabled → remove persistent authentication
            localStorage.removeItem(PERSIST_AUTH_KEY);
        }

        localStorage.setItem('efb_settings', JSON.stringify(settings));

        // ==========================================
        // TOKEN SAVING LOGIC
        // ==========================================
        const tokenInput = document.getElementById('skyplan_token');
        const refreshInput = document.getElementById('skyplan_refresh_token');

        if (tokenInput) {
            const newToken = tokenInput.value.trim();
            if (newToken) {
                localStorage.setItem('skyplan_token', newToken);
                
                // Automatically extract and save the user's username
                try {
                    const decoded = decodeJWT(newToken);
                    if (decoded && decoded.preferred_username) {
                        localStorage.setItem('efb_user', decoded.preferred_username);
                    }
                } catch (err) {
                    console.warn("Could not extract username from token.");
                }
            } else {
                localStorage.removeItem('skyplan_token');
                localStorage.removeItem('efb_user');
            }
        }

        if (refreshInput) {
            const newRefreshToken = refreshInput.value.trim();
            if (newRefreshToken) {
                localStorage.setItem('skyplan_refresh_token', newRefreshToken);
            } else {
                localStorage.removeItem('skyplan_refresh_token');
            }
        }
        // ==========================================

        if (sessionStorage.getItem('efb_authenticated') === 'true') {
            resetAutoLockTimer();
        }
        showToast('Settings saved successfully');
    }

    function isNewerVersion(latest, current) {
        const latestParts = latest.split('.').map(Number);
        const currentParts = current.split('.').map(Number);
        for (let i = 0; i < Math.max(latestParts.length, currentParts.length); i++) {
            const l = latestParts[i] || 0;
            const c = currentParts[i] || 0;
            if (l !== c) return l > c;
        }
        return false;
    }

// ==========================================
// 17. EVENT LISTENERS
// ==========================================

    window.addEventListener('DOMContentLoaded', function() {
        // 1. Initialize pdfFallbackElement
        pdfFallbackElement = document.getElementById('pdf-fallback');
        
        // 2. Check initial OFP state
        if (window.ofpPdfBytes) {
            setOFPLoadedState(true);
        } else {
            setOFPLoadedState(false);
        }
        
        // 3. Add drag and drop functionality for the overlay
        const overlay = document.getElementById('upload-overlay');
        const ofpFileInput = document.getElementById('ofp-file-in');
        
        if (overlay && ofpFileInput) {
            // Drag enter/over
            ['dragenter', 'dragover'].forEach(eventName => {
                overlay.addEventListener(eventName, (e) => {
                    e.preventDefault();
                    e.stopPropagation();
                    overlay.style.background = 'rgba(0, 132, 255, 0.3)';
                }, false);
            });
            
            // Drag leave
            ['dragleave', 'drop'].forEach(eventName => {
                overlay.addEventListener(eventName, (e) => {
                    e.preventDefault();
                    e.stopPropagation();
                    overlay.style.background = 'rgba(0, 0, 0, 0.9)';
                }, false);
            });
            
            // Drop
            overlay.addEventListener('drop', (e) => {
                e.preventDefault();
                e.stopPropagation();
                const files = e.dataTransfer.files;
                if (files.length > 0) {
                    ofpFileInput.files = files;
                    ofpFileInput.dispatchEvent(new Event('change'));
                }
            }, false);
        }
        
        // 4. Initialize theme on page load
        const savedTheme = localStorage.getItem('data-theme');
        const html = document.documentElement;
        const themeButton = document.querySelector('.theme-toggle');
        
        if (savedTheme) {
            // Apply saved theme
            html.setAttribute('data-theme', savedTheme);
            
            // Update button text and active state
            if (themeButton) {
                themeButton.textContent = savedTheme === 'dark' ? 'Day Mode' : 'Night Mode';
            }
        } else {
            // Default to light theme if no saved preference
            html.setAttribute('data-theme', 'light');
            if (themeButton) {
                themeButton.textContent = 'Night Mode';
            }
        }
        
        // 5. Initialize tab navigation
        initializeTabNavigation();
        
        // 6. Initial update for upload button visibility
        updateUploadButtonVisibility();

        initFileManagerTabs();
        
        // 7. Add time input masks
        addTimeInputMasks();
        
        // 8. Initialize Main Drawing Pad
        setTimeout(() => {
            initPad('main');
            if (pads.main.pad) {
                pads.main.pad.onEnd = () => {
                    debouncedSave();
                };
                // Restore saved signature if exists (from savedSignatureData)
                if (savedSignatureData) {
                    pads.main.pad.fromDataURL(savedSignatureData, { ratio: pads.main.lastRatio });
                }
            }

        }, 100);

        // Clear buttons for ATIS/ATC
        const clearAtis = document.getElementById('clear-atis-btn');
        const clearAtc = document.getElementById('clear-atc-btn');

        if (clearAtis) {
            clearAtis.addEventListener('click', () => clearPad('atis'));
        }
        if (clearAtc) {
            clearAtc.addEventListener('click', () => clearPad('atc'));
        }
    
        // Auto-save settings when changed
        ['auto-lock-time', 'pdf-quality','auto-activate-next','hide-all-duty'].forEach(id => {
            const element = document.getElementById(id);
            if (element) {
                element.addEventListener('change', saveSettings);
            }
        });

        // Token elements
        const tokenInput = document.getElementById('input-token');
        const refreshTokenInput = document.getElementById('refresh-token');

        if (tokenInput) {
            tokenInput.value = localStorage.getItem('skyplan_token') || '';

            tokenInput.addEventListener('input', (e) => {
                const newToken = e.target.value.trim();
                
                if (newToken) {
                    localStorage.setItem('skyplan_token', newToken);
                    
                    // Automatically extract and save the user's username!
                    try {
                        const decoded = decodeJWT(newToken);
                        if (decoded && decoded.preferred_username) {
                            localStorage.setItem('efb_user', decoded.preferred_username);
                            console.log("Logged in user:", decoded.preferred_username);
                        }
                    } catch (err) {
                        console.warn("Could not extract username from token.");
                    }
                    
                } else {
                    localStorage.removeItem('skyplan_token');
                    localStorage.removeItem('efb_user'); // Clear username on logout
                }
            });
        }

        // Add the listener for the Refresh Token
        if (refreshTokenInput) {
            refreshTokenInput.value = localStorage.getItem('skyplan_refresh_token') || '';

            refreshTokenInput.addEventListener('input', (e) => {
                const newRefreshToken = e.target.value.trim();
                if (newRefreshToken) {
                    localStorage.setItem('skyplan_refresh_token', newRefreshToken);
                } else {
                    localStorage.removeItem('skyplan_refresh_token');
                }
            });
        }

        document.getElementById('notam-filter')?.addEventListener('input', function() {
            const filterText = this.value.toLowerCase().trim();
            if (!window.notamFullAlerts) return;
            if (filterText === '') {
                renderNotamsWXTable(window.notamFullAlerts);
            } else {
                const filtered = window.notamFullAlerts.filter(alert => {
                    const airport = (alert.airport || '').toLowerCase();
                    const message = (alert.message || '').toLowerCase();
                    const type = (alert.type || '').toLowerCase();
                    return airport.includes(filterText) || message.includes(filterText) || type.includes(filterText);
                });
                renderNotamsWXTable(filtered);
            }
        });

        // Wire up the ATIS and CLR text field (typing mode only)
        const atisField = document.getElementById('front-atis');
        if (atisField) {   // ← only attach ATIS listener if element exists
            atisField.addEventListener('focus', function(e) {
                const settings = JSON.parse(localStorage.getItem('efb_settings') || '{}');
                if (settings.atisInputMode !== 'writing') {
                    e.preventDefault();
                    atisField.blur();
                    showAtisPopup();
                }
            });
        }

        const atcField = document.getElementById('front-atc');
        if (atcField) {
            atcField.addEventListener('focus', function(e) {
                const settings = JSON.parse(localStorage.getItem('efb_settings') || '{}');
                if (settings.atisInputMode !== 'writing') {   // same mode setting as ATIS
                    e.preventDefault();
                    atcField.blur();
                    showClearancePopup();
                }
            });
        }

        const btn = document.getElementById('btn-send-tripinfo');
        if (btn) {
            btn.addEventListener('click', sendTripInfo);
        }

        // Activity tracking
        if (sessionStorage.getItem('efb_authenticated') === 'true') {
            setupActivityTracking();
            resetAutoLockTimer();
        }
        loadState();
    });

    window.addEventListener('beforeunload', () => {
        debouncedSave.cancel();
        saveState(); 
    });

    // Trigger Save on tab change
    document.addEventListener('visibilitychange', () => {
        if (document.visibilityState === 'hidden') {
            saveState();
        }
    });

    window.addEventListener('resize', function() {
        resizePad('main');
        if (currentAtisInputMode === 'writing') {
            resizePad('atis');
            resizePad('atc');
        }
    });


    window.addEventListener('pagehide', () => {
        saveState();
    });

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
// Trip Info
// ==========================================

function parseSkyplanCrew(apiResponse) {
  const flightData = apiResponse?.FlightsCrewMembers?.[0];

  if (!flightData || !Array.isArray(flightData.CrewMembers)) {
    return {
      flightId: null,
      captain: null,
      flightDeck: [],
      cabinCrew: [],
      allCrew: []
    };
  }

  const crewMembers = flightData.CrewMembers;

  // Format individual member objects
  const formattedMembers = crewMembers.map(member => ({
    employeeId: member.EmployeeID,
    firstName: member.FirstName,
    lastName: member.LastName,
    fullName: `${member.FirstName} ${member.LastName}`.trim(),
    position: member.Position,
    phoneNumber: member.PhoneNumber,
    dateOfBirth: member.DateOfBirth ? member.DateOfBirth.split('T')[0] : null
  }));

  // Role categorization
  const flightDeckPositions = ['CP', 'FO'];

  const captain = formattedMembers.find(m => m.position === 'CP') || null;
  const flightDeck = formattedMembers.filter(m => flightDeckPositions.includes(m.position));
  const cabinCrew = formattedMembers.filter(m => !flightDeckPositions.includes(m.position));

  return {
    flightId: flightData.FlightID,
    pilotCount: flightData.PilotCount,
    totalCrewCount: flightData.CrewCount,
    captain: captain ? {
      name: captain.fullName,
      employeeId: captain.employeeId,
      phone: captain.phoneNumber
    } : null,
    flightDeck,
    cabinCrew,
    allCrew: formattedMembers
  };
}

function convertTripTime(timeStr) {
    if (!timeStr || timeStr === '-') return '';
    // Expect "HH.MM"
    const [h, m] = timeStr.split('.');
    return (h || '00').padStart(2,'0') + (m || '00').padStart(2,'0');
}

async function fetchFlightIdFromRoster(flightDateStr, flightNumberRaw, depIcaoRaw) {
    console.log('--- [Roster Check] START ---');
    console.log(`1. Raw Inputs -> Date: "${flightDateStr}", Flight: "${flightNumberRaw}", Dep: "${depIcaoRaw}"`);

    const token = await getValidSkyplanToken();
    if (!token) {
        console.error('❌ No token found in localStorage.');
        return null;
    }
    console.log('2. Token found in storage (starts with):', token.substring(0, 15) + '...');

    let employeeId = '15183';
    try {
        const employee = decodeJWT(token);
        employeeId = employee.employeeid || '15183';
        console.log(`3. Decoded JWT -> EmployeeID: ${employeeId}`);
    } catch (e) {
        console.warn('⚠️ Failed to decode JWT, defaulting to employee 15183', e);
    }

    // Clean inputs
    const flightNumber = String(parseInt(flightNumberRaw.replace(/\D/g, ''), 10)); 
    const depIcao = depIcaoRaw.replace(/[^A-Z]/ig, '').toUpperCase(); 
    console.log(`4. Cleaned Inputs -> FlightNumber: "${flightNumber}", DepStation: "${depIcao}"`);

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
    console.log(`5. Parsed Base Date: "${flightDate}"`);

    const baseDate = new Date(flightDate);
    if (isNaN(baseDate.getTime())) {
        console.error("❌ Date parsing failed completely.");
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
    console.log('6. Sending API Payload:', payload);
    
    try {
        const resp = await fetch('https://kcskyplanapi.airastana.com/api/v1/crew-roster-flights-details', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`
            },
            body: JSON.stringify(payload)
        });
        
        console.log(`7. API Response Status: ${resp.status} ${resp.statusText}`);
        
        if (!resp.ok) {
            if (resp.status === 401) {
                console.error('❌ 401 Unauthorized - Your Skyplan token has expired or is invalid.');
                showToast('Skyplan Token Expired. Please update in settings.', 'error');
            }
            const errText = await resp.text();
            console.error(`❌ Error Response Body:`, errText);
            throw new Error(`Status ${resp.status}`);
        }
        
        const data = await resp.json();
        const flights = data.Flights || [];
        console.log(`8. Roster Fetch Success! Found ${flights.length} flights in the window.`);

        // Dump what flights it actually sees to the console
        if (flights.length > 0) {
            console.log('9. Available flights from API:');
            flights.forEach(f => {
                console.log(`   -> ${f.CarrierCode}${f.FlightNumber} | Dep: ${f.DepartureStationIcaoCode}/${f.DepartureStationCode} | Date: ${f.StdLt}`);
            });
        }

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
            console.log(`10. ✅ MATCH FOUND! Assigned ExternalFlightID: ${match.ID}`);
            console.log('--- [Roster Check] END ---');
            return match.ID;
        } else {
            console.warn(`10. ⚠️ NO MATCH. Could not find Flight ${flightNumber} departing from ${depIcao} in the array above.`);
            console.log('--- [Roster Check] END ---');
            return null;
        }

    } catch (e) {
        console.error('❌ [Roster Check] Failed entirely:', e);
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

window.getValidSkyplanToken = async function() {
    let token = localStorage.getItem('skyplan_token');
    let refreshToken = localStorage.getItem('skyplan_refresh_token');

    if (!token) return null;

    const decoded = decodeJWT(token);
    if (!decoded || typeof decoded.exp !== 'number') {
        // Could not decode or no expiry – assume token is still valid, do not refresh
        return token;
    }

    const now = Math.floor(Date.now() / 1000);
    if (decoded.exp > now + 300) {
        return token;  // still valid
    }

    // Only now do we know for certain it’s expired

    // --- TOKEN IS EXPIRED ---
    if (!refreshToken) {
        console.warn("Access token expired and no refresh token found in settings.");
        if (typeof showToast === 'function') showToast("Skyplan token expired. Please update settings.", "error");
        return null; 
    }

    try {
        console.log("Access token expired. Auto-refreshing in background...");
        
        // Call the Keycloak token endpoint
        const response = await fetch('https://id.airastana.com/realms/air-astana/protocol/openid-connect/token', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded'
            },
            // Note: client_id 'app-sky-plan-web' is extracted directly from your token's 'azp' field
            body: new URLSearchParams({
                'grant_type': 'refresh_token',
                'client_id': 'app-sky-plan-web',
                'refresh_token': refreshToken
            })
        });

        if (response.ok) {
            const data = await response.json();
            
            // Save the new tokens!
            token = data.access_token;
            localStorage.setItem('skyplan_token', token);
            
            if (data.refresh_token) {
                localStorage.setItem('skyplan_refresh_token', data.refresh_token);
                // Also update the UI input box if settings are currently open
                const refreshInput = document.getElementById('skyplan_refresh_token');
                if (refreshInput) refreshInput.value = data.refresh_token;
            }
            
            console.log("Token refreshed successfully!");
            return token;
        } else {
            console.error("Failed to refresh token. It may have expired. Code:", response.status);
            if (typeof showToast === 'function') showToast("Session expired completely. Please get new tokens.", "error");
            return null;
        }
    } catch (e) {
        console.error("Network error while trying to refresh token:", e);
        return token; // Return old token as a last resort, though it will likely fail
    }
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
        let employeeId = null;
        try {
            const employee = decodeJWT(token);
            employeeId = employee.employeeid;
        } catch (e) {
            console.warn('Failed to decode JWT for employee ID, using default.');
        }

        if (!employeeId) {
            container.innerHTML = '<div style="color: #ff6b6b; text-align: center; padding: 40px; font-family: sans-serif;">⚠️ Could not find Employee ID in your token. Please generate a new token.</div>';
            return;
        }

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

        // Filter and Sort
        flights = flights.filter(f => ['KC', 'AYN', 'FS'].includes(f.CarrierCode));
        flights.sort((a, b) => new Date(a.StdLt) - new Date(b.StdLt));

        if (flights.length === 0) {
            container.innerHTML = '<div style="color: white; text-align: center; padding: 40px; font-family: sans-serif;">No assigned flights found in the next 3 days.</div>';
            return;
        }

        // Pro-tip: Log the very first flight to the console so you can see ALL the hidden data!
        console.log("Here is everything Skyplan knows about your first flight:", flights[0]);

        // Build the UI Table
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
            const dateStr = f.StdLt ? f.StdLt.split('T')[0] : 'Unknown';
            const flightNum = `${f.CarrierCode}${f.FlightNumber}`;
            const routing = `${f.DepartureStationIcaoCode || f.DepartureStationCode} ➔ ${f.ArrivalStationIcaoCode || f.ArrivalStationCode}`;
            
            const stdStr = f.StdLt ? f.StdLt.split('T')[1].substring(0, 5) : '--:--';
            const staStr = f.StaLt ? f.StaLt.split('T')[1].substring(0, 5) : '--:--';
            
            const aircraft = f.RegistrationNumber || f.AircraftDescription || 'TBA';

            let blockTime = '--:--';
            if (f.DurationMinutes) {
                const hrs = Math.floor(f.DurationMinutes / 60);
                const mins = f.DurationMinutes % 60;
                blockTime = `${hrs}h ${mins.toString().padStart(2, '0')}m`;
            } else if (f.Std && f.Sta) {
                const diffMs = new Date(f.Sta) - new Date(f.Std);
                if (diffMs > 0) {
                    const hrs = Math.floor(diffMs / 3600000);
                    const mins = Math.floor((diffMs % 3600000) / 60000);
                    blockTime = `${hrs}h ${mins.toString().padStart(2, '0')}m`;
                }
            }

            html += `
                <tr class="assigned-flight-row">
                    <td class="assigned-date">${dateStr}</td>
                    <td class="assigned-flight">${flightNum}</td>
                    <td class="assigned-route">${routing}</td>
                    <td class="assigned-time">${stdStr}</td>
                    <td class="assigned-sta">${staStr}</td>
                    <td class="assigned-block">${blockTime}</td>
                    <td class="assigned-reg">${aircraft}</td>
                                        <td style="padding: 15px; text-align: right;">
                                                                <button onclick="importOFPFromSkyplan('${f.ID}', '${flightNum}', '${dateStr}')" 
                                                                                                style="background: #81c995; color: #000; border: none; padding: 6px 12px; border-radius: 4px; font-weight: bold; cursor: pointer;">
                                                                                                                            Sync OFP
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

window.importOFPFromSkyplan = async function(flightId, flightNum, dateStr) {
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

                                                                                                                                                                                                                                    // 3. FORCE THE CORRECT FILENAME so the parser knows what flight it is!
                                                                                                                                                                                                                                            const safeDate = dateStr ? dateStr.replace(/-/g, '') : 'UnknownDate';
                                                                                                                                                                                                                                                    const safeFlight = flightNum ? flightNum.replace(/\s+/g, '') : 'UnknownFlight';
                                                                                                                                                                                                                                                            const fileName = `${safeFlight}_${safeDate}_OFP.pdf`;
                                                                                                                                                                                                                                                                    
                                                                                                                                                                                                                                                                            const file = new File([bytes], fileName, { type: 'application/pdf' });

                                                                                                                                                                                                                                                                                    if (typeof showToast === 'function') showToast("OFP Downloaded! Extracting data...", "success");

                                                                                                                                                                                                                                                                                            // 4. Send it directly to your existing pipeline
                                                                                                                                                                                                                                                                                                    if (typeof runAnalysis === 'function') {
                                                                                                                                                                                                                                                                                                                // runAnalysis will now parse it, save it, and auto-activate it automatically
                                                                                                                                                                                                                                                                                                                            await runAnalysis(file, false);
                                                                                                                                                                                                                                                                                                                                    } else {
                                                                                                                                                                                                                                                                                                                                                alert("Error: Core PDF analyzer is missing.");
                                                                                                                                                                                                                                                                                                                                                        }

                                                                                                                                                                                                                                                                                                                                                            } catch (error) {
                                                                                                                                                                                                                                                                                                                                                                    console.error("Failed to import OFP:", error);
                                                                                                                                                                                                                                                                                                                                                                            alert("Error syncing OFP: " + error.message);
                                                                                                                                                                                                                                                                                                                                                                                }
                                                                                                                                                                                                                                                                                                                                                                                }
                                                                                                                                                                                                                                                                                                                                                                                 
}
    // Shared function to restore OFP‑specific user data (waypoints + persistent inputs)
    async function restoreOFPData(ofp) {
        if (!ofp) return;

        // Restore saved waypoint inputs (userWaypoints)
        if (ofp.userWaypoints && Array.isArray(ofp.userWaypoints)) {
            ofp.userWaypoints.forEach((data, i) => {
                if (i < waypoints.length) {
                    if (data.ato) safeSet(`o-a-${i}`, data.ato);
                    if (data.fuel) safeSet(`o-f-${i}`, data.fuel);
                    if (data.notes) safeSet(`o-n-${i}`, data.notes);
                    if (data.agl) safeSet(`o-agl-${i}`, data.agl);
                }
            });
            runFlightLogCalculations();
            syncLastWaypoint();
        }

        // Restore saved user inputs (persistent text fields)
        if (ofp.userInputs && typeof ofp.userInputs === 'object') {
            Object.keys(ofp.userInputs).forEach(id => {
                const val = ofp.userInputs[id];
                // Skip drawing keys – they will be restored by pad initialisation
                if (id === 'signature' || id === 'front-atis-drawing' || id === 'front-atc-drawing') return;
                if (val !== undefined && val !== null) {
                    safeSet(id, val);
                }
            });
        }
    }
    async function getAllOFPOrders() {
        const db = await getDB();
        if (!db.objectStoreNames.contains('ofp_orders')) return [];
        return new Promise((resolve, reject) => {
            const tx = db.transaction("ofp_orders", "readonly");
            const store = tx.objectStore("ofp_orders");
            const request = store.getAll();
            request.onsuccess = () => resolve(request.result);
            request.onerror = (e) => reject(e);
        });
    }
    async function rebuildOFPOrders() {
        const db = await getDB();
        const tx = db.transaction(["ofps", "ofp_orders"], "readwrite");
        const ofpsStore = tx.objectStore("ofps");
        const ordersStore = tx.objectStore("ofp_orders");
        
        // Clear existing orders
        ordersStore.clear();

        const ofps = await new Promise((res, rej) => {
            const req = ofpsStore.getAll();
            req.onsuccess = () => res(req.result);
            req.onerror = (e) => rej(e);
        });

        ofps.forEach(ofp => {
            ordersStore.put({ id: ofp.id, order: ofp.order || 0 });
        });

        await new Promise((res, rej) => {
            tx.oncomplete = res;
            tx.onerror = (e) => rej(e);
        });
        console.log('OFP orders rebuilt');
    }
    async function restoreOFPUserData(userData) {
        if (userData.userWaypoints && Array.isArray(userData.userWaypoints)) {
            userData.userWaypoints.forEach((data, i) => {
                if (i < waypoints.length) {
                    if (data.ato) safeSet(`o-a-${i}`, data.ato);
                    if (data.fuel) safeSet(`o-f-${i}`, data.fuel);
                    if (data.notes) safeSet(`o-n-${i}`, data.notes);
                    if (data.agl) safeSet(`o-agl-${i}`, data.agl);
                }
            });
            runFlightLogCalculations();
            syncLastWaypoint();
        }
        if (userData.userInputs && typeof userData.userInputs === 'object') {
            Object.keys(userData.userInputs).forEach(id => {
                const val = userData.userInputs[id];
                if (id === 'signature' || id === 'front-atis-drawing' || id === 'front-atc-drawing') {
                    // Handle drawings after pads are initialized (already handled elsewhere)
                    // We'll rely on the pad restoration logic
                } else {
                    safeSet(id, val);
                }
            });
            // Restore drawings if needed – you may need to call a separate function
            if (userData.userInputs.signature && pads.main.pad) {
                pads.main.pad.fromDataURL(userData.userInputs.signature);
            }
            if (userData.userInputs['front-atis-drawing'] && pads.atis.pad) {
                pads.atis.pad.fromDataURL(userData.userInputs['front-atis-drawing']);
            }
            if (userData.userInputs['front-atc-drawing'] && pads.atc.pad) {
                pads.atc.pad.fromDataURL(userData.userInputs['front-atc-drawing']);
            }
        }
    }
    async function setActiveOFP(id) {
        localStorage.setItem('activeOFPId', Number(id));
        console.log(`[setActiveOFP] active ID set to ${id}`);
    }
    async function getAllOFPsFromDB() {
        try {
            const db = await getDB();
            if (!db.objectStoreNames.contains('ofps')) return [];

            return new Promise((resolve, reject) => {
                const tx = db.transaction("ofps", "readonly");
                const store = tx.objectStore("ofps");
                const request = store.getAll();

                request.onsuccess = () => {
                    const ofps = request.result;
                    ofps.sort((a, b) => (a.order || 0) - (b.order || 0));
                    resolve(ofps);
                };
                request.onerror = (e) => reject(e.target.error);
            });
        } catch (error) {
            console.error('getAllOFPsFromDB failed:', error);
            return [];
        }
    }

})();