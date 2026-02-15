(function() {
const APP_VERSION = "2.0.4";
const RELEASE_NOTES = {
    "2.0.4": {
        title: "Release Notes",
        notes: [
            "✍️ Write or Type ATIS/ATC",
            "⚡ DOM caching for waypoint inputs – 10x faster flight log updates",
            "📁 Upload multiple OFPs at once",
            "🆕 Shear Rate (SR) column added to Flight Log and Alternate tables",
            "📁 Downloaded OFP filenames now include flight number and date",
            "📋 OFP Manager table with Trip Time, Max SR, Request #",
            "🔄 Replace existing OFPs (same flight/date)",
            "✅ Finalized OFP indicator and download",
            "🎨 New Sectors tab with search & reorder",
            "✍️ Signature pad scaling fixed",
            "🔐 Auto‑lock ‘Never’ now persists across reloads",
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
const EXPECTED_SW_HASH = '43c3ee5e095f8a16ccf0e5677a19a68920d243eed6d2f64857243571eeff1a22';
const SW_HASH_STORAGE_KEY = 'efb_sw_hash_cache';
const PERSISTENT_INPUT_IDS = [
    'front-atis', 'front-atc', 'front-altm1', 'front-stby', 'front-altm2',
    'front-extra-kg', 'front-extra-reason', 'view-pic-block'
];


// ==========================================
// 1. CONFIGURATION & UPDATE LOGIC
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
                    alert('Pop-up blocked. Please allow pop-ups for this site.');
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

    // Setup for Authentication
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

    // Generate or retrieve encryption key
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

    // Encrypt data
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

    // Decrypt data
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
// UTILITY: Debounce
// ==========================================

    /**
     * Creates a debounced function that delays invoking `func` until after `wait` milliseconds
     * have elapsed since the last time the debounced function was invoked.
     * @param {Function} func - The function to debounce.
     * @param {number} wait - Milliseconds to wait.
     * @param {boolean} [immediate=false] - If true, trigger `func` on the leading edge instead of trailing.
     * @returns {Function} Debounced function with a `cancel` method.
     */
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
// 2. STATE & VARIABLES
// ==========================================

    const JOURNEY_CONFIG = {
        fontSize: 10,
        
        // Vertical positioning for the leg list
        rowStartMain: 525, 
        rowStartFuel: 420,
        rowStartCrew: 350, 
        rowGap: 17, 
        
        // Signature Position for Journey Log
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
// 3. INITIALIZATION & LISTENERS
// ==========================================

    async function initializeApp() {
        // Debugging if IndexedDB is working
        const hasPdf = await checkPdfInDB();
        // --- PDF.js worker setup ---
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
        
        // Journey Log Upload
        const journeyLogFile = el('journey-log-file');
        if (journeyLogFile) {
            journeyLogFile.addEventListener('change', async function(e) {
                const file = e.target.files[0];
                if (file) {
                    journeyLogTemplateBytes = await file.arrayBuffer();
                }
            });
        }
        
        // REAL-TIME CALCULATION LISTENERS (debounced)
        ['j-out','j-off','j-on','j-in'].forEach(id => {
            const e = el(id);
            if (e) e.addEventListener('input', debounce(calcTripTime, 300)); // uses global debounce
        });
            
        ['j-init', 'j-uplift-w', 'j-calc-ramp', 'j-act-ramp', 'j-shut', 'j-burn', 'j-uplift-vol', 'j-disc', 'j-slip', 'j-slip-2'].forEach(id => {
            const e = el(id);
            if (e) e.addEventListener('input', debounce(calcFuel, 300));
        });

        ['j-adl', 'j-chl', 'j-inf', 'j-cargo', 'j-mail', 'j-bag', 'j-zfw'].forEach(id => {
            const e = el(id);
            if (e) e.addEventListener('input', debounce(calcFuel, 300));
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

        // Validation Triggers (debounced)
        const altm1Input = el('front-altm1');
        if(altm1Input) altm1Input.addEventListener('input', debounce(validateOFPInputs, 500));
        
        ['j-flt', 'j-date'].forEach(id => {
            const e = el(id);
            if(e) e.addEventListener('input', debounce(validateOFPInputs, 500));
        });

        // OFFLINE AUTO‑LOAD LOGIC
        try {
            const activeOFP = await getActiveOFPFromDB();
            if (activeOFP && activeOFP.data) {
                setOFPLoadedState(true);
                window.ofpPdfBytes = await activeOFP.data.arrayBuffer();
                window.originalFileName = activeOFP.fileName || "Logged_OFP.pdf";

                // Parse the OFP
                await runAnalysis(activeOFP.data, true);

                // Restore all saved OFP data (waypoints + persistent inputs)
                await restoreOFPData(activeOFP);

                // Restore other non‑OFP state (dailyLegs, dutyStartTime, inputs) from localStorage
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

        const allOFPs = await getCachedOFPs();
        if (allOFPs.length > 0 && !localStorage.getItem('activeOFPId')) {
            console.log("No active OFP set – activating the newest OFP.");
            await activateOFP(allOFPs[0].id);
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

    async function validatePDF(file) {
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
                alert('Invalid Document: This does not look like an Operational Flight Plan.');
                return false;
            }
            
            return true; 

        } catch (e) {
            console.error("PDF Validation Error:", e);
            alert('Error validating PDF: ' + e.message);
            return false;
        }
    }

    // One‑time migration of legacy localStorage state
    async function migrateLegacyState() {
        const MIGRATION_KEY = 'efb_state_migration_v2';
        if (localStorage.getItem(MIGRATION_KEY) === 'done') return;

        console.log('Running one‑time state migration...');
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
                    console.log(`Migrated ${key}`);
                }
            } catch (e) {
                console.warn(`Failed to migrate ${key}:`, e);
            }
        }

        localStorage.setItem(MIGRATION_KEY, 'done');
        console.log('State migration complete.');
    }

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
                await runAnalysis(file, false); 
                
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
    }

    // Shared manual upload preparation
    async function prepareForManualUpload() {
        if (typeof clearOFPInputs === 'function') clearOFPInputs();
        const legForm = document.getElementById('leg-input-form');
        if (legForm) legForm.style.display = 'block';
    }

    // Refresh OFP Manager table if visible
    async function afterManualUpload() {
        if (document.getElementById('section-sectors')?.classList.contains('active')) {
            await renderOFPMangerTable();
        }
    }

    // Handle replacement of an existing OFP
    async function handleReplacement(existingOFP, blob, metadata, previouslyActiveId) {
        const wasActive = existingOFP.isActive;
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
            isActive: wasActive,
            order: originalOrder
        };

        await updateOFP(replacedId, updatedData);
        await getCachedOFPs(true);

        if (!wasActive) {
            if (typeof clearOFPInputs === 'function') clearOFPInputs();

            if (previouslyActiveId && previouslyActiveId !== String(replacedId)) {
                await activateOFP(previouslyActiveId, false);
                showToast(`OFP updated: ${metadata.flight} (inactive)`, 'success');
            } else {
                setOFPLoadedState(false);
                showToast(`OFP updated: ${metadata.flight} (no active OFP)`, 'success');
            }
        } else {
            setOFPLoadedState(true);
            showToast(`OFP updated: ${metadata.flight} (active)`, 'success');
        }

        await afterManualUpload();
    }

    // Handle brand‑new OFP
    async function handleNewOFP(blob, metadata) {
        const currentActiveId = localStorage.getItem('activeOFPId');
        const shouldActivate = !currentActiveId;

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

        await afterManualUpload();
    }

    // Analyze OFP
    async function runAnalysis(fileOrEvent, isAutoLoad = false) {
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
                    const isValid = await validatePDF(blob);
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

        // 3. Manual upload: clear UI, show leg form
        if (!isAutoLoad && !isBatchUpload) {
            await prepareForManualUpload();
        }

        // 4. PARSE PDF
        let parseResult;
        try {
            parseResult = await parsePDFData(window.ofpPdfBytes, isAutoLoad);
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
                if (existingOFP) {
                    await handleReplacement(existingOFP, blob, metadata, previouslyActiveId);
                } else {
                    await handleNewOFP(blob, metadata);
                }
            } catch (error) {
                // Emergency fallback – something went wrong in the handlers
                console.error("Unexpected error during save:", error);
                const emergencyResult = await emergencySaveOFP(blob, metadata, existingOFP || null);
                let toastMessage = existingOFP
                    ? "OFP replaced (emergency mode"
                    : "OFP saved (emergency mode";
                if (!emergencyResult.pdfSaved) toastMessage += " – PDF not saved";
                if (!emergencyResult.ofpsRecordCreated) toastMessage += " – record not created";
                toastMessage += ")";
                showToast(toastMessage, emergencyResult.ofpsRecordCreated ? 'warning' : 'error');
                setOFPLoadedState(true);
            }
        }

        // After manual upload, force a full redraw of flight log tables
        if (!isAutoLoad) {
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

        // 7. Handle state
        if (isAutoLoad) {
        } else {
            saveState();
        }
    }
        
    // Validate Altimeter
    window.validateAltimeter = function(el) {
        el.value = el.value.replace(/[^0-9]/g, '').substring(0, 4);
    };

    // Validate Flight Times
    function validateFlightTime(timeStr, fieldName = '') {
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

    // Validate journey log time inputs
    function validateAllJourneyTimes() {
        const timeFields = ['j-out', 'j-off', 'j-on', 'j-in', 'j-std', 'j-duty-start', 'j-cc-duty-start'];
        
        timeFields.forEach(fieldId => {
            const input = el(fieldId);
            if (input && input.value) {
                try {
                    const validated = validateFlightTime(input.value, fieldId.replace('j-', '').toUpperCase());
                    input.value = validated.value;
                } catch (error) {
                    alert(`${fieldId.replace('j-', '').toUpperCase()}: ${error.message}`);
                    input.value = '';
                    input.focus();
                    throw error; // Stop further processing
                }
            }
        });
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

    // Handle input events 
    function handleWaypointInput(e) {
        const target = e.target;
        const id = target.id;
        if (!id) return;

        // --- ATO input (time) ---
        if (id.startsWith('o-a-') || id.startsWith('a-a-')) {
            const [prefix, , idx] = id.split('-');
            const index = parseInt(idx, 10);
            const isTO = (index === 0 && prefix === 'o');
            
            if (isTO) {
                try {
                    const validated = validateFlightTime(target.value, 'Takeoff Time');
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

        // --- Fuel input ---
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

        // --- Notes input ---
        else if (id.startsWith('o-n-') || id.startsWith('a-n-')) {
            debouncedSave();
        }

        // --- Actual FL input ---
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
                const validated = validateFlightTime(target.value, 'Waypoint Time');
                target.value = validated.value;
            } catch (error) {
                alert(error.message);
                target.value = '';
            }
        }
    }

// ==========================================
// 4. OFP PARSING LOGIC
// ==========================================

    // Activate OFP
    window.activateOFP = async function(id, switchTab = true) {
        if (isActivating) {
            console.warn('Already activating an OFP, please wait');
            showToast('Please wait, activation in progress', 'info');
            return;
        }
        await getCachedOFPs(true);
        isActivating = true;

        try {
            
            const numericId = Number(id);
            if (isNaN(numericId)) throw new Error('Invalid OFP ID');
            console.log('Activating OFP with ID:', numericId);

            // This will throw if not found
            const ofpToActivate = await getOFPById(numericId);
            console.log('OFP retrieved:', ofpToActivate);
            if (ofpToActivate.finalized) {
                showToast("Cannot activate a finalized OFP", 'error');
                return;
            }

            await setActiveOFP(numericId);
            const ofp = await getActiveOFPFromDB(); // This gets the active OFP after setting
            if (!ofp) throw new Error('Failed to load OFP data');

            // Clear existing data
            if (typeof clearOFPInputs === 'function') clearOFPInputs();

            setOFPLoadedState(true);
            window.ofpPdfBytes = await ofp.data.arrayBuffer();
            window.originalFileName = ofp.fileName || "Logged_OFP.pdf";

            await runAnalysis(ofp.data, true);
            await restoreOFPData(ofp);
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

        } catch (error) {
            console.error("Error activating OFP:", error);
            showToast(`Failed to activate OFP: ${error.message}`, 'error');
        } finally {
            isActivating = false;
        }
    };

    // Delete OFP
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
        } catch (error) {
            console.error("Error deleting OFP:", error);
            showToast("Failed to delete OFP", 'error');
        }
    };

    // Clear all OFPs
    window.clearAllOFPs = async function() {
        const confirmed = await showConfirmDialog(
            'Clear All OFPs',
            '⚠️ This will delete ALL stored OFPs. Continue?',
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
            // Try more specific pattern first
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

// ==========================================
// 5. FLIGHT LOG CALCULATION LOGIC
// ==========================================
    
    // Calculate Fuel on board
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
        
        // Update the Flight Log Table immediately //
        runFlightLogCalculations();
    };

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
                
                if (era) safeText('view-era-text', era);
                if (altn2) safeText('view-altn2', altn2);
                
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

    async function parsePage1(pdf) {
        const page = await pdf.getPage(1);
        const content = await page.getTextContent();
        const textContent = content.items.map(x => x.str).join(' ');

        extractFrontCoords(content.items);
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

        // Request Number – already extracted in parsePage1
        // We'll need to pass it; we'll get it as parameter

        // Basic flight info
        const flight = document.getElementById('view-flt')?.innerText || 'N/A';
        const date = document.getElementById('view-date')?.innerText || 'N/A';
        const dep = document.getElementById('view-dep')?.innerText || 'N/A';
        const dest = document.getElementById('view-dest')?.innerText || 'N/A';

        return { flight, date, dep, dest, tripTime, maxSR };
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

            // 5. Detect cutoff page (if any)
            for (let i = 4; i <= pdf.numPages; i++) { // start from page 4
                const page = await pdf.getPage(i);
                const content = await page.getTextContent();
                const textContent = content.items.map(x => x.str).join(' ');
                const cutoff = detectCutoffPage(textContent, i);
                if (cutoff !== null) {
                    window.cutoffPageIndex = cutoff;
                    break;
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

            // 10. Return everything needed
            return {
                success: true,
                metadata,
                tripTime,
                maxSR,
                requestNumber
            };

        } catch (error) {
            console.error('Error in parsePDFData:', error);
            throw error;
        }
    }
// ==========================================
// 7. UI RENDERING
// ==========================================

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
                    <span style="font-size:30px; margin-bottom:10px;">📄</span>
                    No OFP uploaded yet.
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
            if (!tbody) {
                console.error('OFP Manager table body not found');
                return;
            }

            const ofps = await getCachedOFPs();
            const filterText = document.getElementById('ofp-search-input')?.value.toLowerCase() || '';

            if (ofps.length === 0) {
                tbody.innerHTML = `
                    <tr>
                        <td colspan="9" style="text-align: center; padding: 30px; color: var(--dim);">
                            No OFPs uploaded yet.<br>
                        </td>
                    </tr>
                `;
                return;
            }

            // Filter logic
            const filtered = ofps.filter(ofp => {
                if (!filterText) return true;
                const flight = (ofp.flight || '').toLowerCase();
                const date = (ofp.date || '').toLowerCase();
                const dep = (ofp.departure || '').toLowerCase();
                const dest = (ofp.destination || '').toLowerCase();
                return flight.includes(filterText) || date.includes(filterText) || 
                    dep.includes(filterText) || dest.includes(filterText);
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

                // Status badge
                let statusBadge = '';
                if (ofp.finalized) {
                    statusBadge = `<span class="status-badge status-finalized">✓ Finalized</span>`;
                } else {
                    statusBadge = `<span class="status-badge ${ofp.isActive ? 'status-active' : 'status-inactive'}">
                        ${ofp.isActive ? '✓ Active' : 'Inactive'}
                    </span>`;
                }

                const activateDisabled = ofp.finalized || ofp.isActive;
                const activateTitle = ofp.finalized 
                    ? 'Cannot activate – OFP is finalized' 
                    : (ofp.isActive ? 'Already active' : 'Activate this OFP');

                return `
                    <tr data-ofp-id="${ofp.id}" ${ofp.isActive ? 'class="active-ofp-row"' : ''}>
                        <td><strong>${sanitizeHTML(flight)}</strong></td>
                        <td>${sanitizeHTML(date)}</td>
                        <td>${sanitizeHTML(dep)}</td>
                        <td>${sanitizeHTML(dest)}</td>
                        <td>${sanitizeHTML(ofp.tripTime || '—')}</td>
                        <td>${sanitizeHTML(ofp.maxSR || '—')}</td>
                        <td>${sanitizeHTML(ofp.requestNumber || '—')}</td>
                        <td>${statusBadge}</td>
                        <td style="white-space: nowrap;">
                            <button onclick="activateOFP(${ofp.id})" 
                                    class="btn-icon activate" 
                                    ${activateDisabled ? 'disabled' : ''}
                                    title="${activateTitle}">
                                ▶️
                            </button>
                            
                            ${ofp.finalized ? 
                                `<button onclick="downloadLoggedOFP(${ofp.id})" 
                                        class="btn-icon download" 
                                        title="Download Logged OFP">
                                    ⬇️
                                </button>` : 
                                `<button class="btn-icon download" disabled style="opacity:0.3" 
                                        title="Finalize OFP first">
                                    ⬇️
                                </button>`
                            }
                            
                            <button onclick="moveOFP(${ofp.id}, -1)" 
                                    class="btn-icon" 
                                    title="Move Up">
                                ▲
                            </button>
                            
                            <button onclick="moveOFP(${ofp.id}, 1)" 
                                    class="btn-icon" 
                                    title="Move Down">
                                ▼
                            </button>
                            
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
            console.error('Error rendering OFP Manager table:', error);
            const tbody = document.getElementById('ofp-manager-tbody');
            if (tbody) {
                tbody.innerHTML = `<tr><td colspan="9" style="text-align: center; padding: 30px; color: var(--error);">
                    Error loading OFPs: ${sanitizeHTML(error.message)}
                </td></tr>`;
            }
        }
    };

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

    // SECTORS TAB - Move OFP up  or down
    window.moveOFP = async function(id, direction) {
        if (isReordering) {
            console.warn('Reordering already in progress');
            showToast('Please wait, reordering in progress', 'info');
            return;
        }
        isReordering = true;

        try {
            const numericId = Number(id);
            if (isNaN(numericId)) throw new Error('Invalid ID');

            const db = await getDB();
            const tx = db.transaction("ofp_orders", "readwrite");
            const store = tx.objectStore("ofp_orders");

            // Get all orders
            const allOrders = await new Promise((resolve, reject) => {
                const req = store.getAll();
                req.onsuccess = () => resolve(req.result);
                req.onerror = (e) => reject(e);
            });

            allOrders.sort((a, b) => a.order - b.order);

            const index = allOrders.findIndex(o => o.id === numericId);
            if (index === -1) throw new Error(`Order for OFP ${numericId} not found`);

            const swapIndex = index + direction;
            if (swapIndex < 0 || swapIndex >= allOrders.length) return; // no move

            // Swap orders
            const temp = allOrders[index].order;
            allOrders[index].order = allOrders[swapIndex].order;
            allOrders[swapIndex].order = temp;

            // Save both updated orders
            store.put(allOrders[index]);
            store.put(allOrders[swapIndex]);

            await new Promise((resolve, reject) => {
                tx.oncomplete = resolve;
                tx.onerror = (e) => reject(e.target.error);
            });

            // Update cache (now metadata cache includes order from orders store)
            await getCachedOFPs(true);
            await renderOFPMangerTable();

            showToast("OFP order updated", 'success');

        } catch (error) {
            console.error("Error moving OFP:", error);
            showToast("Failed to update order: " + error.message, 'error');
        } finally {
            isReordering = false;
        }
    };

    async function renumberOFPOrders() {
        const db = await getDB();
        const tx = db.transaction("ofp_orders", "readwrite");
        const store = tx.objectStore("ofp_orders");
        
        const allOrders = await new Promise((res, rej) => {
            const req = store.getAll();
            req.onsuccess = () => res(req.result);
            req.onerror = (e) => rej(e);
        });
        
        allOrders.sort((a, b) => a.order - b.order);
        allOrders.forEach((ord, idx) => {
            ord.order = idx + 1;
            store.put(ord);
        });
        
        await new Promise((res, rej) => {
            tx.oncomplete = res;
            tx.onerror = (e) => rej(e);
        });
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

    // Handle changing tabs
    window.showTab = window.showTab || function(id, btn) {
        // Standard tab switching logic
        document.querySelectorAll('.tool-section').forEach(s => s.classList.remove('active'));
        document.querySelectorAll('.nav-btn').forEach(b => b.classList.remove('active'));
        if(el('section-'+id)) el('section-'+id).classList.add('active');
        if(btn) btn.classList.add('active');
        
        if (id === 'sectors') {
            // Refresh table
            setTimeout(() => {
                if (typeof renderOFPMangerTable === 'function') {
                    renderOFPMangerTable();
                }
            }, 100);
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
            // Ensure canvas is visible and then restore
            setTimeout(() => {
                resizePad('main');
                // Restore from IndexedDB/backup, not from savedSignatureData
                restorePadDrawing('main', 'signature');
            }, 50);
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
    function updateEmptyStates() {
        const activeSection = document.querySelector('.tool-section.active');
        const activeTabId = activeSection ? activeSection.id.replace('section-', '') : '';
        
        // Show empty state in Paper Flight Plan tab when no OFP
        if (activeTabId === 'paper' && !isOFPLoaded) {
            const pdfContainer = document.getElementById('pdf-render-container');
            const pdfFallback = document.getElementById('pdf-fallback');
            if (pdfContainer) pdfContainer.style.display = 'none';
            if (pdfFallback) {
                // Update the fallback to show upload button
                pdfFallback.innerHTML = `
                    <div id="empty-state-upload" class="empty-state-upload">
                        <div style="font-size: 48px; color: #ccc;">📄</div>
                        <h3 style="color: #ccc;">No OFP Uploaded</h3>
                        <p style="color: #ccc; text-align: center; max-width: 300px; margin-bottom: 20px;">
                            Upload your Operational Flight Plan to view it here
                        </p>
                        <button class="upload-center-btn" onclick="document.getElementById('ofp-file-in').click()">
                            📁
                            <span>Upload</span>
                        </button>
                    </div>
                `;
                pdfFallback.style.display = 'flex';
            }
        }
    }

    // Update upload button visibility
    function updateUploadButtonVisibility() {
        const overlay = document.getElementById('upload-overlay');
        const activeSection = document.querySelector('.tool-section.active');
        const activeTabId = activeSection ? activeSection.id.replace('section-', '') : '';
        
        // Show overlay only when:
        // 1. No OFP is loaded and not on Journey log, Sectors or Settings tab
        if (!isOFPLoaded && activeTabId !== 'journey' && activeTabId !== 'sectors' && activeTabId !== 'settings') {
            if (overlay) overlay.classList.remove('hidden');
        } else {
            if (overlay) overlay.classList.add('hidden');
        }
        
        // Also handle empty states in specific tabs
        updateEmptyStates();
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
            const pdfQuality = settings.pdfQuality || '1.0'; // Keep as string
            
            // Fixed scale mapping based on quality setting (as strings to avoid float issues)
            const qualityScales = {
                '0.8': 0.8,   // Low quality = 80% scale (faster rendering)
                '1.0': 1.0,   // Medium quality = 100% scale (standard)
                '1.5': 1.5,   // High quality = 150% scale (better readability)
                '2.0': 2.0    // Maximum quality = 200% scale (best for reading)
            };
            
            // Get the fixed scale from quality setting
            let fixedScale = qualityScales[pdfQuality] || 1.0;
            
            // Load PDF document
            const pdf = await pdfjsLib.getDocument(pdfBytes).promise;
            const totalPages = pdf.numPages;
            
            // Get first page for calculations
            const firstPage = await pdf.getPage(1);
            const firstViewport = firstPage.getViewport({ scale: 1 });
            const pageWidth = firstViewport.width;
            
            // Hide fallback, show container BEFORE measuring container width
            if (fallback) fallback.style.display = 'none';
            container.innerHTML = '';
            container.style.display = 'block';
            
            // Wait a moment for container to be visible and have dimensions
            await new Promise(resolve => setTimeout(resolve, 100));
            
            // Calculate container width - use offsetWidth instead of clientWidth
            let containerWidth = container.offsetWidth || container.clientWidth;
            
            // Ensure we have a valid width
            if (!containerWidth || containerWidth <= 0) {
                containerWidth = 800;
            }
            
            // Calculate maximum scale that fits container (leave 20px padding)
            const maxScaleForContainer = (containerWidth - 20) / pageWidth;
            
            // Use the smaller of fixed scale or container-fit scale
            let scale = Math.min(fixedScale, maxScaleForContainer);
            
            // Always ensure minimum readable scale (100% for readability)
            const MIN_SCALE = 1.0; // Changed from 0.8 to 1.0 for better readability
            scale = Math.max(scale, MIN_SCALE);
            
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
                    
                    // Set canvas dimensions
                    canvas.width = viewport.width;
                    canvas.height = viewport.height;
                    
                    // Apply CSS for responsive sizing
                    canvas.style.cssText = `
                        width: ${viewport.width}px;
                        max-width: 100%;
                        height: auto;
                        margin: 0 auto 20px auto;
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
                    
                    // Render the page
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
        
        if(typeof updateCruiseLevel === 'function') updateCruiseLevel();
    }

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


    // DRAWING FUNCTIONS
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
        if (!activeId) {
            console.log('No active OFP, skipping restore');
            return;
        }
        try {
            const ofp = await getActiveOFPFromDB();
            if (!ofp) {
                console.log('Active OFP not found in DB');
                return;
            }
            if (!ofp.userInputs) {
                console.log('ofp.userInputs is empty');
                return;
            }
            let data = ofp.userInputs[drawingKey];
            // Only try backup if the key does NOT exist (undefined), not if it's null
            if (data === undefined) {
                const backupKey = `drawing_backup_${activeId}_${drawingKey === 'front-atis-drawing' ? 'atis' : drawingKey === 'front-atc-drawing' ? 'atc' : 'signature'}`;
                const backup = localStorage.getItem(backupKey);
                if (backup) {
                    console.log('Found backup in localStorage, using it');
                    data = backup;
                    // Optionally restore it back to IndexedDB for future
                    try {
                        await updateOFP(activeId, { 
                            userInputs: { ...ofp.userInputs, [drawingKey]: backup } 
                        });
                    } catch (e) {
                        console.warn('Failed to restore backup to IndexedDB', e);
                    }
                }
            }

            if (!data) { // still no data? (null or undefined)
                return;
            }
            console.log(`Restoring ${drawingKey}, data length:`, data.length);
            if (!data.startsWith('data:image/png;base64,') || data.length < 100) {
                console.warn(`Invalid data URL for ${drawingKey}, skipping`);
                return;
            }

            const pad = pads[padName]?.pad;
            if (!pad) {
                console.warn(`Pad ${padName} not initialized yet – retrying in 100ms`);
                setTimeout(() => restorePadDrawing(padName, drawingKey), 100);
                return;
            }

            try {
                await pad.fromDataURL(data);
                resizePad(padName);
                console.log(`✅ Restored ${drawingKey} to ${padName} pad`);
            } catch (e) {
                console.error(`Failed to load drawing into pad ${padName}:`, e);
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

    // Incremental update functions
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
            const validated = validateFlightTime(v, 'Takeoff Time');
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
            // optionally re‑init (resize handled later)
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

// ==========================================
// 8. Journey Log Managment
// ==========================================

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
                let displayFDP = "";
                if (i === 0) {
                    // First leg: Show reporting to block
                    displayFDP = l.fdp || '-';
                } else {
                    // Subsequent legs: Show sector time (previous on block to current on block)
                    const prevLeg = dailyLegs[i-1];
                    if (prevLeg['j-in'] && l['j-in']) {
                        displayFDP = getDiff(prevLeg['j-in'], l['j-in']);
                    } else {
                        displayFDP = '-';
                    }
                }

                return `
                <tr>
                    <td style="text-align:center; font-weight:bold;">${i+1}</td>
                    <td>${sanitizeHTML(l['j-flt'])}</td>
                    <td>${sanitizeHTML(l['j-dep'])} - ${sanitizeHTML(l['j-dest'])}</td>
                    <td style="${l.fdpAlert ? 'color:red; font-weight:bold;' : ''}">${sanitizeHTML(displayFDP || '-')}</td>
                    
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

        // 4. Check FDP Limitation
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

        // 5. Save current leg data
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

        // Get the nightTime value from the j-night input
        const nightTime = d['j-night'] || "00:00";
        
        d.fdp = fdp; 
        d.fdpAlert = alertFdp;
        d.ccFdpAlert = ccFdpAlert;
        d.nightTime = nightTime; // Use the value we just got
        
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

            // 2.5 Re-calculate FDP Duration & Alerts for ALL legs
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
    
    // Calculate Block and Flight Time for current Leg
    window.calcTripTime = function() {
        try {
            validateAllJourneyTimes();
            
            const outT = el('j-out')?.value;
            const inT = el('j-in')?.value;
            const offT = el('j-off')?.value;
            const onT = el('j-on')?.value;

            if(outT && inT) safeSet('j-block', getDiff(outT, inT));
            else safeSet('j-block', '');
                
            if(offT && onT) safeSet('j-flight', getDiff(offT, onT));
            else safeSet('j-flight', '');
            
            calcDutyLogic();
        } catch (error) {
            // Validation failed, times cleared
            safeSet('j-block', '');
            safeSet('j-flight', '');
        }
    };

    // Update Cruise Level for Journey Leg
    window.updateCruiseLevel = function() {
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
        calcTripTime(); 
        calcFuel();
    };

    // Calculate Fuel values for current Leg
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

    // Helper for time calculation
    function getDiff(start, end) {
        if(!start || !end) return "";
        
        // Parse times - handle various formats
        const parseTime = (timeStr) => {
            if (!timeStr) return null;
            
            // Handle "HHMM" format (no colon)
            if (timeStr.length === 4 && /^\d{4}$/.test(timeStr)) {
                return {
                    h: parseInt(timeStr.substring(0, 2)),
                    m: parseInt(timeStr.substring(2, 4))
                };
            }
            
            // Handle "HH:MM" format
            if (timeStr.includes(':')) {
                const [h, m] = timeStr.split(':').map(Number);
                return { h, m };
            }
            
            return null;
        };
        
        const startTime = parseTime(start);
        const endTime = parseTime(end);
        
        if(!startTime || !endTime) return "";
        
        // Convert to minutes since midnight
        let startMinutes = startTime.h * 60 + startTime.m;
        let endMinutes = endTime.h * 60 + endTime.m;
        
        // Handle multi-day operations (up to 48 hours)
        // If end time appears to be earlier than start time, assume next day
        let dayOffset = 0;
        
        // If end is significantly earlier than start (more than 12 hours difference),
        // assume it's on the next day
        if (endMinutes < startMinutes - 720) { // 12 hours buffer
            dayOffset = 1;
        }
        // If start is near midnight and end is after midnight
        else if (endMinutes < startMinutes) {
            // For flights that cross midnight but are less than 12 hours
            dayOffset = 1;
        }
        
        // Calculate total minutes
        const totalMinutes = (endMinutes + (dayOffset * 1440)) - startMinutes;
        
        // Safety check: if total minutes is negative or unreasonable (more than 48 hours),
        // fall back to simple calculation
        if (totalMinutes < 0 || totalMinutes > 2880) { // 48 hours max
            // Fallback: assume same day
            const diff = endMinutes - startMinutes;
            if (diff < 0) {
                const correctedDiff = diff + 1440;
                const hours = Math.floor(correctedDiff / 60);
                const minutes = correctedDiff % 60;
                return `${hours.toString().padStart(2,'0')}:${minutes.toString().padStart(2,'0')}`;
            }
        }
        
        const hours = Math.floor(totalMinutes / 60);
        const minutes = totalMinutes % 60;
        
        // Format with day indicator if needed
        if (dayOffset > 0) {
            return `${hours.toString().padStart(2,'0')}:${minutes.toString().padStart(2,'0')}`;
        }
        
        return `${hours.toString().padStart(2,'0')}:${minutes.toString().padStart(2,'0')}`;
    }

    // Helper for time caluclation
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

    // Helper for time calculation
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

    // Helper to calculate the values based on a specific leg's data
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

        // 5. Helper function to calculate max FDP based on reporting time
        const calculateMaxFDP = (startMins) => {
            // Using the standard table
            if (startMins >= 360 && startMins <= 809) return 780;  // 06:00-13:29
            else if (startMins >= 810 && startMins <= 839) return 765;
            else if (startMins >= 840 && startMins <= 869) return 750;
            else if (startMins >= 870 && startMins <= 899) return 735;
            else if (startMins >= 900 && startMins <= 929) return 720;
            else if (startMins >= 930 && startMins <= 959) return 705;
            else if (startMins >= 960 && startMins <= 989) return 690;
            else if (startMins >= 990 && startMins <= 1019) return 675;
            else if (startMins >= 1020 || startMins <= 299) return 660; // 11:00 for night
            else if (startMins >= 300 && startMins <= 314) return 720;  // 05:00-05:14
            else if (startMins >= 315 && startMins <= 329) return 735;  // 05:15-05:29
            else if (startMins >= 330 && startMins <= 344) return 750;  // 05:30-05:44
            else if (startMins >= 345 && startMins <= 359) return 765;  // 05:45-05:59

            return 780; // Default
        };

        // 6. Calculate base FDP based on FC reporting time
        const baseFDP = calculateMaxFDP(fcStartMins);
        
        // 7. Calculate CC max FDP: base FDP + reporting difference (capped at 60 mins)
        const reportingDiff = (ccDiff > 0) ? ccDiff : 0;
        const cappedDiff = Math.min(reportingDiff, 60);
        const ccMaxFDP = baseFDP + cappedDiff;

        return {
            fc: minsToTime(fcStartMins),
            cc: minsToTime(ccStartMins),
            max: minsToTime(baseFDP),     
            ccMax: minsToTime(ccMaxFDP)
        };
    };

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

        // 3. Helper function to calculate BASE max FDP based on reporting time
        const calculateBaseMaxFDP = (startMins) => {
            // Convert UTC to local Kazakhstan time
            const localStartMins = (startMins + 300) % 1440; // +5 hours = +300 minutes
            
            // FDP table (same for both FC and CC, based on reporting time)
            if (localStartMins >= 360 && localStartMins <= 809) return 780;  // 06:00-13:29 local
            else if (localStartMins >= 810 && localStartMins <= 839) return 765; // 13:30-13:59
            else if (localStartMins >= 840 && localStartMins <= 869) return 750; // 14:00-14:29
            else if (localStartMins >= 870 && localStartMins <= 899) return 735; // 14:30-14:59
            else if (localStartMins >= 900 && localStartMins <= 929) return 720; // 15:00-15:29
            else if (localStartMins >= 930 && localStartMins <= 959) return 705; // 15:30-15:59
            else if (localStartMins >= 960 && localStartMins <= 989) return 690; // 16:00-16:29
            else if (localStartMins >= 990 && localStartMins <= 1019) return 675; // 16:30-16:59
            else if (localStartMins >= 1020 || localStartMins <= 299) return 660; // 17:00-04:59 (night)
            else if (localStartMins >= 300 && localStartMins <= 314) return 720;  // 05:00-05:14
            else if (localStartMins >= 315 && localStartMins <= 329) return 735;  // 05:15-05:29
            else if (localStartMins >= 330 && localStartMins <= 344) return 750;  // 05:30-05:44
            else if (localStartMins >= 345 && localStartMins <= 359) return 765;  // 05:45-05:59
            
            return 780; // Default
        };

        // 4. Calculate base max FDP based on FLIGHT CREW reporting time
        const baseFDP = calculateBaseMaxFDP(fcMins);

        // 5. Calculate reporting time difference
        let reportingDiff = fcMins - ccMins;
        if (reportingDiff < 0) reportingDiff += 1440; // Handle midnight crossing
        
        // Cap the difference at 60 minutes (1 hour)
        const cappedDiff = Math.min(reportingDiff, 60);
        
        // 6. Apply sector reductions
        const getMaxFDPWithSectors = (baseMax, sectors) => {
            let finalMax = baseMax;
            
            // Apply reductions
            if (sectors === 2) {
                // No reduction
            } else if (sectors === 3) {
                finalMax -= 30; // 3 Sectors: -30 mins
            } else if (sectors === 4) {
                finalMax -= 60; // 4 Sectors: -60 mins
            } else if (sectors >= 5) {
                finalMax -= 90; // 5+ Sectors: -90 mins
            }
            
            // Ensure minimum 660 minutes (11 hours)
            return Math.max(finalMax, 660);
        };

        // 7. Calculate Flight Crew max FDP
        const fcMax = getMaxFDPWithSectors(baseFDP, sectors);
        
        // 8. Calculate Cabin Crew max FDP: Base FDP + capped reporting difference (then apply sector reductions)
        const ccBaseMax = baseFDP + cappedDiff;
        const ccMax = getMaxFDPWithSectors(ccBaseMax, sectors);

        // 9. Update both fields
        safeSet('j-max-fdp', minsToTime(fcMax));
        
        // Update hidden cabin crew max FDP
        const ccMaxInput = document.getElementById('j-cc-max-fdp-hidden');
        if (ccMaxInput) {
            ccMaxInput.value = minsToTime(ccMax);
        }
        
        // 10. Update FDP alerts for all legs
        updateAllLegFDPAlerts();
    };

    // Helper function for calculating night duty (crew night hours)
    function calculateNightDuty(startMinsUTC, endMinsUTC) {
        if(!startMinsUTC || !endMinsUTC) return "00:00";
        
        // Kazakhstan night for duty: 21:00-23:59 UTC and 00:00-01:59 UTC
        let nightOverlap = 0;
        
        // Adjust for midnight crossing
        let start = startMinsUTC;
        let end = endMinsUTC;
        if (end < start) end += 1440;
        
        // Night windows in UTC for duty
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
        
        return minsToTime(nightOverlap);
    }

    // Function to calculate night duty for crew based on their reporting time
    function getNightDutyForCrew(startMinsUTC) {
        if(!startMinsUTC && startMinsUTC !== 0) return "00:00";
        
        const lastLeg = dailyLegs[dailyLegs.length - 1];
        if (!lastLeg) return "00:00";
        
        const endMinsUTC = parseTimeString(lastLeg['j-in']);
        if (!endMinsUTC && endMinsUTC !== 0) return "00:00";
        
        return calculateNightDuty(startMinsUTC, endMinsUTC);
    }

    // Helper function to update FDP alerts for all legs
    function updateAllLegFDPAlerts() {
        const fcStartStr = el('j-duty-start')?.value;
        const ccStartStr = el('j-cc-duty-start')?.value;
        const fcMaxStr = el('j-max-fdp')?.value;
        
        // Use the same FDP limit for both FC and CC
        const ccMaxStr = fcMaxStr || "00:00"; // Same as FC now
        
        if (!fcStartStr || !ccStartStr) return;
        
        const fcStartMins = parseTimeString(fcStartStr);
        const ccStartMins = parseTimeString(ccStartStr);
        const fcLimit = parseTimeString(fcMaxStr || "13:00");
        const ccLimit = parseTimeString(ccMaxStr || "13:00"); // Same limit as FC
        
        dailyLegs.forEach((leg, index) => {
            const onBlockStr = leg['j-in'];
            if (onBlockStr) {
                // Calculate FC FDP
                let fcMins = parseTimeString(onBlockStr) - fcStartMins;
                if (fcMins < 0) fcMins += 1440;
                
                // Update FDP display value (cumulative from reporting)
                leg.cumulativeFDP = minsToTime(fcMins);
                
                // Check alert
                leg.fdpAlert = (fcMins > fcLimit);
                
                // Calculate CC FDP (using same limit now)
                let ccMins = parseTimeString(onBlockStr) - ccStartMins;
                if (ccMins < 0) ccMins += 1440;
                leg.ccFdpAlert = (ccMins > ccLimit);
            }
        });
        
        // Re-render the journey list with updated alerts
        renderJourneyList();
    }

// ==========================================
// 9. Journey Log Download
// ==========================================

    window.downloadJourneyLog = async function(mode = 'download') {
        try {
            await logSecurityEvent('JOURNEY_LOG_GENERATE', {
                mode: mode,
                legCount: dailyLegs.length,
                timestamp: new Date().toISOString()
            });
            
            if (!journeyLogTemplateBytes) return alert("Please upload Journey Log first");
            if (dailyLegs.length === 0) return alert("No legs to print.");

            const pdfDoc = await PDFLib.PDFDocument.load(journeyLogTemplateBytes);
            const page = pdfDoc.getPages()[0];
            const font = await pdfDoc.embedFont(PDFLib.StandardFonts.HelveticaBold);
            
            const isIpadMode = el('chk-ipad-mode') ? el('chk-ipad-mode').checked : false;
            if(!isIpadMode) page.setRotation(PDFLib.degrees(0));

            // 1. DYNAMIC OFFSET CALCULATION
            const templateRows = parseInt(document.getElementById('j-template-rows')?.value || "4");
            const standardRows = 4;
            const rowGap = JOURNEY_CONFIG.rowGap; // 17
            const FUEL_OFFSET = (standardRows - templateRows) * rowGap;
            const CREW_OFFSET = (standardRows - templateRows) * rowGap * 2;
            
            if (templateRows === 3) {
                CREW_OFFSET += rowGap; 
            }

            // HEADERS
            const { width, height } = page.getSize();
            page.drawText("75/125", { x: width - 280, y: height - 40, size: 10, font: font, color: PDFLib.rgb(0,0,0) });

            const headers = JOURNEY_CONFIG.headers;
            Object.keys(headers).forEach(id => {
                const val = el(id)?.value;
                const cfg = headers[id];
                if(val && cfg) page.drawText(String(val).toUpperCase(), { x: cfg.x, y: cfg.y, size: JOURNEY_CONFIG.fontSize, font: font, color: PDFLib.rgb(0,0,0) });
            });

            // LEG DATA
            const cols = JOURNEY_CONFIG.cols;
            const fuelKeys = JOURNEY_CONFIG.fuelKeys;
            
            dailyLegs.forEach((leg, idx) => {
                if (idx >= templateRows) return; 

                Object.keys(leg).forEach(key => {
                    const colX = cols[key];
                    if(colX) {
                        let startRow = JOURNEY_CONFIG.rowStartMain;
                        
                        // APPLY STANDARD OFFSET TO FUEL/LOAD COLUMNS
                        if (fuelKeys.includes(key)) {
                            startRow = JOURNEY_CONFIG.rowStartFuel + FUEL_OFFSET; 
                        }

                        const rowY = startRow - (idx * JOURNEY_CONFIG.rowGap);
                        const val = leg[key];
                        if(val !== undefined && val !== null && val !== "") {
                            page.drawText(String(val).toUpperCase(), { x: colX, y: rowY, size: JOURNEY_CONFIG.fontSize, font: font, color: PDFLib.rgb(0,0,0) });
                        }
                    }
                });
            });

            // SIGNATURE
            if (signaturePad && !signaturePad.isEmpty()) {
                try {
                    const sigImageBase64 = signaturePad.toDataURL();
                    const sigImage = await pdfDoc.embedPng(sigImageBase64);
                    
                    page.drawImage(sigImage, {
                        x: 570,        
                        y: 120 + CREW_OFFSET,
                        width: 200,    
                        height: 50,    
                    });
                } catch (sigError) {
                    console.error("Error Embedding the Signature ", sigError);
                    await logSecurityEvent('SIGNATURE_EMBED_ERROR', {
                        error: sigError.message,
                        timestamp: new Date().toISOString()
                    });
                }
            }

            // CREW DUTY DATA
            const settings = JSON.parse(localStorage.getItem('efb_settings') || '{}');
            const shouldHideAll = settings.hideAllDuty === true;
            const crewStart = 333 + CREW_OFFSET;
            const crewGap = 17;    
            
            const numFC = parseInt(el('j-fc-count')?.value || 2);
            const numCC = parseInt(el('j-cc-count')?.value || 4);
            const totalRows = numFC + numCC;

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

            const getNightOverlap = (startMinsUTC) => {
                const nightStartUTC = 1260; 
                const nightEndUTC = 1439;   
                let end = onBlocksMins; 
                let start = startMinsUTC;
                if(end < start) end += 1440;
                let overlap = 0;
                for (let current = start; current < end; current++) {
                    const minuteOfDay = current % 1440;
                    if (minuteOfDay >= nightStartUTC && minuteOfDay <= nightEndUTC) overlap++;
                }
                return minsToTime(overlap);
            };

            // DRAW DUTY ROWS
            for(let i = 0; i < totalRows; i++) {
                if (shouldHideAll) {
                    continue; // Skip
                }
                const y = crewStart - (i * crewGap);
                const isFlightCrew = (i < numFC);
                const myStart = isFlightCrew ? fcStartMins : ccStartMins;
                const myMaxFDP = isFlightCrew ? fcMaxFDPStr : ccMaxFDPStr;
                const myFDP = getFDP(myStart);
                const myNightDuty = getNightDutyForCrew(myStart);

                if(cols['j-duty-operating']) 
                    page.drawText("OP", { x: cols['j-duty-operating'], y: y, size: JOURNEY_CONFIG.fontSize, font: font, color: PDFLib.rgb(0,0,0) });

                if(myFDP && cols['j-duty-time']) 
                    page.drawText(myFDP, { x: cols['j-duty-time'], y: y, size: JOURNEY_CONFIG.fontSize, font: font, color: PDFLib.rgb(0,0,0) });

                // Always draw night duty, even if "00:00"
                if(cols['j-duty-night']) {
                    page.drawText(myNightDuty, { x: cols['j-duty-night'], y: y, size: JOURNEY_CONFIG.fontSize, font: font, color: PDFLib.rgb(0,0,0) });
                }

                if(myMaxFDP && cols['j-duty-allowed']) 
                    page.drawText(myMaxFDP, { x: cols['j-duty-allowed'], y: y, size: JOURNEY_CONFIG.fontSize, font: font, color: PDFLib.rgb(0,0,0) });
            }

            // SAVE & DOWNLOAD
            const out = await pdfDoc.save();
            const flt = (el('j-flt')?.value || "FLT").replace(/\s+/g, '');
            const filename = `JOURNEY_LOG_${flt}.pdf`;
            
            const isMobile = /iPhone|iPad|iPod|Android/i.test(navigator.userAgent);
            if (mode === 'email' && isMobile) {
                const subject = `Journey Log: ${flt}`;
                await sharePdf(out, filename, subject, "Journey Log attached.");
            } else {
                downloadBlob(out, filename);
            }
            
            await resetAfterJourneyLog();

        } catch(e) { 
            console.error("Journey Log Generation Error:", e); 
            await logSecurityEvent('JOURNEY_LOG_ERROR', {
                error: e.message,
                mode: mode
            });
            alert("Error generating Log: " + e.message); 
        }
    };

    // Full reset after sending Journey Log (end of day)
    async function resetAfterJourneyLog() {
        const userConfirmed = await showConfirmDialog(
        'End of the Day',
            'This will remove ALL data including:<br>'+
            'OFPs<br>'+
            'Flight Log entries<br>'+
            'Journey Log entries<br>'+
            'All input data<br>',
            'Continue',
            'Cancel',
        );
        if (userConfirmed) {
            try {
                // Call Worker (Preserve Daily Logs = FALSE)
                await performDataReset(false);
                
                // Switch to Summary Tab (UX improvement)
                const summaryBtn = document.querySelector('.nav-btn[onclick*="summary"]');
                if (summaryBtn) showTab('summary', summaryBtn);
                
                console.log("End of Day Reset Complete.");
                return true;
            } catch (error) {
                console.error("Error ending day:", error);
                return false;
            }
        }
        return false;
    }

// ==========================================
// 10. OFP Download
// ==========================================

    window.DownloadOFP = async function(mode = 'download') {
        // 1. SAFETY CHECK
            try {
                await logSecurityEvent('OFP_DOWNLOAD', {
                    mode: mode,
                    fileName: window.originalFileName,
                    timestamp: new Date().toISOString()
                });
                if(!window.ofpPdfBytes) return alert("Please Upload the OFP PDF first.");
                
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
                                const frontItems = [ 
                                    {id:'front-atis', offset:40, coord:frontCoords.atis}, 
                                    {id:'front-atc', offset:50, coord:frontCoords.atcLabel}
                                ];
                                frontItems.forEach(f => {
                                    const v = el(f.id)?.value;
                                    if(f.coord && v) newPage.drawText(v.toUpperCase(), { 
                                        x: f.coord.transform[4] + f.offset, 
                                        y: f.coord.transform[5] + V_LIFT, 
                                        size: 12, font: fontB, color: PDFLib.rgb(0,0,0)
                                    });
                                });
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
                }
            } catch (error) { 
            // ... error handling ...
            await logSecurityEvent('OFP_DOWNLOAD_ERROR', {
                error: error.message,
                mode: mode
            });
        }
    };


    async function resetOFPAfterSend() {
        // 1. Popup Confirmation
        const userConfirmed = await showConfirmDialog(
            'OFP Generated Successfully.',
            'Click Finalize to wipe the form for the next flight.<br>'+
            'Click Modify if you need to make changes and download again.<br>',
            'Finalize',
            'Modify',
        );

        if (!userConfirmed) {
            window.lastGeneratedOFPPdfBytes = null;
            return;
        }

        // 2. Save logged PDF to the active OFP
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

        // 3. Reset UI but do NOT show upload overlay yet
        await performDataReset(true, false);

        // 4. Get settings
        const settings = JSON.parse(localStorage.getItem('efb_settings') || '{}');
        const autoActivate = settings.autoActivateNext !== false; // default true

        // 5. Get all OFPs and check if there are any non‑finalized OFPs
        const allOFPs = await getCachedOFPs(); // sorted by order
        const nonFinalizedOFPs = allOFPs.filter(ofp => !ofp.finalized);

        if (nonFinalizedOFPs.length === 0) {
            // --- NO NON‑FINALIZED OFPs LEFT → END OF DAY, GO TO JOURNEY LOG ---
            showToast("All OFPs finalized – complete your Journey Log", 'info');
            
            // Switch to Journey Log tab
            const journeyBtn = document.querySelector('.nav-btn[data-tab="journey"], .nav-btn[onclick*="journey"]');
            if (journeyBtn) {
                if (typeof window.showTab === 'function') {
                    window.showTab('journey', journeyBtn);
                } else {
                    journeyBtn.click();
                }
            }
            
            // Ensure the upload overlay is hidden (we are in Journey Log tab)
            setOFPLoadedState(false);
            return;
        }

        // --- THERE ARE NON‑FINALIZED OFPs → PROCEED WITH AUTO‑ACTIVATION (if enabled) ---
        const currentActiveId = localStorage.getItem('activeOFPId');
        let nextOFP = null;

        if (autoActivate && allOFPs.length > 0) {
            if (currentActiveId) {
                // Find the OFP that comes after the current one in order
                const currentIndex = allOFPs.findIndex(o => o.id === Number(currentActiveId));
                if (currentIndex !== -1 && currentIndex < allOFPs.length - 1) {
                    nextOFP = allOFPs[currentIndex + 1];
                }
            }
            // If no next found, activate the first non‑finalized one (top of list)
            if (!nextOFP && nonFinalizedOFPs.length > 0) {
                nextOFP = nonFinalizedOFPs[0];
            }
        }

        if (nextOFP) {
            await activateOFP(nextOFP.id);
        } else {
            // No OFP to activate – show upload overlay
            setOFPLoadedState(false);
        }
    }

    window.downloadLoggedOFP = async function(id) {
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
// 11. Download/Upload Managment
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
            // Fallback for computers
            downloadBlob(pdfBytes, filename);
        }
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

    // Shared function to clean UI, Variables, and Database
    async function performDataReset(preserveDailyLegs = true, setLoadedState = true) {

        // 1. Reset Internal Variables
        waypoints = [];
        alternateWaypoints = [];
        fuelData = [];
        blockFuelValue = 0;
        window.cutoffPageIndex = -1;
        
        // Reset Coordinates
        frontCoords = { 
            atis: null, atcLabel: null, altm1: null, stby: null, 
            altm2: null, picBlockLabel: null, reasonLabel: null 
        };

        // 2. Clear PDF Database & Memory
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
            dailyLegs = []; // Clear internal array
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
        }

        if (setLoadedState && typeof setOFPLoadedState === 'function') {
            setOFPLoadedState(false);
        }
        if (typeof validateOFPInputs === 'function') {
            validateOFPInputs();
        }
    }

// ==========================================
// 12. LOCAL STORAGE (AUTO-SAVE)
// ==========================================

    window.manualSaveTest = function() {
        console.log('Manual save triggered');
        saveState();
    };

    const SAVE_IDS = [
        'j-flt', 'j-reg', 'j-date', 'j-dep', 'j-dest', 'j-altn', 'j-alt2', 'j-std','front-extra-kg',
        'j-out', 'j-off', 'j-on', 'j-in', 'j-night', 'j-night-calc',
        'j-to', 'j-ldg', 'j-ldg-type', 'j-flt-alt', 'j-ldg-detail',
        'j-init', 'j-uplift-w', 'j-uplift-vol', 'j-act-ramp', 'j-shut', 'j-slip', 'j-slip-2',
        'j-adl', 'j-chl', 'j-inf', 'j-bag', 'j-cargo', 'j-mail', 'j-zfw',
        'j-report-type', 'j-fc-count', 'j-cc-count', 'front-extra-reason',
        'front-atis', 'front-atc', 'front-altm1', 'front-stby', 'front-altm2', 'view-pic-block',
    ];

    // 1. SAVE FUNCTION 
    // 1. SAVE FUNCTION 
    async function saveState() {
        if (!isAppLoaded) return;
        console.log('🔄 saveState started');

        // MUST be declared before any usage
        const activeId = localStorage.getItem('activeOFPId');
        if (!activeId) {
            console.log('⚠️ No active OFP, skipping save');
            return;
        }

        // Capture waypoint user inputs
        const userInputs = waypoints.map((wp, i) => ({
            ato: el(`o-a-${i}`)?.value || "",
            fuel: el(`o-f-${i}`)?.value || "",
            notes: el(`o-n-${i}`)?.value || "",
            agl: el(`o-agl-${i}`)?.value || ""
        }));

        // Save waypoint inputs to IndexedDB
        try {
            await updateOFP(activeId, { userWaypoints: userInputs });
            console.log('✅ Waypoint inputs saved');
        } catch (e) {
            console.warn('❌ Failed to save waypoint inputs', e);
        }

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
                    // Backup to localStorage
                    localStorage.setItem(`drawing_backup_${activeId}_atis`, data);
                } else {
                    console.log('⚠️ Invalid ATIS drawing data, not saving');
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
                    console.log('⚠️ Invalid ATC drawing data, not saving');
                    combinedInputs['front-atc-drawing'] = null;
                }
            } else {
                combinedInputs['front-atc-drawing'] = null;
            }
        } else {
            combinedInputs['front-atis-drawing'] = null;
            combinedInputs['front-atc-drawing'] = null;
            console.log('not writing mode');
        }

        // Main signature
        if (pads.main.pad && !pads.main.pad.isEmpty()) {
            const data = pads.main.pad.toDataURL();
            if (isValidDataURL(data)) {
                combinedInputs.signature = data;
                console.log('📸 Signature captured, length:', data.length);
                localStorage.setItem(`drawing_backup_${activeId}_signature`, data);
            } else {
                console.warn('⚠️ Invalid signature data, not saving');
                combinedInputs.signature = null;
            }
        } else {
            combinedInputs.signature = null;
        }

        // Save combined inputs to IndexedDB
        try {
            await updateOFP(activeId, { userInputs: combinedInputs });
        } catch (e) {
            console.warn('❌ Failed to save user inputs', e);
        }

        // Save non‑OFP state to localStorage (encrypted + fallback)
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

        // Fallback sync save (unencrypted)
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

            // -Restore non‑OFP‑specific state (safe)
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

    // 3. INITIALIZATION (Wait for DOM)
    document.addEventListener('DOMContentLoaded', () => {
        // Ensure we load before any user interaction happens
        loadState();
    });


// ==========================================
// 13. PDF STORAGE (IndexedDB)
// ==========================================

    // One connection reused across the app.
    function getDB() {
        if (!dbPromise) {
            dbPromise = new Promise((resolve, reject) => {
                const request = indexedDB.open("EFB_PDF_DB", 7); // Version 7
                
                request.onupgradeneeded = function(e) {
                    const db = e.target.result;
                    const oldVersion = e.oldVersion;
                    const tx = e.target.transaction;

                    // GUARANTEE OFPs STORE EXISTS
                    if (!db.objectStoreNames.contains("ofps")) {
                        console.warn(`getDB: creating ofps store (oldVersion=${oldVersion})`);
                        const ofpStore = db.createObjectStore("ofps", { keyPath: "id", autoIncrement: true });
                        ofpStore.createIndex("flight", "flight", { unique: false });
                        ofpStore.createIndex("date", "date", { unique: false });
                        ofpStore.createIndex("uploadTime", "uploadTime", { unique: false });
                        ofpStore.createIndex("isActive", "isActive", { unique: false });
                        ofpStore.createIndex("order", "order", { unique: false });
                    }

                    // Version-specific migrations
                    if (oldVersion < 2) {
                        if (!db.objectStoreNames.contains("files")) {
                            db.createObjectStore("files");
                        }
                    }
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
                    if (oldVersion < 8) {
                        // Create orders store
                        if (!db.objectStoreNames.contains("ofp_orders")) {
                            const orderStore = db.createObjectStore("ofp_orders", { keyPath: "id" });
                            // Copy existing orders from ofps store
                            const tx = e.target.transaction;
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
            const tx = db.transaction("ofps", "readwrite");
            const store = tx.objectStore("ofps");

            // Determine next order number
            const getAllRequest = store.getAll();
            getAllRequest.onsuccess = () => {
                const ofps = getAllRequest.result;
                const maxOrder = ofps.length > 0 ? Math.max(...ofps.map(o => o.order || 0)) : 0;
                const nextOrder = maxOrder + 1;

                // Only deactivate active OFP if the new one should be active
                const deactivateAll = () => {
                    return new Promise((res) => {
                        if (activate) {
                            let deactivatedCount = 0;
                            ofps.forEach(rec => {
                                if (rec.isActive) {
                                    rec.isActive = false;
                                    store.put(rec);
                                    deactivatedCount++;
                                }
                            });
                        }
                        res();
                    });
                };

                deactivateAll().then(() => {
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
                        requestNumber: metadata.requestNumber || '',
                        userWaypoints: [],
                        userInputs: {}
                    };

                    const addRequest = store.add(ofpRecord);
                    addRequest.onsuccess = (e) => {
                        const newId = e.target.result;
                        
                        // Verify the record was actually written
                        const verifyRequest = store.get(newId);
                        verifyRequest.onsuccess = () => {
                            if (verifyRequest.result) {
                            } else {
                                console.error(`❌ saveOFPToDB: verification FAILED – record with ID ${newId} not found immediately after add!`);
                            }
                        };
                        verifyRequest.onerror = (verr) => console.error('saveOFPToDB: verification error', verr);

                        if (activate) {
                            localStorage.setItem('activeOFPId', newId);
                        }
                        resolve(newId);
                    };
                    addRequest.onerror = (e) => {
                        console.error('❌ saveOFPToDB: store.add() error', e.target.error);
                        reject(e.target.error);
                    };
                }).catch(reject);
            };
            getAllRequest.onerror = (e) => {
                console.error('saveOFPToDB: getAll() error', e.target.error);
                reject(e.target.error);
            };

            tx.oncomplete = () => {
            };
            tx.onerror = (e) => {
                console.error('saveOFPToDB: transaction error', e.target.error);
                reject(e.target.error);
            };
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
                // --- Update existing record (preserve ID, isActive, order) ---
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
                // --- Create new minimal record (bottom of order, inactive) ---
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
                putRequest.onsuccess = () => {
                    // Wait for transaction to complete before resolving
                    tx.oncomplete = () => resolve(ofp);
                    tx.onerror = (e) => reject(e.target.error);
                };
                putRequest.onerror = (e) => reject(e.target.error);
            };
            getRequest.onerror = (e) => reject(e.target.error);
        });
    }

    // Get all OFPs (sorted newest first)
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

    async function findOFPByFlightAndDate(flight, date) {
        if (!flight || !date || flight === 'N/A' || date === 'N/A') return null;
        const db = await getDB();
        return new Promise((resolve, reject) => {
            const tx = db.transaction("ofps", "readonly");
            const store = tx.objectStore("ofps");
            const index = store.index("flight");
            const request = index.getAll(flight);
            request.onsuccess = () => {
                const ofps = request.result;
                const match = ofps.find(ofp => ofp.date === date);
                resolve(match || null);
            };
            request.onerror = (e) => reject(e);
        });
    }

    // Get active OFP
    async function getActiveOFPFromDB() {
        const activeId = localStorage.getItem('activeOFPId');
        if (!activeId) return null;
        
        const db = await getDB();
        return new Promise((resolve, reject) => {
            const tx = db.transaction("ofps", "readonly");
            const store = tx.objectStore("ofps");
            const request = store.get(Number(activeId));
            request.onsuccess = () => resolve(request.result);
            request.onerror = (e) => reject(e);
        });
    }

    async function setActiveOFP(id) {
        const db = await getDB();
        return new Promise((resolve, reject) => {
            const tx = db.transaction("ofps", "readwrite");
            const store = tx.objectStore("ofps");
            
            const getAllRequest = store.getAll();
            getAllRequest.onsuccess = () => {
                const ofps = getAllRequest.result;
                ofps.forEach(ofp => {
                    const shouldBeActive = (ofp.id === Number(id));
                    if (ofp.isActive !== shouldBeActive) {
                        ofp.isActive = shouldBeActive;
                        store.put(ofp);
                    }
                });
                localStorage.setItem('activeOFPId', id);
                resolve();
            };
            getAllRequest.onerror = (e) => reject(e);
            
        });
    }

    // Delete OFP by ID
    async function deleteOFPFromDB(id) {
        const db = await getDB();
        return new Promise((resolve, reject) => {
            const tx = db.transaction("ofps", "readwrite");
            const store = tx.objectStore("ofps");
            const request = store.delete(Number(id));
            request.onsuccess = () => resolve();
            request.onerror = (e) => reject(e);
        });
    }

    // Clear all OFPs
    async function clearAllOFPsFromDB() {
        const db = await getDB();
        return new Promise((resolve, reject) => {
            const tx = db.transaction("ofps", "readwrite");
            const store = tx.objectStore("ofps");
            const request = store.clear();
            request.onsuccess = () => {
                localStorage.removeItem('activeOFPId');
                resolve();
            };
            request.onerror = (e) => reject(e);
        });
    }

    // Check if PDF exists
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

    // Save PDF to DB
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

    // Load PDF from DB
    async function loadPdfFromDB() {
        const db = await getDB();
        return new Promise((resolve, reject) => {
            const tx = db.transaction("files", "readonly");
            const req = tx.objectStore("files").get("currentOFP");
            req.onsuccess = () => resolve(req.result); // Return the Blob directly
            req.onerror = () => resolve(null);
        });
    }

    // Delete PDF from DB
    async function clearPdfDB() {
        const db = await getDB();
        const tx = db.transaction("files", "readwrite");
        tx.objectStore("files").delete("currentOFP");
    }

    async function getAllOFPMetadata() {
        const db = await getDB();
        if (!db.objectStoreNames.contains('ofps')) return [];
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
        
        // Build order map
        const orderMap = {};
        orders.forEach(o => { orderMap[o.id] = o.order; });
        
        // Merge order into each OFP (remove data blob)
        const metadata = ofps.map(({ data, ...rest }) => ({
            ...rest,
            order: orderMap[rest.id] || 0
        }));
        metadata.sort((a, b) => (a.order || 0) - (b.order || 0));
        return metadata;
    }

// ==========================================
// 14. SETTINGS
// ==========================================

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
        
        // Auto-save settings when changed (for all except atis-input-mode)
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

    // Initialize settings when app loads
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

    // Load settings from localStorage
    function loadSettings() {
        try {
            const settings = JSON.parse(localStorage.getItem('efb_settings') || '{}');
            
            // Apply settings to UI
            if (settings.autoLockTime) {
                const autoLockSelect = document.getElementById('auto-lock-time');
                if (autoLockSelect) autoLockSelect.value = settings.autoLockTime;
            }
            
            if (settings.pdfQuality) {
                const pdfQualitySelect = document.getElementById('pdf-quality');
                if (pdfQualitySelect) pdfQualitySelect.value = settings.pdfQuality;
            }

            // Hide FC Duty Checkbox
            const hideFCDutyBox = document.getElementById('hide-all-duty');
            if (hideFCDutyBox) {
                hideFCDutyBox.checked = settings.hideFCDuty === true; 
            }

            // Auto-activate next OFP
            const autoActivateCheckbox = document.getElementById('auto-activate-next');
            if (autoActivateCheckbox) {
                autoActivateCheckbox.checked = settings.autoActivateNext !== false; // default true
            }

            // Writing or Typing ATIS/ATC
            const modeSelect = document.getElementById('atis-input-mode');
            if (modeSelect) {
                modeSelect.value = settings.atisInputMode || 'typing';
                applyInputMode(settings.atisInputMode || 'typing');
            }
                
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
            
        } catch (error) {
            console.error('Failed to load settings:', error);
        }
    }

    // Save settings to localStorage
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
        if (sessionStorage.getItem('efb_authenticated') === 'true') {
            resetAutoLockTimer();
        }
        showToast('Settings saved successfully');
    }

    // Calculate storage usage
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

    // Change PIN function
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

    // Export all data
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

    // Try data recovery
    window.recoverLostData = async function() {
        const confirmed = await showConfirmDialog(
            'Data Recovery Mode',
            '⚠️ WARNING: This will attempt to recover any lost data.<br>' +
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
        alert("No recoverable data found");
    };

    // Factory reset
    async function confirmFactoryReset() {
        const confirmed = await showConfirmDialog(
            'Factory Reset',
            '⚠️ WARNING: This will delete ALL data including:<br>' +
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

    function showConfirmDialog(title, message, confirmText = 'Continue', cancelText = 'Cancel', type = 'warning') {
        return createModal({
            title,
            message,
            confirmText,
            cancelText,
            type: type === 'error' ? 'error' : 'info',
            icon: type === 'error' ? '⚠️' : '❓'
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
        listItems = null
    }) {
        const dialog = document.createElement('div');
        dialog.style.cssText = `
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: rgba(0,0,0,0.8);
            display: flex;
            justify-content: center;
            align-items: center;
            z-index: 10001;
            backdrop-filter: blur(5px);
            animation: fadeIn 0.3s ease;
        `;

        let contentHTML = '';

        // Title + icon area
        contentHTML += `
            <div style="display: flex; align-items: center; gap: 15px; margin-bottom: 20px;">
                <span style="font-size: 40px;">${icon}</span>
                <div>
                    <h2 style="color: ${type === 'error' ? 'var(--error)' : 'var(--accent)'}; margin: 0; font-size: 24px;">
                        ${title}
                    </h2>
                    ${showVersion ? `<p style="color: var(--dim); margin: 5px 0 0 0;">Version ${showVersion}</p>` : ''}
                </div>
            </div>
        `;

        // Message (supports HTML)
        if (message) {
            contentHTML += `<p style="color: var(--text); margin-bottom: 25px; line-height: 1.5;">${message}</p>`;
        }

        // List items (e.g., release notes)
        if (listItems && listItems.length) {
            contentHTML += `<div style="margin-bottom: 25px; max-height: 400px; overflow-y: auto; padding-right: 10px;">
                <ul style="list-style: none; padding: 0; margin: 0;">
                    ${listItems.map(item => `<li style="margin-bottom: 8px; color: var(--text);">${item}</li>`).join('')}
                </ul>
            </div>`;
        }

        // Buttons
        contentHTML += `<div style="display: flex; gap: 15px; margin-top: 25px;">`;
        if (cancelText) {
            contentHTML += `
                <button id="modal-cancel" style="
                    flex: 1;
                    padding: 14px;
                    background: var(--input);
                    border: 1px solid var(--border);
                    color: var(--text);
                    border-radius: 12px;
                    font-weight: 600;
                    cursor: pointer;
                ">${cancelText}</button>
            `;
        }
        contentHTML += `
            <button id="modal-confirm" style="
                flex: 1;
                padding: 14px;
                background: ${type === 'error' ? 'var(--error)' : 'var(--accent)'};
                border: none;
                color: white;
                border-radius: 12px;
                font-weight: 800;
                cursor: pointer;
                box-shadow: ${type !== 'error' ? '0 5px 15px rgba(var(--accent-rgb), 0.3)' : 'none'};
            ">${confirmText}</button>
        </div>`;

        dialog.innerHTML = `
            <div style="
                background: var(--panel);
                border-radius: 20px;
                padding: 30px;
                max-width: 500px;
                width: 90%;
                border: 2px solid ${type === 'error' ? 'var(--error)' : 'var(--accent)'};
                box-shadow: 0 20px 40px rgba(0,0,0,0.5);
                text-align: left;
            ">
                ${contentHTML}
            </div>
        `;

        document.body.appendChild(dialog);

        return new Promise((resolve) => {
            const confirmBtn = dialog.querySelector('#modal-confirm');
            const cancelBtn = dialog.querySelector('#modal-cancel');

            confirmBtn.onclick = () => {
                dialog.remove();
                if (onConfirm) onConfirm();
                resolve(true);
            };

            if (cancelBtn) {
                cancelBtn.onclick = () => {
                    dialog.remove();
                    if (onCancel) onCancel();
                    resolve(false);
                };
            }
        });
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


// ==========================================
// DEBOUNCED FUNCTION INSTANCES
// ==========================================

const debouncedSave = debounce(saveState, SAVE_STATE_DEBOUNCE);
const debouncedFullRecalc = debounce(() => {
    runFlightLogCalculations();
    syncLastWaypoint();
}, 300);
const debouncedSyncLastWaypoint = debounce(syncLastWaypoint, 300);
const debouncedUpdateCruiseLevel = debounce(updateCruiseLevel, 300);

// ==========================================
// EVENT LISTENERS
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

        // Activity tracking
        if (sessionStorage.getItem('efb_authenticated') === 'true') {
            setupActivityTracking();
            resetAutoLockTimer();
        }
        loadState();
    });

    window.addEventListener('beforeunload', () => {
        debouncedSave.cancel(); // cancel any pending debounced save
        saveState(); // final immediate save
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

})();