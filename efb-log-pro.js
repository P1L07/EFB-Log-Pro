(function() {
const APP_VERSION = "1.7";
const ENCRYPTION_KEY_NAME = 'efb_encryption_key';
const ENCRYPTION_ALGO = {
    name: 'AES-GCM',
    length: 256
};
const AUTH_KEY = 'efb_auth_hash';
const MAX_ATTEMPTS = 5;
const LOCKOUT_TIME = 15 * 60 * 1000; // 15 minutes
const AUDIT_LOG_KEY = 'efb_audit_log';
const MAX_LOG_ENTRIES = 1000;
const EXPECTED_SW_HASH = '120fd1126d072afd30fc85d8624abe81c2752b679c94e51bfdda09abf4cb2778';
const SW_HASH_STORAGE_KEY = 'efb_sw_hash_cache';

// ==========================================
// 1. CONFIGURATION & UPDATE LOGIC
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
        
        // 3. Add event listener for file input change to update OFP state
        const fileInput = document.getElementById('ofp-file-in');
        if (fileInput) {
            fileInput.addEventListener('change', function() {
                setOFPLoadedState(true);
            });
        }
        
        // 4. Add drag and drop functionality for the overlay
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
        
        // 5. Initialize theme on page load
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
        
        // 6. Initialize tab navigation
        initializeTabNavigation();
        
        // 7. Initial update for upload button visibility
        updateUploadButtonVisibility();
        
        // 8. Add time input masks
        addTimeInputMasks();
        
        // 9. Initialize signature pad if on confirm tab
        setTimeout(() => {
            const canvas = document.getElementById('sig-canvas');
            if (canvas) {
                const ratio = Math.max(window.devicePixelRatio || 1, 1);
                canvas.width = canvas.offsetWidth * ratio;
                canvas.height = canvas.offsetHeight * ratio;
                canvas.getContext("2d").scale(ratio, ratio);
                
                signaturePad = new SignaturePad(canvas, {
                    backgroundColor: 'rgba(0,0,0,0)',
                    penColor: getComputedStyle(document.documentElement).getPropertyValue('--accent').trim()
                });
                
                // Restore saved signature if exists
                if (savedSignatureData) {
                    signaturePad.fromDataURL(savedSignatureData, { ratio: ratio });
                }
                
                // Update save button state
                updateSaveButtonState();
            }
        }, 100);
        
        setTimeout(() => {
            initializeSettingsTab();
        }, 1500);
    
        // Auto-save settings when changed
        ['auto-lock-time', 'pdf-quality',].forEach(id => {
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
        // Remove all event listeners
    });

    // Trigger Save on any input change (wait 500ms before saving to save performance)
    window.addEventListener('input', (e) => {
        if(window.saveTimeout) clearTimeout(window.saveTimeout);
        window.saveTimeout = setTimeout(() => saveState(), 500);
    });

    window.addEventListener('resize', function() {
        if (signaturePad) {
            const canvas = document.getElementById('sig-canvas');
            canvas.width = canvas.offsetWidth;
            signaturePad.clear();
        }
    });

    window.addEventListener('pagehide', () => {
        saveState();
    });

    // 2. Save on Tab Switch
    document.addEventListener('visibilitychange', () => {
        if (document.visibilityState === 'hidden') {
            saveState();
        }
    });

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
            
            // Display in new window or console
            const win = window.open();
            win.document.write('<pre>' + sanitizeHTML(logText) + '</pre>');
            
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
        const autoLockMinutes = parseInt(settings.autoLockTime) || 15;
        
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
            
            const encoded = new TextEncoder().encode(JSON.stringify(data));
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
            // Fallback: store without encryption (should inform user)
            return btoa(JSON.stringify({ 
                data: data,
                encrypted: false,
                error: 'Encryption failed'
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

    function sanitizeHTML(str) {
        const div = document.createElement('div');
        div.textContent = str;
        return div.innerHTML;
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
        let fromCache = false;
        
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
                        
                        try {
                            // Verify new worker before prompting
                            const response = await fetch(installingWorker.scriptURL);
                            const swText = await response.text();
                            
                            // Calculate hash of new worker
                            const encoder = new TextEncoder();
                            const data = encoder.encode(swText);
                            const hashBuffer = await crypto.subtle.digest('SHA-256', data);
                            const hashArray = Array.from(new Uint8Array(hashBuffer));
                            const calculatedHash = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
                            
                            const hashValid = (calculatedHash === EXPECTED_SW_HASH);
                            
                            if (hashValid) {
                                if(confirm("New version available! Reload now?")) {
                                    installingWorker.postMessage({ type: 'SKIP_WAITING' });
                                    setTimeout(() => window.location.reload(), 500);
                                }
                            } else {
                                console.error('New service worker failed hash check:', { calculatedHash, expected: EXPECTED_SW_HASH });
                                installingWorker.postMessage({ type: 'UNINSTALL' });
                                alert('Update verification failed. Update rejected.');
                                
                                // Log this security event
                                if (typeof logSecurityEvent === 'function') {
                                    await logSecurityEvent('SERVICE_WORKER_HASH_MISMATCH', {
                                        calculatedHash: calculatedHash,
                                        expectedHash: EXPECTED_SW_HASH,
                                        scriptURL: installingWorker.scriptURL
                                    });
                                }
                            }
                        } catch(err) {
                            console.error('Failed to verify update:', err);
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

    // Set OFP loaded state
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

    window.checkIfPDFIsCut = async function() {
        if (!window.ofpPdfBytes) {
            console.log("No PDF loaded");
            return;
        }
        
        try {
            // Check with PDF.js
            const pdfjsDoc = await pdfjsLib.getDocument(window.ofpPdfBytes).promise;
            const pdfjsPages = pdfjsDoc.numPages;
            
            // Check with PDF-Lib
            const pdfLibDoc = await PDFLib.PDFDocument.load(window.ofpPdfBytes);
            const pdfLibPages = pdfLibDoc.getPageCount();
            
            
            if (pdfjsPages === pdfLibPages) {
                return true;
            } else {
                return false;
            }
            
        } catch (error) {
            console.error("Error checking PDF:", error);
            return false;
        }
    };

    // Also debounce the waypoint-specific inputs
    const debouncedSave = createDebouncedSave();
    function createDebouncedSave() {
        let timeout;
        return function() {
            clearTimeout(timeout);
            timeout = setTimeout(() => {
                const now = Date.now();
                if (now - lastSaveStateTime > SAVE_STATE_DEBOUNCE) {
                    saveState().catch(console.error); // Handle async
                    lastSaveStateTime = now;
                }
            }, 300);
        };
    }

    // Update the waypoint input handlers to use this
    function attachWaypointEventListeners(tableId, prefix, count) {
        for (let i = 0; i < count; i++) {
            // Time input
            const timeInput = el(`${prefix}-a-${i}`);
            if (timeInput) {
                timeInput.addEventListener('blur', function(e) {
                    try {
                        const validated = validateFlightTime(e.target.value, 'Waypoint Time');
                        e.target.value = validated.value;
                        
                        if (isTO) {
                            updateTakeoffTime(validated.value);
                            debouncedFullRecalc();
                        } else {
                            debouncedSyncLastWaypoint();
                        }
                    } catch (error) {
                        alert(error.message);
                        e.target.value = '';
                        e.target.focus();
                    }
                });
            }
            
            // Fuel input
            const fuelInput = el(`${prefix}-f-${i}`);
            if (fuelInput) {
                fuelInput.oninput = () => {
                    runFlightLogCalculations();
                    debouncedSave();
                };
            }
            
            // Notes input
            const notesInput = el(`${prefix}-n-${i}`);
            if (notesInput) {
                notesInput.oninput = debouncedSave;
            }
            
            // FL input
            const flInput = el(`${prefix}-agl-${i}`);
            if (flInput) {
                flInput.oninput = () => {
                    updateCruiseLevel();
                    debouncedSave();
                };
            }
        }
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
    let pdfFallbackElement = null;
    let lastSaveStateTime = 0;
    let isOFPLoaded = false;
    let journeyLogTemplateBytes = null;
    let waypoints = [], alternateWaypoints = [], dailyLegs = [], signaturePad = null; let savedSignatureData = null;
    let fuelData = [];
    let blockFuelValue = 0;
    let dutyStartTime = null;
    let recalcTimeout, syncTimeout, cruiseTimeout;
    let autoLockTimer = null;
    let isLoaded = false;
    let lastActivityTime = Date.now();
    let waypointTableCache = {
        waypoints: [],
        alternateWaypoints: [],
        lastUpdate: 0
    };
    let frontCoords = {  
        atis: null, atcLabel: null, altm1: null, stby: null, altm2: null, picBlockLabel: null, reasonLabel: null 
    };

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

// ==========================================
// 3. INITIALIZATION & LISTENERS
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

    async function initializeApp() {
        // Debugging if IndexedDB is working
        const hasPdf = await checkPdfInDB();
        if (typeof pdfjsLib !== 'undefined') {
            const WORKER_HASH = 'sha384-cdzss87ZwpiG252tPQexupMwS1W1lTzzgy/UlNUHXW6h8aaJpBizRQk9j8Vj3zw9';
            console.warn = function(...args) {
                if (args[0] && args[0].includes && args[0].includes('TT: undefined function')) {
                    return; // Suppress these warnings
                }
            };
            try {
                // Create a script element with integrity
                const workerScript = document.createElement('script');
                workerScript.src = './pdf.worker.min.js';
                workerScript.integrity = WORKER_HASH;
                workerScript.crossOrigin = 'anonymous';
                
                workerScript.onload = () => {
                    pdfjsLib.GlobalWorkerOptions.workerSrc = './pdf.worker.min.js';
                };
                
                workerScript.onerror = () => {
                    console.error('PDF worker failed integrity check');
                    // Fallback: show warning but continue
                    alert('Warning: PDF worker integrity check failed. Continue at your own risk.');
                    pdfjsLib.GlobalWorkerOptions.workerSrc = './pdf.worker.min.js';
                };
                
                document.head.appendChild(workerScript);
            } catch (error) {
                console.error('Error loading PDF worker:', error);
                pdfjsLib.GlobalWorkerOptions.workerSrc = './pdf.worker.min.js';
            }
        }
        
        addTimeInputMasks();

        // OFP Upload
        const ofpFileInput = el('ofp-file-in');
        if (ofpFileInput) ofpFileInput.onchange = runAnalysis;
        
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
        const debounce = (fn, delay) => {
            let timeout;
            return (...args) => {
                clearTimeout(timeout);
                timeout = setTimeout(() => fn(...args), delay);
            };
        };
        
        ['j-out','j-off','j-on','j-in'].forEach(id => {
            const e = el(id);
            if (e) e.addEventListener('input', debounce(calcTripTime, 300));
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
            ofpAtdInput.addEventListener('input', debounce((e) => {
                safeSet('j-off', e.target.value); 
                runFlightLogCalculations(); 
                calcTripTime();
            }, 300));
        }
            
        const extraKgInput = el('front-extra-kg');
        if (extraKgInput) {
            extraKgInput.addEventListener('input', debounce(function() {
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

        // OFFLINE AUTO-LOAD LOGIC //
        try {
            // 1. Check if we have a saved PDF in the database
            const savedPdfBlob = await loadPdfFromDB();    
            if (savedPdfBlob && savedPdfBlob.size > 0) {
                setOFPLoadedState(true);
                // Convert Blob to ArrayBuffer and set global variable
                window.ofpPdfBytes = await savedPdfBlob.arrayBuffer();
                window.originalFileName = savedPdfBlob.name || "Logged_OFP.pdf"; 
                // Then run analysis with the PDF Blob
                await runAnalysis(savedPdfBlob); 
                await loadState();
            } else {
                // If no PDF, just load the text inputs from LocalStorage
                loadState();
                console.log("OFP PDF not found");
                setOFPLoadedState(false);
            }
        } catch (e) {
            console.error("Auto-load error:", e);
            loadState();
            setOFPLoadedState(false);
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

    // Analyze OFP
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
                try {
                    const isValid = await validatePDF(blob);
                    if (!isValid) {
                        fileInput.value = ''; 
                        if (typeof setOFPLoadedState === 'function') {
                            setOFPLoadedState(false);
                        } else {
                            window.isOFPLoaded = false; 
                            updateUploadButtonVisibility();
                        }
                        return;
                    }
                } catch (error) {
                    alert(`Invalid PDF: ${error.message}`);
                    fileInput.value = '';
                    if (typeof setOFPLoadedState === 'function') {
                        setOFPLoadedState(false);
                    }
                    return;
                }
                window.savedWaypointData = [];
                localStorage.removeItem('efb_log_state'); 
            }
        }

        if (!blob) return;

        // 2. Save PDF
        window.ofpPdfBytes = await blob.arrayBuffer(); 
        window.originalFileName = blob.name || "Logged_OFP.pdf";
        
        // 3. Save to IndexedDB (only for manual uploads)
        if (!isAutoLoad) {
            try {
                await savePdfToDB(blob);
                setOFPLoadedState(true);
            } catch (error) {
                console.error("Failed to save PDF to IndexedDB:", error);
            }
        }

        // 4. Show journey log form for new uploads
        if (!isAutoLoad) {
            if (typeof clearOFPInputs === 'function') clearOFPInputs();
            const legForm = document.getElementById('leg-input-form');
            if(legForm) legForm.style.display = 'block';
        }

        // 5. Render PDF preview (don't fail if parsing fails)
        renderPDFPreview(window.ofpPdfBytes).catch(console.error);

        // 6. Parse PDF with error handling
        try {
            await parsePDFData(window.ofpPdfBytes, isAutoLoad);
            
            // Only log success if parsing succeeded
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
            
        } catch (error) {
            console.error('PDF parsing failed:', error);
            
            // Set OFP loaded to false so upload overlay shows again
            if (typeof setOFPLoadedState === 'function') {
                setOFPLoadedState(false);
            }
            
            // Clear the file input so they can retry (only for manual uploads)
            if (!isAutoLoad) {
                const fileInput = document.getElementById('ofp-file-in');
                if (fileInput) {
                    fileInput.value = '';
                }
            }
            
            // Log the failure
            try {
                await logSecurityEvent('PDF_UPLOAD', {
                    fileName: blob.name,
                    fileSize: blob.size,
                    fileType: blob.type,
                    success: false,
                    error: error.message
                });
            } catch (logError) {
                console.error('Failed to log upload error:', logError);
            }
            return;
        }

        // 7. Handle state (only if parsing succeeded)
        if (isAutoLoad) { 
            await loadSavedState();
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

// ==========================================
// 4. OFP PARSING LOGIC
// ==========================================

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
        const dr = text.match(/DEST\s+ROUTE[:\s]+([^\n]+?)(?=\s+ALTN\s+ROUTE|\s+FUEL|\s+$)/i);
        safeText('view-dest-route', dr ? dr[1].trim() : '-');
        const ar = text.match(/ALTN\s+ROUTE[:\s]+([^\n]+?)(?=\s+FUEL|\s+$)/i);
        safeText('view-altn-route', ar ? ar[1].trim() : '-');
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
        
        if (row1Match) {
            // Format: CRZ WIND [M032] AVG TEMP [M54] ISA DEV [M08] LOWEST TEMP [M60] MAX SR [08]
            row1Text = `CRZ WIND ${row1Match[1]} AVG TEMP ${row1Match[2]} ISA DEV ${row1Match[3]} LOWEST TEMP ${row1Match[4]} MAX SR ${row1Match[5]}`;
        } else {
            // Try alternative pattern without the M prefix
            const altRow1Pattern = /CRZ WIND\s+(\w+)\s+AVG TEMP\s+(\w+)\s+ISA DEV\s+(\w+)\s+LOWEST TEMP\s+(\w+)\s+MAX SR\s+(\w+)/i;
            const altRow1Match = singleLine.match(altRow1Pattern);
            if (altRow1Match) {
                row1Text = `CRZ WIND ${altRow1Match[1]} AVG TEMP ${altRow1Match[2]} ISA DEV ${altRow1Match[3]} LOWEST TEMP ${altRow1Match[4]} MAX SR ${altRow1Match[5]}`;
            }
        }
        
        if (row2Match) {
            // Format: IDLE/PERF [-0.1/2.0] SEATS [166 (16/150)] STN [7] JMP [2]
            row2Text = `IDLE/PERF ${row2Match[1]}/${row2Match[2]} SEATS ${row2Match[3]} (${row2Match[4]}/${row2Match[5]}) STN ${row2Match[6]} JMP ${row2Match[7]}`;
        } else {
            // Try simpler pattern for row 2
            const altRow2Pattern = /IDLE\/PERF\s+([^ ]+)\s+SEATS\s+([^ ]+)\s+STN\s+([^ ]+)\s+JMP\s+([^ ]+)/i;
            const altRow2Match = singleLine.match(altRow2Pattern);
            if (altRow2Match) {
                row2Text = `IDLE/PERF ${altRow2Match[1]} SEATS ${altRow2Match[2]} STN ${altRow2Match[3]} JMP ${altRow2Match[4]}`;
            }
        }
        
        // Update the UI
        safeText('view-crz-wind-temp', row1Text);
        safeText('view-seats-stn-jmp', row2Text);
        
        return { row1: row1Text, row2: row2Text };
    }

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

        // 2. Find the latest ATO
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

        // 3. Determine start fuel
        const pdfTakeoffFuel = waypoints[0] ? (waypoints[0].baseFuel || parseInt(waypoints[0].fob)) : 0;
        let startFuelInput = el('o-f-0');
        const picBlock = parseInt(el('view-pic-block')?.value || el('view-pic-block')?.innerText) || blockFuelValue || 0;
        
        let currentStartFuel = (startFuelInput && startFuelInput.value) 
            ? parseInt(startFuelInput.value) 
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
                // Get the text after the matched pattern
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
                            if(parts[1]) data.awy = parts[1];
                            if(parts[2]) data.level = parts[2];
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
                        rawTime: timeValue
                    };
                    waypoints.push(wpObj); 
                }
            }
        }
        
        return waypoints;
    }

    async function parsePDFData(pdfBytes, isAutoLoad) {
        try {
            // Reset Variables
            waypoints = []; 
            alternateWaypoints = []; 
            fuelData = []; 
            blockFuelValue = 0;
            window.cutoffPageIndex = -1;
            
            // Reset frontCoords to null values
            frontCoords = { 
                atis: null, atcLabel: null, altm1: null, stby: null, 
                altm2: null, picBlockLabel: null, reasonLabel: null 
            };

            const pdf = await pdfjsLib.getDocument(pdfBytes).promise;

            // Parse each page
            for (let i = 1; i <= pdf.numPages; i++) {
                const page = await pdf.getPage(i);
                const content = await page.getTextContent();
                const textContent = content.items.map(x => x.str).join(' ');

                // Cutoff detection
                if (i > 3 && window.cutoffPageIndex === -1) {
                    const upper = textContent.toUpperCase();
                    if (upper.includes("END OF ALTERNATE FLIGHT PLAN") ||
                        (upper.includes("END") && upper.includes("FLIGHT") && upper.includes("PLAN")) || 
                        (upper.includes("WEATHER") && upper.includes("CHART")) ||
                        (upper.includes("NOTAM") && upper.includes("BRIEFING"))) {
                        window.cutoffPageIndex = i - 1; 
                    }
                }

                // Page 1 - with error handling
                if (i === 1) {
                    extractFrontCoords(content.items);
                    
                    // Try to parse page one, but don't crash on failure
                    try {
                        parsePageOne(textContent);
                    } catch (parseError) {
                        console.warn('Failed to parse page 1:', parseError);
                        // Set OFP loaded state to false so user can retry
                        if (typeof setOFPLoadedState === 'function') {
                            setOFPLoadedState(false);
                        }
                        throw parseError; // Re-throw to stop further processing
                    }
                }
                
                // Page 2+ (Waypoints) - only parse if page 1 succeeded
                if (i >= 2) {
                    const pageWaypoints = await parseWaypoints(page, i);
                    waypoints.push(...pageWaypoints);
                }
            }
            
            // Validate that we extracted some data
            if (waypoints.length === 0) {
                console.warn('No waypoints found in PDF');
                // Don't throw here, just continue with what we have
            }
            
            // Process the extracted data
            waypoints.forEach(wp => { 
                wp.baseFuel = parseInt(wp.fob) || 0; 
                wp.fuel = wp.baseFuel; 
            });
            processWaypointsList();
            
            // Update UI
            if (document.getElementById('view-pic-block')) {
                const elPic = document.getElementById('view-pic-block');
                const val = blockFuelValue || 0;
                if(elPic.tagName === 'INPUT') elPic.value = val; 
                else elPic.innerText = val; 
            }
        
            // Run calculations
            runFlightLogCalculations();
            renderFuelTable();
            renderFlightLogTables();
            
        } catch (error) {
            console.error('Error in parsePDFData:', error);
            
            // Make sure OFP state is set to false so user can retry
            if (typeof setOFPLoadedState === 'function') {
                setOFPLoadedState(false);
            }
            
            // Clear any partially loaded data
            waypoints = [];
            alternateWaypoints = [];
            fuelData = [];
            blockFuelValue = 0;
            
            // Clear UI tables
            ['ofp-tbody', 'altn-tbody', 'fuel-tbody'].forEach(id => {
                const tb = document.getElementById(id);
                if(tb) tb.innerHTML = '<tr><td colspan="13" style="text-align:center;color:gray;padding:20px">No data</td></tr>';
            });
            
            // Clear flight summary
            ['view-flt', 'view-reg', 'view-date', 'view-dep', 'view-dest', 
            'view-altn', 'view-std-text', 'view-sta-text', 'view-ci',
            'view-era-text', 'view-altn2', 'view-crz-wind-temp', 'view-seats-stn-jmp',
            'view-dest-route', 'view-altn-route', 'view-min-block', 'view-pic-block'].forEach(id => {
                safeText(id, '-');
            });
            
            // Show error notification (only for manual uploads)
            if (!isAutoLoad) {
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
                        <small>${error.message || 'Could not parse PDF data. Please check the file format.'}</small><br>
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
            }
            
            throw error; // Re-throw so runAnalysis knows it failed
        }
    }

    function debouncedFullRecalc() {
        clearTimeout(recalcTimeout);
        clearTimeout(syncTimeout);
        
        recalcTimeout = setTimeout(() => {
            runFlightLogCalculations();
            syncLastWaypoint();
        }, 300);
    }

// ==========================================
// 7. UI RENDERING
// ==========================================

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

    // Handle changing tabs
    window.showTab = window.showTab || function(id, btn) {
        // Save signature before leaving
        const activeSection = document.querySelector('.tool-section.active');
        if (activeSection && activeSection.id === 'section-confirm' && signaturePad) {
            if (!signaturePad.isEmpty()) {
                savedSignatureData = signaturePad.toDataURL(); 
            }
        }
        
        // Standard tab switching logic
        document.querySelectorAll('.tool-section').forEach(s => s.classList.remove('active'));
        document.querySelectorAll('.nav-btn').forEach(b => b.classList.remove('active'));
        if(el('section-'+id)) el('section-'+id).classList.add('active');
        if(btn) btn.classList.add('active');
        
        // Restore Signature if going to confirm tab
        if(id === 'confirm') {
            validateOFPInputs();
            setTimeout(() => {
                const canvas = el('sig-canvas');
                if (canvas) {
                    const ratio = Math.max(window.devicePixelRatio || 1, 1);
                    const newWidth = canvas.offsetWidth;
                    const newHeight = canvas.offsetHeight;
                    
                    if (canvas.width !== newWidth * ratio || canvas.height !== newHeight * ratio) {
                        canvas.width = newWidth * ratio;
                        canvas.height = newHeight * ratio;
                        canvas.getContext("2d").scale(ratio, ratio);
                        
                        if (signaturePad) signaturePad.off();
                        signaturePad = new SignaturePad(canvas, {
                            backgroundColor: 'rgba(0,0,0,0)',
                            penColor: getComputedStyle(document.documentElement).getPropertyValue('--accent').trim()
                        });
                    }
                    
                    if (!signaturePad) {
                        signaturePad = new SignaturePad(canvas, {
                            backgroundColor: 'rgba(0,0,0,0)',
                            penColor: getComputedStyle(document.documentElement).getPropertyValue('--accent').trim()
                        });
                    }
                    
                    if (savedSignatureData) {
                        signaturePad.fromDataURL(savedSignatureData, { ratio: ratio });
                    }
                }
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
        // 1. No OFP is loaded
        // 2. Not on Journey Log tab
        // 3. Not on Confirm tab (where we send OFP)
        if (!isOFPLoaded && activeTabId !== 'journey' && activeTabId !== 'confirm' && activeTabId !== 'settings') {
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
                console.warn('Container has no width, using default 800px');
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
            
            // Event listeners count matches list length exactly
            if(typeof attachWaypointEventListeners === 'function') attachWaypointEventListeners(id, pre, list.length);
        };
        
        fill(waypoints, 'ofp-tbody', 'o'); 
        fill(alternateWaypoints, 'altn-tbody', 'a');
        
        waypointTableCache = {
            waypoints: [...waypoints],
            alternateWaypoints: [...alternateWaypoints],
            lastUpdate: Date.now()
        };
        
        if(typeof updateCruiseLevel === 'function') updateCruiseLevel();
    }

    // SIGNATURE FUNCTIONS
    function clearSignature() {
        if (signaturePad) {
            signaturePad.clear();
            updateSaveButtonState();
        }
    }

    // Update save button state based on whether signature exists
    function updateSaveButtonState() {
        const saveButton = document.getElementById('btn-send-ofp');
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

    window.saveSignatureToMemory = function() {
        if (signaturePad && !signaturePad.isEmpty()) {
            savedSignatureData = signaturePad.toDataURL(); 
        }
    };

    // Make functions available globally
    window.clearSignature = clearSignature;
    window.getSignatureDataURL = getSignatureDataURL;

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
        let baseTimeStr = el(`o-a-${lastPrimaryIdx}`)?.value; // Try ATO
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
            const atd = el('j-on')?.value;
            const flightLogOK = !!atd;
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
                    `<div class="checklist-item"><span>${sanitizeHTML(c.label)}</span><span class="${c.valid?'status-ok':'status-fail'}">${c.valid?'✔':'✖'}</span></div>`
                ).join('');
                
                const valid = checks.every(c => c.valid);
                if(el('btn-send-ofp')) el('btn-send-ofp').disabled = !valid;
            }
    };

    function clearOFPInputs() {
        // 1. Clear FLight Summary Tab Inputs
        ['front-atis', 'front-atc', 'front-altm1', 'front-stby', 'front-altm2', 'front-extra-kg', 'front-extra-reason'].forEach(id => safeSet(id, ''));
            
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
        ['view-flt', 'view-reg', 'view-date','view-std-text', 'view-sta-text', 'view-dep', 'view-dest', 'view-altn', 'view-dest-route', 'view-altn-route', 'view-ci','view-etd-text', 'view-eta-text', 'view-era','view-crz-wind-temp', 'view-seats-stn-jmp'].forEach(id => safeText(id, '-'));
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

    // Attach event listeners to waypoint inputs
    function attachWaypointEventListeners(tableId, prefix, count) {
        for (let i = 0; i < count; i++) {
            const isTO = (i === 0 && prefix === 'o');
            
            // Time input
            const timeInput = el(`${prefix}-a-${i}`);
            if (timeInput) {
                if (isTO) {
                    timeInput.oninput = (e) => {
                        updateTakeoffTime(e.target.value);
                        debouncedFullRecalc();
                    };
                } else {
                    timeInput.oninput = debouncedSyncLastWaypoint;
                }
            }
            
            // Fuel input
            const fuelInput = el(`${prefix}-f-${i}`);
            if (fuelInput) {
                if (isTO) {
                    fuelInput.oninput = () => {
                        runFlightLogCalculations();
                        debouncedSyncLastWaypoint();
                    };
                } else {
                    fuelInput.oninput = () => {
                        debouncedSyncLastWaypoint();
                    };
                }
            }
            
            // FL input
            const flInput = el(`${prefix}-agl-${i}`);
            if (flInput) {
                flInput.oninput = debouncedUpdateCruiseLevel;
            }
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
    
    window.resetSystem = async function() {
        await logSecurityEvent('SYSTEM_RESET', {
            userInitiated: true,
            timestamp: new Date().toISOString()
        });
        if(!confirm("Warning: This will delete ALL data (OFP, Flight Log, and Journey Log). Continue?")) return;

        if (autoLockTimer) {
            clearTimeout(autoLockTimer);
            autoLockTimer = null;
        }

        // 1. Reset Internal Variables
        dailyLegs = [];
        waypoints = [];
        alternateWaypoints = [];
        fuelData = [];
        window.savedWaypointData = [];
        dutyStartTime = null;
        blockFuelValue = 0;
        savedSignatureData = null;
        window.cutoffPageIndex = -1;

        // 2. Clear Tables
        renderJourneyList();
        ['ofp-tbody', 'altn-tbody', 'fuel-tbody'].forEach(id => {
            const tb = document.getElementById(id);
            if(tb) tb.innerHTML = '';
        });
        
        // 3. Fuel Table to "Empty" state
        const fuelTb = document.getElementById('fuel-tbody');
        if(fuelTb) fuelTb.innerHTML = '<tr><td colspan="4" style="text-align:center;">No Fuel Data</td></tr>';

        // 4. Remove canvas on 'Paper Flight Plan'
        const pdfContainer = document.getElementById('pdf-render-container');
        const pdfFallback = document.getElementById('pdf-fallback');

        if (pdfFallback) pdfFallback.style.display = 'block'; // Show the "Drop PDF Here" box again

        if (pdfContainer) pdfContainer.innerHTML = ''; // Remove the canvas elements

        // 5. Reset Text Values
        const textIDs = [
            'view-flt', 'view-reg', 'view-date', 'view-dep', 'view-dest', 
            'view-std-text', 'view-sta-text', 'view-altn', 'view-ci',
            'view-dest-route', 'view-altn-route', 
            'view-min-block', 'view-pic-block',
            'view-mtow', 'view-mlw', 'view-mzfw', 'view-mpld', 'view-fcap', 
            'view-dow', 'view-tow', 'view-lw', 'view-zfw','view-etd-text', 'view-eta-text', 'view-era', 'view-altn2','view-crz-wind-temp', 'view-seats-stn-jmp',
        ];
        
        textIDs.forEach(id => {
            const e = document.getElementById(id);
            if(e) {
                // If it's an input, clear value; otherwise clear text
                if(e.tagName === 'INPUT' || e.tagName === 'TEXTAREA') e.value = "";
                else e.innerText = "-"; 
            }
        });

        // 6. Reset Input Values
        const inputIDs = [
            // Front Page & OFP Inputs
            'front-atis', 'front-atc', 'front-altm1', 'front-stby', 'front-altm2', 
            'front-extra-kg', 'front-extra-reason', 'ofp-atd-in',
            
            // Hidden/Sync Inputs
            'j-flt', 'j-reg', 'j-date', 'j-dep', 'j-dest', 'j-altn', 'j-std', 'j-alt2',
            
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

        // 7. Reset Duty times
        safeSet('j-duty-start', "00:00");
        safeSet('j-cc-duty-start', "00:00");
        safeSet('j-max-fdp', "00:00");
        safeSet('j-fc-count', "2"); 
        safeSet('j-cc-count', "4");
        const ccMaxHidden = document.getElementById('j-cc-max-fdp-hidden');
        if (ccMaxHidden) {
            ccMaxHidden.value = "00:00";
        }

        // 8. Reset Signature Pad
        if (window.signaturePad) {
            window.signaturePad.clear();
        }
        
        // 9. Reset File Input
        const fileInput = document.getElementById('ofp-file-in');
        if(fileInput) fileInput.value = "";
        
        // 10.Reset Database
        localStorage.removeItem('efb_log_state');
        
        try {
            if (typeof clearPdfDB === 'function') {
                await clearPdfDB();
            }
        } catch(e) { 
            console.log("Database clear error:", e); 
        }

        if (typeof validateOFPInputs === 'function') validateOFPInputs();
        
        setOFPLoadedState(false);
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

    function debouncedUpdateCruiseLevel() {
        clearTimeout(cruiseTimeout);
        cruiseTimeout = setTimeout(() => {
            updateCruiseLevel();
        }, 300);
    }

    // Transfer Last Waypoint for current Leg
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
        calcTripTime(); 
        calcFuel();
    };

    function debouncedSyncLastWaypoint() {
        clearTimeout(syncTimeout);
        syncTimeout = setTimeout(() => {
            syncLastWaypoint();
        }, 300);
    }

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

    // Helper to recalculate everything when app loads or leg is added
    window.initializeDutyCalculations = function() {
        
        if (dailyLegs.length > 0) {
            const firstLeg = dailyLegs[0];
            if (firstLeg['j-std']) {
                calcDutyLogic();
                recalcMaxFDP();
            }
        }
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

    // Helper to update highest Cruise Level
    window.updateLevel = function(type, index, value) {
        // 1. Update the internal data model
        if(type === 'o' && waypoints[index]) waypoints[index].level = value;
        if(type === 'a' && alternateWaypoints[index]) alternateWaypoints[index].level = value;
        
        // 2. Update the UI using the new SMART logic
        if(type === 'o') {
            updateCruiseLevel();
        }
    };

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

            // OFFSET 1.1: FOR FUEL & LOAD (Standard Calculation)
            const FUEL_OFFSET = (standardRows - templateRows) * rowGap;

            // OFFSET 1.2: FOR CREW & SIGNATURE (Boosted Calculation)
            let CREW_OFFSET = FUEL_OFFSET;
            
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

    // Helper to get value from input OR text from span
    window.detectReportOffset = function() {
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

    function confirmEndOfDay() {
        return new Promise((resolve) => {
            // Create a custom confirmation dialog
            const dialog = document.createElement('div');
            dialog.style.cssText = `
                position: fixed;
                top: 0;
                left: 0;
                right: 0;
                bottom: 0;
                background: rgba(0,0,0,0.7);
                display: flex;
                justify-content: center;
                align-items: center;
                z-index: 10000;
                backdrop-filter: blur(3px);
            `;
            
            dialog.innerHTML = `
                <div style="
                    background: var(--panel);
                    border-radius: 15px;
                    padding: 30px;
                    max-width: 400px;
                    width: 90%;
                    border: 1px solid var(--border);
                ">
                    <h3 style="color: var(--accent); margin-top: 0;">End of Day Confirmation</h3>
                    <p style="color: var(--text); margin-bottom: 20px;">
                        Are you sure you want to finalize the Journey Log and end the day?
                        <br><br>
                        <strong style="color: var(--error);">This will reset ALL data including:</strong>
                        <ul style="text-align: left; color: var(--dim);">
                            <li>Current OFP</li>
                            <li>Flight Log entries</li>
                            <li>Journey Log entries</li>
                            <li>All input data</li>
                        </ul>
                    </p>
                    <div style="display: flex; gap: 15px; margin-top: 25px;">
                        <button id="confirm-cancel" style="
                            flex: 1;
                            padding: 12px;
                            background: var(--input);
                            border: 1px solid var(--border);
                            color: var(--text);
                            border-radius: 10px;
                            cursor: pointer;
                        ">Cancel</button>
                        <button id="confirm-send" style="
                            flex: 1;
                            padding: 12px;
                            background: var(--success);
                            border: none;
                            color: white;
                            border-radius: 10px;
                            font-weight: bold;
                            cursor: pointer;
                        ">Finalize</button>
                    </div>
                </div>
            `;
            
            document.body.appendChild(dialog);
            
            // Add event listeners
            dialog.querySelector('#confirm-cancel').onclick = () => {
                document.body.removeChild(dialog);
                resolve(false);
            };
            
            dialog.querySelector('#confirm-send').onclick = () => {
                document.body.removeChild(dialog);
                resolve(true);
            };
        });
    }

    // Full reset after sending Journey Log (end of day)
    async function resetAfterJourneyLog() {
        const userConfirmed = await confirmEndOfDay();
        
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
                            // ATIS/ATC
                            const frontItems = [ 
                                {id:'front-atis', offset:40, coord:frontCoords.atis}, 
                                {id:'front-atc', offset:50, coord:frontCoords.atcLabel}
                            ];
                            frontItems.forEach(f => {
                                const v = el(f.id)?.value;
                                if(f.coord && v) newPage.drawText(v.toUpperCase(), { 
                                    x: f.coord.transform[4] + f.offset, 
                                    y: f.coord.transform[5] + V_LIFT, 
                                    size: 12, font: fontB, color: PDFLib.rgb(0,0,0) // Black text
                                });
                            });

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
                            if (signaturePad && !signaturePad.isEmpty() && frontCoords.reasonLabel) {
                                try {
                                    const sigData = signaturePad.toDataURL();
                                    const sigImg = await newPdf.embedPng(sigData);
                                    newPage.drawImage(sigImg, { x: frontCoords.reasonLabel.transform[4], y: frontCoords.reasonLabel.transform[5] + 40, width: 100, height: 35 });
                                } catch(e){}
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
                    
                    if(typeof resetOFPAfterSend === 'function') await resetOFPAfterSend();

                } catch (error) { 
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

    function confirmResetOFP() {
        return new Promise((resolve) => {
            // Create a custom confirmation dialog
            const dialog = document.createElement('div');
            dialog.style.cssText = `
                position: fixed;
                top: 0;
                left: 0;
                right: 0;
                bottom: 0;
                background: rgba(0,0,0,0.7);
                display: flex;
                justify-content: center;
                align-items: center;
                z-index: 10000;
                backdrop-filter: blur(3px);
            `;
            
            dialog.innerHTML = `
                <div style="
                    background: var(--panel);
                    border-radius: 15px;
                    padding: 30px;
                    max-width: 400px;
                    width: 90%;
                    border: 1px solid var(--border);
                    box-shadow: 0 10px 25px rgba(0,0,0,0.5);
                    text-align: center;
                ">
                    <h3 style="color: var(--accent); margin-top: 0; font-size: 1.2em;">OFP Generated Successfully</h3>
                    
                    <p style="color: var(--text); margin-bottom: 25px; line-height: 1.5;">
                        Are you happy with the downloaded file?
                        <br><br>
                        <span style="color: var(--dim); font-size: 0.9em;">
                            Click <strong>Finalize</strong> to wipe the form for the next flight.<br>
                            Click <strong>Modify</strong> if you need to make changes and download again.
                        </span>
                    </p>

                    <div style="display: flex; gap: 15px; margin-top: 25px;">
                        <button id="btn-keep" style="
                            flex: 1;
                            padding: 12px;
                            background: var(--input);
                            border: 1px solid var(--border);
                            color: var(--text);
                            border-radius: 10px;
                            cursor: pointer;
                            font-weight: 500;
                        ">Modify</button>
                        
                        <button id="btn-clear" style="
                            flex: 1;
                            padding: 12px;
                            background: var(--success);
                            border: none;
                            color: white;
                            border-radius: 10px;
                            font-weight: bold;
                            cursor: pointer;
                        ">Finalize</button>
                    </div>
                </div>
            `;
            
            document.body.appendChild(dialog);
            
            // Handle 'Modify'
            dialog.querySelector('#btn-keep').onclick = () => {
                document.body.removeChild(dialog);
                resolve(false);
            };
            
            // Handle 'Finalize'
            dialog.querySelector('#btn-clear').onclick = () => {
                document.body.removeChild(dialog);
                resolve(true);
            };
        });
    }

    async function resetOFPAfterSend() {
        // 1. Popup Confirmation
        const userConfirmed = await confirmResetOFP();
        if (!userConfirmed) return;

        try {
            // 2. Call Worker
            await performDataReset(true);
        } catch (error) {
            console.error("Error resetting OFP:", error);
        }
    }

// ==========================================
// 11. Download Managment
// ==========================================
    
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
    async function performDataReset(preserveDailyLegs = true) {

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

        if(typeof setOFPLoadedState === 'function') setOFPLoadedState(false);
        if(typeof validateOFPInputs === 'function') validateOFPInputs();
    }

// ==========================================
// 12. LOCAL STORAGE (AUTO-SAVE)
// ==========================================

    // Input ID
    const SAVE_IDS = [
        'j-flt', 'j-reg', 'j-date', 'j-dep', 'j-dest', 'j-altn', 'j-alt2', 'j-std','front-extra-kg',
        'j-out', 'j-off', 'j-on', 'j-in', 'j-night', 'j-night-calc',
        'j-to', 'j-ldg', 'j-ldg-type', 'j-flt-alt', 'j-ldg-detail',
        'j-init', 'j-uplift-w', 'j-uplift-vol', 'j-act-ramp', 'j-shut', 'j-slip', 'j-slip-2',
        'j-adl', 'j-chl', 'j-inf', 'j-bag', 'j-cargo', 'j-mail', 'j-zfw',
        'j-report-type', 'j-fc-count', 'j-cc-count', 'front-extra-reason',
        'front-atis', 'front-atc', 'front-altm1', 'front-stby', 'front-altm2', 'view-pic-block',
    ];

    // Save Inputs
    async function saveState() {
        if (!isLoaded) return;
        // 1. Capture the "User Inputs" from the DOM
        const userInputs = waypoints.map((wp, i) => ({
            ato: el(`o-a-${i}`)?.value || "",
            fuel: el(`o-f-${i}`)?.value || "",
            notes: el(`o-n-${i}`)?.value || "",
            agl: el(`o-agl-${i}`)?.value || ""
        }));

        const state = {
            inputs: {},
            dailyLegs: dailyLegs, 
            dutyStartTime: dutyStartTime,
            routeStructure: waypoints, 
            waypointUserValues: userInputs,
            version: APP_VERSION,
            timestamp: new Date().toISOString(),
            savedTaxiValue: fuelData.find(x => x.name === "TAXI")?.fuel || 200
        };

        // 2. Save the "User Inputs"
        SAVE_IDS.forEach(id => {
            const e = el(id);
            if(e) state.inputs[id] = e.value;
        });

        // 3. Encrypt and save
        try {
            const plainState = JSON.stringify(state);
            localStorage.setItem('efb_log_state_fallback', plainState);
            // Also save to the legacy key just in case
            localStorage.setItem('efb_log_state_plain', plainState);
        } catch (e) {
            console.error("Fallback save failed (Quota exceeded?)", e);
        }

        // 3. Try Encrypted Save (Async)
        // If this fails or gets killed by iOS, we already have the fallback above.
        try {
            // Check if crypto is actually available (often restricted in simple HTTP PWA contexts)
            if (window.crypto && window.crypto.subtle) {
                const encryptedState = await encryptData(state);
                localStorage.setItem('efb_log_state', encryptedState);
            }
        } catch (error) {
            console.warn("Encryption skipped or failed (using fallback):", error);
        }
    }

    // Reload Inputs
    async function loadState() {
        // Try encrypted first, then fallback
        let raw = localStorage.getItem('efb_log_state');
        let isEncrypted = true;
        
        if (!raw) {
            // Try unencrypted fallback
            raw = localStorage.getItem('efb_log_state_fallback');
            isEncrypted = false;
            
            if (!raw) return;
        }

        try {
            let state;
            
            if (isEncrypted) {
                try {
                    state = await decryptData(raw);
                } catch (decryptError) {
                    console.error("Decryption failed:", decryptError);
                    // Try unencrypted fallback
                    raw = localStorage.getItem('efb_log_state_fallback');
                    if (raw) {
                        state = JSON.parse(raw);
                        isEncrypted = false;
                    } else {
                        throw new Error("Could not decrypt data and no fallback found");
                    }
                }
            } else {
                state = JSON.parse(raw);
            }
            
            // Check version compatibility
            if (state.version && state.version !== APP_VERSION) {
                console.log(`Migrating from v${state.version} to v${APP_VERSION}`);
            }

            // 1. Restore User Inputs
            if(state.inputs) {
                Object.keys(state.inputs).forEach(id => {
                    const val = state.inputs[id];
                    if (val !== "" && val !== null) safeSet(id, val);
                });
            }
            
            // 2. Restore Route Structure
            if(state.routeStructure && Array.isArray(state.routeStructure) && state.routeStructure.length > 0) {
                waypoints = state.routeStructure;
                
                // 2.1 Draw the empty table first
                if (typeof renderFlightLogTables === 'function') {
                    renderFlightLogTables(); 
                }
                
                // 2.2 Restore Waypoint Inputs (ATO, Fuel, Notes) into the table
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

            // 6. Run Calculations
            runFlightLogCalculations();
            if (typeof syncLastWaypoint === 'function') syncLastWaypoint();
            console.log("Reloaded input data from auto-save (local storage)");

        } catch(e) { 
            console.error("Load error", e);
            
            // If corrupted, clear storage
            if (e.message && (e.message.includes('corrupted') || e.message.includes('decrypt') || e.message.includes('JSON'))) {
                localStorage.removeItem('efb_log_state');
                localStorage.removeItem('efb_log_state_fallback');
                console.log("Corrupted data detected. Storage has been cleared.");
            }
        }
        isLoaded = true;
    }

    async function loadSavedState() {
        // Load from localStorage
        await loadState();
        
        // Restore waypoints if saved
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
// ==========================================
// 13. PDF STORAGE (IndexedDB)
// ==========================================
    
    // Open Database
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

    // Check if PDF exists
    async function checkPdfInDB() {
        try {
            const db = await openDB();
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
        const db = await openDB();
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
        const db = await openDB();
        return new Promise((resolve, reject) => {
            const tx = db.transaction("files", "readonly");
            const req = tx.objectStore("files").get("currentOFP");
            req.onsuccess = () => resolve(req.result); // Return the Blob directly
            req.onerror = () => resolve(null);
        });
    }

    // Delete PDF from DB
    async function clearPdfDB() {
        const db = await openDB();
        const tx = db.transaction("files", "readwrite");
        tx.objectStore("files").delete("currentOFP");
    }

// ==========================================
// 14. SETTINGS
// ==========================================

    function initializeSettingsTab() {
        const settingsButtons = {
            'btn-change-pin': changePIN,
            'btn-view-audit': viewAuditLog,
            'btn-export-data': exportAllData,
            'btn-factory-reset': confirmFactoryReset,
            'btn-recover-data': recoverLostData,
        };
        
        Object.entries(settingsButtons).forEach(([id, handler]) => {
            const button = document.getElementById(id);
            if (button && typeof handler === 'function') {
                button.addEventListener('click', handler);
            }
        });
        
        // Auto-save settings when changed
        ['auto-lock-time', 'pdf-quality'].forEach(id => {
            const element = document.getElementById(id);
            if (element) {
                element.addEventListener('change', saveSettings);
            }
        });
        
        // Initialize settings display
        loadSettings();
        calculateStorageUsage();
    }

    // Initialize settings when app loads
    async function initializeSettings() {
        // Load saved settings
        loadSettings();
        
        // Calculate storage usage
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
            pdfQuality: document.getElementById('pdf-quality')?.value || '2.0', //
            lastSaved: new Date().toISOString()
        };
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
            
            // Calculate localStorage usage
            for (let i = 0; i < localStorage.length; i++) {
                const key = localStorage.key(i);
                const value = localStorage.getItem(key);
                if (value) {
                    totalBytes += key.length + value.length;
                }
            }
            
            // Calculate IndexedDB usage (approximate)
            if ('indexedDB' in window) {
                const db = await openDB();
                const tx = db.transaction("files", "readonly");
                const store = tx.objectStore("files");
                const request = store.get("currentOFP");
                
                request.onsuccess = () => {
                    if (request.result) {
                        totalBytes += request.result.size || 0;
                    }
                    updateStorageDisplay(totalBytes);
                };
                
                request.onerror = () => {
                    updateStorageDisplay(totalBytes);
                };
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
        const confirmed = await showConfirmModal(
            'Data Recovery Mode',
            '⚠️ WARNING: This will attempt to recover any lost data.<br>' +
            '<br>Continue?',
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
        const confirmed = await showConfirmModal(
            'Factory Reset',
            '⚠️ WARNING: This will delete ALL data including:<br>' +
            '• All flight data<br>' +
            '• All app settings<br>' +
            '• PIN and security data<br>' +
            '• Audit logs<br>' +
            '<br>This action cannot be undone. Continue?',
            'error'
        );
        
        if (confirmed) {
            // Clear all data
            localStorage.clear();
            
            // Clear IndexedDB
            if (typeof clearPdfDB === 'function') {
                await clearPdfDB();
            }
            
            // Logout user
            sessionStorage.removeItem('efb_authenticated');
            
            // Reload app
            showToast('All data reset. Reloading app...');
            setTimeout(() => location.reload(), 2000);
        }
    }

    // Utility functions
    function showConfirmModal(title, message, type = 'warning') {
        return new Promise((resolve) => {
            const dialog = document.createElement('div');
            dialog.className = 'settings-modal';
            
            dialog.innerHTML = `
                <div class="settings-modal-content">
                    <h3 style="color: ${type === 'error' ? 'var(--error)' : 'var(--accent)'}">${title}</h3>
                    <p style="color: var(--text); margin-bottom: 20px;">${message}</p>
                    
                    <div class="settings-modal-actions">
                        <button class="btn-cancel" id="modal-cancel-btn">Cancel</button>
                        <button class="btn-confirm" id="modal-confirm-btn" 
                                style="background: ${type === 'error' ? 'var(--error)' : 'var(--success)'}">
                            Continue
                        </button>
                    </div>
                </div>
            `;
            
            document.body.appendChild(dialog);
            
            // Add event listeners
            document.getElementById('modal-cancel-btn').addEventListener('click', () => {
                dialog.remove();
                resolve(false);
            });
            
            document.getElementById('modal-confirm-btn').addEventListener('click', () => {
                dialog.remove();
                resolve(true);
            });
        });
    }

    function showToast(message, type = 'success') {
        const toast = document.createElement('div');
        toast.style.cssText = `
            position: fixed;
            top: 20px;
            right: 20px;
            background: ${type === 'error' ? 'var(--error)' : 'var(--success)'};
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

// ==========================================
// 15. EVENT LISTENERS
// ==========================================

})();