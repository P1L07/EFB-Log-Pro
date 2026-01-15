# EFB Log Pro (for Air Astana)

## Overview
EFB Log Pro is a **client-side web application** designed to digitize and automate the cockpit paperwork workflow for Air Astana (KZR) and FlyArystan (AYN) pilots. It replaces manual pen-and-paper logging with an **interactive, semi-automated digital interface** that runs directly on the Electronic Flight Bag (iPad), featuring **military-grade security** and **complete offline capability**.

## Key Features

### 1. Automated OFP Parsing & Security
- **One-Click Secure Upload:** Parses standard Air Astana OFP PDFs with **integrity verification**
- **Smart Data Extraction:** Automatically extracts flight number, registration, callsign, weights, fuel data, and complete navigational route
- **Encrypted Storage:** All flight data encrypted with **AES-GCM 256-bit** encryption
- **PIN Authentication:** 6-digit PIN protection with account lockout (5 attempts = 15-minute lockout)

### 2. Digital Flight Log with Real-time Intelligence
- **Live Calculations:** Automatically calculates Fuel Difference (EFOB vs AFOB) and Time Difference (ETA vs ATA)
- **Visual Alerts:** Color-coded status indicators (Green/Red) for fuel checks and schedule adherence
- **Intelligent Waypoint Management:** Auto-fills subsequent waypoints based on actual time over (ATO) inputs
- **Offline Operation:** Full functionality without internet connection

### 3. Journey Log Automation with Airline-Specific Rules
- **Multi-Sector Support:** Handles up to 4 legs per duty day with automatic reordering
- **Dynamic Template Matching:** Automatically adjusts PDF output for 3, 4, or 6-sector Journey Log paper templates
- **Airline-Specific Duty Calculator:** Computes FDP and Night Duty overlaps based on:
  - **Air Astana:** 90min int'l / 75min domestic reporting times
  - **FlyArystan:** 75min int'l / 60min domestic reporting times
- **Built-in Digital Signature:** Vector-based signature pad with PDF embedding capability

### 4. High-Fidelity PDF Generation & Security
- **Secure Rasterization Engine:** Uses high-resolution rendering with **integrity verification** to prevent tampering
- **Vector Overlay:** Overlays user data (times, fuel, notes) with crystal-clear vector text
- **Audit Trail:** All PDF operations logged with encrypted audit trails
- **Standardized Output:** Generates flattened, read-only PDFs ready for archiving or emailing

## Technical Architecture & Security

### Privacy by Design
This application operates entirely **Client-Side**:
- **Zero External Servers:** All PDF parsing and logic happen within the browser's memory using JavaScript
- **No Data Uploads:** Flight plans and sensitive data are **never** uploaded to a cloud server; they remain strictly on the pilot's device
- **Complete Offline Capability:** Once loaded, the application functions without an internet connection

### Advanced Security Implementation
- **AES-GCM 256-bit Encryption:** All stored data encrypted with military-grade cryptography
- **Service Worker Integrity:** SHA-256 hash verification prevents unauthorized modifications
- **Audit Logging:** All security events (PIN attempts, PDF uploads, system resets) are encrypted and stored
- **Origin Verification:** Only allows updates from authorized sources
- **Automatic Encryption:** All user inputs automatically encrypted before storage

### Tech Stack:
- **Core:** HTML5, CSS3, Vanilla JavaScript (ES6+)
- **Security:** Web Crypto API (AES-GCM 256-bit, SHA-256)
- **PDF Engine:** `pdf.js` (Mozilla) for rendering and parsing with integrity checks
- **PDF Generation:** `pdf-lib` for modification and creation
- **Storage:** IndexedDB (for PDFs) + encrypted LocalStorage (for app state)
- **PWA:** Service Worker for offline capability and installation

## Airline-Specific Implementation
- **FDP Calculations:** Based on Kazakhstan CARS with sector reductions
- **Night Duty:** 21:00-23:59 UTC (02:00-04:59 local KZ time)
- **Streamlined Calculations:** Optimized for high-frequency operations
  
### Air Astana (KZR/KC) Rules
- **Reporting Times:** 90 minutes before STD for international, 75 minutes for domestic
- **Cabin Crew:** Reports 15 minutes before flight crew

### FlyArystan (AYN/FS) Rules
- **Reporting Times:** 75 minutes before STD for international, 60 minutes for domestic
- **Crew Coordination:** Flight and cabin crew report simultaneously


## Usage Guide

### 1. Initial Setup
1. **First Launch:** Set your 6-digit security PIN
2. **Upload Journey Template:** Load your airline's journey log PDF template
3. **Configure Airline:** System auto-detects KZR vs AYN based on flight number

### 2. Daily Workflow
```
[OFP Upload] → [Flight Data Entry] → [Journey Log Management] → [Sign & Export]
```

#### Step 1: Upload OFP
- **Secure Upload:** Click "Upload OFP" - system verifies PDF integrity
- **Auto-Parse:** Extracts flight data, route, fuel, weights automatically
- **Validation:** Cross-checks extracted data for consistency

#### Step 2: Pre-Flight Preparation
1. Navigate to "Flight Summary" tab
2. Verify fuel/weights in the "Fuel & Load" tab
3. Fill in ATIS/Clearance/Altimeter settings
4. System auto-calculates PIC block fuel

#### Step 3: In-Flight Logging
1. Go to "Flight Log" tab
2. Enter ATO (Actual Time Over) at waypoints
3. Record actual Fuel on Board (FOB) readings
4. System automatically:
   - Updates subsequent ETAs
   - Calculates fuel differences
   - Syncs with journey log

#### Step 4: Post-Flight & Journey Log
1. Switch to "Journey Log" tab
2. Click "+ Add Leg" for each sector
3. System auto-populates:
   - Block times from flight log
   - Fuel statistics
   - Duty calculations
4. **Airline-Specific Rules Applied:**
   - Automatic FDP limits based on reporting time
   - Night duty hour calculations
   - Sector count reductions

#### Step 5: End of Day & Export
1. Navigate to "Confirm" tab
2. **Digital Signature:** Sign with finger/stylus
3. **Export Options:**
   - **Modified OFP:** Annotated PDF with all pilot inputs
   - **Journey Log:** Completed log with all legs
   - **Email:** Automatic sharing via email
4. **End of Day Reset:** System prompts to clear for next day

## Compatibility & Performance

### Device Support
- **Primary:** iPad (Safari/Chrome) - optimized for cockpit use
- **Secondary:** Desktop (Windows/Mac) for planning
- **Mobile:** iPhone/Android for reference
- **Installation:** Install as PWA for native app experience

### Technical Requirements
- **Browser:** Safari 14+, Chrome 80+, Firefox 75+
- **Storage:** 100MB minimum for PDF caching
- **Memory:** 1GB RAM recommended
- **Permissions:** Local storage, IndexedDB access

### Performance Optimizations
- **Debounced Saving:** Auto-save with 500ms delay to prevent lag
- **Incremental Updates:** Only modified DOM elements refreshed
- **PDF Caching:** OFP cached in IndexedDB for instant reload
- **Memory Management:** Automatic cleanup of large objects

## Security Protocol

### For Pilots
1. **PIN Management:**
   - Never share your PIN
   - Change PIN monthly
   - Use device biometrics as secondary protection

2. **Data Security:**
   - Log out when leaving device unattended
   - Enable device passcode protection
   - Regular PDF exports for backup

3. **Incident Response:**
   - Report lost/stolen devices immediately
   - Use remote wipe if available
   - Contact ops for security incidents

### For Administrators
1. **Audit Trail Review:**
   - Monitor failed PIN attempts
   - Track PDF export frequency
   - Review system reset events

2. **Update Management:**
   - Verify service worker integrity hashes
   - Test new airline rule implementations
   - Validate PDF template compatibility

## Troubleshooting

### Common Issues

| Issue | Solution | Security Note |
|-------|----------|---------------|
| **PDF won't upload** | Check file format (.pdf), size (<10MB) | Verify PDF isn't password-protected |
| **PIN not accepted** | Use "Forgot PIN" (erases all data) | 5th failure triggers 15-min lockout |
| **Data not saving** | Check browser storage permissions | Data encrypted; cannot recover without PIN |
| **Journey log mismatch** | Verify airline (KZR vs AYN) detection | Rules differ between airlines |
| **Signature not appearing** | Check PDF viewer compatibility | Signature embedded as vector graphic |

### Recovery Procedures
1. **Corrupted Data:**
   - System auto-detects corruption
   - Offers to restore from last good save
   - Maintains encrypted audit log of corruption events

2. **Lost PIN:**
   - No PIN recovery (security feature)
   - "Forgot PIN" erases all encrypted data
   - Must restart with new PIN and re-upload OFP

3. **Device Change:**
   - Export all PDFs before switching devices
   - Import PDFs on new device
   - Set new PIN (cannot transfer encrypted state)

## Compliance & Standards

### Aviation Regulations
- **Kazakhstan CARS** compliant for duty calculations
- **ICAO Annex 6** standards for electronic documentation
- **EASA/FAA** electronic flight bag requirements
- **Air Astana/FlyArystan SOPs** integrated

### Data Protection
- **GDPR Compliant:** All processing local, no external transfers
- **Right to Erasure:** Complete reset available
- **Data Minimization:** Only essential data collected
- **Encryption at Rest:** All data encrypted before storage

## Future Roadmap

### Short-term (Q2 2024)
- **Multi-crew Sync:** Real-time coordination between pilot and copilot devices
- **Weather Integration:** METAR/TAF display overlay

### Long-term (2025)
- **Maintenance Integration:** Technical log entries
- **API Integration:** Direct OFP download from airline systems

---
**Version:** 1.3 (Secure Production)  
**Security Level:** AES-GCM 256-bit Encrypted  
**Last Audit:** January 2026  
**Contact:** -
**Emergency Security:** -

*Developed for Flight Crew Operations*
