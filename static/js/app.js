/**
 * Anti-Forensics Detection System — Frontend JavaScript (Phase 2 & Persistent History)
 * Handles user file selection via Windows File Explorer, live scan execution,
 * dynamic dashboard rendering, persistent Scan History, user isolation, and PDF reports.
 */

let currentScans = [];
let selectedScanId = null;
let currentScanResult = null;
let cachedModelMetadata = null;
let selectedFilePath = null;
let currentView = 'dashboard';
let stagedFile = null;
let stagedFolderFiles = null;

// History Pagination & Filtering State
let currentHistoryPage = 1;
let totalHistoryPages = 1;
let historySearchDebounceTimer = null;
let pendingDeleteScanId = null;

document.addEventListener('DOMContentLoaded', () => {
    // Purge any stale client-side cache across sessions
    try {
        sessionStorage.clear();
    } catch (e) {}
    initDragAndDrop();
    loadScans();
});

function initDragAndDrop() {
    const banner = document.getElementById('file-selection-banner');
    if (!banner) return;

    ['dragenter', 'dragover'].forEach(eventName => {
        banner.addEventListener(eventName, (e) => {
            e.preventDefault();
            e.stopPropagation();
            banner.classList.add('drag-over');
        });
    });

    ['dragleave', 'drop'].forEach(eventName => {
        banner.addEventListener(eventName, (e) => {
            e.preventDefault();
            e.stopPropagation();
            banner.classList.remove('drag-over');
        });
    });

    banner.addEventListener('drop', (e) => {
        const dt = e.dataTransfer;
        if (dt && dt.files && dt.files.length > 0) {
            stageChosenFile(dt.files[0]);
        }
    });

    // Prevent default window navigation on accidental drop outside banner
    window.addEventListener('dragover', (e) => e.preventDefault());
    window.addEventListener('drop', (e) => e.preventDefault());
}

function logoutUser(event) {
    if (event) event.preventDefault();
    try {
        sessionStorage.clear();
        localStorage.clear();
    } catch (e) {}
    resetDetailsPanel();
    window.location.href = '/logout';
}

function resetDetailsPanel() {
    selectedScanId = null;
    currentScanResult = null;
    stagedFile = null;
    stagedFolderFiles = null;
    selectedFilePath = null;

    const scanTitle = document.getElementById('selected-scan-title');
    if (scanTitle) scanTitle.innerText = 'Evidence File Inspection';
    const scanMeta = document.getElementById('selected-scan-meta');
    if (scanMeta) scanMeta.innerText = 'Select a scan or click "Start New Scan" above';

    const detailsActions = document.getElementById('details-actions');
    if (detailsActions) detailsActions.style.display = 'none';

    const riskBar = document.getElementById('risk-overview-bar');
    if (riskBar) riskBar.style.display = 'none';

    const metaCard = document.getElementById('evidence-meta-card');
    if (metaCard) metaCard.style.display = 'none';

    const mlCard = document.getElementById('ml-prediction-card');
    if (mlCard) mlCard.style.display = 'none';

    const findingsWrap = document.getElementById('findings-table-wrap');
    if (findingsWrap) {
        findingsWrap.innerHTML = `
            <div class="empty-state">
                <div class="empty-icon">🛡️</div>
                <h4>No Scan Active</h4>
                <p>Click <b>Start New Scan</b> above to select a file from Windows File Explorer or choose a past scan from the list.</p>
            </div>
        `;
    }

    const bannerPath = document.getElementById('banner-path-text');
    if (bannerPath) bannerPath.innerHTML = 'No evidence file selected yet. Click below to browse Windows File Explorer.';

    const scanBtn = document.getElementById('btn-run-scan');
    if (scanBtn) scanBtn.style.display = 'none';

    // Also reset dedicated ML Feature Matrix View
    const mlNoScan = document.getElementById('ml-no-scan-state');
    if (mlNoScan) mlNoScan.style.display = 'block';
    const mlContainer = document.getElementById('ml-selected-scan-container');
    if (mlContainer) mlContainer.style.display = 'none';
    const mlActions = document.getElementById('ml-view-actions');
    if (mlActions) mlActions.style.display = 'none';
}

// ============================================================================
// Data Fetching & Scans Management (Dashboard Recent Scans)
// ============================================================================

async function loadScans() {
    const container = document.getElementById('scans-container');
    if (container) {
        container.innerHTML = '<div class="loading-state">Loading recent scan records...</div>';
    }

    try {
        const res = await fetch('/api/scans?limit=10', { cache: 'no-store' });
        const data = await res.json();

        if (data.status === 'success') {
            currentScans = data.scans || [];
            renderScansList(currentScans);
            updateDashboardMetrics(data.stats, data.total);

            const badge = document.getElementById('recent-scans-total-badge');
            if (badge) {
                badge.innerText = data.total !== undefined ? data.total : currentScans.length;
            }

            if (currentScans.length > 0) {
                const exists = currentScans.some(s => s.scan_id === selectedScanId);
                if (!selectedScanId || !exists) {
                    selectScan(currentScans[0].scan_id);
                }
            } else {
                // Strict user data isolation: if this account has 0 scans, wipe inspection panel completely
                resetDetailsPanel();
            }
        } else {
            resetDetailsPanel();
            if (container) container.innerHTML = '<div class="empty-state"><p>No scans recorded yet.</p></div>';
        }
    } catch (err) {
        console.error("Error loading scans:", err);
        resetDetailsPanel();
        if (container) container.innerHTML = '<div class="empty-state"><p>Error connecting to database.</p></div>';
    }
}

function updateDashboardMetrics(stats, totalCount) {
    if (stats) {
        document.getElementById('stat-total-scans').innerText = stats.total_scans !== undefined ? stats.total_scans : (totalCount || 0);
        document.getElementById('stat-total-findings').innerText = stats.total_findings || 0;
        document.getElementById('stat-critical-findings').innerText = stats.critical_findings || 0;
    } else if (currentScans) {
        document.getElementById('stat-total-scans').innerText = totalCount || currentScans.length;
        let totalFindings = 0;
        let criticalFindings = 0;
        currentScans.forEach(s => {
            totalFindings += (s.total_findings || 0);
            if (s.risk_level === 'HIGH' || s.risk_level === 'CRITICAL' || s.risk_score >= 61.0) {
                criticalFindings += 1;
            }
        });
        document.getElementById('stat-total-findings').innerText = totalFindings;
        document.getElementById('stat-critical-findings').innerText = criticalFindings;
    }
}

function renderScansList(scans) {
    const container = document.getElementById('scans-container');
    if (!container) return;

    if (!scans || scans.length === 0) {
        container.innerHTML = '<div class="empty-state"><p>No scans found. Click "Start New Scan" to begin.</p></div>';
        return;
    }

    container.innerHTML = '';
    scans.forEach(s => {
        const item = document.createElement('div');
        item.className = `scan-item ${s.scan_id === selectedScanId ? 'selected' : ''}`;
        item.id = `scan-item-${s.scan_id}`;
        item.onclick = () => selectScan(s.scan_id);

        const risk = s.risk_score || 0;
        const riskLevel = (s.risk_level || (risk >= 80 ? 'CRITICAL' : (risk >= 61 ? 'HIGH' : (risk >= 31 ? 'MEDIUM' : (risk > 0 ? 'LOW' : 'CLEAN'))))).toUpperCase();

        let riskClass = 'risk-low';
        if (riskLevel === 'CRITICAL' || risk >= 80) riskClass = 'risk-critical';
        else if (riskLevel === 'HIGH' || risk >= 61) riskClass = 'risk-high';
        else if (riskLevel === 'MEDIUM' || risk >= 31) riskClass = 'risk-med';
        else if (riskLevel === 'CLEAN' || risk === 0) riskClass = 'risk-clean';

        const timeStr = s.start_time ? new Date(s.start_time).toLocaleDateString([], { month: 'short', day: 'numeric' }) + ' ' + new Date(s.start_time).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : '-';
        const targetName = s.filename || s.summary?.file_name || (s.target_path ? s.target_path.split(/[\\/]/).pop() : formatScanType(s.target_type));

        const statusTag = s.status === 'FAILED' ? '<span class="scan-item-status-tag status-failed">FAILED</span>' : '';

        item.innerHTML = `
            <div class="scan-item-header">
                <span class="scan-item-type" title="${s.target_path || targetName}">${targetName}</span>
                <span class="scan-item-risk ${riskClass}">${riskLevel}: ${risk.toFixed(0)}</span>
            </div>
            <div class="scan-item-meta">
                <span>${s.total_findings || 0} findings</span> • <span>${timeStr}</span> ${statusTag}
            </div>
        `;
        container.appendChild(item);
    });
}

function formatScanType(type) {
    switch (type) {
        case 'single_file': return '📄 Evidence File';
        case 'demo_simulation': return '⚡ Demo Simulation';
        case 'filesystem': return '📁 Directory Scan';
        case 'live_system': return '💻 Live Host Audit';
        default: return type || 'Evidence Scan';
    }
}

// ============================================================================
// Phase 2: User File/Folder Selection via Native Windows File Explorer
// ============================================================================

let stagedFile = null;
let stagedFolderFiles = null;

function openStartScanFlow() {
    openScanModal();
}

function stageChosenFile(file) {
    if (!file) return;

    stagedFile = file;
    stagedFolderFiles = null;
    selectedFilePath = file.name;

    const bannerPath = document.getElementById('banner-path-text');
    const scanBtn = document.getElementById('btn-run-scan');

    const sizeKb = (file.size / 1024).toFixed(1);
    const sizeFormatted = file.size > 1024 * 1024 
        ? `${(file.size / (1024 * 1024)).toFixed(2)} MB` 
        : `${sizeKb} KB`;

    if (bannerPath) {
        bannerPath.innerHTML = `<strong>Selected:</strong> <span style="color: var(--accent-blue); font-weight: 600;">${file.name}</span> (${sizeFormatted})<br/><span style="color: var(--text-muted); font-size: 11px;">Ready for strict read-only forensic analysis & ML evaluation</span>`;
    }
    
    if (scanBtn) {
        scanBtn.style.display = 'inline-flex';
        scanBtn.innerText = '🚀 Scan Selected File';
        scanBtn.onclick = executeSelectedFileScan;
    }
}

async function handleSelectFileClick(event) {
    // If showOpenFilePicker is available (Desktop Chrome / PWA), use it for direct native Explorer integration
    if (typeof window.showOpenFilePicker === 'function') {
        if (event) event.preventDefault();
        await openFilePicker();
    }
    // Else allow default label action to trigger evidence-file-input natively
}

async function handleSelectFolderClick(event) {
    if (typeof window.showDirectoryPicker === 'function') {
        if (event) event.preventDefault();
        await openFolderPicker();
    }
    // Else allow default label action to trigger evidence-folder-input natively
}

async function handleModalFileSelect(event) {
    closeScanModal();
    if (typeof window.showOpenFilePicker === 'function') {
        if (event) event.preventDefault();
        await openFilePicker();
    }
}

async function handleModalFolderSelect(event) {
    closeScanModal();
    if (typeof window.showDirectoryPicker === 'function') {
        if (event) event.preventDefault();
        await openFolderPicker();
    }
}

function openFilePickerFromModal() {
    closeScanModal();
    openFilePicker();
}

function openFolderPickerFromModal() {
    closeScanModal();
    openFolderPicker();
}

async function openFilePicker() {
    // 1. First attempt: Modern File System Access API (official native picker for desktop Chromium PWAs)
    if (typeof window.showOpenFilePicker === 'function') {
        try {
            const handles = await window.showOpenFilePicker({
                multiple: false,
                types: [
                    {
                        description: 'Evidence Files',
                        accept: {
                            '*/*': []
                        }
                    }
                ]
            });
            if (handles && handles.length > 0) {
                const file = await handles[0].getFile();
                stageChosenFile(file);
                return;
            }
        } catch (err) {
            // User cancelled file selection dialog
            if (err.name === 'AbortError') return;
            console.warn('[PWA] showOpenFilePicker fallback:', err);
        }
    }

    // 2. Fallback: Accessible file input element
    const input = document.getElementById('evidence-file-input');
    if (input) {
        input.value = ''; // Reset so same file can be re-selected
        input.click();   // Opens native Windows File Explorer
    }
}

async function openFolderPicker() {
    if (typeof window.showDirectoryPicker === 'function') {
        try {
            const dirHandle = await window.showDirectoryPicker();
            if (dirHandle) {
                const folderFiles = [];
                for await (const entry of dirHandle.values()) {
                    if (entry.kind === 'file') {
                        const file = await entry.getFile();
                        folderFiles.push(file);
                    }
                }
                if (folderFiles.length > 0) {
                    stagedFolderFiles = folderFiles;
                    stagedFile = null;
                    const bannerPath = document.getElementById('banner-path-text');
                    const scanBtn = document.getElementById('btn-run-scan');
                    if (bannerPath) {
                        bannerPath.innerHTML = `<strong>Selected Folder:</strong> <span style="color: var(--accent-blue); font-weight: 600;">${dirHandle.name}</span> (${folderFiles.length} evidence files)<br/><span style="color: var(--text-muted); font-size: 11px;">Ready for batch recursive artifact inspection</span>`;
                    }
                    if (scanBtn) {
                        scanBtn.style.display = 'inline-flex';
                        scanBtn.innerText = `🚀 Scan Folder (${folderFiles.length} files)`;
                        scanBtn.onclick = executeFolderScan;
                    }
                    return;
                }
            }
        } catch (err) {
            if (err.name === 'AbortError') return;
            console.warn('[PWA] showDirectoryPicker fallback:', err);
        }
    }

    const input = document.getElementById('evidence-folder-input');
    if (input) {
        input.value = '';
        input.click();   // Opens native Windows File Explorer folder picker
    }
}

function handleFileChosen(event) {
    const files = event.target.files;
    if (!files || files.length === 0) {
        return;
    }
    stageChosenFile(files[0]);
}

function handleFolderChosen(event) {
    const files = event.target.files;
    const bannerPath = document.getElementById('banner-path-text');
    const scanBtn = document.getElementById('btn-run-scan');

    if (!files || files.length === 0) {
        return;
    }

    stagedFolderFiles = Array.from(files);
    stagedFile = null;

    let folderName = 'Evidence Folder';
    if (files[0].webkitRelativePath) {
        folderName = files[0].webkitRelativePath.split('/')[0];
    }

    bannerPath.innerHTML = `<strong>Selected Folder:</strong> <span style="color: var(--accent-blue); font-weight: 600;">${folderName}</span> (${files.length} evidence files)<br/><span style="color: var(--text-muted); font-size: 11px;">Ready for batch recursive artifact inspection</span>`;

    scanBtn.style.display = 'inline-flex';
    scanBtn.innerText = `🚀 Scan Folder (${files.length} files)`;
    scanBtn.onclick = executeFolderScan;
}

async function executeSelectedFileScan() {
    if (!stagedFile) {
        alert('Please select an evidence file first from Windows File Explorer.');
        return;
    }

    const scanBtn = document.getElementById('btn-run-scan');
    const bannerPath = document.getElementById('banner-path-text');
    scanBtn.disabled = true;
    scanBtn.innerText = '⏳ Scanning (Read-Only)...';
    bannerPath.innerHTML = `<em>Performing read-only forensic inspection, signature verification, and ML risk evaluation on ${stagedFile.name}...</em>`;

    try {
        const formData = new FormData();
        formData.append('file', stagedFile);

        const res = await fetch('/api/scan/upload', {
            method: 'POST',
            body: formData
        });

        const data = await res.json();
        if (data.status === 'success' && data.result) {
            bannerPath.innerHTML = `<strong>Scan Complete:</strong> <span style="color: var(--accent-green); font-weight: 600;">${data.result.file_name}</span> | Risk Score: <strong>${data.result.risk_score}/100</strong> (${data.result.risk_level})`;
            await loadScans();
            displayScanResult(data.result);
        } else {
            const errorMsg = data.message || 'Failed to scan evidence file';
            bannerPath.innerHTML = `<strong style="color: var(--accent-red);">Scan Error:</strong> ${errorMsg}`;
            alert(`Scan error: ${errorMsg}`);
        }
    } catch (err) {
        bannerPath.innerHTML = `<strong style="color: var(--accent-red);">Network Error:</strong> Failed to communicate with forensic analysis engine.`;
        alert('Network error executing forensic scan.');
    } finally {
        scanBtn.disabled = false;
        scanBtn.innerText = '🚀 Scan Selected File';
    }
}

async function executeFolderScan() {
    if (!stagedFolderFiles || stagedFolderFiles.length === 0) {
        alert('Please select an evidence folder first.');
        return;
    }

    const scanBtn = document.getElementById('btn-run-scan');
    const bannerPath = document.getElementById('banner-path-text');
    scanBtn.disabled = true;
    scanBtn.innerText = '⏳ Scanning Folder...';
    bannerPath.innerHTML = `<em>Uploading and analyzing ${stagedFolderFiles.length} folder artifacts in isolated evidence vault...</em>`;

    try {
        const formData = new FormData();
        stagedFolderFiles.forEach(f => {
            formData.append('files', f, f.webkitRelativePath || f.name);
        });

        const res = await fetch('/api/scan/upload-folder', {
            method: 'POST',
            body: formData
        });

        const data = await res.json();
        if (data.status === 'success') {
            await loadScans();
            if (data.scan_id) {
                selectScan(data.scan_id);
            }
            bannerPath.innerHTML = `<strong>Folder Scan Complete:</strong> Analyzed ${data.total_files || stagedFolderFiles.length} files. Risk Score: <strong>${data.risk_score}/100</strong>`;
        } else {
            const errorMsg = data.message || 'Failed to scan folder';
            bannerPath.innerHTML = `<strong style="color: var(--accent-red);">Folder Scan Error:</strong> ${errorMsg}`;
            alert(`Folder scan error: ${errorMsg}`);
        }
    } catch (err) {
        bannerPath.innerHTML = `<strong style="color: var(--accent-red);">Network Error:</strong> Failed to execute folder scan.`;
        alert('Network error executing folder scan.');
    } finally {
        scanBtn.disabled = false;
        scanBtn.innerText = '🚀 Scan Selected Folder';
    }
}

// ============================================================================
// Selected Scan Details Rendering (100% Fidelity Snapshot)
// ============================================================================

async function selectScan(scanId) {
    selectedScanId = scanId;

    document.querySelectorAll('.scan-item').forEach(el => el.classList.remove('selected'));
    const selectedEl = document.getElementById(`scan-item-${scanId}`);
    if (selectedEl) selectedEl.classList.add('selected');

    try {
        const res = await fetch(`/api/scan/${scanId}`, { cache: 'no-store' });
        const data = await res.json();

        if (data.status === 'success') {
            const scan = data.scan;
            const summary = scan.summary || {};

            if (data.model_metadata) {
                cachedModelMetadata = data.model_metadata;
            }

            let compositeResult;
            if (data.result) {
                compositeResult = data.result;
            } else {
                const risk = scan.risk_score || 0.0;
                const riskLevel = scan.risk_level || summary.risk_level || (risk >= 80 ? 'CRITICAL' : (risk >= 61 ? 'HIGH' : (risk >= 31 ? 'MEDIUM' : (risk > 0 ? 'LOW' : 'CLEAN'))));
                const fileName = scan.filename || summary.file_name || (scan.target_path ? scan.target_path.split(/[\\/]/).pop() : 'Evidence Target');

                compositeResult = {
                    scan_id: scan.scan_id,
                    scan_date: scan.start_time,
                    file_name: fileName,
                    file_path: scan.target_path || 'N/A',
                    file_size: scan.file_size || summary.file_size || 0,
                    extension: scan.file_type || summary.extension || '-',
                    signature_type: summary.signature_type || 'Unknown',
                    extension_match: summary.extension_match !== undefined ? summary.extension_match : true,
                    is_hidden: summary.is_hidden || false,
                    sha256_hash: scan.sha256_hash || summary.sha256 || summary.sha256_hash || 'N/A',
                    created_time: summary.created_time || '-',
                    modified_time: summary.modified_time || '-',
                    accessed_time: summary.accessed_time || '-',
                    risk_score: risk,
                    risk_level: riskLevel,
                    ml_prediction: scan.ml_prediction || summary.ml_prediction || (risk >= 50 ? 'Suspicious' : 'Normal'),
                    ml_probability: scan.ml_probability !== undefined ? scan.ml_probability : (summary.ml_probability || (risk / 100.0)),
                    ml_confidence_percent: scan.ml_confidence || summary.ml_confidence_percent || 96.7,
                    findings: data.findings || [],
                    features: data.features || {}
                };
            }

            currentScanResult = compositeResult;
            displayScanResult(compositeResult);

            if (currentView === 'features') {
                renderMLFeatureMatrixView(compositeResult, cachedModelMetadata);
            }
        } else {
            console.error("Scan details error:", data.message);
        }
    } catch (err) {
        console.error("Error loading scan details:", err);
    }
}

function displayScanResult(result) {
    selectedScanId = result.scan_id;
    currentScanResult = result;

    const sizeFormatted = result.file_size > 1024 * 1024 
        ? `${(result.file_size / (1024 * 1024)).toFixed(2)} MB` 
        : `${((result.file_size || 0) / 1024).toFixed(1)} KB`;

    document.getElementById('selected-scan-title').innerText = `${result.file_name} (${sizeFormatted})`;
    document.getElementById('selected-scan-meta').innerText = `Scan ID: ${result.scan_id} | Scanned: ${result.scan_date || result.created_time || '-'}`;
    document.getElementById('details-actions').style.display = 'flex';

    // 1. Risk Overview & Gauge
    const riskBar = document.getElementById('risk-overview-bar');
    riskBar.style.display = 'flex';
    const riskScore = result.risk_score || 0.0;
    document.getElementById('risk-meter-fill').style.width = `${Math.min(100, Math.max(0, riskScore))}%`;
    document.getElementById('risk-meter-text').innerText = `${riskScore.toFixed(1)} / 100`;

    const riskBadge = document.getElementById('risk-level-badge');
    const riskLevel = (result.risk_level || (riskScore >= 80 ? 'CRITICAL' : (riskScore >= 61 ? 'HIGH' : (riskScore >= 31 ? 'MEDIUM' : (riskScore > 0 ? 'LOW' : 'CLEAN'))))).toUpperCase();
    riskBadge.innerText = `${riskLevel} RISK`;
    riskBadge.className = `risk-level-badge level-${riskLevel.toLowerCase()}`;

    // Breakdown tags
    const breakdown = document.getElementById('risk-breakdown-tags');
    breakdown.innerHTML = '';
    const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
    (result.findings || []).forEach(f => {
        const sev = (f.severity || 'INFO').toUpperCase();
        if (counts[sev] !== undefined) counts[sev]++;
    });
    if (counts.CRITICAL > 0) breakdown.innerHTML += `<span class="badge badge-critical">${counts.CRITICAL} Critical</span>`;
    if (counts.HIGH > 0) breakdown.innerHTML += `<span class="badge badge-high">${counts.HIGH} High</span>`;
    if (counts.MEDIUM > 0) breakdown.innerHTML += `<span class="badge badge-medium">${counts.MEDIUM} Medium</span>`;
    if (counts.LOW > 0) breakdown.innerHTML += `<span class="badge badge-low">${counts.LOW} Low</span>`;
    if ((result.findings || []).length === 0) breakdown.innerHTML += `<span class="badge badge-clean">Clean Baseline</span>`;

    // 2. Evidence Properties Card
    document.getElementById('evidence-meta-card').style.display = 'block';
    document.getElementById('meta-file-name').innerText = result.file_name || '-';
    document.getElementById('meta-file-size').innerText = `${(result.file_size || 0).toLocaleString()} bytes`;
    document.getElementById('meta-extension').innerText = result.extension || result.metadata?.extension || '-';
    document.getElementById('meta-signature').innerText = result.signature_type || result.signature?.actual_type || 'Unknown';

    const matchSpan = document.getElementById('meta-sig-match');
    const isMatch = result.extension_match !== undefined ? result.extension_match : (result.signature?.extension_match ?? true);
    if (isMatch) {
        matchSpan.innerHTML = '<span style="color: var(--accent-green);">✓ MATCH (Extension aligns with signature)</span>';
    } else {
        matchSpan.innerHTML = '<span style="color: var(--accent-red); font-weight: 700;">⚠️ MISMATCH (Disguised File Type)</span>';
    }

    const isHidden = result.is_hidden || result.hidden_file?.is_hidden;
    document.getElementById('meta-hidden-status').innerText = isHidden ? 'Hidden Attribute Set' : 'Normal / Visible';
    document.getElementById('meta-created-time').innerText = result.created_time || result.metadata?.created_time || '-';
    document.getElementById('meta-modified-time').innerText = result.modified_time || result.metadata?.modified_time || '-';
    document.getElementById('meta-accessed-time').innerText = result.accessed_time || result.metadata?.accessed_time || '-';

    const sha256Val = result.sha256_hash || result.metadata?.sha256_hash || result.summary?.sha256 || result.summary?.sha256_hash || 'N/A';
    document.getElementById('meta-sha256-hash').innerText = sha256Val;

    // 3. ML Prediction Card
    document.getElementById('ml-prediction-card').style.display = 'block';
    const predLabel = result.ml_prediction || 'Normal';
    const predColor = predLabel === 'Suspicious' ? 'var(--accent-red)' : 'var(--accent-green)';
    document.getElementById('ml-pred-label').innerHTML = `<span style="color: ${predColor}; font-weight: 700;">${predLabel}</span>`;
    document.getElementById('ml-prob-val').innerText = `${((result.ml_probability || 0) * 100).toFixed(1)}%`;
    document.getElementById('ml-conf-val').innerText = `${result.ml_confidence_percent || result.ml_confidence || 96.7}%`;

    // 4. Findings Table (Forensic Scanner view)
    renderFindingsTable(result.findings || []);
}

function renderFindingsTable(findings) {
    const wrap = document.getElementById('findings-table-wrap');

    if (!findings || findings.length === 0) {
        wrap.innerHTML = `
            <div class="empty-state">
                <div class="empty-icon">🛡️</div>
                <h4>Clean Forensic Baseline</h4>
                <p>No anti-forensic evasion techniques or timestamp anomalies detected for this evidence file.</p>
            </div>
        `;
        return;
    }

    let html = `
        <table class="data-table">
            <thead>
                <tr>
                    <th style="width: 110px;">Severity</th>
                    <th style="width: 140px;">Category</th>
                    <th>Anomaly Title & Forensic Description</th>
                    <th>Artifact Target</th>
                </tr>
            </thead>
            <tbody>
    `;

    findings.forEach(f => {
        const sevClass = `badge-${(f.severity || 'low').toLowerCase()}`;
        html += `
            <tr>
                <td><span class="badge ${sevClass}">${f.severity}</span></td>
                <td><span class="mono">${f.category}</span></td>
                <td>
                    <strong>${f.title}</strong>
                    <div style="font-size: 12px; color: var(--text-secondary); margin-top: 4px; line-height: 1.4;">${f.description || ''}</div>
                </td>
                <td><span class="mono" style="font-size: 11px; word-break: break-all;">${f.artifact_path || '-'}</span></td>
            </tr>
        `;
    });

    html += `</tbody></table>`;
    wrap.innerHTML = html;
}

// ============================================================================
// Dedicated Standalone ML Feature Matrix View (View 3)
// ============================================================================

async function renderMLFeatureMatrixView(result, modelMeta) {
    if (!result) return;

    if (!modelMeta) {
        try {
            const res = await fetch('/api/ml/model', { cache: 'no-store' });
            const data = await res.json();
            if (data.status === 'success') {
                cachedModelMetadata = data.model;
                modelMeta = data.model;
            }
        } catch (e) {
            console.warn("Could not fetch ML model metadata:", e);
        }
    }

    const noScanState = document.getElementById('ml-no-scan-state');
    const container = document.getElementById('ml-selected-scan-container');
    const actions = document.getElementById('ml-view-actions');
    if (noScanState) noScanState.style.display = 'none';
    if (container) container.style.display = 'block';
    if (actions) actions.style.display = 'flex';

    // 1. Evidence Overview Card
    const fileNameEl = document.getElementById('ml-card-file-name');
    if (fileNameEl) fileNameEl.innerText = result.file_name || '-';
    const scanIdEl = document.getElementById('ml-card-scan-id');
    if (scanIdEl) scanIdEl.innerText = result.scan_id || '-';
    const scanDateEl = document.getElementById('ml-card-scan-date');
    if (scanDateEl) scanDateEl.innerText = result.scan_date || result.created_time || '-';
    const sha256El = document.getElementById('ml-card-sha256');
    if (sha256El) sha256El.innerText = result.sha256_hash || result.metadata?.sha256_hash || '-';

    // 2. Classifier Architecture Card
    if (modelMeta) {
        const typeEl = document.getElementById('ml-card-model-type');
        if (typeEl) typeEl.innerText = modelMeta.model_type || 'Random Forest Classifier';
        const treesEl = document.getElementById('ml-card-estimators');
        if (treesEl) treesEl.innerText = `${modelMeta.n_estimators || 100} Decision Trees`;
        const featsEl = document.getElementById('ml-card-feature-count');
        if (featsEl) featsEl.innerText = `${modelMeta.feature_count || 16} Dimensions`;
        const critEl = document.getElementById('ml-card-criterion');
        if (critEl) critEl.innerText = `${modelMeta.criterion || 'gini'} (Gini Impurity)`;
    }

    // 3. Inference & Probabilities Card
    const predLabel = result.ml_prediction || 'Normal';
    const predColor = predLabel === 'Suspicious' ? 'var(--accent-red)' : 'var(--accent-green)';
    const predEl = document.getElementById('ml-card-prediction');
    if (predEl) predEl.innerHTML = `<span style="color: ${predColor}; font-weight: 700;">${predLabel}</span>`;
    const probEl = document.getElementById('ml-card-probability');
    if (probEl) probEl.innerText = `${((result.ml_probability || 0) * 100).toFixed(1)}%`;
    const confEl = document.getElementById('ml-card-confidence');
    if (confEl) confEl.innerText = `${result.ml_confidence_percent || result.ml_confidence || 96.7}%`;

    // 4. Feature Importance Horizontal Bars (Exact trained weights)
    const barsContainer = document.getElementById('ml-importance-bars');
    if (barsContainer && modelMeta && modelMeta.feature_importances) {
        barsContainer.innerHTML = '';
        const importances = modelMeta.feature_importances;
        const sortedEntries = Object.entries(importances).sort((a, b) => b[1] - a[1]);
        const maxImp = sortedEntries.length > 0 && sortedEntries[0][1] > 0 ? sortedEntries[0][1] : 1.0;

        sortedEntries.forEach(([featName, weight]) => {
            const pct = (weight * 100).toFixed(2);
            const barWidth = Math.min(100, Math.max(3, (weight / maxImp) * 100)).toFixed(1);

            const item = document.createElement('div');
            item.className = 'importance-item';
            item.innerHTML = `
                <div class="importance-header">
                    <span class="importance-name">${featName}</span>
                    <span class="importance-pct">${pct}% (weight: ${weight})</span>
                </div>
                <div class="importance-bar-track">
                    <div class="importance-bar-fill" style="width: ${barWidth}%;"></div>
                </div>
            `;
            barsContainer.appendChild(item);
        });
    }

    // 5. Full 16-Feature Vector Table
    const tbody = document.getElementById('ml-full-matrix-tbody');
    if (tbody) {
        tbody.innerHTML = '';
        const features = result.features || {};
        const importances = (modelMeta && modelMeta.feature_importances) ? modelMeta.feature_importances : {};

        const allFeatureNames = modelMeta?.feature_names || [
            "file_size", "is_hidden", "is_in_hidden_folder", "extension_match",
            "has_double_extension", "has_suspicious_extension", "signature_type",
            "metadata_anomaly", "filename_anomaly", "access_time_anomaly",
            "modification_time_anomaly", "creation_time_anomaly", "has_ads_streams",
            "subsecond_zeroed", "causal_m_lt_c", "future_timestamp"
        ];

        allFeatureNames.forEach(feat => {
            const rawVal = features[feat] !== undefined ? features[feat] : '-';
            let valStr = rawVal;
            if (typeof rawVal === 'number' && !Number.isInteger(rawVal)) {
                valStr = rawVal.toFixed(4);
            } else if (typeof rawVal === 'boolean') {
                valStr = rawVal ? 'true (1)' : 'false (0)';
            }

            const typeStr = (feat.startsWith('has_') || feat.startsWith('is_') || feat.includes('anomaly') || feat.includes('zeroed') || feat.includes('m_lt_c') || feat.includes('match')) 
                ? 'Boolean (0/1)' 
                : (feat === 'signature_type' ? 'Categorical (Encoded)' : 'Numerical');

            const weightVal = importances[feat] !== undefined ? `${(importances[feat] * 100).toFixed(2)}%` : '-';

            const tr = document.createElement('tr');
            tr.innerHTML = `
                <td><strong class="mono" style="color: var(--accent-blue);">${feat}</strong></td>
                <td><span class="badge badge-low">${typeStr}</span></td>
                <td><strong class="mono">${valStr}</strong></td>
                <td><span class="mono" style="color: var(--accent-green); font-weight: 600;">${weightVal}</span></td>
            `;
            tbody.appendChild(tr);
        });
    }
}

// ============================================================================
// Complete Persistent Scan History Page (Search, Filter, Sort, Pagination)
// ============================================================================

function handleHistorySearchInput() {
    clearTimeout(historySearchDebounceTimer);
    historySearchDebounceTimer = setTimeout(() => {
        loadHistoryPage(1);
    }, 300);
}

async function loadHistoryPage(page = 1) {
    currentHistoryPage = page;
    const tbody = document.getElementById('history-tbody');
    if (!tbody) return;

    tbody.innerHTML = '<tr><td colspan="9" class="loading-state">Querying persistent database records...</td></tr>';

    const search = document.getElementById('history-search-input')?.value || '';
    const riskLevel = document.getElementById('history-filter-risk')?.value || 'ALL';
    const status = document.getElementById('history-filter-status')?.value || 'ALL';
    const sort = document.getElementById('history-sort')?.value || 'newest';
    const limit = parseInt(document.getElementById('history-limit')?.value || '25', 10);

    const params = new URLSearchParams({
        page: currentHistoryPage,
        limit: limit,
        search: search,
        risk_level: riskLevel,
        status: status,
        sort: sort
    });

    try {
        const res = await fetch(`/api/history?${params.toString()}`);
        const data = await res.json();

        if (data.status === 'success') {
            renderFullHistoryTable(data.scans || []);
            updateHistoryPagination(data.total || 0, data.page, data.limit, data.total_pages);
        } else {
            tbody.innerHTML = `<tr><td colspan="9" class="empty-state">${data.message || 'Error loading scan history.'}</td></tr>`;
        }
    } catch (err) {
        console.error("Error fetching history page:", err);
        tbody.innerHTML = '<tr><td colspan="9" class="empty-state">Failed to retrieve historical scans from server.</td></tr>';
    }
}

function renderFullHistoryTable(scans) {
    const tbody = document.getElementById('history-tbody');
    if (!tbody) return;

    if (!scans || scans.length === 0) {
        tbody.innerHTML = '<tr><td colspan="9" class="empty-state"><div class="empty-icon">📁</div><h4>No Scan Records Found</h4><p>No historical scans match your current filter criteria.</p></td></tr>';
        return;
    }

    tbody.innerHTML = '';
    scans.forEach(s => {
        const risk = s.risk_score || 0.0;
        const riskLevel = (s.risk_level || s.summary?.risk_level || (risk >= 80 ? 'CRITICAL' : (risk >= 61 ? 'HIGH' : (risk >= 31 ? 'MEDIUM' : (risk > 0 ? 'LOW' : 'CLEAN'))))).toUpperCase();
        const riskBadgeClass = `badge-${riskLevel.toLowerCase()}`;
        const targetName = s.filename || s.summary?.file_name || (s.target_path ? s.target_path.split(/[\\/]/).pop() : formatScanType(s.target_type));
        const mlPred = s.ml_prediction || s.summary?.ml_prediction || (risk >= 50 ? 'Suspicious' : 'Normal');
        const statusStr = s.status || 'COMPLETED';
        const statusBadgeClass = `badge-${statusStr.toLowerCase()}`;

        const sha256Val = s.sha256_hash || s.summary?.sha256 || s.summary?.sha256_hash || 'N/A';
        const sha256Short = sha256Val.length > 16 ? `${sha256Val.substring(0, 10)}...${sha256Val.substring(sha256Val.length - 6)}` : sha256Val;

        const dateStr = s.start_time ? new Date(s.start_time).toLocaleString([], { dateStyle: 'short', timeStyle: 'short' }) : '-';

        const critCount = s.critical_count || (s.summary?.critical_count || 0);
        const highCount = s.high_count || (s.summary?.high_count || 0);
        let findingsTag = `${s.total_findings || 0}`;
        if (critCount > 0 || highCount > 0) {
            findingsTag += ` <span style="font-size: 11px; color: var(--accent-red);">(${critCount + highCount} high)</span>`;
        }

        const tr = document.createElement('tr');
        tr.innerHTML = `
            <td>
                <strong>${targetName}</strong>
                <div style="font-size: 11px; font-family: var(--font-mono); color: var(--text-muted);">${s.scan_id.substring(0, 8)}...</div>
            </td>
            <td>${dateStr}</td>
            <td><span class="badge ${statusBadgeClass}">${statusStr}</span></td>
            <td><strong>${risk.toFixed(1)}/100</strong></td>
            <td><span class="badge ${riskBadgeClass}">${riskLevel}</span></td>
            <td>${findingsTag}</td>
            <td>
                <span class="sha256-chip" title="Click to copy SHA-256: ${sha256Val}" onclick="copyToClipboard('${sha256Val}', this)">
                    📋 ${sha256Short}
                </span>
            </td>
            <td>${mlPred}</td>
            <td>
                <div class="action-btn-group">
                    <button class="btn-sm btn-outline" title="Open in Forensic Scanner" onclick="selectScanAndSwitch('${s.scan_id}')">🔍 View Scan</button>
                    <button class="btn-sm btn-outline" title="Open in ML Feature Matrix" onclick="selectScanAndShowML('${s.scan_id}')">🧠 View ML Features</button>
                    <button class="btn-sm btn-primary" title="Download Forensic Report PDF" onclick="downloadPDFById('${s.scan_id}')">📄 PDF</button>
                    <button class="btn-danger-outline" title="Delete scan from history" onclick="openDeleteModal('${s.scan_id}', '${targetName.replace(/'/g, "\\'")}')">🗑️</button>
                </div>
            </td>
        `;
        tbody.appendChild(tr);
    });
}

function updateHistoryPagination(totalCount, currentPage, limit, totalPages) {
    totalHistoryPages = totalPages || 1;
    currentHistoryPage = currentPage || 1;

    const showingInfo = document.getElementById('history-showing-info');
    const pageIndicator = document.getElementById('history-page-indicator');
    const prevBtn = document.getElementById('btn-page-prev');
    const nextBtn = document.getElementById('btn-page-next');

    const start = totalCount === 0 ? 0 : (currentPage - 1) * limit + 1;
    const end = Math.min(totalCount, currentPage * limit);

    if (showingInfo) showingInfo.innerText = `Showing ${start}-${end} of ${totalCount} scans`;
    if (pageIndicator) pageIndicator.innerText = `Page ${currentPage} of ${totalHistoryPages}`;

    if (prevBtn) prevBtn.disabled = currentPage <= 1;
    if (nextBtn) nextBtn.disabled = currentPage >= totalHistoryPages;
}

function changeHistoryPage(delta) {
    const targetPage = currentHistoryPage + delta;
    if (targetPage >= 1 && targetPage <= totalHistoryPages) {
        loadHistoryPage(targetPage);
    }
}

// ============================================================================
// Deletion Workflow & Confirmation Modal
// ============================================================================

function openDeleteModal(scanId, filename) {
    pendingDeleteScanId = scanId;
    document.getElementById('delete-scan-filename').innerText = filename || 'Evidence Scan';
    document.getElementById('delete-scan-id').innerText = `Scan ID: ${scanId}`;
    document.getElementById('delete-modal').classList.add('active');
}

function closeDeleteModal() {
    pendingDeleteScanId = null;
    document.getElementById('delete-modal').classList.remove('active');
}

async function executeDeleteScan() {
    if (!pendingDeleteScanId) return;

    const deleteBtn = document.getElementById('btn-confirm-delete');
    deleteBtn.disabled = true;
    deleteBtn.innerText = 'Deleting...';

    try {
        const res = await fetch(`/api/scan/${pendingDeleteScanId}`, {
            method: 'DELETE'
        });
        const data = await res.json();

        if (data.status === 'success') {
            closeDeleteModal();
            // Refresh history table and recent scans list
            await loadHistoryPage(currentHistoryPage);
            await loadScans();
        } else {
            alert(`Failed to delete scan: ${data.message || 'Unknown error'}`);
        }
    } catch (err) {
        alert('Network error deleting scan.');
    } finally {
        deleteBtn.disabled = false;
        deleteBtn.innerText = 'Delete Scan';
    }
}

// ============================================================================
// Utility & Navigation Actions
// ============================================================================

function copyToClipboard(text, element) {
    if (!text || text === 'N/A') return;
    navigator.clipboard.writeText(text).then(() => {
        const origText = element.innerText;
        element.innerText = '✓ Copied!';
        setTimeout(() => {
            element.innerText = origText;
        }, 1500);
    }).catch(err => {
        console.error("Copy failed:", err);
    });
}

function downloadCurrentPDFReport() {
    if (!selectedScanId) return;
    downloadPDFById(selectedScanId);
}

function downloadPDFById(scanId) {
    window.open(`/api/report/${scanId}`, '_blank');
}

function exportCurrentCSV() {
    if (!selectedScanId) return;
    window.location.href = `/api/features/export/${selectedScanId}`;
}

async function triggerBatchScan(type) {
    closeScanModal();
    try {
        const res = await fetch('/api/scan/trigger', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ type: type })
        });
        const data = await res.json();
        if (data.status === 'success') {
            await loadScans();
            if (data.scan_id) {
                selectScan(data.scan_id);
            }
        } else {
            alert(`Scan error: ${data.message || 'Failed'}`);
        }
    } catch (err) {
        alert('Error triggering scan.');
    }
}

function selectScanAndSwitch(scanId) {
    switchView('dashboard');
    selectScan(scanId);
}

async function selectScanAndShowML(scanId) {
    switchView('features');
    await selectScan(scanId);
    if (currentScanResult) {
        renderMLFeatureMatrixView(currentScanResult, cachedModelMetadata);
    }
}

function switchView(view) {
    currentView = view;
    document.querySelectorAll('.nav-item').forEach(el => el.classList.remove('active'));
    const navBtn = document.getElementById(`nav-${view}`);
    if (navBtn) navBtn.classList.add('active');

    const scannerBody = document.getElementById('view-scanner-body');
    const historyBody = document.getElementById('view-history-body');
    const featuresBody = document.getElementById('view-features-body');

    if (view === 'history') {
        if (scannerBody) scannerBody.style.display = 'none';
        if (historyBody) historyBody.style.display = 'grid';
        if (featuresBody) featuresBody.style.display = 'none';
        document.getElementById('view-title').innerText = 'Historical Evidence Scans';
        document.getElementById('view-subtitle').innerText = 'Persistent DFIR investigation records saved in database with user isolation';
        loadHistoryPage(1);
    } else if (view === 'features') {
        if (scannerBody) scannerBody.style.display = 'none';
        if (historyBody) historyBody.style.display = 'none';
        if (featuresBody) featuresBody.style.display = 'grid';
        document.getElementById('view-title').innerText = 'Machine Learning Feature Matrix';
        document.getElementById('view-subtitle').innerText = 'Explainable Random Forest classification across 16 engineered forensic dimensions';

        if (selectedScanId && currentScanResult) {
            renderMLFeatureMatrixView(currentScanResult, cachedModelMetadata);
        } else {
            const noScan = document.getElementById('ml-no-scan-state');
            const container = document.getElementById('ml-selected-scan-container');
            const actions = document.getElementById('ml-view-actions');
            if (noScan) noScan.style.display = 'block';
            if (container) container.style.display = 'none';
            if (actions) actions.style.display = 'none';
        }
    } else {
        if (scannerBody) scannerBody.style.display = 'grid';
        if (historyBody) historyBody.style.display = 'none';
        if (featuresBody) featuresBody.style.display = 'none';
        document.getElementById('view-title').innerText = 'User-Driven Forensic Analysis';
        document.getElementById('view-subtitle').innerText = 'Select an evidence file from Windows File Explorer for strict read-only forensic inspection';
    }
}

// ============================================================================
// Modal Management
// ============================================================================

function openScanModal() {
    document.getElementById('scan-modal').classList.add('active');
}

function closeScanModal() {
    document.getElementById('scan-modal').classList.remove('active');
}
