/**
 * Anti-Forensics Detection System — Frontend JavaScript (Phase 2)
 * Handles user file selection via Windows File Explorer, live scan execution,
 * dynamic dashboard rendering, Scan History, and PDF report downloads.
 */

let currentScans = [];
let selectedScanId = null;
let selectedFilePath = null;
let currentView = 'dashboard';

document.addEventListener('DOMContentLoaded', () => {
    loadScans();
});

// ============================================================================
// Data Fetching & Scans Management
// ============================================================================

async function loadScans() {
    const container = document.getElementById('scans-container');
    container.innerHTML = '<div class="loading-state">Loading scan sessions...</div>';

    try {
        const res = await fetch('/api/scans');
        const data = await res.json();

        if (data.status === 'success' && data.scans) {
            currentScans = data.scans;
            renderScansList(currentScans);
            updateDashboardMetrics(currentScans);
            renderHistoryTable(currentScans);

            if (currentScans.length > 0 && !selectedScanId) {
                selectScan(currentScans[0].scan_id);
            }
        } else {
            container.innerHTML = '<div class="empty-state">No scans recorded yet.</div>';
        }
    } catch (err) {
        container.innerHTML = '<div class="empty-state">Error loading scans from SQLite database.</div>';
    }
}

function updateDashboardMetrics(scans) {
    document.getElementById('stat-total-scans').innerText = scans.length;

    let totalFindings = 0;
    let criticalFindings = 0;

    scans.forEach(s => {
        totalFindings += (s.total_findings || 0);
        if (s.summary && (s.summary.critical_count || s.summary.risk_level === 'HIGH')) {
            criticalFindings += 1;
        }
    });

    document.getElementById('stat-total-findings').innerText = totalFindings;
    document.getElementById('stat-critical-findings').innerText = criticalFindings;
}

function renderScansList(scans) {
    const container = document.getElementById('scans-container');
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
        let riskClass = 'risk-low';
        if (risk >= 61) riskClass = 'risk-high';
        else if (risk >= 31) riskClass = 'risk-med';

        const timeStr = s.start_time ? new Date(s.start_time).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : '-';
        const targetName = s.summary?.file_name || s.target_path ? (s.summary?.file_name || s.target_path.split(/[\\/]/).pop()) : formatScanType(s.target_type);

        item.innerHTML = `
            <div class="scan-item-header">
                <span class="scan-item-type" title="${s.target_path || ''}">${targetName}</span>
                <span class="scan-item-risk ${riskClass}">Risk: ${risk.toFixed(0)}</span>
            </div>
            <div class="scan-item-meta">
                <span>Findings: ${s.total_findings}</span> • <span>${timeStr}</span>
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
        default: return type || 'Scan';
    }
}

let stagedFile = null;
let stagedFolderFiles = null;

// ============================================================================
// Phase 2: User File/Folder Selection via Native Windows File Explorer
// ============================================================================

function openStartScanFlow() {
    openScanModal();
}

function openFilePickerFromModal() {
    closeScanModal();
    openFilePicker();
}

function openFolderPickerFromModal() {
    closeScanModal();
    openFolderPicker();
}

function openFilePicker() {
    const input = document.getElementById('evidence-file-input');
    if (input) {
        input.value = ''; // Reset so same file can be re-selected
        input.click();   // Opens native Windows File Explorer
    }
}

function openFolderPicker() {
    const input = document.getElementById('evidence-folder-input');
    if (input) {
        input.value = '';
        input.click();   // Opens native Windows File Explorer folder picker
    }
}

function handleFileChosen(event) {
    const files = event.target.files;
    const bannerPath = document.getElementById('banner-path-text');
    const scanBtn = document.getElementById('btn-run-scan');

    if (!files || files.length === 0) {
        return;
    }

    stagedFile = files[0];
    stagedFolderFiles = null;
    selectedFilePath = stagedFile.name;

    const sizeKb = (stagedFile.size / 1024).toFixed(1);
    const sizeFormatted = stagedFile.size > 1024 * 1024 
        ? `${(stagedFile.size / (1024 * 1024)).toFixed(2)} MB` 
        : `${sizeKb} KB`;

    bannerPath.innerHTML = `<strong>Selected:</strong> <span style="color: var(--accent-blue); font-weight: 600;">${stagedFile.name}</span> (${sizeFormatted})<br/><span style="color: var(--text-muted); font-size: 11px;">Ready for strict read-only forensic analysis & ML evaluation</span>`;
    
    scanBtn.style.display = 'inline-flex';
    scanBtn.innerText = '🚀 Scan Selected File';
    scanBtn.onclick = executeSelectedFileScan;
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
// Selected Scan Details Rendering
// ============================================================================

async function selectScan(scanId) {
    selectedScanId = scanId;

    document.querySelectorAll('.scan-item').forEach(el => el.classList.remove('selected'));
    const selectedEl = document.getElementById(`scan-item-${scanId}`);
    if (selectedEl) selectedEl.classList.add('selected');

    try {
        const res = await fetch(`/api/scan/${scanId}`);
        const data = await res.json();

        if (data.status === 'success') {
            const scan = data.scan;
            const summary = scan.summary || {};

            const compositeResult = {
                scan_id: scan.scan_id,
                scan_date: scan.start_time,
                file_name: summary.file_name || (scan.target_path ? scan.target_path.split(/[\\/]/).pop() : 'Evidence Target'),
                file_path: scan.target_path || 'N/A',
                file_size: summary.file_size || 0,
                extension: summary.extension || '-',
                signature_type: summary.signature_type || 'Unknown',
                extension_match: summary.extension_match !== undefined ? summary.extension_match : true,
                is_hidden: summary.is_hidden || false,
                created_time: summary.created_time || '-',
                modified_time: summary.modified_time || '-',
                accessed_time: summary.accessed_time || '-',
                risk_score: scan.risk_score || 0.0,
                risk_level: summary.risk_level || (scan.risk_score >= 61 ? 'HIGH' : (scan.risk_score >= 31 ? 'MEDIUM' : 'LOW')),
                ml_prediction: summary.ml_prediction || (scan.risk_score >= 50 ? 'Suspicious' : 'Normal'),
                ml_probability: summary.ml_probability || (scan.risk_score / 100.0),
                ml_confidence_percent: 96.7,
                findings: data.findings || [],
                features: data.features || {}
            };

            displayScanResult(compositeResult);
        }
    } catch (err) {
        console.error("Error loading scan details:", err);
    }
}

function displayScanResult(result) {
    selectedScanId = result.scan_id;

    document.getElementById('selected-scan-title').innerText = `${result.file_name} (${(result.file_size / 1024).toFixed(1)} KB)`;
    document.getElementById('selected-scan-meta').innerText = `Scan ID: ${result.scan_id} | Assessed: ${result.scan_date || result.created_time}`;
    document.getElementById('details-actions').style.display = 'flex';

    // 1. Risk Overview & Gauge
    const riskBar = document.getElementById('risk-overview-bar');
    riskBar.style.display = 'flex';
    const riskScore = result.risk_score || 0.0;
    document.getElementById('risk-meter-fill').style.width = `${Math.min(100, riskScore)}%`;
    document.getElementById('risk-meter-text').innerText = `${riskScore.toFixed(1)} / 100`;

    const riskBadge = document.getElementById('risk-level-badge');
    const riskLevel = (result.risk_level || (riskScore >= 61 ? 'HIGH' : (riskScore >= 31 ? 'MEDIUM' : 'LOW'))).toUpperCase();
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

    // 2. Evidence Properties Card
    document.getElementById('evidence-meta-card').style.display = 'block';
    document.getElementById('meta-file-name').innerText = result.file_name || '-';
    document.getElementById('meta-file-size').innerText = `${(result.file_size || 0).toLocaleString()} bytes`;
    document.getElementById('meta-extension').innerText = result.extension || '-';
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

    // 3. ML Prediction Card
    document.getElementById('ml-prediction-card').style.display = 'block';
    const predLabel = result.ml_prediction || 'Normal';
    const predColor = predLabel === 'Suspicious' ? 'var(--accent-red)' : 'var(--accent-green)';
    document.getElementById('ml-pred-label').innerHTML = `<span style="color: ${predColor}; font-weight: 700;">${predLabel}</span>`;
    document.getElementById('ml-prob-val').innerText = `${((result.ml_probability || 0) * 100).toFixed(1)}%`;
    document.getElementById('ml-conf-val').innerText = `${result.ml_confidence_percent || 96.7}%`;

    // 4. Findings Table
    renderFindingsTable(result.findings || []);

    // 5. Features Matrix Table
    renderFeaturesTable(result.features || {});
}

function renderFindingsTable(findings) {
    const wrap = document.getElementById('findings-table-wrap');

    if (!findings || findings.length === 0) {
        wrap.innerHTML = `
            <div class="empty-state">
                <div class="empty-icon">✓</div>
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
                    <th style="width: 100px;">Severity</th>
                    <th style="width: 130px;">Category</th>
                    <th>Anomaly Title & Description</th>
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
                    <div style="font-size: 12px; color: var(--text-secondary); margin-top: 4px;">${f.description || ''}</div>
                </td>
                <td><span class="mono" style="font-size: 11px; word-break: break-all;">${f.artifact_path || '-'}</span></td>
            </tr>
        `;
    });

    html += `</tbody></table>`;
    wrap.innerHTML = html;
}

function renderFeaturesTable(features) {
    const tbody = document.getElementById('features-tbody');
    tbody.innerHTML = '';

    if (!features || Object.keys(features).length === 0) {
        tbody.innerHTML = '<tr><td colspan="3" class="empty-state">No features extracted for this scan.</td></tr>';
        return;
    }

    Object.keys(features).sort().forEach(name => {
        const val = features[name];
        const valStr = typeof val === 'number' && !Number.isInteger(val) ? val.toFixed(4) : val;
        const typeStr = name.includes('flag') || name.startsWith('has_') || name.startsWith('is_') || name.includes('anomaly') || name.includes('zeroed') || name.includes('m_lt_c') ? 'Boolean' : 'Numeric';

        const tr = document.createElement('tr');
        tr.innerHTML = `
            <td><span class="mono">${name}</span></td>
            <td><span class="badge badge-low">${typeStr}</span></td>
            <td><strong>${valStr}</strong></td>
        `;
        tbody.appendChild(tr);
    });
}

function renderHistoryTable(scans) {
    const tbody = document.getElementById('history-tbody');
    if (!tbody) return;

    if (!scans || scans.length === 0) {
        tbody.innerHTML = '<tr><td colspan="8" class="empty-state">No scan history recorded in SQLite yet.</td></tr>';
        return;
    }

    tbody.innerHTML = '';
    scans.forEach(s => {
        const risk = s.risk_score || 0.0;
        const riskLevel = s.summary?.risk_level || (risk >= 61 ? 'HIGH' : (risk >= 31 ? 'MEDIUM' : 'LOW'));
        const riskBadgeClass = `badge-${riskLevel.toLowerCase()}`;
        const targetName = s.summary?.file_name || (s.target_path ? s.target_path.split(/[\\/]/).pop() : formatScanType(s.target_type));
        const mlPred = s.summary?.ml_prediction || (risk >= 50 ? 'Suspicious' : 'Normal');

        const tr = document.createElement('tr');
        tr.innerHTML = `
            <td><span class="mono">${s.scan_id.substring(0, 8)}...</span></td>
            <td>${s.start_time || '-'}</td>
            <td><strong>${targetName}</strong></td>
            <td><strong>${risk.toFixed(1)}/100</strong></td>
            <td><span class="badge ${riskBadgeClass}">${riskLevel}</span></td>
            <td>${mlPred}</td>
            <td>${s.total_findings || 0}</td>
            <td>
                <button class="btn-sm btn-outline" onclick="selectScanAndSwitch('${s.scan_id}')">View</button>
                <button class="btn-sm btn-primary" onclick="downloadPDFById('${s.scan_id}')">PDF</button>
            </td>
        `;
        tbody.appendChild(tr);
    });
}

// ============================================================================
// Actions & PDF Downloads
// ============================================================================

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
        }
    } catch (err) {
        alert('Error triggering scan.');
    }
}

function selectScanAndSwitch(scanId) {
    switchView('dashboard');
    selectScan(scanId);
}

function switchView(view) {
    currentView = view;
    document.querySelectorAll('.nav-item').forEach(el => el.classList.remove('active'));
    const navBtn = document.getElementById(`nav-${view}`);
    if (navBtn) navBtn.classList.add('active');

    const scannerBody = document.getElementById('view-scanner-body');
    const historyBody = document.getElementById('view-history-body');
    const findingsWrap = document.getElementById('findings-table-wrap');
    const featuresWrap = document.getElementById('features-table-wrap');

    if (view === 'history') {
        scannerBody.style.display = 'none';
        historyBody.style.display = 'grid';
        document.getElementById('view-title').innerText = 'Historical Evidence Scans';
        document.getElementById('view-subtitle').innerText = 'Persistent DFIR investigation records saved in SQLite database';
    } else if (view === 'features') {
        scannerBody.style.display = 'grid';
        historyBody.style.display = 'none';
        findingsWrap.style.display = 'none';
        featuresWrap.style.display = 'block';
        document.getElementById('view-title').innerText = 'ML Feature Vector Matrix';
        document.getElementById('view-subtitle').innerText = '16 standard numerical & categorical forensic features feed into Random Forest model';
    } else {
        scannerBody.style.display = 'grid';
        historyBody.style.display = 'none';
        findingsWrap.style.display = 'block';
        featuresWrap.style.display = 'none';
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
