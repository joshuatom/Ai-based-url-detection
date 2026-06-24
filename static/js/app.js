document.addEventListener('DOMContentLoaded', () => {
    // Initialize Lucide Icons
    lucide.createIcons();

    // DOM Elements
    const scanForm = document.getElementById('scan-form');
    const urlInput = document.getElementById('url-input');
    const btnScan = document.getElementById('btn-scan');
    const scanLoader = document.getElementById('scan-loader');
    
    const resultsPlaceholder = document.getElementById('results-placeholder');
    const resultsPanel = document.getElementById('results-panel');
    
    const riskPercentage = document.getElementById('risk-percentage');
    const gaugeProgress = document.getElementById('gauge-progress');
    const verdictTitle = document.getElementById('verdict-title');
    const verdictDescription = document.getElementById('verdict-description');
    const modelConfidence = document.getElementById('model-confidence');
    const inferenceTime = document.getElementById('inference-time');
    
    const featuresBreakdown = document.getElementById('features-breakdown');
    const historyList = document.getElementById('history-list');
    const clearHistoryBtn = document.getElementById('clear-history');

    // Playground DOM Elements
    const pgIsHttps = document.getElementById('pg-is_https');
    const pgHaveIp = document.getElementById('pg-have_ip');
    const pgHaveAt = document.getElementById('pg-have_at');
    const pgPrefixSuffix = document.getElementById('pg-prefix_suffix');
    const pgShorteningService = document.getElementById('pg-shortening_service');
    const pgSuspiciousWords = document.getElementById('pg-suspicious_words');
    
    const pgUrlLength = document.getElementById('pg-url_length');
    const pgHostnameLength = document.getElementById('pg-hostname_length');
    const pgNbDots = document.getElementById('pg-nb_dots');
    const pgNbSlashes = document.getElementById('pg-nb_slashes');
    const pgNbDigits = document.getElementById('pg-nb_digits');
    
    const valUrlLength = document.getElementById('val-url_length');
    const valHostnameLength = document.getElementById('val-hostname_length');
    const valNbDots = document.getElementById('val-nb_dots');
    const valNbSlashes = document.getElementById('val-nb_slashes');
    const valNbDigits = document.getElementById('val-nb_digits');

    // Hidden playground elements for complete feature set
    const pgNbHyphens = document.getElementById('pg-nb_hyphens');
    const pgNbQuestion = document.getElementById('pg-nb_question');
    const pgNbEqual = document.getElementById('pg-nb_equal');
    const pgNbLetters = document.getElementById('pg-nb_letters');

    const pgRiskPercentage = document.getElementById('pg-risk-percentage');
    const pgGaugeProgress = document.getElementById('pg-gauge-progress');
    const pgRiskBadge = document.getElementById('pg-risk-badge');
    const playgroundLayout = document.querySelector('.playground-layout');

    // Constants
    const GAUGE_CIRCUMFERENCE = 263.89; // 2 * Math.PI * 42

    // Initialize scan history
    let scanHistory = JSON.parse(localStorage.getItem('phish_history')) || [];
    renderHistory();

    /* ----------------------------------------------------
       Event Listeners
    ---------------------------------------------------- */
    scanForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const url = urlInput.value.trim();
        if (!url) return;
        
        await analyzeURL(url);
    });

    clearHistoryBtn.addEventListener('click', () => {
        scanHistory = [];
        localStorage.removeItem('phish_history');
        renderHistory();
    });

    // Wire up slider displays
    const sliders = [
        { el: pgUrlLength, display: valUrlLength },
        { el: pgHostnameLength, display: valHostnameLength },
        { el: pgNbDots, display: valNbDots },
        { el: pgNbSlashes, display: valNbSlashes },
        { el: pgNbDigits, display: valNbDigits }
    ];

    sliders.forEach(slider => {
        slider.el.addEventListener('input', (e) => {
            slider.display.textContent = e.target.value;
            // Update letters count dynamically to keep features logically aligned
            if (slider.el === pgUrlLength || slider.el === pgNbDigits) {
                updateLettersCount();
            }
            triggerPlaygroundInference();
        });
    });

    // Wire up checkbox toggles
    const toggles = [pgIsHttps, pgHaveIp, pgHaveAt, pgPrefixSuffix, pgShorteningService, pgSuspiciousWords];
    toggles.forEach(toggle => {
        toggle.addEventListener('change', () => {
            // Logic correction: if have hyphen domain is checked, prefix_suffix should align hyphens count
            if (toggle === pgPrefixSuffix) {
                pgNbHyphens.value = pgPrefixSuffix.checked ? 1 : 0;
            }
            triggerPlaygroundInference();
        });
    });

    /* ----------------------------------------------------
       Core Scan Functions
    ---------------------------------------------------- */
    async function analyzeURL(url) {
        // UI Loading State
        btnScan.disabled = true;
        scanLoader.classList.remove('hidden');
        resultsPlaceholder.classList.remove('hidden');
        resultsPanel.classList.add('hidden');

        const startTime = performance.now();

        try {
            const response = await fetch('/api/analyze', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ url: url })
            });

            const data = await response.json();
            const elapsed = (performance.now() - startTime).toFixed(1);

            if (!response.ok) {
                alert(data.error || 'Server error occurred during scan.');
                return;
            }

            // Render Scan Results
            renderResults(data, elapsed);
            
            // Add to history
            addToHistory(url, data.risk_score, data.prediction);

        } catch (error) {
            console.error('Fetch error:', error);
            alert('Could not connect to analysis backend. Ensure Flask is running.');
        } finally {
            btnScan.disabled = false;
            scanLoader.classList.add('hidden');
        }
    }

    function renderResults(data, elapsed) {
        resultsPlaceholder.classList.add('hidden');
        resultsPanel.classList.remove('hidden');

        // Update Verdict Classes (Safe, Warning, Danger states)
        resultsPanel.className = 'results-panel'; // Reset
        const risk = data.risk_score;
        let verdict = 'SECURE';
        let desc = 'This URL displays normal structural and lexical characteristics. No significant phishing indicators detected.';
        let confidence = (100 - risk).toFixed(1) + '%';
        
        if (risk >= 70) {
            resultsPanel.classList.add('danger-state');
            verdict = 'DANGER: SUSPECTED PHISHING';
            desc = 'CRITICAL: This URL displays heavy patterns matching known phishing campaigns. Proceed with extreme caution and do not enter credentials.';
            confidence = risk.toFixed(1) + '%';
        } else if (risk >= 30) {
            resultsPanel.classList.add('warning-state');
            verdict = 'WARNING: SUSPICIOUS';
            desc = 'CAUTION: Features extract showing mild anomaly flags (e.g. suspicious words or missing HTTPS). Review features breakdown below.';
            confidence = Math.max(risk, 100 - risk).toFixed(1) + '%';
        } else {
            resultsPanel.classList.add('safe-state');
        }

        // Fill Gauges & Verdict Info
        riskPercentage.textContent = `${risk}%`;
        setGaugeProgress(gaugeProgress, risk);
        
        verdictTitle.textContent = verdict;
        verdictDescription.textContent = desc;
        modelConfidence.textContent = confidence;
        inferenceTime.textContent = `${elapsed}ms`;

        // Render Features Breakdown
        featuresBreakdown.innerHTML = '';
        data.analysis.forEach(item => {
            const row = document.createElement('div');
            row.className = `feature-analysis-item ${item.status}-item`;
            
            let iconName = 'shield-check';
            if (item.status === 'warning') iconName = 'alert-circle';
            if (item.status === 'critical') iconName = 'alert-triangle';

            row.innerHTML = `
                <div class="feature-status-icon">
                    <i data-lucide="${iconName}"></i>
                </div>
                <div class="feature-info">
                    <div class="feature-name-row">
                        <span class="feature-title">${item.name}</span>
                        <span class="feature-value">${item.value}</span>
                    </div>
                    <p class="feature-desc">${item.detail}</p>
                </div>
            `;
            featuresBreakdown.appendChild(row);
        });

        // Initialize Playground state from current URL features
        initPlayground(data.features, risk);
        
        // Re-trigger icon updates
        lucide.createIcons();
    }

    function setGaugeProgress(gaugeEl, percent) {
        const offset = GAUGE_CIRCUMFERENCE - (GAUGE_CIRCUMFERENCE * percent / 100);
        gaugeEl.style.strokeDashoffset = offset;
    }

    /* ----------------------------------------------------
       Model Playground Functions
    ---------------------------------------------------- */
    function initPlayground(features, risk) {
        // Set values for sliders/checkboxes
        pgIsHttps.checked = features.is_https === 1;
        pgHaveIp.checked = features.have_ip === 1;
        pgHaveAt.checked = features.have_at === 1;
        pgPrefixSuffix.checked = features.prefix_suffix === 1;
        pgShorteningService.checked = features.shortening_service === 1;
        pgSuspiciousWords.checked = features.suspicious_words === 1;

        pgUrlLength.value = features.url_length;
        valUrlLength.textContent = features.url_length;

        pgHostnameLength.value = features.hostname_length;
        valHostnameLength.textContent = features.hostname_length;

        pgNbDots.value = features.nb_dots;
        valNbDots.textContent = features.nb_dots;

        pgNbSlashes.value = features.nb_slashes;
        valNbSlashes.textContent = features.nb_slashes;

        pgNbDigits.value = features.nb_digits;
        valNbDigits.textContent = features.nb_digits;

        // Hidden attributes
        pgNbHyphens.value = features.nb_hyphens;
        pgNbQuestion.value = features.nb_question;
        pgNbEqual.value = features.nb_equal;
        pgNbLetters.value = features.nb_letters;

        // Update playground gauge
        updatePlaygroundUI(risk);
    }

    function updateLettersCount() {
        const urlLen = parseInt(pgUrlLength.value);
        const digits = parseInt(pgNbDigits.value);
        // Approximation: letters = url_length - digits - (other symbols approximately 10)
        pgNbLetters.value = Math.max(0, urlLen - digits - 10);
    }

    let playgroundDebounceTimer;
    function triggerPlaygroundInference() {
        clearTimeout(playgroundDebounceTimer);
        playgroundDebounceTimer = setTimeout(async () => {
            const payload = {
                url_length: parseInt(pgUrlLength.value),
                hostname_length: parseInt(pgHostnameLength.value),
                is_https: pgIsHttps.checked ? 1 : 0,
                have_ip: pgHaveIp.checked ? 1 : 0,
                have_at: pgHaveAt.checked ? 1 : 0,
                nb_dots: parseInt(pgNbDots.value),
                nb_hyphens: parseInt(pgNbHyphens.value),
                nb_slashes: parseInt(pgNbSlashes.value),
                nb_question: parseInt(pgNbQuestion.value),
                nb_equal: parseInt(pgNbEqual.value),
                prefix_suffix: pgPrefixSuffix.checked ? 1 : 0,
                shortening_service: pgShorteningService.checked ? 1 : 0,
                suspicious_words: pgSuspiciousWords.checked ? 1 : 0,
                nb_digits: parseInt(pgNbDigits.value),
                nb_letters: parseInt(pgNbLetters.value)
            };

            try {
                const response = await fetch('/api/evaluate_features', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(payload)
                });
                
                const data = await response.json();
                if (response.ok) {
                    updatePlaygroundUI(data.risk_score);
                }
            } catch (err) {
                console.error("Playground evaluation error: ", err);
            }
        }, 150);
    }

    function updatePlaygroundUI(score) {
        pgRiskPercentage.textContent = `${score}%`;
        setGaugeProgress(pgGaugeProgress, score);

        playgroundLayout.className = 'playground-layout'; // Reset classes
        pgRiskBadge.className = 'pg-risk-badge';

        if (score >= 70) {
            playgroundLayout.classList.add('danger-state');
            pgRiskBadge.classList.add('danger');
            pgRiskBadge.textContent = 'HIGH RISK';
        } else if (score >= 30) {
            playgroundLayout.classList.add('warning-state');
            pgRiskBadge.classList.add('warning');
            pgRiskBadge.textContent = 'MEDIUM RISK';
        } else {
            playgroundLayout.classList.add('safe-state');
            pgRiskBadge.classList.add('safe');
            pgRiskBadge.textContent = 'LOW RISK';
        }
    }

    /* ----------------------------------------------------
       Session History Functions
    ---------------------------------------------------- */
    function addToHistory(url, score, prediction) {
        // Prevent duplicate URLs in history by shifting it to front
        scanHistory = scanHistory.filter(item => item.url !== url);
        scanHistory.unshift({ url, score, prediction, timestamp: new Date().toLocaleTimeString() });

        // Keep maximum of 10 items
        if (scanHistory.length > 10) scanHistory.pop();

        localStorage.setItem('phish_history', JSON.stringify(scanHistory));
        renderHistory();
    }

    function renderHistory() {
        historyList.innerHTML = '';
        if (scanHistory.length === 0) {
            historyList.innerHTML = `
                <tr class="empty-state">
                    <td colspan="4">No URLs analyzed in this session yet.</td>
                </tr>
            `;
            return;
        }

        scanHistory.forEach(item => {
            const tr = document.createElement('tr');
            
            let badgeClass = 'safe';
            let badgeLabel = 'SAFE';
            if (item.score >= 70) {
                badgeClass = 'danger';
                badgeLabel = 'MALICIOUS';
            } else if (item.score >= 30) {
                badgeClass = 'warning';
                badgeLabel = 'SUSPICIOUS';
            }

            tr.innerHTML = `
                <td>
                    <span class="history-url" title="${item.url}">${item.url}</span>
                </td>
                <td>
                    <span class="history-score ${badgeClass}">${item.score}%</span>
                </td>
                <td>
                    <span class="status-badge ${badgeClass}">${badgeLabel}</span>
                </td>
                <td>
                    <button class="btn-history-reanalyze" data-url="${item.url}">
                        <i data-lucide="rotate-ccw" class="sm-icon"></i>
                    </button>
                </td>
            `;

            // Click listener for reanalyze
            tr.querySelector('.btn-history-reanalyze').addEventListener('click', (e) => {
                const targetUrl = e.currentTarget.getAttribute('data-url');
                urlInput.value = targetUrl;
                analyzeURL(targetUrl);
            });

            historyList.appendChild(tr);
        });

        lucide.createIcons();
    }
});
