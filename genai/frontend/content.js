// Content script for Gmail
class GmailScanner {
  constructor() {
    this.scanButton = null;
    this.dashboard = null;
    this.isInjected = false;
    this.init();
  }

  init() {
    // Wait for Gmail to load
    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', () => this.injectButton());
    } else {
      this.injectButton();
    }

    // Re-inject when navigating (Gmail is SPA)
    this.observeGmailChanges();
  }

  observeGmailChanges() {
    const observer = new MutationObserver((mutations) => {
      mutations.forEach((mutation) => {
        if (!this.isInjected && this.isEmailOpen()) {
          this.injectButton();
        }
      });
    });

    observer.observe(document.body, {
      childList: true,
      subtree: true
    });
  }

  isEmailOpen() {
    // Check if we're in an email view
    return document.querySelector('[role="main"] [data-message-id]') !== null;
  }

  injectButton() {
    if (this.isInjected || !this.isEmailOpen()) return;

    const toolbar = this.findGmailToolbar();
    if (!toolbar) {
      setTimeout(() => this.injectButton(), 1000);
      return;
    }

    this.createScanButton(toolbar);
    this.isInjected = true;
  }

  findGmailToolbar() {
    // Look for Gmail's action buttons toolbar
    const selectors = [
      '.G-Ni.J-J5-Ji', // New Gmail
      '.G-tF', // Classic Gmail
      '[gh="mtb"]', // Gmail toolbar
      '.iH .aeJ', // Alternative toolbar
    ];

    for (const selector of selectors) {
      const toolbar = document.querySelector(selector);
      if (toolbar) return toolbar;
    }

    return null;
  }

  createScanButton(toolbar) {
    // Remove existing button if any
    if (this.scanButton) {
      this.scanButton.remove();
    }

    this.scanButton = document.createElement('div');
    this.scanButton.className = 'email-scanner-btn';
    this.scanButton.innerHTML = `
      <button class="scan-email-btn" title="Scan Email for Security Threats">
        <span class="btn-icon">🛡️</span>
        <span class="btn-text">Scan Security</span>
      </button>
    `;

    // Insert before the last element (usually the "More" button)
    if (toolbar.lastChild) {
      toolbar.insertBefore(this.scanButton, toolbar.lastChild);
    } else {
      toolbar.appendChild(this.scanButton);
    }

    this.attachButtonEvents();
  }

  attachButtonEvents() {
    const button = this.scanButton.querySelector('.scan-email-btn');
    button.addEventListener('click', () => this.handleScanClick());
  }

  async handleScanClick() {
    try {
      this.showLoadingState();
      
      const emailData = this.extractEmailData();
      if (!emailData) {
        this.showError('Could not extract email content');
        return;
      }

      // Send to background script for API call
      const response = await chrome.runtime.sendMessage({
        action: 'scanEmail',
        subject: emailData.subject,
        content: emailData.content
      });

      if (response.success) {
        this.showResults(response.data);
      } else {
        this.showError(response.error || 'Scan failed');
      }

    } catch (error) {
      console.error('Scan error:', error);
      this.showError('Failed to scan email');
    } finally {
      this.hideLoadingState();
    }
  }

  extractEmailData() {
    const subject = this.extractSubject();
    const content = this.extractContent();
    
    if (!subject && !content) {
      return null;
    }

    return {
      subject: subject || 'No Subject',
      content: content || 'No Content'
    };
  }

  extractSubject() {
    const subjectSelectors = [
      'h2[data-thread-perm-id]',
      '.hP',
      '[data-legacy-thread-id] .ha',
      '.ii.gt .hP'
    ];

    for (const selector of subjectSelectors) {
      const element = document.querySelector(selector);
      if (element) return element.textContent.trim();
    }

    return '';
  }

  extractContent() {
    const contentSelectors = [
      '.a3s.aiL', // Main email content
      '.ii.gt', // Email body
      '[role="main"] .a3s', // Alternative content area
      '.gs' // General selector
    ];

    for (const selector of contentSelectors) {
      const element = document.querySelector(selector);
      if (element) {
        // Get text content but preserve some structure
        return element.textContent || element.innerText || '';
      }
    }

    return '';
  }

  showLoadingState() {
    const button = this.scanButton.querySelector('.scan-email-btn');
    button.disabled = true;
    button.innerHTML = '<span class="btn-icon">⏳</span><span class="btn-text">Scanning...</span>';
  }

  hideLoadingState() {
    const button = this.scanButton.querySelector('.scan-email-btn');
    button.disabled = false;
    button.innerHTML = '<span class="btn-icon">🛡️</span><span class="btn-text">Scan Security</span>';
  }

  showError(message) {
    this.showNotification(message, 'error');
  }

  showNotification(message, type = 'info') {
    // Remove existing notification
    const existingNotification = document.querySelector('.email-scanner-notification');
    if (existingNotification) {
      existingNotification.remove();
    }

    const notification = document.createElement('div');
    notification.className = `email-scanner-notification ${type}`;
    notification.textContent = message;

    document.body.appendChild(notification);

    // Auto remove after 5 seconds
    setTimeout(() => {
      if (notification.parentNode) {
        notification.remove();
      }
    }, 5000);
  }

  showResults(scanData) {
    this.removeDashboard(); // Remove existing dashboard

    this.dashboard = document.createElement('div');
    this.dashboard.className = 'email-scanner-dashboard';
    this.dashboard.innerHTML = this.createDashboardHTML(scanData);

    document.body.appendChild(this.dashboard);

    // Add event listeners
    this.attachDashboardEvents();
    this.renderCharts(scanData);
  }

  createDashboardHTML(scanData) {
    const { analysis, url_scan_results, processing_time } = scanData;
    
    return `
      <div class="scanner-dashboard">
        <div class="dashboard-header">
          <h2>🛡️ Security Scan Results</h2>
          <button class="close-dashboard" title="Close">×</button>
        </div>
        
        <div class="dashboard-content">
          <!-- Threat Overview -->
          <div class="threat-overview card">
            <h3>Threat Overview</h3>
            <div class="threat-metrics">
              <div class="metric threat-score">
                <div class="metric-value ${this.getRiskClass(analysis.risk_level)}">
                  ${analysis.threat_score}
                </div>
                <div class="metric-label">Threat Score</div>
              </div>
              <div class="metric risk-level">
                <div class="metric-badge ${analysis.risk_level}">
                  ${analysis.risk_level.toUpperCase()}
                </div>
                <div class="metric-label">Risk Level</div>
              </div>
              <div class="metric confidence">
                <div class="metric-value">
                  ${analysis.confidence}%
                </div>
                <div class="metric-label">Confidence</div>
              </div>
            </div>
          </div>

          <!-- Detailed Analysis -->
          <div class="detailed-analysis card">
            <h3>Detailed Analysis</h3>
            <div class="analysis-content">
              ${analysis.detailed_analysis}
            </div>
          </div>

          <!-- URL Analysis -->
          ${url_scan_results.length > 0 ? `
          <div class="url-analysis card">
            <h3>URL Analysis</h3>
            <div class="url-list">
              ${url_scan_results.map(url => this.createURLEntryHTML(url)).join('')}
            </div>
          </div>
          ` : ''}

          <!-- Behavioral Analysis -->
          <div class="behavioral-analysis card">
            <h3>Behavioral Analysis</h3>
            <div class="analysis-content">
              ${analysis.behavioral_analysis}
            </div>
          </div>

          <!-- Recommendations -->
          <div class="recommendations card">
            <h3>Recommendations</h3>
            <ul class="recommendations-list">
              ${analysis.recommendations.map(rec => `<li>${rec}</li>`).join('')}
            </ul>
          </div>

          <!-- Processing Info -->
          <div class="processing-info">
            Scan completed in ${processing_time}s
          </div>
        </div>
      </div>
    `;
  }

  createURLEntryHTML(urlResult) {
    return `
      <div class="url-entry ${urlResult.risk_level}">
        <div class="url-header">
          <span class="url-text">${urlResult.url}</span>
          <span class="url-risk ${urlResult.risk_level}">${urlResult.risk_level.toUpperCase()}</span>
        </div>
        <div class="url-details">
          <div class="url-scan-result">
            <strong>PhishingArmy:</strong> ${urlResult.phishing_army_result ? 'BLOCKED' : 'Not Found'}
          </div>
          ${urlResult.virustotal_result ? `
          <div class="url-scan-result">
            <strong>VirusTotal:</strong> ${this.formatVirusTotalResult(urlResult.virustotal_result)}
          </div>
          ` : ''}
        </div>
      </div>
    `;
  }

  formatVirusTotalResult(vtResult) {
    if (vtResult.error) {
      return `Error: ${vtResult.error}`;
    }
    
    if (vtResult.data) {
      const data = vtResult.data.data || vtResult.data;
      const stats = data.attributes?.last_analysis_stats || {};
      const malicious = stats.malicious || 0;
      const total = Object.values(stats).reduce((sum, val) => sum + val, 0);
      
      return `${malicious}/${total} engines detected threats`;
    }
    
    return 'No data';
  }

  getRiskClass(riskLevel) {
    const riskClasses = {
      safe: 'safe',
      suspicious: 'suspicious', 
      malicious: 'malicious'
    };
    return riskClasses[riskLevel] || 'suspicious';
  }

  attachDashboardEvents() {
    // Close button
    const closeBtn = this.dashboard.querySelector('.close-dashboard');
    closeBtn.addEventListener('click', () => this.removeDashboard());

    // Close on escape key
    document.addEventListener('keydown', (e) => {
      if (e.key === 'Escape') {
        this.removeDashboard();
      }
    });

    // Close on outside click
    this.dashboard.addEventListener('click', (e) => {
      if (e.target === this.dashboard) {
        this.removeDashboard();
      }
    });
  }

  renderCharts(scanData) {
    // Simple chart rendering for threat visualization
    this.renderThreatGauge(scanData.analysis.threat_score);
  }

  renderThreatGauge(score) {
    const gaugeElement = document.querySelector('.threat-score .metric-value');
    if (gaugeElement) {
      // Visual indicator through color and animation
      gaugeElement.style.setProperty('--threat-score', `${score}%`);
    }
  }

  removeDashboard() {
    if (this.dashboard && this.dashboard.parentNode) {
      this.dashboard.remove();
      this.dashboard = null;
    }
  }
}

// Initialize when page loads
let gmailScanner;
function initScanner() {
  if (!gmailScanner) {
    gmailScanner = new GmailScanner();
  }
}

// Start the scanner
initScanner();