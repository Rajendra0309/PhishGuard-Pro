document.addEventListener('DOMContentLoaded', () => {
  const scanToggle = document.getElementById('scanToggle');
  const statusText = document.getElementById('statusText');
  const totalScanned = document.getElementById('totalScanned');
  const phishingDetected = document.getElementById('phishingDetected');
  const siteStatus = document.getElementById('siteStatus');
  const detectionLevel = document.getElementById('detectionLevel');
  const notificationsToggle = document.getElementById('notificationsToggle');
  const backgroundScanToggle = document.getElementById('backgroundScanToggle');
  const scanNowBtn = document.getElementById('scanNowBtn');
  const viewHistoryBtn = document.getElementById('viewHistoryBtn');
  const addWhitelistBtn = document.getElementById('addWhitelistBtn');

  loadSettings();
  loadStats();
  checkCurrentSite();

  scanToggle.addEventListener('change', () => {
    const isEnabled = scanToggle.checked;
    statusText.textContent = isEnabled ? 'Protection Active' : 'Protection Disabled';
    
    chrome.storage.local.set({ scanEnabled: isEnabled });
    
    chrome.tabs.query({ active: true, currentWindow: true }, tabs => {
      if (tabs[0]) {
        chrome.tabs.sendMessage(tabs[0].id, { 
          type: 'toggleScan', 
          enabled: isEnabled 
        });
      }
    });
  });

  detectionLevel.addEventListener('change', () => {
    chrome.storage.local.set({ detectionLevel: detectionLevel.value });
  });

  notificationsToggle.addEventListener('change', () => {
    chrome.storage.local.set({ notificationsEnabled: notificationsToggle.checked });
  });
  
  backgroundScanToggle.addEventListener('change', () => {
    const isEnabled = backgroundScanToggle.checked;
    chrome.storage.local.set({ backgroundScanEnabled: isEnabled });
    chrome.runtime.sendMessage({ 
      type: 'toggleBackgroundScan', 
      enabled: isEnabled 
    });
  });

  scanNowBtn.addEventListener('click', () => {
    scanNowBtn.textContent = 'Scanning...';
    scanNowBtn.disabled = true;
    siteStatus.textContent = 'Analyzing...';
    
    chrome.tabs.query({ active: true, currentWindow: true }, tabs => {
      if (tabs[0]) {
        const currentUrl = tabs[0].url;
        
        chrome.runtime.sendMessage({ 
          type: 'checkUrl', 
          url: currentUrl 
        }, response => {
          updateSiteStatus(response);
          scanNowBtn.textContent = 'Scan Now';
          scanNowBtn.disabled = false;
        });
      } else {
        scanNowBtn.textContent = 'Scan Now';
        scanNowBtn.disabled = false;
        siteStatus.textContent = 'No active tab';
      }
    });
  });

  viewHistoryBtn.addEventListener('click', () => {
    chrome.tabs.create({ url: 'history.html' });
  });

  if (addWhitelistBtn) {
    addWhitelistBtn.addEventListener('click', () => {
      chrome.tabs.query({ active: true, currentWindow: true }, tabs => {
        if (tabs[0] && tabs[0].url) {
          try {
            const domain = new URL(tabs[0].url).hostname;
            
            chrome.storage.local.get(['whitelistedDomains'], (data) => {
              const whitelist = data.whitelistedDomains || [];
              if (!whitelist.includes(domain)) {
                whitelist.push(domain);
                chrome.storage.local.set({ whitelistedDomains: whitelist }, () => {
                  addWhitelistBtn.textContent = 'Added to Whitelist';
                  setTimeout(() => {
                    addWhitelistBtn.textContent = 'Add to Whitelist';
                  }, 2000);
                });
              }
            });
          } catch (e) {
            addWhitelistBtn.textContent = 'Invalid URL';
            setTimeout(() => {
              addWhitelistBtn.textContent = 'Add to Whitelist';
            }, 2000);
          }
        }
      });
    });
  }

  function loadSettings() {
    chrome.storage.local.get(
      ['scanEnabled', 'detectionLevel', 'notificationsEnabled', 'backgroundScanEnabled', 'apiKeys'], 
      data => {
        if (data.scanEnabled !== undefined) {
          scanToggle.checked = data.scanEnabled;
          statusText.textContent = data.scanEnabled ? 'Protection Active' : 'Protection Disabled';
        }
        
        if (data.detectionLevel) {
          detectionLevel.value = data.detectionLevel;
        }
        
        if (data.notificationsEnabled !== undefined) {
          notificationsToggle.checked = data.notificationsEnabled;
        }
        
        if (data.backgroundScanEnabled !== undefined) {
          backgroundScanToggle.checked = data.backgroundScanEnabled;
        }
        
        const apiStatusEl = document.getElementById('apiStatus');
        if (apiStatusEl) {
          const vtStatus = data.apiKeys?.virustotal ? '✓' : '✗';
          const gmStatus = data.apiKeys?.gemini ? '✓' : '✗';
          apiStatusEl.textContent = `API Status: VirusTotal ${vtStatus} | Gemini ${gmStatus}`;
        }
      }
    );
  }

  function loadStats() {
    chrome.runtime.sendMessage({ type: 'getStats' }, response => {
      if (response && response.stats) {
        totalScanned.textContent = response.stats.totalScanned.toLocaleString();
        phishingDetected.textContent = response.stats.phishingDetected.toLocaleString();
      }
    });
  }

  function checkCurrentSite() {
    chrome.tabs.query({ active: true, currentWindow: true }, tabs => {
      if (tabs[0]) {
        const currentUrl = tabs[0].url;
        
        if (!currentUrl || !currentUrl.startsWith('http')) {
          siteStatus.textContent = 'Not applicable';
          return;
        }
        
        siteStatus.textContent = 'Analyzing...';
        
        chrome.runtime.sendMessage({ 
          type: 'checkUrl', 
          url: currentUrl 
        }, response => {
          updateSiteStatus(response);
        });
      }
    });
  }
  
  function updateSiteStatus(response) {
    if (response && response.result) {
      if (response.result.isPhishing) {
        siteStatus.textContent = '⚠️ Suspicious site detected!';
        siteStatus.className = 'site-status danger';
      } else {
        siteStatus.textContent = '✓ No threats detected';
        siteStatus.className = 'site-status safe';
      }
    } else {
      siteStatus.textContent = 'Unable to analyze';
    }
  }
});
