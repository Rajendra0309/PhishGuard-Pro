const SCAN_INTERVAL = 2000;
let scanEnabled = true;
let pageObserver;
let lastScannedText = '';
let lastAnalyzedImages = new Set();
let scannedUrls = new Set();
let intervalId = null;
let isContextValid = true;
let whitelistedDomains = ['google.com', 'gmail.com', 'youtube.com', 'microsoft.com', 'github.com', 'stackoverflow.com'];
let scanCount = 0;

function safeRuntime(callback) {
  try {
    if (!chrome.runtime) {
      isContextValid = false;
      return;
    }
    
    chrome.runtime.id;
    return callback();
  } catch (e) {
    isContextValid = false;
    cleanupResources();
    return;
  }
}

function cleanupResources() {
  if (intervalId) {
    clearInterval(intervalId);
    intervalId = null;
  }
  
  if (pageObserver) {
    pageObserver.disconnect();
    pageObserver = null;
  }
}

function initSafely() {
  try {
    if (!chrome || !chrome.runtime) {
      throw new Error("Chrome runtime not available");
    }
    
    chrome.storage.local.get(['scanEnabled', 'whitelistedDomains'], (data) => {
      try {
        scanEnabled = data.scanEnabled !== undefined ? data.scanEnabled : true;
        if (data.whitelistedDomains) {
          whitelistedDomains = data.whitelistedDomains;
        }
        
        if (scanEnabled) {
          safeSetupPageObserver();
          safeScanPage();
          intervalId = setInterval(safeScanInterval, SCAN_INTERVAL);
        }
      } catch (e) {}
    });
  } catch (e) {}
  
  try {
    chrome.runtime.onMessage.addListener(function(message, sender, sendResponse) {
      try {
        if (message.type === 'toggleScan') {
          scanEnabled = message.enabled;
          if (scanEnabled) {
            safeSetupPageObserver();
            safeScanPage();
          } else if (pageObserver) {
            try { pageObserver.disconnect(); } catch (e) {}
          }
          sendResponse({ success: true });
        } else if (message.type === 'scanPage') {
          if (scanEnabled) {
            safeScanPage();
          }
          sendResponse({ success: true });
        } else if (message.type === 'phishingDetected') {
          showPageWarning({
            confidence: message.confidence,
            url: message.url
          });
        }
      } catch (e) {}
      return true;
    });
  } catch (e) {}
}

function safeSetupPageObserver() {
  try {
    if (pageObserver) {
      try { pageObserver.disconnect(); } catch (e) {}
    }

    pageObserver = new MutationObserver(mutations => {
      let shouldScan = false;
      
      for (const mutation of mutations) {
        if (mutation.type === 'childList' || mutation.type === 'characterData') {
          shouldScan = true;
          break;
        }
      }
      
      if (shouldScan) {
        safeScanPage();
      }
    });
    
    pageObserver.observe(document.body, {
      childList: true,
      subtree: true,
      characterData: true
    });
  } catch (e) {
    console.error("Observer setup error:", e);
  }
}

function safeScanInterval() {
  try {
    if (!chrome || !chrome.runtime) {
      clearInterval(intervalId);
      return;
    }
    safeScanPage();
  } catch (e) {
    clearInterval(intervalId);
  }
}

function safeScanPage() {
  try {
    if (!scanEnabled) return;
    
    if (isWhitelistedPage()) return;
    
    scanCount++;
    if (scanCount % 5 === 0) {
      safePageText();
    }
    
    safePageUrls();
    safeInputFields();
    safeImageScan();
  } catch (e) {}
}

function isWhitelistedPage() {
  try {
    const currentDomain = window.location.hostname.toLowerCase();
    return whitelistedDomains.some(domain => currentDomain.endsWith(domain));
  } catch (e) {
    return false;
  }
}

function safePageUrls() {
  try {
    const links = Array.from(document.querySelectorAll('a'));
    
    links.forEach(link => {
      try {
        const url = link.href;
        if (!url || url === '#' || url.startsWith('javascript:') || scannedUrls.has(url)) return;
        
        scannedUrls.add(url);
        
        trySendMessage({ type: 'checkUrl', url }, response => {
          try {
            if (response && response.result && response.result.isPhishing) {
              markElement(link, response.result.confidence);
            }
          } catch (e) {}
        });
      } catch (e) {}
    });
    
    if (scannedUrls.size > 500) {
      scannedUrls.clear();
    }
  } catch (e) {}
}

function safePageText() {
  try {
    const visibleText = getVisiblePageText();
    
    if (visibleText === lastScannedText || visibleText.length < 100) return;
    lastScannedText = visibleText;
    
    const suspiciousPatterns = [
      /password.*expired/i,
      /account.*verify/i,
      /bank.*login/i,
      /update.*payment/i,
      /unusual.*activity/i,
      /security.*alert/i,
      /verify.*identity/i
    ];
    
    let patternMatches = 0;
    for (const pattern of suspiciousPatterns) {
      if (pattern.test(visibleText)) {
        patternMatches++;
      }
    }
    
    if (patternMatches >= 2) {
      trySendMessage({ 
        type: 'analyzeContent', 
        data: { 
          type: 'text', 
          content: visibleText, 
          url: window.location.href,
          patternMatches
        } 
      }, response => {
        try {
          if (response && response.result && response.result.isPhishing && 
              response.result.confidence > 0.7) {
            showPageWarning(response.result);
          }
        } catch (e) {}
      });
    }
  } catch (e) {}
}

function safeImageScan() {
  try {
    const images = Array.from(document.querySelectorAll('img'));
    const newImages = images.filter(img => 
      img.complete && 
      img.naturalWidth > 100 && 
      img.naturalHeight > 100 && 
      !lastAnalyzedImages.has(img.src) &&
      (img.src.includes('logo') || img.width > 200 || img.height > 50)
    ).slice(0, 3);
    
    newImages.forEach(img => {
      try {
        lastAnalyzedImages.add(img.src);
        
        const canvas = document.createElement('canvas');
        const context = canvas.getContext('2d');
        canvas.width = Math.min(img.naturalWidth, 300);
        canvas.height = Math.min(img.naturalHeight, 300);
        context.drawImage(img, 0, 0, canvas.width, canvas.height);
        
        const imageData = canvas.toDataURL('image/jpeg', 0.7);
        
        trySendMessage({ 
          type: 'analyzeContent', 
          data: { 
            type: 'image', 
            content: imageData, 
            url: window.location.href
          } 
        }, response => {
          try {
            if (response && response.result && response.result.isPhishing) {
              markElement(img, response.result.confidence);
            }
          } catch (e) {}
        });
      } catch (e) {}
    });
    
    if (lastAnalyzedImages.size > 100) {
      lastAnalyzedImages.clear();
    }
  } catch (e) {}
}

function safeInputFields() {
  try {
    const forms = Array.from(document.querySelectorAll('form'));
    
    forms.forEach(form => {
      try {
        const passwordFields = form.querySelectorAll('input[type="password"]');
        const loginInputs = form.querySelectorAll('input[type="text"], input[type="email"]');
        const cardFields = form.querySelectorAll('input[name*="card"], input[name*="cvv"], input[name*="ccv"]');
        
        if (passwordFields.length === 0 && cardFields.length === 0) return;
        
        let suspiciousScore = 0;
        
        if (passwordFields.length > 0) suspiciousScore += 1;
        
        if (cardFields.length > 0) suspiciousScore += 2;
        
        try {
          const formDomain = new URL(form.action).hostname.toLowerCase();
          const pageDomain = window.location.hostname.toLowerCase();
          
          if (formDomain !== pageDomain && !formDomain.endsWith('.' + pageDomain.split('.').slice(-2).join('.'))) {
            suspiciousScore += 3;
          }
        } catch (e) {}
        
        if (form.action && !form.action.startsWith('https')) {
          suspiciousScore += 2;
        }

        if (suspiciousScore >= 3) {
          const formData = {
            hasPassword: passwordFields.length > 0,
            hasLoginField: loginInputs.length > 0,
            hasCardFields: cardFields.length > 0,
            action: form.action || window.location.href,
            domain: window.location.hostname,
            suspiciousScore
          };
          
          trySendMessage({ 
            type: 'analyzeContent', 
            data: { 
              type: 'form', 
              content: formData, 
              url: window.location.href 
            } 
          }, response => {
            try {
              if (response && response.result && response.result.isPhishing) {
                markElement(form, response.result.confidence);
                
                const submitButtons = form.querySelectorAll('input[type="submit"], button[type="submit"], button');
                submitButtons.forEach(button => {
                  button.addEventListener('click', function(e) {
                    if (confirm('Warning: This form may be attempting to steal your information. Continue anyway?')) {
                      return true;
                    } else {
                      e.preventDefault();
                      e.stopPropagation();
                      return false;
                    }
                  }, true);
                });
              }
            } catch (e) {}
          });
        }
      } catch (e) {}
    });
  } catch (e) {}
}

function trySendMessage(message, callback) {
  try {
    if (!chrome || !chrome.runtime) return;
    chrome.runtime.sendMessage(message, callback);
  } catch (e) {}
}

function getVisiblePageText() {
  try {
    const bodyText = document.body.innerText;
    return bodyText.substring(0, 5000);
  } catch (e) {
    return '';
  }
}

function markElement(element, confidence) {
  try {
    element.style.border = '2px solid red';
    
    const warningBadge = document.createElement('div');
    warningBadge.style.position = 'absolute';
    warningBadge.style.backgroundColor = 'red';
    warningBadge.style.color = 'white';
    warningBadge.style.padding = '2px 5px';
    warningBadge.style.borderRadius = '3px';
    warningBadge.style.fontSize = '12px';
    warningBadge.style.zIndex = '9999';
    warningBadge.style.pointerEvents = 'none';
    warningBadge.innerText = 'PHISHING RISK';
    
    const parentPosition = element.getBoundingClientRect();
    warningBadge.style.top = `${window.scrollY + parentPosition.top - 20}px`;
    warningBadge.style.left = `${window.scrollX + parentPosition.left}px`;
    
    document.body.appendChild(warningBadge);
  } catch (e) {}
}

function showPageWarning(result) {
  try {
    const existingBanner = document.getElementById('phishguard-warning');
    if (existingBanner) {
      try { document.body.removeChild(existingBanner); } catch (e) {}
    }

    const warningBanner = document.createElement('div');
    warningBanner.id = 'phishguard-warning';
    warningBanner.style.position = 'fixed';
    warningBanner.style.top = '0';
    warningBanner.style.left = '0';
    warningBanner.style.width = '100%';
    warningBanner.style.backgroundColor = '#f44336';
    warningBanner.style.color = 'white';
    warningBanner.style.padding = '10px';
    warningBanner.style.textAlign = 'center';
    warningBanner.style.zIndex = '10000';
    warningBanner.style.fontSize = '16px';
    warningBanner.style.fontWeight = 'bold';
    
    const confidencePercentage = Math.round(result.confidence * 100);
    warningBanner.innerText = `⚠️ Warning: This page contains potential phishing content (${confidencePercentage}% confidence)`;
    
    const closeButton = document.createElement('span');
    closeButton.innerText = '✖';
    closeButton.style.float = 'right';
    closeButton.style.cursor = 'pointer';
    closeButton.style.marginRight = '10px';
    closeButton.onclick = function() {
      try { document.body.removeChild(warningBanner); } catch (e) {}
    };
    
    warningBanner.appendChild(closeButton);
    document.body.appendChild(warningBanner);
  } catch (e) {}
}

window.addEventListener('load', initSafely);
