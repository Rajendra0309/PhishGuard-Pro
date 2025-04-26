const SCAN_INTERVAL = 2000;
let scanEnabled = true;
let pageObserver;
let lastScannedText = '';
let lastAnalyzedImages = new Set();
let scannedUrls = new Set();
let intervalId = null;
let isContextValid = true;
let scanCount = 0;
let trustedDomains = new Set([
  'google.com', 'google.co.uk', 'youtube.com', 'gmail.com', 'microsoft.com',
  'apple.com', 'amazon.com', 'facebook.com', 'instagram.com',
  'linkedin.com', 'github.com', 'stackoverflow.com'
]);

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
      return;
    }
    
    chrome.storage.local.get(['scanEnabled'], (data) => {
      try {
        scanEnabled = data.scanEnabled !== undefined ? data.scanEnabled : true;
        
        if (scanEnabled) {
          safeSetupPageObserver();
          safeScanPage();
          if (intervalId) clearInterval(intervalId);
          intervalId = setInterval(safeScanInterval, SCAN_INTERVAL);
          setupMessageScanning();
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
            if (!intervalId) {
              intervalId = setInterval(safeScanInterval, SCAN_INTERVAL);
            }
            setupMessageScanning();
          } else {
            cleanupResources();
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
          sendResponse({ success: true });
        } else if (message.type === 'checkPageSafety') {
          trySendMessage({
            type: 'checkUrl',
            url: window.location.href
          }, response => {
            sendResponse(response);
          });
          return true;
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
      if (!scanEnabled) return;
      
      let shouldScan = false;
      for (const mutation of mutations) {
        if (mutation.type === 'childList' || mutation.type === 'characterData') {
          shouldScan = true;
          break;
        }
      }
      
      if (shouldScan) {
        setTimeout(safeScanPage, 500);
      }
    });
    
    if (document.body) {
      pageObserver.observe(document.body, {
        childList: true,
        subtree: true,
        characterData: true
      });
    }
  } catch (e) {}
}

function safeScanInterval() {
  safeRuntime(() => {
    if (scanEnabled) {
      safeScanPage();
    }
  });
}

function safeScanPage() {
  try {
    if (!scanEnabled) return;
    
    if (isTrustedPage()) return;
    
    scanCount++;
    if (scanCount % 5 === 0) {
      safePageText();
    }
    
    safePageUrls();
    safeInputFields();
    safeImageScan();
    scanMessagingPlatforms();
  } catch (e) {}
}

function isTrustedPage() {
  try {
    const currentHostname = window.location.hostname.toLowerCase();
    return Array.from(trustedDomains).some(domain => 
      currentHostname === domain || currentHostname.endsWith('.' + domain)
    );
  } catch (e) {
    return false;
  }
}

function safePageUrls() {
  try {
    const links = Array.from(document.querySelectorAll('a[href]'));
    
    const newLinks = links.filter(link => {
      const url = link.href;
      return url && 
        url !== '#' && 
        !url.startsWith('javascript:') && 
        !scannedUrls.has(url) &&
        url.startsWith('http');
    }).slice(0, 10);
    
    newLinks.forEach(link => {
      try {
        const url = link.href;
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
        if (form.dataset.scanned) return;
        form.dataset.scanned = 'true';
        
        const passwordFields = form.querySelectorAll('input[type="password"]');
        const loginInputs = form.querySelectorAll('input[type="text"], input[type="email"]');
        const cardFields = form.querySelectorAll('input[name*="card"], input[name*="cvv"], input[name*="ccv"]');
        
        if (passwordFields.length === 0 && cardFields.length === 0) return;
        
        let suspiciousScore = 0;
        
        if (passwordFields.length > 0) suspiciousScore += 1;
        if (cardFields.length > 0) suspiciousScore += 2;
        
        try {
          const formAction = form.action || '';
          if (formAction) {
            const formDomain = new URL(formAction).hostname.toLowerCase();
            const pageDomain = window.location.hostname.toLowerCase();
            
            if (formDomain !== pageDomain && !formDomain.endsWith('.' + pageDomain.split('.').slice(-2).join('.'))) {
              suspiciousScore += 3;
            }
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
    if (element.dataset.phishguardMarked) return;
    element.dataset.phishguardMarked = "true";
    
    element.style.border = '2px solid red';
    element.style.position = 'relative';
    
    const warningBadge = document.createElement('div');
    warningBadge.style.position = 'absolute';
    warningBadge.style.backgroundColor = 'red';
    warningBadge.style.color = 'white';
    warningBadge.style.padding = '2px 5px';
    warningBadge.style.borderRadius = '3px';
    warningBadge.style.fontSize = '12px';
    warningBadge.style.zIndex = '9999';
    warningBadge.style.top = '0';
    warningBadge.style.right = '0';
    warningBadge.innerText = 'PHISHING RISK';
    
    element.appendChild(warningBadge);
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

function setupMessageScanning() {
  try {
    const messageObserver = new MutationObserver(mutations => {
      for (const mutation of mutations) {
        if (mutation.addedNodes.length > 0) {
          scanMessagingPlatforms();
        }
      }
    });
    
    if (document.body) {
      messageObserver.observe(document.body, {
        childList: true,
        subtree: true
      });
    }
    
    scanMessagingPlatforms();
  } catch (e) {}
}

function scanMessagingPlatforms() {
  try {
    const hostname = window.location.hostname.toLowerCase();
    
    if (hostname.includes('gmail')) {
      scanEmailMessages();
    } else if (hostname.includes('outlook') || hostname.includes('mail')) {
      scanEmailMessages();
    } else if (hostname.includes('facebook') || hostname.includes('messenger')) {
      scanFacebookMessages();
    } else if (hostname.includes('twitter') || hostname.includes('x.com')) {
      scanTwitterMessages();
    } else if (hostname.includes('instagram')) {
      scanInstagramMessages();
    } else if (hostname.includes('linkedin')) {
      scanLinkedInMessages();
    } else if (hostname.includes('telegram')) {
      scanTelegramMessages();
    } else if (hostname.includes('slack')) {
      scanSlackMessages();
    } else if (hostname.includes('discord')) {
      scanDiscordMessages();
    } else if (hostname.includes('web.whatsapp')) {
      scanWhatsappMessages();
    } else {
      scanForMessageThreats();
    }
  } catch (e) {}
}

function scanEmailMessages() {
  try {
    const emailBodies = document.querySelectorAll('.message-body, .mail-message-body, .email-content, .message-part');
    
    for (const emailBody of emailBodies) {
      if (emailBody && !emailBody.dataset.scanned) {
        emailBody.dataset.scanned = 'true';
        const messageText = emailBody.innerText;
        analyzeMessageContent(messageText, emailBody, 'email');
      }
    }
  } catch (e) {}
}

function scanWhatsappMessages() {
  try {
    const messages = document.querySelectorAll('.message-in, .selectable-text');
    
    for (const message of messages) {
      if (message && !message.dataset.scanned) {
        message.dataset.scanned = 'true';
        const messageText = message.innerText;
        analyzeMessageContent(messageText, message, 'whatsapp');
      }
    }
  } catch (e) {}
}

function scanFacebookMessages() {
  try {
    const messages = document.querySelectorAll('[data-testid="message-container"]');
    
    for (const message of messages) {
      if (message && !message.dataset.scanned) {
        message.dataset.scanned = 'true';
        const messageText = message.innerText;
        analyzeMessageContent(messageText, message, 'facebook');
      }
    }
  } catch (e) {}
}

function scanTwitterMessages() {
  try {
    const tweets = document.querySelectorAll('[data-testid="tweet"], [data-testid="tweetText"]');
    
    for (const tweet of tweets) {
      if (tweet && !tweet.dataset.scanned) {
        tweet.dataset.scanned = 'true';
        const messageText = tweet.innerText;
        analyzeMessageContent(messageText, tweet, 'twitter');
      }
    }
  } catch (e) {}
}

function scanInstagramMessages() {
  try {
    const messages = document.querySelectorAll('.msg-text, ._aa_m');
    
    for (const message of messages) {
      if (message && !message.dataset.scanned) {
        message.dataset.scanned = 'true';
        const messageText = message.innerText;
        analyzeMessageContent(messageText, message, 'instagram');
      }
    }
  } catch (e) {}
}

function scanLinkedInMessages() {
  try {
    const messages = document.querySelectorAll('.msg-s-event-listitem__body');
    
    for (const message of messages) {
      if (message && !message.dataset.scanned) {
        message.dataset.scanned = 'true';
        const messageText = message.innerText;
        analyzeMessageContent(messageText, message, 'linkedin');
      }
    }
  } catch (e) {}
}

function scanTelegramMessages() {
  try {
    const messages = document.querySelectorAll('.message');
    
    for (const message of messages) {
      if (message && !message.dataset.scanned) {
        message.dataset.scanned = 'true';
        const messageText = message.innerText;
        analyzeMessageContent(messageText, message, 'telegram');
      }
    }
  } catch (e) {}
}

function scanSlackMessages() {
  try {
    const messages = document.querySelectorAll('.c-message__body');
    
    for (const message of messages) {
      if (message && !message.dataset.scanned) {
        message.dataset.scanned = 'true';
        const messageText = message.innerText;
        analyzeMessageContent(messageText, message, 'slack');
      }
    }
  } catch (e) {}
}

function scanDiscordMessages() {
  try {
    const messages = document.querySelectorAll('[class*="messageContent-"]');
    
    for (const message of messages) {
      if (message && !message.dataset.scanned) {
        message.dataset.scanned = 'true';
        const messageText = message.innerText;
        analyzeMessageContent(messageText, message, 'discord');
      }
    }
  } catch (e) {}
}

function scanForMessageThreats() {
  try {
    const messageElements = document.querySelectorAll('p, div, span, li');
    
    for (const element of messageElements) {
      if (!element.dataset.scanned && element.innerText && element.innerText.length > 20) {
        element.dataset.scanned = 'true';
        const possibleMessage = element.innerText;
        analyzeMessageContent(possibleMessage, element, 'generic');
      }
    }
  } catch (e) {}
}

function analyzeMessageContent(text, element, platform) {
  try {
    if (!text || text.length < 20) return;
    
    const threatPatterns = [
      { regex: /(bitcoin|crypto|wallet|investment).*(urgent|opportunity|profit|double)/i, type: 'crypto_scam' },
      { regex: /(password|account|verify|suspended|limited|access|unusual).*(reset|confirm|verify|login)/i, type: 'account_phishing' },
      { regex: /(bank|payment|paypal|transfer).*(confirm|verify|update|urgent|problem)/i, type: 'financial_fraud' },
      { regex: /(click|download|open|access).*(here|link|attachment|doc|invoice|statement)/i, type: 'malware_delivery' },
      { regex: /(prize|won|winner|lottery|million|free|gift).*(claim|collect|receive)/i, type: 'lottery_scam' },
      { regex: /(hello dear|dear friend|dear beneficiary|unclaimed inheritance|deceased client)/i, type: 'inheritance_scam' },
      { regex: /(job|work|earn|income).*(home|online|easily|quickly|passive)/i, type: 'job_scam' },
      { regex: /(dating|relationship|meet|singles|partner).*(nearby|area|looking|want)/i, type: 'romance_scam' },
      { regex: /(urgent|assistance|help|kindly).*(transfer|money|payment|western union)/i, type: 'advance_fee_fraud' },
      { regex: /(government|irs|tax|refund|stimulus).*(payment|return|money|fund)/i, type: 'tax_scam' }
    ];
    
    for (const pattern of threatPatterns) {
      if (pattern.regex.test(text)) {
        markMessageAsThreat(element, pattern.type, platform);
        break;
      }
    }
    
    const urls = extractUrls(text);
    if (urls.length > 0) {
      for (const url of urls) {
        trySendMessage({ 
          type: 'checkUrl', 
          url: url,
          context: 'message'
        }, response => {
          try {
            if (response && response.result && response.result.isPhishing) {
              markMessageAsThreat(element, 'suspicious_link', platform);
              showUrlWarning(url, response.result.confidence);
            }
          } catch (e) {}
        });
      }
    }
  } catch (e) {}
}

function extractUrls(text) {
  const urlRegex = /(https?:\/\/[^\s]+)/g;
  return text.match(urlRegex) || [];
}

function markMessageAsThreat(element, threatType, platform) {
  try {
    if (element.classList.contains('phishguard-marked')) return;
    
    element.classList.add('phishguard-marked');
    element.style.position = 'relative';
    element.style.border = '2px solid #ff3b30';
    element.style.padding = '8px';
    element.style.borderRadius = '4px';
    element.style.backgroundColor = 'rgba(255, 59, 48, 0.05)';
    
    const threatInfo = getThreatInfo(threatType);
    
    const warningElement = document.createElement('div');
    warningElement.style.backgroundColor = '#ff3b30';
    warningElement.style.color = 'white';
    warningElement.style.padding = '5px 10px';
    warningElement.style.borderRadius = '4px';
    warningElement.style.fontSize = '12px';
    warningElement.style.fontWeight = 'bold';
    warningElement.style.marginBottom = '5px';
    warningElement.style.display = 'flex';
    warningElement.style.alignItems = 'center';
    warningElement.style.justifyContent = 'space-between';
    
    warningElement.innerHTML = `
      <div>⚠️ ${threatInfo.title}</div>
      <div style="cursor: pointer; margin-left: 10px;" class="threat-info-button">ℹ️</div>
    `;
    
    element.parentNode.insertBefore(warningElement, element);
    
    const infoButton = warningElement.querySelector('.threat-info-button');
    if (infoButton) {
      infoButton.addEventListener('click', () => {
        showThreatDetails(threatType, platform);
      });
    }
    
    trySendMessage({
      type: 'logThreatDetection',
      threatType,
      platform,
      url: window.location.href
    });
    
  } catch (e) {}
}

function getThreatInfo(threatType) {
  const threatTypes = {
    crypto_scam: { 
      title: 'Cryptocurrency Scam', 
      description: 'This message contains signs of a cryptocurrency investment scam, which often promises unrealistic returns.' 
    },
    account_phishing: { 
      title: 'Account Phishing Attempt', 
      description: 'This message appears to be attempting to steal your account credentials by creating a false sense of urgency.' 
    },
    financial_fraud: { 
      title: 'Financial Fraud Attempt', 
      description: 'This message is attempting to trick you into providing financial information or making payments.' 
    },
    malware_delivery: { 
      title: 'Potential Malware Delivery', 
      description: 'This message may be attempting to get you to download malware or visit a malicious website.' 
    },
    lottery_scam: { 
      title: 'Lottery or Prize Scam', 
      description: 'This message claims you\'ve won a prize or lottery you didn\'t enter, a common fraud tactic.' 
    },
    inheritance_scam: { 
      title: 'Inheritance Scam', 
      description: 'This message claims you can receive money from an unknown deceased relative, a common advance fee fraud.' 
    },
    job_scam: { 
      title: 'Fake Job Opportunity', 
      description: 'This appears to be promoting a fake job or income opportunity that is likely a scam.' 
    },
    romance_scam: { 
      title: 'Romance Scam', 
      description: 'This message may be part of a romance scam attempting to establish a deceptive relationship.' 
    },
    advance_fee_fraud: { 
      title: 'Advance Fee Fraud', 
      description: 'This appears to be an advance fee fraud (like "Nigerian Prince" scams) asking for upfront payments.' 
    },
    tax_scam: { 
      title: 'Tax or Government Impersonation Scam', 
      description: 'This message is impersonating a tax or government agency, a common tactic to steal personal information.' 
    },
    suspicious_link: { 
      title: 'Suspicious Link Detected', 
      description: 'This message contains a link that has been flagged as potentially dangerous.' 
    }
  };
  
  return threatTypes[threatType] || { title: 'Suspicious Content', description: 'This message contains potentially harmful content.' };
}

function showThreatDetails(threatType, platform) {
  try {
    const existingPopup = document.getElementById('phishguard-threat-popup');
    if (existingPopup) existingPopup.remove();
    
    const threatInfo = getThreatInfo(threatType);
    
    const popup = document.createElement('div');
    popup.id = 'phishguard-threat-popup';
    popup.style.position = 'fixed';
    popup.style.top = '50%';
    popup.style.left = '50%';
    popup.style.transform = 'translate(-50%, -50%)';
    popup.style.backgroundColor = 'white';
    popup.style.boxShadow = '0 4px 24px rgba(0, 0, 0, 0.2)';
    popup.style.borderRadius = '8px';
    popup.style.padding = '20px';
    popup.style.maxWidth = '400px';
    popup.style.width = '80%';
    popup.style.zIndex = '100000';
    
    popup.innerHTML = `
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px;">
        <h3 style="margin: 0; color: #ff3b30;">⚠️ ${threatInfo.title}</h3>
        <span id="phishguard-close-popup" style="cursor: pointer; font-size: 20px;">✕</span>
      </div>
      <p style="margin-bottom: 15px;">${threatInfo.description}</p>
      <div style="margin-top: 20px; font-size: 12px; color: #666;">
        <p>Detected by PhishGuard Pro on ${platform}</p>
      </div>
      <div style="margin-top: 15px; display: flex; justify-content: flex-end;">
        <button id="phishguard-dismiss-btn" style="padding: 8px 15px; background-color: #f2f2f2; border: none; border-radius: 4px; margin-right: 10px; cursor: pointer;">Dismiss</button>
      </div>
    `;
    
    document.body.appendChild(popup);
    
    document.getElementById('phishguard-close-popup').addEventListener('click', () => {
      popup.remove();
    });
    
    document.getElementById('phishguard-dismiss-btn').addEventListener('click', () => {
      popup.remove();
    });
  } catch (e) {}
}

function showUrlWarning(url, confidence) {
  try {
    const confidencePct = Math.round(confidence * 100);
    
    trySendMessage({ 
      type: 'showNotification',
      url: url,
      confidence: confidencePct
    });
    
    const existingWarning = document.getElementById('phishguard-url-warning');
    if (existingWarning) {
      existingWarning.remove();
    }
    
    const warningBanner = document.createElement('div');
    warningBanner.id = 'phishguard-url-warning';
    warningBanner.style.position = 'fixed';
    warningBanner.style.top = '0';
    warningBanner.style.left = '0';
    warningBanner.style.right = '0';
    warningBanner.style.backgroundColor = '#ff3b30';
    warningBanner.style.color = 'white';
    warningBanner.style.padding = '12px';
    warningBanner.style.textAlign = 'center';
    warningBanner.style.zIndex = '2147483647';
    warningBanner.style.fontSize = '14px';
    
    const urlHost = new URL(url).hostname;
    
    warningBanner.innerHTML = `
      <div style="display: flex; justify-content: space-between; align-items: center;">
        <div style="flex-grow: 1;">
          <strong>⚠️ Suspicious URL Detected!</strong> 
          <span>${urlHost} has been identified as potentially dangerous (${confidencePct}% risk)</span>
        </div>
        <div id="phishguard-close-url-warning" style="cursor: pointer; padding: 0 10px; font-size: 20px;">✕</div>
      </div>
    `;
    
    document.body.appendChild(warningBanner);
    
    document.getElementById('phishguard-close-url-warning').addEventListener('click', () => {
      warningBanner.remove();
    });
    
    setTimeout(() => {
      if (document.body.contains(warningBanner)) {
        warningBanner.remove();
      }
    }, 15000);
  } catch (e) {}
}

function updateSiteStatus() {
  const threatCount = document.querySelectorAll('.phishguard-marked').length;
  const siteStatusElement = document.querySelector('.site-status-indicator');
  
  if (siteStatusElement && threatCount > 0) {
    siteStatusElement.innerHTML = `⚠️ ${threatCount} threat${threatCount > 1 ? 's' : ''} detected`;
    siteStatusElement.classList.remove('status-safe');
    siteStatusElement.classList.add('status-threat');
  }
}

document.addEventListener('DOMContentLoaded', updateSiteStatus);

window.addEventListener('load', () => {
  initSafely();
  
  if (window.location.href.startsWith('http')) {
    trySendMessage({
      type: 'checkPageSafety',
      url: window.location.href
    }, response => {
      if (response && response.result && response.result.isPhishing) {
        showFullPageWarning(response.result);
      }
    });
  }
});

function showFullPageWarning(result) {
  try {
    const warningModal = document.createElement('div');
    warningModal.style.position = 'fixed';
    warningModal.style.top = '0';
    warningModal.style.left = '0';
    warningModal.style.width = '100%';
    warningModal.style.height = '100%';
    warningModal.style.backgroundColor = 'rgba(0, 0, 0, 0.85)';
    warningModal.style.zIndex = '2147483647';
    warningModal.style.display = 'flex';
    warningModal.style.flexDirection = 'column';
    warningModal.style.alignItems = 'center';
    warningModal.style.justifyContent = 'center';
    warningModal.style.color = 'white';
    warningModal.style.textAlign = 'center';
    warningModal.style.padding = '20px';
    
    const confidencePct = Math.round(result.confidence * 100);
    
    warningModal.innerHTML = `
      <div style="max-width: 600px; background-color: #222; padding: 30px; border-radius: 8px; border: 2px solid #ff3b30;">
        <div style="font-size: 80px; margin-bottom: 20px;">⚠️</div>
        <h1 style="color: #ff3b30; margin-bottom: 15px; font-size: 28px;">PHISHING ALERT</h1>
        <p style="font-size: 18px; margin-bottom: 20px;">This website has been detected as a potential phishing site with ${confidencePct}% confidence.</p>
        <p style="font-size: 14px; margin-bottom: 30px;">Continuing to this site may put your personal information at risk. We recommend leaving immediately.</p>
        <div style="display: flex; justify-content: center; gap: 15px;">
          <button id="phishguard-back-button" style="padding: 10px 25px; background-color: #ff3b30; color: white; border: none; border-radius: 4px; font-weight: bold; cursor: pointer;">Go Back to Safety</button>
          <button id="phishguard-continue-button" style="padding: 10px 25px; background-color: transparent; color: #ccc; border: 1px solid #ccc; border-radius: 4px; cursor: pointer;">Continue at My Own Risk</button>
        </div>
        <div style="margin-top: 30px; font-size: 12px; color: #888;">
          Detected by PhishGuard Pro | ${result.source || 'AI Detection'}
        </div>
      </div>
    `;
    
    document.body.appendChild(warningModal);
    
    document.getElementById('phishguard-back-button').addEventListener('click', () => {
      window.history.back();
    });
    
    document.getElementById('phishguard-continue-button').addEventListener('click', () => {
      warningModal.remove();
      
      const minimizedWarning = document.createElement('div');
      minimizedWarning.style.position = 'fixed';
      minimizedWarning.style.top = '10px';
      minimizedWarning.style.right = '10px';
      minimizedWarning.style.backgroundColor = '#ff3b30';
      minimizedWarning.style.color = 'white';
      minimizedWarning.style.padding = '8px 15px';
      minimizedWarning.style.borderRadius = '4px';
      minimizedWarning.style.zIndex = '2147483646';
      minimizedWarning.style.fontSize = '12px';
      minimizedWarning.style.fontWeight = 'bold';
      minimizedWarning.style.cursor = 'pointer';
      minimizedWarning.innerText = '⚠️ Phishing Site Detected';
      
      minimizedWarning.addEventListener('click', () => {
        document.body.appendChild(warningModal);
      });
      
      document.body.appendChild(minimizedWarning);
    });
    
    trySendMessage({
      type: 'phishingFullPageDetection',
      url: window.location.href,
      confidence: result.confidence
    });
    
  } catch (e) {}
}
