const API_ENDPOINT = 'https://phishguard-api.com/analyze';
const VIRUSTOTAL_API = 'https://www.virustotal.com/api/v3/urls';
const GEMINI_API = 'https://generativelanguage.googleapis.com/v1beta/models/gemini-pro:generateContent';

let detectionStats = {
  totalScanned: 0,
  phishingDetected: 0,
  lastDetection: null
};

let detectionHistory = [];
let cachedResults = new Map();
let backgroundScanActive = false;
let scanQueue = [];
let VIRUSTOTAL_KEY = '';
let GEMINI_KEY = '';

try {
  const fs = require('fs');
  const path = require('path');
  
  const envPath = path.join(__dirname, '.env');
  if (fs.existsSync(envPath)) {
    const envContent = fs.readFileSync(envPath, 'utf8');
    const envLines = envContent.split('\n');
    
    for (const line of envLines) {
      const vtMatch = line.match(/^VIRUSTOTAL_API_KEY=(.+)$/);
      if (vtMatch) {
        VIRUSTOTAL_KEY = vtMatch[1];
      }
      
      const gmMatch = line.match(/^GEMINI_API_KEY=(.+)$/);
      if (gmMatch) {
        GEMINI_KEY = gmMatch[1];
      }
    }
  }
} catch (e) {}

chrome.storage.local.get(['apiKeys'], (data) => {
  if (data.apiKeys) {
    if (data.apiKeys.virustotal) {
      VIRUSTOTAL_KEY = data.apiKeys.virustotal;
    }
    if (data.apiKeys.gemini) {
      GEMINI_KEY = data.apiKeys.gemini;
    }
  }
});

chrome.runtime.onInstalled.addListener(() => {
  chrome.storage.local.set({ 
    detectionStats,
    detectionHistory: [],
    scanEnabled: true,
    detectionLevel: 'medium',
    notificationsEnabled: true,
    backgroundScanEnabled: true,
    apiKeys: {
      virustotal: VIRUSTOTAL_KEY,
      gemini: GEMINI_KEY
    }
  });
  
  initWeeklyStats();
  setupAlarms();
});

chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === 'cleanCache') {
    cleanCache();
  }
  else if (alarm.name === 'backgroundScan') {
    startBackgroundScan();
  }
});

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === 'complete' && tab.url?.startsWith('http')) {
    chrome.storage.local.get(['backgroundScanEnabled'], (data) => {
      if (data.backgroundScanEnabled !== false) {
        queueBackgroundScan(tabId, tab.url);
      }
    });
  }
});

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === 'checkUrl') {
    checkUrl(message.url)
      .then(result => sendResponse({ result }))
      .catch(error => sendResponse({ error: error.message }));
    return true;
  } 
  else if (message.type === 'analyzeContent') {
    analyzeContent(message.data)
      .then(result => sendResponse({ result }))
      .catch(error => sendResponse({ error: error.message }));
    return true;
  }
  else if (message.type === 'getStats') {
    chrome.storage.local.get(['detectionStats'], (data) => {
      sendResponse({ stats: data.detectionStats });
    });
    return true;
  }
  else if (message.type === 'scanPage') {
    queueBackgroundScan(sender.tab?.id, sender.tab?.url);
    sendResponse({ success: true });
    return true;
  }
  else if (message.type === 'toggleBackgroundScan') {
    chrome.storage.local.set({ backgroundScanEnabled: message.enabled });
    sendResponse({ success: true });
    return true;
  }
  else if (message.type === 'checkApiStatus') {
    sendResponse({ 
      status: {
        virusTotal: !!VIRUSTOTAL_KEY,
        gemini: !!GEMINI_KEY
      }
    });
    return true;
  }
  else if (message.type === 'showNotification') {
    chrome.notifications.create(`phishing-url-${Date.now()}`, {
      type: 'basic',
      iconUrl: 'images/icon128.png',
      title: 'Suspicious URL Detected',
      message: `PhishGuard has detected a suspicious URL with ${message.confidence}% confidence: ${new URL(message.url).hostname}`,
      priority: 2
    });
    sendResponse({ success: true });
    return true;
  }
  else if (message.type === 'logThreatDetection') {
    logThreatDetection(
      message.threatType, 
      message.platform, 
      message.url
    );
    sendResponse({ success: true });
    return true;
  }
  else if (message.type === 'phishingFullPageDetection') {
    logPhishingDetection(
      message.url,
      message.confidence,
      'full_page'
    );
    sendResponse({ success: true });
    return true;
  }
  else if (message.type === 'checkPageSafety') {
    checkUrl(message.url)
      .then(result => sendResponse({ result }))
      .catch(error => sendResponse({ error: error.message }));
    return true;
  }
});

function setupAlarms() {
  chrome.alarms.create('cleanCache', { periodInMinutes: 15 });
  chrome.alarms.create('backgroundScan', { periodInMinutes: 1 });
}

function cleanCache() {
  const now = Date.now();
  for (const [url, data] of cachedResults.entries()) {
    if (now - data.timestamp > 30 * 60 * 1000) {
      cachedResults.delete(url);
    }
  }
}

function queueBackgroundScan(tabId, url) {
  if (tabId && url) {
    const scanItem = { tabId, url, timestamp: Date.now() };
    
    const existingIndex = scanQueue.findIndex(item => item.tabId === tabId);
    if (existingIndex >= 0) {
      scanQueue[existingIndex] = scanItem;
    } else {
      scanQueue.push(scanItem);
    }
    
    if (!backgroundScanActive) {
      startBackgroundScan();
    }
  }
}

async function startBackgroundScan() {
  if (backgroundScanActive || scanQueue.length === 0) {
    return;
  }
  
  backgroundScanActive = true;
  
  const scanItem = scanQueue.shift();
  const { tabId, url } = scanItem;

  try {
    const result = await checkUrl(url);
    
    if (result.isPhishing) {
      chrome.action.setBadgeText({ text: '!', tabId });
      chrome.action.setBadgeBackgroundColor({ color: '#ff0000', tabId });
      
      chrome.storage.local.get(['notificationsEnabled'], (data) => {
        if (data.notificationsEnabled !== false) {
          chrome.notifications.create(`phishing-${Date.now()}`, {
            type: 'basic',
            iconUrl: 'images/icon128.png',
            title: 'Phishing Detected!',
            message: `A phishing attempt was detected on: ${new URL(url).hostname}`,
            priority: 2
          });
        }
      });
      
      try {
        chrome.tabs.sendMessage(tabId, { 
          type: 'phishingDetected', 
          url: url,
          confidence: result.confidence
        });
      } catch (e) {}
    } else {
      chrome.action.setBadgeText({ text: '', tabId });
    }
  } catch (error) {
    console.error('Background scan error:', error);
  }
  
  backgroundScanActive = false;
  
  if (scanQueue.length > 0) {
    setTimeout(startBackgroundScan, 500);
  }
}

async function checkUrl(url) {
  try {
    if (cachedResults.has(url)) {
      const cached = cachedResults.get(url);
      if (Date.now() - cached.timestamp < 30 * 60 * 1000) {
        return cached.result;
      }
    }
    
    const data = await new Promise(resolve => 
      chrome.storage.local.get(['detectionLevel', 'apiKeys'], resolve)
    );
    
    let threshold = 0.5;
    if (data.detectionLevel === 'low') threshold = 0.7;
    if (data.detectionLevel === 'high') threshold = 0.3;
    
    if (data.apiKeys) {
      VIRUSTOTAL_KEY = data.apiKeys.virustotal || VIRUSTOTAL_KEY;
      GEMINI_KEY = data.apiKeys.gemini || GEMINI_KEY;
    }
    
    let result = null;
    
    if (VIRUSTOTAL_KEY) {
      result = await checkVirusTotal(url);
      if (result.isPhishing) {
        cachedResults.set(url, {
          result,
          timestamp: Date.now()
        });
        
        updateStats(result.isPhishing, url, 'url', result.confidence);
        return result;
      }
    }
    
    if (GEMINI_KEY) {
      result = await checkWithGemini(url);
      if (result.isPhishing && result.confidence > threshold) {
        cachedResults.set(url, {
          result,
          timestamp: Date.now()
        });
        
        updateStats(result.isPhishing, url, 'url', result.confidence);
        return result;
      }
    }
    
    result = analyzeUrlLocally(url);
    
    if (result.confidence < threshold) {
      result.isPhishing = false;
    }
    
    cachedResults.set(url, {
      result,
      timestamp: Date.now()
    });
    
    updateStats(result.isPhishing, url, 'url', result.confidence);
    return result;
  } catch (error) {
    console.error('Error checking URL:', error);
    return { isPhishing: false, confidence: 0, source: 'error', error: error.message };
  }
}

async function checkVirusTotal(url) {
  try {
    if (!VIRUSTOTAL_KEY) return { isPhishing: false };
    
    const formData = new URLSearchParams();
    formData.append('url', url);
    
    const submitResponse = await fetch(VIRUSTOTAL_API, {
      method: 'POST',
      headers: {
        'x-apikey': VIRUSTOTAL_KEY,
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      body: formData
    });
    
    if (!submitResponse.ok) return { isPhishing: false };
    
    const submitData = await submitResponse.json();
    const analysisId = submitData.data.id;
    
    await new Promise(resolve => setTimeout(resolve, 2000));
    
    const resultResponse = await fetch(`${VIRUSTOTAL_API}/${analysisId}`, {
      method: 'GET',
      headers: { 'x-apikey': VIRUSTOTAL_KEY }
    });
    
    if (!resultResponse.ok) return { isPhishing: false };
    
    const resultData = await resultResponse.json();
    const attributes = resultData.data.attributes;
    const stats = attributes.stats;
    const engines = attributes.results || {};
    
    const maliciousSources = [];
    for (const [engine, result] of Object.entries(engines)) {
      if (result.category === 'malicious') {
        maliciousSources.push(engine);
      }
    }
    
    const isPhishing = stats.malicious > 0 || 
                     stats.suspicious > 0 || 
                     (attributes.categories && 
                     Object.values(attributes.categories).some(cat => 
                       cat.toLowerCase().includes('phish') || 
                       cat.toLowerCase().includes('malicious')
                     ));
    
    if (isPhishing) {
      const confidence = Math.min(0.6 + (stats.malicious * 0.05) + (stats.suspicious * 0.025), 0.95);
      
      return {
        isPhishing: true,
        confidence,
        details: maliciousSources.length > 0 ? 
          `Flagged by: ${maliciousSources.join(', ')}` : 
          'Flagged by VirusTotal'
      };
    }
    
    return { isPhishing: false };
  } catch (error) {
    return { isPhishing: false };
  }
}

async function checkWithGemini(url) {
  try {
    if (!GEMINI_KEY) return { isPhishing: false, confidence: 0 };
    
    const response = await fetch(`${GEMINI_API}?key=${GEMINI_KEY}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        contents: [{
          parts: [{
            text: `Analyze this URL for phishing indicators. Return JSON format only with properties: isPhishing (boolean), confidence (number between 0-1), and reason (text): ${url}`
          }]
        }],
        generationConfig: {
          temperature: 0.1,
          topK: 16,
          topP: 0.1,
          maxOutputTokens: 256
        }
      })
    });
    
    if (!response.ok) return { isPhishing: false, confidence: 0 };
    
    const result = await response.json();
    const text = result.candidates?.[0]?.content?.parts?.[0]?.text || '';
    
    try {
      const jsonMatch = text.match(/(\{[\s\S]*\})/);
      if (jsonMatch) {
        const jsonData = JSON.parse(jsonMatch[0]);
        return {
          isPhishing: jsonData.isPhishing === true,
          confidence: typeof jsonData.confidence === 'number' ? jsonData.confidence : 0,
          source: 'gemini',
          details: jsonData.reason || 'URL analysis'
        };
      }
    } catch (e) {}
    
    return { isPhishing: false, confidence: 0 };
  } catch (error) {
    console.error('Gemini API error:', error);
    return { isPhishing: false, confidence: 0 };
  }
}

function analyzeUrlLocally(url) {
  try {
    const parsedUrl = new URL(url);
    const features = {
      domainLength: parsedUrl.hostname.length,
      pathLength: parsedUrl.pathname.length,
      numDots: parsedUrl.hostname.split('.').length - 1,
      numDashes: parsedUrl.hostname.split('-').length - 1,
      hasHttps: parsedUrl.protocol === 'https:',
      numParams: parsedUrl.searchParams.toString().length,
      hasSuspiciousWords: /login|account|secure|verify|bank|update|confirm/.test(url.toLowerCase()),
      numSpecialChars: (url.match(/[^a-zA-Z0-9-.]/g) || []).length
    };
    
    let score = 0;
    
    if (features.domainLength > 20) score += 0.2;
    if (features.numDots > 3) score += 0.2;
    if (features.numDashes > 2) score += 0.2;
    if (!features.hasHttps) score += 0.15;
    if (features.hasSuspiciousWords) score += 0.3;
    if (features.numSpecialChars > 5) score += 0.2;
    
    return {
      isPhishing: score > 0.5,
      confidence: Math.min(score, 0.95),
      source: 'local-ml'
    };
  } catch (e) {
    return { isPhishing: false, confidence: 0, source: 'error' };
  }
}

async function analyzeContent(data) {
  try {
    const storageData = await new Promise(resolve => 
      chrome.storage.local.get(['detectionLevel', 'apiKeys'], resolve)
    );
    
    let threshold = 0.5;
    if (storageData.detectionLevel === 'low') threshold = 0.7;
    if (storageData.detectionLevel === 'high') threshold = 0.3;
    
    if (storageData.apiKeys) {
      GEMINI_KEY = storageData.apiKeys.gemini || GEMINI_KEY;
    }
    
    let result;
    
    if (data.type === 'text') {
      result = analyzeTextLocally(data.content);
      
      if (result.confidence > 0.4 && GEMINI_KEY) {
        try {
          const geminiResult = await checkTextWithGemini(data.content);
          if (geminiResult) {
            const combinedConfidence = (result.confidence * 0.6) + (geminiResult.confidence * 0.4);
            result = {
              isPhishing: combinedConfidence > threshold,
              confidence: combinedConfidence,
              source: 'gemini+local',
              details: geminiResult.details || result.details
            };
          }
        } catch (e) {}
      }
      
      if (data.patternMatches) {
        result.confidence = Math.min(result.confidence + (data.patternMatches * 0.05), 1.0);
      }
      
      if (result.confidence < threshold + 0.1) {
        result.isPhishing = false;
      }
    } else if (data.type === 'form') {
      result = analyzeFormLocally(data.content);
      
      if (data.content.suspiciousScore) {
        result.confidence = Math.min(0.4 + (data.content.suspiciousScore * 0.1), 1.0);
        result.isPhishing = result.confidence > threshold;
      }
    } else if (data.type === 'image') {
      result = { isPhishing: false, confidence: 0, source: 'local-image-analysis' };
    } else {
      result = { isPhishing: false, confidence: 0 };
    }
    
    if (result.confidence < threshold) {
      result.isPhishing = false;
    }
    
    updateStats(result.isPhishing, data.url, data.type, result.confidence);
    return result;
  } catch (error) {
    return { isPhishing: false, confidence: 0, error: error.message };
  }
}

async function checkTextWithGemini(text) {
  try {
    if (!GEMINI_KEY) return null;
    
    const response = await fetch(`${GEMINI_API}?key=${GEMINI_KEY}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        contents: [{
          parts: [{
            text: `Analyze this text from a webpage for phishing indicators. Return JSON format only with properties: isPhishing (boolean), confidence (number between 0-1), and reason (text): ${text.slice(0, 1500)}`
          }]
        }],
        generationConfig: {
          temperature: 0.1,
          topK: 16,
          topP: 0.1,
          maxOutputTokens: 256
        }
      })
    });
    
    if (!response.ok) return null;
    
    const result = await response.json();
    const responseText = result.candidates?.[0]?.content?.parts?.[0]?.text || '';
    
    try {
      const jsonMatch = responseText.match(/(\{[\s\S]*\})/);
      if (jsonMatch) {
        const jsonData = JSON.parse(jsonMatch[0]);
        return {
          isPhishing: jsonData.isPhishing === true,
          confidence: typeof jsonData.confidence === 'number' ? jsonData.confidence : 0,
          details: jsonData.reason || 'Gemini text analysis'
        };
      }
    } catch (e) {}
    
    return null;
  } catch (error) {
    return null;
  }
}

function analyzeTextLocally(text) {
  const lowerText = text.toLowerCase();
  
  if (text.length < 200 || text.split(' ').length < 30) {
    return { isPhishing: false, confidence: 0.1, source: 'local-ml' };
  }
  
  const searchPatterns = [
    /search results for/i,
    /results for/i,
    /sponsored/i,
    /advertisement/i,
    /\d+ results/i,
    /people also ask/i,
    /related searches/i
  ];
  
  for (const pattern of searchPatterns) {
    if (pattern.test(lowerText)) {
      return { isPhishing: false, confidence: 0.05, source: 'local-ml' };
    }
  }
  
  let score = 0;
  
  const phishingPatterns = [
    { pattern: /verify.*account|account.*verify/i, weight: 0.12 },
    { pattern: /confirm.*identity|identity.*confirm/i, weight: 0.15 },
    { pattern: /update.*payment|payment.*update/i, weight: 0.18 },
    { pattern: /unusual.*activity|suspicious.*activity/i, weight: 0.2 },
    { pattern: /limited.*access|account.*suspended/i, weight: 0.25 },
    { pattern: /password.*expired|reset.*password.*now/i, weight: 0.15 },
    { pattern: /security.*alert|urgent.*action/i, weight: 0.17 },
    { pattern: /(enter|verify|confirm|validate).*card details/i, weight: 0.3 },
    { pattern: /click.*here.*login/i, weight: 0.1 },
    { pattern: /account.*terminated|reactivate.*account/i, weight: 0.22 },
    { pattern: /bank.*transfer|wire.*transfer/i, weight: 0.14 },
    { pattern: /(100|1000)%.*guarantee/i, weight: 0.08 },
    { pattern: /limited.*time.*offer/i, weight: 0.07 },
    { pattern: /(won|winner|winning|lottery|prize).*(million|billion)/i, weight: 0.35 },
    { pattern: /dear.*customer/i, weight: 0.1 },
    { pattern: /final.*warning|last.*notice/i, weight: 0.2 }
  ];
  
  for (const {pattern, weight} of phishingPatterns) {
    if (pattern.test(lowerText)) {
      score += weight;
    }
  }
  
  const urgencyWords = ['urgent', 'immediately', 'alert', 'warning', 'attention', 'important', 'now', 'critical'];
  for (const word of urgencyWords) {
    const regex = new RegExp(`\\b${word}\\b`, 'gi');
    const matches = lowerText.match(regex);
    if (matches) {
      score += matches.length * 0.03;
    }
  }
  
  if (/please do not (ignore|delay)/i.test(lowerText)) {
    score += 0.1;
  }
  
  if (/dear (valued|customer|user)/i.test(lowerText) && 
      /thank you for your/i.test(lowerText) && 
      /sincerely|regards|team/i.test(lowerText)) {
    score += 0.25;
  }
  
  return {
    isPhishing: score > 0.5,
    confidence: Math.min(score, 0.95),
    source: 'local-ml'
  };
}

function analyzeFormLocally(formData) {
  let score = 0;
  
  if (formData.hasPassword) score += 0.3;
  if (formData.hasCardFields) score += 0.4;
  if (formData.hasLoginField) score += 0.2;
  
  try {
    const formDomain = new URL(formData.action).hostname;
    if (formDomain !== formData.domain) score += 0.3;
    if (!formData.action.startsWith('https')) score += 0.3;
  } catch (e) {
    score += 0.2;
  }
  
  if (formData.suspiciousScore) {
    score = Math.max(score, 0.3 + (formData.suspiciousScore * 0.1));
  }
  
  return {
    isPhishing: score > 0.5,
    confidence: Math.min(score, 0.95),
    source: 'local-ml'
  };
}

function updateStats(isPhishing, url = '', type = '', confidence = 0) {
  chrome.storage.local.get(['detectionStats', 'detectionHistory', 'weeklyStats'], (data) => {
    const stats = data.detectionStats || detectionStats;
    const history = data.detectionHistory || [];
    stats.totalScanned++;
    
    const weeklyStats = data.weeklyStats || generateEmptyWeeklyData();
    const currentDay = new Date().toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
    const dayIndex = weeklyStats.labels.indexOf(currentDay);
    
    if (dayIndex !== -1) {
      weeklyStats.scans[dayIndex]++;
    }
    
    if (isPhishing) {
      stats.phishingDetected++;
      stats.lastDetection = new Date().toISOString();
      
      const detectionData = {
        timestamp: new Date().toISOString(),
        url: url,
        type: type,
        confidence: confidence,
        action: 'Detected'
      };
      
      history.push(detectionData);
      
      if (history.length > 1000) {
        history.splice(0, history.length - 1000);
      }
      
      if (dayIndex !== -1) {
        weeklyStats.detections[dayIndex]++;
      }
    }
    
    chrome.storage.local.set({ 
      detectionStats: stats,
      detectionHistory: history,
      weeklyStats: weeklyStats
    });
  });
}

function initWeeklyStats() {
  chrome.storage.local.get(['weeklyStats'], (data) => {
    if (!data.weeklyStats) {
      chrome.storage.local.set({ 
        weeklyStats: generateEmptyWeeklyData()
      });
    }
  });
}

function generateEmptyWeeklyData() {
  const labels = [];
  const scans = [];
  const detections = [];
  
  for (let i = 6; i >= 0; i--) {
    const date = new Date();
    date.setDate(date.getDate() - i);
    
    labels.push(date.toLocaleDateString('en-US', { month: 'short', day: 'numeric' }));
    scans.push(0);
    detections.push(0);
  }
  
  return { labels, scans, detections };
}

function logThreatDetection(threatType, platform, url) {
  chrome.storage.local.get(['detectionStats', 'threatStats'], (data) => {
    const stats = data.detectionStats || detectionStats;
    
    const threatStats = data.threatStats || {
      byType: {},
      byPlatform: {}
    };
    
    stats.phishingDetected++;
    
    if (!threatStats.byType[threatType]) {
      threatStats.byType[threatType] = 1;
    } else {
      threatStats.byType[threatType]++;
    }
    
    if (!threatStats.byPlatform[platform]) {
      threatStats.byPlatform[platform] = 1;
    } else {
      threatStats.byPlatform[platform]++;
    }
    
    chrome.storage.local.set({
      detectionStats: stats,
      threatStats: threatStats
    });
    
    const detectionData = {
      timestamp: new Date().toISOString(),
      url: url,
      type: 'message',
      threatType: threatType,
      platform: platform,
      action: 'Detected'
    };
    
    chrome.storage.local.get(['detectionHistory'], (histData) => {
      const history = histData.detectionHistory || [];
      history.push(detectionData);
      
      if (history.length > 1000) {
        history.splice(0, history.length - 1000);
      }
      
      chrome.storage.local.set({ 
        detectionHistory: history
      });
    });
  });
}

function logPhishingDetection(url, confidence, detectionType) {
  chrome.storage.local.get(['detectionStats', 'detectionHistory', 'weeklyStats'], (data) => {
    const stats = data.detectionStats || detectionStats;
    const history = data.detectionHistory || [];
    
    stats.phishingDetected++;
    stats.lastDetection = new Date().toISOString();
    
    const weeklyStats = data.weeklyStats || generateEmptyWeeklyData();
    const currentDay = new Date().toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
    const dayIndex = weeklyStats.labels.indexOf(currentDay);
    
    if (dayIndex !== -1) {
      weeklyStats.detections[dayIndex]++;
    }
    
    const detectionData = {
      timestamp: new Date().toISOString(),
      url: url,
      type: detectionType,
      confidence: confidence,
      action: 'Blocked'
    };
    
    history.push(detectionData);
    
    if (history.length > 1000) {
      history.splice(0, history.length - 1000);
    }
    
    chrome.storage.local.set({ 
      detectionStats: stats,
      detectionHistory: history,
      weeklyStats: weeklyStats
    });
  });
}
