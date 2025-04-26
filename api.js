const ML_API_ENDPOINT = process.env.API_ENDPOINT || 'https://phishguard-api.com/analyze';
const VIRUSTOTAL_API = 'https://www.virustotal.com/api/v3/urls';
const GEMINI_API = 'https://generativelanguage.googleapis.com/v1beta/models/gemini-pro:generateContent';
const MONGODB_API = 'https://data.mongodb-api.com/app/phishguard-api/endpoint/data';

const API_CONFIG = {
  endpoints: {
    ml: ML_API_ENDPOINT,
    virustotal: VIRUSTOTAL_API,
    gemini: GEMINI_API,
    mongodb: MONGODB_API,
    whois: 'https://www.whoisxmlapi.com/whoisserver/WhoisService'
  },
  apiKeys: {
    virustotal: process.env.VIRUSTOTAL_API_KEY || '',
    gemini: process.env.GEMINI_API_KEY || '',
    whois: process.env.WHOIS_API_KEY || '',
    mongodb: process.env.MONGODB_API_KEY || ''
  }
};

class PhishingAPI {
  static async checkUrl(url) {
    try {
      const virusTotalResult = await this.checkVirusTotal(url);
      if (virusTotalResult.isPhishing) {
        return { 
          isPhishing: true, 
          confidence: 0.95, 
          source: 'virustotal',
          details: virusTotalResult.details || 'Detected by VirusTotal'
        };
      }
      
      const urlFeatures = this.extractUrlFeatures(url);
      const mlResult = await this.analyzeMachineLearning({
        type: 'url',
        content: url,
        features: urlFeatures
      });
      
      const geminiResult = await this.analyzeWithGemini({
        type: 'url',
        content: url
      });
      
      if (geminiResult.isPhishing) {
        return {
          isPhishing: true,
          confidence: Math.max(mlResult.confidence, geminiResult.confidence),
          source: 'gemini+ml',
          details: 'URL analysis'
        };
      }
      
      return mlResult;
    } catch (error) {
      console.error('Error checking URL:', error);
      return { isPhishing: false, confidence: 0, error: error.message };
    }
  }

  static async analyzeContent(data) {
    try {
      const mlResult = await this.analyzeMachineLearning(data);
      
      if (mlResult.confidence > 0.6) {
        const geminiResult = await this.analyzeWithGemini(data);
        
        const combinedConfidence = (mlResult.confidence * 0.7) + (geminiResult.confidence * 0.3);
        return {
          isPhishing: combinedConfidence > 0.6,
          confidence: combinedConfidence,
          source: 'gemini+ml',
          details: data.type + ' analysis'
        };
      }
      
      return mlResult;
    } catch (error) {
      console.error('Error analyzing content:', error);
      return { isPhishing: false, confidence: 0, error: error.message };
    }
  }

  static async checkVirusTotal(url) {
    try {
      const VIRUSTOTAL_KEY = process.env.VIRUSTOTAL_API_KEY || '';
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
      const urlId = submitData.data.links.self.split('/').pop();
      
      const resultResponse = await fetch(`${VIRUSTOTAL_API}/analyses/${analysisId}`, {
        method: 'GET',
        headers: { 'x-apikey': VIRUSTOTAL_KEY }
      });
      
      if (!resultResponse.ok) return { isPhishing: false };
      
      const resultData = await resultResponse.json();
      const attributes = resultData.data.attributes;
      const stats = attributes.stats;
      
      if (stats.malicious > 0 || stats.suspicious > 0) {
        return {
          isPhishing: true,
          confidence: Math.min((stats.malicious * 0.1) + (stats.suspicious * 0.05) + 0.6, 0.98),
          details: `VirusTotal: ${stats.malicious} engines detected as malicious`
        };
      }
      
      const urlInfoResponse = await fetch(`${VIRUSTOTAL_API}/${urlId}`, {
        method: 'GET',
        headers: { 'x-apikey': VIRUSTOTAL_KEY }
      });
      
      if (!urlInfoResponse.ok) return { isPhishing: false };
      
      const urlInfo = await urlInfoResponse.json();
      const categories = urlInfo.data.attributes?.categories || {};
      
      const badCategories = [
        'phishing', 'malicious', 'malware', 'suspicious', 'spam'
      ];
      
      for (const [engine, category] of Object.entries(categories)) {
        if (badCategories.some(bad => category.toLowerCase().includes(bad))) {
          return {
            isPhishing: true,
            confidence: 0.9,
            details: `VirusTotal: Categorized as ${category} by ${engine}`
          };
        }
      }
      
      return { isPhishing: false };
    } catch (error) {
      console.error('VirusTotal API error:', error);
      return { isPhishing: false };
    }
  }
  
  static async analyzeWithGemini(data) {
    try {
      const GEMINI_KEY = process.env.GEMINI_API_KEY || '';
      if (!GEMINI_KEY) return { isPhishing: false, confidence: 0 };
      
      let prompt = '';
      
      if (data.type === 'url') {
        prompt = `Analyze this URL for phishing indicators. Return JSON format only with properties: isPhishing (boolean), confidence (number between 0-1), and reason (text): ${data.content}`;
      } else if (data.type === 'text') {
        const content = data.content.slice(0, 2000);
        prompt = `Analyze this text from a webpage for phishing or scam indicators. Return JSON format only with properties: isPhishing (boolean), confidence (number between 0-1), and reason (text): ${content}`;
      } else if (data.type === 'form') {
        prompt = `Analyze this form data for phishing indicators. Return JSON format only with properties: isPhishing (boolean), confidence (number between 0-1), and reason (text): ${JSON.stringify(data.content)}`;
      }
      
      const response = await fetch(`${GEMINI_API}?key=${GEMINI_KEY}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          contents: [{
            parts: [{
              text: prompt
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
            details: jsonData.reason || 'Gemini analysis'
          };
        }
      } catch (e) {}
      
      return { 
        isPhishing: text.toLowerCase().includes('phishing') && text.toLowerCase().includes('suspicious'),
        confidence: 0.5,
        details: 'Gemini analysis (parsed)'
      };
    } catch (error) {
      console.error('Gemini API error:', error);
      return { isPhishing: false, confidence: 0 };
    }
  }
  
  static extractUrlFeatures(url) {
    try {
      const parsedUrl = new URL(url);
      
      return {
        domainLength: parsedUrl.hostname.length,
        pathLength: parsedUrl.pathname.length,
        numDots: parsedUrl.hostname.split('.').length - 1,
        numDashes: parsedUrl.hostname.split('-').length - 1,
        hasHttps: parsedUrl.protocol === 'https:',
        numParams: parsedUrl.searchParams.toString().length,
        hasSuspiciousWords: /login|account|secure|verify|bank|update|confirm/.test(url.toLowerCase()),
        numSpecialChars: (url.match(/[^a-zA-Z0-9-.]/g) || []).length
      };
    } catch (e) {
      return {};
    }
  }
  
  static async analyzeMachineLearning(data) {
    try {
      const response = await fetch(API_CONFIG.endpoints.ml, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data)
      });
      
      if (!response.ok) {
        return this.runLocalML(data);
      }
      
      return await response.json();
    } catch (error) {
      console.error('ML API error:', error);
      return this.runLocalML(data);
    }
  }
  
  static async storeResultInMongoDB(data) {
    if (!API_CONFIG.apiKeys.mongodb) {
      return;
    }
    
    try {
      await fetch(`${API_CONFIG.endpoints.mongodb}/insertOne`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'api-key': API_CONFIG.apiKeys.mongodb
        },
        body: JSON.stringify({
          collection: 'detection_results',
          database: 'phishguard',
          dataSource: 'PhishGuard-Cluster',
          document: data
        })
      });
    } catch (error) {
      console.error('MongoDB API error:', error);
    }
  }
  
  static runLocalML(data) {
    try {
      if (data.type === 'url') {
        return this.urlML(data.features || this.extractUrlFeatures(data.content));
      } else if (data.type === 'text') {
        return this.textML(data.features || this.extractTextFeatures(data.content));
      } else if (data.type === 'form') {
        return this.formML(data.features || this.extractFormFeatures(data.content));
      }
      
      return { isPhishing: false, confidence: 0.1, source: 'local-fallback' };
    } catch (error) {
      return { isPhishing: false, confidence: 0, source: 'error-handler' };
    }
  }
  
  static urlML(features) {
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
  }
  
  static textML(features) {
    let score = 0;
    
    if (features.hasSuspiciousWords) score += 0.3;
    if (features.capitalRatio > 0.3) score += 0.2;
    if (features.specialCharRatio > 0.1) score += 0.1;
    if (features.urgencyIndicators > 2) score += 0.25;
    
    return {
      isPhishing: score > 0.5,
      confidence: Math.min(score, 0.9),
      source: 'local-ml'
    };
  }
  
  static formML(features) {
    let score = 0;
    
    if (features.hasPasswordField) score += 0.25;
    if (features.hasLoginField) score += 0.15;
    if (!features.domainMatch) score += 0.3;
    if (!features.isSecureConnection) score += 0.3;
    
    return {
      isPhishing: score > 0.5,
      confidence: Math.min(score, 0.95),
      source: 'local-ml'
    };
  }
}

class MockPhishingAPI {
  static async checkUrl(url) {
    await new Promise(resolve => setTimeout(resolve, 300));
    
    const isSuspicious = url.includes('login') && (
      url.includes('verify') || 
      url.includes('secure') || 
      url.includes('account')
    );
    
    return {
      isPhishing: isSuspicious || Math.random() < 0.1,
      confidence: isSuspicious ? 0.85 : 0.3,
      source: 'mock-api',
      details: 'Mock detection response'
    };
  }

  static async analyzeContent(data) {
    await new Promise(resolve => setTimeout(resolve, 500));
    
    let confidence = 0.1;
    let isPhishing = false;
    
    if (data.type === 'text') {
      const text = data.content.toLowerCase();
      if (text.includes('password') && 
          (text.includes('verify') || text.includes('confirm') || text.includes('login'))) {
        confidence = 0.75;
        isPhishing = true;
      }
    } else if (data.type === 'form') {
      if (data.content.hasPassword && data.content.domain !== new URL(data.content.action).hostname) {
        confidence = 0.9;
        isPhishing = true;
      }
    } else if (data.type === 'url') {
      return await this.checkUrl(data.content);
    }
    
    return {
      isPhishing,
      confidence,
      source: 'mock-api'
    };
  }
}

const PhishingDetector = process.env.NODE_ENV === 'production' ? PhishingAPI : PhishingAPI;

export default PhishingDetector;
