# PhishGuard Pro

PhishGuard Pro is an AI-powered browser extension for real-time phishing detection across all websites, protecting users from sophisticated phishing attempts and social engineering attacks.

## Features

- Real-time webpage scanning for phishing indicators
- AI-powered detection system with machine learning capabilities
- Background scanning of sites as you browse
- Form submission protection for sensitive information
- Visual warnings for suspicious content
- VirusTotal API integration for verified threat detection
- Customizable detection sensitivity levels
- Comprehensive detection statistics and history
- Visual charts for detection activity monitoring

## Tech Stack

### Browser Extension
- JavaScript (ES6) – Core scanning logic
- Chrome Extension API (Manifest V3) – Browser integration
- MutationObserver API – For detecting live content changes
- Browser Notifications API – For real-time security alerts

### AI/ML Detection
- Local machine learning models for URL, text, and form analysis
- Classical ML features extraction for phishing detection
- NLP pattern recognition for social engineering detection
- VirusTotal API integration for known threats verification
- Gemini API for advanced language understanding 

### Data Storage
- Chrome Storage API for extension settings, history and caching

### Frontend
- Chart.js for detection statistics visualization
- Custom CSS for warning UI and extension popup

## Setup Instructions

1. **Clone the repository**
   ```
   git clone https://github.com/Rajendra0309/PhishGuard-Pro.git
   cd phishguard-pro
   ```

2. **Install dependencies**
   ```
   npm install
   ```

3. **Configure environment variables**
   - Create a `.env` file in the root directory
   - Add your VirusTotal API key:
     ```
     VIRUSTOTAL_API_KEY=your_api_key_here
     API_ENDPOINT=your_custom_api_endpoint (optional)
     GEMINI_API_KEY=your_gemini_api_key (optional)
     ```

4. **Build the extension**
   ```
   npm run build
   ```

5. **Load into Chrome**
   - Open Chrome and navigate to `chrome://extensions/`
   - Enable Developer Mode
   - Click "Load unpacked" and select the `dist` directory

## Usage

### Basic Usage
1. After installation, PhishGuard Pro automatically scans webpages as you browse
2. Look for the extension icon in your browser toolbar:
   - Normal: No threats detected
   - Red badge: Potential threat detected
3. Click the extension icon to see the current page status and protection settings

### Advanced Features
- Adjust detection sensitivity in the extension popup (Low/Medium/High)
- View comprehensive detection history and statistics in the History page
- Enable/disable notifications for threat alerts
- Use the "Scan Now" button to manually scan the current page

## Development

### Development Commands
- `npm run dev` - Build development version
- `npm run watch` - Build and watch for changes
- `npm run build` - Build production version

### Project Structure
```
phishguard-pro/
├── manifest.json     # Extension manifest
├── background.js     # Service worker background script
├── content.js        # Page content scanning script
├── popup.html/js/css # Extension popup interface
├── history.html/js   # Detection history interface
├── images/           # Extension icons and assets
└── dist/             # Build output directory
```

## Security Notes

PhishGuard Pro functions locally within your browser and only sends URLs to the VirusTotal API for verification. The extension does not collect personal data or browsing history for any purpose other than detecting phishing threats.