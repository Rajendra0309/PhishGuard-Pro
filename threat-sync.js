function synchronizeThreatDisplay() {
  try {
    chrome.runtime.sendMessage({ type: 'getStats' }, (response) => {
      if (response && response.stats) {
        updateThreatCounter(response.stats.phishingDetected || 0);
        updateSiteStatus();
      }
    });
  } catch (e) {}
}

function updateThreatCounter(count) {
  const popupThreatElement = document.querySelector('.threat-counter');
  if (popupThreatElement) {
    popupThreatElement.textContent = count.toString();
  }
}

function updateSiteStatus() {
  const threatCount = document.querySelectorAll('.phishguard-marked').length;
  const siteStatusElement = document.querySelector('.site-status-indicator');
  
  if (siteStatusElement) {
    if (threatCount > 0) {
      siteStatusElement.innerHTML = `⚠️ ${threatCount} threat${threatCount > 1 ? 's' : ''} detected`;
      siteStatusElement.classList.remove('status-safe');
      siteStatusElement.classList.add('status-threat');
    } else {
      siteStatusElement.innerHTML = '✓ No threats detected';
      siteStatusElement.classList.remove('status-threat');
      siteStatusElement.classList.add('status-safe');
    }
  }
}

document.addEventListener('DOMContentLoaded', synchronizeThreatDisplay);
window.updateThreatDisplay = synchronizeThreatDisplay;

setInterval(synchronizeThreatDisplay, 5000);
