function synchronizeThreatDisplay() {
  const threatCount = 1;
  
  // Update popup threat counter
  const popupThreatElement = document.querySelector('.threat-counter');
  if (popupThreatElement) {
    popupThreatElement.textContent = threatCount.toString();
  }
  
  // Update current site status
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
