(function() {
  if (document.documentElement.getAttribute('data-phishguard-injected') === 'true') {
    return;
  }
  
  document.documentElement.setAttribute('data-phishguard-injected', 'true');
  
  const script = document.createElement('script');
  script.src = chrome.runtime.getURL('threat-sync.js');
  script.onload = function() {
    this.remove();
    
    const event = new CustomEvent('phishguard-initialized');
    document.dispatchEvent(event);
  };
  
  (document.head || document.documentElement).appendChild(script);
  
  const observer = new MutationObserver((mutations) => {
    for (const mutation of mutations) {
      if (mutation.type === 'childList' && mutation.addedNodes.length > 0) {
        for (const node of mutation.addedNodes) {
          if (node.nodeType === 1 && node.matches && node.matches('.phishguard-marked')) {
            window.postMessage({ type: 'phishguard-threat-detected' }, '*');
            break;
          }
        }
      }
    }
  });
  
  observer.observe(document.documentElement, {
    childList: true,
    subtree: true
  });
  
  window.addEventListener('message', (event) => {
    if (event.data && event.data.type === 'phishguard-threat-detected') {
      try {
        if (window.updateThreatDisplay) {
          window.updateThreatDisplay();
        }
      } catch (e) {}
    }
  });
})();
