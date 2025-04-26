document.addEventListener('DOMContentLoaded', () => {
  const totalScannedElement = document.getElementById('totalScanned');
  const phishingDetectedElement = document.getElementById('phishingDetected');
  const detectionRateElement = document.getElementById('detectionRate');
  const detectionsTableBody = document.getElementById('detectionsTable').querySelector('tbody');
  
  loadStats();
  loadDetectionHistory();
  createChart();
  
  function loadStats() {
    try {
      if (typeof require === 'function') {
        const { getStatistics } = require('./db');
        getStatistics().then(stats => {
          if (stats) {
            totalScannedElement.textContent = stats.totalScanned.toLocaleString();
            phishingDetectedElement.textContent = stats.phishingDetected.toLocaleString();
            
            const detectionRate = stats.totalScanned > 0 
              ? ((stats.phishingDetected / stats.totalScanned) * 100).toFixed(2) 
              : '0';
              
            detectionRateElement.textContent = `${detectionRate}%`;
          }
        });
      } else {
        chrome.storage.local.get(['detectionStats'], (data) => {
          if (data.detectionStats) {
            const stats = data.detectionStats;
            totalScannedElement.textContent = stats.totalScanned.toLocaleString();
            phishingDetectedElement.textContent = stats.phishingDetected.toLocaleString();
            
            const detectionRate = stats.totalScanned > 0 
              ? ((stats.phishingDetected / stats.totalScanned) * 100).toFixed(2) 
              : '0';
              
            detectionRateElement.textContent = `${detectionRate}%`;
          }
        });
      }
    } catch (e) {
      chrome.storage.local.get(['detectionStats'], (data) => {
        if (data.detectionStats) {
          const stats = data.detectionStats;
          totalScannedElement.textContent = stats.totalScanned.toLocaleString();
          phishingDetectedElement.textContent = stats.phishingDetected.toLocaleString();
          
          const detectionRate = stats.totalScanned > 0 
            ? ((stats.phishingDetected / stats.totalScanned) * 100).toFixed(2) 
            : '0';
            
          detectionRateElement.textContent = `${detectionRate}%`;
        }
      });
    }
  }
  
  function loadDetectionHistory() {
    try {
      if (typeof require === 'function') {
        const { getDetectionHistory } = require('./db');
        getDetectionHistory(100).then(detections => {
          if (detections && detections.length > 0) {
            displayDetections(detections);
          } else {
            fallbackToStorageHistory();
          }
        });
      } else {
        fallbackToStorageHistory();
      }
    } catch (e) {
      fallbackToStorageHistory();
    }
  }
  
  function fallbackToStorageHistory() {
    chrome.storage.local.get(['detectionHistory'], (data) => {
      if (data.detectionHistory && data.detectionHistory.length > 0) {
        displayDetections(data.detectionHistory);
      } else {
        detectionsTableBody.innerHTML = `
          <tr>
            <td colspan="5" class="no-data">No detection history available yet.</td>
          </tr>
        `;
      }
    });
  }
  
  function displayDetections(detections) {
    detectionsTableBody.innerHTML = '';
    
    detections
      .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp))
      .slice(0, 100)
      .forEach(detection => {
        const row = document.createElement('tr');
        
        const dateCell = document.createElement('td');
        const date = new Date(detection.timestamp);
        dateCell.textContent = date.toLocaleString();
        
        const urlCell = document.createElement('td');
        const urlText = detection.url.length > 50 
          ? detection.url.substring(0, 50) + '...'
          : detection.url;
        urlCell.textContent = urlText;
        
        const typeCell = document.createElement('td');
        typeCell.textContent = detection.type;
        
        const riskCell = document.createElement('td');
        
        let riskClass = '';
        if (detection.confidence > 0.7) {
          riskClass = 'risk-high';
          riskCell.textContent = 'High';
        } else if (detection.confidence > 0.4) {
          riskClass = 'risk-medium';
          riskCell.textContent = 'Medium';
        } else {
          riskClass = 'risk-low';
          riskCell.textContent = 'Low';
        }
        riskCell.classList.add(riskClass);
        
        const actionCell = document.createElement('td');
        actionCell.textContent = detection.action || 'Blocked';
        
        row.appendChild(dateCell);
        row.appendChild(urlCell);
        row.appendChild(typeCell);
        row.appendChild(riskCell);
        row.appendChild(actionCell);
        
        detectionsTableBody.appendChild(row);
      });
  }
  
  function createChart() {
    chrome.storage.local.get(['detectionStats', 'weeklyStats'], (data) => {
      const ctx = document.getElementById('detectionChart').getContext('2d');
      
      const weeklyData = data.weeklyStats || generateEmptyWeeklyData();
      
      new Chart(ctx, {
        type: 'line',
        data: {
          labels: weeklyData.labels,
          datasets: [{
            label: 'Phishing Attempts Detected',
            data: weeklyData.detections,
            borderColor: 'rgb(255, 99, 132)',
            backgroundColor: 'rgba(255, 99, 132, 0.1)',
            borderWidth: 2,
            tension: 0.1,
            fill: true
          },
          {
            label: 'Total Scans',
            data: weeklyData.scans,
            borderColor: 'rgb(54, 162, 235)',
            borderWidth: 2,
            tension: 0.1,
            fill: false
          }]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          scales: {
            y: {
              beginAtZero: true
            }
          },
          plugins: {
            legend: {
              position: 'top',
            },
            title: {
              display: true,
              text: 'Detection Activity (Last 7 Days)'
            }
          }
        }
      });
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
});
