document.addEventListener('DOMContentLoaded', () => {
  const totalScannedElement = document.getElementById('totalScanned');
  const phishingDetectedElement = document.getElementById('phishingDetected');
  const detectionRateElement = document.getElementById('detectionRate');
  const detectionsTableBody = document.getElementById('detectionTable').querySelector('tbody');
  
  loadStats();
  loadDetectionHistory();
  createChart();
  
  function loadStats() {
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
  
  function loadDetectionHistory() {
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
  
  function switchChartType(type) {
    currentChartType = type;
    
    // Update active tab
    document.querySelectorAll('.chart-tab').forEach(tab => tab.classList.remove('active'));
    document.getElementById(`${type}Tab`).classList.add('active');
    
    if (!detectionChart) return;
    
    if (type === 'weekly' || type === 'monthly') {
      const stats = type === 'weekly' ? weeklyStats : 
        (monthlyStats || generateEmptyMonthlyData());
      
      detectionChart.data.labels = stats.labels;
      detectionChart.data.datasets = [
        {
          label: 'Phishing Attempts Detected',
          data: stats.detections,
          borderColor: '#dc2626',
          backgroundColor: 'rgba(220, 38, 38, 0.1)',
          borderWidth: 2,
          tension: 0.3,
          fill: true
        },
        {
          label: 'Total Scans',
          data: stats.scans,
          borderColor: '#2563eb',
          borderWidth: 2,
          tension: 0.3,
          fill: false
        }
      ];
    } else if (type === 'rate') {
      // Calculate detection rate for each day
      const rateData = weeklyStats.scans.map((scans, i) => {
        const detections = weeklyStats.detections[i];
        return scans > 0 ? (detections / scans) * 100 : 0;
      });
      
      detectionChart.data.labels = weeklyStats.labels;
      detectionChart.data.datasets = [{
        label: 'Detection Rate (%)',
        data: rateData,
        borderColor: '#8b5cf6',
        backgroundColor: 'rgba(139, 92, 246, 0.1)',
        borderWidth: 2,
        tension: 0.3,
        fill: true
      }];
    }
    
    detectionChart.update();
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
  
  function generateEmptyMonthlyData() {
    const labels = [];
    const scans = [];
    const detections = [];
    
    for (let i = 29; i >= 0; i--) {
      const date = new Date();
      date.setDate(date.getDate() - i);
      
      // For monthly data, we'll show shorter labels (only every 3 days)
      const label = i % 3 === 0 ? date.toLocaleDateString('en-US', { month: 'short', day: 'numeric' }) : '';
      labels.push(label);
      scans.push(0);
      detections.push(0);
    }
    
    return { labels, scans, detections };
  }
  
  function calculateTrends(weeklyStats) {
    if (!weeklyStats || weeklyStats.scans.length < 2) {
      return {
        scanTrend: 0,
        threatTrend: 0,
        rateTrend: 0,
        highRiskTrend: 0
      };
    }
    
    // Last two days for trend calculation
    const lastDayIndex = weeklyStats.scans.length - 1;
    const prevDayIndex = lastDayIndex - 1;
    
    // Scan trend
    const lastDayScans = weeklyStats.scans[lastDayIndex];
    const prevDayScans = weeklyStats.scans[prevDayIndex];
    const scanTrend = prevDayScans > 0 ? 
      ((lastDayScans - prevDayScans) / prevDayScans) * 100 : 0;
    
    // Threat trend
    const lastDayThreats = weeklyStats.detections[lastDayIndex];
    const prevDayThreats = weeklyStats.detections[prevDayIndex];
    const threatTrend = prevDayThreats > 0 ? 
      ((lastDayThreats - prevDayThreats) / prevDayThreats) * 100 : 0;
    
    // Rate trend
    const lastDayRate = lastDayScans > 0 ? 
      (lastDayThreats / lastDayScans) * 100 : 0;
    const prevDayRate = prevDayScans > 0 ?
      (prevDayThreats / prevDayScans) * 100 : 0;
    const rateTrend = prevDayRate > 0 ?
      ((lastDayRate - prevDayRate) / prevDayRate) * 100 : 0;
    
    return {
      scanTrend,
      threatTrend,
      rateTrend,
      highRiskTrend: 0 // Placeholder for future implementation
    };
  }
  
  function updateTrendIndicators(trends) {
    updateTrendIndicator('scanTrend', trends.scanTrend);
    updateTrendIndicator('threatTrend', trends.threatTrend);
    updateTrendIndicator('rateTrend', trends.rateTrend);
    updateTrendIndicator('highRiskTrend', trends.highRiskTrend);
  }
  
  function updateTrendIndicator(elementId, trendValue) {
    const element = document.getElementById(elementId);
    if (!element) return;
    
    const iconSpan = element.querySelector('i');
    const textSpan = element.querySelector('span');
    
    if (!iconSpan || !textSpan) return;
    
    iconSpan.className = 'fas';
    
    if (Math.abs(trendValue) < 0.1) {
      iconSpan.className = 'fas fa-minus';
      iconSpan.style.color = 'var(--gray-500)';
      textSpan.textContent = 'No change';
      return;
    }
    
    const formattedValue = Math.abs(trendValue).toFixed(1);
    
    if (trendValue > 0) {
      iconSpan.className = 'fas fa-arrow-up';
      
      if (elementId === 'rateTrend' || elementId === 'highRiskTrend') {
        iconSpan.className += ' trend-up';
        iconSpan.style.color = 'var(--danger)';
      } else {
        iconSpan.className += ' trend-up';
        iconSpan.style.color = 'var(--success)';
      }
      
      textSpan.textContent = `${formattedValue}% increase`;
    } else {
      iconSpan.className = 'fas fa-arrow-down';
      
      if (elementId === 'rateTrend' || elementId === 'highRiskTrend') {
        iconSpan.className += ' trend-down';
        iconSpan.style.color = 'var(--success)';
      } else {
        iconSpan.className += ' trend-down';
        iconSpan.style.color = 'var(--danger)';
      }
      
      textSpan.textContent = `${formattedValue}% decrease`;
    }
  }
  
  function viewDetectionDetails(detection) {
    // Calculate domain from URL
    let domain = '';
    try {
      domain = new URL(detection.url).hostname;
    } catch (e) {
      domain = 'Unknown';
    }
    
    // Format detection time
    const detectionTime = new Date(detection.timestamp).toLocaleString();
    
    // Determine risk level text and color
    let riskLevel, riskColor;
    if (detection.confidence > 0.7) {
      riskLevel = 'High Risk';
      riskColor = 'var(--danger)';
    } else if (detection.confidence > 0.4) {
      riskLevel = 'Medium Risk';
      riskColor = 'var(--warning)';
    } else {
      riskLevel = 'Low Risk';
      riskColor = 'var(--success)';
    }
    
    // Create modal HTML
    const modal = document.createElement('div');
    modal.style.position = 'fixed';
    modal.style.top = '0';
    modal.style.left = '0';
    modal.style.width = '100%';
    modal.style.height = '100%';
    modal.style.backgroundColor = 'rgba(0, 0, 0, 0.5)';
    modal.style.display = 'flex';
    modal.style.justifyContent = 'center';
    modal.style.alignItems = 'center';
    modal.style.zIndex = '9999';
    
    const modalContent = document.createElement('div');
    modalContent.style.backgroundColor = 'white';
    modalContent.style.borderRadius = 'var(--radius-lg)';
    modalContent.style.padding = '1.5rem';
    modalContent.style.width = '600px';
    modalContent.style.maxWidth = '90%';
    modalContent.style.maxHeight = '90vh';
    modalContent.style.overflowY = 'auto';
    modalContent.style.boxShadow = 'var(--shadow-lg)';
    
    // Header with close button
    const header = document.createElement('div');
    header.style.display = 'flex';
    header.style.justifyContent = 'space-between';
    header.style.alignItems = 'center';
    header.style.marginBottom = '1rem';
    header.style.paddingBottom = '1rem';
    header.style.borderBottom = '1px solid var(--gray-200)';
    
    const title = document.createElement('h2');
    title.style.fontSize = '1.25rem';
    title.style.fontWeight = '600';
    title.style.margin = '0';
    title.textContent = 'Detection Details';
    
    const closeButton = document.createElement('button');
    closeButton.className = 'secondary';
    closeButton.innerHTML = '<i class="fas fa-times"></i>';
    closeButton.style.padding = '0.5rem';
    closeButton.style.fontSize = '1rem';
    closeButton.onclick = () => document.body.removeChild(modal);
    
    header.appendChild(title);
    header.appendChild(closeButton);
    modalContent.appendChild(header);
    
    // Risk level indicator
    const riskIndicator = document.createElement('div');
    riskIndicator.style.display = 'flex';
    riskIndicator.style.alignItems = 'center';
    riskIndicator.style.gap = '0.5rem';
    riskIndicator.style.padding = '0.75rem 1rem';
    riskIndicator.style.backgroundColor = 'var(--gray-100)';
    riskIndicator.style.borderRadius = 'var(--radius)';
    riskIndicator.style.marginBottom = '1rem';
    
    const riskIcon = document.createElement('i');
    riskIcon.className = 'fas fa-exclamation-triangle';
    riskIcon.style.color = riskColor;
    
    const riskText = document.createElement('span');
    riskText.style.fontWeight = '600';
    riskText.style.color = riskColor;
    riskText.textContent = riskLevel;
    
    riskIndicator.appendChild(riskIcon);
    riskIndicator.appendChild(riskText);
    modalContent.appendChild(riskIndicator);
    
    // Details grid
    const detailsGrid = document.createElement('div');
    detailsGrid.style.display = 'grid';
    detailsGrid.style.gridTemplateColumns = 'auto 1fr';
    detailsGrid.style.gap = '0.75rem 1rem';
    detailsGrid.style.margin = '1.5rem 0';
    
    // Add detail rows
    const addDetailRow = (label, value) => {
      const labelElement = document.createElement('div');
      labelElement.style.fontWeight = '500';
      labelElement.style.color = 'var(--gray-700)';
      labelElement.textContent = label;
      
      const valueElement = document.createElement('div');
      valueElement.style.color = 'var(--gray-900)';
      valueElement.style.wordBreak = 'break-word';
      valueElement.textContent = value || 'N/A';
      
      detailsGrid.appendChild(labelElement);
      detailsGrid.appendChild(valueElement);
    };
    
    // Add detection details
    addDetailRow('URL', detection.url);
    addDetailRow('Domain', domain);
    addDetailRow('Detection Time', detectionTime);
    addDetailRow('Threat Type', detection.type || 'URL');
    if (detection.threatType) {
      addDetailRow('Specific Threat', detection.threatType);
    }
    addDetailRow('Risk Level', riskLevel);
    addDetailRow('Confidence Score', `${Math.round(detection.confidence * 100)}%`);
    addDetailRow('Action Taken', detection.action || 'Blocked');
    if (detection.details) {
      addDetailRow('Additional Details', detection.details);
    }
    if (detection.platform) {
      addDetailRow('Platform', detection.platform);
    }
    if (detection.source) {
      addDetailRow('Detection Source', detection.source);
    }
    
    modalContent.appendChild(detailsGrid);
    
    // Action buttons
    const actions = document.createElement('div');
    actions.style.display = 'flex';
    actions.style.justifyContent = 'flex-end';
    actions.style.gap = '0.75rem';
    actions.style.marginTop = '1.5rem';
    
    const closeModalBtn = document.createElement('button');
    closeModalBtn.className = 'secondary';
    closeModalBtn.textContent = 'Close';
    closeModalBtn.onclick = () => document.body.removeChild(modal);
    actions.appendChild(closeModalBtn);
    
    const reportBtn = document.createElement('button');
    reportBtn.innerHTML = '<i class="fas fa-flag"></i> Report False Positive';
    reportBtn.onclick = () => {
      showToast('Report submitted. Thank you for your feedback!', 'success');
      document.body.removeChild(modal);
    };
    actions.appendChild(reportBtn);
    
    modalContent.appendChild(actions);
    modal.appendChild(modalContent);
    document.body.appendChild(modal);
  }
});
