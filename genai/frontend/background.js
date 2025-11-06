// Background script for handling API calls
class APIService {
  constructor() {
    this.baseURL = 'http://localhost:8000';
  }

  async scanEmail(subject, content) {
    try {
      const response = await fetch(`${this.baseURL}/scan`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          subject: subject,
          content: content
        })
      });

      if (!response.ok) {
        throw new Error(`API error: ${response.status}`);
      }

      return await response.json();
    } catch (error) {
      console.error('Scan failed:', error);
      throw error;
    }
  }

  async healthCheck() {
    try {
      const response = await fetch(`${this.baseURL}/health`);
      return response.ok;
    } catch (error) {
      return false;
    }
  }
}

const apiService = new APIService();

// Handle messages from content script
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === 'scanEmail') {
    apiService.scanEmail(request.subject, request.content)
      .then(result => sendResponse({ success: true, data: result }))
      .catch(error => sendResponse({ success: false, error: error.message }));
    return true; // Will respond asynchronously
  }

  if (request.action === 'healthCheck') {
    apiService.healthCheck()
      .then(healthy => sendResponse({ healthy }))
      .catch(() => sendResponse({ healthy: false }));
    return true;
  }
});