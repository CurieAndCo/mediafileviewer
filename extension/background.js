// Background service worker for File Type Detector Extension
// Author: mia

// Service worker for Manifest V3
chrome.runtime.onInstalled.addListener(() => {
  console.log('File Type Detector extension installed');
});

// Handle fetch requests from popup (for chrome-extension:// URLs or CORS issues)
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === 'fetch') {
    (async () => {
      try {
        const fetchOptions = {
          method: request.method || 'GET',
          redirect: 'follow'
        };
        
        if (request.headers && Object.keys(request.headers).length > 0) {
          fetchOptions.headers = request.headers;
        }

        const response = await fetch(request.url, fetchOptions);
        
        const headers = {};
        response.headers.forEach((value, key) => {
          headers[key.toLowerCase()] = value;
        });

        let body = null;
        if (request.method !== 'HEAD') {
          if (response.status === 206 || request.range) {
            // Partial content (Range request)
            const arrayBuffer = await response.arrayBuffer();
            body = Array.from(new Uint8Array(arrayBuffer));
          } else if (request.fullFile) {
            // Full file request - get the entire file (no size limit)
            // This is used for video playback where we need the complete file
            const arrayBuffer = await response.arrayBuffer();
            body = Array.from(new Uint8Array(arrayBuffer));
          } else {
            // Full response - only take first 4KB
            const blob = await response.blob();
            const arrayBuffer = await blob.slice(0, 4096).arrayBuffer();
            body = Array.from(new Uint8Array(arrayBuffer));
          }
        }

        sendResponse({
          success: true,
          status: response.status,
          statusText: response.statusText,
          headers: headers,
          body: body
        });
      } catch (error) {
        console.error('Background fetch error:', error);
        sendResponse({
          success: false,
          error: error.message
        });
      }
    })();

    return true; // Keep message channel open for async response
  }
  
  if (request.action === 'ping') {
    sendResponse({ status: 'ok' });
  }
  
  return true;
});
