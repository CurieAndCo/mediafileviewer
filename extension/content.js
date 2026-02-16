// Content script for File Type Detector Extension
// Author: mia
// This script runs in the page context to fetch files that may be behind age verification

// Listen for messages from popup
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === 'fetchFile') {
    // Fetch the file from the current page context
    // This bypasses age verification since we're in the authenticated page
    fetch(request.url, {
      method: request.method || 'GET',
      headers: request.headers || {},
      redirect: 'follow',
      credentials: 'include' // Include cookies for authenticated requests
    })
    .then(async (response) => {
      const headers = {};
      response.headers.forEach((value, key) => {
        headers[key.toLowerCase()] = value;
      });

      let body = null;
      if (request.method !== 'HEAD') {
        if (response.status === 206 || request.range) {
          // Partial content (Range request) - get the full range
          const arrayBuffer = await response.arrayBuffer();
          body = Array.from(new Uint8Array(arrayBuffer));
        } else if (request.fullFile) {
          // Full file request - get the entire file (no size limit)
          // This is used for video playback where we need the complete file
          const arrayBuffer = await response.arrayBuffer();
          body = Array.from(new Uint8Array(arrayBuffer));
        } else {
          // Full response - check if this is a metadata request (needs more data)
          // For metadata, we need up to 64KB, otherwise limit to 4KB for file type detection
          const maxBytes = request.metadata ? 65536 : 4096;
          const blob = await response.blob();
          const arrayBuffer = await blob.slice(0, maxBytes).arrayBuffer();
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
    })
    .catch((error) => {
      console.error('Content script fetch error:', error);
      sendResponse({
        success: false,
        error: error.message
      });
    });

    return true; // Keep message channel open for async response
  }
  
  return false;
});
