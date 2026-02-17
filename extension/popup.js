// File Type Detector Extension
// Author: @helloitsmia.tech

// Magic byte signatures for file type detection
const MAGIC_BYTES = {
  'application/pdf': [
    [0x25, 0x50, 0x44, 0x46] // %PDF
  ],
  'video/mp4': null, // Special handling - ftyp at offset 4
  'image/png': [
    [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A] // PNG signature
  ],
  'image/jpeg': [
    [0xFF, 0xD8, 0xFF] // JPEG signature
  ],
  'image/gif': [
    [0x47, 0x49, 0x46, 0x38, 0x39, 0x61], // GIF89a
    [0x47, 0x49, 0x46, 0x38, 0x37, 0x61]  // GIF87a
  ],
  'video/webm': [
    [0x1A, 0x45, 0xDF, 0xA3] // WebM signature
  ],
  'application/zip': [
    [0x50, 0x4B, 0x03, 0x04], // ZIP (PK..)
    [0x50, 0x4B, 0x05, 0x06], // Empty ZIP
    [0x50, 0x4B, 0x07, 0x08]  // Spanned ZIP
  ]
};

// Generic MIME types that should trigger magic byte detection
const GENERIC_MIME_TYPES = [
  'application/octet-stream',
  'binary/octet-stream',
  'application/force-download',
  'application/x-download',
  'application/unknown',
  'unknown/unknown'
];

let detectedMimeType = null;
let detectionMethod = null;
let fileUrl = null;
let detectedExtensionHint = null; // Extension verified during alternative URL probing
let statusCode = null;
let fileSize = null;
const ALLOWED_PROTOCOLS = new Set(['http:', 'https:']);
const ALLOWED_DATASET_SCOPES = [
  { host: 'www.justice.gov', pathPrefix: '/epstein/files' },
  { host: 'assets.getkino.com', pathPrefix: '/documents' }
];

// DOM elements
const detectBtn = document.getElementById('detectBtn');
const openBtn = document.getElementById('openBtn');
const resultSection = document.getElementById('resultSection');
const mimeTypeDisplay = document.getElementById('mimeType');
const detectionMethodDisplay = document.getElementById('detectionMethod');
const messageArea = document.getElementById('messageArea');
const spinner = document.getElementById('spinner');
const checkmark = document.getElementById('checkmark');
const statusCodeDisplay = document.getElementById('statusCode');
const fileSizeDisplay = document.getElementById('fileSize');
const currentUrlText = document.getElementById('currentUrlText');
const scanMetadataBtn = document.getElementById('scanMetadataBtn');
const metadataSection = document.getElementById('metadataSection');
const metadataContent = document.getElementById('metadataContent');
const metadataSpinner = document.getElementById('metadataScanSpinner');
const movWarning = document.getElementById('movWarning');
const videoPreviewSection = document.getElementById('videoPreviewSection');
const videoUrlInput = document.getElementById('videoUrlInput');
const loadVideoBtn = document.getElementById('loadVideoBtn');
const videoPlayerContainer = document.getElementById('videoPlayerContainer');
const videoPlayer = document.getElementById('videoPlayer');
const videoInfo = document.getElementById('videoInfo');
const videoError = document.getElementById('videoError');
const closeVideoPreview = document.getElementById('closeVideoPreview');
const videoLoadSpinner = document.getElementById('videoLoadSpinner');

// Initialize
document.addEventListener('DOMContentLoaded', async () => {
  detectBtn.addEventListener('click', handleDetect);
  openBtn.addEventListener('click', handleOpen);
  scanMetadataBtn.addEventListener('click', handleScanMetadata);
  loadVideoBtn.addEventListener('click', handleLoadVideo);
  closeVideoPreview.addEventListener('click', handleCloseVideoPreview);
  
  // Allow Enter key to load video
  videoUrlInput.addEventListener('keypress', (e) => {
    if (e.key === 'Enter') {
      handleLoadVideo();
    }
  });
  
  // Load current tab URL on popup open
  await loadCurrentTabUrl();
});

function getSafeHttpUrl(url) {
  try {
    const parsed = new URL(url);
    if (!ALLOWED_PROTOCOLS.has(parsed.protocol)) return null;
    const isAllowedScope = ALLOWED_DATASET_SCOPES.some(
      ({ host, pathPrefix }) => parsed.hostname === host && parsed.pathname.startsWith(pathPrefix)
    );
    if (!isAllowedScope) return null;
    return parsed;
  } catch (e) {
    return null;
  }
}

// Load and display current tab URL
async function loadCurrentTabUrl() {
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (tab && tab.url) {
      const extractedUrl = extractRealUrl(tab.url);
      const safeUrl = getSafeHttpUrl(extractedUrl);
      if (!safeUrl) {
        currentUrlText.textContent = 'Only supported on justice.gov/epstein/files and assets.getkino.com/documents';
        currentUrlText.title = extractedUrl;
        detectBtn.disabled = true;
        return;
      }
      fileUrl = safeUrl.toString();
      // Display shortened URL
      try {
        const urlObj = new URL(fileUrl);
        const displayUrl = urlObj.pathname.length > 50 
          ? urlObj.pathname.substring(0, 47) + '...' 
          : urlObj.pathname;
        currentUrlText.textContent = displayUrl || fileUrl;
        currentUrlText.title = fileUrl;
      } catch (e) {
        currentUrlText.textContent = fileUrl.length > 50 ? fileUrl.substring(0, 47) + '...' : fileUrl;
        currentUrlText.title = fileUrl;
      }
    } else {
      currentUrlText.textContent = 'No URL available';
      detectBtn.disabled = true;
    }
  } catch (error) {
    console.error('Error loading current tab:', error);
    currentUrlText.textContent = 'Error loading URL';
    detectBtn.disabled = true;
  }
}

// Extract real URL from chrome-extension:// proxy URLs
function extractRealUrl(url) {
  // Handle chrome-extension:// URLs that proxy other URLs
  // Format: chrome-extension://EXT_ID/ACTUAL_URL
  if (url.startsWith('chrome-extension://')) {
    const match = url.match(/^chrome-extension:\/\/[^/]+\/(.+)$/);
    if (match && match[1]) {
      // Try to decode and use the embedded URL
      try {
        const decoded = decodeURIComponent(match[1]);
        const safeDecoded = getSafeHttpUrl(decoded);
        if (safeDecoded) {
          console.log('Extracted real URL from chrome-extension://:', safeDecoded.toString());
          return safeDecoded.toString();
        }
      } catch (e) {
        // If decoding fails, try using it as-is
        try {
          const safePathUrl = getSafeHttpUrl(match[1]);
          if (safePathUrl) {
            console.log('Using URL from chrome-extension:// path:', safePathUrl.toString());
            return safePathUrl.toString();
          }
        } catch (e2) {
          // Keep original if extraction fails
          console.log('Could not extract URL, using original');
        }
      }
    }
  }
  return url;
}

// Main detection handler
async function handleDetect() {
  // Get current tab URL
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab || !tab.url) {
      showMessage('No URL available in current tab', 'error');
      return;
    }
    
    let url = extractRealUrl(tab.url);
    const safeUrl = getSafeHttpUrl(url);
    if (!safeUrl) {
      showMessage('This tool is restricted to justice.gov/epstein/files and assets.getkino.com/documents', 'error');
      return;
    }
    url = safeUrl.toString();
    fileUrl = url; // Store for opening

  // Reset state
  detectedMimeType = null;
  detectionMethod = null;
  detectedExtensionHint = null;
  statusCode = null;
  fileSize = null;
  
  // UI updates
  setLoading(true);
  hideMessage();
  resultSection.style.display = 'none';
  metadataSection.style.display = 'none';
  openBtn.disabled = true;
  scanMetadataBtn.disabled = true;
  checkmark.style.display = 'none';

    try {
      await detectFileType(url, tab.id);
    } catch (error) {
      showMessage('Detection failed: ' + error.message, 'error');
      setLoading(false);
    }
  } catch (error) {
    showMessage('Error: ' + error.message, 'error');
    setLoading(false);
  }
}

// Fetch via content script (uses page context, bypasses age verification)
async function fetchViaContentScript(url, tabId, method = 'GET', headers = {}, range = false, metadata = false, fullFile = false) {
  return new Promise((resolve, reject) => {
    // Add timeout to prevent hanging (longer timeout for full file requests)
    const timeoutDuration = fullFile ? 60000 : 15000; // 60 seconds for full files, 15 for others
    const messageTimeout = setTimeout(() => {
      reject(new Error(`Content script message timeout after ${timeoutDuration / 1000} seconds`));
    }, timeoutDuration);
    
    // Content script should be auto-injected via manifest
    // Try sending message directly
    chrome.tabs.sendMessage(tabId, {
      action: 'fetchFile',
      url: url,
      method: method,
      headers: headers,
      range: range,
      metadata: metadata,
      fullFile: fullFile
    }, (response) => {
      clearTimeout(messageTimeout);
      
      if (chrome.runtime.lastError) {
        // Content script might not be ready, try background script as fallback
        console.log('Content script not ready, trying background:', chrome.runtime.lastError.message);
        fetchViaBackground(url, method, headers, range, fullFile)
          .then(resolve)
          .catch(reject);
        return;
      }
      if (response && response.success) {
        resolve(response);
      } else {
        reject(new Error(response?.error || 'Content script fetch failed'));
      }
    });
  });
}

// Fetch via background script (fallback for chrome-extension:// URLs or CORS issues)
async function fetchViaBackground(url, method = 'GET', headers = {}, range = false, fullFile = false) {
  return new Promise((resolve, reject) => {
    // Add timeout for full file requests
    const timeoutDuration = fullFile ? 60000 : 15000;
    const timeout = setTimeout(() => {
      reject(new Error(`Background fetch timeout after ${timeoutDuration / 1000} seconds`));
    }, timeoutDuration);
    
    chrome.runtime.sendMessage({
      action: 'fetch',
      url: url,
      method: method,
      headers: headers,
      range: range,
      fullFile: fullFile
    }, (response) => {
      clearTimeout(timeout);
      
      if (chrome.runtime.lastError) {
        reject(new Error(chrome.runtime.lastError.message));
        return;
      }
      if (response && response.success) {
        resolve(response);
      } else {
        reject(new Error(response?.error || 'Background fetch failed'));
      }
    });
  });
}

// Detect file type
async function detectFileType(url, tabId) {
  let contentType = null;
  let headers = null;
  let arrayBuffer = null;
  const isChromeExtension = url.startsWith('chrome-extension://');
  
  try {
    // Step 1: Try to get headers and file size with HEAD request
    try {
      let headResponse;
      if (isChromeExtension || tabId) {
        // Use content script (page context) or background script
        try {
          const bgResponse = await fetchViaContentScript(url, tabId, 'HEAD');
          headResponse = {
            status: bgResponse.status,
            statusText: bgResponse.statusText,
            ok: bgResponse.status >= 200 && bgResponse.status < 300,
            headers: {
              get: (name) => bgResponse.headers[name.toLowerCase()] || null
            }
          };
        } catch (e) {
          // Fallback to background
          const bgResponse = await fetchViaBackground(url, 'HEAD');
          headResponse = {
            status: bgResponse.status,
            statusText: bgResponse.statusText,
            ok: bgResponse.status >= 200 && bgResponse.status < 300,
            headers: {
              get: (name) => bgResponse.headers[name.toLowerCase()] || null
            }
          };
        }
      } else {
        headResponse = await fetch(url, {
          method: 'HEAD',
          mode: 'cors',
          redirect: 'follow'
        });
      }
      
      statusCode = headResponse.status;
      if (isChromeExtension || tabId) {
        headers = { get: (name) => headResponse.headers.get(name) };
      } else {
        headers = headResponse.headers;
      }
      contentType = headResponse.headers.get('content-type');
      
      // Extract file size if available
      const contentLength = headResponse.headers.get('content-length');
      if (contentLength) {
        fileSize = formatFileSize(parseInt(contentLength, 10));
      }
    } catch (headError) {
      console.log('HEAD request failed, will try GET:', headError.message);
      // Continue to fetch bytes for magic detection
    }

    // Step 2: ALWAYS fetch first bytes for magic byte detection
    // This is the primary detection method, regardless of Content-Type
    // Use content script to fetch from page context (bypasses age verification)
    try {
      let response;
      let responseData;
      
      if (isChromeExtension || tabId) {
        // Use content script (page context) for authenticated requests
        try {
          responseData = await fetchViaContentScript(url, tabId, 'GET', { 'Range': 'bytes=0-4095' }, true);
        } catch (rangeError) {
          // Try without range
          console.log('Range request failed, trying full GET:', rangeError.message);
          responseData = await fetchViaContentScript(url, tabId, 'GET', {}, false);
        }
        
        // Convert response data to arrayBuffer
        if (responseData.body && Array.isArray(responseData.body)) {
          arrayBuffer = new Uint8Array(responseData.body).buffer;
        } else if (responseData.body) {
          // If it's already an ArrayBuffer or similar
          arrayBuffer = responseData.body;
        }
        
        // Update status code if not set
        if (!statusCode) {
          statusCode = responseData.status;
        }
        
        // Update Content-Type if not set
        if (!contentType && responseData.headers['content-type']) {
          contentType = responseData.headers['content-type'];
        }
        
        // Update file size if available and not set
        if (!fileSize && responseData.headers['content-length']) {
          fileSize = formatFileSize(parseInt(responseData.headers['content-length'], 10));
        }
        
      } else {
        // Regular fetch for http/https URLs (fallback)
        try {
          response = await fetch(url, {
            method: 'GET',
            headers: {
              'Range': 'bytes=0-4095'
            },
            mode: 'cors',
            redirect: 'follow'
          });
        } catch (rangeError) {
          // Range might not be supported, try regular GET
          console.log('Range request failed, trying full GET:', rangeError.message);
          response = await fetch(url, {
            method: 'GET',
            mode: 'cors',
            redirect: 'follow'
          });
        }

        // Update status code if not set
        if (!statusCode) {
          statusCode = response.status;
        }

        // Update headers if not set
        if (!headers) {
          headers = response.headers;
        }

        // Update Content-Type if not set
        if (!contentType) {
          contentType = response.headers.get('content-type');
        }

        // Update file size if available and not set
        if (!fileSize) {
          const contentLength = response.headers.get('content-length');
          if (contentLength) {
            fileSize = formatFileSize(parseInt(contentLength, 10));
          }
        }

        if (!response.ok && response.status !== 206) {
          throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }

        // Get the bytes for magic detection
        if (response.status === 206) {
          // Partial content (Range request succeeded)
          arrayBuffer = await response.arrayBuffer();
        } else {
          // Full response - only take first 4KB
          const blob = await response.blob();
          arrayBuffer = await blob.slice(0, 4096).arrayBuffer();
        }
      }

      // Step 3: Detect using magic bytes (PRIMARY METHOD)
      if (arrayBuffer && arrayBuffer.byteLength > 0) {
        const detected = detectMagicBytes(arrayBuffer);
        
        // If we detected PDF but the URL ends in .pdf, try alternative extensions
        // The server may serve different content based on extension (error page vs actual file)
        if (detected === 'application/pdf' && url.toLowerCase().endsWith('.pdf')) {
          console.log('PDF detected from .pdf URL - trying alternative extensions to find actual file type...');
          console.log('Original URL:', url);
          
          let foundValidFile = false;
          const baseUrl = url.replace(/\.pdf$/i, '');
          const candidateResults = [];
          const expectedMimeByExtension = {
            mp4: 'video/mp4',
            m4a: 'audio/mp4',
            m4v: 'video/x-m4v',
            mov: 'video/quicktime',
            '3gp': 'video/3gpp',
            avi: 'video/x-msvideo',
            webm: 'video/webm'
          };
          
          // Try each alternative extension
          for (const ext of ALTERNATIVE_EXTENSIONS) {
            const testUrl = baseUrl + '.' + ext;
            console.log(`Trying extension .${ext}:`, testUrl);
            
            try {
              let testResponseData;
              try {
                testResponseData = await fetchViaContentScript(testUrl, tabId, 'GET', { 'Range': 'bytes=0-4095' }, true);
              } catch (rangeError) {
                console.log(`Range request failed for .${ext}, trying full GET:`, rangeError.message);
                try {
                  testResponseData = await fetchViaContentScript(testUrl, tabId, 'GET', {}, false);
                } catch (fullError) {
                  console.log(`Both Range and full GET failed for .${ext}:`, fullError.message);
                  continue; // Try next extension
                }
              }
              
              // Check if we got a valid response (not 404)
              if (testResponseData && testResponseData.success !== false && 
                  testResponseData.status >= 200 && testResponseData.status < 400) {
                
                if (testResponseData.body && Array.isArray(testResponseData.body) && testResponseData.body.length > 0) {
                  console.log(`✓ .${ext} returned valid file (${testResponseData.body.length} bytes, status ${testResponseData.status})`);
                  const testBytes = new Uint8Array(testResponseData.body);
                  const testDetected = detectMagicBytes(testBytes.buffer);
                  console.log(`Magic bytes detection for .${ext}:`, testDetected);
                  
                  // Check if it's a valid media file (not PDF or error page)
                  if (testDetected && testDetected !== 'application/pdf') {
                    const expectedMime = expectedMimeByExtension[ext] || null;
                    let score = 10; // Base score for a valid non-PDF detection
                    if (expectedMime && expectedMime === testDetected) {
                      score += 100; // Strongly prefer extension/mime agreement
                    }
                    if (testDetected.startsWith('video/') || testDetected.startsWith('audio/')) {
                      score += 15;
                    }
                    if (testDetected === 'video/x-msvideo') {
                      score += 15; // Slightly favor AVI when detected explicitly
                    }

                    candidateResults.push({
                      ext,
                      url: testUrl,
                      mime: testDetected,
                      score,
                      contentLength: testResponseData.headers?.['content-length'] || null
                    });
                    console.log(`✓ Candidate found: .${ext} => ${testDetected} (score ${score})`);
                  } else if (testDetected === 'application/pdf') {
                    console.log(`.${ext} also returned PDF, continuing search...`);
                    continue; // Try next extension
                  } else {
                    // Unknown type but got data - might be valid
                    console.log(`.${ext} returned unknown type, but got data - might be valid`);
                    // Continue to see if we find a better match
                  }
                } else {
                  console.log(`.${ext} returned valid status but no body data`);
                  continue;
                }
              } else if (testResponseData && testResponseData.status === 404) {
                console.log(`.${ext} returned 404 (not found)`);
                continue; // Try next extension
              } else {
                console.log(`.${ext} returned error status:`, testResponseData?.status);
                continue;
              }
            } catch (testError) {
              console.log(`Error testing .${ext} extension:`, testError.message);
              continue; // Try next extension
            }
          }

          if (candidateResults.length > 0) {
            candidateResults.sort((a, b) => b.score - a.score);
            const bestCandidate = candidateResults[0];
            console.log('Best extension candidate selected:', bestCandidate);

            detectedMimeType = bestCandidate.mime;
            detectionMethod = `Magic bytes (verified via .${bestCandidate.ext} URL - server serves different content by extension)`;
            fileUrl = bestCandidate.url; // Update URL for opening
            detectedExtensionHint = bestCandidate.ext;
            foundValidFile = true;

            if (bestCandidate.contentLength) {
              fileSize = formatFileSize(parseInt(bestCandidate.contentLength, 10));
              console.log('Updated file size:', fileSize);
            }
          }
          
          // If we didn't find a valid file, keep PDF detection
          if (!foundValidFile) {
            console.log('No valid alternative extension found, keeping PDF detection');
            detectedMimeType = detected;
            detectionMethod = 'Magic bytes (tried alternative extensions but none returned valid file)';
            detectedExtensionHint = null;
          }
        } else if (detected) {
          detectedMimeType = detected;
          detectionMethod = 'Magic bytes';
          detectedExtensionHint = null;
        } else {
          // Fallback to Content-Type header if magic bytes don't match
          if (contentType) {
            detectedMimeType = contentType.split(';')[0].trim();
            const isGeneric = GENERIC_MIME_TYPES.some(
              generic => contentType.toLowerCase().includes(generic)
            );
            detectionMethod = isGeneric 
              ? 'Content-Type header (generic, magic bytes not detected)' 
              : 'Content-Type header (magic bytes not detected)';
            detectedExtensionHint = null;
          } else {
            detectedMimeType = 'application/octet-stream';
            detectionMethod = 'Unknown (no Content-Type, magic bytes not detected)';
            detectedExtensionHint = null;
          }
        }
      } else {
        throw new Error('No data received for magic byte detection');
      }

    } catch (fetchError) {
      console.error('Failed to fetch file bytes:', fetchError);
      
      // If we have Content-Type from HEAD, use it
      if (contentType) {
        detectedMimeType = contentType.split(';')[0].trim();
        detectionMethod = 'Content-Type header (could not fetch bytes for magic detection: ' + fetchError.message + ')';
      } else {
        detectedMimeType = 'application/octet-stream';
        detectionMethod = 'Unknown (fetch failed: ' + fetchError.message + ')';
      }
      
      // Show error but still display what we have
      showMessage('Warning: Could not fetch file bytes. Using Content-Type header only.', 'info');
    }

    // Ensure we always have status code and file size displayed if available
    if (!statusCode && headers) {
      // Try to get from headers if we have them
      const responseStatus = headers.get ? headers.get('status') : null;
      if (responseStatus) statusCode = responseStatus;
    }

    // Display results
    displayResults();
    setLoading(false);
    checkmark.style.display = 'flex';
    
    if (detectionMethod && detectionMethod.includes('Magic bytes')) {
      showMessage('File type detected via magic bytes!', 'success');
    } else if (detectionMethod && detectionMethod.includes('Content-Type')) {
      showMessage('File type detected from Content-Type header', 'info');
    } else {
      showMessage('File type detection completed', 'info');
    }
    
  } catch (error) {
    console.error('Detection error:', error);
    setLoading(false);
    showMessage('Detection failed: ' + error.message, 'error');
    // Still try to display what we have
    if (detectedMimeType) {
      displayResults();
    }
    throw error;
  }
}

// Detect magic bytes in array buffer
function detectMagicBytes(arrayBuffer) {
  const bytes = new Uint8Array(arrayBuffer);
  
  // Debug: log first 64 bytes for troubleshooting
  if (bytes.length > 0) {
    const hexPreview = Array.from(bytes.slice(0, Math.min(64, bytes.length)))
      .map(b => b.toString(16).padStart(2, '0'))
      .join(' ');
    console.log('First bytes (hex):', hexPreview);
    const asciiPreview = Array.from(bytes.slice(0, Math.min(64, bytes.length)))
      .map(b => (b >= 32 && b <= 126) ? String.fromCharCode(b) : '.')
      .join('');
    console.log('First bytes (ascii):', asciiPreview);
    console.log('Total bytes received:', bytes.length);
  }
  
  // Special handling for AVI: RIFF container with AVI/AVIX brand
  // Layout: bytes 0-3 = "RIFF", bytes 8-11 = "AVI " or "AVIX"
  if (bytes.length >= 12) {
    const hasRiff =
      bytes[0] === 0x52 && // R
      bytes[1] === 0x49 && // I
      bytes[2] === 0x46 && // F
      bytes[3] === 0x46;   // F

    if (hasRiff) {
      const riffType = String.fromCharCode(bytes[8], bytes[9], bytes[10], bytes[11]);
      if (riffType === 'AVI ' || riffType === 'AVIX') {
        console.log('AVI detected via RIFF container, type:', riffType);
        return 'video/x-msvideo';
      }
    }
  }

  // Special handling for ISO BMFF family (MP4/MOV/M4A/M4V/3GP)
  // Require a valid first box: [size][ftyp][major_brand]
  if (bytes.length >= 12) {
    const firstBoxSize =
      (bytes[0] << 24) |
      (bytes[1] << 16) |
      (bytes[2] << 8) |
      bytes[3];
    const hasFtypAtOffset4 =
      bytes[4] === 0x66 && // f
      bytes[5] === 0x74 && // t
      bytes[6] === 0x79 && // y
      bytes[7] === 0x70;   // p

    const plausibleFtypSize = firstBoxSize === 1 || (firstBoxSize >= 8 && firstBoxSize <= 4096);
    if (hasFtypAtOffset4 && plausibleFtypSize) {
      const majorBrand = String.fromCharCode(bytes[8], bytes[9], bytes[10], bytes[11]);
      const brand = majorBrand.trim();
      const brandLower = brand.toLowerCase();
      console.log('ISO BMFF detected via ftyp, major brand:', majorBrand);

      if (brandLower === 'm4a') return 'audio/mp4';
      if (brandLower === 'm4v') return 'video/x-m4v';
      if (brandLower === 'qt') return 'video/quicktime';
      if (brandLower.startsWith('3gp')) return 'video/3gpp';

      const mp4Brands = new Set([
        'isom', 'iso2', 'iso3', 'iso4', 'iso5', 'iso6',
        'mp41', 'mp42', 'avc1', 'dash', 'msnv', 'f4v', 'f4p', 'f4a', 'f4b'
      ]);
      if (mp4Brands.has(brandLower)) return 'video/mp4';

      // If the structure is valid but brand is unknown, treat as generic MP4 container.
      return 'video/mp4';
    }
  }
  
  // Check other file types (but prioritize MP4 which was checked above)
  for (const [mimeType, signatures] of Object.entries(MAGIC_BYTES)) {
    if (signatures === null) continue; // Skip special cases (MP4 handled above)
    
    for (const signature of signatures) {
      if (bytes.length >= signature.length) {
        let match = true;
        for (let i = 0; i < signature.length; i++) {
          if (bytes[i] !== signature[i]) {
            match = false;
            break;
          }
        }
        if (match) {
          console.log(`Detected ${mimeType} via magic bytes at offset 0`);
          return mimeType;
        }
      }
    }
  }
  
  console.log('No magic bytes matched');
  return null;
}

// Display detection results
function displayResults() {
  mimeTypeDisplay.textContent = detectedMimeType || 'Unknown';
  detectionMethodDisplay.textContent = `Detected via: ${detectionMethod || 'Unknown'}`;
  statusCodeDisplay.textContent = statusCode ? statusCode.toString() : '-';
  fileSizeDisplay.textContent = fileSize || '-';
  resultSection.style.display = 'block';
  openBtn.disabled = false;
  scanMetadataBtn.disabled = false; // Enable metadata scanning
  
  // Show MOV warning and warning icon for .mov files specifically
  const extension = getPreferredOutputExtension();
  const isMovType = extension === 'mov';
  if (isMovType) {
    movWarning.style.display = 'flex';
    checkmark.textContent = '⚠';
    checkmark.className = 'warning-checkmark';
  } else {
    movWarning.style.display = 'none';
    checkmark.textContent = '✓';
    checkmark.className = 'success-checkmark';
  }
  
  // Show video preview section for all video/audio types
  const videoMimeTypes = [
    'video/mp4', 'video/webm', 'video/x-m4v', 'video/3gpp', 
    'video/quicktime', 'video/x-msvideo',
    'audio/mp4', 'audio/m4a'
  ];
  if (videoMimeTypes.includes(detectedMimeType)) {
    videoPreviewSection.style.display = 'block';
    // Pre-fill the URL input with the current file URL
    if (fileUrl && extension) {
      const correctedUrl = replaceFileExtension(fileUrl, extension);
      videoUrlInput.value = correctedUrl;
    }
  } else {
    videoPreviewSection.style.display = 'none';
  }
}

// Map MIME types to file extensions
const MIME_TO_EXTENSION = {
  'application/pdf': 'pdf',
  'video/mp4': 'mp4',
  'audio/mp4': 'm4a',
  'audio/m4a': 'm4a',
  'video/x-m4v': 'm4v',
  'video/quicktime': 'mov',
  'video/3gpp': '3gp',
  'video/x-msvideo': 'avi',
  'image/png': 'png',
  'image/jpeg': 'jpg',
  'image/gif': 'gif',
  'video/webm': 'webm',
  'application/zip': 'zip'
};

// Common video/audio extensions to try when .pdf returns a PDF
const ALTERNATIVE_EXTENSIONS = [
  'mp4',
  'm4a',
  'm4v',
  'mov',
  '3gp',
  'avi',
  'mkv',
  'webm',
  'mp3',
  'wav',
  'flac',
  'aac'
];

function getPreferredOutputExtension() {
  const mimeExtension = MIME_TO_EXTENSION[detectedMimeType] || null;
  if (detectedExtensionHint) {
    if (mimeExtension && detectedExtensionHint !== mimeExtension) {
      console.log(
        `Extension hint mismatch detected (hint: .${detectedExtensionHint}, mime: .${mimeExtension}). Using verified hint.`
      );
    }
    return detectedExtensionHint;
  }
  return mimeExtension;
}

// Replace file extension in URL
function replaceFileExtension(url, newExtension) {
  try {
    const urlObj = new URL(url);
    if (!ALLOWED_PROTOCOLS.has(urlObj.protocol)) {
      return url;
    }
    const pathname = urlObj.pathname;
    
    // Find the last dot in the pathname
    const lastDot = pathname.lastIndexOf('.');
    const lastSlash = pathname.lastIndexOf('/');
    
    if (lastDot > lastSlash && lastDot > 0) {
      // Replace extension
      urlObj.pathname = pathname.substring(0, lastDot + 1) + newExtension;
    } else {
      // No extension found, append it
      urlObj.pathname = pathname + '.' + newExtension;
    }
    
    return urlObj.toString();
  } catch (e) {
    console.error('Error replacing extension:', e);
    return url;
  }
}

// Scan file for metadata
async function handleScanMetadata() {
  // Get current tab for content script access
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab || !tab.id) {
      showMessage('Could not access current tab', 'error');
      return;
    }

    // Get the actual file URL (use fileUrl if available, otherwise extract from current tab)
    let urlToScan = fileUrl;
    if (!urlToScan) {
      urlToScan = extractRealUrl(tab.url);
      console.log('No fileUrl set, using current tab URL:', urlToScan);
    } else {
      console.log('Using stored fileUrl:', urlToScan);
    }

    if (!urlToScan) {
      showMessage('Could not determine file URL', 'error');
      return;
    }
    const safeScanUrl = getSafeHttpUrl(urlToScan);
    if (!safeScanUrl) {
      showMessage('Metadata scan is restricted to justice.gov/epstein/files and assets.getkino.com/documents', 'error');
      return;
    }
    urlToScan = safeScanUrl.toString();

    setMetadataLoading(true);
    hideMessage();
    metadataSection.style.display = 'none';
    metadataContent.innerHTML = '';

    // Add timeout to prevent hanging
    const timeout = setTimeout(() => {
      setMetadataLoading(false);
      showMessage('Metadata scan timed out after 30 seconds', 'error');
      console.error('Metadata scan timeout');
    }, 30000);

    try {
      console.log('Starting metadata extraction for:', urlToScan);
      const metadata = await extractMetadata(urlToScan, tab.id);
      clearTimeout(timeout);
      console.log('Metadata extraction result:', metadata);
      displayMetadata(metadata);
      metadataSection.style.display = 'block';
      showMessage('Metadata scan completed', 'success');
    } catch (error) {
      clearTimeout(timeout);
      console.error('Metadata extraction error:', error);
      showMessage('Metadata scan failed: ' + error.message, 'error');
    } finally {
      setMetadataLoading(false);
    }
  } catch (error) {
    showMessage('Error: ' + error.message, 'error');
    setMetadataLoading(false);
  }
}

// Extract metadata from file
async function extractMetadata(url, tabId) {
  const metadata = {
    gps: null,
    creationDate: null,
    modificationDate: null,
    camera: null,
    software: null,
    location: null,
    other: {}
  };

  try {
    // Fetch a larger chunk of the file for metadata extraction (first 64KB should be enough for most metadata)
    console.log('Fetching file data for metadata extraction...');
    let responseData;
    try {
      // Add timeout to fetch
      const fetchPromise = fetchViaContentScript(url, tabId, 'GET', { 'Range': 'bytes=0-65535' }, true, true);
      const timeoutPromise = new Promise((_, reject) => 
        setTimeout(() => reject(new Error('Fetch timeout')), 20000)
      );
      responseData = await Promise.race([fetchPromise, timeoutPromise]);
      console.log('Range request succeeded, got', responseData?.body?.length || 0, 'bytes');
    } catch (rangeError) {
      console.log('Range request failed, trying full fetch:', rangeError.message);
      try {
        const fetchPromise = fetchViaContentScript(url, tabId, 'GET', {}, false, true);
        const timeoutPromise = new Promise((_, reject) => 
          setTimeout(() => reject(new Error('Fetch timeout')), 20000)
        );
        responseData = await Promise.race([fetchPromise, timeoutPromise]);
        console.log('Full fetch succeeded, got', responseData?.body?.length || 0, 'bytes');
      } catch (fullError) {
        console.error('Both Range and full fetch failed:', fullError);
        throw new Error('Could not fetch file: ' + fullError.message);
      }
    }

    if (!responseData || !responseData.body || !Array.isArray(responseData.body)) {
      console.error('Invalid response data:', responseData);
      throw new Error('Could not fetch file data for metadata extraction');
    }
    
    if (responseData.body.length === 0) {
      throw new Error('Received empty file data');
    }

    const bytes = new Uint8Array(responseData.body);
    console.log('Extracting metadata from', bytes.length, 'bytes');
    console.log('First 100 bytes (hex):', Array.from(bytes.slice(0, 100)).map(b => b.toString(16).padStart(2, '0')).join(' '));

    // Check file type and extract metadata accordingly
    const detected = detectMagicBytes(bytes.buffer);
    console.log('Detected file type for metadata:', detected);
    
    if (detected === 'video/quicktime' || detected === 'video/mp4' || detected === 'audio/mp4' || 
        detected === 'video/x-m4v' || detected === 'video/3gpp') {
      // QuickTime/MP4 format - parse atoms/boxes
      console.log('Parsing QuickTime/MP4 metadata...');
      const qtMetadata = parseQuickTimeMetadata(bytes);
      console.log('QuickTime metadata result:', qtMetadata);
      Object.assign(metadata, qtMetadata);
    } else if (detected === 'image/jpeg') {
      // JPEG - parse EXIF
      const jpegMetadata = parseJPEGMetadata(bytes);
      Object.assign(metadata, jpegMetadata);
    } else {
      console.log('File type not supported for metadata extraction:', detected);
      metadata.other['File Type'] = detected || 'Unknown';
      metadata.other['Note'] = 'Metadata extraction not yet supported for this file type';
      
      // Even if file type detection failed, try to parse as QuickTime anyway (might be misdetected)
      if (bytes.length > 8) {
        console.log('Attempting QuickTime parsing anyway...');
        const qtMetadata = parseQuickTimeMetadata(bytes);
        if (qtMetadata.gps || qtMetadata.creationDate || qtMetadata.camera) {
          console.log('Found metadata with QuickTime parser:', qtMetadata);
          Object.assign(metadata, qtMetadata);
        }
      }
    }

  } catch (error) {
    console.error('Error extracting metadata:', error);
    throw error;
  }

  return metadata;
}

// Parse QuickTime/MOV metadata atoms
// Metadata in MOV files is stored in QuickTime atoms:
// - 'moov' atom: Contains movie header and metadata
//   - 'udta' atom: User data atom (often contains GPS)
//     - '©xyz' or '\xA9xyz': GPS location atom
//   - 'meta' atom: Metadata atom
//     - 'ilst' atom: Item list (contains various metadata items)
//       - '©xyz': GPS location
//       - '©day': Creation date
//       - '©mak': Camera make
//       - '©mod': Camera model
//       - '©swr': Software
// - Metadata can also be in track atoms ('trak') but less common
function parseQuickTimeMetadata(bytes) {
  const metadata = {
    gps: null,
    creationDate: null,
    modificationDate: null,
    camera: null,
    software: null,
    location: null,
    other: {}
  };

  let offset = 0;
  const maxOffset = Math.min(bytes.length, 131072); // Search up to 128KB

  console.log('Parsing QuickTime metadata from', bytes.length, 'bytes');
  console.log('Looking for metadata atoms: moov, udta, meta, ilst, ©xyz, ©loc, ©gps');

  while (offset < maxOffset - 8) {
    // Read atom size (4 bytes, big-endian)
    const size = (bytes[offset] << 24) | (bytes[offset + 1] << 16) | (bytes[offset + 2] << 8) | bytes[offset + 3];
    
    if (size === 0 || size > maxOffset - offset || size < 8) {
      offset++;
      continue; // Skip invalid atoms
    }
    
    // Read atom type (4 bytes)
    const type = String.fromCharCode(bytes[offset + 4], bytes[offset + 5], bytes[offset + 6], bytes[offset + 7]);
    
    // Only recurse into metadata/container atoms (not media payload like mdat)
    if (type === 'moov' || type === 'udta' || type === 'meta' || type === 'ilst' || type === 'trak') {
      // Parse nested atoms
      const nested = parseQuickTimeAtom(bytes, offset + 8, offset + size, metadata);
      if (nested) Object.assign(metadata, nested);
    } else if (type === '\xA9xyz' || type === '©xyz' || type === '©loc' || 
               type === '\xA9loc' || type === '©gps' || type === '\xA9gps') {
      // GPS location atom (various formats)
      console.log('Found GPS atom:', type, 'at offset', offset);
      const gpsData = parseGPSAtom(bytes, offset + 8, offset + size);
      if (gpsData) {
        console.log('GPS atom data:', gpsData);
        // Prioritize DMS format or coordinates with decimals (not whole numbers)
        if (gpsData.latitude !== undefined) {
          const isWholeNumber = (gpsData.latitude % 1 === 0 && gpsData.longitude % 1 === 0);
          const isRoundNumber = (gpsData.latitude % 10 === 0 || gpsData.latitude % 5 === 0) && 
                               (gpsData.longitude % 10 === 0 || gpsData.longitude % 5 === 0);
          
          // Only use if it's not a suspicious whole/round number, OR if we don't have any GPS yet
          if (!isWholeNumber && !isRoundNumber) {
            // Good coordinates - use them
            if (!metadata.gps || !metadata.gps.latitude || metadata.gps.format !== 'DMS') {
              metadata.gps = gpsData;
            }
          } else if (!metadata.gps) {
            // Suspicious but it's all we have - store it but mark as suspicious
            console.log('Storing suspicious GPS coordinates (whole/round numbers):', gpsData);
            metadata.gps = { ...gpsData, suspicious: true };
          } else {
            console.log('Rejecting suspicious GPS coordinates, keeping existing:', metadata.gps);
          }
        } else if (gpsData.raw && !metadata.gps) {
          // Store raw GPS string if we don't have coordinates yet
          metadata.gps = gpsData;
        }
      }
    } else if (type === '\xA9day' || type === '©day') {
      // Creation date
      const dateStr = parseStringAtom(bytes, offset + 8, offset + size);
      if (dateStr) metadata.creationDate = dateStr;
    } else if (type === '\xA9swr' || type === '©swr') {
      // Software
      const software = parseStringAtom(bytes, offset + 8, offset + size);
      if (software) metadata.software = software;
    } else if (type === '\xA9mak' || type === '©mak') {
      // Camera make
      const make = parseStringAtom(bytes, offset + 8, offset + size);
      if (make) metadata.camera = (metadata.camera || '') + make + ' ';
    } else if (type === '\xA9mod' || type === '©mod') {
      // Camera model
      const model = parseStringAtom(bytes, offset + 8, offset + size);
      if (model) metadata.camera = (metadata.camera || '') + model;
    }
    
    offset += size;
  }

  // Try to find GPS in other common locations - search more thoroughly
  // Collect all GPS candidates and choose the best one
  const gpsCandidates = [];
  
  if (metadata.gps && metadata.gps.latitude !== undefined) {
    gpsCandidates.push(metadata.gps);
  }
  
  console.log('Searching entire file for GPS patterns...');
  const gpsMatch = findGPSInBytes(bytes);
  if (gpsMatch && gpsMatch.latitude !== undefined) {
    console.log('Found GPS coordinates in byte search:', gpsMatch);
    gpsCandidates.push(gpsMatch);
  }
  
  // Last resort: search for any text that looks like coordinates
  if (gpsCandidates.length === 0) {
    const textSearch = searchForCoordinateText(bytes);
    if (textSearch) {
      console.log('Found coordinate-like text:', textSearch);
      // Create a fake atom structure to parse it
      const testString = textSearch;
      // Try to parse using the GPS string parsing logic
      const dmsPatterns = [
        /(\d+)°\s*(\d+)['']\s*([\d.]+)["'']\s*([NS])\s+(\d+)°\s*(\d+)['']\s*([\d.]+)["'']\s*([EW])/i,
        /(\d+)°(\d+)['']([\d.]+)["'']([NS])(\d+)°(\d+)['']([\d.]+)["'']([EW])/i
      ];
      
      for (const pattern of dmsPatterns) {
        const match = testString.match(pattern);
        if (match) {
          const lat = dmsToDecimal(parseInt(match[1]), parseInt(match[2]), parseFloat(match[3]), match[4].toUpperCase());
          const lon = dmsToDecimal(parseInt(match[5]), parseInt(match[6]), parseFloat(match[7]), match[8].toUpperCase());
          if (lat >= -90 && lat <= 90 && lon >= -180 && lon <= 180) {
            gpsCandidates.push({ latitude: lat, longitude: lon, raw: testString, format: 'DMS' });
            break;
          }
        }
      }
      
    }
  }
  
  // Choose the best GPS candidate
  if (gpsCandidates.length > 0) {
    // Prioritize: DMS format > decimal with decimals > decimal whole numbers
    gpsCandidates.sort((a, b) => {
      // DMS format is always best
      if (a.format === 'DMS' && b.format !== 'DMS') return -1;
      if (b.format === 'DMS' && a.format !== 'DMS') return 1;
      
      // Prefer coordinates with decimal places over whole numbers
      const aHasDecimals = (a.latitude % 1 !== 0 || a.longitude % 1 !== 0);
      const bHasDecimals = (b.latitude % 1 !== 0 || b.longitude % 1 !== 0);
      if (aHasDecimals && !bHasDecimals) return -1;
      if (bHasDecimals && !aHasDecimals) return 1;
      
      return 0;
    });
    
    // Filter out suspicious whole/round numbers unless it's all we have
    const validCandidates = gpsCandidates.filter(gps => {
      if (!gps.latitude) return true; // Keep raw strings
      const isWholeNumber = (gps.latitude % 1 === 0 && gps.longitude % 1 === 0);
      const isRoundNumber = (gps.latitude % 10 === 0 || gps.latitude % 5 === 0) && 
                           (gps.longitude % 10 === 0 || gps.longitude % 5 === 0);
      return !isWholeNumber && !isRoundNumber;
    });
    
    if (validCandidates.length > 0) {
      metadata.gps = validCandidates[0];
      console.log('Selected best GPS candidate:', metadata.gps);
    } else if (gpsCandidates.length > 0) {
      // All candidates are suspicious, but use the best one and mark it
      metadata.gps = { ...gpsCandidates[0], suspicious: true };
      console.log('Using suspicious GPS (only option):', metadata.gps);
    }
  } else {
    console.log('No GPS found in any search');
  }

  // Log what we found
  console.log('Final metadata:', {
    hasGPS: !!metadata.gps,
    hasDate: !!metadata.creationDate,
    hasCamera: !!metadata.camera,
    hasSoftware: !!metadata.software
  });

  return metadata;
}

// Parse QuickTime atom recursively
function parseQuickTimeAtom(bytes, start, end, metadata) {
  const result = {};
  let offset = start;
  const maxDepth = 10; // Prevent infinite recursion
  let depth = 0;
  
  while (offset < end - 8 && depth < maxDepth) {
    const size = (bytes[offset] << 24) | (bytes[offset + 1] << 16) | (bytes[offset + 2] << 8) | bytes[offset + 3];
    if (size === 0 || size > end - offset || size < 8) {
      offset++;
      continue;
    }
    
    const type = String.fromCharCode(bytes[offset + 4], bytes[offset + 5], bytes[offset + 6], bytes[offset + 7]);
    
    // Handle common metadata atoms - expand search
    if (type === '\xA9xyz' || type === '©xyz' || type === '©loc' || 
        type === '\xA9loc' || type === '©gps' || type === '\xA9gps') {
      const gpsData = parseGPSAtom(bytes, offset + 8, offset + size);
      if (gpsData) {
        if (gpsData.latitude !== undefined) {
          // Only use if we got actual coordinates
          if (!result.gps || !result.gps.latitude) {
            result.gps = gpsData;
          }
        } else if (gpsData.raw && !result.gps) {
          result.gps = gpsData;
        }
      }
    } else if (type === '\xA9day' || type === '©day') {
      const dateStr = parseStringAtom(bytes, offset + 8, offset + size);
      if (dateStr) result.creationDate = dateStr;
    } else if (type === '\xA9swr' || type === '©swr') {
      const software = parseStringAtom(bytes, offset + 8, offset + size);
      if (software) result.software = software;
    } else if (type === '\xA9mak' || type === '©mak') {
      const make = parseStringAtom(bytes, offset + 8, offset + size);
      if (make) result.camera = (result.camera || '') + make + ' ';
    } else if (type === '\xA9mod' || type === '©mod') {
      const model = parseStringAtom(bytes, offset + 8, offset + size);
      if (model) result.camera = (result.camera || '') + model;
    } else if (type === 'data') {
      // Data atom - might contain GPS in binary format
      const dataAtom = parseDataAtom(bytes, offset + 8, offset + size);
      if (dataAtom && dataAtom.gps) {
        if (!result.gps || !result.gps.latitude) {
          result.gps = dataAtom.gps;
        }
      }
    } else if (type === 'moov' || type === 'udta' || type === 'meta' || type === 'ilst') {
      // Recursively parse nested atoms
      depth++;
      const nested = parseQuickTimeAtom(bytes, offset + 8, offset + size, metadata);
      if (nested) {
        Object.assign(result, nested);
      }
      depth--;
    }
    
    offset += size;
  }
  
  return result;
}

// Parse data atom (can contain GPS in various formats)
function parseDataAtom(bytes, start, end) {
  try {
    if (end - start < 16) return null;
    
    // Data atom has: type indicator (4 bytes), locale (4 bytes), then data
    // Skip first 8 bytes (type and locale)
    const dataStart = start + 8;
    const dataLength = end - dataStart;
    
    if (dataLength < 4) return null;
    
    // Try to parse as string
    let dataString = '';
    for (let i = dataStart; i < end && i < dataStart + 500; i++) {
      if (bytes[i] >= 32 && bytes[i] < 127) {
        dataString += String.fromCharCode(bytes[i]);
      } else if (bytes[i] === 0 && dataString.length > 0) {
        break;
      }
    }
    
    // Check if this looks like GPS data
    if (dataString.includes('°') || dataString.match(/[NS]/i) || dataString.match(/[EW]/i)) {
      const gpsData = parseGPSAtom(bytes, dataStart, end);
      if (gpsData) {
        return { gps: gpsData };
      }
    }
    
    return null;
  } catch (e) {
    return null;
  }
}

// Convert degrees/minutes/seconds to decimal degrees
function dmsToDecimal(degrees, minutes, seconds, direction) {
  let decimal = degrees + (minutes / 60) + (seconds / 3600);
  if (direction === 'S' || direction === 'W') {
    decimal = -decimal;
  }
  return decimal;
}

// Parse GPS atom
function parseGPSAtom(bytes, start, end) {
  try {
    const dataLength = end - start;
    if (dataLength < 4) return null;
    
    // Try to parse as string first
    let gpsString = '';
    for (let i = start; i < end && i < start + 200; i++) {
      if (bytes[i] >= 32 && bytes[i] < 127) {
        gpsString += String.fromCharCode(bytes[i]);
      } else if (bytes[i] === 0 && gpsString.length > 0) {
        // Null terminator - might be end of string
        break;
      }
    }
    
    console.log('GPS atom string:', gpsString);
    
    // First, try to parse degrees/minutes/seconds format (e.g., "42°04'14.5"N 74°07'25.3"W")
    // PRIORITIZE DMS format - it's more reliable than decimal
    const dmsPatterns = [
      /(\d+)°\s*(\d+)['']\s*([\d.]+)["'']\s*([NS])\s+(\d+)°\s*(\d+)['']\s*([\d.]+)["'']\s*([EW])/i,
      /(\d+)°(\d+)['']([\d.]+)["'']([NS])(\d+)°(\d+)['']([\d.]+)["'']([EW])/i,
      /(\d+)°\s*(\d+)\s*['']\s*([\d.]+)\s*["'']\s*([NS])\s+(\d+)°\s*(\d+)\s*['']\s*([\d.]+)\s*["'']\s*([EW])/i
    ];
    
    for (const dmsPattern of dmsPatterns) {
      const dmsMatch = gpsString.match(dmsPattern);
      if (dmsMatch) {
        const latDeg = parseInt(dmsMatch[1]);
        const latMin = parseInt(dmsMatch[2]);
        const latSec = parseFloat(dmsMatch[3]);
        const latDir = dmsMatch[4].toUpperCase();
        const lonDeg = parseInt(dmsMatch[5]);
        const lonMin = parseInt(dmsMatch[6]);
        const lonSec = parseFloat(dmsMatch[7]);
        const lonDir = dmsMatch[8].toUpperCase();
        
        const lat = dmsToDecimal(latDeg, latMin, latSec, latDir);
        const lon = dmsToDecimal(lonDeg, lonMin, lonSec, lonDir);
        
        if (lat >= -90 && lat <= 90 && lon >= -180 && lon <= 180) {
          console.log('Parsed DMS format:', lat, lon, 'from', gpsString);
          // DMS format is always preferred - return immediately
          return { latitude: lat, longitude: lon, raw: gpsString.trim(), format: 'DMS' };
        }
      }
    }
    
    // Try QuickTime GPS format: "+DD.DDDD+DDD.DDDD/" or "+DD.DDDD-DDD.DDDD/"
    const qtPattern = /([+-])(\d{1,2})\.(\d+)([+-])(\d{1,3})\.(\d+)/;
    const qtMatch = gpsString.match(qtPattern);
    if (qtMatch) {
      const latSign = qtMatch[1] === '+' ? 1 : -1;
      const lat = latSign * (parseFloat(qtMatch[2]) + parseFloat('0.' + qtMatch[3]));
      const lonSign = qtMatch[4] === '+' ? 1 : -1;
      const lon = lonSign * (parseFloat(qtMatch[5]) + parseFloat('0.' + qtMatch[6]));
      
      // Filter out suspicious placeholder values - reject whole numbers that look like defaults
      if (lat >= -90 && lat <= 90 && lon >= -180 && lon <= 180) {
        // Reject coordinates that are whole numbers (likely defaults like 52.0, 64.0)
        const isWholeNumber = (lat % 1 === 0 && lon % 1 === 0);
        // Also reject if both are round numbers (like 50.0, 60.0, 52.0, 64.0)
        const isRoundNumber = (lat % 10 === 0 || lat % 5 === 0) && (lon % 10 === 0 || lon % 5 === 0);
        
        if (!isWholeNumber && !isRoundNumber) {
          console.log('Parsed QuickTime format:', lat, lon);
          return { latitude: lat, longitude: lon, raw: gpsString.trim(), format: 'QuickTime' };
        } else {
          console.log('Rejected suspicious QuickTime coordinates (whole/round numbers):', lat, lon);
        }
      }
    }
    
    // Look for decimal coordinate patterns, but filter out suspicious values
    const coordPattern = /([+-]?\d+\.?\d*)\s*[,/]\s*([+-]?\d+\.?\d*)/;
    const match = gpsString.match(coordPattern);
    if (match) {
      const lat = parseFloat(match[1]);
      const lon = parseFloat(match[2]);
      if (!isNaN(lat) && !isNaN(lon) && lat >= -90 && lat <= 90 && lon >= -180 && lon <= 180) {
        // Reject whole numbers and round numbers (likely defaults)
        const isWholeNumber = (lat % 1 === 0 && lon % 1 === 0);
        const isRoundNumber = (lat % 10 === 0 || lat % 5 === 0) && (lon % 10 === 0 || lon % 5 === 0);
        
        if (!isWholeNumber && !isRoundNumber) {
          console.log('Parsed decimal format:', lat, lon);
          return { latitude: lat, longitude: lon, raw: gpsString.trim(), format: 'Decimal' };
        } else {
          console.log('Rejected suspicious decimal coordinates (whole/round numbers):', lat, lon);
        }
      }
    }
    
    return null;
  } catch (e) {
    console.error('Error parsing GPS atom:', e);
    return null;
  }
}

// Find GPS coordinates in byte array (search for common patterns)
function findGPSInBytes(bytes) {
  const searchLimit = Math.min(bytes.length, 131072); // Search up to 128KB
  
  // Search for degrees/minutes/seconds format first (most reliable)
  // Use sliding window to catch coordinates that span chunk boundaries
  for (let i = 0; i < searchLimit - 50; i++) {
    // Create a larger window to catch coordinates
    const windowSize = 200;
    const chunk = Array.from(bytes.slice(i, Math.min(i + windowSize, searchLimit)))
      .map(b => (b >= 32 && b < 127) ? String.fromCharCode(b) : (b === 0 ? ' ' : '.'))
      .join('');
    
    // Look for DMS format: "42°04'14.5"N 74°07'25.3"W" (with various spacing)
    const dmsPatterns = [
      /(\d+)°\s*(\d+)['']\s*([\d.]+)["'']\s*([NS])\s+(\d+)°\s*(\d+)['']\s*([\d.]+)["'']\s*([EW])/i,
      /(\d+)°(\d+)['']([\d.]+)["'']([NS])(\d+)°(\d+)['']([\d.]+)["'']([EW])/i,
      /(\d+)\s*deg\s*(\d+)\s*min\s*([\d.]+)\s*sec\s*([NS])\s+(\d+)\s*deg\s*(\d+)\s*min\s*([\d.]+)\s*sec\s*([EW])/i
    ];
    
    for (const pattern of dmsPatterns) {
      const dmsMatch = chunk.match(pattern);
      if (dmsMatch) {
        const lat = dmsToDecimal(parseInt(dmsMatch[1]), parseInt(dmsMatch[2]), parseFloat(dmsMatch[3]), dmsMatch[4].toUpperCase());
        const lon = dmsToDecimal(parseInt(dmsMatch[5]), parseInt(dmsMatch[6]), parseFloat(dmsMatch[7]), dmsMatch[8].toUpperCase());
        if (lat >= -90 && lat <= 90 && lon >= -180 && lon <= 180) {
          console.log('Found DMS format in bytes at offset', i, ':', lat, lon);
          return { latitude: lat, longitude: lon, raw: chunk.trim(), format: 'DMS' };
        }
      }
    }
  }
  
  // Search for decimal coordinates, but be more selective
  for (let i = 0; i < searchLimit - 20; i++) {
    const chunk = Array.from(bytes.slice(i, Math.min(i + 150, searchLimit)))
      .map(b => (b >= 32 && b < 127) ? String.fromCharCode(b) : (b === 0 ? ' ' : '.'))
      .join('');
    
    // Look for coordinate patterns with more context (avoid single-digit defaults)
    const coordPatterns = [
      /([+-]?\d{2,}\.\d+)\s*[,\s/]\s*([+-]?\d{2,}\.\d+)/,  // Decimal with decimals
      /([+-]?\d{2,})\s*[,\s/]\s*([+-]?\d{2,})/,  // Whole numbers
      /lat[itude]*\s*:?\s*([+-]?\d+\.?\d*)\s*lon[gitude]*\s*:?\s*([+-]?\d+\.?\d*)/i,
      /([+-]?\d+\.?\d*)\s*,\s*([+-]?\d+\.?\d*)\s*\(GPS\)/i
    ];
    
    for (const pattern of coordPatterns) {
      const coordMatch = chunk.match(pattern);
      if (coordMatch) {
        const lat = parseFloat(coordMatch[1]);
        const lon = parseFloat(coordMatch[2]);
        // Filter out suspicious values - reject whole numbers and round numbers
        if (!isNaN(lat) && !isNaN(lon) && 
            lat >= -90 && lat <= 90 && lon >= -180 && lon <= 180) {
          const isWholeNumber = (lat % 1 === 0 && lon % 1 === 0);
          const isRoundNumber = (lat % 10 === 0 || lat % 5 === 0) && (lon % 10 === 0 || lon % 5 === 0);
          
          if (!isWholeNumber && !isRoundNumber) {
            console.log('Found decimal format in bytes at offset', i, ':', lat, lon);
            return { latitude: lat, longitude: lon, raw: chunk.trim(), format: 'Decimal' };
          } else {
            console.log('Rejected suspicious coordinates (whole/round numbers):', lat, lon);
          }
        }
      }
    }
  }
  
  return null;
}

// Search for coordinate-like text (last resort)
function searchForCoordinateText(bytes) {
  const searchLimit = Math.min(bytes.length, 131072);
  
  // Look for any text that contains degree symbols and direction letters
  for (let i = 0; i < searchLimit - 30; i++) {
    const chunk = Array.from(bytes.slice(i, Math.min(i + 100, searchLimit)))
      .map(b => (b >= 32 && b < 127) ? String.fromCharCode(b) : ' ')
      .join('');
    
    // Look for patterns like "42°" or "N 74°" or similar
    if ((chunk.includes('°') || chunk.includes("'")) && 
        (chunk.match(/[NS]/i) || chunk.match(/[EW]/i))) {
      // Extract a reasonable snippet
      const match = chunk.match(/.{0,50}(°|'|"|N|S|E|W).{0,50}/i);
      if (match) {
        console.log('Found coordinate-like text:', match[0]);
        return match[0].trim();
      }
    }
  }
  
  return null;
}

// Parse string atom
function parseStringAtom(bytes, start, end) {
  try {
    // Skip header/data descriptor (usually 16-24 bytes)
    let dataStart = start + 16;
    if (dataStart >= end) dataStart = start + 8;
    
    let str = '';
    for (let i = dataStart; i < end && i < dataStart + 200; i++) {
      if (bytes[i] === 0) break; // Null terminator
      if (bytes[i] >= 32 && bytes[i] < 127) {
        str += String.fromCharCode(bytes[i]);
      }
    }
    
    return sanitizeMetadataText(str);
  } catch (e) {
    return null;
  }
}

function sanitizeMetadataText(value) {
  if (!value) return null;
  const cleaned = value.replace(/\s+/g, ' ').trim();
  if (cleaned.length < 2 || cleaned.length > 120) return null;
  
  // Metadata text should be mostly readable ASCII and include some alphanumeric content.
  const allowedChars = (cleaned.match(/[A-Za-z0-9\s:;.,_\/()+\-#&'"]/g) || []).length;
  const readableRatio = allowedChars / cleaned.length;
  const alnumCount = (cleaned.match(/[A-Za-z0-9]/g) || []).length;
  
  if (readableRatio < 0.9 || alnumCount < 3) return null;
  return cleaned;
}

// Parse JPEG EXIF metadata (basic)
function parseJPEGMetadata(bytes) {
  const metadata = {
    gps: null,
    creationDate: null,
    camera: null,
    other: {}
  };
  
  // JPEG EXIF parsing is more complex, would need full EXIF parser
  // For now, just indicate JPEG support
  metadata.other['Format'] = 'JPEG (EXIF parsing in development)';
  
  return metadata;
}

// Validate GPS coordinates are real (not placeholders)
function isValidGPS(gps) {
  if (!gps || gps.latitude === undefined || gps.longitude === undefined) {
    return false;
  }
  
  const lat = gps.latitude;
  const lon = gps.longitude;
  
  // Must be valid ranges
  if (lat < -90 || lat > 90 || lon < -180 || lon > 180) {
    return false;
  }
  
  // Reject whole numbers (likely defaults like 0.0, 52.0, 64.0)
  if (lat % 1 === 0 && lon % 1 === 0) {
    return false;
  }
  
  // Reject round numbers (multiples of 5 or 10)
  if ((lat % 10 === 0 || lat % 5 === 0) && (lon % 10 === 0 || lon % 5 === 0)) {
    return false;
  }
  
  // Reject coordinates that are too close to 0,0 (common default)
  if (Math.abs(lat) < 1 && Math.abs(lon) < 1) {
    return false;
  }
  
  // If it has a format and it's DMS, it's more likely to be real
  if (gps.format === 'DMS') {
    return true;
  }
  
  // For decimal coordinates, require at least 3 decimal places (more precision = more likely real)
  const latDecimals = (lat.toString().split('.')[1] || '').length;
  const lonDecimals = (lon.toString().split('.')[1] || '').length;
  if (latDecimals >= 3 && lonDecimals >= 3) {
    return true;
  }
  
  // If marked as suspicious, reject it
  if (gps.suspicious) {
    return false;
  }
  
  // Default: if it passed all other checks and has decimals, accept it
  return (latDecimals > 0 || lonDecimals > 0);
}

// Display metadata in UI
function displayMetadata(metadata) {
  let html = '';
  let hasAnyMetadata = false;
  
  // Only show GPS if it's valid
  if (metadata.gps && isValidGPS(metadata.gps)) {
    hasAnyMetadata = true;
    html += '<div class="metadata-item">';
    html += '<div class="metadata-label">📍 Location (GPS)</div>';
    const lat = metadata.gps.latitude.toFixed(6);
    const lon = metadata.gps.longitude.toFixed(6);
    const mapsUrl = `https://www.google.com/maps?q=${lat},${lon}`;
    html += `<div class="metadata-value">`;
    html += `Latitude: ${lat}<br>Longitude: ${lon}<br>`;
    if (metadata.gps.format) {
      html += `<small style="color: #666;">Format: ${metadata.gps.format}</small><br>`;
    }
    html += `<a href="${mapsUrl}" target="_blank" rel="noopener noreferrer" style="color: #667eea; text-decoration: none;">View on Google Maps</a>`;
    html += `</div>`;
    html += '</div>';
  }
  
  if (metadata.creationDate && metadata.creationDate.trim().length > 0) {
    hasAnyMetadata = true;
    html += '<div class="metadata-item">';
    html += '<div class="metadata-label">📅 Creation Date</div>';
    html += `<div class="metadata-value">${escapeHtml(metadata.creationDate)}</div>`;
    html += '</div>';
  }
  
  if (metadata.modificationDate && metadata.modificationDate.trim().length > 0) {
    hasAnyMetadata = true;
    html += '<div class="metadata-item">';
    html += '<div class="metadata-label">📅 Modification Date</div>';
    html += `<div class="metadata-value">${escapeHtml(metadata.modificationDate)}</div>`;
    html += '</div>';
  }
  
  if (metadata.camera && metadata.camera.trim().length > 0) {
    hasAnyMetadata = true;
    html += '<div class="metadata-item">';
    html += '<div class="metadata-label">📷 Camera/Device</div>';
    html += `<div class="metadata-value">${escapeHtml(metadata.camera.trim())}</div>`;
    html += '</div>';
  }
  
  if (metadata.software && metadata.software.trim().length > 0) {
    hasAnyMetadata = true;
    html += '<div class="metadata-item">';
    html += '<div class="metadata-label">💻 Software</div>';
    html += `<div class="metadata-value">${escapeHtml(metadata.software)}</div>`;
    html += '</div>';
  }
  
  // Other metadata (only show if meaningful)
  for (const [key, value] of Object.entries(metadata.other)) {
    if (value && String(value).trim().length > 0 && key !== 'Note') {
      hasAnyMetadata = true;
      html += '<div class="metadata-item">';
      html += `<div class="metadata-label">${escapeHtml(key)}</div>`;
      html += `<div class="metadata-value">${escapeHtml(String(value))}</div>`;
      html += '</div>';
    }
  }
  
  if (!hasAnyMetadata) {
    html = '<div class="metadata-item"><div class="metadata-value" style="color: #666;">No metadata found in file</div></div>';
  }
  
  metadataContent.innerHTML = html;
}

// Escape HTML
function escapeHtml(text) {
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}

// Set metadata loading state
function setMetadataLoading(loading) {
  if (loading) {
    scanMetadataBtn.disabled = true;
    metadataSpinner.classList.add('active');
    scanMetadataBtn.querySelector('.btn-text').textContent = 'Scanning...';
  } else {
    scanMetadataBtn.disabled = false;
    metadataSpinner.classList.remove('active');
    scanMetadataBtn.querySelector('.btn-text').textContent = 'Scan for Metadata';
  }
}

// Open file with correct MIME type
async function handleOpen() {
  if (!detectedMimeType || !fileUrl) {
    showMessage('Please detect file type first', 'error');
    return;
  }

  setLoading(true);
  openBtn.disabled = true;
  hideMessage();

  try {
    // Get the preferred extension (verified hint wins over mime-derived extension)
    const extension = getPreferredOutputExtension();
    
    if (!extension) {
      showMessage('Unknown file extension for MIME type: ' + detectedMimeType, 'error');
      setLoading(false);
      openBtn.disabled = false;
      return;
    }

    // Replace the extension in the URL
    const correctedUrl = replaceFileExtension(fileUrl, extension);
    console.log('Opening URL with corrected extension:', correctedUrl);
    
    const safeOpenUrl = getSafeHttpUrl(correctedUrl);
    if (!safeOpenUrl) {
      throw new Error('Blocked non-http(s) URL');
    }
    
    // Open the corrected URL in a new tab
    chrome.tabs.create({ url: safeOpenUrl.toString() });
    
    showMessage('Opening file with correct extension in new tab!', 'success');
    
  } catch (error) {
    showMessage('Failed to open file: ' + error.message, 'error');
    console.error('Open error:', error);
  } finally {
    setLoading(false);
    openBtn.disabled = false;
  }
}

// Wait for FFmpeg to be available
async function waitForFFmpeg(maxWait = 5000) {
  const startTime = Date.now();
  while (Date.now() - startTime < maxWait) {
    if (
      window.FFmpegWASM ||
      window.FFmpeg ||
      (typeof FFmpegWASM !== 'undefined') ||
      (typeof FFmpeg !== 'undefined')
    ) {
      return true;
    }
    await new Promise(resolve => setTimeout(resolve, 100));
  }
  return false;
}

// Load and preview video from URL
async function handleLoadVideo() {
  let url = videoUrlInput.value.trim();
  
  if (!url) {
    showMessage('Please enter a video URL', 'error');
    return;
  }

  const safeUrl = getSafeHttpUrl(url);
  if (!safeUrl) {
    showMessage('Video preview is restricted to justice.gov/epstein/files and assets.getkino.com/documents', 'error');
    return;
  }
  url = safeUrl.toString();

  // Set loading state
  loadVideoBtn.disabled = true;
  videoLoadSpinner.classList.add('active');
  videoError.style.display = 'none';
  videoPlayerContainer.style.display = 'none';
  hideMessage();

  try {
    // Get current tab for content script access
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab || !tab.id) {
      throw new Error('Could not access current tab');
    }

    // Fetch the video file using content script (handles CORS and authentication)
    console.log('Fetching video from URL:', url);
    let responseData;
    
    try {
      // Request full file for video playback (not just metadata chunk)
      responseData = await fetchViaContentScript(url, tab.id, 'GET', {}, false, false, true);
    } catch (fetchError) {
      // If content script fails, try background script
      console.log('Content script fetch failed, trying background:', fetchError.message);
      try {
        responseData = await fetchViaBackground(url, 'GET', {}, false, true);
      } catch (bgError) {
        throw new Error('Failed to fetch video: ' + (bgError.message || fetchError.message));
      }
    }

    if (!responseData || !responseData.body || !Array.isArray(responseData.body)) {
      throw new Error('Invalid response data from server');
    }

    if (responseData.body.length === 0) {
      throw new Error('Received empty file data');
    }

    const bytes = new Uint8Array(responseData.body);
    const mimeType = responseData.headers['content-type'] || 'video/mp4';
    const fileName = url.split('/').pop() || 'video';
    const isMov = url.toLowerCase().endsWith('.mov') || mimeType.includes('quicktime') || mimeType.includes('x-quicktime');
    
    // Check if file is suspiciously small (likely an error page or redirect)
    if (bytes.length < 10240) { // Less than 10KB
      console.warn('File is very small (' + bytes.length + ' bytes), might be an error page');
      videoError.textContent = `Warning: File is very small (${formatFileSize(bytes.length)}). This might be an error page or redirect, not the actual video file. Please check the URL.`;
      videoError.style.display = 'block';
    }
    
    // Warn about very large files (may cause memory issues)
    if (bytes.length > 100 * 1024 * 1024) { // Larger than 100MB
      console.warn('File is very large (' + bytes.length + ' bytes)');
      showMessage('Large file detected. Conversion may take a while and use significant memory.', 'error');
    }
    
    let blobUrl;
    let convertedType = mimeType;
    
    // If it's a MOV file, try to convert it with FFmpeg
    if (isMov) {
      // Wait for FFmpeg to load (if it's still loading)
      const ffmpegReady = await waitForFFmpeg();
      
      if (!ffmpegReady) {
        // FFmpeg not loaded - try to play original and show helpful message
        console.warn('FFmpeg not available, attempting to play MOV directly (may not work)');
        const blob = new Blob([bytes], { type: mimeType });
        blobUrl = URL.createObjectURL(blob);
        videoError.textContent = 'FFmpeg library not loaded. MOV files may not play in Chrome. Please refresh the extension or download the file to view it.';
        videoError.style.display = 'block';
      } else {
        const maxSafeConvertSize = 60 * 1024 * 1024; // 60MB
        if (bytes.length > maxSafeConvertSize) {
          console.warn('MOV too large for reliable in-popup FFmpeg conversion:', bytes.length);
          const blob = new Blob([bytes], { type: mimeType });
          blobUrl = URL.createObjectURL(blob);
          convertedType = `${mimeType} (original - conversion skipped due to file size)`;
          videoError.textContent = `File is ${formatFileSize(bytes.length)}. In-browser FFmpeg conversion may fail due to memory limits, so the original file is loaded instead.`;
          videoError.style.display = 'block';
        } else {
        showMessage('Converting MOV file for browser playback... This may take a moment.', 'success');
        
        try {
          // Initialize FFmpeg - check different ways it might be exposed
          const FFmpegClass =
            window.FFmpegWASM?.FFmpeg ||
            window.FFmpeg?.FFmpeg ||
            window.FFmpeg ||
            (typeof FFmpegWASM !== 'undefined' ? FFmpegWASM.FFmpeg || FFmpegWASM : null) ||
            (typeof FFmpeg !== 'undefined' ? FFmpeg.FFmpeg || FFmpeg : null);
          if (!FFmpegClass) {
            throw new Error('FFmpeg class not found');
          }
          
          const ffmpeg = new FFmpegClass();
        
        // Set up logging/progress callbacks (supported in @ffmpeg/ffmpeg v0.12.x)
        if (typeof ffmpeg.on === 'function') {
          ffmpeg.on('log', ({ message }) => {
            console.log('FFmpeg:', message);
          });
          
          ffmpeg.on('progress', ({ progress }) => {
            const percent = Math.round(progress * 100);
            showMessage(`Converting: ${percent}%`, 'success');
          });
        }
        
        // Load FFmpeg core from local extension assets (CSP-safe)
        console.log('Loading FFmpeg...');
        try {
          const coreBase = chrome.runtime.getURL('vendor/ffmpeg/');
          await ffmpeg.load({
            coreURL: `${coreBase}ffmpeg-core.js`,
            wasmURL: `${coreBase}ffmpeg-core.wasm`,
          });
        } catch (loadError) {
          throw new Error(`FFmpeg local core load failed: ${loadError.message || loadError}`);
        }
        console.log('FFmpeg loaded');
        
        // Write input file
        console.log('Writing input file...');
        await ffmpeg.writeFile('input.mov', bytes);
        
        // Try a low-memory remux first (container change only, no re-encode)
        console.log('Attempting MOV -> MP4 remux...');
        let outputFile = 'output.mp4';
        let outputMime = 'video/mp4';
        let convertedLabel = 'video/mp4 (remuxed from MOV)';
        
        try {
          await ffmpeg.exec([
            '-i', 'input.mov',
            '-c', 'copy',
            '-movflags', '+faststart',
            outputFile
          ]);
        } catch (remuxError) {
          console.warn('Remux failed, trying lightweight transcode:', remuxError);
          // Fallback transcode tuned for lower memory usage than VP9/WebM
          await ffmpeg.exec([
            '-i', 'input.mov',
            '-vf', 'scale=min(960,iw):-2',
            '-c:v', 'mpeg4',
            '-q:v', '8',
            '-c:a', 'aac',
            '-b:a', '96k',
            '-threads', '1',
            outputFile
          ]);
          convertedLabel = 'video/mp4 (transcoded from MOV)';
        }
        
        // Read output file
        console.log('Reading converted file...');
        const outputData = await ffmpeg.readFile(outputFile);
        
        // Create blob from converted video
        const blob = new Blob([outputData], { type: outputMime });
        blobUrl = URL.createObjectURL(blob);
        convertedType = convertedLabel;
        
        // Clean up
        await ffmpeg.deleteFile('input.mov');
        await ffmpeg.deleteFile(outputFile);
        
          console.log('Conversion successful');
          showMessage('Conversion complete! Video ready to play.', 'success');
          
        } catch (ffmpegError) {
          console.error('FFmpeg conversion error:', ffmpegError);
          
          // Fallback: try to play original file anyway (might work if codec is compatible)
          console.log('Trying original format as fallback...');
          const blob = new Blob([bytes], { type: mimeType });
          blobUrl = URL.createObjectURL(blob);
          
          showMessage('Conversion failed. Trying original format (may not work)...', 'error');
          
          // Set a timeout to check if video can play
          setTimeout(() => {
            if (videoPlayer.readyState === 0 || videoPlayer.error) {
              videoError.textContent = 'MOV file cannot be played in browser. FFmpeg conversion failed: ' + (ffmpegError.message || 'Unknown error') + '. Please download the file to view it.';
              videoError.style.display = 'block';
            }
          }, 2000);
        }
        }
      }
    } else {
      // For non-MOV files, use original format
      const blob = new Blob([bytes], { type: mimeType });
      blobUrl = URL.createObjectURL(blob);
    }

    // Set video source
    videoPlayer.src = blobUrl;
    
    // Display video info
    const fileSize = formatFileSize(bytes.length);
    videoInfo.textContent = `File: ${fileName} | Size: ${fileSize} | Type: ${convertedType}`;

    // Show video player
    videoPlayerContainer.style.display = 'block';
    
    // Add comprehensive error handling
    const errorHandler = (e) => {
      const error = videoPlayer.error;
      if (error) {
        let errorMsg = 'Video playback failed: ';
        if (error.code === 4) {
          errorMsg += 'Format not supported. ';
          if (isMov) {
            errorMsg += 'MOV conversion may have failed or the file uses an unsupported codec. ';
            errorMsg += 'Please download the file to view it with a media player.';
          } else {
            errorMsg += 'This video format is not supported by your browser.';
          }
        } else if (error.code === 3) {
          errorMsg += 'Network error or corrupted file data.';
        } else if (error.code === 2) {
          errorMsg += 'Video decoding error. The file may be corrupted.';
        } else {
          errorMsg += error.message || `Unknown error (code: ${error.code})`;
        }
        videoError.textContent = errorMsg;
        videoError.style.display = 'block';
        showMessage('Video cannot be played', 'error');
      }
    };
    
    videoPlayer.addEventListener('error', errorHandler);
    
    // Check if video can actually play after loading
    videoPlayer.addEventListener('loadedmetadata', () => {
      console.log('Video metadata loaded successfully');
    });
    
    videoPlayer.addEventListener('canplay', () => {
      console.log('Video can play');
      showMessage('Video ready to play!', 'success');
    });
    
    // Load video metadata
    videoPlayer.load();
    
    if (!isMov) {
      showMessage('Video loaded successfully!', 'success');
    }

  } catch (error) {
    console.error('Video load error:', error);
    videoError.textContent = `Error loading video: ${error.message}`;
    videoError.style.display = 'block';
    showMessage('Failed to load video: ' + error.message, 'error');
  } finally {
    loadVideoBtn.disabled = false;
    videoLoadSpinner.classList.remove('active');
  }
}

// Close video preview
function handleCloseVideoPreview() {
  // Clean up blob URL if video is loaded
  if (videoPlayer.src && videoPlayer.src.startsWith('blob:')) {
    URL.revokeObjectURL(videoPlayer.src);
    videoPlayer.src = '';
  }
  
  videoPlayerContainer.style.display = 'none';
  videoError.style.display = 'none';
  videoUrlInput.value = '';
}

// UI helper functions
function setLoading(loading) {
  if (loading) {
    detectBtn.disabled = true;
    spinner.classList.add('active');
    detectBtn.querySelector('.btn-text').textContent = 'Detecting...';
  } else {
    detectBtn.disabled = false;
    spinner.classList.remove('active');
    detectBtn.querySelector('.btn-text').textContent = 'Detect File Type';
  }
}

function showMessage(message, type = 'info') {
  messageArea.textContent = message;
  messageArea.className = `message-area ${type}`;
  messageArea.style.display = 'block';
  
  // Auto-hide success/info messages after 5 seconds
  if (type === 'success' || type === 'info') {
    setTimeout(() => {
      if (messageArea.textContent === message) {
        hideMessage();
      }
    }, 5000);
  }
}

function hideMessage() {
  messageArea.style.display = 'none';
  messageArea.className = 'message-area';
}

function formatFileSize(bytes) {
  if (bytes === 0) return '0 Bytes';
  const k = 1024;
  const sizes = ['Bytes', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i];
}
