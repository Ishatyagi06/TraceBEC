/**
 * phisGuard Gmail In-Page Extraction Content Script.
 * Extracts user-visible message elements strictly upon explicit user click in the extension popup.
 */

function extractGmailMessage() {
  // 1. Subject Extraction
  let subject = "";
  const subjectElem = document.querySelector("h2.hP");
  if (subjectElem) {
    subject = subjectElem.innerText.trim();
  }

  // 2. Sender Extraction (Display Name & Email)
  let sender = "";
  const senderElem = document.querySelector("span.gD");
  if (senderElem) {
    const emailAttr = senderElem.getAttribute("email") || "";
    const nameText = senderElem.innerText.trim();
    sender = emailAttr ? `${nameText} <${emailAttr}>` : nameText;
  }

  // 3. Body Text Extraction (Sanitized)
  let body = "";
  // In Gmail, message bodies are rendered in .a3s.aiL containers
  const bodyContainers = document.querySelectorAll("div.a3s.aiL");
  if (bodyContainers.length > 0) {
    // Select the last visible expanded message in the thread
    const activeBody = bodyContainers[bodyContainers.length - 1];
    body = activeBody.innerText.trim();
  } else {
    // Fallback: search within the main role container
    const mainContainer = document.querySelector('div[role="main"]');
    if (mainContainer) {
      body = mainContainer.innerText.slice(0, 3000);
    }
  }

  return {
    isAvailable: Boolean(subject || body),
    subject: subject || "(No Subject)",
    sender: sender || "Unknown Sender",
    body: body || "",
  };
}

// Listen for explicit extraction requests from popup
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "EXTRACT_GMAIL_CONTENT") {
    const data = extractGmailMessage();
    sendResponse(data);
  }
  return true;
});
