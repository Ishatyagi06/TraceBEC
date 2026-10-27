/**
 * phisGuard Extension Popup Logic.
 * Interacts with content script and backend API.
 */

document.getElementById("analyze-btn").addEventListener("click", async () => {
  const resultArea = document.getElementById("result-area");
  const analyzeBtn = document.getElementById("analyze-btn");

  analyzeBtn.innerText = "Extracting & Analyzing...";
  analyzeBtn.disabled = true;

  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab || !tab.id) {
      throw new Error("No active browser tab found.");
    }

    // Send extraction command to content script
    chrome.tabs.sendMessage(tab.id, { action: "EXTRACT_GMAIL_CONTENT" }, async (response) => {
      if (chrome.runtime.lastError || !response || !response.isAvailable) {
        resultArea.style.display = "block";
        resultArea.innerHTML = `
          <div class="result-card" style="border-color: #DC2626;">
            <div style="color: #F87171; font-weight: 600;">No Open Gmail Email Found</div>
            <p style="font-size: 11px; color: #94A3B8; margin-top: 4px;">
              Please open or select an individual email in Gmail (mail.google.com) before clicking analyze.
            </p>
          </div>
        `;
        analyzeBtn.innerText = "Analyze Current Email";
        analyzeBtn.disabled = false;
        return;
      }

      // Call backend /analyze/text API
      try {
        const apiRes = await fetch("http://localhost:8000/api/v1/analyze/text", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            subject: response.subject,
            body: response.body,
            sender: response.sender,
          }),
        });

        if (!apiRes.ok) {
          throw new Error("Backend engine unreachable (:8000). Ensure the phisGuard server is running.");
        }

        const data = await apiRes.json();
        const assessment = data.risk_assessment;
        const cat = assessment.risk_category;
        const badgeClass = cat === "HIGH" ? "risk-high" : cat === "REVIEW" ? "risk-review" : "risk-low";

        resultArea.style.display = "block";
        resultArea.innerHTML = `
          <div class="result-card">
            <span class="risk-badge ${badgeClass}">${cat} RISK (${(assessment.calibrated_score * 100).toFixed(1)}%)</span>
            <div style="font-size: 11px; color: #94A3B8; margin-bottom: 8px;">
              <strong>Subject:</strong> ${data.subject.slice(0, 45)}...
            </div>
            
            <div style="font-weight: 600; font-size: 11px; color: #38BDF8; margin-top: 8px;">Observed Indicators:</div>
            ${
              assessment.observed_evidence.length > 0
                ? assessment.observed_evidence
                    .slice(0, 3)
                    .map((s) => `<div class="signal-item"><strong>${s.title}:</strong> ${s.description.slice(0, 80)}...</div>`)
                    .join("")
                : '<div style="font-size: 11px; color: #64748B;">No overt BEC conversational indicators.</div>'
            }

            <div style="font-weight: 600; font-size: 11px; color: #64748B; margin-top: 10px;">Unavailable Evidence:</div>
            <div class="unavail-item">• RFC 5322 transit hops unverified</div>
            <div class="unavail-item">• SPF/DKIM authentication absent</div>

            <a href="http://localhost:5173" target="_blank" class="btn-link">
              Open Full Investigation in Dashboard &rarr;
            </a>
          </div>
        `;
      } catch (backendErr) {
        resultArea.style.display = "block";
        resultArea.innerHTML = `
          <div class="result-card" style="border-color: #DC2626;">
            <div style="color: #F87171; font-weight: 600;">Engine Offline</div>
            <p style="font-size: 11px; color: #94A3B8; margin-top: 4px;">${backendErr.message}</p>
          </div>
        `;
      } finally {
        analyzeBtn.innerText = "Analyze Current Email";
        analyzeBtn.disabled = false;
      }
    });
  } catch (err) {
    resultArea.style.display = "block";
    resultArea.innerHTML = `<div style="color: #F87171; font-size: 11px;">${err.message}</div>`;
    analyzeBtn.innerText = "Analyze Current Email";
    analyzeBtn.disabled = false;
  }
});
