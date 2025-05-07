function checkURL() {
  const input = document.getElementById('urlInput').value.trim();
  const resultBox = document.getElementById('result');
  resultBox.classList.remove('success', 'error');
  resultBox.innerHTML = "";

  try {
    const url = new URL(input);
    const hostname = url.hostname.toLowerCase();

    const suspiciousTLDs = ['.tk', '.ml', '.ga', '.cf', '.gq'];
    const knownShorteners = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'is.gd'];
    const redFlags = [];

    // Heuristic checks
    if (url.href.includes('@')) redFlags.push("Contains '@' which can hide real domain");
    if (/^\d+\.\d+\.\d+\.\d+$/.test(hostname)) redFlags.push("Uses IP address instead of domain");
    if (hostname.split('.').length > 5) redFlags.push("Excessive subdomains");
    if (hostname.includes('xn--')) redFlags.push("Uses punycode which may hide lookalike domains");
    if (suspiciousTLDs.some(tld => hostname.endsWith(tld))) redFlags.push("Suspicious top-level domain (TLD)");
    if (knownShorteners.some(short => hostname === short)) redFlags.push("URL shortening service hides destination");
    if (url.protocol !== 'https:') redFlags.push("Does not use HTTPS");
    if (url.href.length > 100) redFlags.push("URL is unusually long");
    if (url.search.split('&').length > 5) redFlags.push("Too many parameters in query string");

    // Create AI box
    const aiBox = document.createElement('div');
    aiBox.classList.add('ai-box');
    aiBox.innerHTML = `<p><strong>Analyzing with AI...</strong></p>`;
    resultBox.appendChild(aiBox);

    // Call Flask backend
    fetch('http://localhost:5000/explain', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        url: url.href,
        redFlags: redFlags
      })
    })
      .then(res => res.json())
      .then(data => {
        if (data.explanation) {
          const isSafe = data.explanation.toLowerCase().includes("likely safe") || data.explanation.toLowerCase().includes("appears safe");
          resultBox.classList.add(isSafe ? "success" : "error");

          aiBox.innerHTML = `
            <strong>🤖 AI Report:</strong><br>
            <div class="wrap-text">${data.explanation}</div>
          `;

          // Add Download Report button
          const downloadBtn = document.createElement("button");
          downloadBtn.textContent = "📄 Download Report";
          downloadBtn.classList.add("info-button");
          downloadBtn.style.marginTop = "15px";

          downloadBtn.onclick = () => {
            fetch('http://localhost:5000/generate_pdf', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({
                url: url.href,
                checklist: redFlags,
                explanation: data.explanation
              })
            })
              .then(res => res.blob())
              .then(blob => {
                const link = document.createElement('a');
                link.href = window.URL.createObjectURL(blob);
                link.download = "phishing_report.pdf";
                link.click();
              });
          };

          aiBox.appendChild(downloadBtn);
        } else {
          aiBox.innerHTML = `<strong>⚠️ AI error:</strong> Could not explain the URL.`;
          resultBox.classList.add("error");
        }
      })
      .catch(() => {
        aiBox.innerHTML = `<strong>⚠️ Connection Error:</strong> Unable to reach AI server.`;
        resultBox.classList.add("error");
      });

  } catch (err) {
    resultBox.textContent = "❌ Invalid URL format!";
    resultBox.classList.add('error');
  }
}
