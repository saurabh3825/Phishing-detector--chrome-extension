document.addEventListener("DOMContentLoaded", () => {
  const statusEl = document.getElementById("status");
  const resultEl = document.getElementById("result");

  // Get the current tab’s URL
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    const currentUrl = tabs[0].url;
    statusEl.textContent = "Checking: " + currentUrl;

    // Call Flask backend
    fetch("http://127.0.0.1:8000/predict", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: currentUrl })
    })
      .then((res) => res.json())
      .then((data) => {
        statusEl.textContent = "Result:";
        if (data.model_result === "phishing" || data.virustotal_result === "phishing") {
          resultEl.textContent = "❌ Phishing Detected!";
          resultEl.className = "phishing";
        } else {
          resultEl.textContent = "✅ Safe Website";
          resultEl.className = "safe";
        }
      })
      .catch((err) => {
        statusEl.textContent = "Error checking site.";
        resultEl.textContent = err.message;
        resultEl.className = "loading";
      });
  });
});
