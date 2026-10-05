document.getElementById("capture").addEventListener("click", async () => {
  const result = document.getElementById("result");
  try {
    const [tab] = await chrome.tabs.query({active:true,currentWindow:true});
    const response = await chrome.tabs.sendMessage(tab.id,{action:"capture-visible-mail"});
    result.textContent = response?.ok ? (response.queued ? "Capture queued for the agent." : "Capture delivered.") : (response?.error || "Capture unavailable.");
  } catch { result.textContent = "Open supported Gmail or Outlook webmail and configure the native agent."; }
});
