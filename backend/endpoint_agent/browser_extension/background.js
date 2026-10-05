const HOST = "com.zanaq.endpoint_capture";
const MAIL_HOSTS = new Set(["mail.google.com", "outlook.office.com", "outlook.office365.com", "outlook.live.com"]);

async function fingerprint(value) {
  const raw = new TextEncoder().encode(value);
  return Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", raw)), b => b.toString(16).padStart(2, "0")).join("");
}

let deliveryChain = Promise.resolve();
function deliver(message) {
  const next = deliveryChain.then(() => deliverOne(message));
  deliveryChain = next.catch(() => {});
  return next;
}

async function deliverOne(message) {
  const key = message.event_key || await fingerprint(JSON.stringify(message));
  message.event_key = key;
  try {
    const response = await chrome.runtime.sendNativeMessage(HOST, message);
    if (!response?.ok) throw new Error("Agent rejected the capture");
    await chrome.storage.local.remove(`pending:${key}`);
    return {ok: true, queued: response.queued};
  } catch {
    const pending = await chrome.storage.local.get(null);
    const keys = Object.keys(pending).filter(key => key.startsWith("pending:"));
    if (keys.length >= 50 && !pending[`pending:${key}`]) return {ok:false, error:"Capture queue is full; connect the native agent before capturing more"};
    try { await chrome.storage.local.set({[`pending:${key}`]: message}); }
    catch { return {ok:false, error:"Browser capture storage is full; connect the native agent before capturing more"}; }
    return {ok: true, queued:true};
  }
}

chrome.runtime.onMessage.addListener((message, sender, reply) => {
  if (message.kind !== "mail" || !sender.tab) return;
  let origin;
  try { origin = new URL(sender.tab.url); } catch { return; }
  if (origin.protocol !== "https:" || !MAIL_HOSTS.has(origin.hostname)) return;
  message.source_url = `${origin.origin}${origin.pathname}`;
  deliver(message).then(reply);
  return true;
});

chrome.downloads.onChanged.addListener(async delta => {
  if (delta.state?.current !== "complete") return;
  const [item] = await chrome.downloads.search({id:delta.id});
  if (!item) return;
  const occurred_at = item.endTime || new Date().toISOString();
  let source_url = "";
  try { const url = new URL(item.finalUrl || item.url); source_url = `${url.origin}${url.pathname}`; } catch {}
  const event_key = await fingerprint(`download:${item.id}:${item.startTime}:${item.filename}`);
  await deliver({kind:"download", event_key, occurred_at, path:item.filename, bytes:Math.max(0,item.fileSize || item.totalBytes || 0), source_url});
});

async function retryPending() {
  const pending = await chrome.storage.local.get(null);
  for (const [key, message] of Object.entries(pending)) if (key.startsWith("pending:")) await deliver(message);
}
chrome.runtime.onStartup.addListener(retryPending);
chrome.runtime.onInstalled.addListener(() => chrome.alarms.create("retry-captures", {periodInMinutes:1}));
chrome.alarms.onAlarm.addListener(alarm => { if (alarm.name === "retry-captures") retryPending(); });
