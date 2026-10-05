// Only supported visible mail elements are read; page scripts and cookies are not captured.
const attachmentsByCompose = new WeakMap();
function composeFor(node) { return node?.closest('[role="dialog"]') || document; }
function visible(node) { return !!node && !!(node.offsetWidth || node.offsetHeight || node.getClientRects().length); }
function firstVisible(selectors, root = document) { return [...root.querySelectorAll(selectors)].find(visible); }
function value(node) { return node?.value || node?.innerText || node?.textContent || ""; }

function snapshot(sendIntent = false, selectedCompose = null) {
  const gmail = location.hostname === "mail.google.com";
  const compose = selectedCompose || firstVisible(gmail ? '[role="dialog"]' : '[role="dialog"], [aria-label="Message body"]') || document;
  const body = firstVisible(gmail ? '[contenteditable="true"][role="textbox"], .a3s' : '[contenteditable="true"][aria-label*="Message body"], [role="document"]', compose);
  if (!body) throw new Error("Open a supported message or compose window first");
  const subject = firstVisible(gmail ? 'input[name="subjectbox"], h2.hP' : 'input[aria-label*="subject" i], [data-testid="message-subject"]', compose);
  const recipients = [];
  for (const kind of ["to", "cc", "bcc"]) {
    const nodes = compose.querySelectorAll(gmail ? `input[name="${kind}"], [name="${kind}"] [email]` : `input[aria-label="${kind}" i], [aria-label="${kind}" i] [data-email-address]`);
    for (const node of nodes) {
      if (!visible(node)) continue;
      const address = node.getAttribute("email") || node.getAttribute("data-email-address") || value(node);
      for (const match of address.matchAll(/[A-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Z0-9.-]+\.[A-Z]{2,}/gi)) {
        if (!recipients.some(r => r.address === match[0])) recipients.push({kind,address:match[0]});
      }
    }
  }
  const sender = firstVisible(gmail ? '.gD[email]' : '[data-testid="message-sender"]');
  return {kind:"mail", occurred_at:new Date().toISOString(), send_intent:sendIntent,
          subject:value(subject).slice(0,200), sender:(sender?.getAttribute("email") || value(sender)).slice(0,320),
          recipients:recipients.slice(0,200), body:value(body).slice(0,32768), attachments:attachmentsByCompose.get(compose) || []};
}

document.addEventListener("change", async event => {
  if (event.target?.type !== "file" || !event.target.files) return;
  const compose = composeFor(event.target);
  const selectedAttachments = [];
  attachmentsByCompose.set(compose, selectedAttachments);
  let total = 0;
  for (const file of [...event.target.files].slice(0,30)) {
    const item = {filename:file.name, size:file.size};
    total += file.size;
    if (total <= 2 * 1024 * 1024) {
      const bytes = new Uint8Array(await file.arrayBuffer());
      let binary = "";
      for (let offset=0; offset<bytes.length; offset+=8192) binary += String.fromCharCode(...bytes.subarray(offset,offset+8192));
      item.data_base64 = btoa(binary);
    }
    selectedAttachments.push(item);
  }
}, true);

document.addEventListener("click", event => {
  const button = event.target.closest('[role="button"],button');
  const label = button?.getAttribute("aria-label") || button?.getAttribute("data-tooltip") || button?.innerText || "";
  if (!/^send(?:\s*\([^)]*\))?$/i.test(label.trim())) return;
  try { chrome.runtime.sendMessage(snapshot(true, composeFor(button))); } catch { /* Unsupported page layout: no fabricated capture. */ }
}, true);

chrome.runtime.onMessage.addListener((message, sender, reply) => {
  if (message.action !== "capture-visible-mail") return;
  try { chrome.runtime.sendMessage(snapshot(false)).then(reply); }
  catch (error) { reply({ok:false,error:error.message}); }
  return true;
});
