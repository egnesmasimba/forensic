async function loadMailMessages() {
  const messages = await api("/api/mail/messages");
  if (!state.user) return;
  $("mail-messages").replaceChildren(...messages.map(message => {
    const button = el("button", {type:"button",class:"secondary"}, [message.subject || "Untitled message"]);
    button.addEventListener("click", () => run(() => showMailMessage(message.id)));
    return el("article", {class:"content-hit"}, [button,
      el("p", {class:"muted"}, [`${message.client} · ${message.direction} · ${new Date(message.occurred_at).toLocaleString()} · ${message.attachments} attachments`]),
      el("p", {}, ["Recipient domains: " + (message.recipient_domains.join(", ") || "Unavailable")]),
      el("p", {}, [message.findings.map(f => f.reason).join("; ") || "No configured review rules matched."])]);
  }));
  if (!messages.length) $("mail-messages").append(el("p", {}, ["No email records captured yet."]));
}

async function showMailMessage(id) {
  const message = await api(`/api/mail/messages/${id}`);
  if (!state.user) return;
  const report = message.report;
  const children = [el("h3", {}, [message.subject || "Untitled message"]),
    el("p", {}, [`Sender: ${report.sender || "Unavailable"} · Direction: ${report.direction} · Source: ${message.client}`]),
    el("p", {}, [report.capture_provenance]),
    el("p", {}, ["Recipients: " + report.recipients.map(r => `${r.kind.toUpperCase()} ${r.address} (${r.classification})`).join("; ")]),
    el("p", {}, ["Sensitive terms: " + (report.body_analysis.sensitive_terms.join(", ") || "None matched")])];
  if (report.partial) children.push(el("p", {}, ["Capture is partial. Some content could not be read or exceeded inspection limits."]));
  children.push(el("pre", {}, [report.body || (report.encrypted_message ? "Encrypted message body could not be read." : "No readable message body.")]));
  for (const attachment of report.attachments) {
    const detail = el("details", {}, [el("summary", {}, [`${attachment.filename} · ${attachment.size} bytes · Encryption: ${attachment.encryption}`]),
      el("p", {}, [`Format: ${attachment.format}. ${attachment.encryption_basis || "Encryption coverage unavailable"}. ${attachment.partial ? "Partial inspection." : ""}`]),
      el("p", {}, ["Matched terms: " + (attachment.analysis.sensitive_terms.join(", ") || "None")]),
      el("p", {}, [attachment.notes.join(" ")]), el("pre", {}, [attachment.text || "No readable attachment text."])]);
    children.push(detail);
  }
  if (report.notes.length) children.push(el("p", {}, [report.notes.join(" ")]));
  if (message.alert_id) children.push(el("p", {}, [`Review alert #${message.alert_id} is available in Activity & alerts.`]));
  $("mail-detail").replaceChildren(...children);
}

$("mail-open").addEventListener("click", () => run(async () => {
  await loadMailMessages();
  if (!state.user) return;
  $("mail-import-section").hidden = state.user.role === "viewer";
  $("mail-policy-section").hidden = state.user.role !== "administrator";
  if (state.user.role === "administrator") {
    const policy = await api("/api/mail/policy");
    $("mail-internal-domains").value = policy.internal_domains.join("\n");
    $("mail-sensitive-terms").value = policy.sensitive_terms.join("\n");
  }
  $("mail-dialog").showModal();
}));
$("close-mail").addEventListener("click", () => $("mail-dialog").close());
$("mail-refresh").addEventListener("click", () => run(loadMailMessages));
$("mail-import-form").addEventListener("submit", event => {
  event.preventDefault();
  run(async () => {
    const file = $("mail-eml-file").files[0];
    const text = $("mail-eml-text").value.trim();
    if (!file && !text) throw new Error("Choose an email file or paste the original message.");
    const form = new FormData();
    form.append("file", file || new Blob([text], {type:"message/rfc822"}), file?.name || "provided-message.eml");
    form.append("direction", $("mail-direction").value);
    const result = await api("/api/mail/eml", {method:"POST",body:form});
    if (!state.user) return;
    $("mail-import-result").textContent = result.duplicate ? "This email was already captured." : "Email captured and analyzed.";
    $("mail-eml-file").value = "";
    $("mail-eml-text").value = "";
    await loadMailMessages();
    await showMailMessage(result.id);
  });
});
$("mail-policy-form").addEventListener("submit", event => {
  event.preventDefault();
  run(async () => {
    const values = id => $(id).value.split("\n").map(v => v.trim()).filter(Boolean);
    await api("/api/mail/policy", {method:"PUT",body:JSON.stringify({internal_domains:values("mail-internal-domains"),sensitive_terms:values("mail-sensitive-terms")})});
    toast("Mail policy saved for future captures.");
  });
});
