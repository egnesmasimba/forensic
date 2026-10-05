const state = {
  user: null,
  meta: null,
  cases: [],
  selectedId: null,
  detail: null,
  linkScale: 1,
  linkGraph: null,
  reports: [],
};

const $ = (id) => document.getElementById(id);

function el(tag, attrs = {}, children = []) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs)) {
    if (key === "class") node.className = value;
    else if (value !== null && value !== undefined) node.setAttribute(key, String(value));
  }
  for (const child of children) {
    node.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return node;
}

function run(work) {
  return Promise.resolve()
    .then(work)
    .catch((error) => toast(error.message, true));
}

function toast(message, isError = false) {
  const node = $("toast");
  node.hidden = false;
  node.textContent = message;
  node.classList.toggle("is-error", isError);
  node.setAttribute("role", isError ? "alert" : "status");
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => {
    node.hidden = true;
  }, 3200);
}

async function api(path, options = {}) {
  const headers = { ...(options.headers || {}) };
  if (state.privacyRaw) headers["X-Privacy-Raw"] = "1";
  const isForm = typeof FormData !== "undefined" && options.body instanceof FormData;
  if (options.body && !isForm) headers["Content-Type"] = "application/json";
  if (state.user) headers["X-CSRF-Token"] = state.user.csrf;
  const response = await fetch(path, { ...options, headers });
  const text = await response.text();
  const data = text ? JSON.parse(text) : null;
  if (!response.ok) {
    if (response.status === 401 && state.user) showLogin();
    let message = "Request failed";
    if (data && typeof data.detail === "string") message = data.detail;
    else if (data && Array.isArray(data.detail)) {
      message = data.detail.map((item) => item.msg || "Invalid value").join(" ");
    }
    throw new Error(message);
  }
  return data;
}

function actor() {
  return state.user.username;
}

function formatWhen(iso) {
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return iso;
  return date.toLocaleString(undefined, {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

function scoreClass(score) {
  if (score >= 90) return "score score-critical";
  if (score >= 70) return "score score-high";
  if (score >= 40) return "score score-mid";
  return "score";
}

function labelStatus(status) {
  return state.meta.status_labels[status] || status;
}

function actionLabel(from, to) {
  if (from === "closed" && to === "investigating") return "Reopen";
  return state.meta.action_labels[to] || to;
}

function fillSelect(select, values, labels) {
  select.replaceChildren();
  for (const value of values) {
    const option = el("option", { value }, [labels ? labels(value) : value]);
    select.append(option);
  }
}

function fillMeta() {
  const status = $("status");
  const current = status.value;
  status.replaceChildren(el("option", { value: "" }, ["Any"]));
  for (const value of state.meta.statuses) {
    status.append(el("option", { value }, [labelStatus(value)]));
  }
  status.value = current;
  fillSelect($("case-type"), state.meta.case_types);
  fillSelect($("case-risk"), state.meta.risk_levels, (value) => value[0].toUpperCase() + value.slice(1));
}

function filterParams() {
  const params = new URLSearchParams({ sort: $("sort").value || "score", order: $("order").value || "desc" });
  const q = $("q").value.trim();
  const status = $("status").value;
  const minScore = $("min-score").value;
  if (q) params.set("q", q);
  if (status) params.set("status", status);
  if (minScore !== "") params.set("min_score", minScore);
  return params;
}

function selectedColumns() {
  return [...document.querySelectorAll("#report-columns input:checked")].map((node) => node.value);
}

async function searchImageText() {
  const term = $("ocr-q").value.trim();
  if (term.length < 2) throw new Error("Enter at least two characters");
  const rows = await api(`/api/ocr/search?q=${encodeURIComponent(term)}`);
  const box = $("ocr-results");
  box.replaceChildren();
  if (!rows.length) box.append(el("p", { class: "muted" }, ["No image text matched."]));
  for (const row of rows) {
    const open = el("button", { type: "button", class: "secondary", "data-view": "true" }, ["Open case"]);
    open.addEventListener("click", () => run(() => openCase(row.case_id)));
    box.append(el("article", { class: "note" }, [
      el("strong", {}, [`${row.filename} | confidence ${row.confidence}`]),
      el("p", {}, [row.snippet]),
      open,
    ]));
  }
}

function downloadReport(path) {
  const params = filterParams();
  const columns = selectedColumns();
  if (columns.length && columns.length < document.querySelectorAll("#report-columns input").length) {
    params.set("columns", columns.join(","));
  }
  const link = document.createElement("a");
  link.href = `${path}?${params.toString()}`;
  link.rel = "noopener";
  document.body.append(link);
  link.click();
  link.remove();
}

function formatSize(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

async function loadList() {
  state.cases = await api(`/api/cases?${filterParams().toString()}`);
  renderList();
}

async function openCase(id) {
  state.selectedId = id;
  state.detail = await api(`/api/cases/${id}`);
  renderList();
  renderDetail();
}

function renderList() {
  const list = $("case-list");
  list.replaceChildren();
  if (!state.cases.length) {
    list.append(el("p", { class: "empty" }, ["No cases match these filters."]));
    return;
  }
  for (const item of state.cases) {
    const button = el("button", {
      type: "button",
      class: `case-row${item.id === state.selectedId ? " is-selected" : ""}`,
    }, [
      el("span", { class: scoreClass(item.score) }, [String(item.score)]),
      el("span", {}, [
        el("strong", {}, [item.title]),
        el("span", { class: "muted" }, [
          `${item.case_type} | ${labelStatus(item.status)} | ${item.alert_count} alert${item.alert_count === 1 ? "" : "s"}`,
        ]),
      ]),
    ]);
    button.addEventListener("click", () => {
      openCase(item.id).catch((error) => toast(error.message, true));
    });
    list.append(button);
  }
}

function renderDetail() {
  const panel = $("detail-panel");
  panel.replaceChildren();
  const detail = state.detail;
  if (!detail) {
    panel.append(el("p", { class: "empty" }, ["Select a case to review the file."]));
    return;
  }

  const transitions = el("div", { class: "transition-row" });
  const note = el("input", { id: "transition-note", maxlength: "4000", placeholder: "Optional note" });
  transitions.append(note);
  for (const next of state.meta.transitions[detail.status] || []) {
    const button = el("button", { type: "button" }, [actionLabel(detail.status, next)]);
    if (next !== "closed") button.classList.add("secondary");
    button.addEventListener("click", () => run(() => changeStatus(detail.id, next, note.value)));
    transitions.append(button);
  }

  const title = el("input", { id: "detail-title", value: detail.title, maxlength: "200" });
  const summary = el("textarea", { id: "detail-summary", rows: "4", maxlength: "4000" });
  summary.value = detail.summary;
  const conclusion = el("textarea", { id: "detail-conclusion", rows: "3", maxlength: "4000" });
  conclusion.value = detail.conclusion;
  const assignee = el("input", { id: "detail-assignee", value: detail.assignee, maxlength: "120" });
  const risk = el("select", { id: "detail-risk" });
  fillSelect(risk, state.meta.risk_levels, (value) => value[0].toUpperCase() + value.slice(1));
  risk.value = detail.risk;
  const score = el("input", { id: "detail-score", type: "number", min: "0", max: "1000", value: String(detail.score) });
  const type = el("select", { id: "detail-type" });
  fillSelect(type, state.meta.case_types);
  type.value = detail.case_type;

  const save = el("button", { type: "button", id: "save-details" }, ["Save details"]);
  save.addEventListener("click", () => run(() => saveDetails(detail.id)));
  const fieldWrap = el("div", { id: "detail-fields", class: "stack" });
  appendFieldInputs(fieldWrap, detail.fields);
  type.addEventListener("change", () => run(() => reloadDetailFields(type.value)));

  panel.append(
    el("div", { class: "detail-head" }, [
      el("div", {}, [
        el("h2", {}, [detail.title]),
        el("p", { class: "muted" }, [
          `${labelStatus(detail.status)} | updated ${formatWhen(detail.updated_at)}`,
        ]),
      ]),
      el("span", { class: scoreClass(detail.score) }, [String(detail.score)]),
    ]),
    el("p", {}, [el("span", { class: "pill" }, [detail.case_type]), " ", el("span", { class: "pill" }, [detail.risk])]),
    el("p", { class: "row-actions" }, [
      el("a", { class: "button-link", href: `/api/reports/cases/${detail.id}.pdf` }, ["Download PDF"]),
      " ",
      el("a", { class: "button-link", href: `/api/reports/cases/${detail.id}/package.zip` }, ["Download package"]),
    ]),
    transitions,
    el("div", { class: "stack" }, [
      el("label", {}, ["Title", title]),
      el("div", { class: "split" }, [
        el("label", {}, ["Type", type]),
        el("label", {}, ["Risk", risk]),
      ]),
      el("div", { class: "split" }, [
        el("label", {}, ["Score", score]),
        el("label", {}, ["Assignee", assignee]),
      ]),
      el("label", {}, ["Summary", summary]),
      el("label", {}, ["Conclusion", conclusion]),
      fieldWrap,
      el("div", {}, [save]),
    ]),
    renderTimeline(detail),
    renderAlerts(detail),
    renderNotes(detail),
    renderAttachments(detail),
    renderActivity(detail),
  );
  if (state.user.role === "viewer") {
    panel.querySelectorAll("input, textarea, select, button:not([data-view])").forEach(node => node.disabled = true);
    transitions.hidden = true;
    save.hidden = true;
    panel.querySelectorAll("form").forEach(node => node.hidden = true);
  }
}

function renderAlerts(detail) {
  const wrap = el("section", { class: "stack" }, [el("h3", {}, ["Alerts"])]);
  if (!detail.alerts.length) wrap.append(el("p", { class: "muted" }, ["No alerts linked yet."]));
  for (const alert of detail.alerts) {
    const dismiss = el("button", { type: "button", class: "secondary" }, ["Dismiss"]);
    dismiss.addEventListener("click", () => run(() => dismissAlert(alert.id)));
    wrap.append(el("article", { class: "alert-card" }, [
      el("div", {}, [
        el("strong", {}, [`${alert.score} | ${alert.title}`]),
        el("p", { class: "muted" }, [
          `${alert.entity_type} ${alert.entity_ref} | ${alert.channel || "No channel"} | ${alert.status}`,
        ]),
        el("p", {}, [alert.description]),
      ]),
      dismiss,
    ]));
  }

  const form = el("form", { id: "alert-form", class: "stack" });
  const alertTitle = el("input", { id: "alert-title", required: "true", minlength: "3", maxlength: "200" });
  const alertScore = el("input", { id: "alert-score", type: "number", min: "0", max: "1000", value: "0", required: "true" });
  const entityType = el("select", { id: "alert-entity-type" });
  fillSelect(entityType, state.meta.entity_types, (value) => value[0].toUpperCase() + value.slice(1));
  const entityRef = el("input", { id: "alert-entity-ref", maxlength: "120" });
  const channel = el("input", { id: "alert-channel", maxlength: "80" });
  const description = el("textarea", { id: "alert-description", rows: "3", maxlength: "4000" });
  form.append(
    el("h3", {}, ["Add alert"]),
    el("label", {}, ["Title", alertTitle]),
    el("div", { class: "split" }, [
      el("label", {}, ["Score", alertScore]),
      el("label", {}, ["Entity type", entityType]),
    ]),
    el("div", { class: "split" }, [
      el("label", {}, ["Entity reference", entityRef]),
      el("label", {}, ["Channel", channel]),
    ]),
    el("label", {}, ["Description", description]),
    el("button", { type: "submit" }, ["Add alert"]),
  );
  form.addEventListener("submit", (event) => {
    event.preventDefault();
    run(() => addAlert(detail.id));
  });
  wrap.append(form);
  return wrap;
}

function renderTimeline(detail) {
  const items = [
    ...(detail.activities || []).map((item) => ({ at: item.created_at, text: `${item.actor || "Investigator"} | ${item.detail}` })),
    ...(detail.notes || []).map((item) => ({ at: item.created_at, text: `${item.author} | ${item.body}` })),
    ...(detail.alerts || []).map((item) => ({ at: item.created_at, text: `Alert ${item.score} | ${item.title}` })),
    ...(detail.attachments || []).map((item) => ({ at: item.created_at, text: `File | ${item.original_name}` })),
  ].sort((left, right) => String(left.at).localeCompare(String(right.at)));
  const wrap = el("section", { class: "stack" }, [el("h3", {}, ["Case timeline"])]);
  if (!items.length) wrap.append(el("p", { class: "muted" }, ["No case records yet."]));
  for (const item of items) {
    wrap.append(el("article", { class: "activity" }, [
      el("span", { class: "muted" }, [formatWhen(item.at)]),
      el("p", {}, [item.text]),
    ]));
  }
  return wrap;
}

function renderNotes(detail) {
  const wrap = el("section", { class: "stack" }, [el("h3", {}, ["Notes"])]);
  if (!detail.notes.length) wrap.append(el("p", { class: "muted" }, ["No notes yet."]));
  for (const note of detail.notes) {
    wrap.append(el("article", { class: "note" }, [
      el("strong", {}, [note.author]),
      el("span", { class: "muted" }, [` | ${formatWhen(note.created_at)}`]),
      el("p", {}, [note.body]),
    ]));
  }
  const form = el("form", { id: "note-form" });
  const body = el("textarea", { id: "note-body", rows: "3", maxlength: "4000", required: "true" });
  form.append(el("label", {}, ["Add note", body]), el("button", { type: "submit" }, ["Add note"]));
  form.addEventListener("submit", (event) => {
    event.preventDefault();
    run(() => addNote(detail.id, body.value));
  });
  wrap.append(form);
  return wrap;
}

function renderAttachments(detail) {
  const wrap = el("section", { class: "stack" }, [el("h3", {}, ["Attachments"])]);
  const files = detail.attachments || [];
  if (!files.length) wrap.append(el("p", { class: "muted" }, ["No files attached."]));
  for (const file of files) {
    const actions = [];
    if (state.user.role !== "viewer") {
      const remove = el("button", { type: "button", class: "secondary" }, ["Remove"]);
      remove.addEventListener("click", () => run(() => removeAttachment(detail.id, file.id)));
      actions.push(remove);
    }
    if (state.user.role !== "viewer" && (file.content_type === "image/png" || file.content_type === "image/jpeg")) {
      const language = el("select", { "aria-label": "OCR language" });
      for (const [code, label] of [["eng", "English"], ["fra", "French"], ["deu", "German"], ["spa", "Spanish"], ["por", "Portuguese"], ["ita", "Italian"], ["nld", "Dutch"], ["pol", "Polish"], ["rus", "Russian"], ["ara", "Arabic"]]) {
        language.append(el("option", { value: code }, [label]));
      }
      const read = el("button", { type: "button" }, ["Read image text"]);
      read.addEventListener("click", () => run(async () => {
        await api(`/api/ocr/attachments/${file.id}?language=${language.value}`, { method: "POST" });
        toast("Image text saved");
        await refresh(detail.id);
      }));
      actions.push(language, read);
    }
    const verify = el("button", { type: "button", class: "secondary", "data-view": "true" }, ["Verify hash"]);
    verify.addEventListener("click", () => run(async () => {
      const result = await api(`/api/cases/${detail.id}/attachments/${file.id}/integrity`);
      toast(result.detail);
    }));
    actions.push(verify);
    wrap.append(el("article", { class: "alert-card" }, [
      el("div", {}, [
        el("a", { href: `/api/cases/${detail.id}/attachments/${file.id}` }, [file.original_name]),
        el("p", { class: "muted" }, [
          `${formatSize(file.size)} | ${file.uploaded_by} | ${formatWhen(file.created_at)}`,
        ]),
        el("p", { class: "muted" }, [file.sha256 ? `SHA-256 ${file.sha256}` : "No stored hash"]),
      ]),
      ...(file.ocr_text ? [el("p", {}, [`${file.ocr_language} | confidence ${file.ocr_confidence} | ${file.ocr_text}`])] : []),
      ...actions,
    ]));
  }
  const form = el("form", { id: "attachment-form" });
  const input = el("input", {
    id: "attachment-file",
    type: "file",
    required: "true",
    accept: ".pdf,.png,.jpg,.jpeg,.txt,.csv,.xlsx,.docx",
  });
  form.append(
    el("label", {}, ["Add a file", input]),
    el("button", { type: "submit" }, ["Upload file"]),
  );
  form.addEventListener("submit", (event) => {
    event.preventDefault();
    const file = input.files && input.files[0];
    if (!file) return;
    run(() => uploadAttachment(detail.id, file));
  });
  if (state.user.role !== "viewer") wrap.append(form);
  return wrap;
}

function renderActivity(detail) {
  const wrap = el("section", { class: "stack" }, [el("h3", {}, ["Activity"])]);
  for (const item of detail.activities) {
    wrap.append(el("article", { class: "activity" }, [
      el("strong", {}, [item.actor || "Investigator"]),
      el("span", { class: "muted" }, [` | ${formatWhen(item.created_at)}`]),
      el("p", {}, [item.detail]),
    ]));
  }
  return wrap;
}

async function refresh(id) {
  await loadList();
  if (id) await openCase(id);
  else if (state.selectedId && state.cases.some((item) => item.id === state.selectedId)) {
    await openCase(state.selectedId);
  } else if (state.cases.length) {
    await openCase(state.cases[0].id);
  } else {
    state.selectedId = null;
    state.detail = null;
    renderDetail();
  }
}

async function saveDetails(id) {
  await api(`/api/cases/${id}`, {
    method: "PATCH",
    body: JSON.stringify({
      title: $("detail-title").value,
      case_type: $("detail-type").value,
      risk: $("detail-risk").value,
      score: Number($("detail-score").value),
      assignee: $("detail-assignee").value,
      summary: $("detail-summary").value,
      conclusion: $("detail-conclusion").value,
      fields: collectFields($("detail-panel")),
      actor: actor(),
    }),
  });
  toast("Case details saved");
  await refresh(id);
}

async function changeStatus(id, status, note) {
  await api(`/api/cases/${id}/transition`, {
    method: "POST",
    body: JSON.stringify({ status, actor: actor(), note }),
  });
  toast(`Moved to ${labelStatus(status)}`);
  await refresh(id);
}

async function addNote(id, body) {
  await api(`/api/cases/${id}/notes`, {
    method: "POST",
    body: JSON.stringify({ author: actor(), body }),
  });
  toast("Note added");
  await refresh(id);
}

async function addAlert(caseId) {
  await api("/api/alerts", {
    method: "POST",
    body: JSON.stringify({
      title: $("alert-title").value,
      score: Number($("alert-score").value),
      entity_type: $("alert-entity-type").value,
      entity_ref: $("alert-entity-ref").value,
      channel: $("alert-channel").value,
      description: $("alert-description").value,
      case_id: caseId,
      actor: actor(),
    }),
  });
  toast("Alert linked");
  await refresh(caseId);
}

async function uploadAttachment(caseId, file) {
  const body = new FormData();
  body.append("file", file);
  body.append("actor", actor());
  await api(`/api/cases/${caseId}/attachments`, { method: "POST", body });
  toast("File attached");
  await refresh(caseId);
}

async function removeAttachment(caseId, attachmentId) {
  await api(`/api/cases/${caseId}/attachments/${attachmentId}`, { method: "DELETE" });
  toast("File removed");
  await refresh(caseId);
}

async function dismissAlert(id) {
  await api(`/api/alerts/${id}`, {
    method: "PATCH",
    body: JSON.stringify({ status: "dismissed", actor: actor() }),
  });
  toast("Alert dismissed");
  await refresh(state.selectedId);
}

function bind() {
  let timer = 0;
  $("filters").addEventListener("input", () => {
    clearTimeout(timer);
    timer = setTimeout(() => {
      loadList().catch((error) => toast(error.message, true));
    }, 200);
  });
  $("filters").addEventListener("submit", (event) => event.preventDefault());
  $("ocr-search").addEventListener("click", () => run(searchImageText));
  $("export-csv").addEventListener("click", () => downloadReport("/api/reports/cases.csv"));
  $("export-excel").addEventListener("click", () => downloadReport("/api/reports/cases.xlsx"));
  $("apply-report").addEventListener("click", () => run(applySavedReport));
  $("save-report").addEventListener("click", () => run(saveReport));
  $("delete-report").addEventListener("click", () => run(deleteReport));
  $("new-case").addEventListener("click", () => run(async () => {
    await showCreateFields();
    $("case-dialog").showModal();
  }));
  $("case-type").addEventListener("change", () => run(showCreateFields));
  $("case-risk").addEventListener("change", () => run(refreshRouteHint));
  $("case-assignee").addEventListener("input", () => run(refreshRouteHint));
  $("cancel-case").addEventListener("click", () => $("case-dialog").close());
  $("case-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    try {
      const created = await api("/api/cases", {
        method: "POST",
        body: JSON.stringify({
          title: $("case-title").value,
          case_type: $("case-type").value,
          risk: $("case-risk").value,
          score: Number($("case-score").value),
          assignee: $("case-assignee").value,
          summary: $("case-summary").value,
          fields: collectFields($("case-fields")),
          actor: actor(),
        }),
      });
      $("case-form").reset();
      $("case-score").value = "0";
      $("case-dialog").close();
      toast("Case created");
      await refresh(created.id);
    } catch (error) {
      toast(error.message, true);
    }
  });
}


function showLogin() {
  if ($('iam-dialog')) {
    $('iam-dialog').close();
    ['iam-ticket','iam-enrollment','iam-accounts','iam-audit','iam-sessions','iam-requests','iam-status'].forEach(id => $(id).replaceChildren());
    ['iam-password','iam-hardware','iam-old-code','iam-old-challenge','iam-confirm-code'].forEach(id => $(id).value='');
  }
  state.user = null;
  state.privacyRaw = false;
  if ($("privacy-dashboard")) $("privacy-dashboard").hidden = true;
  ["privacy-open", "education-open", "phase3-open", "iam-open"].forEach(id => { if ($(id)) $(id).hidden = true; });
  state.cases = [];
  state.detail = null;
  state.selectedId = null;
  document.querySelector("main").hidden = true;
  $("case-list").replaceChildren();
  $("detail-panel").replaceChildren();
  $("signed-user").textContent = "";
  $("login-panel").hidden = false;
  $("logout").hidden = true;
  $("change-password").hidden = true;
  $("new-case").hidden = true;
  $("manage-users").hidden = true;
  $("network-open").hidden = true;
  $("search-open").hidden = true;
  $("mail-open").hidden = true;
  $("replay-open").hidden = true;
  $("response-open").hidden = true;
  if (typeof stopResponsePolling === "function") stopResponsePolling();
  ["mail-messages", "mail-detail"].forEach(id => $(id).replaceChildren());
  ["mail-eml-file", "mail-eml-text", "mail-internal-domains", "mail-sensitive-terms"].forEach(id => { $(id).value = ""; });
  $("mail-import-result").textContent = "";
  ["content-results", "content-detail"].forEach(id => $(id).replaceChildren());
  ["content-index-status", "content-result-status", "content-import-status", "content-text", "content-query", "content-title"].forEach(id => { if ("value" in $(id)) $(id).value = ""; else $(id).textContent = ""; });
  $("applications-open").hidden = true;
  $("agents-open").hidden = true;
  $("endpoint-events-open").hidden = true;
  $("network-captures").replaceChildren();
  $("network-sessions").replaceChildren();
  $("network-result").textContent = "";
  $("layout-result").textContent = "";
  $("saved-layouts").replaceChildren();
  $("auth-audit").replaceChildren();
  $("activity-import").hidden = true;
  $("inbox-alerts").replaceChildren();
  $("alert-groups").replaceChildren();
  $("open-links").hidden = true;
  $("open-processes").hidden = true;
  $("open-analytics").hidden = true;
  $("open-profiles").hidden = true;
  $("open-dlp").hidden = true;
  $("open-compliance").hidden = true;
  $("open-automation").hidden = true;
  $("open-setup").hidden = true;
  $("inbox-alerts").replaceChildren();
  $("import-events").replaceChildren();
  $("import-result").textContent = "";
  document.querySelectorAll("dialog[open]").forEach(dialog => dialog.close());
}

async function signedIn(user) {
  state.user = user;
  $("phase3-open").hidden = false;
  $("password").value = "";
  $("signed-user").textContent = `${user.username} | ${user.role}`;
  $("login-panel").hidden = true;
  $("logout").hidden = false;
  $("change-password").hidden = false;
  $("new-case").hidden = user.role === "viewer";
  $("manage-users").hidden = user.role !== "administrator";
  $("activity-import").hidden = false;
  $("network-open").hidden = false;
  $("search-open").hidden = false;
  $("mail-open").hidden = false;
  $("replay-open").hidden = false;
  $("response-open").hidden = false;
  $("applications-open").hidden = user.role !== "administrator";
  $("agents-open").hidden = user.role === "viewer";
  $("endpoint-events-open").hidden = user.role === "viewer";
  $("network-form").hidden = user.role === "viewer";
  $("layout-form").hidden = user.role === "viewer";
  $("open-links").hidden = false;
  $("open-processes").hidden = false;
  $("open-analytics").hidden = false;
  $("open-profiles").hidden = false;
  $("open-dlp").hidden = false;
  $("open-compliance").hidden = user.role !== "administrator";
  $("open-automation").hidden = false;
  ["playbook-form", "notice-form", "trigger-form"].forEach((id) => { $(id).hidden = user.role === "viewer"; });
  ["dlp-text-form", "dlp-policy-form", "dlp-usb-form", "dlp-cloud-form", "dlp-print-form", "dlp-screenshot-form", "alert-policy-form", "alert-route-form"].forEach((id) => { $(id).hidden = user.role === "viewer"; });
  $("refresh-profile").hidden = user.role === "viewer";
  $("build-twin").hidden = user.role === "viewer";
  $("outcome-form").hidden = user.role === "viewer";
  $("library-form").hidden = user.role === "viewer";
  $("update-library").hidden = user.role === "viewer";
  $("entity-form").hidden = user.role === "viewer";
  $("rule-form").hidden = user.role === "viewer";
  $("evaluate-rules").hidden = user.role === "viewer";
  $("save-score-threshold").hidden = user.role === "viewer";
  $("indicator-form").hidden = user.role === "viewer";
  $("save-baseline").hidden = user.role === "viewer";
  $("refresh-baselines").hidden = user.role === "viewer";
  $("channel-form").hidden = user.role === "viewer";
  $("process-form").hidden = user.role === "viewer";
  $("screen-form").hidden = user.role === "viewer";
  $("navigation-form").hidden = user.role === "viewer";
  $("open-setup").hidden = user.role !== "administrator";
  $("website-rule-form").hidden = user.role !== "administrator";
  $("import-form").hidden = user.role === "viewer";
  ["collect-form", "table-form", "layout-form", "layout-apply", "queue-form", "run-collection", "email-form", "traffic-form", "website-form"].forEach((id) => {
    $(id).hidden = user.role === "viewer";
  });
  state.meta = await api("/api/meta");
  fillMeta();
  fillSetupSelects();
  document.querySelector("main").hidden = false;
  $("save-report").hidden = user.role === "viewer";
  $("delete-report").hidden = user.role === "viewer";
  $("report-name").parentElement.hidden = user.role === "viewer";
  if (document.readyState === "loading") await new Promise(resolve => document.addEventListener("DOMContentLoaded", resolve, {once:true}));
  if (typeof initializeIdentity === "function" && await initializeIdentity()) return;
  if (typeof initializePrivacy === "function" && await initializePrivacy()) return;
  await loadReports();
  await refresh();
}

async function loadReports() {
  state.reports = await api("/api/reports/templates");
  const choice = $("saved-reports");
  const current = choice.value;
  choice.replaceChildren(el("option", { value: "" }, ["Current filters"]));
  for (const report of state.reports) choice.append(el("option", { value: report.id }, [report.name]));
  if ([...choice.options].some((option) => option.value === current)) choice.value = current;
}

async function saveReport() {
  const columns = selectedColumns();
  if (!columns.length) throw new Error("Choose at least one column");
  await api("/api/reports/templates", {
    method: "POST",
    body: JSON.stringify({
      name: $("report-name").value,
      columns,
      status: $("status").value,
      query: $("q").value.trim(),
      min_score: $("min-score").value === "" ? null : Number($("min-score").value),
      sort: $("sort").value,
      order: $("order").value,
    }),
  });
  $("report-name").value = "";
  toast("Report saved");
  await loadReports();
}

async function applySavedReport() {
  const report = (state.reports || []).find((item) => String(item.id) === $("saved-reports").value);
  if (!report) return;
  $("q").value = report.query || "";
  $("status").value = report.status || "";
  $("min-score").value = report.min_score == null ? "" : String(report.min_score);
  $("sort").value = report.sort;
  $("order").value = report.order;
  document.querySelectorAll("#report-columns input").forEach((node) => {
    node.checked = report.columns.includes(node.value);
  });
  await loadList();
}

async function deleteReport() {
  if (!$("saved-reports").value) throw new Error("Choose a saved report");
  await api(`/api/reports/templates/${$("saved-reports").value}`, { method: "DELETE" });
  toast("Report deleted");
  await loadReports();
}

async function loadUsers() {
  const users = await api("/api/auth/users");
  await loadAuthAudit();
  $("users-list").replaceChildren(...users.map((account) => {
    const password = el("input", { type: "password", maxlength: "256", placeholder: "New password", autocomplete: "new-password" });
    const setPassword = el("button", { type: "button" }, ["Set password"]);
    setPassword.addEventListener("click", () => run(async () => {
      if (password.value.length < 12) throw new Error("Use at least 12 characters");
      await api(`/api/auth/users/${account.id}/password`, { method: "POST", body: JSON.stringify({ password: password.value }) });
      password.value = "";
      toast("Password updated");
    }));
    const toggle = el("button", { type: "button", class: "secondary" }, [account.disabled ? "Enable" : "Disable"]);
    toggle.addEventListener("click", () => run(async () => {
      await api(`/api/auth/users/${account.id}`, { method: "PATCH", body: JSON.stringify({ disabled: !account.disabled }) });
      await loadUsers();
    }));
    return el("article", { class: "alert-card" }, [
      el("div", {}, [
        el("strong", {}, [`${account.username} | ${account.role}`]),
        el("p", { class: "muted" }, [account.disabled ? "Disabled" : "Enabled"]),
      ]),
      password,
      setPassword,
      toggle,
    ]);
  }));
}

async function boot() {
  bind();
  bindImports();
  bindStructure();
  bindProcesses();
  bindAnalytics();
  bindProfiles();
  bindDlp();
  bindAutomation();
showLogin();
    // Self-registration is opt-in, so the form stays hidden unless the deployment
    // says so. A failure here must not block sign-in, so it is swallowed.
    run(async () => {
      try {
        const status = await api("/api/auth/registration");
        const form = $("register-form");
        if (form && status.enabled) {
          $("register-password").minLength = status.password_minimum;
          $("register-confirm").minLength = status.password_minimum;
          form.hidden = false;
        }
      } catch (error) { /* registration stays hidden */ }
    });
    $("register-form").addEventListener("submit", event => {
      event.preventDefault();
      run(async () => {
        const password = $("register-password").value;
        if (password !== $("register-confirm").value) throw new Error("Passwords do not match");
        const created = await api("/api/auth/register", {
          method: "POST", body: JSON.stringify({username: $("register-username").value, password})
        });
        $("register-form").reset();
        toast(created.message || "Account created");
      });
    });
    $("login-form").addEventListener("submit", event => {
    event.preventDefault();
    run(async () => signedIn(await api("/api/auth/login", {
      method: "POST", body: JSON.stringify({username: $("username").value, password: $("password").value,
        otp: $("login-otp").value, challenge_id: $("login-challenge").value,
        personal_username: $("login-personal").value, personal_password: $("login-personal-password").value})
    })));
  });
  $("change-password").addEventListener("click", () => $("password-dialog").showModal());
  $("close-password").addEventListener("click", () => $("password-dialog").close());
  $("password-form").addEventListener("submit", (event) => {
    event.preventDefault();
    run(async () => {
      await api("/api/auth/password", { method: "POST", body: JSON.stringify({
        current_password: $("current-password").value, new_password: $("new-password").value,
      }) });
      $("password-form").reset();
      $("password-dialog").close();
      toast("Password updated");
    });
  });
  $("logout").addEventListener("click", () => run(async () => {
    await api("/api/auth/logout", {method: "POST"});
    showLogin();
  }));
  $("manage-users").addEventListener("click", () => run(async () => {
    await loadUsers();
    $("users-dialog").showModal();
  }));
  $("refresh-auth-audit").addEventListener("click", () => run(loadAuthAudit));
  $("close-users").addEventListener("click", () => $("users-dialog").close());
  if (typeof bindAgentsUI === "function") bindAgentsUI();
  $("agents-open").addEventListener("click", () => run(async () => {
    await Promise.all([loadAgents(), loadAgentGroups(), loadEndpointEventFilters()]);
    $("agents-dialog").showModal();
  }));
  $("close-agents").addEventListener("click", () => $("agents-dialog").close());
  $("endpoint-events-open").addEventListener("click", () => run(async () => {
    await loadEndpointEventFilters();
    await loadEndpointEvents();
    $("endpoint-events-dialog").showModal();
  }));
  $("close-endpoint-events").addEventListener("click", () => $("endpoint-events-dialog").close());
  $("user-form").addEventListener("submit", event => {
    event.preventDefault();
    run(async () => {
      await api("/api/auth/users", {method: "POST", body: JSON.stringify({
        username: $("user-username").value, password: $("user-password").value, role: $("user-role").value
      })});
      $("user-form").reset();
      await loadUsers();
      toast("Account created");
    });
  });
  try { await signedIn(await api("/api/auth/me")); }
  catch (error) { showLogin(); }
}

boot();


async function loadImportInbox() {
  const [alerts, events, cases, groups] = await Promise.all([
    api("/api/alerts?status=open"), api("/api/imports/events"), api("/api/cases"), api("/api/alerts/groups")
  ]);
  $("inbox-alerts").replaceChildren();
  if (!alerts.length) $("inbox-alerts").append(el("p", {}, ["No open alerts."]));
  for (const alert of alerts) {
    const card = el("article", {class: "alert-card"}, [el("div", {}, [
      el("strong", {}, [`${alert.score} | ${alert.title}`]),
      el("p", {}, [`${alert.entity_ref} | ${alert.channel}${alert.assignee ? ` | assigned to ${alert.assignee}` : ""}`]),
      el("p", {}, [alert.description])
    ])]);
    if (state.user.role !== "viewer") {
      const actions = el("div", {class: "stack"});
      const select = el("select", {"aria-label": "Case for alert"});
      select.append(el("option", {value: ""}, ["Choose a case"]));
      for (const item of cases) select.append(el("option", {value: item.id}, [item.title]));
      const link = el("button", {type: "button"}, ["Link to case"]);
      link.addEventListener("click", () => run(async () => {
        if (!select.value) throw new Error("Choose a case first. Create one from New case if needed.");
        await api(`/api/alerts/${alert.id}`, {method: "PATCH", body: JSON.stringify({case_id: Number(select.value)})});
        await refresh(Number(select.value));
        await loadImportInbox();
        toast("Alert linked to case");
      }));
      const dismiss = el("button", {type: "button", class: "secondary"}, ["Dismiss"]);
      dismiss.addEventListener("click", () => run(async () => {
        await api(`/api/alerts/${alert.id}`, {method: "PATCH", body: JSON.stringify({status: "dismissed"})});
        await loadImportInbox();
      }));
      actions.append(select, link, dismiss);
      card.append(actions);
    }
    $("inbox-alerts").append(card);
  }
  $("import-events").replaceChildren(...events.map(item => el("article", {class: "note"}, [
    el("strong", {}, [`${item.event.user} | ${item.event.action}`]),
    el("p", {}, [`${item.source} | ${item.event.event_id} | ${formatWhen(item.event.occurred_at)}`]),
    el("p", {class: "muted"}, [`Imported by ${item.imported_by}${item.alert_id ? ` | Alert #${item.alert_id}` : " | No rule matched"}`])
  ])));
  if (!events.length) $("import-events").append(el("p", {}, ["No activity imported yet."]));
  $("alert-groups").replaceChildren();
  if (!groups.length) $("alert-groups").append(el("p", {}, ["No entity has more than one open or linked alert."]));
  for (const group of groups) {
    $("alert-groups").append(el("article", {class: "note"}, [
      el("strong", {}, [group.entity_ref]),
      el("p", {}, [group.alerts.map((item) => `${item.score} ${item.title}`).join(" | ")]),
    ]));
  }
}

function bindImports() {
  $("activity-import").addEventListener("click", () => run(async () => {
    await loadImportInbox();
    if (state.user.role !== "viewer") await loadLayouts();
    if (state.user.role === "administrator") await loadWebsiteRules();
    $("imports-dialog").showModal();
  }));
  $("close-imports").addEventListener("click", () => $("imports-dialog").close());
  $("alert-policy-form").addEventListener("submit", (event) => {
    event.preventDefault();
    run(async () => {
      await api("/api/alerts/policies", {method: "POST", body: JSON.stringify({
        kind: $("policy-kind").value, entity_ref: $("policy-entity").value, title: $("policy-title").value, channel: $("policy-channel").value,
      })});
      toast("Suppression saved");
    });
  });
  $("alert-route-form").addEventListener("submit", (event) => {
    event.preventDefault();
    run(async () => {
      await api("/api/alerts/routes", {method: "POST", body: JSON.stringify({
        channel: $("route-channel").value, min_score: Number($("route-score").value), assignee: $("route-assignee").value, delivery: $("route-delivery").value,
      })});
      toast("Route saved");
    });
  });
  $("import-form").addEventListener("submit", event => {
    event.preventDefault();
    run(async () => {
      const button = $("import-form").querySelector("button[type=submit]");
      button.disabled = true;
      $("import-result").textContent = "Importing activity...";
      try {
        const body = new FormData();
        body.append("source", $("import-source").value);
        body.append("file", $("import-file").files[0]);
        const result = await api("/api/imports/csv", {method: "POST", body});
        $("import-result").textContent = `${result.accepted} events imported, ${result.duplicates} duplicates skipped, ${result.alerts_created} alerts created.`;
        $("import-file").value = "";
        await loadImportInbox();
      } catch (error) {
        $("import-result").textContent = error.message;
        throw error;
      } finally { button.disabled = false; }
    });
  });
  $("email-form").addEventListener("submit", (event) => submitUpload(event, "/api/imports/email", "email-source", "email-file"));
  $("traffic-form").addEventListener("submit", (event) => submitUpload(event, "/api/imports/traffic", "traffic-source", "traffic-file"));
  $("website-form").addEventListener("submit", (event) => submitUpload(event, "/api/websites/visits", "website-source", "website-file"));
  $("website-rule-form").addEventListener("submit", (event) => {
    event.preventDefault();
    run(async () => {
      await api("/api/websites/rules", { method: "POST", body: JSON.stringify({
        host: $("website-host").value, category: $("website-category").value,
      }) });
      $("website-host").value = "";
      toast("Hostname mapped");
      await loadWebsiteRules();
    });
  });
  $("collect-form").addEventListener("submit", (event) => submitUpload(event, "/api/collectors/file", "collect-source", "collect-file"));
  $("table-form").addEventListener("submit", (event) => {
    event.preventDefault();
    run(async () => {
      const body = new FormData();
      body.append("source", $("table-source").value);
      body.append("table", $("table-name").value);
      body.append("file", $("table-file").files[0]);
      const result = await api("/api/collectors/table", { method: "POST", body });
      $("import-result").textContent = collectionSummary(result);
      $("table-file").value = "";
      await loadImportInbox();
    });
  });
  $("layout-form").addEventListener("submit", (event) => {
    event.preventDefault();
    run(async () => {
      await api("/api/collectors/layouts", {
        method: "POST",
        body: JSON.stringify({
          name: $("layout-name").value,
          mode: $("layout-mode").value,
          delimiter: $("layout-delimiter").value,
          spec: JSON.parse($("layout-spec").value),
        }),
      });
      $("layout-name").value = "";
      toast("Layout saved");
      await loadLayouts();
    });
  });
  $("layout-apply").addEventListener("submit", (event) => {
    event.preventDefault();
    run(async () => {
      const body = new FormData();
      body.append("source", "Record layout");
      body.append("file", $("layout-file").files[0]);
      const result = await api(`/api/collectors/layouts/${$("layout-choice").value}/apply`, { method: "POST", body });
      $("import-result").textContent = collectionSummary(result);
      $("layout-file").value = "";
      await loadImportInbox();
    });
  });
  $("queue-form").addEventListener("submit", (event) => {
    event.preventDefault();
    run(async () => {
      const result = await api("/api/collectors/queue", {
        method: "POST",
        body: JSON.stringify({ message: JSON.parse($("queue-body").value) }),
      });
      $("import-result").textContent = collectionSummary(result);
      $("queue-body").value = "";
      await loadImportInbox();
    });
  });
  $("run-collection").addEventListener("click", () => run(async () => {
    const result = await api("/api/collectors/run", { method: "POST" });
    $("import-result").textContent = `Scheduled collection accepted ${result.accepted} item(s).`;
    await loadImportInbox();
  }));
}

function collectionSummary(result) {
  if (result.duplicate) return "That file was already collected.";
  const correlated = (result.correlations || []).length;
  const accepted = result.accepted ?? 1;
  const alerts = result.alerts_created ? `, ${result.alerts_created} alert(s) created` : "";
  return `Collected ${accepted} item(s)${alerts}${correlated ? `, ${correlated} matched existing alerts` : ""}.`;
}

async function loadWebsiteRules() {
  const [categories, rules, report] = await Promise.all([
    api("/api/websites/categories"),
    api("/api/websites/rules"),
    api("/api/websites/report"),
  ]);
  const select = $("website-category");
  const current = select.value;
  select.replaceChildren(...categories.filter((name) => name !== "Uncategorized").map((name) => el("option", { value: name }, [name])));
  if ([...select.options].some((option) => option.value === current)) select.value = current;
  $("website-rules").replaceChildren(...rules.map((rule) => {
    const remove = el("button", { type: "button", class: "secondary" }, ["Remove"]);
    remove.addEventListener("click", () => run(async () => {
      await api(`/api/websites/rules/${rule.id}`, { method: "DELETE" });
      await loadWebsiteRules();
    }));
    return el("article", { class: "note" }, [el("strong", {}, [`${rule.host} | ${rule.category}`]), remove]);
  }));
  const box = $("website-report");
  box.replaceChildren();
  if (!report.length) box.append(el("p", { class: "muted" }, ["No website visits imported."]));
  for (const row of report) {
    box.append(el("p", {}, [`${row.category}: ${row.visits} visits, ${row.seconds} seconds, ${row.users} users`]));
  }
}

async function loadLayouts() {
  const layouts = await api("/api/collectors/layouts");
  const choice = $("layout-choice");
  choice.replaceChildren();
  for (const layout of layouts) choice.append(el("option", { value: layout.id }, [`${layout.name} (${layout.mode})`]));
}

function submitUpload(event, path, sourceId, fileId) {
  event.preventDefault();
  run(async () => {
    const body = new FormData();
    body.append("source", $(sourceId).value);
    body.append("file", $(fileId).files[0]);
    const result = await api(path, { method: "POST", body });
    $("import-result").textContent = collectionSummary(result);
    $(fileId).value = "";
    await loadImportInbox();
  });
}

function collectFields(root) {
  const fields = {};
  if (!root) return fields;
  root.querySelectorAll("[data-field-key]").forEach((input) => {
    fields[input.getAttribute("data-field-key")] = input.value;
  });
  return fields;
}

function appendFieldInputs(wrap, fields) {
  wrap.replaceChildren();
  if (!fields.length) return;
  wrap.append(el("h3", {}, ["Case fields"]));
  for (const field of fields) {
    const input = el("input", { maxlength: "500", value: field.value || "" });
    input.dataset.fieldKey = field.key;
    if (field.required) input.required = true;
    wrap.append(el("label", {}, [field.required ? `${field.label} *` : field.label, input]));
  }
}

async function reloadDetailFields(caseType) {
  const fields = await api(`/api/structure/fields?case_type=${encodeURIComponent(caseType)}`);
  const current = collectFields($("detail-fields"));
  appendFieldInputs($("detail-fields"), fields.map((field) => ({ ...field, value: current[field.key] || "" })));
}

async function showCreateFields() {
  const fields = await api(`/api/structure/fields?case_type=${encodeURIComponent($("case-type").value)}`);
  appendFieldInputs($("case-fields"), fields);
  await refreshRouteHint();
}

async function refreshRouteHint() {
  const hint = $("route-hint");
  if ($("case-assignee").value.trim()) {
    hint.textContent = "";
    return;
  }
  const params = new URLSearchParams({ case_type: $("case-type").value, risk: $("case-risk").value });
  const match = await api(`/api/routes/match?${params.toString()}`);
  hint.textContent = match.rule ? `A blank assignee routes to ${match.rule.assignee} (${match.rule.name}).` : "";
}

function fillSetupSelects() {
  fillSelect($("field-type"), state.meta.case_types);
  const routeType = $("route-type");
  routeType.replaceChildren(el("option", { value: "" }, ["Any type"]));
  for (const value of state.meta.case_types) routeType.append(el("option", { value }, [value]));
  fillSelect($("route-risk"), state.meta.risk_levels, (value) => value[0].toUpperCase() + value.slice(1));
  const linkType = $("link-type");
  const current = linkType.value;
  linkType.replaceChildren(el("option", { value: "" }, ["Any"]));
  for (const value of state.meta.entity_types) linkType.append(el("option", { value }, [value]));
  linkType.value = current;
}

async function loadSetup() {
  const [fields, routes] = await Promise.all([api("/api/structure/fields"), api("/api/routes")]);
  const fieldList = $("field-list");
  fieldList.replaceChildren();
  if (!fields.length) fieldList.append(el("p", { class: "muted" }, ["No extra fields yet."]));
  for (const field of fields) {
    const remove = el("button", { type: "button", class: "secondary" }, ["Remove"]);
    remove.addEventListener("click", () => run(async () => {
      await api(`/api/structure/fields/${field.id}`, { method: "DELETE" });
      await loadSetup();
    }));
    fieldList.append(el("article", { class: "alert-card" }, [
      el("div", {}, [el("strong", {}, [field.label]), el("p", { class: "muted" }, [`${field.case_type} | ${field.key}${field.required ? " | required" : ""}`])]),
      remove,
    ]));
  }
  const routeList = $("route-list");
  routeList.replaceChildren();
  if (!routes.length) routeList.append(el("p", { class: "muted" }, ["No routing rules yet."]));
  for (const rule of routes) {
    const remove = el("button", { type: "button", class: "secondary" }, ["Remove"]);
    remove.addEventListener("click", () => run(async () => {
      await api(`/api/routes/${rule.id}`, { method: "DELETE" });
      await loadSetup();
    }));
    routeList.append(el("article", { class: "alert-card" }, [
      el("div", {}, [
        el("strong", {}, [rule.name]),
        el("p", { class: "muted" }, [`${rule.case_type || "Any type"} | ${rule.min_risk} or higher | ${rule.assignee}`]),
      ]),
      remove,
    ]));
  }
  await loadDetection();
}

async function loadDetection() {
  const rules = await api("/api/detection/settings");
  const list = $("detection-list");
  list.replaceChildren();
  for (const rule of rules) {
    const threshold = el("input", { type: "number", min: "1", value: String(rule.threshold) });
    const score = el("input", { type: "number", min: "0", max: "1000", value: String(rule.score) });
    const enabled = el("input", { type: "checkbox" });
    enabled.checked = rule.enabled;
    const save = el("button", { type: "button" }, ["Save"]);
    save.addEventListener("click", () => run(async () => {
      await api(`/api/detection/settings/${rule.rule_id}`, {
        method: "PUT",
        body: JSON.stringify({ threshold: Number(threshold.value), score: Number(score.value), enabled: enabled.checked }),
      });
      toast("Threshold saved");
      await loadDetection();
    }));
    list.append(el("article", { class: "alert-card" }, [
      el("div", {}, [el("strong", {}, [rule.label]), el("p", { class: "muted" }, [rule.rule_id])]),
      el("label", {}, ["Threshold", threshold]),
      el("label", {}, ["Score", score]),
      el("label", { class: "inline" }, [enabled, " Enabled"]),
      save,
    ]));
  }
}

function slugKey(label) {
  return label.toLowerCase().replace(/[^a-z0-9]+/g, "_").replace(/^_|_$/g, "").slice(0, 40);
}

function bindAutomation() {
  $("open-automation").addEventListener("click", () => run(async () => {
    await loadAutomation();
    $("automation-dialog").showModal();
  }));
  $("close-automation").addEventListener("click", () => $("automation-dialog").close());
  $("playbook-form").addEventListener("submit", (event) => {
    event.preventDefault();
    run(async () => {
      await api("/api/automation/playbooks", { method: "POST", body: JSON.stringify({
        name: $("playbook-name").value, trigger: $("playbook-trigger").value, steps: $("playbook-steps").value,
      }) });
      toast("Playbook saved");
      await loadAutomation();
    });
  });
  $("notice-form").addEventListener("submit", (event) => {
    event.preventDefault();
    run(async () => {
      await api("/api/automation/notices", { method: "POST", body: JSON.stringify({ user: $("notice-user").value, message: $("notice-message").value }) });
      toast("Notice recorded");
      await loadAutomation();
    });
  });
  $("trigger-form").addEventListener("submit", (event) => {
    event.preventDefault();
    run(async () => {
      const created = await api("/api/automation/triggers", { method: "POST", body: JSON.stringify({ name: $("trigger-name").value, detail: "Recorded for confirmation" }) });
      await api(`/api/automation/triggers/${created.id}/confirm`, { method: "POST" });
      toast("Trigger confirmed");
    });
  });
}

async function loadAutomation() {
  const [playbooks, notices] = await Promise.all([api("/api/automation/playbooks"), api("/api/automation/notices")]);
  $("playbook-list").replaceChildren(...playbooks.map((row) => el("p", {}, [`${row.name} | ${row.trigger} | ${row.steps}`])));
  const list = $("notice-list");
  list.replaceChildren();
  if (!notices.length) list.append(el("p", { class: "muted" }, ["No notices yet."]));
  for (const row of notices) list.append(el("p", {}, [`${row.channel} | ${row.user} | ${row.subject}`]));
}

function bindDlp() {
  $("open-dlp").addEventListener("click", () => run(async () => {
    const saved = await api("/api/dlp/policy");
    $("dlp-min").value = saved.min_matches;
    $("dlp-score").value = saved.score;
    $("dlp-ip").value = saved.ip_terms;
    $("dlp-customer").value = saved.customer_terms;
    $("dlp-financial").value = saved.financial_terms;
    await loadDlpAudit();
    $("dlp-dialog").showModal();
  }));
  $("close-dlp").addEventListener("click", () => $("dlp-dialog").close());
  $("dlp-text-form").addEventListener("submit", (event) => {
    event.preventDefault();
    run(async () => {
      const result = await api("/api/dlp/inspect", { method: "POST", body: JSON.stringify({ user: $("dlp-user").value, text: $("dlp-text").value }) });
      $("dlp-result").textContent = result.opened ? `Review alert opened (${result.categories.join(", ")}).` : "No review alert.";
      await loadDlpAudit();
    });
  });
  $("dlp-policy-form").addEventListener("submit", (event) => {
    event.preventDefault();
    run(async () => {
      await api("/api/dlp/policy", { method: "PUT", body: JSON.stringify({
        min_matches: Number($("dlp-min").value), score: Number($("dlp-score").value),
        ip_terms: $("dlp-ip").value, customer_terms: $("dlp-customer").value, financial_terms: $("dlp-financial").value,
      }) });
      toast("DLP policy saved");
      await loadDlpAudit();
    });
  });
  $("dlp-usb-form").addEventListener("submit", (event) => {
    event.preventDefault();
    run(async () => {
      await api("/api/dlp/usb", { method: "PUT", body: JSON.stringify({ serial: $("usb-serial").value, label: $("usb-label").value, allowed: true }) });
      toast("USB device allowed");
    });
  });
  $("dlp-print-form").addEventListener("submit", (event) => {
    event.preventDefault();
    run(async () => {
      const result = await api("/api/dlp/print", { method: "POST", body: JSON.stringify({
        user: $("print-user").value, printer: $("print-printer").value, document: $("print-document").value,
        pages: Number($("print-pages").value), size: Number($("print-size").value), occurred_at: new Date().toISOString(),
      }) });
      $("dlp-result").textContent = result.opened ? "Print job recorded." : "Print job stored.";
    });
  });
  $("dlp-screenshot-form").addEventListener("submit", (event) => {
    event.preventDefault();
    run(async () => {
      const result = await api("/api/dlp/screenshots", { method: "POST", body: JSON.stringify({
        user: $("screenshot-user").value, application: $("screenshot-application").value, occurred_at: new Date().toISOString(),
      }) });
      $("dlp-result").textContent = result.opened ? "Screenshot attempt recorded." : "Screenshot attempt stored.";
    });
  });
  $("dlp-cloud-form").addEventListener("submit", (event) => {
    event.preventDefault();
    run(async () => {
      await api("/api/dlp/cloud", { method: "PUT", body: JSON.stringify({ host: $("cloud-host").value, allowed: true }) });
      toast("Cloud host allowed");
    });
  });
}

async function loadDlpAudit() {
  const rows = await api("/api/dlp/audit");
  const list = $("dlp-audit");
  list.replaceChildren();
  if (!rows.length) list.append(el("p", { class: "muted" }, ["No policy changes yet."]));
  for (const row of rows) list.append(el("p", {}, [`${row.actor}: ${row.change}`]));
}

function bindProfiles() {
  $("open-profiles").addEventListener("click", () => run(async () => {
    if (!$("profile-user").value && state.user) $("profile-user").value = state.user.username;
    await loadProfile();
    $("profiles-dialog").showModal();
  }));
  $("close-profiles").addEventListener("click", () => $("profiles-dialog").close());
  $("show-profile").addEventListener("click", () => run(loadProfile));
  $("refresh-profile").addEventListener("click", () => run(async () => {
    const result = await api("/api/profiles/refresh", { method: "POST", body: JSON.stringify({ entity_ref: $("profile-user").value }) });
    $("profile-result").textContent = `${result.alerts_created} profile alerts created.`;
    await loadProfile();
  }));
  $("build-twin").addEventListener("click", () => run(async () => {
    const twin = await api("/api/profiles/synthetic", { method: "POST", body: JSON.stringify({ entity_ref: $("profile-user").value }) });
    $("profile-result").textContent = `Synthetic profile ${twin.token}`;
  }));
  $("outcome-form").addEventListener("submit", (event) => {
    event.preventDefault();
    run(async () => {
      await api(`/api/profiles/predictions/${$("prediction-id").value}/outcome`, { method: "POST", body: JSON.stringify({ outcome: $("prediction-outcome").value }) });
      toast("Outcome saved");
      await loadProfile();
    });
  });
  $("library-form").addEventListener("submit", (event) => {
    event.preventDefault();
    run(async () => {
      await api(`/api/profiles/library/${encodeURIComponent($("library-key").value)}`, { method: "PUT", body: JSON.stringify({
        enabled: $("library-enabled").value === "true",
        threshold: Number($("library-threshold").value),
        score: Number($("library-score").value),
      }) });
      toast("Library rule saved");
      await loadProfile();
    });
  });
  $("update-library").addEventListener("click", () => run(async () => {
    const result = await api("/api/profiles/library/update", { method: "POST" });
    $("profile-result").textContent = `${result.added} library rules added.`;
    await loadProfile();
  }));
}

async function loadProfile() {
  const name = $("profile-user").value.trim();
  if (!name) return;
  const [picture, time, peer, library, accuracy] = await Promise.all([
    api(`/api/profiles/review?entity_ref=${encodeURIComponent(name)}`),
    api(`/api/profiles/time?entity_ref=${encodeURIComponent(name)}`),
    api(`/api/profiles/peers?entity_ref=${encodeURIComponent(name)}`),
    api("/api/profiles/library"),
    api("/api/profiles/predictions/accuracy"),
  ]);
  $("profile-summary").replaceChildren(
    el("p", {}, [`Threat score ${picture.threat.score}`]),
    el("p", {}, [`Workload score ${picture.workload.score} | long days ${picture.workload.overwork_days}`]),
    el("p", {}, [`Work ${time.work} | meeting ${time.meeting_minutes} | idle ${time.idle_minutes}`]),
    el("p", {}, [`Sentiment ${picture.sentiment.label} | ${picture.sentiment.average.toFixed(2)}`]),
    el("p", {}, [`Transfers ${peer.transfer_count} | peer mean ${peer.peer_mean.toFixed(2)}`]),
  );
  $("accuracy-line").textContent = `Confirmed ${accuracy.confirmed} | dismissed ${accuracy.dismissed} | accuracy ${accuracy.rate.toFixed(2)}`;
  $("library-list").replaceChildren(...library.map((rule) => el("p", {}, [
    `${rule.framework} | ${rule.key} | ${rule.enabled ? "enabled" : "disabled"} | ${rule.threshold}`,
  ])));
}

function bindAnalytics() {
  $("open-analytics").addEventListener("click", () => run(async () => {
    if (!$("behavior-user").value && state.user) $("behavior-user").value = state.user.username;
    await loadAnalytics();
    await loadBehavior();
    $("analytics-dialog").showModal();
  }));
  $("close-analytics").addEventListener("click", () => $("analytics-dialog").close());
  $("entity-form").addEventListener("submit", (event) => {
    event.preventDefault();
    run(async () => {
      await api("/api/analytics/entities", { method: "PUT", body: JSON.stringify({
        entity_type: $("entity-type").value, entity_ref: $("entity-ref").value,
        attribute_key: $("entity-attribute").value, attribute_value: $("entity-value").value,
      }) });
      toast("Entity attribute saved");
      await loadAnalytics();
    });
  });
  $("rule-form").addEventListener("submit", (event) => {
    event.preventDefault();
    run(async () => {
      await api("/api/analytics/rules", { method: "POST", body: JSON.stringify(rulePayload()) });
      toast("Rule version saved");
      await loadAnalytics();
    });
  });
  $("test-rule").addEventListener("click", () => run(async () => {
    const result = await api("/api/analytics/rules/test", { method: "POST", body: JSON.stringify(rulePayload()) });
    const lines = result.matches.map((match) => `${match.entity_ref} ${match.value}`);
    $("analytics-result").textContent = lines.length ? lines.join(" | ") : "No match.";
  }));
  $("evaluate-rules").addEventListener("click", () => run(async () => {
    const result = await api("/api/analytics/evaluate", { method: "POST" });
    $("analytics-result").textContent = `${result.facts} facts checked, ${result.alerts_created} alerts created.`;
    await loadAnalytics();
  }));
  $("save-score-threshold").addEventListener("click", () => run(async () => {
    await api("/api/analytics/score-threshold", { method: "PUT", body: JSON.stringify({ threshold: Number($("score-threshold").value) }) });
    toast("Score threshold saved");
  }));
  $("show-behavior").addEventListener("click", () => run(loadBehavior));
  $("indicator-form").addEventListener("submit", (event) => {
    event.preventDefault();
    run(async () => {
      await api("/api/analytics/indicators", { method: "POST", body: JSON.stringify({
        key: $("indicator-key").value, label: $("indicator-label").value, fact_name: $("indicator-fact").value,
        measure: $("indicator-measure").value, period: $("indicator-period").value,
      }) });
      toast("Indicator saved");
      await loadBehavior();
    });
  });
  $("save-baseline").addEventListener("click", () => run(async () => {
    await api("/api/analytics/baseline-settings", { method: "PUT", body: JSON.stringify({
      sigma: Number($("baseline-sigma").value), minimum_periods: Number($("baseline-minimum").value),
    }) });
    toast("Baseline settings saved");
    await loadBehavior();
  }));
  $("refresh-baselines").addEventListener("click", () => run(async () => {
    const result = await api("/api/analytics/baselines/refresh", { method: "POST", body: JSON.stringify({ entity_ref: $("behavior-user").value }) });
    $("analytics-result").textContent = `${result.alerts_created} baseline alerts created.`;
    await loadBehavior();
  }));
  $("channel-form").addEventListener("submit", (event) => {
    event.preventDefault();
    run(async () => {
      const when = new Date($("channel-time").value).toISOString();
      await api("/api/analytics/channels", { method: "POST", body: JSON.stringify({ events: [{
        source_key: `${$("channel-name").value}:${$("behavior-user").value}:${when}`,
        channel: $("channel-name").value, user: $("behavior-user").value, occurred_at: when,
        action: $("channel-action").value, reference: $("channel-reference").value,
      }] }) });
      toast("Channel event recorded");
      await loadBehavior();
    });
  });
}

async function loadBehavior() {
  const name = $("behavior-user").value.trim();
  if (!name) return;
  const [indicators, baselines, channels] = await Promise.all([
    api(`/api/analytics/indicators?entity_ref=${encodeURIComponent(name)}`),
    api(`/api/analytics/baselines?entity_ref=${encodeURIComponent(name)}`),
    api(`/api/analytics/channels?user=${encodeURIComponent(name)}`),
  ]);
  $("baseline-sigma").value = baselines.sigma;
  $("baseline-minimum").value = baselines.minimum_periods;
  $("indicator-list").replaceChildren(...indicators.map((row) => el("p", {}, [
    `${row.label}: ${row.coverage === "no observations" ? "no observations" : row.average.toFixed(3) + " per " + row.period}`,
  ])));
  const deviations = baselines.indicators.filter((row) => row.deviated).map((row) => row.label);
  $("baseline-list").replaceChildren(el("p", { class: "muted" }, [
    deviations.length ? `Above baseline: ${deviations.join(", ")}` : "No current period is above the baseline.",
  ]));
  const view = $("channel-view");
  view.replaceChildren();
  for (const [channel, detail] of Object.entries(channels.channels)) {
    view.append(el("p", {}, [`${channel}: ${detail.count}`]));
  }
}

function rulePayload() {
  return {
    name: $("rule-name").value, version: Number($("rule-version").value), kind: $("rule-kind").value,
    entity_type: $("rule-entity").value, fact_name: $("rule-fact").value,
    aggregation: $("rule-aggregation").value, comparator: $("rule-comparator").value,
    threshold: Number($("rule-threshold").value), score: Number($("rule-score").value),
    attribute_key: $("rule-attribute").value, attribute_value: $("rule-attribute-value").value,
    list_mode: $("rule-list-mode").value, list_values: $("rule-list").value, pattern: $("rule-pattern").value,
    start_hour: Number($("rule-start-hour").value), end_hour: Number($("rule-end-hour").value),
    steps: $("rule-steps").value,
  };
}

async function loadAnalytics() {
  const [entities, rules, scores] = await Promise.all([
    api("/api/analytics/entities"), api("/api/analytics/rules"), api("/api/analytics/scores"),
  ]);
  $("score-threshold").value = scores.threshold;
  $("entity-list").replaceChildren(...entities.map((entity) => el("article", { class: "note" }, [
    el("strong", {}, [`${entity.entity_type} ${entity.entity_ref}`]),
    el("p", {}, [Object.entries(entity.static_info).map(([key, value]) => `${key}=${value}`).join(" | ") || "No static attributes"]),
    el("p", { class: "muted" }, [`Facts ${entity.dynamic_info.fact_count || 0} | last ${entity.dynamic_info.last_occurred_at || "none"}`]),
  ])));
  $("rule-list").replaceChildren(...rules.map((rule) => el("article", { class: "note" }, [
    el("strong", {}, [`${rule.name} v${rule.version} | ${rule.kind} | ${rule.aggregation} ${rule.fact_name} ${rule.comparator} ${rule.threshold}`]),
    el("p", { class: "muted" }, [rule.attribute_key ? `Only ${rule.attribute_key}=${rule.attribute_value}` : "Every entity of this type"]),
  ])));
  const history = $("score-history");
  history.replaceChildren();
  if (!scores.history.length) history.append(el("p", { class: "muted" }, ["No score changes yet."]));
  for (const row of scores.history) {
    history.append(el("p", {}, [`${row.entity_ref} score ${row.score} (${row.delta >= 0 ? "+" : ""}${row.delta}) ${row.reason}`]));
  }
}

function bindProcesses() {
  state.screenDraft = null;
  $("open-processes").addEventListener("click", () => run(async () => {
    await loadProcesses();
    $("process-dialog").showModal();
  }));
  $("close-processes").addEventListener("click", () => $("process-dialog").close());
  $("process-form").addEventListener("submit", (event) => {
    event.preventDefault();
    run(async () => {
      await api("/api/processes", { method: "POST", body: JSON.stringify({
        name: $("process-name").value, description: $("process-description").value,
      }) });
      $("process-form").reset();
      toast("Process added");
      await loadProcesses();
    });
  });
  $("process-choice").addEventListener("change", () => run(loadProcessAudit));
  $("screen-form").addEventListener("submit", (event) => {
    event.preventDefault();
    run(saveScreenMarker);
  });
  $("add-screen-field").addEventListener("click", () => run(addScreenField));
  $("add-process-step").addEventListener("click", () => run(addProcessStep));
  $("navigation-form").addEventListener("submit", (event) => {
    event.preventDefault();
    run(checkNavigation);
  });
}

async function loadProcesses() {
  const [processes, screens, fields] = await Promise.all([
    api("/api/processes"), api("/api/screens"), api("/api/audit/fields"),
  ]);
  state.processes = processes;
  state.screens = screens;
  const choice = $("process-choice");
  const current = choice.value;
  choice.replaceChildren();
  for (const process of processes) choice.append(el("option", { value: process.id }, [process.name]));
  if ([...choice.options].some((option) => option.value === current)) choice.value = current;
  $("process-list").replaceChildren(...processes.map((process) => el("article", { class: "note" }, [
    el("strong", {}, [process.name]),
    el("p", {}, [process.steps.map((step) => `${step.position}. ${step.screen_name}`).join(" | ") || "No screens yet"]),
  ])));
  $("screen-list").replaceChildren(...screens.map((screen) => el("article", { class: "note" }, [
    el("strong", {}, [screen.name]),
    el("p", {}, [
      screen.markers.map((marker) => `line ${marker.line}: ${marker.text}`).join(" | ") || "No markers",
    ]),
    el("p", { class: "muted" }, [
      screen.fields.map((field) => `${field.label} line ${field.line} col ${field.start_column} ${field.action}`).join(" | ") || "No fields",
    ]),
  ])));
  renderFieldAudit(fields);
  await loadProcessAudit();
}

async function saveScreenMarker() {
  const name = $("screen-name").value.trim();
  const marker = $("marker-text").value.trim();
  if (!marker) throw new Error("Enter the text that identifies the screen");
  let screen = state.screenDraft && state.screenDraft.name === name ? state.screenDraft : null;
  if (!screen) {
    screen = await api("/api/screens", { method: "POST", body: JSON.stringify({ name }) });
    state.screenDraft = screen;
  }
  screen = await api(`/api/screens/${screen.id}/markers`, {
    method: "POST",
    body: JSON.stringify({ text: marker, line: Number($("marker-line").value || 0) }),
  });
  state.screenDraft = screen;
  $("marker-text").value = "";
  toast("Screen marker saved");
  await loadProcesses();
}

async function addScreenField() {
  if (!state.screenDraft) throw new Error("Save the screen before adding a field");
  const screen = await api(`/api/screens/${state.screenDraft.id}/fields`, {
    method: "POST",
    body: JSON.stringify({
      name: $("capture-name").value,
      label: $("capture-label").value,
      line: Number($("capture-line").value),
      start_column: Number($("capture-column").value),
      length: Number($("capture-length").value),
      action: $("capture-action").value,
    }),
  });
  state.screenDraft = screen;
  toast("Field placed");
  await loadProcesses();
}

async function addProcessStep() {
  if (!state.screenDraft) throw new Error("Save the screen before adding it to the process");
  if (!$("process-choice").value) throw new Error("Add a business process first");
  await api(`/api/processes/${$("process-choice").value}/steps`, {
    method: "POST",
    body: JSON.stringify({ screen_id: state.screenDraft.id }),
  });
  toast("Screen added to the navigation");
  await loadProcesses();
}

async function checkNavigation() {
  if (!$("process-choice").value) throw new Error("Choose a business process");
  const texts = $("navigation-text").value.split(/\n---\n/).map((part) => part.trim()).filter(Boolean);
  if (!texts.length) throw new Error("Enter the screen transcripts");
  const result = await api(`/api/processes/${$("process-choice").value}/apply`, {
    method: "POST",
    body: JSON.stringify({ texts }),
  });
  toast("Navigation recorded");
  renderAudit(result.audit);
  renderFieldAudit(await api("/api/audit/fields"));
}

async function loadProcessAudit() {
  if (!$("process-choice").value) {
    $("process-audit").replaceChildren(el("p", { class: "muted" }, ["No process selected."]));
    return;
  }
  renderAudit(await api(`/api/processes/${$("process-choice").value}/audit`));
}

function renderAudit(audit) {
  const box = $("process-audit");
  box.replaceChildren();
  if (!audit.rows.length) box.append(el("p", { class: "muted" }, ["No completed navigation yet."]));
  for (const row of audit.rows) {
    box.append(el("article", { class: "note" }, [
      el("strong", {}, [`${row.When} | ${row["Recorded by"]}`]),
      el("p", {}, [audit.columns.filter((column) => column !== "When" && column !== "Recorded by").map((column) => `${column}: ${row[column]}`).join(" | ")]),
    ]));
  }
}

function renderFieldAudit(rows) {
  const box = $("field-audit");
  box.replaceChildren();
  if (!rows.length) box.append(el("p", { class: "muted" }, ["No field values captured."]));
  for (const row of rows) {
    box.append(el("article", { class: "note" }, [
      el("strong", {}, [`${row.screen} | ${row.field} | ${row.action}`]),
      el("p", {}, [`${row.value} | ${row.source} | ${row.recorded_by}`]),
    ]));
  }
}

function bindStructure() {
  $("open-setup").addEventListener("click", () => run(async () => {
    await loadSetup();
    $("setup-dialog").showModal();
  }));
  $("close-setup").addEventListener("click", () => $("setup-dialog").close());
  $("field-label").addEventListener("input", () => {
    if ($("field-key").dataset.touched === "1") return;
    $("field-key").value = slugKey($("field-label").value);
  });
  $("field-key").addEventListener("input", () => {
    $("field-key").dataset.touched = "1";
  });
  $("field-form").addEventListener("submit", (event) => {
    event.preventDefault();
    run(async () => {
      await api("/api/structure/fields", {
        method: "POST",
        body: JSON.stringify({
          case_type: $("field-type").value,
          key: $("field-key").value,
          label: $("field-label").value,
          required: $("field-required").checked,
        }),
      });
      $("field-label").value = "";
      $("field-key").value = "";
      $("field-key").dataset.touched = "";
      $("field-required").checked = false;
      toast("Field added");
      await loadSetup();
    });
  });
  $("route-form").addEventListener("submit", (event) => {
    event.preventDefault();
    run(async () => {
      await api("/api/routes", {
        method: "POST",
        body: JSON.stringify({
          name: $("route-name").value,
          case_type: $("route-type").value,
          min_risk: $("route-risk").value,
          assignee: $("route-assignee").value,
        }),
      });
      $("route-name").value = "";
      $("route-assignee").value = "";
      toast("Routing rule added");
      await loadSetup();
    });
  });
  $("open-links").addEventListener("click", () => run(async () => {
    state.linkScale = 1;
    $("links-dialog").showModal();
    await loadLinks();
  }));
  $("close-links").addEventListener("click", () => $("links-dialog").close());
  $("links-form").addEventListener("submit", (event) => {
    event.preventDefault();
    run(loadLinks);
  });
  $("zoom-in").addEventListener("click", () => {
    state.linkScale = Math.min(2, (state.linkScale || 1) + 0.25);
    if (state.linkGraph) drawLinks(state.linkGraph);
  });
  $("zoom-out").addEventListener("click", () => {
    state.linkScale = Math.max(0.6, (state.linkScale || 1) - 0.25);
    if (state.linkGraph) drawLinks(state.linkGraph);
  });
}

async function loadLinks() {
  const params = new URLSearchParams({ depth: $("link-depth").value });
  if ($("link-type").value) params.set("anchor_type", $("link-type").value);
  if ($("link-ref").value.trim()) params.set("anchor_ref", $("link-ref").value.trim());
  if ($("link-start").value) params.set("start", $("link-start").value);
  if ($("link-end").value) params.set("end", $("link-end").value);
  drawLinks(await api(`/api/links?${params.toString()}`), true);
}

function zoomedViewBox(width, height) {
  const scale = state.linkScale || 1;
  const w = width / scale;
  const h = height / scale;
  return `${(width - w) / 2} ${(height - h) / 2} ${w} ${h}`;
}

function layoutNodes(nodes, width, height) {
  const anchorRef = $("link-ref").value.trim();
  const center = nodes.find((node) => node.kind === "entity" && node.entity_ref === anchorRef) || nodes[0];
  const positions = { [center.id]: { x: width / 2, y: height / 2 } };
  const others = nodes.filter((node) => node.id !== center.id);
  others.forEach((node, index) => {
    const ring = 1 + Math.floor(index / 8);
    const slot = index % 8;
    const count = Math.min(8, others.length - (ring - 1) * 8);
    const angle = (slot / Math.max(count, 1)) * Math.PI * 2 - Math.PI / 2;
    const radius = 130 * ring;
    positions[node.id] = {
      x: width / 2 + Math.cos(angle) * radius,
      y: height / 2 + Math.sin(angle) * radius * 0.72,
    };
  });
  return positions;
}

function svgEl(name) {
  return document.createElementNS("http://www.w3.org/2000/svg", name);
}

function drawLinks(graph, resetFocus = false) {
  state.linkGraph = graph;
  const canvas = $("link-canvas");
  canvas.replaceChildren();
  if (resetFocus) $("link-focus").replaceChildren();
  if (!graph.nodes.length) {
    canvas.append(el("p", { class: "empty" }, ["No entities in this range."]));
    return;
  }
  const width = 640;
  const height = 420;
  const svg = svgEl("svg");
  svg.setAttribute("viewBox", zoomedViewBox(width, height));
  const positions = layoutNodes(graph.nodes, width, height);
  for (const edge of graph.edges) {
    const from = positions[edge.source];
    const to = positions[edge.target];
    if (!from || !to) continue;
    const line = svgEl("line");
    line.setAttribute("x1", from.x);
    line.setAttribute("y1", from.y);
    line.setAttribute("x2", to.x);
    line.setAttribute("y2", to.y);
    line.setAttribute("stroke", "#9aafb8");
    line.setAttribute("stroke-width", "1.5");
    svg.append(line);
  }
  for (const node of graph.nodes) {
    const at = positions[node.id];
    const group = svgEl("g");
    group.setAttribute("class", "link-node");
    const shape = svgEl(node.kind === "case" ? "rect" : "ellipse");
    const tone = node.fraudulent ? "link-fraud" : node.investigating ? "link-open" : node.kind === "case" ? "link-case" : "link-plain";
    shape.setAttribute("class", tone);
    if (node.kind === "case") {
      shape.setAttribute("x", at.x - 58);
      shape.setAttribute("y", at.y - 16);
      shape.setAttribute("width", "116");
      shape.setAttribute("height", "32");
      shape.setAttribute("rx", "8");
    } else {
      shape.setAttribute("cx", at.x);
      shape.setAttribute("cy", at.y);
      shape.setAttribute("rx", "50");
      shape.setAttribute("ry", "18");
    }
    const text = svgEl("text");
    text.setAttribute("x", at.x);
    text.setAttribute("y", at.y + 4);
    text.setAttribute("text-anchor", "middle");
    text.setAttribute("font-size", "11");
    text.textContent = node.label.length > 16 ? `${node.label.slice(0, 15)}...` : node.label;
    group.append(shape, text);
    group.addEventListener("click", () => selectLinkNode(node));
    svg.append(group);
  }
  canvas.append(svg);
  if (graph.truncated) canvas.append(el("p", { class: "muted" }, ["Showing the first 80 nodes."]));
}

function selectLinkNode(node) {
  const wrap = $("link-focus");
  wrap.replaceChildren();
  if (node.kind === "case") {
    const open = el("button", { type: "button" }, ["Open case"]);
    open.addEventListener("click", () => run(async () => {
      $("links-dialog").close();
      await openCase(node.case_id);
    }));
    wrap.append(el("p", {}, [node.label]), open);
    return;
  }
  wrap.append(el("strong", {}, [`${node.entity_type} ${node.entity_ref}`]));
  const related = state.linkGraph.edges
    .filter((edge) => edge.source === node.id)
    .map((edge) => state.linkGraph.nodes.find((item) => item.id === edge.target))
    .filter(Boolean);
  if (!related.length) wrap.append(el("p", { class: "muted" }, ["This entity is not on a case in the current view."]));
  for (const item of related) {
    const open = el("button", { type: "button", class: "secondary" }, [`Open ${item.label}`]);
    open.addEventListener("click", () => run(async () => {
      $("links-dialog").close();
      await openCase(item.case_id);
    }));
    wrap.append(open);
  }
  const center = el("button", { type: "button", class: "secondary" }, ["Center on this entity"]);
  center.addEventListener("click", () => run(async () => {
    $("link-type").value = node.entity_type;
    $("link-ref").value = node.entity_ref;
    await loadLinks();
  }));
  wrap.append(center);
  if (state.user.role !== "viewer") {
    const mark = el("button", { type: "button" }, [node.fraudulent ? "Clear fraudulent mark" : "Mark fraudulent"]);
    mark.addEventListener("click", () => run(async () => {
      await api("/api/links/marks", {
        method: "PUT",
        body: JSON.stringify({
          entity_type: node.entity_type,
          entity_ref: node.entity_ref,
          fraudulent: !node.fraudulent,
        }),
      });
      toast(node.fraudulent ? "Fraudulent mark cleared" : "Entity marked fraudulent");
      await loadLinks();
    }));
    wrap.append(mark);
  }
}


async function loadAuthAudit() {
  const events = await api("/api/auth/audit");
  $("auth-audit").replaceChildren(...events.map(item => el("article", {class: "note"}, [
    el("strong", {}, [item.username]),
    el("p", {}, [`${item.outcome.replaceAll("_", " ")} | ${formatWhen(item.created_at)} | ${item.client_address}`])
  ])));
  if (!events.length) $("auth-audit").append(el("p", {}, ["No sign-in activity recorded yet."]));
}
