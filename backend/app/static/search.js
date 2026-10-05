let contentSearchOffset = 0;
let contentSearchRequest = 0;

async function loadContentStatus() {
  const info = await api("/api/search/status");
  if (!state.user) return;
  $("content-index-status").textContent = `${info.documents} indexed records. ${info.partial_documents} partial records.` +
    (info.backend === "elasticsearch" ? ` ${info.pending_external_updates} updates waiting for the search service.` : "") +
    (info.external_error ? ` ${info.external_error}` : "");
  for (const [id, values, label] of [["content-platform", info.platforms, "All platforms"], ["content-source", info.source_kinds, "All sources"]]) {
    const select = $(id), selected = select.value;
    select.replaceChildren(el("option", {value: ""}, [label]), ...values.map(value => el("option", {value}, [value])));
    if (values.includes(selected)) select.value = selected;
  }
}

function contentTime(id) {
  return $(id).value ? new Date($(id).value).toISOString() : "";
}

async function searchContent() {
  const generation = ++contentSearchRequest;
  const params = new URLSearchParams({q: $("content-query").value.trim(), offset: String(contentSearchOffset), limit: "20"});
  for (const [key, value] of [["platform", $("content-platform").value], ["source_kind", $("content-source").value],
                             ["start", contentTime("content-start")], ["end", contentTime("content-end")]]) {
    if (value) params.set(key, value);
  }
  const result = await api(`/api/search?${params}`);
  if (!state.user || generation !== contentSearchRequest) return;
  $("content-detail").replaceChildren();
  $("content-result-status").textContent = `${result.total} matches, ranked by relevance.` +
    (result.total_is_external ? " The search service count may include older entries; removed or edited entries are hidden until updated." : "") +
    (result.pending_external_updates ? ` ${result.pending_external_updates} source updates are still waiting to be indexed.` : "");
  $("content-results").replaceChildren(...result.results.map(item => {
    const button = el("button", {type: "button", class: "secondary"}, [item.title]);
    button.addEventListener("click", () => run(() => showContentDocument(item.id)));
    const replayButton = el("button", {type:"button",class:"secondary"}, ["Replay result"]);
    replayButton.addEventListener("click", () => run(() => replaySearchResult(item.id)));
    return el("article", {class: "content-hit"}, [button, replayButton,
      el("p", {class: "muted"}, [`${item.platform} · ${item.source_kind} ${item.source_id} · ${new Date(item.occurred_at).toLocaleString()}${item.partial ? " · Partial content" : ""}`]),
      el("p", {}, [item.snippet])]);
  }));
  $("content-previous").disabled = contentSearchOffset === 0;
  $("content-next").disabled = contentSearchOffset + 20 >= result.total || contentSearchOffset >= 9900;
}

async function showContentDocument(id) {
  const item = await api(`/api/search/documents/${id}`);
  if (!state.user) return;
  const children = [el("h3", {}, [item.title]), el("p", {}, [`${item.platform} · ${item.source_kind} ${item.source_id}`])];
  if (item.partial) children.push(el("p", {}, ["This record contains partial content. Refer to the original source for the remaining data."]));
  if (item.headers.length) children.push(el("p", {}, ["Headers: " + item.headers.join(" · ")]));
  if (item.fields.length) children.push(el("dl", {}, item.fields.flatMap(field => [el("dt", {}, [field.caption]), el("dd", {}, [field.value])])));
  children.push(el("pre", {}, [item.body]));
  $("content-detail").replaceChildren(...children);
}

function bindContentSearch() {
  $("search-open").addEventListener("click", () => run(async () => {
    await loadContentStatus();
    if (!state.user) return;
    $("content-backfill").hidden = state.user.role === "viewer";
    $("content-import-section").hidden = state.user.role === "viewer";
    const localNow = new Date(Date.now() - new Date().getTimezoneOffset() * 60000).toISOString().slice(0, 19);
    $("content-observed").value = localNow;
    $("search-dialog").showModal();
  }));
  $("close-search").addEventListener("click", () => $("search-dialog").close());
  $("content-search-form").addEventListener("submit", event => {
    event.preventDefault();
    contentSearchOffset = 0;
    run(searchContent);
  });
  for (const [id, delta] of [["content-previous", -20], ["content-next", 20]]) {
    $(id).addEventListener("click", () => { contentSearchOffset += delta; run(searchContent); });
  }
  $("content-backfill").addEventListener("click", () => run(async () => {
    const button = $("content-backfill");
    button.disabled = true;
    try {
      for (const kind of ["case", "alert", "note", "artifact", "endpoint", "import", "network", "mail"]) {
        let after = "";
        for (let batch = 0; batch < 100; batch++) {
          if (!state.user) return;
          $("content-index-status").textContent = `Indexing existing ${kind} records…`;
          const page = await api(`/api/search/backfill?${new URLSearchParams({source_kind: kind, after})}`, {method: "POST"});
          after = page.next_after;
          if (!page.has_more) break;
          if (batch === 99) throw new Error("Some existing records remain. Use the backfill API cursor to continue this large import.");
        }
      }
      await api("/api/search/sync", {method: "POST"});
      await loadContentStatus();
      if ($("content-query").value.trim()) { contentSearchOffset = 0; await searchContent(); }
    } finally { button.disabled = false; }
  }));
  $("content-import-form").addEventListener("submit", event => {
    event.preventDefault();
    run(async () => {
      const item = await api("/api/search/documents", {method: "POST", body: JSON.stringify({
        kind: $("content-kind").value, content: $("content-text").value, title: $("content-title").value,
        platform: $("content-import-platform").value, occurred_at: contentTime("content-observed")
      })});
      if (!state.user) return;
      $("content-import-status").textContent = `Added “${item.title}” to search.`;
      $("content-text").value = "";
      await loadContentStatus();
    });
  });
}

bindContentSearch();
