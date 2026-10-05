function bindNetwork() {
  $("save-layout").addEventListener("click", () => run(async () => {
    const payload = {
      name: $("layout-name").value.trim(), version: Number($("layout-version").value),
      protocol: $("layout-protocol").value, direction: $("layout-direction").value,
      offset: Number($("layout-offset").value), language: $("layout-language").value,
      declaration: $("layout-text").value, encoding: $("layout-encoding").value,       byteorder: $("layout-order").value, identify_field: $("layout-identify").value.trim(),
      framing: $("layout-framing").value, length_width: Number($("layout-length-width").value),
      envelope: Number($("layout-envelope").value)
    };
    await api("/api/network/layouts", {method: "POST", body: JSON.stringify(payload)});
    await loadSavedLayouts();
    $("layout-result").textContent = "Layout version saved. Reopen a capture to see its decoded records.";
  }));
  $("network-open").addEventListener("click", () => run(async () => {
    const info = await api("/api/network/capabilities");
    fillSelect($("network-protocols"), info.protocols.map(item => item.name));
    for (const option of $("network-protocols").options) option.selected = true;
    $("network-coverage").replaceChildren(...info.protocols.map(item => el("p", {}, [`${item.name}: ${item.coverage}`])));
    fillSelect($("layout-protocol"), info.protocols.map(item => item.name).filter(name => !["https", "ssh"].includes(name)));
    await loadSavedLayouts();
    await loadCaptures();
    $("network-dialog").showModal();
  }));
  $("close-network").addEventListener("click", () => $("network-dialog").close());
  $("message-search-form").addEventListener("submit", (event) => {
    event.preventDefault();
    run(async () => {
      const term = $("message-q").value.trim();
      if (term.length < 2) throw new Error("Enter at least two characters");
      const hits = await api(`/api/network/messages/search?q=${encodeURIComponent(term)}`);
      const box = $("message-hits");
      box.replaceChildren();
      if (!hits.length) box.append(el("p", {class: "muted"}, ["No message field matched."]));
      for (const hit of hits) {
        const fields = Object.entries(hit.fields).map(([key, value]) => `${key}: ${value}`).join(" | ");
        const open = el("button", {type: "button", class: "secondary"}, ["Open capture"]);
        open.addEventListener("click", () => run(() => openCapture(hit.capture_id)));
        box.append(el("article", {class: "note"}, [
          el("strong", {}, [`${hit.capture_name} | direction ${hit.direction} | record ${hit.record} | ${hit.message_type || "unidentified"}`]),
          el("p", {}, [fields]),
          open,
        ]));
      }
    });
  });
  $("network-form").addEventListener("submit", event => {
    event.preventDefault();
    run(async () => {
      const button = $("network-form").querySelector("button");
      button.disabled = true;
      $("network-result").textContent = "Analyzing capture...";
      try {
        const protocols = [...$("network-protocols").selectedOptions].map(option => option.value);
        if (!protocols.length) throw new Error("Select at least one protocol.");
        const body = new FormData();
        body.append("file", $("network-file").files[0]);
        body.append("config", JSON.stringify({protocols, malware_ips: $("network-malware").value.split(",").map(v => v.trim()).filter(Boolean), c2_ips: $("network-c2").value.split(",").map(v => v.trim()).filter(Boolean)}));
        const result = await api("/api/network/pcap", {method: "POST", body});
        $("network-result").textContent = `${result.metrics.processed} packets analyzed; ${result.sessions} sessions. ${result.metrics.malformed} malformed, ${result.metrics.unsupported} unsupported packets.`;
        $("network-file").value = "";
        await loadCaptures();
        await openCapture(result.id);
      } catch (error) { $("network-result").textContent = error.message; throw error; }
      finally { button.disabled = false; }
    });
  });
  $("layout-form").addEventListener("submit", event => {
    event.preventDefault();
    run(async () => {
      const result = await api("/api/network/layouts/preview", {method: "POST", body: JSON.stringify({
        language: $("layout-language").value, declaration: $("layout-text").value,
        message_base64: $("layout-data").value.trim(), encoding: $("layout-encoding").value, byteorder: $("layout-order").value
      })});
      $("layout-result").textContent = JSON.stringify(result, null, 2);
    });
  });
}

async function loadCaptures() {
  const captures = await api("/api/network/captures");
  $("network-captures").replaceChildren();
  if (!captures.length) $("network-captures").append(el("p", {}, ["No captures imported yet."]));
  for (const item of captures) {
    const open = el("button", {type: "button", class: "secondary"}, [`${item.name} | ${item.sessions} sessions | ${item.imported_by}`]);
    open.addEventListener("click", () => run(() => openCapture(item.id)));
    $("network-captures").append(open);
  }
}

async function openCapture(id) {
  const capture = await api(`/api/network/captures/${id}`);
  const wrap = $("network-sessions");
  wrap.replaceChildren(el("p", {}, [`SHA-256: ${capture.sha256}`]),
    el("a", {href: `/api/network/captures/${id}/download`}, ["Download original capture"]));
  if (state.user.role !== "viewer") {
    const form = el("form", {class: "stack"}, [
      el("h3", {}, ["Check this stored capture again"]),
      el("p", {class: "muted"}, ["Enter operator-supplied addresses. The original file is not changed, and this does not start a capture."]),
      el("label", {}, ["Malware addresses", el("input", {id: "indicator-malware", maxlength: "2000", placeholder: "10.0.0.2"})]),
      el("label", {}, ["C2 addresses", el("input", {id: "indicator-c2", maxlength: "2000", placeholder: "10.1.1.1"})]),
      el("button", {type: "submit"}, ["Apply indicators"]),
    ]);
    form.addEventListener("submit", event => {
      event.preventDefault();
      run(async () => {
        const split = value => value.split(/[\s,]+/).map(item => item.trim()).filter(Boolean);
        await api(`/api/network/captures/${id}/indicators`, {method: "POST", body: JSON.stringify({
          malware_ips: split($("indicator-malware").value), c2_ips: split($("indicator-c2").value),
        })});
        await openCapture(id);
      });
    });
    wrap.append(form);
    const rules = el("button", {type: "button"}, ["Apply current rules"]);
    rules.addEventListener("click", () => run(async () => {
      await api(`/api/network/captures/${id}/rules`, {method: "POST"});
      await openCapture(id);
    }));
    wrap.append(el("p", {class: "muted"}, ["Run the rules in this build against the stored file. The original bytes stay unchanged."]));
    wrap.append(rules);
  }
  const analysis = capture.traffic_analysis;
  if (analysis) {
    wrap.append(el("h3", {}, ["Network traffic analysis"]));
    for (const note of analysis.limitations) wrap.append(el("p", {class: "muted"}, [note]));
    wrap.append(el("h4", {}, ["Applications by payload volume"]));
    for (const app of analysis.applications) wrap.append(el("p", {}, [`${app.application}: ${app.payload_bytes.toLocaleString()} bytes | ${app.share_percent}% | ${app.sessions} sessions`]));
    wrap.append(el("h4", {}, [`Findings (${analysis.findings.length})`]));
    if (!analysis.findings.length) wrap.append(el("p", {}, ["No indicators or heuristic thresholds matched."]));
    for (const finding of analysis.findings) wrap.append(el("article", {class: "note"}, [el("strong", {}, [`${finding.severity} | ${finding.title}`]), el("p", {}, [JSON.stringify(finding.evidence)]), el("p", {}, [`Sessions: ${finding.session_ids.join(", ")}`])]));
  } else wrap.append(el("p", {}, ["Reimport this capture to generate traffic analysis."]));
  if (capture.metrics.completed_sessions_omitted) wrap.append(el("p", {}, [`${capture.metrics.completed_sessions_omitted} older session records exceeded the report limit. Download the original capture to retain all packets.`]));
  if (capture.metrics.capacity_rotations) wrap.append(el("p", {}, [`${capture.metrics.capacity_rotations} sessions were rotated to make room for new connections. Continuing connections may have incomplete streams.`]));
  if (capture.metrics.session_overflow) wrap.append(el("p", {}, [`Session limit reached: ${capture.metrics.session_overflow} packets could not be assigned.`]));
  for (const session of capture.session_details) {
    const card = el("details", {class: "note"}, [el("summary", {}, [
      `${session.protocol} | ${session.endpoints.map(endpoint => endpoint.join(":")).join(" <-> ")} | ${session.packets} packets | ${session.classification_basis}`
    ])]);
    card.append(el("p", {class: "muted"}, [session.limitations.join(" ")]));
    if (session.commands && session.commands.length) {
      card.append(el("h4", {}, ["Reconstructed commands"]));
      for (const command of session.commands) card.append(el("p", {}, [`${command.protocol}: ${command.text}`]));
    }
    if (session.files && session.files.length) {
      card.append(el("h4", {}, ["Reconstructed files"]));
      for (const file of session.files) card.append(el("p", {}, [`${file.protocol}: ${file.length} bytes | ${file.sha256}${file.sensitive ? " | " + file.sensitive : ""}`]));
    }
    if (session.capture_source && session.capture_source !== "default") card.append(el("p", {}, [`Capture source: ${session.capture_source}`]));
    const screens = [];
    for (const datagram of session.datagrams) card.append(el("pre", {}, [JSON.stringify(datagram, null, 2)]));
    for (const direction of session.directions) {
      card.append(el("h4", {}, [`From ${direction.source.join(":")}: ${direction.length} reconstructed bytes`]),
        el("p", {}, [`SYN observed: ${direction.syn_seen}; gaps: ${direction.gaps.length}; conflicting overlap: ${direction.overlap_conflict}; truncated: ${direction.truncated}`]));
      for (const message of direction.decoded.messages) card.append(el("pre", {}, [JSON.stringify(message, null, 2)]));
      for (const screen of direction.decoded.screens) screens.push(screen);
      for (const note of direction.decoded.notes) card.append(el("p", {class: "muted"}, [note]));
    }
    if (screens.length) card.append(screenReplay(screens));
    for (const result of session.layout_results) {
      card.append(el("h4", {}, [`${result.name} v${result.version} | direction ${result.direction} | ${result.status}`]));
      if (!result.records.length) card.append(el("p", {class: "muted"}, ["No records in this direction."]));
      for (const record of result.records) {
        const fields = Object.entries(record.fields).map(([key, value]) => `${key}: ${value}`).join(" | ");
        card.append(el("article", {class: "note"}, [
          el("strong", {}, [`Direction ${result.direction} | record ${record.index + 1} | ${record.message_type || "unidentified"}`]),
          el("p", {}, [fields || "No fields"]),
        ]));
      }
    }
    wrap.append(card);
  }
}

function screenReplay(screens) {
  let index = 0;
  const label = el("p", {});
  const view = el("pre", {class: "terminal-screen"});
  const show = () => {
    const screen = screens[index];
    label.textContent = `Screen ${index + 1} of ${screens.length} | ${screen.kind}${screen.partial ? " (partial)" : ""}`;
    view.textContent = screen.rows.join("\n");
  };
  const previous = el("button", {type: "button", class: "secondary"}, ["Previous screen"]);
  const next = el("button", {type: "button", class: "secondary"}, ["Next screen"]);
  previous.addEventListener("click", () => { index = (index - 1 + screens.length) % screens.length; show(); });
  next.addEventListener("click", () => { index = (index + 1) % screens.length; show(); });
  show();
  return el("div", {class: "stack"}, [el("h4", {}, ["Screen replay"]), label, view, el("div", {class: "row-actions"}, [previous, next])]);
}

bindNetwork();


async function loadSavedLayouts() {
  const layouts = await api("/api/network/layouts");
  $("saved-layouts").replaceChildren();
  if (!layouts.length) $("saved-layouts").append(el("p", {}, ["No saved layouts yet."]));
  for (const layout of layouts) {
    const row = el("article", {class: "note"}, [el("strong", {}, [`${layout.name} v${layout.version} | ${layout.protocol} | ${layout.enabled ? "enabled" : "disabled"}`]),
      el("p", {}, [`${layout.definition.size} bytes per record | direction ${layout.direction} | skip ${layout.offset} bytes | saved by ${layout.created_by}`])]);
    if (state.user.role !== "viewer") {
      const toggle = el("button", {type:"button",class:"secondary"}, [layout.enabled ? "Disable" : "Enable"]);
      toggle.addEventListener("click", () => run(async () => {
        await api(`/api/network/layouts/${layout.id}`, {method:"PATCH",body:JSON.stringify({enabled:!layout.enabled})});
        await loadSavedLayouts();
      }));
      row.append(toggle);
    }
    $("saved-layouts").append(row);
  }
}
