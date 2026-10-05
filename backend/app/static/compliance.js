function bindCompliance() {
  const open = $("open-compliance");
  if (!open) return;
  open.addEventListener("click", () => run(async () => {
    $("compliance-result").textContent = "";
    $("compliance-dialog").showModal();
  }));
  $("compliance-request").addEventListener("submit", (event) => {
    event.preventDefault();
    run(async () => {
      const data = await api("/api/compliance/requests", { method: "POST", body: JSON.stringify({
        entity_ref: $("compliance-entity").value, kind: $("compliance-kind").value, regime: $("compliance-regime").value,
      })});
      $("compliance-result").textContent = JSON.stringify(data, null, 2);
    });
  });
  $("compliance-review").addEventListener("submit", (event) => {
    event.preventDefault();
    run(async () => {
      const data = await api("/api/compliance/inspect", { method: "POST", body: JSON.stringify({ text: $("compliance-text").value }) });
      $("compliance-result").textContent = JSON.stringify(data, null, 2);
    });
  });
  $("compliance-retention").addEventListener("submit", (event) => {
    event.preventDefault();
    run(async () => {
      const data = await api("/api/compliance/retention", { method: "PUT", body: JSON.stringify({ online_months: Number($("compliance-months").value) }) });
      $("compliance-result").textContent = JSON.stringify(data, null, 2);
    });
  });
  $("compliance-age").addEventListener("click", () => run(async () => {
    const data = await api("/api/compliance/aging?dry_run=false", { method: "POST" });
    $("compliance-result").textContent = JSON.stringify(data, null, 2);
  }));
}

bindCompliance();
