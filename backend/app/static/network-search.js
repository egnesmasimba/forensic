"use strict";
function requireTerm(value) {
    const term = value.trim();
    if (term.length < 2)
        throw new Error("Enter at least two characters");
    return term;
}
function openButton(id) {
    const open = el("button", { type: "button", class: "secondary" }, ["Open capture"]);
    open.addEventListener("click", () => run(() => openCapture(id)));
    return open;
}
function bindNetworkSearch() {
    document.getElementById("finding-search-form")?.addEventListener("submit", (event) => {
        event.preventDefault();
        run(async () => {
            const tactic = document.getElementById("finding-tactic").value;
            const hits = await api(`/api/network/findings/search?tactic=${encodeURIComponent(tactic)}`);
            const box = $("finding-hits");
            box.replaceChildren();
            if (!hits.length)
                box.append(el("p", { class: "muted" }, ["No stored finding matched."]));
            for (const hit of hits) {
                box.append(el("article", { class: "note" }, [
                    el("strong", {}, [`${hit.capture_name} | ${hit.title}`]),
                    el("p", {}, [JSON.stringify(hit.evidence)]),
                    openButton(hit.capture_id),
                ]));
            }
        });
    });
    document.getElementById("session-search-form")?.addEventListener("submit", (event) => {
        event.preventDefault();
        run(async () => {
            const term = requireTerm(document.getElementById("session-q").value);
            const hits = await api(`/api/network/sessions/search?q=${encodeURIComponent(term)}`);
            const box = $("session-hits");
            box.replaceChildren();
            if (!hits.length)
                box.append(el("p", { class: "muted" }, ["No reconstructed session matched."]));
            for (const hit of hits) {
                box.append(el("article", { class: "note" }, [
                    el("strong", {}, [`${hit.capture_name} | ${hit.protocol} | ${hit.transport}`]),
                    el("p", {}, [`${hit.session} | ${hit.packets} packets`]),
                    openButton(hit.capture_id),
                ]));
            }
        });
    });
    document.getElementById("file-search-form")?.addEventListener("submit", (event) => {
        event.preventDefault();
        run(async () => {
            const term = requireTerm(document.getElementById("file-q").value);
            const hits = await api(`/api/network/files/search?q=${encodeURIComponent(term)}`);
            const box = $("file-hits");
            box.replaceChildren();
            if (!hits.length)
                box.append(el("p", { class: "muted" }, ["No reconstructed file matched."]));
            for (const hit of hits) {
                box.append(el("article", { class: "note" }, [
                    el("strong", {}, [`${hit.capture_name} | ${hit.protocol} | ${hit.length} bytes`]),
                    el("p", {}, [hit.sensitive ? `${hit.sha256} | ${hit.sensitive}` : hit.sha256]),
                    openButton(hit.capture_id),
                ]));
            }
        });
    });
    document.getElementById("command-search-form")?.addEventListener("submit", (event) => {
        event.preventDefault();
        run(async () => {
            const term = requireTerm(document.getElementById("command-q").value);
            const hits = await api(`/api/network/commands/search?q=${encodeURIComponent(term)}`);
            const box = $("command-hits");
            box.replaceChildren();
            if (!hits.length)
                box.append(el("p", { class: "muted" }, ["No reconstructed command matched."]));
            for (const hit of hits) {
                box.append(el("article", { class: "note" }, [
                    el("strong", {}, [`${hit.capture_name} | ${hit.protocol}`]),
                    el("p", {}, [hit.text]),
                    openButton(hit.capture_id),
                ]));
            }
        });
    });
}
bindNetworkSearch();
