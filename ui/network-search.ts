interface SessionHit {
  capture_id: number;
  capture_name: string;
  protocol: string;
  transport: string;
  session: string;
  packets: number;
}

interface CommandHit {
  capture_id: number;
  capture_name: string;
  protocol: string;
  text: string;
}

interface FileHit {
  capture_id: number;
  capture_name: string;
  protocol: string;
  length: number;
  sha256: string;
  sensitive: string;
}

declare function $(id: string): HTMLElement;
declare function el(tag: string, attrs: Record<string, string>, children?: Array<Node | string>): HTMLElement;
declare function api<T>(path: string): Promise<T>;
declare function run(work: () => Promise<void>): void;
declare function openCapture(id: number): Promise<void>;

function requireTerm(value: string): string {
  const term = value.trim();
  if (term.length < 2) throw new Error("Enter at least two characters");
  return term;
}

function openButton(id: number): HTMLButtonElement {
  const open = el("button", {type: "button", class: "secondary"}, ["Open capture"]) as HTMLButtonElement;
  open.addEventListener("click", () => run(() => openCapture(id)));
  return open;
}

function bindNetworkSearch(): void {
  document.getElementById("finding-search-form")?.addEventListener("submit", (event) => {
    event.preventDefault();
    run(async () => {
      const tactic = (document.getElementById("finding-tactic") as HTMLSelectElement).value;
      const hits = await api<Array<{capture_id: number; capture_name: string; title: string; evidence: object}>>(`/api/network/findings/search?tactic=${encodeURIComponent(tactic)}`);
      const box = $("finding-hits");
      box.replaceChildren();
      if (!hits.length) box.append(el("p", {class: "muted"}, ["No stored finding matched."]));
      for (const hit of hits) {
        box.append(el("article", {class: "note"}, [
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
      const term = requireTerm((document.getElementById("session-q") as HTMLInputElement).value);
      const hits = await api<SessionHit[]>(`/api/network/sessions/search?q=${encodeURIComponent(term)}`);
      const box = $("session-hits");
      box.replaceChildren();
      if (!hits.length) box.append(el("p", {class: "muted"}, ["No reconstructed session matched."]));
      for (const hit of hits) {
        box.append(el("article", {class: "note"}, [
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
      const term = requireTerm((document.getElementById("file-q") as HTMLInputElement).value);
      const hits = await api<FileHit[]>(`/api/network/files/search?q=${encodeURIComponent(term)}`);
      const box = $("file-hits");
      box.replaceChildren();
      if (!hits.length) box.append(el("p", {class: "muted"}, ["No reconstructed file matched."]));
      for (const hit of hits) {
        box.append(el("article", {class: "note"}, [
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
      const term = requireTerm((document.getElementById("command-q") as HTMLInputElement).value);
      const hits = await api<CommandHit[]>(`/api/network/commands/search?q=${encodeURIComponent(term)}`);
      const box = $("command-hits");
      box.replaceChildren();
      if (!hits.length) box.append(el("p", {class: "muted"}, ["No reconstructed command matched."]));
      for (const hit of hits) {
        box.append(el("article", {class: "note"}, [
          el("strong", {}, [`${hit.capture_name} | ${hit.protocol}`]),
          el("p", {}, [hit.text]),
          openButton(hit.capture_id),
        ]));
      }
    });
  });
}

bindNetworkSearch();
