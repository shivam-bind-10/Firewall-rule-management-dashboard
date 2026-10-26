const state = { rules: [], stats: null, exportFormat: "iptables", dragId: null };
const content = document.getElementById("app-content");
const escapeHtml = (value) => String(value ?? "").replace(/[&<>"']/g, char => ({
  "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
}[char]));
const api = async (url, options = {}) => {
  const response = await fetch(url, {
    ...options,
    headers: { ...(options.body ? { "Content-Type": "application/json" } : {}), ...options.headers },
  });
  const type = response.headers.get("content-type") || "";
  const payload = type.includes("application/json") ? await response.json() : await response.text();
  if (!response.ok) {
    const error = new Error(payload.error || `Request failed (${response.status})`);
    error.details = payload.errors || {};
    throw error;
  }
  return payload;
};
const toast = (message, error = false) => {
  const item = document.createElement("div");
  item.className = `toast${error ? " error" : ""}`;
  item.textContent = message;
  document.getElementById("toast-region").append(item);
  window.setTimeout(() => item.remove(), 3200);
};
const routeName = () => (location.hash.replace(/^#\/?/, "").split("/")[0] || "overview");
const pageNames = { overview: "Overview", rules: "Rules", simulator: "Simulator", logs: "Activity log", export: "Export" };
const actionClass = action => `action-${String(action).toLowerCase()}`;
const actionPill = action => `<span class="action-pill ${actionClass(action)}">${escapeHtml(action)}</span>`;
const formatTime = stamp => {
  const date = new Date(stamp);
  return Number.isNaN(date.getTime()) ? "--:--" : date.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", hour12: false });
};
const sparkline = seed => {
  const heights = Array.from({ length: 9 }, (_, i) => ((seed * 7 + i * 11 + i * seed) % 9) + 2);
  return `<svg class="spark" viewBox="0 0 32 12" aria-hidden="true">${heights.map((height, i) =>
    `<rect x="${i * 4}" y="${12 - height}" width="2" height="${height}" fill="currentColor" opacity="${0.35 + i * 0.07}"/>`
  ).join("")}</svg>`;
};
const setStatus = () => {
  const total = state.rules.length;
  document.getElementById("nav-rule-count").textContent = total;
  document.getElementById("ruleset-status").textContent =
    `Ruleset loaded · ${total} rule${total === 1 ? "" : "s"} · last simulated ${state.stats?.recent?.[0] ? formatTime(state.stats.recent[0].timestamp) : "—"}`;
};
const refresh = async () => {
  [state.rules, state.stats] = await Promise.all([api("/api/rules"), api("/api/stats")]);
  setStatus();
};
const heading = (title, description, button = "") => `
  <div class="page-heading"><div><div class="eyebrow">POLICY ENGINE / ${escapeHtml(title.toUpperCase())}</div>
  <h1>${escapeHtml(title)}</h1><p>${escapeHtml(description)}</p></div>${button}</div>`;
const noData = (message, action = "") => `<div class="empty-state"><p>${escapeHtml(message)}</p>${action}</div>`;

function renderOverview() {
  const stats = state.stats;
  const total = stats.total;
  const allowRatio = total ? Math.round(stats.allow / total * 100) : 0;
  const top = stats.top_rules.filter(rule => rule.hits > 0);
  const maxHits = Math.max(...top.map(rule => rule.hits), 1);
  const chart = top.length ? top.map(rule => `
    <div class="chart-row"><span class="chart-name" title="${escapeHtml(rule.name)}">${escapeHtml(rule.name)}</span>
    <div class="bar-track"><div class="bar-fill" style="width:${Math.max(2, rule.hits / maxHits * 100)}%"></div></div>
    <span class="chart-count">${rule.hits}</span></div>`).join("") : `<div class="chart-empty">No rule matches recorded yet.</div>`;
  const recent = stats.recent.length ? stats.recent.map(log => `
    <div class="recent-item"><span class="recent-time">${formatTime(log.timestamp)}</span>
    <span class="recent-description"><span class="mono">${escapeHtml(log.src)}:${escapeHtml(log.port)}</span> → <span class="mono">${escapeHtml(log.dst)}</span> · ${escapeHtml(log.rule_name || "Implicit deny")}</span>
    <span class="mini-badge ${actionClass(log.action)}">${escapeHtml(log.action)}</span></div>`).join("") : noData("No simulated activity yet.");
  content.innerHTML = `${heading("Overview", "A live view of the simulated policy set and recent packet decisions.",
    `<a class="button small" href="#/simulator">Run simulation <span class="button-icon">↗</span></a>`)}
    <div class="stats-grid">
      <div class="stat-card"><div class="stat-label">Total rules <span class="stat-indicator">RULESET</span></div><div class="stat-value">${stats.total}</div><div class="stat-foot">${stats.active} enabled for evaluation</div></div>
      <div class="stat-card"><div class="stat-label">Active rules <span class="stat-indicator">STATUS</span></div><div class="stat-value">${stats.active}</div><div class="stat-foot">${stats.total - stats.active} currently disabled</div></div>
      <div class="stat-card"><div class="stat-label">Allow / deny <span class="stat-indicator">POLICY</span></div><div class="stat-value"><span style="color:var(--allow)">${stats.allow}</span><span class="muted"> / </span><span style="color:var(--deny)">${stats.deny}</span></div><div class="stat-foot"><span class="green">${allowRatio}% allow</span> by rule count</div></div>
      <div class="stat-card"><div class="stat-label">Blocked today <span class="stat-indicator">24H</span></div><div class="stat-value">${stats.blocked_today}</div><div class="stat-foot">${stats.hits} matched packet evaluations</div></div>
    </div>
    <div class="overview-grid">
      <section class="panel"><div class="panel-head"><span class="panel-title">Top matching rules</span><span class="panel-subtitle">MATCH COUNTS · TOP 8</span></div><div class="chart-area">${chart}</div></section>
      <section class="panel"><div class="panel-head"><span class="panel-title">Recent activity</span><a class="quick-action" href="#/logs">View log →</a></div><div class="recent-list">${recent}</div></section>
    </div>
    <div class="section-gap"><span class="muted">Shortcuts:</span> <span class="keyboard-key">/</span> search rules <span class="keyboard-key">n</span> new rule</div>`;
}

function renderRules() {
  content.innerHTML = `${heading("Rules", "Ordered policy evaluation. The first enabled rule that matches a packet decides its action.",
    `<button class="button primary" id="new-rule"><span class="button-icon">+</span> New rule</button>`)}
    <div class="toolbar">
      <label class="search-wrap"><span class="search-mark">⌕</span><input id="rule-search" type="search" placeholder="Search name, network, comment…" autocomplete="off"><span class="search-hint">/</span></label>
      <select id="action-filter" class="filter-select" aria-label="Filter by action"><option value="">All actions</option><option>ALLOW</option><option>DENY</option><option>REJECT</option></select>
      <select id="protocol-filter" class="filter-select" aria-label="Filter by protocol"><option value="">All protocols</option><option>TCP</option><option>UDP</option><option>ICMP</option><option>ANY</option></select>
      <span class="table-meta">${state.rules.length} rules · drag to reorder</span>
    </div>
    <section class="panel"><div class="table-wrap"><table><thead><tr>
      <th style="width:34px"></th><th style="width:46px">Order</th><th>Name</th><th>Action</th><th>Direction</th><th>Protocol</th><th>Source / destination</th><th>Port</th><th>Hits</th><th>On</th>
    </tr></thead><tbody id="rules-body"></tbody></table></div>
      <div class="table-footer"><span>Evaluation order: top to bottom</span><span>Hit counters update only when you simulate</span></div>
    </section>`;
  document.getElementById("new-rule").addEventListener("click", () => openEditor());
  const filter = () => {
    const search = document.getElementById("rule-search").value.trim().toLowerCase();
    const action = document.getElementById("action-filter").value;
    const protocol = document.getElementById("protocol-filter").value;
    const rows = state.rules.filter(rule =>
      (!search || [rule.name, rule.src_cidr, rule.dst_cidr, rule.dst_port, rule.comment].some(value => String(value).toLowerCase().includes(search))) &&
      (!action || rule.action === action) && (!protocol || rule.protocol === protocol));
    const body = document.getElementById("rules-body");
    body.innerHTML = rows.length ? rows.map(rule => `
      <tr draggable="true" data-rule-id="${rule.id}">
        <td><span class="drag-handle" title="Drag to reorder">⠿</span></td>
        <td class="mono muted">${String(rule.position).padStart(2, "0")}</td>
        <td><span class="rule-name">${escapeHtml(rule.name)}</span></td><td>${actionPill(rule.action)}</td>
        <td class="mono">${rule.direction}</td><td class="mono">${rule.protocol}</td>
        <td class="mono">${escapeHtml(rule.src_cidr)} <span class="faint">→</span> ${escapeHtml(rule.dst_cidr)}</td>
        <td class="mono">${escapeHtml(rule.dst_port)}</td>
        <td><span class="hit-cell">${sparkline(rule.id)}<span class="mono">${rule.hits}</span></span></td>
        <td><button class="toggle ${rule.enabled ? "on" : ""}" data-toggle="${rule.id}" aria-label="${rule.enabled ? "Disable" : "Enable"} ${escapeHtml(rule.name)}" aria-pressed="${Boolean(rule.enabled)}"></button></td>
      </tr>`).join("") : `<tr><td colspan="10">${noData("No rules match these filters.", '<button class="button small" id="clear-filters">Clear filters</button>')}</td></tr>`;
    body.querySelectorAll("tr[data-rule-id]").forEach(row => {
      row.addEventListener("click", () => openEditor(state.rules.find(rule => rule.id === Number(row.dataset.ruleId))));
      row.addEventListener("dragstart", event => { state.dragId = Number(row.dataset.ruleId); row.classList.add("dragging"); event.dataTransfer.effectAllowed = "move"; });
      row.addEventListener("dragend", () => { row.classList.remove("dragging"); body.querySelectorAll(".drop-target").forEach(node => node.classList.remove("drop-target")); });
      row.addEventListener("dragover", event => { event.preventDefault(); row.classList.add("drop-target"); });
      row.addEventListener("dragleave", () => row.classList.remove("drop-target"));
      row.addEventListener("drop", event => { event.preventDefault(); row.classList.remove("drop-target"); reorderRules(state.dragId, Number(row.dataset.ruleId)); });
    });
    body.querySelectorAll("[data-toggle]").forEach(button => button.addEventListener("click", async event => {
      event.stopPropagation();
      try { await api(`/api/rules/${button.dataset.toggle}/toggle`, { method: "PATCH" }); await refresh(); renderRules(); }
      catch (error) { toast(error.message, true); }
    }));
    document.getElementById("clear-filters")?.addEventListener("click", () => {
      document.getElementById("rule-search").value = "";
      document.getElementById("action-filter").value = "";
      document.getElementById("protocol-filter").value = "";
      filter();
    });
  };
  ["rule-search", "action-filter", "protocol-filter"].forEach(id => document.getElementById(id).addEventListener(id === "rule-search" ? "input" : "change", filter));
  filter();
}

async function reorderRules(from, to) {
  if (!from || from === to) return;
  const ids = state.rules.map(rule => rule.id);
  const start = ids.indexOf(from);
  const end = ids.indexOf(to);
  ids.splice(end, 0, ids.splice(start, 1)[0]);
  try { await api("/api/rules/reorder", { method: "POST", body: JSON.stringify(ids) }); await refresh(); renderRules(); toast("Rule order updated."); }
  catch (error) { toast(error.message, true); }
}

function openEditor(rule = null) {
  const existing = rule || {};
  const values = {
    name: existing.name || "", action: existing.action || "ALLOW", direction: existing.direction || "IN",
    protocol: existing.protocol || "TCP", src_cidr: existing.src_cidr || "0.0.0.0/0",
    dst_cidr: existing.dst_cidr || "0.0.0.0/0", dst_port: existing.dst_port || "any",
    interface: existing.interface || "any", comment: existing.comment || "", enabled: existing.enabled !== 0,
  };
  const root = document.getElementById("drawer-root");
  root.innerHTML = `<div class="drawer-backdrop" id="drawer-backdrop"></div><aside class="drawer" role="dialog" aria-modal="true" aria-labelledby="drawer-title">
    <div class="drawer-head"><div><div class="eyebrow">${rule ? `RULE #${String(rule.position).padStart(2, "0")}` : "POLICY CONFIGURATION"}</div><h2 id="drawer-title">${rule ? "Edit rule" : "Create rule"}</h2></div><button class="icon-button" id="drawer-close" aria-label="Close editor">×</button></div>
    <form id="rule-form" class="drawer-body" novalidate>
      <div class="field"><label for="f-name">Rule name <span>REQUIRED</span></label><input id="f-name" name="name" maxlength="100" value="${escapeHtml(values.name)}" placeholder="Allow HTTPS from office"><div class="field-error" data-error="name"></div></div>
      <div class="field-row"><div class="field"><label for="f-action">Action</label><select id="f-action" name="action">${["ALLOW", "DENY", "REJECT"].map(x => `<option ${values.action === x ? "selected" : ""}>${x}</option>`).join("")}</select><div class="field-error" data-error="action"></div></div>
      <div class="field"><label for="f-direction">Direction</label><select id="f-direction" name="direction">${["IN", "OUT", "FORWARD"].map(x => `<option ${values.direction === x ? "selected" : ""}>${x}</option>`).join("")}</select><div class="field-error" data-error="direction"></div></div></div>
      <div class="field-row"><div class="field"><label for="f-protocol">Protocol</label><select id="f-protocol" name="protocol">${["TCP", "UDP", "ICMP", "ANY"].map(x => `<option ${values.protocol === x ? "selected" : ""}>${x}</option>`).join("")}</select><div class="field-error" data-error="protocol"></div></div>
      <div class="field"><label for="f-port">Destination port</label><input id="f-port" name="dst_port" class="mono-input" value="${escapeHtml(values.dst_port)}" placeholder="any or 443"><div class="field-error" data-error="dst_port"></div></div></div>
      <div class="field"><label for="f-src">Source IPv4 / CIDR</label><input id="f-src" name="src_cidr" class="mono-input" value="${escapeHtml(values.src_cidr)}" placeholder="192.168.1.0/24"><div class="field-error" data-error="src_cidr"></div></div>
      <div class="field"><label for="f-dst">Destination IPv4 / CIDR</label><input id="f-dst" name="dst_cidr" class="mono-input" value="${escapeHtml(values.dst_cidr)}" placeholder="0.0.0.0/0"><div class="field-error" data-error="dst_cidr"></div></div>
      <div class="field"><label for="f-interface">Interface</label><input id="f-interface" name="interface" value="${escapeHtml(values.interface)}" placeholder="eth0 or any"><div class="field-error" data-error="interface"></div></div>
      <div class="field"><label for="f-comment">Comment <span>OPTIONAL</span></label><textarea id="f-comment" name="comment" rows="2" maxlength="500" placeholder="Why this rule exists">${escapeHtml(values.comment)}</textarea><div class="field-error" data-error="comment"></div></div>
      <label class="field"><input type="checkbox" name="enabled" ${values.enabled ? "checked" : ""} style="width:auto;min-height:auto;margin-right:7px;accent-color:var(--allow)">Rule enabled</label>
      <div class="preview-box"><div class="preview-label">Rule preview</div><div class="preview-text" id="rule-preview"></div></div>
    </form>
    <div class="drawer-foot">${rule ? '<button class="button danger small" id="delete-rule">Delete</button>' : '<span class="muted" style="font-size:10px">New rule is appended to the end.</span>'}
      <div class="drawer-actions"><button class="button" id="cancel-rule">Cancel</button><button class="button primary" type="submit" form="rule-form">${rule ? "Save changes" : "Create rule"}</button></div>
    </div></aside>`;
  const form = document.getElementById("rule-form");
  let validationTimer;
  let validationRequest = 0;
  const preview = () => {
    const data = Object.fromEntries(new FormData(form).entries());
    document.getElementById("rule-preview").textContent =
      `${data.action || "ALLOW"} ${data.protocol || "TCP"} ${data.src_cidr || "0.0.0.0/0"} → ${data.dst_cidr || "0.0.0.0/0"}:${data.dst_port || "any"} · ${data.direction || "IN"}`;
  };
  form.addEventListener("input", preview);
  form.addEventListener("change", preview);
  preview();
  form.addEventListener("input", () => {
    if (form.dataset.submitted !== "true") return;
    window.clearTimeout(validationTimer);
    validationTimer = window.setTimeout(async () => {
      const requestId = ++validationRequest;
      const data = Object.fromEntries(new FormData(form).entries());
      data.enabled = form.elements.enabled.checked;
      try {
        const result = await api("/api/rules/validate", { method: "POST", body: JSON.stringify(data) });
        if (requestId !== validationRequest || !root.firstElementChild) return;
        root.querySelectorAll("[data-error]").forEach(field => {
          field.textContent = result.errors[field.dataset.error] || "";
        });
      } catch (error) {
        toast(`Validation failed: ${error.message}`, true);
      }
    }, 250);
  });
  const close = () => { root.innerHTML = ""; };
  document.getElementById("drawer-close").addEventListener("click", close);
  document.getElementById("cancel-rule").addEventListener("click", close);
  document.getElementById("drawer-backdrop").addEventListener("click", close);
  document.addEventListener("keydown", function escapeDrawer(event) {
    if (event.key === "Escape" && root.firstElementChild) { close(); document.removeEventListener("keydown", escapeDrawer); }
  }, { once: true });
  document.getElementById("delete-rule")?.addEventListener("click", async () => {
    if (!window.confirm(`Delete "${rule.name}"? This cannot be undone.`)) return;
    try { await api(`/api/rules/${rule.id}`, { method: "DELETE" }); close(); await refresh(); render(); toast("Rule deleted."); }
    catch (error) { toast(error.message, true); }
  });
  form.addEventListener("submit", async event => {
    event.preventDefault();
    form.dataset.submitted = "true";
    const data = Object.fromEntries(new FormData(form).entries());
    data.enabled = form.elements.enabled.checked;
    root.querySelectorAll("[data-error]").forEach(field => { field.textContent = ""; });
    try {
      await api(rule ? `/api/rules/${rule.id}` : "/api/rules", {
        method: rule ? "PUT" : "POST", body: JSON.stringify(data),
      });
      close(); await refresh(); render(); toast(rule ? "Rule saved." : "Rule created.");
    } catch (error) {
      Object.entries(error.details || {}).forEach(([field, message]) => {
        const target = root.querySelector(`[data-error="${field}"]`);
        if (target) target.textContent = message;
      });
      toast(error.message, true);
    }
  });
  document.getElementById("f-name").focus();
}

function renderSimulator() {
  content.innerHTML = `${heading("Packet simulator", "Evaluate a packet against the current ruleset. No traffic is sent to a network.")}
    <div class="sim-layout"><section class="panel"><div class="panel-head"><span class="panel-title">Packet parameters</span><span class="panel-subtitle">IPv4 ONLY</span></div>
      <form id="packet-form" class="form-panel" novalidate>
        <div class="field"><label for="p-src">Source address</label><input id="p-src" name="src" class="mono-input" value="192.168.10.44"><div class="field-error" data-error="src"></div></div>
        <div class="field"><label for="p-dst">Destination address</label><input id="p-dst" name="dst" class="mono-input" value="10.0.0.10"><div class="field-error" data-error="dst"></div></div>
        <div class="field-row"><div class="field"><label for="p-proto">Protocol</label><select id="p-proto" name="proto"><option>TCP</option><option>UDP</option><option>ICMP</option></select><div class="field-error" data-error="proto"></div></div>
          <div class="field"><label for="p-port">Destination port</label><input id="p-port" name="port" class="mono-input" value="443"><div class="field-error" data-error="port"></div></div></div>
        <div class="field"><label for="p-direction">Direction</label><select id="p-direction" name="direction"><option>IN</option><option>OUT</option><option>FORWARD</option></select><div class="field-error" data-error="direction"></div></div>
        <button class="button primary" type="submit">Evaluate packet <span class="button-icon">→</span></button>
      </form></section>
      <section class="panel"><div class="panel-head"><span class="panel-title">Evaluation trace</span><span class="panel-subtitle" id="trace-meta">AWAITING PACKET</span></div>
        <div id="simulation-result" class="form-panel">${noData("Submit a packet to see the first-match decision and rule-by-rule trace.")}</div>
      </section></div>`;
  const protocol = document.getElementById("p-proto");
  const port = document.getElementById("p-port");
  protocol.addEventListener("change", () => { port.disabled = protocol.value === "ICMP"; if (port.disabled) port.value = ""; else if (!port.value) port.value = "443"; });
  document.getElementById("packet-form").addEventListener("submit", async event => {
    event.preventDefault();
    const form = event.currentTarget;
    const data = Object.fromEntries(new FormData(form).entries());
    if (data.proto === "ICMP") data.port = "";
    document.querySelectorAll("#packet-form [data-error]").forEach(field => { field.textContent = ""; });
    try {
      const result = await api("/api/simulate", { method: "POST", body: JSON.stringify(data) });
      await refresh();
      document.getElementById("trace-meta").textContent = `${result.trace.length} RULE${result.trace.length === 1 ? "" : "S"} CHECKED`;
      const bannerClass = result.action.toLowerCase() === "allow" ? "allow" : result.action.toLowerCase() === "reject" ? "reject" : "deny";
      const description = result.implicit_deny ? "No matching rule · implicit default deny" : `Matched rule ${String(result.matched_rule.position).padStart(2, "0")} · ${escapeHtml(result.matched_rule.name)}`;
      const trace = result.trace.length ? result.trace.map((item, index) => `
        <div class="trace-item"><span class="trace-index">${String(item.position).padStart(2, "0")}</span><div><div class="trace-name">${escapeHtml(item.name)} ${actionPill(item.action)}</div><div class="trace-reason">${escapeHtml(item.reason)}</div></div>
        <span class="trace-result ${item.matched ? "match" : "skip"}">${item.matched ? "MATCH" : "SKIP"}</span></div>`).join("") : `<div class="trace-empty">No rules are configured. The default policy denies this packet.</div>`;
      document.getElementById("simulation-result").innerHTML = `<div class="result-banner ${bannerClass}"><span class="result-mark">${result.action === "ALLOW" ? "✓" : "×"}</span><span><strong>${escapeHtml(result.action)}</strong><small>${description}</small></span></div>
        <div class="section-gap"><div class="eyebrow">EVALUATION ORDER</div><div class="trace-list">${trace}</div></div>`;
      setStatus();
    } catch (error) {
      Object.entries(error.details || {}).forEach(([field, message]) => {
        const target = document.querySelector(`#packet-form [data-error="${field}"]`);
        if (target) target.textContent = message;
      });
      toast(error.message, true);
    }
  });
}

async function renderExport() {
  content.innerHTML = `${heading("Export", "Review generated rule syntax for manual use. Nothing on this page executes commands.")}
    <section class="panel"><div class="panel-head"><span class="panel-title">Generated ruleset</span><div style="display:flex;gap:7px"><button class="button small" id="copy-export">Copy</button><a class="button small" id="download-export" href="/api/export?format=iptables" download>Download .txt</a></div></div>
      <div class="export-tabs"><button class="export-tab active" data-format="iptables">iptables</button><button class="export-tab" data-format="nftables">nftables</button></div>
      <pre class="code-block" id="export-code"><span class="muted">Loading generated syntax…</span></pre>
      <div class="export-note">Only enabled rules are included, in evaluation order. Chain and table setup are intentionally not applied.</div></section>`;
  const loadFormat = async format => {
    state.exportFormat = format;
    const output = await api(`/api/export?format=${format}`);
    const lines = output.trim() ? output.trimEnd().split("\n") : [];
    document.getElementById("export-code").innerHTML = lines.length ? lines.map(line => {
      const words = line.split(" ");
      return `<span class="code-line"><span class="command">${escapeHtml(words.shift())}</span> ${words.map(word =>
        word.startsWith("-") || ["add", "rule", "ip", "filter", "INPUT", "OUTPUT", "FORWARD"].includes(word)
          ? `<span class="verb">${escapeHtml(word)}</span>` : `<span class="token">${escapeHtml(word)}</span>`
      ).join(" ")}</span>`;
    }).join("") : `<span class="muted">No enabled rules to export.</span>`;
    document.querySelectorAll(".export-tab").forEach(tab => tab.classList.toggle("active", tab.dataset.format === format));
    document.getElementById("download-export").href = `/api/export?format=${format}`;
  };
  document.querySelectorAll(".export-tab").forEach(tab => tab.addEventListener("click", () => loadFormat(tab.dataset.format).catch(error => toast(error.message, true))));
  document.getElementById("copy-export").addEventListener("click", async () => {
    try { await navigator.clipboard.writeText(await api(`/api/export?format=${state.exportFormat}`)); toast("Export copied to clipboard."); }
    catch (error) { toast(`Copy failed: ${error.message}`, true); }
  });
  await loadFormat(state.exportFormat);
}

async function renderLogs() {
  const logs = await api("/api/logs?limit=200");
  content.innerHTML = `${heading("Activity log", "Recent packet evaluations, including seeded demonstration traffic.")}
    <div class="toolbar"><input id="log-search" type="search" placeholder="Filter by address, rule, protocol…" style="max-width:360px">
      <select id="log-action" class="filter-select"><option value="">All decisions</option><option>ALLOW</option><option>DENY</option><option>REJECT</option></select>
      <span class="table-meta">${logs.length} recent events · simulation only</span></div>
    <section class="panel"><div class="table-wrap"><table><thead><tr><th>Timestamp</th><th>Source</th><th>Destination</th><th>Protocol</th><th>Port</th><th>Matched rule</th><th>Decision</th></tr></thead><tbody id="logs-body"></tbody></table></div></section>`;
  const filter = () => {
    const query = document.getElementById("log-search").value.toLowerCase();
    const action = document.getElementById("log-action").value;
    const rows = logs.filter(log => (!action || log.action === action) &&
      [log.src, log.dst, log.proto, log.port, log.rule_name].some(value => String(value || "").toLowerCase().includes(query)));
    document.getElementById("logs-body").innerHTML = rows.length ? rows.map(log => `<tr>
      <td class="mono muted">${escapeHtml(log.timestamp.replace("T", " ").replace("+00:00", "Z"))}</td>
      <td class="mono">${escapeHtml(log.src)}</td><td class="mono">${escapeHtml(log.dst)}</td>
      <td class="mono">${escapeHtml(log.proto)}</td><td class="mono">${escapeHtml(log.port)}</td>
      <td>${escapeHtml(log.rule_name || "Implicit deny")}</td><td>${actionPill(log.action)}</td></tr>`).join("") :
      `<tr><td colspan="7">${noData("No activity matches this filter.")}</td></tr>`;
  };
  document.getElementById("log-search").addEventListener("input", filter);
  document.getElementById("log-action").addEventListener("change", filter);
  filter();
}

function render() {
  const route = routeName();
  const safeRoute = pageNames[route] ? route : "overview";
  document.getElementById("page-label").textContent = pageNames[safeRoute];
  document.querySelectorAll(".main-nav a").forEach(link => link.classList.toggle("active", link.dataset.route === safeRoute));
  content.innerHTML = `<div class="loading">Loading policy data…</div>`;
  const pages = { overview: renderOverview, rules: renderRules, simulator: renderSimulator, export: renderExport, logs: renderLogs };
  Promise.resolve(pages[safeRoute]()).catch(error => {
    content.innerHTML = `<div class="error-state">Unable to load this page: ${escapeHtml(error.message)}</div>`;
  });
}

document.addEventListener("keydown", event => {
  if (event.key === "/" && !["INPUT", "TEXTAREA", "SELECT"].includes(document.activeElement.tagName)) {
    if (routeName() !== "rules") location.hash = "#/rules";
    window.setTimeout(() => document.getElementById("rule-search")?.focus(), 0);
    event.preventDefault();
  }
  if (event.key.toLowerCase() === "n" && !["INPUT", "TEXTAREA", "SELECT"].includes(document.activeElement.tagName)) {
    if (routeName() !== "rules") location.hash = "#/rules";
    window.setTimeout(() => { if (document.getElementById("new-rule")) openEditor(); }, 0);
  }
});
window.addEventListener("hashchange", render);
window.setInterval(() => { document.getElementById("clock").textContent = new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false }); }, 1000);
refresh().then(render).catch(error => { content.innerHTML = `<div class="error-state">Dashboard unavailable: ${escapeHtml(error.message)}</div>`; });
