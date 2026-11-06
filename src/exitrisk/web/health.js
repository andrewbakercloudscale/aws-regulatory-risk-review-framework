/* Health Check: pick the accounts in trouble, read everything in them, rank the likely causes. */
(() => {
  "use strict";
  const $ = (sel) => document.querySelector(sel);
  const esc = (v) => String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  const LS_THEME = "exitrisk.theme";
  const LS_PROFILE = "exitrisk.health.profile";
  const SEV_DOT = { critical: "var(--sev-critical)", high: "var(--sev-error)", medium: "var(--sev-warning)", low: "var(--sev-info)" };
  const state = { accounts: [], chosen: new Map(), details: {}, max: 10, runId: null, poll: null, reportId: null };

  try { const t = localStorage.getItem(LS_THEME); if (t) document.documentElement.dataset.theme = t; } catch { /* storage may be blocked */ }

  async function api(path, opts = {}) {
    const init = { ...opts, headers: { "Content-Type": "application/json", "X-ExitRisk": "1", ...(opts.headers || {}) } };
    if (init.body && typeof init.body !== "string") init.body = JSON.stringify(init.body);
    let res;
    try { res = await fetch(path, init); } catch { throw new Error("Cannot reach the console server. Is `exitrisk serve` still running?"); }
    const text = await res.text();
    let body = null;
    try { body = text ? JSON.parse(text) : null; } catch { body = { error: text }; }
    if (!res.ok) {
      const msg = body?.detail ? (Array.isArray(body.detail) ? body.detail.map((d) => `${d.loc?.slice(-1)[0]}: ${d.msg}`).join("; ") : body.detail) : body?.error || `HTTP ${res.status}`;
      const err = new Error(msg);
      err.hint = body?.hint; err.code = body?.code; err.status = res.status;
      throw err;
    }
    return body;
  }

  const when = (iso) => {
    if (!iso) return "";
    const d = new Date(iso);
    return isNaN(d) ? esc(iso) : d.toLocaleString(undefined, { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
  };
  const sev = (s) => `<span class="sev" style="--dot:${SEV_DOT[s] || "var(--muted)"}">${esc(s)}</span>`;
  const plural = (n, w) => `${n} ${w}${n === 1 ? "" : "s"}`;

  // ------------------------------------------------------------------ credentials
  async function loadProfiles() {
    const sel = $("#hcProfile");
    try {
      const { profiles, details } = await api("/api/profiles");
      state.details = details || {};
      if (!profiles.length) {
        sel.innerHTML = `<option value="">Default credentials (environment or instance role)</option>`;
      } else {
        const order = { "access key": 0, "session key": 1, sso: 2, role: 3, process: 4, other: 5 };
        const label = (p) => { const d = state.details[p]; return d?.label ? `${p}  ·  ${d.label}` : p; };
        const groups = {};
        for (const p of profiles) (groups[state.details[p]?.kind || "other"] ||= []).push(p);
        const names = { "access key": "Access keys", "session key": "Temporary keys", sso: "AWS sign-in (SSO)", role: "Assumed roles", process: "Credential process", other: "Other" };
        sel.innerHTML = Object.keys(groups).sort((a, b) => (order[a] ?? 9) - (order[b] ?? 9))
          .map((k) => `<optgroup label="${esc(names[k] || k)}">${groups[k].map((p) => `<option value="${esc(p)}">${esc(label(p))}</option>`).join("")}</optgroup>`).join("");
        let want = null;
        try { want = localStorage.getItem(LS_PROFILE); } catch { /* ignore */ }
        if (want && profiles.includes(want)) sel.value = want;
      }
    } catch (e) {
      $("#hcError").textContent = e.message;
    }
    await profileChanged();
  }

  function showKind() {
    const d = state.details[$("#hcProfile").value];
    const parts = [];
    if (d?.kind === "access key" || d?.kind === "session key") parts.push(`${d.kind === "access key" ? "Long lived access key" : "Temporary access key"} ${d.key || ""}, from your AWS credentials file. The secret is never shown or sent anywhere but AWS.`);
    else if (d?.kind === "sso") parts.push("Signs in through your AWS access portal; reaches every account the portal gives you.");
    else if (d?.kind === "role") parts.push(`Assumes a role (${d.label.replace(/^assumes /, "")}).`);
    else if (d?.kind === "process") parts.push("Gets its keys from a credential process.");
    if (d?.account) parts.push(`Account ${d.account}.`);
    $("#hcProfileKind").textContent = parts.join(" ");
  }

  let acctReq = 0;
  async function profileChanged() {
    const profile = $("#hcProfile").value;
    try { localStorage.setItem(LS_PROFILE, profile); } catch { /* ignore */ }
    showKind();
    $("#hcError").textContent = "";
    $("#hcSignIn").hidden = true;
    state.accounts = [];
    state.chosen.clear();
    renderChosen();
    $("#hcSearch").disabled = true;
    $("#hcSearch").placeholder = "Loading accounts, one moment…";
    const mine = ++acctReq;
    const sso = state.details[profile]?.kind === "sso";
    const t0 = Date.now();
    $("#hcAcctList").innerHTML = `<div class="busy" role="status" aria-live="polite"><div class="busy-head"><span class="spin" aria-hidden="true"></span>`
      + `<span>Finding the accounts these credentials reach…</span><span class="busy-time" id="hcAcctTime">0s</span></div>`
      + `<div class="busy-sub">${sso ? "Reading the account list from your access portal; a large organisation takes 10 to 20 seconds." : "Asking AWS which accounts this key can read."} Search opens when it is done.</div>`
      + `<span class="busy-bar"><i></i></span></div>`;
    const timer = setInterval(() => {
      const el = $("#hcAcctTime");
      if (!el || mine !== acctReq) return clearInterval(timer);
      el.textContent = `${Math.round((Date.now() - t0) / 1000)}s`;
    }, 500);
    const done = () => { clearInterval(timer); if (mine === acctReq) $("#hcSearch").placeholder = "Type to search"; };
    try {
      const q = new URLSearchParams({ profile, role_name: $("#hcRole").value.trim() });
      const r = await api(`/api/health-check/accounts?${q}`);
      if (mine !== acctReq) return;
      done();
      state.accounts = r.accounts || [];
      $("#hcSearch").disabled = false;
      $("#hcSearch").focus();
      if (state.accounts.length === 1) state.chosen.set(state.accounts[0].id, state.accounts[0]);
      let note = "";
      if (r.needs_role) note = `These credentials can list ${plural(state.accounts.length, "account")} in the organisation, but reach only ${r.caller.account_id} directly. To check another, give a role to assume above.`;
      else if (!r.sso && state.accounts.length === 1) note = `This key reaches its own account only (${r.caller.account_id}).`;
      if (note) { $("#hcSignIn").hidden = false; $("#hcSignIn").textContent = note; }
      renderList();
      renderChosen();
    } catch (e) {
      if (mine !== acctReq) return;
      done();
      $("#hcAcctList").innerHTML = "";
      showAccessError(e, profile);
    }
  }

  async function showAccessError(e, profile) {
    const box = $("#hcSignIn");
    box.hidden = false;
    const d = state.details[profile];
    let st = null;
    if (d?.kind === "sso") { try { st = await api(`/api/sign-in?profile=${encodeURIComponent(profile)}`); } catch { /* ignore */ } }
    if (st?.sso && !st.signed_in) {
      box.innerHTML = `Your AWS sign-in for <b>${esc(profile)}</b> has expired. <button class="btn primary" id="hcSso" type="button">Sign in</button> <span id="hcSsoMsg" class="muted small"></span>`;
      $("#hcSso").addEventListener("click", () => ssoSignIn(st.session));
      return;
    }
    box.innerHTML = `<span class="error-text">${esc(e.message)}</span>${e.hint ? `<div class="muted small">${esc(e.hint)}</div>` : ""}`;
  }

  async function ssoSignIn(session) {
    const tab = window.open("about:blank", "_blank");
    try {
      const login = await api("/api/sso/login", { method: "POST", body: { session } });
      if (tab) { tab.opener = null; tab.location.href = login.verification_uri; }
      $("#hcSsoMsg").innerHTML = `Approve code <b>${esc(login.user_code)}</b> in the tab that opened (<a href="${esc(login.verification_uri)}" target="_blank" rel="noopener">open it again</a>).`;
      for (;;) {
        await new Promise((r) => setTimeout(r, 2000));
        const s = await api(`/api/sso/login/${encodeURIComponent(login.id)}`);
        if (s.status === "complete") return profileChanged();
        if (s.status !== "pending") { $("#hcSsoMsg").textContent = s.message || `Sign-in ${s.status}.`; return; }
      }
    } catch (e) {
      if (tab) tab.close();
      $("#hcSsoMsg").textContent = e.message;
    }
  }

  // ------------------------------------------------------------------ accounts
  function renderList() {
    const q = $("#hcSearch").value.trim().toLowerCase();
    const hits = state.accounts.filter((a) => !q || a.id.includes(q) || (a.name || "").toLowerCase().includes(q));
    const shown = hits.slice(0, 200);
    $("#hcAcctList").innerHTML = shown.length
      ? shown.map((a) => `<label><input type="checkbox" value="${esc(a.id)}" ${state.chosen.has(a.id) ? "checked" : ""}> <span>${esc(a.name || a.id)}</span><span class="id">${esc(a.id)}</span></label>`).join("")
        + (hits.length > shown.length ? `<label class="muted">${hits.length - shown.length} more: type more of the name or number</label>` : "")
      : `<label class="muted">${state.accounts.length ? "No account matches" : "No accounts found"}</label>`;
  }

  function renderChosen() {
    const box = $("#hcChosen");
    box.innerHTML = state.chosen.size
      ? [...state.chosen.values()].map((a) => `<span class="chip">${esc(a.name || a.id)} <span class="muted">${esc(a.id)}</span><button type="button" data-id="${esc(a.id)}" aria-label="Remove ${esc(a.name || a.id)}">×</button></span>`).join("")
      : `<span class="muted small">No account ticked yet.</span>`;
    $("#hcRun").disabled = !state.chosen.size || !!state.runId;
    $("#hcAccessBtn").disabled = !state.chosen.size;
  }

  // ------------------------------------------------------------------ access
  async function checkAccess(body) {
    const box = $("#hcAccess");
    box.hidden = false;
    box.innerHTML = `<p class="muted small">Checking access: each read once in ${body.accounts.length} account${body.accounts.length > 1 ? "s" : ""}…</p>`;
    let r;
    try {
      r = await api("/api/health-check/access", { method: "POST", body });
    } catch (e) {
      box.innerHTML = `<p class="error-text">Access check failed: ${esc(e.message)}</p>`;
      return null;
    }
    const out = r.accounts.filter((a) => a.error || a.denied.length);
    if (r.ready) {
      box.innerHTML = `<p class="hc-ok">✓ Access ready: all ${r.checked} reads allowed in ${r.accounts.map((a) => esc(a.name)).join(", ")}.</p>`;
      return r;
    }
    const policy = r.policy ? JSON.stringify(r.policy, null, 2) : "";
    box.innerHTML = `<p><b>Some reads are refused.</b> The health check still runs; what it cannot read is listed under "Could not check". Add the policy below to the role or user, then run again.</p>
      <ul class="small">${out.map((a) => `<li><b>${esc(a.name)}</b> <span class="muted">${esc(a.account)}</span>: ${a.error ? `not reached (${esc(a.error.code)}: ${esc(a.error.message)})` : `${a.denied.length} refused: ${a.denied.map(esc).join(", ")}`}</li>`).join("")}</ul>
      ${policy ? `<details open><summary>IAM policy to add</summary><pre class="hc-policy">${esc(policy)}</pre><button type="button" class="btn small" id="hcCopyPolicy">Copy policy</button></details>` : ""}`;
    $("#hcCopyPolicy")?.addEventListener("click", async (e) => {
      try { await navigator.clipboard.writeText(policy); e.target.textContent = "Copied"; } catch { /* ignore */ }
    });
    return r;
  }

  function requestBody() {
    return {
      profile: $("#hcProfile").value || null,
      role_name: $("#hcRole").value.trim() || null,
      accounts: [...state.chosen.values()].map((a) => ({ id: a.id, name: a.name || "" })),
      hours: Number($("#hcHours").value),
      symptoms: $("#hcSymptoms").value.trim(),
    };
  }

  // ------------------------------------------------------------------ run
  async function run() {
    $("#hcError").textContent = "";
    $("#hcRun").disabled = true;
    await checkAccess(requestBody()); // permissions first, so a refusal is named before the long run
    const body = {
      profile: $("#hcProfile").value || null,
      role_name: $("#hcRole").value.trim() || null,
      accounts: [...state.chosen.values()].map((a) => ({ id: a.id, name: a.name || "" })),
      hours: Number($("#hcHours").value),
      symptoms: $("#hcSymptoms").value.trim(),
    };
    try {
      const job = await api("/api/health-check", { method: "POST", body });
      follow(job.id);
    } catch (e) {
      $("#hcError").textContent = e.message;
    }
  }

  function follow(id) {
    state.runId = id;
    $("#hcRun").disabled = true;
    $("#hcStop").hidden = false;
    $("#hcProgress").hidden = false;
    clearTimeout(state.poll);
    const tick = async () => {
      try {
        const r = await api(`/api/health-check/${encodeURIComponent(id)}`);
        const run = r.run;
        const pct = run.total ? Math.round((100 * run.done) / run.total) : 2;
        $("#hcProgBar").style.width = `${pct}%`;
        $("#hcProgMsg").textContent = `${run.message || ""} · ${run.done || 0} of ${run.total || "?"} checks · ${run.elapsed ?? 0} s`;
        if (r.report) return finished(r.report);
        state.poll = setTimeout(tick, 1500);
      } catch (e) {
        $("#hcError").textContent = e.message;
        state.poll = setTimeout(tick, 4000);
      }
    };
    tick();
  }

  function finished(report) {
    state.runId = null;
    $("#hcStop").hidden = true;
    $("#hcProgress").hidden = true;
    renderChosen();
    showReport(report);
    loadRuns();
  }

  async function stop() {
    if (!state.runId) return;
    try { await api(`/api/health-check/${encodeURIComponent(state.runId)}`, { method: "DELETE" }); } catch (e) { $("#hcError").textContent = e.message; }
  }

  // ------------------------------------------------------------------ report
  function showReport(r) {
    state.reportId = r.id;
    $("#btnPdf").disabled = false;
    history.replaceState(null, "", `/health?run=${encodeURIComponent(r.id)}`);
    const s = r.summary;
    const accts = r.accounts.map((a) => `${esc(a.name || a.id)} <span class="muted">${esc(a.id)}</span>`).join(", ");
    const tiles = [
      ["Critical now", s.critical, "tone-risk", "Problems at critical level in the window, new since yesterday."],
      ["High now", s.high, "tone-risk", "Problems at high level in the window, new since yesterday."],
      ["Medium now", s.medium, "", "Problems at medium level in the window, new since yesterday."],
      ["Risky changes", `${s.sharp_changes}<span class="muted small"> of ${s.changes}</span>`, "tone-est",
        `Changes made by people or pipelines in the window that can break things straight away: deletes, stops, detaches, revoked access, failovers, key deletion. "of ${s.changes}" counts every change that can affect availability. AWS's own actions are left out. See Recent changes below.`],
      ["Long standing", s.chronic, "", "Problems already at about the same level a day earlier."],
      ["Could not check", s.gaps, s.gaps ? "tone-risk" : "", "Checks that could not read something; listed at the end with the fix."],
    ];
    const status = r.status === "done" ? "" : `<p class="error-text">This run ${esc(r.status)}${r.error ? `: ${esc(r.error)}` : ""}. What it found before then is below.</p>`;
    const top = r.top || [];
    $("#hcReport").innerHTML = `
      <section class="card">
        <div class="card-head"><h2>Health check</h2><span class="muted small">${when(r.window?.start)} to ${when(r.window?.end)} (${esc(r.window?.hours)} h) · run ${when(r.created)}</span></div>
        <p>${accts}</p>
        ${r.symptoms ? `<p class="muted"><b>Symptoms given:</b> ${esc(r.symptoms)}</p>` : ""}
        ${status}
        ${r.unreachable?.length ? `<p class="error-text">Not reached: ${r.unreachable.map((u) => `${esc(u.name || u.account)} (${esc(u.code)}: ${esc(u.message)})`).join("; ")}</p>` : ""}
        <div class="tiles" style="grid-template-columns:repeat(6,minmax(0,1fr))">${tiles.map(([l, v, t, tip]) => `<div class="tile ${t}" title="${esc(tip)}"><div class="tile-label">${l}</div><div class="tile-value">${v}</div></div>`).join("")}</div>
      </section>

      <section class="card">
        <h2>Top ${top.length || 10} issues</h2>
        <p class="muted small">Most critical first, then by outage likelihood: how likely each is to cause, or already be, an outage users feel. High: failing now and new, or started just before failures it can cause. Medium: pressure that becomes an outage if it grows, or a fault standing for over a day. Low: minor, or absorbed at the same level a day earlier. Useful with or without an outage going on; confirm each with its next step.</p>
        ${top.length ? `<div class="table-wrap"><table class="data hc-top"><thead><tr><th>#</th><th>Issue</th><th>Why</th><th>Started</th><th>Where</th><th>Outage likelihood</th><th>Next step</th></tr></thead><tbody>
          ${top.map((g) => `<tr>
            <td class="rank">${g.rank}</td>
            <td><b>${esc(g.title)}</b><div>${sev(g.severity)}${g.kind === "change" ? `<span class="hc-tag">change</span>` : g.kind === "symptom" ? `<span class="hc-tag">unexplained symptom</span>` : ""}${g.ongoing ? `<span class="hc-tag">still happening</span>` : ""}${g.chronic ? `<span class="hc-tag">long standing</span>` : ""}</div></td>
            <td class="why small">${esc(g.why)}</td>
            <td class="nowrap small">${when(g.started) || "before the window"}</td>
            <td class="small">${esc(g.account_name || g.account)}<div class="muted">${esc(g.region)}</div></td>
            <td><span class="conf ${esc(g.likelihood)}" title="${esc(g.likelihood_why || "")}">${esc(g.likelihood)}</span>${g.likelihood_why ? `<div class="muted small conf-why">${esc(g.likelihood_why)}</div>` : ""}</td>
            <td class="small">${esc(g.next || "")}</td></tr>`).join("")}
        </tbody></table></div>` : `<p><b>No fault found in this window.</b> If users still see a problem, widen the window, add symptoms, or check what these accounts call outside AWS.</p>`}
      </section>

      ${r.signals.length ? `<section class="card">
        <details class="hc-more" open><summary>Everything found (${r.signals.length})</summary>
        ${signalsTable(r.signals)}</details>
      </section>` : ""}

      ${(r.risks || []).length ? `<section class="card">
        <h2>Other issues in ${r.accounts.length > 1 ? "these accounts" : "this account"} (${r.risks.length})</h2>
        <p class="muted small">Not the live fault, but what the Outage Risk checks find here: limits nearly reached, single points of failure, resources running hot. Worst first.</p>
        <div class="table-wrap"><table class="data compact"><thead><tr><th>Severity</th><th>Issue</th><th>Resource</th><th>Why</th><th>Where</th></tr></thead><tbody>
          ${r.risks.map((x) => `<tr><td>${sev(x.severity)}</td><td class="small"><b>${esc(x.title)}</b><div class="muted">${esc(x.service_label || "")}</div></td><td class="small">${esc(x.res || "")}${x.note ? `<div class="muted">${esc(x.note)}</div>` : ""}</td><td class="small">${esc(x.why || "")}</td><td class="small">${esc(x.account_name || x.account)}<div class="muted">${esc(x.region || "")}</div></td></tr>`).join("")}
        </tbody></table></div>
      </section>` : ""}

      ${(r.readiness || []).length ? `<section class="card">
        <h2>Turn on to see more (${r.readiness.length})</h2>
        <p class="muted small">Data sources that are off, so a cause there could not be seen. Turn them on now and run again: they only cover traffic from then on.</p>
        <div class="table-wrap"><table class="data compact"><thead><tr><th>What is off</th><th>What it hides</th><th>How to turn it on</th><th>Where</th></tr></thead><tbody>
          ${r.readiness.map((x) => `<tr><td class="small"><b>${esc(x.item)}</b></td><td class="small">${esc(x.why)}</td><td class="small">${esc(x.how)}${x.permission ? `<div class="muted">Needs ${esc(x.permission)}</div>` : ""}</td><td class="small">${esc(x.account_name || x.account)}<div class="muted">${esc(x.region)}</div></td></tr>`).join("")}
        </tbody></table></div>
      </section>` : ""}

      ${r.changes.length ? `<section class="card">
        <details class="hc-more"><summary>Changes in the window (${r.changes.length})</summary>
        ${changesTable(r.changes)}</details>
      </section>` : ""}

      ${r.timeline.length ? `<section class="card">
        <details class="hc-more"><summary>Timeline (${r.timeline.length})</summary>
        ${r.timeline.length ? `<div class="table-wrap"><table class="data compact"><thead><tr><th>When</th><th>What</th><th>Kind</th><th>Account</th><th>Region</th></tr></thead><tbody>
          ${r.timeline.map((t) => `<tr><td class="nowrap small">${when(t.time)}</td><td class="small">${sev(t.severity)} ${esc(t.what)}</td><td class="small">${esc(t.kind)}</td><td class="small">${esc(t.account)}</td><td class="small">${esc(t.region)}</td></tr>`).join("")}
        </tbody></table></div>` : ""}</details>
      </section>` : ""}

      <section class="card">
        ${r.gaps.length ? `<h3>Could not check (${r.gaps.length})</h3><p class="muted small">A cause in one of these would not show above.</p><div class="table-wrap"><table class="data compact"><thead><tr><th>Check</th><th>Account</th><th>Region</th><th>Reason</th></tr></thead><tbody>
          ${r.gaps.map((g) => `<tr><td class="small">${esc(g.check)}</td><td class="small">${esc(g.account_name || g.account)}</td><td class="small">${esc(g.region)}</td><td class="small"><b>${esc(g.code)}</b> ${esc(g.message)}${g.hint ? `<div class="muted">${esc(g.hint)}</div>` : ""}</td></tr>`).join("")}
        </tbody></table></div>` : `<p class="muted small">Every check ran in every region in use (${r.accounts.map((a) => `${esc(a.name || a.id)}: ${a.regions.map(esc).join(", ")}`).join("; ")}).</p>`}
        <p class="muted small">Checks: ${r.checks.map(esc).join(", ")}.${s.scanned_gb ? ` Logs Insights read ${esc(s.scanned_gb)} GB (about US$${(s.scanned_gb * 0.005).toFixed(2)}).` : ""}</p>
      </section>
      <p class="report-footer">AWS Cloud Risk Review · Health Check ${esc(r.id)}</p>`;
    for (const tr of document.querySelectorAll("#hcRuns tr[data-id]")) tr.classList.toggle("chosen", tr.dataset.id === r.id);
  }

  function signalsTable(signals) {
    if (!signals.length) return `<p class="muted">Nothing out of the ordinary.</p>`;
    return `<div class="table-wrap"><table class="data compact"><thead><tr><th>Severity</th><th>What</th><th>Evidence</th><th>Started</th><th>Where</th><th>Source</th></tr></thead><tbody>
      ${signals.map((s) => `<tr><td>${sev(s.severity)}${s.chronic ? `<div class="hc-tag">long standing</div>` : ""}</td><td class="small"><b>${esc(s.title)}</b>${s.next ? `<div class="muted">${esc(s.next)}</div>` : ""}</td><td class="small">${esc(s.evidence || "")}</td><td class="nowrap small">${when(s.started)}</td><td class="small">${esc(s.account_name || s.account)}<div class="muted">${esc(s.region)}</div></td><td class="small">${esc(s.source || s.area || "")}</td></tr>`).join("")}
    </tbody></table></div>`;
  }

  // Hundreds of the same call by the same caller (a clean-up job) read as one row.
  function changesTable(changes) {
    if (!changes.length) return `<p class="muted">No risky change was made in the window.</p>`;
    const groups = new Map();
    for (const c of changes) {
      const k = `${c.account}|${c.region}|${c.event}|${c.who}`;
      const g = groups.get(k);
      if (g) { g.n += 1; g.first = c.time < g.first ? c.time : g.first; g.last = c.time > g.last ? c.time : g.last; if (g.res.length < 4 && c.resource) g.res.push(c.resource); }
      else groups.set(k, { ...c, n: 1, first: c.time, last: c.time, res: c.resource ? [c.resource] : [] });
    }
    const rows = [...groups.values()].sort((a, b) => (b.sharp - a.sharp) || (b.last > a.last ? 1 : -1));
    return `<div class="table-wrap"><table class="data compact"><thead><tr><th>When</th><th>Change</th><th>On</th><th>By</th><th>Where</th></tr></thead><tbody>
      ${rows.map((g) => `<tr><td class="nowrap small">${when(g.last)}${g.n > 1 ? `<div class="muted">from ${when(g.first)}</div>` : ""}</td><td class="small"><b>${esc(g.event)}</b>${g.n > 1 ? ` <span class="hc-tag">×${g.n}</span>` : ""}${g.sharp ? `<span class="hc-tag">risky</span>` : ""}<div class="muted">${esc(g.service)}</div></td><td class="small">${esc(g.res.join(", "))}${g.n > g.res.length && g.res.length ? " …" : ""}</td><td class="small">${esc(g.who)}</td><td class="small">${esc(g.account_name || g.account)}<div class="muted">${esc(g.region)}</div></td></tr>`).join("")}
    </tbody></table></div>`;
  }

  // ------------------------------------------------------------------ earlier runs
  async function loadRuns() {
    try {
      const { runs, running } = await api("/api/health-checks");
      $("#hcRuns").innerHTML = runs.length
        ? `<thead><tr><th>When</th><th>Accounts</th><th>Window</th><th>Symptoms</th><th>Status</th><th></th></tr></thead><tbody>${runs.map((r) => `<tr data-id="${esc(r.id)}" class="${r.id === state.reportId ? "chosen" : ""}"><td class="nowrap">${when(r.created)}</td><td>${esc(r.accounts.join(", "))}</td><td>${esc(r.hours)} h</td><td class="muted">${esc(r.symptoms)}</td><td>${esc(r.status)}</td><td><button class="btn ghost" data-del="${esc(r.id)}" type="button" title="Delete this run">Delete</button></td></tr>`).join("")}</tbody>`
        : `<tbody><tr><td class="muted">None yet.</td></tr></tbody>`;
      if (running?.length && !state.runId) follow(running[0]);
    } catch (e) {
      $("#hcRuns").innerHTML = `<tbody><tr><td class="error-text">${esc(e.message)}</td></tr></tbody>`;
    }
  }

  async function openRun(id) {
    try {
      const r = await api(`/api/health-check/${encodeURIComponent(id)}`);
      if (r.report) showReport(r.report); else follow(id);
      $("#hcReport").scrollIntoView({ behavior: "smooth", block: "start" });
    } catch (e) {
      $("#hcError").textContent = e.message;
    }
  }

  // ------------------------------------------------------------------ wiring
  $("#hcProfile").addEventListener("change", profileChanged);
  let roleTimer = null;
  $("#hcRole").addEventListener("input", () => { clearTimeout(roleTimer); roleTimer = setTimeout(profileChanged, 700); });
  $("#hcSearch").addEventListener("input", renderList);
  $("#hcAcctList").addEventListener("change", (e) => {
    const box = e.target.closest("input[type=checkbox]");
    if (!box) return;
    const a = state.accounts.find((x) => x.id === box.value);
    if (box.checked) {
      if (state.chosen.size >= state.max) { box.checked = false; $("#hcError").textContent = `Up to ${state.max} accounts at a time.`; return; }
      state.chosen.set(a.id, a);
    } else state.chosen.delete(a.id);
    $("#hcError").textContent = "";
    renderChosen();
  });
  $("#hcSearch").addEventListener("keydown", (e) => {
    if (e.key !== "Enter") return;
    e.preventDefault();
    const first = $("#hcAcctList input[type=checkbox]:not(:checked)");
    if (first) { first.checked = true; first.dispatchEvent(new Event("change", { bubbles: true })); }
  });
  $("#hcChosen").addEventListener("click", (e) => {
    const b = e.target.closest("button[data-id]");
    if (!b) return;
    state.chosen.delete(b.dataset.id);
    renderChosen();
    renderList();
  });
  $("#hcRun").addEventListener("click", run);
  $("#hcAccessBtn").addEventListener("click", () => checkAccess(requestBody()));
  $("#hcStop").addEventListener("click", stop);
  $("#btnPdf").addEventListener("click", () => {
    for (const d of document.querySelectorAll("details.hc-more")) d.open = true;
    setTimeout(() => window.print(), 200);
  });
  $("#hcRuns").addEventListener("click", async (e) => {
    const del = e.target.closest("button[data-del]");
    if (del) {
      e.stopPropagation();
      try { await api(`/api/health-check/${encodeURIComponent(del.dataset.del)}`, { method: "DELETE" }); } catch (err) { $("#hcError").textContent = err.message; }
      if (del.dataset.del === state.reportId) { $("#hcReport").innerHTML = ""; $("#btnPdf").disabled = true; state.reportId = null; history.replaceState(null, "", "/health"); }
      return loadRuns();
    }
    const tr = e.target.closest("tr[data-id]");
    if (tr) openRun(tr.dataset.id);
  });

  loadProfiles();
  loadRuns();
  const want = new URLSearchParams(location.search).get("run");
  if (want) openRun(want);
})();
