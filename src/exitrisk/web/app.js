/* AWS Exit Risk Review - dashboard client.
 * Talks to the local API (see server.py). Every value from the API is escaped before it
 * reaches the DOM: account names and error messages come from AWS and are not trusted HTML.
 */
(() => {
  "use strict";

  const params = new URLSearchParams(location.search);
  const PRINT = params.get("print") === "1";
  if (params.get("onepage") === "1") document.body.classList.add("onepage");
  const LS_Q = "exitrisk.questionnaire.v1";
  const LS_THEME = "exitrisk.theme";
  const LS_ORG_PROFILE = "exitrisk.orgProfile"; // last profile that could read the OU tree
  const MGMT_RE = /mgmt|management|payer|master|org/i;
  const state = { exclude: new Set(), scanId: null, report: null, catalog: null, options: null, charts: {}, pollTimer: null };

  // ------------------------------------------------------------------ utils
  const $ = (sel) => document.querySelector(sel);
  const esc = (v) => String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  const css = (name) => getComputedStyle(document.documentElement).getPropertyValue(name).trim();
  const tierColor = (t) => css(`--t${t}`);
  const RATING_TIER = { Low: 1, Moderate: 2, Elevated: 3, High: 4, Critical: 5 };
  const SEV_COLOR = { critical: "--sev-critical", error: "--sev-error", warning: "--sev-warning", info: "--sev-info" };

  // A value that is not there. Not a dash: the console and reports use no en or em dashes.
  const EMPTY = "n/a";
  function money(v, cur = "USD", digits) {
    if (v == null || isNaN(v)) return EMPTY;
    const abs = Math.abs(v);
    const sym = cur === "USD" ? "$" : cur + " ";
    if (abs >= 1e6) return `${sym}${(v / 1e6).toFixed(digits ?? 1)}m`;
    if (abs >= 1e4) return `${sym}${(v / 1e3).toFixed(0)}k`;
    if (abs >= 1e3) return `${sym}${(v / 1e3).toFixed(1)}k`;
    return `${sym}${v.toFixed(0)}`;
  }
  const num = (v, d = 0) => (v == null || isNaN(v) ? EMPTY : Number(v).toLocaleString(undefined, { maximumFractionDigits: d, minimumFractionDigits: d }));
  const pct = (v, d = 0) => (v == null ? EMPTY : `${Number(v).toFixed(d)}%`);
  const plural = (n, word, many) => `${num(n)} ${Math.round(n) === 1 ? word : many || word + "s"}`;
  // "2025-10" -> "Oct 2025" (or "Oct 25" for chart axes).
  const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
  function month(m, short) {
    const [y, mo] = String(m || "").split("-").map(Number);
    if (!y || !mo) return String(m ?? EMPTY);
    return `${MONTHS[mo - 1]} ${short ? String(y).slice(2) : y}`;
  }
  const ACCOUNT_ROWS = 15; // account ranking rows shown before "Show all"

  function toast(msg, ms = 3500) {
    const t = $("#toast");
    t.textContent = msg;
    t.classList.add("show");
    clearTimeout(t._h);
    t._h = setTimeout(() => t.classList.remove("show"), ms);
  }

  // POST that answers with NDJSON: onLine gets each parsed line as it arrives.
  async function apiStream(path, body, onLine) {
    let res;
    try {
      res = await fetch(path, { method: "POST", headers: { "Content-Type": "application/json", "X-ExitRisk": "1" }, body: JSON.stringify(body) });
    } catch (e) {
      console.error("network error", path, e);
      throw new Error("Cannot reach the console server. Is `exitrisk serve` still running?");
    }
    if (!res.ok) {
      let msg = `HTTP ${res.status}`;
      try { const b = await res.json(); msg = typeof b.detail === "string" ? b.detail : b.error || msg; } catch { /* keep HTTP status */ }
      console.error("api error", path, res.status, msg);
      throw new Error(msg);
    }
    const reader = res.body.getReader();
    const dec = new TextDecoder();
    let buf = "";
    for (;;) {
      const { value, done } = await reader.read();
      buf += dec.decode(value || new Uint8Array(), { stream: !done });
      let nl;
      while ((nl = buf.indexOf("\n")) >= 0) {
        const line = buf.slice(0, nl).trim();
        buf = buf.slice(nl + 1);
        if (line) onLine(JSON.parse(line));
      }
      if (done) return;
    }
  }

  async function api(path, opts = {}) {
    const init = { ...opts, headers: { "Content-Type": "application/json", "X-ExitRisk": "1", ...(opts.headers || {}) } };
    if (init.body && typeof init.body !== "string") init.body = JSON.stringify(init.body);
    let res;
    try {
      res = await fetch(path, init);
    } catch (e) {
      console.error("network error", path, e);
      throw new Error("Cannot reach the console server. Is `exitrisk serve` still running?");
    }
    const text = await res.text();
    let body = null;
    try { body = text ? JSON.parse(text) : null; } catch { body = { error: text }; }
    if (!res.ok) {
      const msg = body?.detail ? (Array.isArray(body.detail) ? body.detail.map((d) => `${d.loc?.slice(-1)[0]}: ${d.msg}`).join("; ") : body.detail)
        : body?.error || `HTTP ${res.status}`;
      const err = new Error(msg);
      err.hint = body?.hint;
      err.code = body?.code;
      err.status = res.status;
      err.requestId = body?.request_id || res.headers.get("X-Request-Id");
      console.error("api error", path, res.status, msg);
      throw err;
    }
    return body;
  }

  // ------------------------------------------------------------------ theme
  function applyTheme(t) {
    if (t) document.documentElement.dataset.theme = t; else delete document.documentElement.dataset.theme;
  }
  try { applyTheme(localStorage.getItem(LS_THEME)); } catch { /* storage may be unavailable */ }
  if (PRINT) applyTheme("light");

  // ------------------------------------------------------------------ questionnaire
  const Q_NUM = ["cloud_team_size", "cloud_team_allocation_pct", "app_engineers_fte", "day_rate", "fx_per_usd",
    "contingency_pct", "parallel_run_months", "materiality", "migration_circuit_monthly", "exit_deadline_months", "edp_annual_commit"];

  function loadQuestionnaire() {
    let q = { ...(state.options?.defaults || {}) };
    try { Object.assign(q, JSON.parse(localStorage.getItem(LS_Q) || "{}")); } catch { /* ignore */ }
    if (params.get("q")) {
      try { Object.assign(q, JSON.parse(params.get("q"))); state.answersFromLink = true; } catch { console.warn("bad q param"); }
    }
    return q;
  }

  function fillQuestionnaire(q) {
    const f = $("#qForm");
    const fillSelect = (name, labels) => {
      f[name].innerHTML = Object.entries(labels).map(([v, l]) => `<option value="${esc(v)}">${esc(l)}</option>`).join("");
    };
    fillSelect("cicd", state.options.cicd);
    fillSelect("iac", state.options.iac);
    fillSelect("target", state.options.target);
    fillSelect("dc_facility", state.options.dc_facility);
    for (const form of [f, $("#resForm"), $("#timeForm")]) {
      for (const [k, v] of Object.entries(q)) {
        if (!form[k]) continue;
        if (form[k].type === "checkbox") form[k].checked = !!v;
        // A saved answer an older or newer version no longer offers keeps the default instead of blanking the select.
        else if (form[k].tagName === "SELECT" && ![...form[k].options].some((o) => o.value === v)) continue;
        else form[k].value = v;
      }
    }
    state.exclude = new Set(Array.isArray(q.exclude_services) ? q.exclude_services : []);
    syncDatacenter();
  }

  // The data-centre questions only apply when the exit target is your own data centre.
  function syncDatacenter() {
    $("#dcFields").hidden = $("#qForm").target.value !== "datacenter";
  }

  function readQuestionnaire() {
    const q = {};
    // The resilience (section 6) and timing inputs travel with the delivery answers but do not confirm them.
    for (const el of [...$("#qForm").elements, ...$("#resForm").elements, ...$("#timeForm").elements]) {
      if (!el.name) continue;
      if (el.type === "checkbox") q[el.name] = el.checked;
      else if (el.name === "confirmed") q.confirmed = el.value === "true";
      else if (Q_NUM.includes(el.name)) q[el.name] = el.value === "" ? undefined : Number(el.value);
      else q[el.name] = el.name === "currency" ? el.value.toUpperCase() : el.value;
    }
    q.exclude_services = [...(state.exclude || [])].sort();
    // Answers opened from a shared link (?q=) are someone else's: keep them out of this browser's saved
    // answers until the reader changes one.
    if (!state.answersFromLink) { try { localStorage.setItem(LS_Q, JSON.stringify(q)); } catch { /* ignore */ } }
    return q;
  }

  // ------------------------------------------------------------------ compare scans
  function openCompare() {
    const done = (state.scans || []).filter((x) => x.status === "complete");
    const label = (x) => `${x.label || x.ou || "Scan"} · ${x.id.slice(0, 13)}${x.mode === "demo" ? " · demo" : ""}`;
    const opts = done.map((x) => `<option value="${esc(x.id)}">${esc(label(x))}</option>`).join("");
    $("#cmpBefore").innerHTML = opts;
    $("#cmpAfter").innerHTML = opts;
    $("#cmpOut").innerHTML = "";
    $("#cmpError").textContent = done.length < 2 ? "Compare needs two completed scans. Run another scan later and compare it with this one." : "";
    // Default: the open scan against the previous scan of the same OU (scans are listed newest first).
    const now = done.find((x) => x.id === state.scanId) || done[0];
    const older = now && (done.find((x) => x.id < now.id && x.ou === now.ou && x.mode === now.mode) || done.find((x) => x.id < now.id));
    if (now) $("#cmpAfter").value = now.id;
    if (older) $("#cmpBefore").value = older.id;
    $("#compareDialog").showModal();
    if (now && older) runCompare();
  }

  async function runCompare() {
    const before_id = $("#cmpBefore").value, after_id = $("#cmpAfter").value;
    $("#cmpError").textContent = "";
    if (!before_id || !after_id) return;
    if (before_id === after_id) { $("#cmpOut").innerHTML = ""; $("#cmpError").textContent = "Pick two different scans."; return; }
    const filter = { include: $("#fInclude").value, exclude: $("#fExclude").value, mode: $("#fMode").value };
    const seq = (state.cmpSeq = (state.cmpSeq || 0) + 1);
    busy("#cmpBusy", "Scoring both scans…");
    try {
      const c = await api("/api/compare", { method: "POST", body: { before_id, after_id, filter, questionnaire: readQuestionnaire() } });
      if (seq === state.cmpSeq) renderCompare(c);
    } catch (e) {
      if (seq === state.cmpSeq) { $("#cmpOut").innerHTML = ""; $("#cmpError").textContent = e.message; }
    } finally {
      if (seq === state.cmpSeq) busy("#cmpBusy", "");
    }
  }

  function renderCompare(c) {
    const h = c.headline;
    const chg = (d, fmt) => d.change == null ? EMPTY : `${d.change > 0 ? "+" : d.change < 0 ? "−" : ""}${fmt(Math.abs(d.change))}${d.change_pct != null && d.change ? ` (${d.change_pct > 0 ? "+" : ""}${num(d.change_pct)}%)` : ""}`;
    // Colour only the figures where up is worse (risk); spend and counts are neutral.
    const cls = (d, worse) => !worse || !d.change ? "" : d.change > 0 ? "up-bad" : "down-good";
    const before = (ym) => { const [y, m] = ym.split("-").map(Number); return m > 1 ? `${y}-${m - 1}` : `${y - 1}-12`; };
    const period = (x) => x.period?.start ? `${month(x.period.start.slice(0, 7))} to ${month(before(x.period.end.slice(0, 7)))}` : ""; // end is exclusive
    const row = (k, d, fmt, worse) => `<tr><td><strong>${esc(k)}</strong></td><td class="num-cell">${d.before == null ? EMPTY : fmt(d.before)}</td><td class="num-cell">${d.after == null ? EMPTY : fmt(d.after)}</td><td class="num-cell ${cls(d, worse)}">${chg(d, fmt)}</td></tr>`;
    const n1 = (v) => num(v, 1), n0 = (v) => num(v);
    let html = `<ul class="cmp-summary">${c.summary.map((t) => `<li>${esc(t)}</li>`).join("")}</ul>`;
    if (!c.same_scope) html += `<p class="warn-text small">The scans cover different OUs (${esc(c.before.ou)} and ${esc(c.after.ou)}): part of the change is scope.</p>`;
    html += `<h3>Key figures</h3><div class="table-wrap"><table class="data"><thead><tr><th></th><th class="num-cell">${esc(c.before.scan_id.slice(0, 13))}<div class="hint">${esc(period(c.before))}</div></th><th class="num-cell">${esc(c.after.scan_id.slice(0, 13))}<div class="hint">${esc(period(c.after))}</div></th><th class="num-cell">Change</th></tr></thead><tbody>` +
      row("Exit-risk score", h.score, n1, 1) + row("Monthly spend", h.monthly_spend, money, 0) + row("High/Critical spend a month", h.high_risk_monthly, money, 1) +
      row("Share on High/Critical (%)", h.high_risk_pct, n1, 1) + row("Accounts with spend", h.accounts, n0, 0) + row("High/Critical accounts", h.high_risk_accounts, n0, 1) +
      row("Services in use", h.services, n0, 0) +
      `<tr><td><strong>Exit cost estimate</strong></td><td class="num-cell">${esc(h.cost_range.before)}</td><td class="num-cell">${esc(h.cost_range.after)}</td><td></td></tr></tbody></table></div>`;
    html += `<h3>Spend by tier</h3><div class="table-wrap"><table class="data"><thead><tr><th>Tier</th><th class="num-cell">Earlier</th><th class="num-cell">Later</th><th class="num-cell">Change</th></tr></thead><tbody>` +
      c.tiers.map((t) => row(`${t.tier} · ${t.label}`, t, money, t.tier >= 4 ? 1 : 0)).join("") + "</tbody></table></div>";
    const a = c.accounts;
    const names = (list, n) => list.map((x) => `${esc(x.name)} <span class="muted">(${money(x.monthly_spend)}/month, ${esc(x.rating || EMPTY)})</span>`).join(", ") + (n > list.length ? `, and ${n - list.length} more` : "");
    html += `<h3>Accounts</h3>`;
    if (a.added_count) html += `<p><strong>Added (${num(a.added_count)}):</strong> ${names(a.added, a.added_count)}</p>`;
    if (a.removed_count) html += `<p><strong>Removed (${num(a.removed_count)}):</strong> ${names(a.removed, a.removed_count)}</p>`;
    html += a.movers.length ? `<div class="table-wrap"><table class="data"><thead><tr><th>Biggest movers</th><th>Rating</th><th class="num-cell">Per month</th><th class="num-cell">Spend at risk / month</th></tr></thead><tbody>` +
      a.movers.map((m) => `<tr><td><strong>${esc(m.name)}</strong></td><td>${m.rating.before === m.rating.after ? esc(m.rating.after || EMPTY) : `${esc(m.rating.before || EMPTY)} → <strong>${esc(m.rating.after || EMPTY)}</strong>`}</td>
        <td class="num-cell">${money(m.monthly_spend.after)} <span class="hint">${chg(m.monthly_spend, money)}</span></td><td class="num-cell ${cls(m.spend_at_risk, 1)}">${chg(m.spend_at_risk, money)}</td></tr>`).join("") + "</tbody></table></div>"
      : `<p class="muted">No account changed materially.</p>`;
    html += `<h3>Services</h3>` + (c.services.length ? `<div class="table-wrap"><table class="data"><thead><tr><th>Service</th><th>Tier</th><th class="num-cell">Earlier</th><th class="num-cell">Later</th><th class="num-cell">Change</th></tr></thead><tbody>` +
      c.services.map((x) => `<tr><td><strong>${esc(x.service)}</strong>${x.status !== "both" ? ` <span class="chip">${x.status === "new" ? "new" : "no longer used"}</span>` : ""}</td><td><span class="tier-pill" style="--dot:${tierColor(x.tier)}">${esc(x.tier_label)}</span></td>
        <td class="num-cell">${money(x.before)}</td><td class="num-cell">${money(x.after)}</td><td class="num-cell ${cls(x, x.tier >= 4 ? 1 : 0)}">${chg(x, money)}</td></tr>`).join("") + "</tbody></table></div>"
      : `<p class="muted">No service's spend changed.</p>`);
    $("#cmpOut").innerHTML = html;
  }

  // ------------------------------------------------------------------ monthly scan
  const fmtDate = (iso) => iso ? new Date(iso).toLocaleDateString("en-GB", { day: "numeric", month: "short", year: "numeric" }) : "";
  const fmtWhen = (iso) => iso ? new Date(iso).toLocaleString("en-GB", { day: "numeric", month: "short", hour: "2-digit", minute: "2-digit" }) : "";

  async function refreshSchedule() {
    try { state.sched = await api("/api/schedule"); } catch { return; }
    const st = state.sched, s = st.schedule, banner = $("#schedBanner");
    clearTimeout(state.schedTimer);
    if (s?.running) state.schedTimer = setTimeout(refreshSchedule, 15000);
    if (state.schedWasRunning && !s?.running) refreshScans(state.scanId);
    state.schedWasRunning = !!s?.running;
    banner.hidden = !(s?.running || st.failing);
    banner.classList.toggle("bad", !!st.failing && !s?.running);
    $("#schedBannerText").textContent = s?.running
      ? `Monthly scan running since ${fmtWhen(s.running.started_at)}. It appears in the scan list when it finishes.`
      : st.failing ? `Monthly scan failed ${fmtWhen(s.last_attempt_at)}: ${s.last_error || "see the log"}. Sign in to AWS, then Run now${st.retry_at ? `, or it retries ${fmtWhen(st.retry_at)}` : ""}.` : "";
    if ($("#schedDialog").open) renderScheduleState();
  }

  function renderScheduleState() {
    const st = state.sched || {}, s = st.schedule, box = $("#schedState");
    box.hidden = !s;
    $("#btnSchedOff").hidden = $("#btnSchedRun").hidden = !s;
    $("#btnSchedRun").disabled = !!s?.running;
    if (!s) return;
    const last = s.last_status === "failed" ? `<span class="error-text">failed ${esc(fmtWhen(s.last_attempt_at))}: ${esc(s.last_error || "see the log")}</span>`
      : `${esc(s.last_status)}, scan ${esc((s.last_scan_id || "").slice(0, 13))} (${esc(fmtDate(s.last_success_at))})`;
    box.innerHTML = `<div><strong>${s.enabled ? "On" : "Off"}</strong> · repeats ${esc(s.label || s.ou || s.from_scan)}${s.ou ? ` <span class="muted">(${esc(s.ou)})</span>` : ""}</div>
      <div>${s.running ? `<strong>Running</strong> since ${esc(fmtWhen(s.running.started_at))}` : `Next run: <strong>${esc(fmtDate(st.next_run))}</strong>${st.due ? (st.failing ? " (overdue)" : " (due now)") : ""}`}</div>
      <div class="muted">Last run: ${last}</div>`;
  }

  function openSchedule() {
    const s = state.sched?.schedule;
    const live = (state.scans || []).filter((x) => x.mode === "live" && x.status !== "failed");
    $("#schedFrom").innerHTML = live.length ? live.map((x) => `<option value="${esc(x.id)}">${esc(`${x.label || x.ou || "Scan"} · ${x.id.slice(0, 13)}`)}</option>`).join("")
      : `<option value="">No live scans yet</option>`;
    const open = live.find((x) => x.id === state.scanId);
    $("#schedFrom").value = s && live.some((x) => x.id === s.from_scan) ? s.from_scan : (open || live[0])?.id || "";
    $("#schedDay").innerHTML = Array.from({ length: 28 }, (_, i) => `<option value="${i + 1}">${i + 1}</option>`).join("");
    $("#schedDay").value = String(s?.day || 3);
    $("#btnSchedSave").disabled = !live.length;
    $("#schedError").textContent = live.length ? "" : "Run a scan against AWS first: the monthly scan repeats its settings (the demo has none).";
    renderScheduleState();
    $("#schedDialog").showModal();
    refreshSchedule();
  }

  async function saveSchedule() {
    $("#schedError").textContent = "";
    try {
      state.sched = await api("/api/schedule", { method: "PUT", body: { from_scan: $("#schedFrom").value, day: Number($("#schedDay").value) } });
      renderScheduleState();
      toast(`Monthly scan set: next run ${fmtDate(state.sched.next_run)}`);
    } catch (e) { $("#schedError").textContent = e.message; }
  }

  async function scheduleOff() {
    try { state.sched = await api("/api/schedule", { method: "DELETE" }); } catch (e) { $("#schedError").textContent = e.message; return; }
    renderScheduleState();
    refreshSchedule();
    toast("Monthly scan turned off");
  }

  async function scheduleRunNow() {
    $("#schedError").textContent = "";
    clearTimeout(state.schedTimer);
    $("#btnSchedRun").disabled = true;
    busy("#schedBusy", "Starting the monthly scan…");
    try {
      const r = await api("/api/schedule/run", { method: "POST" });
      const tick = async () => {
        let j;
        try { j = await api(`/api/scans/${encodeURIComponent(r.scan_id)}/status`); }
        catch (e) { busy("#schedBusy", ""); $("#btnSchedRun").disabled = false; $("#schedError").textContent = `Lost track of the scan: ${e.message}. It may still be running; check the scan list.`; return; }
        busyProgress("#schedBusy", j.pct / 100);
        $("#schedBusy .busy-text").textContent = j.message || j.phase;
        if (j.status === "running") { state.schedTimer = setTimeout(tick, 1000); return; }
        busy("#schedBusy", "");
        $("#btnSchedRun").disabled = false;
        await refreshSchedule();
        if (j.status === "failed") $("#schedError").textContent = `Scan failed: ${j.message}.`;
        else { await refreshScans(state.scanId); toast(`Monthly scan ${j.status}: open it from the scan list, or Compare scans`); }
      };
      refreshSchedule();
      tick();
    } catch (e) { busy("#schedBusy", ""); $("#btnSchedRun").disabled = false; $("#schedError").textContent = e.message; }
  }

  // ------------------------------------------------------------------ scans
  async function refreshScans(selectId) {
    const { scans } = await api("/api/scans");
    const sel = $("#scanSelect");
    sel.innerHTML = scans.length
      ? scans.map((s) => `<option value="${esc(s.id)}">${esc(s.label || s.ou || "Scan")} · ${esc(s.id.slice(0, 13))}${s.mode === "demo" ? " · demo" : ""}${s.status !== "complete" ? " · " + esc(s.status) : ""}</option>`).join("")
      : `<option value="">No scans yet</option>`;
    if (selectId) sel.value = selectId;
    state.scans = scans;
    return scans;
  }

  /** Load and render the report; true when it worked (the error is already shown when it did not). */
  async function loadReport() {
    if (!state.scanId) return false;
    const filter = { include: $("#fInclude").value, exclude: $("#fExclude").value, mode: $("#fMode").value };
    const weighting = $("#fWeighting").value || "spend";
    $("#filterError").textContent = "";
    try {
      state.report = await api("/api/report", { method: "POST", body: { scan_id: state.scanId, filter, questionnaire: readQuestionnaire(), weighting } });
    } catch (e) {
      const msg = /scan not found/i.test(e.message)
        ? "This scan is not on this machine any more (deleted, or the console uses another data folder). Pick another scan."
        : e.message;
      $("#filterError").textContent = msg;
      toast(msg);
      if (PRINT) { document.body.dataset.error = e.message; document.body.dataset.ready = "1"; }
      return false;
    }
    const url = new URL(location.href);
    url.searchParams.set("scan", state.scanId);
    for (const [k, v] of Object.entries(filter)) { if (v && !(k === "mode" && v === "contains")) url.searchParams.set(k, v); else url.searchParams.delete(k); }
    if (weighting !== "spend") url.searchParams.set("weighting", weighting); else url.searchParams.delete("weighting");
    if ($("#fMinRating").value) url.searchParams.set("min_rating", $("#fMinRating").value); else url.searchParams.delete("min_rating");
    if (!PRINT) history.replaceState(null, "", url);
    // The optional AI review is stored per scan; fetch it before drawing so the PDF includes it.
    state.ai = await api(`/api/ai/review/${encodeURIComponent(state.scanId)}`).catch(() => null);
    render();
    if (state.ai?.run?.status === "running") pollAi();
    // The multi-region view follows the same scan and filter.
    state.mr = null;
    if (state.view === "multiregion") loadMultiRegion();
    return true;
  }

  // ------------------------------------------------------------------ render
  function render() {
    const r = state.report;
    $("#empty").hidden = true;
    $("#reportBar").hidden = false;
    $("#content").hidden = state.view === "multiregion";
    try {
      renderCover(r);
      renderSummary(r);
      renderWork(r);
      renderProfile(r);
      renderAccounts(r);
      renderServices(r);
      renderEstimate(r);
      renderResilience(r);
      renderTiming(r);
      renderFocus(r);
      renderAi(r);
      renderIssues(r);
      renderAppendix(r);
      renderOnePager(r);
      renderExclusions(r);
    } catch (e) {
      // A rendering bug must not leave a half-drawn report that looks complete, or hang the PDF export.
      console.error("render failed", e);
      const msg = `The report could not be drawn (${e.message}). Reload the page; if it persists, open the log and report it.`;
      $("#filterError").textContent = msg;
      toast(msg, 8000);
      if (PRINT) { document.body.dataset.error = msg; document.body.dataset.ready = "1"; }
      return;
    }
    $("#footer").textContent = `Generated ${new Date(r.meta.generated_at).toLocaleString()} by aws-regulatory-risk-review-framework v${r.meta.tool_version} · catalog ${r.meta.catalog_version} · scan ${r.meta.scan_id}`;
    if (state.view !== "multiregion") document.body.dataset.ready = "1";
  }

  function renderCover(r) {
    const m = r.meta;
    $("#title").textContent = m.mode === "demo" ? "AWS exit risk review: demo organisation" : `AWS exit risk review: ${m.ou?.path || "organisation"}`;
    $("#subtitle").textContent = m.mode === "demo"
      ? "Synthetic data for demonstration. Not a real organisation."
      : "How hard it would be to leave AWS, weighted by where the money is spent.";
    const items = [
      ["Scope", m.filter.description],
      ["Organizational unit", m.ou?.path || EMPTY],
      ["Accounts in scope", `${r.summary.accounts_in_scope} of ${r.summary.accounts_total}`],
      ["Spend period", m.months_in_data?.length ? `${month(m.months_in_data[0])} to ${month(m.months_in_data.at(-1))} (${plural(m.months_in_data.length, "month")}, amortised)` : EMPTY],
      ["Scanned", m.scanned_at ? new Date(m.scanned_at).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" }) : EMPTY],
      ["Management account", m.org?.management_account_id || m.identity?.account_id || EMPTY],
      ["Scan depth", r.summary.scan_depth_label || (m.inventory ? "Inventory scan (resource counts)" : "Quick scan (billing only)")],
      ["Exit target assumed", m.target_label],
    ];
    const notes = r.summary.coverage || [];
    $("#coverage").hidden = !notes.length;
    $("#coverage").innerHTML = notes.map((n) => `<p>${esc(n)}</p>`).join("");
    $("#metaList").innerHTML = items.map(([k, v]) => `<div><dt>${esc(k)}</dt><dd>${esc(v)}</dd></div>`).join("");
  }

  // Tiles are tinted by what they say: lock-in and risk (warm), cost and time to act (violet), plain facts (blue).
  const TILE_TONE = [
    [/high\/critical|bespoke|aws-only|rapid exit|correlated|critical accounts|failover|commitments|edp/i, "risk"],
    [/cost|window|effort|time to|finishes|deadline|notice|people|uplift|infrastructure/i, "est"],
  ];
  function tile(label, value, sub, provisional) {
    const tone = TILE_TONE.find(([re]) => re.test(label))?.[1] || "fact";
    return `<div class="tile tone-${tone}${provisional ? " is-provisional" : ""}"><div class="tile-label">${esc(label)}</div><div class="tile-value">${esc(String(value).replace(/person-/g, "person\u2011"))}${provisional ? ' <span class="prov-tag" title="Uses default answers: answer the questions under Exit model">Provisional</span>' : ""}</div>${sub ? `<div class="tile-sub">${esc(sub)}</div>` : ""}</div>`;
  }

  // "team of 128 full-time people": capacity is headcount working in parallel, not years.
  const teamSize = (fte) => `team of ${num(fte, Number.isInteger(fte) ? 0 : 1)} full-time people`;

  function ratingBadge(el, rating, text) {
    el.textContent = text;
    el.style.setProperty("--dot", RATING_TIER[rating] ? tierColor(RATING_TIER[rating]) : css("--muted"));
  }

  const DEPTH_HINT = {
    quick: "Spend and account data from the management account. Effort is sized from spend, so confidence stays lower.",
    inventory: "Also counts resources (instances, functions, tables, queues...) in each member account and sizes effort from them. Needs a role in every member account.",
    dependency: "Also counts the integrations between services (event sources, rule targets, subscriptions, API and workflow integrations). Highest confidence; needs the dependency-scan actions in the member role.",
  };
  const STATUS_TIER = { Ready: 1, "Needs work": 3, "Hard to move": 5 };
  // Portability runs the other way to risk: 100 is easy to move (green), 0 is hard (red).
  const portTier = (p) => (p == null ? null : p >= 80 ? 1 : p >= 60 ? 2 : p >= 40 ? 3 : p >= 20 ? 4 : 5);
  const pill = (tier, text, color) => tier || color ? `<span class="tier-pill" style="--dot:${color || tierColor(tier)}">${esc(text)}</span>` : esc(text);

  // Exit difficulty on its own terms: three measures, five dimensions, critical readiness, integrations.
  function renderWork(r) {
    const s = r.summary, m = s.measures, e = r.estimate;
    $("#workBlock").hidden = $("#workDetail").hidden = !m || m.portability.score == null;
    if (!m || m.portability.score == null) return;
    const depth = s.scan_depth || "quick";
    ratingBadge($("#depthBadge"), { quick: "Critical", inventory: "High", dependency: "Low" }[depth], s.scan_depth_label || depth);
    const b = m.basis_pct || {};
    const basis = [b.resources ? `${pct(b.resources)} from counted resources` : "", b.integrations ? `${pct(b.integrations)} integrations` : "", b.spend ? `${pct(b.spend)} from spend` : ""].filter(Boolean).join(", ");
    $("#measureTiles").innerHTML = [
      tile("Technical portability", `${Math.round(m.portability.score)}/100`, `${m.portability.rating} exit difficulty · weighted by effort, not spend`),
      tile("Exit effort", m.effort.range, basis ? `sized ${basis}` : "", m.provisional),
      tile("Exit window", m.duration || EMPTY, e.duration ? `bound by ${e.duration.constrained_by}` : "", m.provisional),
    ].join("");
    $("#measureTiles").firstElementChild.style.setProperty("--tone", tierColor(portTier(m.portability.score)));
    $("#dimCards").innerHTML = (s.dimensions || []).map((d, i) => `<div class="dim${d.measured ? "" : " unmeasured"}">
      <div class="dim-num">${i + 1}</div>
      <div class="dim-label">${esc(d.label)}</div>
      <div class="dim-value">${d.measured ? esc(d.value) : "Not measured"}</div>
      <div class="dim-detail">${esc(d.detail)}</div>
      <div class="dim-ev">${esc(d.evidence)}</div>
    </div>`).join("");
    const port = (s.dimensions || []).find((d) => d.key === "portability");
    if (port) $("#dimCards").firstElementChild.style.setProperty("--tone", tierColor(portTier(m.portability.score)));

    const ready = s.critical_readiness || [];
    $("#readyTable").innerHTML = ready.length ? `<thead><tr><th>Account</th><th>Readiness</th><th class="num-cell" title="Technical portability, 0-100: 100 is easy to move">Portability</th><th class="num-cell">Engineer-days</th><th class="num-cell" title="AWS-specific integrations found by the dependency scan">Integrations</th><th class="num-cell">Data</th><th>What blocks it</th></tr></thead><tbody>` +
      ready.map((a) => `<tr><td><strong>${esc(a.name)}</strong><div class="hint">${money(a.monthly_spend)}/month</div></td><td>${pill(STATUS_TIER[a.status], a.status, a.status === "Needs work" ? css("--warn-ink") : "")}</td><td class="num-cell">${a.portability == null ? EMPTY : Math.round(a.portability)}</td><td class="num-cell">${num(a.effort_days)}</td><td class="num-cell">${a.integrations == null ? EMPTY : num(a.integrations)}</td><td class="num-cell">${tb(a.data_tb)}</td><td>${esc((a.blockers.length ? a.blockers : a.lockin).slice(0, 3).join(", ") || "none")}</td></tr>`).join("") + "</tbody>"
      : `<tbody><tr><td class="muted">No account is marked critical. Tag accounts, or list their names under Resilience in the exit model, to see their readiness here.</td></tr></tbody>`;

    const it = s.integrations || {};
    $("#intCap").textContent = it.measured
      ? `${num(it.total)} found in ${plural(it.accounts, "dependency-scanned account")}, ${num(it.hard)} involving High or Critical services. Each one is wiring an exit must rebuild, whatever the services cost.`
      : "Not measured: run a Dependency scan to count the event sources, rule targets, subscriptions and API and workflow integrations between services.";
    $("#intTable").innerHTML = it.measured && it.top?.length ? `<thead><tr><th>Integration</th><th class="num-cell">Count</th><th>Exit tier</th></tr></thead><tbody>` +
      it.top.map((x) => `<tr><td>${esc(x.label)}</td><td class="num-cell">${num(x.count)}</td><td>${pill(x.tier, r.tiers.find((t) => t.tier === x.tier)?.label || `Tier ${x.tier}`)}</td></tr>`).join("") + "</tbody>" : "";
    $("#intNote").innerHTML = it.measured
      ? `Read from: ${esc(it.sources.join("; ") || "none")}.${it.missing_sources?.length ? ` <strong>Not read</strong> (permission refused somewhere, see Data quality): ${esc(it.missing_sources.join("; "))}.` : ""} Not visible to this scan: ${esc(it.not_discovered.join("; "))}. Missing evidence is not evidence of independence.`
      : "";
  }

  function renderSummary(r) {
    const s = r.summary, e = r.estimate;
    $("#heroScore").textContent = s.score_by_spend == null ? EMPTY : Math.round(s.score_by_spend);
    ratingBadge($("#heroRating"), s.rating_by_spend, s.score_by_spend == null ? "No spend in scope" : s.rating_by_spend);
    $("#heroScoreAcc").textContent = s.score_by_accounts == null ? EMPTY : Math.round(s.score_by_accounts);
    ratingBadge($("#heroRatingAcc"), s.rating_by_accounts, s.score_by_accounts == null ? EMPTY : s.rating_by_accounts);
    $(".scale-bands").innerHTML = [1, 2, 3, 4, 5].map((t) => `<div style="background:${tierColor(t)};border-radius:3px"></div>`).join("");
    $("#heroAlt").textContent = s.score == null ? "" : s.score_by_spend - s.score_by_accounts >= 5
      ? "Risk is concentrated in a few large accounts: most accounts are easier to move than the spend view suggests."
      : s.score_by_accounts - s.score_by_spend >= 5
        ? "Risk is spread across many smaller accounts: the spend view understates how many workloads need re-engineering."
        : "Spend and account views agree: risk is spread in line with spend.";
    $("#scaleMarker").style.left = `${Math.min(100, Math.max(0, s.score_by_spend || 0))}%`;
    $("#scaleMarkerAcc").style.left = `${Math.min(100, Math.max(0, s.score_by_accounts || 0))}%`;
    $("#kpiTiles").innerHTML = [
      tile("Annual spend in scope", money(s.annual_spend), `${money(s.monthly_spend)} / month, amortised`),
      tile("High/Critical spend", pct(s.high_risk_pct), `${money(s.high_risk_monthly * 12)} a year`),
      tile("Accounts in scope", num(s.accounts_in_scope), `${num(s.accounts_with_spend)} with spend · ${num(s.accounts_excluded)} filtered out`),
      tile("High/Critical accounts", s.accounts_rated ? `${num(s.high_risk_accounts)} of ${num(s.accounts_rated)}` : EMPTY,
        s.accounts_rated ? `${pct(s.high_risk_accounts_spend_pct)} of spend · ${num(s.portable_accounts)} portable (Low/Moderate)` : "No accounts with spend"),
      tile("AWS-only services", num(s.bespoke_services), s.top_lockin_services.length ? `largest: ${s.top_lockin_services.slice(0, 3).map((x) => x.display).join(", ")}` : "none in use"),
      tile("Spend growth", s.growth?.total?.pct == null ? EMPTY : `${s.growth.total.pct > 0 ? "+" : ""}${num(s.growth.total.pct, 1)}%`,
        s.growth?.total ? `${month(s.growth.first_month)} → ${month(s.growth.last_month)} · High/Critical ${s.growth.lockin.pct > 0 ? "+" : ""}${num(s.growth.lockin.pct, 1)}%` : "needs 2+ months of history"),
      ...(e.empty ? [tile("Exit cost (one-off)", EMPTY, "No spend in scope"), tile("Exit window (time to leave AWS)", EMPTY, "No spend in scope"), tile("Engineering effort", EMPTY, "No spend in scope")] : [
        // Ranges only: a single figure would claim precision an early-stage estimate does not have.
        tile("Exit cost (one-off)", e.ranges.cost, e.ranges.pct_of_annual_spend ? `${e.ranges.pct_of_annual_spend} of a year's AWS spend` : "engineering and parallel running", e.provisional),
        tile("Exit window (time to leave AWS)", e.ranges.duration, `bound by ${e.duration.constrained_by}`, e.provisional),
        tile("Engineering effort", e.ranges.effort, teamSize(e.team.capacity_fte), e.provisional),
        ...writtenOffTile(s.executive, e.provisional),
      ]),
    ].join("");
    const x = s.executive;
    const lead = (i) => `<li><strong>${esc(i.lead)}</strong> ${esc(i.text)}</li>`;
    $("#briefHeadline").textContent = x.headline || x.bottom_line;
    $("#briefContext").textContent = x.context || "";
    $("#briefProvisional").hidden = !x.provisional;
    $("#briefFacts").innerHTML = (x.exit_facts || []).map((f) => `<div class="${f.provisional ? "is-provisional" : ""}"><dt>${esc(f.label)}${f.provisional ? ' <span class="prov-tag">Provisional</span>' : ""}</dt><dd>${esc(f.value)}</dd><dd class="note">${esc(f.note)}</dd></div>`).join("");
    // With default answers the numbers describe a made-up organisation: the callout replaces them.
    $("#briefFacts").hidden = !(x.exit_facts || []).length || !!x.provisional;
    $("#briefFindings").innerHTML = (x.findings_rich || x.findings.map((t) => ({ lead: "", text: t }))).map(lead).join("");
    $("#briefActions").innerHTML = (x.actions_rich || x.actions.map((t) => ({ lead: "", text: t }))).map(lead).join("");
    const confRating = { High: "Low", Medium: "High", Low: "Critical" }[x.confidence];
    ratingBadge($("#briefConf"), confRating, `Confidence: ${x.confidence}`);
    $("#briefConfWhy").textContent = x.confidence_reasons.join(" ");
    // Each reason confidence is not High, with the step (and the console control) that removes it.
    const steps = x.confidence_steps || [];
    const iamDoc = "https://github.com/andrewbakercloudscale/aws-regulatory-risk-review-framework/blob/main/docs/IAM_PERMISSIONS.md#2-deep-scan-member-accounts";
    const btnLabel = { model: "Answer the questions", scan: "New scan", deep: "New deep scan" };
    $("#briefConfSteps").hidden = !steps.length;
    $("#briefConfSteps").innerHTML = steps.length ? `<h4>To raise confidence</h4><ol>${steps.map((st) => `<li><span>${esc(st.fix).replace("IAM_PERMISSIONS.md", `<a href="${iamDoc}" target="_blank" rel="noopener noreferrer">IAM_PERMISSIONS.md</a>`)}</span>${st.action ? ` <button type="button" class="btn sm no-print" data-conf-action="${esc(st.action)}">${btnLabel[st.action]}</button>` : ""}</li>`).join("")}</ol>` : "";
  }

  // Savings Plans, reservations and EDP still running when the exit finishes: paid for, no longer used.
  function writtenOffTile(x, provisional, short) {
    const f = (x.exit_facts || []).find((v) => v.label === "Commitments written off");
    const sub = f?.value === "None" ? "all end before the fastest exit finishes"
      : short ? "still owed after the exit" : "still owed after the exit; whole organisation, even when filtered";
    return f ? [tile(f.label, f.value, sub, provisional)] : [];
  }

  // Chart.js defaults - recessive chrome, thin marks, tooltips on.
  function chartDefaults() {
    const C = window.Chart;
    C.defaults.font.family = css("--font") || "system-ui";
    C.defaults.font.size = 12;
    C.defaults.color = css("--ink-2");
    C.defaults.borderColor = css("--grid");
    // Set the duration in place: replacing the animation object drops Chart.js's colour interpolator,
    // and hovering a bar then throws "this._fn is not a function", which stops every chart redrawing.
    if (PRINT) C.defaults.animation = false; else C.defaults.animation.duration = 400;
    C.defaults.maintainAspectRatio = false;
    C.defaults.plugins.legend.labels.boxWidth = 10;
    C.defaults.plugins.legend.labels.boxHeight = 10;
    C.defaults.plugins.legend.labels.useBorderRadius = true;
    C.defaults.plugins.legend.labels.borderRadius = 3;
    C.defaults.plugins.legend.labels.padding = 14;
    C.defaults.plugins.legend.labels.color = css("--ink-2");
    // Tooltips read as cards: surface, hairline border, bold title, colour swatch per line.
    C.defaults.plugins.tooltip.backgroundColor = css("--surface");
    C.defaults.plugins.tooltip.borderColor = css("--axis");
    C.defaults.plugins.tooltip.borderWidth = 1;
    C.defaults.plugins.tooltip.titleColor = css("--ink");
    C.defaults.plugins.tooltip.bodyColor = css("--ink-2");
    C.defaults.plugins.tooltip.footerColor = css("--ink");
    C.defaults.plugins.tooltip.titleFont = { weight: "600", size: 13 };
    C.defaults.plugins.tooltip.bodyFont = { size: 12.5 };
    C.defaults.plugins.tooltip.padding = 12;
    C.defaults.plugins.tooltip.cornerRadius = 8;
    C.defaults.plugins.tooltip.boxPadding = 4;
    C.defaults.plugins.tooltip.usePointStyle = true;
    C.defaults.plugins.tooltip.caretSize = 5;
    // Recessive axes: no axis line, soft grid, ticks a step away from the plot.
    C.defaults.scale.border.display = false;
    C.defaults.scale.grid.color = css("--grid");
    C.defaults.scale.grid.tickLength = 0;
    C.defaults.scale.ticks.padding = 8;
    C.defaults.elements.bar.borderRadius = 4;
    C.defaults.elements.arc.borderColor = css("--surface");
    C.defaults.elements.arc.borderWidth = 2;
    C.defaults.elements.point.hoverRadius = 6;
  }

  function chart(id, config) {
    const canvas = document.getElementById(id);
    const box = canvas.parentElement;
    box.querySelector(".chart-error")?.remove();
    if (!window.Chart) {
      console.error("Chart.js not loaded");
      box.insertAdjacentHTML("beforeend", `<p class="chart-error">The chart library did not load. Reload the page (Cmd+Shift+R).</p>`);
      return;
    }
    state.charts[id]?.destroy();
    // Hover keeps the mark's own colour (Chart.js would saturate it); the tooltip does the highlighting.
    for (const ds of config.data?.datasets || []) {
      if (ds.hoverBackgroundColor === undefined && ds.backgroundColor !== undefined) ds.hoverBackgroundColor = ds.backgroundColor;
      if (ds.hoverBorderColor === undefined && ds.borderColor !== undefined) ds.hoverBorderColor = ds.borderColor;
    }
    try {
      state.charts[id] = new window.Chart(canvas, config);
    } catch (e) {
      console.error(`chart ${id} failed`, e);
      box.insertAdjacentHTML("beforeend", `<p class="chart-error">This chart could not be drawn (${esc(e.message)}).</p>`);
    }
  }

  // Chrome may drop a canvas's pixels when the tab sits in the background or memory runs short, and
  // printing resizes charts for paper; redraw them all when that happens so none is left blank.
  function redrawCharts() {
    for (const c of Object.values(state.charts)) { c.resize(); c.update("none"); }
  }

  function renderProfile(r) {
    const tiers = r.tiers;
    chart("chTiers", {
      type: "doughnut",
      data: {
        labels: tiers.map((t) => `${t.tier} · ${t.label}`),
        datasets: [{ data: tiers.map((t) => t.monthly_spend), backgroundColor: tiers.map((t) => tierColor(t.tier)), borderColor: css("--surface"), borderWidth: 2, hoverOffset: 4 }],
      },
      options: {
        cutout: "62%",
        plugins: {
          legend: { display: false }, // the table beside it is the legend
          tooltip: { callbacks: { label: (c) => ` ${money(c.raw)}/month · ${pct(tiers[c.dataIndex].pct, 1)}` } },
        },
      },
    });
    $("#tierTable").innerHTML = `<thead><tr><th>Tier</th><th class="num-cell">Per month</th><th class="num-cell">Share</th><th class="num-cell">Services</th><th class="num-cell" title="Accounts spending at least $1/month on services in this tier; an account can use several tiers">Accounts</th></tr></thead><tbody>` +
      tiers.map((t) => `<tr><td class="nowrap"><span class="swatch" style="background:${tierColor(t.tier)}"></span>${t.tier} · ${esc(t.label)}</td><td class="num-cell">${money(t.monthly_spend)}</td><td class="num-cell">${pct(t.pct, 1)}</td><td class="num-cell">${t.services}</td><td class="num-cell">${num(t.accounts)}</td></tr>`).join("") + "</tbody>";

    renderGrowth(r);
    chart("chTrend", {
      type: "bar",
      data: {
        labels: r.trend.map((m) => month(m.month, true)),
        datasets: [1, 2, 3, 4, 5].map((t) => ({
          label: `${t} · ${tiers[t - 1].label}`, data: r.trend.map((m) => m.tier_spend[t]),
          backgroundColor: tierColor(t), borderColor: css("--surface"), borderWidth: 1, borderRadius: 3, borderSkipped: false, maxBarThickness: 46,
        })),
      },
      options: {
        scales: { x: { stacked: true, grid: { display: false }, ticks: { maxRotation: 0, autoSkipPadding: 8 } }, y: { stacked: true, ticks: { callback: (v) => money(v) }, border: { display: false } } },
        plugins: { legend: { position: "bottom" }, tooltip: { mode: "index", callbacks: { title: (items) => month(r.trend[items[0].dataIndex].month), label: (c) => ` ${c.dataset.label}: ${money(c.raw)}`, footer: (items) => `Total: ${money(items.reduce((a, i) => a + (i.raw || 0), 0))}` } } },
        interaction: { mode: "index", intersect: false },
      },
    });
  }

  function renderGrowth(r) {
    const g = r.growth;
    const sgn = (v, d = 1) => v == null ? EMPTY : `${v > 0 ? "+" : ""}${num(v, d)}%`;
    const usd = (v) => `${v > 0 ? "+" : v < 0 ? "−" : ""}${money(Math.abs(v))}`;
    // The model caps annualised growth at 999% (a near-zero first month); say so rather than show a false figure.
    const perYear = (v) => (v != null && v >= 999 ? "over +999%" : sgn(v));
    if (!g || g.months < 2 || !g.total) {
      $("#growthHead").textContent = "Growth needs at least two months of spend history. Run a scan with 12 months to see it.";
      $("#growthCap").textContent = "";
      $("#growthTable").innerHTML = "";
      $("#growthNote").textContent = "";
      chart("chGrowth", { type: "bar", data: { labels: [], datasets: [] } });
      return;
    }
    const annual = g.months >= 6;
    const cls = (v) => (v > 0 ? "up" : v < 0 ? "down" : "");
    $("#growthHead").innerHTML = `${esc(month(g.first_month))} to ${esc(month(g.last_month))}: total spend <span class="${cls(g.total.pct)}">${sgn(g.total.pct)}</span>` +
      (annual ? ` (${sgn(g.total.annualised_pct)} a year)` : "") +
      `; spend on High/Critical services <span class="${cls(g.lockin.pct)}">${sgn(g.lockin.pct)}</span>` + (annual ? ` (${sgn(g.lockin.annualised_pct)} a year)` : "") +
      `. ${g.lockin.pct != null && g.total.pct != null ? (g.lockin.pct > g.total.pct + 1 ? "Lock-in is growing faster than the estate." : g.lockin.pct < g.total.pct - 1 ? "Lock-in is growing more slowly than the estate." : "Lock-in is growing in line with the estate.") : ""}`;
    $("#growthCap").textContent = `Change in monthly spend from ${month(g.first_month)} to ${month(g.last_month)}, by product type, in dollars and percent. Under each type, the service that moved most. Each bar is split by how hard its services are to exit: green easy, grey moderate, red hard.`;
    const rows = [...g.by_category].sort((a, b) => b.change - a.change);
    // The service that moved a product type most; for Marketplace/Bedrock, the product behind it.
    const pctOrNew = (v) => (v == null ? "new" : sgn(v, 0));
    const short = (t) => (t.length > 16 ? `${t.slice(0, 15)}…` : t);
    const driverText = (d) => `${short(d.products?.length ? d.products[0] : d.display)} ${usd(d.change)} (${pctOrNew(d.change_pct)})`;
    // Each bar's change in money and percent, written right of the bar (or of zero, for a decline) so
    // the chart reads without hovering; the right padding fits the longest one.
    const endText = rows.map((x) => `${usd(x.change)}  ${pctOrNew(x.pct)}`);
    const endFont = `600 12px ${css("--font")}`;
    const measure = document.createElement("canvas").getContext("2d");
    measure.font = endFont;
    const endPad = Math.ceil(Math.max(0, ...endText.map((t) => measure.measureText(t).width))) + 14;
    measure.font = `${Chart.defaults.font.size}px ${Chart.defaults.font.family}`;
    const labelWidth = Math.ceil(Math.max(0, ...rows.flatMap((c) => [c.category, ...(c.drivers?.length ? [driverText(c.drivers[0])] : [])]).map((t) => measure.measureText(t).width))) + 16;
    const barEnds = { id: "barEnds", afterDatasetsDraw(ch) {
      const ctx = ch.ctx;
      ctx.save();
      ctx.font = endFont;
      ctx.fillStyle = css("--ink");
      ctx.textBaseline = "middle";
      ctx.textAlign = "left";
      // Stacked by tier: write after the rises (or after zero, for a decline).
      ch.getDatasetMeta(0).data.forEach((bar, i) => ctx.fillText(endText[i], ch.scales.x.getPixelForValue(rises[i]) + 8, bar.y));
      ctx.restore();
    } };
    const tiers = [1, 2, 3, 4, 5];
    const seg = (c, t) => (c.by_tier ? c.by_tier[t] || 0 : 0);
    const rises = rows.map((c) => tiers.reduce((sum, t) => sum + Math.max(seg(c, t), 0), 0));
    // Match the table beside it so the two cards line up.
    $("#chGrowth").parentElement.style.height = `${Math.max(300, 42 * rows.length + 70)}px`;
    chart("chGrowth", {
      type: "bar",
      data: {
        labels: rows.map((c) => c.drivers?.length ? [c.category, driverText(c.drivers[0])] : c.category),
        datasets: tiers.map((t) => ({ label: `${t} · ${r.tiers[t - 1].label}`, data: rows.map((c) => seg(c, t)), backgroundColor: tierColor(t), barPercentage: 0.75 })),
      },
      plugins: [barEnds],
      options: {
        indexAxis: "y",
        layout: { padding: { right: endPad } },
        // Chart.js caps the label column and clips longer labels, so size it to the widest line.
        scales: { x: { stacked: true, ticks: { callback: (v) => usd(v), maxRotation: 0 }, grid: { color: css("--grid") } }, y: { stacked: true, grid: { display: false }, afterFit: (sc) => { sc.width = Math.max(sc.width, labelWidth); } } },
        interaction: { mode: "index", axis: "y", intersect: false },
        plugins: { legend: { position: "bottom", labels: { filter: (l) => rows.some((c) => Math.abs(seg(c, l.datasetIndex + 1)) >= 1) } }, tooltip: {
          filter: (c) => Math.abs(c.raw) >= 1,
          callbacks: {
            title: (items) => rows[items[0].dataIndex].category,
            label: (c) => ` ${c.dataset.label}: ${usd(c.raw)}`,
            afterBody: (items) => {
              const x = rows[items[0].dataIndex];
              return [` ${money(x.first)} → ${money(x.last)} a month, ${usd(x.change)} (${sgn(x.pct)})`, ` ${pct(x.lockin_pct)} of it on High/Critical services`,
                ...(x.drivers || []).map((d) => ` ${d.display}: ${usd(d.change)}${d.products?.length ? ` (${d.products.join(", ")})` : ""}`)];
            },
          },
        } },
      },
    });
    $("#growthTable").innerHTML = `<thead><tr><th>Product type</th><th class="num-cell">${esc(month(g.first_month))}</th><th class="num-cell">${esc(month(g.last_month))}</th><th class="num-cell">Change</th>${annual ? `<th class="num-cell">Per year</th>` : ""}<th class="num-cell" title="Share of this product type's spend on High or Critical services">Lock-in</th></tr></thead><tbody>` +
      g.by_category.map((c) => `<tr><td>${esc(c.category)}${c.services?.length ? `<div class="hint">${esc(c.services.slice(0, 4).join(", "))}${c.services.length > 4 ? ` +${c.services.length - 4} more` : ""}</div>` : ""}</td><td class="num-cell">${money(c.first)}</td><td class="num-cell">${money(c.last)}</td><td class="num-cell">${sgn(c.pct)}</td>${annual ? `<td class="num-cell">${perYear(c.annualised_pct)}</td>` : ""}<td class="num-cell">${pct(c.lockin_pct)}</td></tr>`).join("") +
      `<tr class="total"><td><strong>Total</strong></td><td class="num-cell">${money(g.total.first)}</td><td class="num-cell">${money(g.total.last)}</td><td class="num-cell"><strong>${sgn(g.total.pct)}</strong></td>${annual ? `<td class="num-cell">${perYear(g.total.annualised_pct)}</td>` : ""}<td></td></tr></tbody>`;
    $("#growthNote").textContent = annual
      ? "Per year = the first-to-last-month change annualised. Amortised spend: Savings Plans and RIs are spread over the months they cover."
      : `Only ${g.months} months of history, so no annual rate is shown: a short window makes it misleading. Scan 12 months for a reliable trend.`;
  }

  function renderBreadth(r) {
    const s = r.summary, rows = s.accounts_by_rating || [];
    chart("chBreadth", {
      type: "bar",
      data: {
        labels: ["Accounts", "Spend"],
        datasets: rows.map((b) => ({ label: b.rating, data: [b.pct_accounts, b.pct_spend], raw: b, backgroundColor: tierColor(RATING_TIER[b.rating]), borderColor: css("--surface"), borderWidth: 1, barPercentage: 0.7 })),
      },
      options: {
        indexAxis: "y",
        scales: { x: { stacked: true, max: 100, ticks: { callback: (v) => `${v}%` }, grid: { color: css("--grid") } }, y: { stacked: true, grid: { display: false } } },
        plugins: { legend: { position: "bottom" }, tooltip: { callbacks: { label: (c) => {
          const b = c.dataset.raw;
          return c.dataIndex === 0 ? ` ${b.rating}: ${plural(b.accounts, "account")} · ${pct(b.pct_accounts, 1)}` : ` ${b.rating}: ${money(b.monthly_spend)}/month · ${pct(b.pct_spend, 1)}`;
        } } } },
      },
    });
    $("#ratingTable").innerHTML = `<thead><tr><th>Rating</th><th class="num-cell">Accounts</th><th class="num-cell">Share</th><th class="num-cell">Per month</th><th class="num-cell">Spend share</th></tr></thead><tbody>` +
      rows.map((b) => `<tr><td><span class="swatch" style="background:${tierColor(RATING_TIER[b.rating])}"></span>${esc(b.rating)}</td><td class="num-cell">${num(b.accounts)}</td><td class="num-cell">${pct(b.pct_accounts, 1)}</td><td class="num-cell">${money(b.monthly_spend)}</td><td class="num-cell">${pct(b.pct_spend, 1)}</td></tr>`).join("") +
      `<tr class="total"><td class="nowrap"><strong>Portable</strong> (Low + Moderate)</td><td class="num-cell"><strong>${num(s.portable_accounts)}</strong></td><td class="num-cell">${s.accounts_rated ? pct(100 * s.portable_accounts / s.accounts_rated, 1) : EMPTY}</td><td></td><td></td></tr></tbody>`;
    $("#weightingNote").textContent = `OU score weighting: ${s.weighting_label}. ` + ({
      spend: "Each account counts in proportion to its spend, so a small high-risk account adds little.",
      equal: "Every account with spend counts the same, whatever its size.",
      balanced: "A blend: bigger accounts count for more, but no single account dominates.",
    })[s.weighting] + " It sets bubble sizes and contributions; change it in the bar at the top.";
  }

  function renderAccounts(r) {
    renderBreadth(r);
    const accts = r.accounts.filter((a) => a.monthly_spend > 0 && a.score != null);
    const maxC = Math.max(...accts.map((a) => a.contribution), 0.01);
    chart("chAccounts", {
      type: "bubble",
      data: {
        datasets: [{
          label: "Accounts",
          data: accts.map((a) => ({ x: a.monthly_spend, y: a.score, r: 5 + 22 * Math.sqrt(a.contribution / maxC), a })),
          backgroundColor: accts.map((a) => tierColor(RATING_TIER[a.rating]) + "cc"),
          borderColor: css("--surface"), borderWidth: 2, hoverBorderWidth: 2,
        }],
      },
      options: {
        layout: { padding: 12 },
        scales: {
          x: { type: "logarithmic", title: { display: true, text: "Monthly spend (USD, log scale)" }, ticks: { maxRotation: 0, autoSkip: false, callback: (v) => ([1, 10, 100, 1e3, 1e4, 1e5, 1e6].includes(v) ? money(v) : "") }, grid: { color: (c) => ([1, 10, 100, 1e3, 1e4, 1e5, 1e6].includes(c.tick?.value) ? css("--grid") : "transparent") } },
          y: { min: 0, max: 100, title: { display: true, text: "Inherent exit-risk score" }, grid: { color: css("--grid") } },
        },
        plugins: {
          legend: { display: false },
          tooltip: { callbacks: {
            title: (items) => items[0].raw.a.name,
            label: (c) => {
              const a = c.raw.a;
              return [` Risk ${a.score} (${a.rating}) · ${money(a.monthly_spend)}/month`, ` Weight ${pct(a.weight * 100, 1)} · contributes ${a.contribution.toFixed(1)} pts`,
                a.top_lockin.length ? ` Lock-in: ${a.top_lockin.map((s) => s.service).join(", ")}` : " No High/Critical services"];
            },
          } },
        },
      },
      plugins: [{
        id: "labels",
        afterDatasetsDraw(ch) {
          // Direct-label only the accounts that matter: the top five by spend at risk.
          const ctx = ch.ctx, meta = ch.getDatasetMeta(0);
          const top = [...accts].sort((a, b) => b.spend_at_risk - a.spend_at_risk).slice(0, 5).map((a) => a.id);
          ctx.save();
          ctx.font = `600 11px ${css("--font")}`;
          ctx.fillStyle = css("--ink");
          ctx.strokeStyle = css("--surface");
          ctx.lineWidth = 3;
          const placed = []; // label boxes already drawn: nudge new ones down until they do not overlap
          meta.data.map((pt, i) => ({ pt, a: accts[i] })).filter((o) => top.includes(o.a.id)).sort((p, q) => p.pt.y - q.pt.y).forEach(({ pt, a }) => {
            const rad = pt.options.radius || 6;
            const w = ctx.measureText(a.name).width;
            const right = pt.x > ch.chartArea.right - 160;
            const x0 = right ? pt.x - rad - 6 - w : pt.x + rad + 6;
            let y = pt.y + 4;
            while (placed.some((b) => x0 < b.x + b.w && x0 + w > b.x && Math.abs(y - b.y) < 14)) y += 14;
            placed.push({ x: x0, y, w });
            ctx.textAlign = "left";
            ctx.strokeText(a.name, x0, y);
            ctx.fillText(a.name, x0, y);
          });
          ctx.restore();
        },
      }, {
        id: "bands",
        beforeDatasetsDraw(ch) {
          const { ctx, chartArea: ca, scales: { y } } = ch;
          ctx.save();
          ctx.strokeStyle = css("--axis");
          ctx.lineWidth = 1;
          const yy = y.getPixelForValue(55);
          ctx.beginPath(); ctx.moveTo(ca.left, yy); ctx.lineTo(ca.right, yy); ctx.stroke();
          ctx.fillStyle = css("--muted");
          ctx.font = `11px ${css("--font")}`;
          ctx.fillText("High risk ↑", ca.left + 6, yy - 6);
          ctx.restore();
        },
      }],
    });

    renderAccountTable(r, Math.max(...accts.map((a) => a.spend_at_risk), 0.01));
    renderOwners(r);
  }

  function renderOwners(r) {
    const o = r.resilience?.owners;
    $("#ownersCard").hidden = !o;
    if (!o) return;
    const lead = $("#ownersLead"), rows = o.by_executive;
    $("#ownersTable").hidden = true;
    if (!o.tagged_accounts) {
      lead.textContent = "No account has an owner or executive tag, so the report cannot say who to talk to about each account.";
      $("#ownersNote").textContent = "Tag accounts in AWS Organizations with Owner and Executive (or Account holder, Team, Linked executive) and scan again.";
      return;
    }
    if (o.single_owner && o.tagged_accounts === o.accounts_with_spend) {
      lead.textContent = `All ${plural(o.accounts_with_spend, "account")} are owned by ${o.single_owner}` +
        (o.single_executive && o.single_executive !== o.single_owner ? `, executive ${o.single_executive}.` : ".");
      $("#ownersNote").textContent = "";
      return;
    }
    const top = rows[0];
    lead.textContent = rows.length === 1 ? `Every tagged account reports to ${top.name}.`
      : `${top.name} carries the most spend at risk: ${money(top.spend_at_risk)} a month across ${plural(top.accounts, "account")}.`;
    $("#ownersTable").hidden = false;
    $("#ownersTable").innerHTML = `<thead><tr><th>Executive or owner</th><th class="num-cell">Accounts</th><th class="num-cell">Per month</th><th class="num-cell" title="Spend x risk / 100">Spend at risk / month</th><th class="num-cell">High/Critical accounts</th><th>Account owners</th></tr></thead><tbody>` +
      rows.slice(0, PRINT ? 12 : 20).map((g) => `<tr><td><strong>${esc(g.name)}</strong></td><td class="num-cell">${num(g.accounts)}</td><td class="num-cell">${money(g.monthly_spend)}</td><td class="num-cell">${money(g.spend_at_risk)}</td><td class="num-cell">${num(g.high_risk_accounts)}</td>
        <td class="small">${esc(g.owners.slice(0, 3).join(", "))}${g.owners.length > 3 ? ` +${g.owners.length - 3} more` : ""}</td></tr>`).join("") + "</tbody>";
    const untagged = o.accounts_with_spend - o.tagged_accounts;
    $("#ownersNote").textContent = `${plural(o.tagged_accounts, "account")} of ${num(o.accounts_with_spend)} with spend carry an owner or executive tag.` +
      (untagged ? ` ${plural(untagged, "account")} (${money(o.untagged_monthly)} a month) have none and are left out of this table.` : "");
  }

  // Distinct hues for the most common lock-in services (not the green-to-red risk scale).
  const LOCKIN_COLORS = ["#2f6fdf", "#e07b00", "#8a4fd8", "#0f9b8e", "#d63f8c", "#7a8a00", "#a0522d", "#0096c7"];

  function renderAccountTable(r, maxC) {
    // Display filter only: scores, charts and totals still count every account.
    const min = RATING_TIER[$("#fMinRating").value] || 0;
    const all = r.accounts.filter((a) => !min || (a.score != null && RATING_TIER[a.rating] >= min));
    const hidden = r.accounts.length - all.length;
    const limit = state.showAllAccounts ? all.length : PRINT ? 25 : ACCOUNT_ROWS;
    const shown = all.slice(0, limit);
    // Only show the OU path when accounts sit in different OUs; otherwise it repeats on every row.
    const multiOu = new Set(all.map((a) => a.ou_path)).size > 1;
    // Likewise the owner: when one person owns every account, the owners card says it once.
    const perOwner = !r.resilience?.owners?.single_owner;
    // Colour the most common lock-in services so repeats stand out down the column.
    const freq = {};
    all.forEach((a) => a.top_lockin.forEach((s) => { freq[s.service] = (freq[s.service] || 0) + 1; }));
    const common = Object.entries(freq).filter(([, n]) => n > 1).sort((x, y) => y[1] - x[1]).slice(0, LOCKIN_COLORS.length);
    const hue = Object.fromEntries(common.map(([svc], i) => [svc, LOCKIN_COLORS[i]]));
    const lockChip = (svc, n) => `<span class="chip${hue[svc] ? " lc" : ""}"${hue[svc] ? ` style="--lc:${hue[svc]}" title="Main lock-in in ${plural(freq[svc], "account")}"` : ""}>${esc(svc)}${n ? ` <b>${n}</b>` : ""}</span>`;
    $("#lockinLegend").hidden = !common.length;
    $("#lockinLegend").innerHTML = common.length ? `<span class="muted small">Most common lock-in:</span> ${common.map(([svc, n]) => lockChip(svc, n)).join("")}` : "";
    const rows = shown.map((a, i) => `<tr>
      <td class="num-cell muted">${i + 1}</td>
      <td class="acct"><strong>${esc(a.name)}</strong>${a.critical ? ` <span class="chip crit" title="${a.critical_source === "tag" ? "Criticality tag on the account" : "Matches a critical name in section 6"}">Critical</span>` : ""}<div class="hint">${esc(a.id)}${a.channel ? ` · ${esc(a.channel)}` : ""}${multiOu ? ` · ${esc(a.ou_path)}` : ""}${perOwner && a.owner ? ` · Owner: ${esc(a.owner)}` : ""}</div></td>
      <td class="num-cell">${money(a.monthly_spend)}</td>
      <td class="risk">${a.score == null ? EMPTY : `<span class="tier-pill" style="--dot:${tierColor(RATING_TIER[a.rating])}">${esc(a.rating)} · ${Math.round(a.score)}</span><div class="hint">${pct(a.high_risk_pct)} High/Crit spend</div>`}</td>
      <td><div class="contrib"><div class="bar"><i style="width:${(100 * a.spend_at_risk / maxC).toFixed(1)}%"></i></div><span class="num-cell">${money(a.spend_at_risk)}</span></div></td>
      <td><div class="chips">${a.top_lockin.map((s) => lockChip(s.service)).join("") || '<span class="hint">none</span>'}</div></td>
      <td class="num-cell">${num(a.effort_weeks / 4.33, 1)}${a.portability == null ? "" : `<div class="hint" title="Technical portability, 0-100: 100 is easy to move">portability ${Math.round(a.portability)}</div>`}</td>
    </tr>`).join("");
    $("#accountTable").innerHTML = `<thead><tr><th class="num-cell">#</th><th>Account</th><th class="num-cell">Per month</th><th title="Exit-risk rating and score (0-100); beneath, the share of the account's spend on High or Critical services">Risk</th><th title="Spend x risk / 100: monthly spend that is hard to move. The ranking sorts by this.">Spend at risk / month</th><th>Main lock-in</th><th class="num-cell" title="Estimated engineering effort to move this account">Person-months</th></tr></thead><tbody>${rows}</tbody>`;
    const more = all.length - shown.length;
    const hiddenNote = hidden ? ` ${plural(hidden, "lower-risk account")} not listed (still counted in the scores).` : "";
    $("#acctMoreNote").textContent = (more > 0 ? `Top ${shown.length} of ${plural(all.length, "account")} by spend at risk.${PRINT ? " The JSON export lists every account." : ""}` : `${plural(all.length, "account")}.`) + hiddenNote;
    $("#btnAcctMore").hidden = all.length <= ACCOUNT_ROWS || PRINT;
    $("#btnAcctMore").textContent = state.showAllAccounts ? `Show top ${ACCOUNT_ROWS} only` : `Show all ${num(all.length)} accounts`;
  }

  function renderServices(r) {
    const top = r.services.slice(0, 15);
    chart("chServices", {
      type: "bar",
      data: {
        labels: top.map((s) => s.display),
        datasets: [{ label: "USD / month", data: top.map((s) => s.monthly_spend), backgroundColor: top.map((s) => tierColor(s.tier)), borderRadius: 4, borderSkipped: "start", barPercentage: 0.75, categoryPercentage: 0.9 }],
      },
      options: {
        indexAxis: "y",
        scales: { x: { ticks: { callback: (v) => money(v) }, grid: { color: css("--grid") }, border: { display: false } }, y: { grid: { display: false } } },
        plugins: {
          legend: { display: false },
          tooltip: { callbacks: { label: (c) => ` ${money(c.raw)}/month · Tier ${top[c.dataIndex].tier} ${top[c.dataIndex].tier_label} · ${plural(top[c.dataIndex].accounts, "account")}` } },
        },
      },
    });
    const lock = r.services.filter((s) => s.tier >= 4);
    $("#chServices").parentElement.style.height = `${Math.min(760, Math.max(420, 54 * lock.length + 40))}px`;
    const g = r.growth || {};
    const hasChange = lock.some((s) => s.change != null);
    const chg = (s) => s.change == null ? EMPTY : `${s.change > 0 ? "+" : s.change < 0 ? "−" : ""}${money(Math.abs(s.change))}${s.change_pct != null ? `<div class="hint">${s.change_pct > 0 ? "+" : ""}${num(s.change_pct, 0)}%</div>` : ""}`;
    $("#lockinTable").innerHTML = `<thead><tr><th>Service</th><th>Tier</th><th class="num-cell">Per month</th><th class="num-cell">Share</th><th class="num-cell">Accounts</th>${hasChange ? `<th class="num-cell" title="Monthly spend in ${esc(month(g.last_month))} minus ${esc(month(g.first_month))}">Change</th>` : ""}</tr></thead><tbody>` +
      (lock.map((s) => `<tr><td><strong>${esc(s.display)}</strong><div class="hint">${esc(s.category)}</div></td><td><span class="tier-pill" style="--dot:${tierColor(s.tier)}">${s.tier} · ${esc(s.tier_label)}</span></td><td class="num-cell">${money(s.monthly_spend)}</td><td class="num-cell">${pct(s.pct, 1)}</td><td class="num-cell">${s.accounts}</td>${hasChange ? `<td class="num-cell">${chg(s)}</td>` : ""}</tr>`).join("")
        || `<tr><td colspan="6" class="hint">No High or Critical services in scope.</td></tr>`) + "</tbody>";
    const prods = r.services.flatMap((s) => (s.products || []).map((p) => ({ ...p, billed: s.display, tier: s.tier }))).sort((a, b) => b.monthly_spend - a.monthly_spend).slice(0, 12);
    $("#mktCard").hidden = !prods.length;
    if (prods.length) {
      const pc = prods.some((p) => p.change != null);
      $("#mktTable").innerHTML = `<thead><tr><th>Product</th><th>Billed as</th><th class="num-cell">Per month</th><th class="num-cell">Accounts</th>${pc ? `<th class="num-cell">Change</th>` : ""}</tr></thead><tbody>` +
        prods.map((p) => `<tr><td>${esc(p.name)}</td><td><span class="tier-pill" style="--dot:${tierColor(p.tier)}">${esc(p.billed)}</span></td><td class="num-cell">${money(p.monthly_spend)}</td><td class="num-cell">${p.accounts}</td>${pc ? `<td class="num-cell">${chg(p)}</td>` : ""}</tr>`).join("") + "</tbody>";
    }
  }

  // "about 60% engineering, the rest parallel running"; a data-centre exit also names hardware and facility.
  function costSplit(e) {
    const pct = (v) => Math.round(100 * v / Math.max(e.cost.total, 1));
    const hw = e.datacenter ? `, ${pct(e.cost.hardware + e.cost.facility)}% hardware and facility` : "";
    return `about ${pct(e.cost.labour)}% engineering${hw}, the rest parallel running and the target platform`;
  }

  function renderEstimate(r) {
    const e = r.estimate;
    $("#estEmpty").hidden = !e.empty;
    $("#estBody").hidden = !!e.empty;
    const prov = e.provisional;
    $("#qStatus").innerHTML = prov
      ? `<span class="prov-tag">Provisional</span> Using default answers. Change any answer, or confirm these, to estimate for your organisation.`
      : `<span class="ok-tag">✓ Your answers</span> The estimate uses the answers below.`;
    $("#estTiles").innerHTML = e.empty ? "" : [
      tile("Exit cost (one-off)", e.ranges.cost, `${e.ranges.pct_of_annual_spend ? `${e.ranges.pct_of_annual_spend} of a year's AWS spend · ` : ""}${costSplit(e)}`, prov),
      tile("Exit window (time to leave AWS)", e.ranges.duration, `bound by ${e.duration.constrained_by}`, prov),
      tile("Engineering effort", e.ranges.effort, `${plural(e.effort.material_accounts, "material account")}${e.effort.data_tb ? ` · ${tb(e.effort.data_tb)} of data` : ""} · ${{ quick: "wide range: billing data only", inventory: "range from resource counts", dependency: "narrower range: integrations counted" }[e.range_factors?.scan_depth] || ""}`, prov),
    ].join("");

    const WPM = 4.33; // weeks per month
    const total = Math.max(...e.waves.map((w) => w.start + w.weeks), 1);
    const totalMonths = total / WPM;
    const waveColor = (w) => (w.tiers.length ? tierColor(Math.max(...w.tiers)) : css("--ink-2"));
    const stepM = [1, 3, 6, 12, 24].find((st) => totalMonths / st <= 6) || 36; // at most ~6 ticks, so labels never collide
    const ticks = [];
    for (let mo = 0; mo <= totalMonths + 0.01; mo += stepM) ticks.push(mo);
    const dur = (wk) => `~${wk < 9 ? plural(Math.round(wk), "week") : plural(Math.round(wk / WPM), "month")}`;
    const tickLabel = (mo) => (mo === 0 ? "Start" : stepM >= 12 ? `Year ${mo / 12}` : `Month ${mo}`);
    $("#gantt").innerHTML = e.waves.map((w) => `<div class="g-row"><div>${esc(w.name)}<div class="hint">${dur(w.weeks)}</div></div>
      <div class="g-track" title="months ${num(w.start / WPM)} to ${num((w.start + w.weeks) / WPM)}"><div class="g-bar" style="left:${(100 * w.start / total).toFixed(2)}%;width:${Math.max(0.8, 100 * w.weeks / total).toFixed(2)}%;background:${waveColor(w)}"></div></div></div>`).join("") +
      `<div class="g-axis"><div></div><div class="g-ticks">${ticks.map((t, i) => `<span class="${i === 0 ? "first" : ""}" style="left:${(100 * t * WPM / total).toFixed(2)}%">${tickLabel(t)}</span>`).join("")}</div></div>`;

    const parts = [["Landing zone", e.effort.landing_zone_weeks], ["Tier 1 and 2 workloads", e.effort.by_tier[1] + e.effort.by_tier[2]], ["Tier 3 workloads", e.effort.by_tier[3]],
      ["Tier 4 and 5 workloads", e.effort.by_tier[4] + e.effort.by_tier[5]], ["Data migration", e.effort.data_weeks || 0], ["Account overhead", e.effort.account_weeks * e.factors.combined], ["Programme mgmt", e.effort.pmo_weeks], ["Contingency", e.effort.contingency_weeks]];
    const pc = [css("--ink-2"), tierColor(1), tierColor(3), tierColor(5), css("--tone-fact"), css("--t2"), css("--muted"), css("--axis")];
    chart("chEffort", {
      type: "bar",
      data: { labels: parts.map((p) => p[0]), datasets: [{ label: "Person-months", data: parts.map((p) => Math.round(p[1] / WPM)), backgroundColor: pc, borderRadius: 4, borderSkipped: "start", barPercentage: 0.7 }] },
      options: { indexAxis: "y", scales: { x: { grid: { color: css("--grid") }, border: { display: false } }, y: { grid: { display: false } } },
        plugins: { legend: { display: false }, tooltip: { callbacks: { label: (c) => ` ${num(c.raw)} person-months` } } } },
    });

    const q = e.inputs, o = state.options;
    const ans = [["Standard CI/CD pipeline", o.cicd[q.cicd]], ["Terraform / IaC", o.iac[q.iac]], ["Core cloud team", `${q.cloud_team_size} people at ${q.cloud_team_allocation_pct}%`],
      ["Application engineers", `${q.app_engineers_fte} FTE`], ["Target", o.target[q.target]],
      ...(e.datacenter ? [["Data centre", o.dc_facility[q.dc_facility]], ["Disaster-recovery site", q.dc_dr_site ? "Yes, a second site" : "No"]] : []),
      ["Blended day rate", `${num(q.day_rate)} ${q.currency}`],
      ["Contingency", `${q.contingency_pct}%`], ["Parallel running", `${q.parallel_run_months} months`], ["Regulated", q.regulated ? "Yes" : "No"],
      ["AI coding agents", q.ai_agents ? `Yes, about ${num(e.effort.agentic_saved_weeks / 4.33, 0)} person-months less work` : "Not used"],
      ["Left out", r.summary.excluded_services.length ? `${r.summary.excluded_services.map((s) => s.display).join(", ")} (${money(r.summary.excluded_services_monthly)}/mo)` : "Nothing"]];
    $("#answers").innerHTML = ans.map(([k, v]) => `<div><dt>${esc(k)}</dt><dd>${esc(v)}</dd></div>`).join("");
    $("#assumptions").innerHTML = e.assumptions.map((a) => `<li>${esc(a)}</li>`).join("");
  }

  // ------------------------------------------------------------------ resilience
  const tb = (v) => (!v ? EMPTY : v >= 1000 ? `${num(v / 1024, 1)} PB` : `${num(v, v < 10 ? 1 : 0)} TB`);
  const days = (d) => (d < 1 ? "under a day" : d < 120 ? `${Math.round(d)} days` : `${num(d / 30.4, 0)} months`);

  function splitList(rows) {
    // rows: [{label, pct, color, note}]: one bar per row, so it reads in print and on a phone.
    return rows.map((x) => `<div class="split-row"><div class="split-label"><span>${esc(x.label)}</span><span class="num-cell">${pct(x.pct)}</span></div>
      <div class="bar"><i style="width:${Math.min(100, x.pct).toFixed(1)}%;background:${x.color}"></i></div>${x.note ? `<div class="hint">${esc(x.note)}</div>` : ""}</div>`).join("");
  }

  function renderResilience(r) {
    const s = r.resilience, c = s.criticality, d = s.data, k = s.concentration, st = s.stressed_exit;
    const crit = c.critical_accounts > 0;
    $("#resTagNote").textContent = !c.tags_read
      ? "Account tags were not read in this scan (older scan, or organizations:ListTagsForResource not granted). Name the critical accounts below."
      : c.by_tag
        ? `${plural(c.by_tag, "account")} tagged critical in AWS Organizations (a Criticality or Tier tag of Tier 1, Critical, Mission critical or similar).`
        : `${plural(c.tagged_accounts, "account")} carry tags, but none marks criticality. Add Criticality = Tier1, or name the critical accounts below.`;
    const rf = $("#resForm");
    answerStrip("#resAnswers", [
      ["Critical accounts", c.by_tag ? `${plural(c.by_tag, "account")} tagged${rf.critical_accounts.value.trim() ? `, plus names containing ${rf.critical_accounts.value.trim()}` : ""}` : rf.critical_accounts.value.trim() ? `Names containing ${rf.critical_accounts.value.trim()}` : "None marked"],
      ["Direct Connect today", linksToday(d.links_today)],
      ["Carrier cost per new link", d.migration_links?.circuit_monthly ? `${money(d.migration_links.circuit_monthly)} a month` : "Not entered"],
    ]);
    const basis = crit ? "critical spend" : "in-scope spend";
    const none = st.buckets.find((b) => b.key === "none");
    const tiles = [
      tile("Critical accounts", crit ? num(c.critical_accounts) : "None marked", crit ? `${pct(c.pct_spend)} of spend · ${money(c.monthly_spend * 12)} a year` : "Figures below cover all in-scope accounts"),
      k.available ? tile("Correlated failure", `${k.level} · ${k.score}`, `${pct(k.pct)} of ${basis} in ${k.region_name}`) : tile("Correlated failure", EMPTY, k.reason),
      tile("No rapid exit", pct(none.pct), `of ${basis} is on AWS-only services`),
    ];
    if (d.available && !d.empty) {
      const o = d.migration_links.options;
      tiles.push(tile("Data to move", tb(d.move_tb), `${days(o.at(-1).days).replace(/ days$/, days(o[0].days).endsWith(" days") ? "" : " days")} to ${days(o[0].days)} on ${o[0].links} to ${o.at(-1).links} new ${d.migration_links.link_gbps} Gbps links`));
    }
    $("#resTiles").innerHTML = tiles.join("");

    // Correlated failure.
    if (k.available) {
      $("#resConcNote").textContent = `Share of ${basis} by region${crit ? ` (${plural(c.critical_accounts, "critical account")})` : ""}. One regional event takes out everything in the top bar at once.${k.global_pct ? ` A further ${pct(k.global_pct, 1)} is global services (IAM, Route 53, CloudFront), which share a control plane across regions.` : ""}`;
      $("#resRegions").innerHTML = splitList(k.regions.slice(0, 5).map((x, i) => ({ label: x.name, pct: x.pct, color: i ? css("--ink-2") : tierColor(k.level === "High" ? 5 : k.level === "Elevated" ? 4 : 3) })));
      const shared = new Set(k.no_anti_affinity.flatMap((x) => x.channels));
      $("#resChannels").innerHTML = k.channels.length
        ? `<thead><tr><th>Channel</th><th>Runs mainly in</th><th>Isolated from other channels?</th></tr></thead><tbody>${k.channels.map((ch) => `<tr><td>${esc(ch.channel)}</td><td>${esc(ch.name)} <span class="hint">${pct(ch.pct)}</span></td><td>${shared.has(ch.channel) ? '<span class="sev" style="--dot:var(--t5)">No</span>' : '<span class="sev" style="--dot:var(--t1)">Yes</span>'}</td></tr>`).join("")}</tbody>`
        : `<tbody><tr><td class="hint">No Channel tag on the accounts. Tag accounts with Channel (cards, mobile app, payments) to test whether tier 1 channels are isolated from each other.</td></tr></tbody>`;
    } else {
      $("#resConcNote").textContent = k.reason;
      $("#resRegions").innerHTML = "";
      $("#resChannels").innerHTML = "";
    }

    // Stressed exit.
    $("#resStressNote").textContent = `If AWS stopped serving you with little notice, how fast could ${basis} (${money(st.monthly_spend * 12)} a year) move?`;
    const bColor = { weeks: tierColor(1), months: tierColor(3), none: tierColor(5) };
    $("#resStress").innerHTML = splitList(st.buckets.map((b) => ({ label: b.label, pct: b.pct, color: bColor[b.key], note: b.note })));
    $("#resStuck").innerHTML = st.accounts.length
      ? `<thead><tr><th>${crit ? "Critical account" : "Account"} with no rapid exit</th><th class="num-cell">Per month</th><th class="num-cell">AWS-only</th></tr></thead><tbody>${st.accounts.slice(0, 8).map((a) => `<tr><td><strong>${esc(a.name)}</strong><div class="hint">${esc(a.services.join(", "))}</div></td><td class="num-cell">${money(a.monthly_spend)}</td><td class="num-cell">${pct(a.pct)}</td></tr>`).join("")}</tbody>`
      : `<tbody><tr><td class="hint">No ${crit ? "critical " : ""}account has a quarter or more of its spend on AWS-only services.</td></tr></tbody>`;

    // Data held.
    $("#resLinksCard").hidden = !d.available || d.empty;
    if (!d.available || d.empty) {
      $("#resDataNote").textContent = d.reason || "No storage usage recorded for these accounts.";
      for (const id of ["#resDataPoints", "#resDataServices", "#resDataAccounts"]) $(id).innerHTML = "";
      return;
    }
    renderMigrationLinks(d);
    $("#resDataNote").textContent = `Average data stored last month, from Cost Explorer storage usage (GB-months); no data is read. ${tb(d.total_tb)} in all: ${tb(d.live_tb)} live, ${tb(d.archive_tb)} archived and ${tb(d.copy_tb)} of snapshots and backups, which are rebuilt at the target rather than moved.`;
    const egress = d.egress_list_usd;
    const points = [
      `${tb(d.move_tb)} (live and archived) has to move; the options for the links that carry it are below.`,
      `Over the internet instead, AWS waives data transfer out for customers leaving AWS if the move finishes within ${d.credit_days} days: that needs about ${num(d.migration_links.credit_gbps, 0)} Gbps of internet capacity for two months. Without that credit, internet egress at list price would be roughly ${money(egress[0])} to ${money(egress[1])}.`,
      ...(crit && d.critical_tb ? [`Critical accounts hold ${tb(d.critical_tb)}: the data a stressed exit would need first.`] : []),
      ...(d.dynamodb_tb ? [`DynamoDB holds ${tb(d.dynamodb_tb)}; the largest account (${d.dynamodb_largest_account}) holds ${tb(d.dynamodb_largest_tb)}. Exports to S3 are not region-limited, but rebuilding in a second region by import from S3 takes ${plural(d.dynamodb_imports_small_region, "import job")} of up to 1 TB each outside us-east-1, us-west-2 and eu-west-1.`] : []),
      ...(d.regions.length ? [`By region: ${d.regions.slice(0, 4).map((x) => `${x.name} ${tb(x.tb)}`).join(", ")}.`] : []),
    ];
    $("#resDataPoints").innerHTML = points.map((x) => `<li>${esc(x)}</li>`).join("");
    const head = (first) => `<thead><tr><th>${first}</th><th class="num-cell">Live</th><th class="num-cell">Archive</th><th class="num-cell">Copies</th></tr></thead>`;
    const cells = (x) => `<td class="num-cell">${tb(x.live_tb)}</td><td class="num-cell">${tb(x.archive_tb)}</td><td class="num-cell">${tb(x.copy_tb)}</td>`;
    $("#resDataServices").innerHTML = head("Service") + `<tbody>${d.services.slice(0, 8).map((x) => `<tr><td>${esc(x.service.replace(/^Amazon |^AWS /, ""))}</td>${cells(x)}</tr>`).join("")}</tbody>`;
    $("#resDataAccounts").innerHTML = head("Account") + `<tbody>${d.accounts.slice(0, 8).map((x) => `<tr><td>${esc(x.name)}${x.critical ? ' <span class="chip crit">Critical</span>' : ""}</td>${cells(x)}</tr>`).join("")}</tbody>`;
  }

  function linksToday(t) {
    if (!t || !t.available) return "Not read in this scan";
    if (!t.count) return "None found";
    return t.ports.map((p) => `${p.count} × ${num(p.gbps, p.gbps < 1 ? 1 : 0)} Gbps${p.kind === "dedicated" ? "" : ` ${p.kind}`}`).join(", ");
  }

  // New Direct Connect links for the copy: cheap, medium and urgent, with time and list cost.
  function renderMigrationLinks(d) {
    const m = d.migration_links, t = d.links_today, o = m.options;
    const today = !t.available
      ? `This scan predates the Direct Connect check; run a new scan to see the links you have today.`
      : t.count
        ? `Today you have ${linksToday(t)} of Direct Connect (${t.ports.map((p) => p.location).join(", ")}), costing ${money(t.monthly_cost)} a month in ports and carrying ${tb(t.out_tb_month)} out last month. Those carry production traffic and stay as they are.`
        : `Cost Explorer shows no Direct Connect ports billed last month.`;
    $("#resLinksNote").textContent = `${today} The migration gets its own new ${m.link_gbps} Gbps links, dedicated to the copy and kept apart from production, so moving ${tb(d.move_tb)} cannot slow customer-facing systems. Time assumes half the line rate is usable.`;
    const carrier = m.circuit_monthly > 0;
    $("#resLinks").innerHTML = `<thead><tr><th>Option</th><th class="num-cell">New links</th><th class="num-cell">Time to copy</th><th class="num-cell">AWS ports</th>${carrier ? '<th class="num-cell">Carrier</th>' : ""}<th class="num-cell">Data out</th><th class="num-cell">Total</th></tr></thead><tbody>${o.map((x) => `<tr><td><strong>${esc(x.label)}</strong><div class="hint">${esc(x.note)}</div></td><td class="num-cell">${x.links} × ${m.link_gbps} Gbps</td><td class="num-cell">${days(x.days)}</td><td class="num-cell">${money(x.port_cost)}</td>${carrier ? `<td class="num-cell">${money(x.circuit_cost)}</td>` : ""}<td class="num-cell">${money(x.transfer_cost)}</td><td class="num-cell"><strong>${money(x.total_cost)}</strong></td></tr>`).join("")}</tbody>`;
    const points = [
      `AWS list prices for ${m.region_name} (price list of ${m.price_date}): $${m.port_hour_usd.toFixed(2)} per ${m.link_gbps} Gbps port-hour, paid for the copy plus ${plural(m.extra_months, "month")} to commission, test and run the final sync; data out over Direct Connect at $${m.dto_per_gb_usd.toFixed(3)} per GB on average, from the regions that hold the data. Data out costs the same whichever option you pick; the links only change how long it takes.`,
      carrier ? `Carrier circuit and cross-connect at ${money(m.circuit_monthly)} per link a month (your answer under Exit model).` : `Not included: your carrier's circuit and the cross-connect at the Direct Connect location. Enter them under Exit model to add them.`,
      `Order early: a new dedicated connection needs a cross-connect at the Direct Connect location and a carrier circuit to your site, which often take weeks to months to deliver.`,
      ...(m.flat_rate_hour_usd && m.dto_per_gb_usd > 0 ? [`AWS's price list also has flat-rate ${m.link_gbps} Gbps ports with no per-GB charge, from $${m.flat_rate_hour_usd.toFixed(2)} an hour in this region. For a one-off copy of this size, ask AWS whether one costs less than paying per GB.`] : []),
      ...(m.assumed || []),
    ];
    $("#resLinksPoints").innerHTML = points.map((x) => `<li>${esc(x)}</li>`).join("");
  }

  // ------------------------------------------------------------------ timing
  const monthYear = (iso) => (iso ? new Date(`${iso.slice(0, 7)}-15`).toLocaleDateString("en-GB", { month: "short", year: "numeric" }) : EMPTY);
  const mrange = (x) => (x[0] === x[1] ? money(x[0]) : `${money(x[0])} to ${money(x[1])}`);

  // The Exit model answers a section uses, shown above its results (the forms live in the dialog).
  function answerStrip(sel, pairs) {
    $(sel).innerHTML = pairs.map(([k, v]) => `<div><dt>${esc(k)}</dt><dd>${esc(v)}</dd></div>`).join("");
  }

  // Commitments are bought in one account and shared, so no account filter applies to them.
  function orgWide(r) {
    const f = r.meta.filter;
    return f.include?.length || f.exclude?.length
      ? ` Savings Plans and reservations cover the whole organisation, even though the report is filtered (${f.description}).`
      : " Savings Plans and reservations cover the whole organisation.";
  }

  function renderTiming(r) {
    const t = r.timing, d = t.deadline, c = t.commitments, e = t.edp;
    const tf = $("#timeForm");
    answerStrip("#timeAnswers", [
      ["Notice period", d.set ? `${d.months} months` : "None"],
      ["EDP ends", tf.edp_end.value ? monthYear(`${tf.edp_end.value}-15`) : "No EDP"],
      ["EDP annual commit", Number(tf.edp_annual_commit.value) > 0 ? money(Number(tf.edp_annual_commit.value)) : EMPTY],
    ]);
    const exitEnd = t.exit_end ? `${monthYear(t.exit_end[0])} to ${monthYear(t.exit_end[1])}` : EMPTY;
    const tiles = [
      tile("Exit finishes", exitEnd, t.duration_range ? `${t.duration_range} if it starts now` : "No spend in scope", t.provisional),
      d.set ? tile("Deadline", d.label, `${d.months}-month notice`, t.provisional)
        : tile("Deadline", "Not set", "Enter a notice period"),
    ];
    if (c.available && !c.empty) tiles.push(tile("Commitments", `${money(c.monthly)}/mo`, `${money(c.remaining)} still to run · last ends ${monthYear(c.last_end)}`));
    if (e.set) tiles.push(tile("EDP", `ends ${monthYear(`${e.end_month}-15`)}`, `${money(e.remaining)} of commit left`));
    $("#timeTiles").innerHTML = tiles.join("");

    const pts = [];
    if (d.set) {
      pts.push(d.status === "fits" ? `The exit fits the ${d.months}-month notice period even at the slow end.`
        : d.status === "at_risk" ? `The ${d.months}-month notice period only fits if the exit runs at the fast end; at the slow end it is ${num(d.short_months, 0)} months over.`
          : d.status === "misses" ? `The exit does not fit the ${d.months}-month notice period: even the fast end runs over, and the slow end is ${num(d.short_months, 0)} months over.`
            : "Set the delivery answers to test the deadline.");
    }
    if (c.available && !c.empty) {
      pts.push(c.stranded_range
        ? `${c.stranded_range.startsWith("up to") ? "Up to " + c.stranded_range.slice(6) : "About " + c.stranded_range} of commitments would be written off: still owed after the exit finishes; ${money(c.monthly_past_exit)}/mo runs past the fastest finish.`
        : `Every Savings Plan and reservation ends before the fastest exit finishes, so a planned exit pays nothing to break them. Leaving in a hurry would still owe ${c.stressed_range}.`);
      if (c.buy_by?.["3yr"]) pts.push(`A new 3-year term bought after ${monthYear(c.buy_by["3yr"])} would outlast the fastest exit; ${c.buy_by["1yr"] ? `1-year terms stay safe until ${monthYear(c.buy_by["1yr"])}` : "buy 1-year terms"}.`);
      else if (c.buy_by?.["1yr"]) pts.push(`3-year terms already outlast the fastest exit; 1-year terms stay safe until ${monthYear(c.buy_by["1yr"])}.`);
    }
    if (e.set) {
      pts.push(e.shortfall_range
        ? `The EDP runs beyond the exit: about ${e.shortfall_range} of commit could go unspent. Negotiate the term or a shortfall clause before signing the next one.`
        : `The EDP ends ${monthYear(`${e.end_month}-15`)}${e.ends_before_exit ? ", before the exit finishes: renew on a shorter term or without a commit" : ""}.`);
    }
    $("#timePoints").innerHTML = pts.length ? pts.map((x) => `<li>${esc(x)}</li>`).join("") : '<li class="hint">Enter a notice period and your EDP to test the timing.</li>';
    renderWriteOff(t, r);

    const undated = c.undated ? ` ${plural(c.undated, "commitment")} (${money(c.undated_monthly)}/mo) came without an end date, so ${c.undated === 1 ? "it is" : "they are"} not in the figures below; check ${c.undated === 1 ? "it" : "them"} in the AWS Billing console.` : "";
    if (!c.available || c.empty) {
      $("#timeNote").textContent = (c.reason || (c.undated ? "No dated Savings Plans or reservations in this scan." : "No active Savings Plans or reservations in this scan.")) + undated;
      $("#timeTable").innerHTML = "";
      return;
    }
    $("#timeNote").textContent = `${plural(c.savings_plans, "Savings Plan")} and ${plural(c.reservations, "reservation")} from Cost Explorer, amortised per month. Written off is what would still be owed between the exit finishing and the commitment ending: paid for, no longer used.${undated}`;
    $("#timeTable").innerHTML = `<thead><tr><th>Commitment</th><th>Term</th><th>Ends</th><th class="num-cell">Per month</th><th class="num-cell">Still to run</th><th class="num-cell">Written off</th></tr></thead><tbody>${c.rows.map((x) => `<tr><td><strong>${esc(x.name)}</strong>${x.utilization_pct != null ? `<div class="hint">${pct(x.utilization_pct)} used</div>` : ""}</td><td>${esc(x.term || EMPTY)}<div class="hint">${esc(x.payment || "")}</div></td><td>${monthYear(x.end)}</td><td class="num-cell">${money(x.monthly)}</td><td class="num-cell">${money(x.remaining)}</td><td class="num-cell">${x.stranded?.[1] ? mrange(x.stranded) : EMPTY}</td></tr>`).join("")}</tbody>`;
  }

  // Commitments by month, and what is written off if the exit finishes in that month. Months after the
  // fastest finish are drawn solid (written off); before it, faded (still in use during the exit).
  function renderWriteOff(t, r) {
    const c = t.commitments, rows = c.by_month || [];
    $("#writeOffCard").hidden = !c.available || c.empty || !rows.length;
    if ($("#writeOffCard").hidden) return;
    const keys = rows.map((x) => x.month);
    const at = (iso) => (iso ? keys.indexOf(iso.slice(0, 7)) : -1);
    const fast = at(t.exit_end?.[0]), slow = at(t.exit_end?.[1]);
    const fastIx = fast < 0 && t.exit_end && t.exit_end[0].slice(0, 7) > keys.at(-1) ? keys.length : fast;
    const fade = (hex, i) => (fastIx >= 0 && i <= fastIx ? `${hex}55` : hex);
    const blue = css("--tone-fact"), purple = css("--tone-est"), red = css("--tone-risk");
    const owed = c.stranded;
    $("#writeOffCap").textContent = (t.exit_end
      ? `The exit finishes between ${monthYear(t.exit_end[0])} and ${monthYear(t.exit_end[1])} (shaded). Bars after the fastest finish are commitments paid for but no longer used: ${owed && owed[1] >= 1000 ? c.stranded_range : "none"} written off. `
      : "") + "The red line is what would be written off if the exit finished at the end of that month." + orgWide(r);
    // The exit window, shaded behind the bars.
    const windowBand = {
      id: "exitWindow",
      beforeDatasetsDraw(ch) {
        if (fast < 0 && slow < 0) return;
        const x = ch.scales.x, a = ch.chartArea, step = x.width / keys.length;
        const x0 = fast >= 0 ? x.getPixelForValue(fast) + step / 2 : a.left;
        const x1 = slow >= 0 ? x.getPixelForValue(slow) + step / 2 : a.right;
        if (x0 >= a.right) return;
        const g = ch.ctx;
        g.save();
        g.fillStyle = `${red}1f`;
        g.fillRect(x0, a.top, Math.min(x1, a.right) - x0, a.bottom - a.top);
        g.fillStyle = css("--ink-2");
        g.font = `600 11px ${css("--font") || "system-ui"}`;
        g.fillText("Exit finishes", x0 + 6, a.top + 14);
        g.restore();
      },
    };
    chart("chWriteOff", {
      type: "bar",
      data: {
        labels: keys.map((m) => month(m, true)),
        datasets: [
          { type: "line", label: "Written off if the exit finishes that month", data: rows.map((x) => x.written_off), yAxisID: "y2", borderColor: red, backgroundColor: red, borderWidth: 2, pointRadius: 0, tension: 0.2, order: 0 },
          { label: "Savings Plans", data: rows.map((x) => x.savings_plans), backgroundColor: rows.map((_, i) => fade(blue, i)), borderRadius: 2, maxBarThickness: 26, order: 1 },
          { label: "Reservations", data: rows.map((x) => x.reservations), backgroundColor: rows.map((_, i) => fade(purple, i)), borderRadius: 2, maxBarThickness: 26, order: 1 },
        ],
      },
      options: {
        scales: {
          x: { stacked: true, grid: { display: false }, ticks: { maxRotation: 0, autoSkipPadding: 10 } },
          y: { stacked: true, title: { display: true, text: "Billed each month" }, ticks: { callback: (v) => money(v) } },
          y2: { position: "right", beginAtZero: true, grid: { display: false }, title: { display: true, text: "Written off" }, ticks: { callback: (v) => money(v) } },
        },
        plugins: {
          legend: { position: "bottom", labels: { generateLabels: (ch) => window.Chart.defaults.plugins.legend.labels.generateLabels(ch).map((l, i) => ({ ...l, fillStyle: [red, blue, purple][i], strokeStyle: [red, blue, purple][i] })) } },
          tooltip: { mode: "index", callbacks: { title: (items) => month(rows[items[0].dataIndex].month), label: (x) => ` ${x.dataset.label}: ${money(x.raw)}` } },
        },
        interaction: { mode: "index", intersect: false },
      },
      plugins: [windowBand],
    });
  }

  // One A4 page for the executive committee, printed on its own (body.onepage).
  function renderOnePager(r) {
    const m = r.meta, s = r.summary, e = r.estimate, x = s.executive, d = r.timing?.deadline;
    $("#opTitle").textContent = m.mode === "demo" ? "Demo organisation (synthetic data)" : m.ou?.path || "Organisation";
    $("#opScope").textContent = [m.filter.description, `${num(s.accounts_in_scope)} accounts`, `${money(s.annual_spend)} a year on AWS`,
      m.scanned_at ? `scanned ${new Date(m.scanned_at).toLocaleDateString("en-GB", { day: "numeric", month: "short", year: "numeric" })}` : ""].filter(Boolean).join(" · ");
    $("#opScore").textContent = s.score_by_spend == null ? EMPTY : Math.round(s.score_by_spend);
    ratingBadge($("#opRating"), s.rating_by_spend, s.score_by_spend == null ? "No spend in scope" : s.rating_by_spend);
    $("#opScoreAcc").textContent = s.score_by_accounts == null ? "" : `By spend · ${Math.round(s.score_by_accounts)} by no. of accounts`;
    $("#opHeadline").textContent = x.headline || x.bottom_line;
    $("#opProv").hidden = !x.provisional;
    $("#opTiles").innerHTML = [
      tile("High/Critical spend", pct(s.high_risk_pct), `${money(s.high_risk_monthly * 12)} a year`),
      tile("High/Critical accounts", s.accounts_rated ? `${num(s.high_risk_accounts)} of ${num(s.accounts_rated)}` : EMPTY, s.accounts_rated ? `${pct(s.high_risk_accounts_spend_pct)} of spend` : ""),
      tile("AWS-only services", num(s.bespoke_services), s.top_lockin_services.slice(0, 3).map((v) => v.display).join(", ") || "none in use"),
      ...(s.measures?.portability?.score == null ? [] : [tile("Technical portability", `${Math.round(s.measures.portability.score)}/100`, `${s.measures.portability.rating} difficulty, by effort`)]),
      ...(e.empty ? [] : [
        tile("Exit cost (one-off)", e.ranges.cost, e.ranges.pct_of_annual_spend ? `${e.ranges.pct_of_annual_spend} of a year's spend` : "", e.provisional),
        tile("Exit window", e.ranges.duration, `bound by ${e.duration.constrained_by}`, e.provisional),
        d?.set && d.status !== "unknown" ? tile("Notice period", d.label, `${d.months}-month notice${d.short_months ? `, ${num(d.short_months, 0)} over` : ""}`, e.provisional)
          : tile("Engineering effort", e.ranges.effort, teamSize(e.team.capacity_fte), e.provisional),
        ...writtenOffTile(x, e.provisional, true),
      ]),
    ].join("");
    // Seven tiles sit in four columns, the last spanning two, so no row is left with one tile.
    const n = $("#opTiles").children.length;
    $("#opTiles").classList.toggle("cols-4", n > 6);
    $("#opTiles").lastElementChild?.classList.toggle("span-2", n === 7);
    $("#opTierBar").innerHTML = r.tiers.map((v) => `<i style="width:${v.pct}%;background:${tierColor(v.tier)}" title="${esc(v.label)}"></i>`).join("");
    $("#opTierLegend").innerHTML = `<span>Spend by exit-risk tier:</span>` + r.tiers.map((v) => `<span><span class="swatch" style="background:${tierColor(v.tier)}"></span>${esc(v.label)} ${pct(v.pct, 0)}</span>`).join("");
    const lead = (i) => `<li><strong>${esc(i.lead)}</strong> ${esc(i.text)}</li>`;
    $("#opRisks").innerHTML = (x.findings_rich || []).slice(0, 3).map(lead).join("");
    $("#opDecisions").innerHTML = (x.actions_rich || []).slice(0, 3).map(lead).join("");
    const top = r.accounts.filter((a) => a.score != null && a.monthly_spend > 0).slice(0, 5);
    const o = r.resilience?.owners;
    const showOwner = !!o?.tagged_accounts && !o.single_owner;
    $("#opAccounts").innerHTML = `<thead><tr><th>Account</th>${showOwner ? "<th>Owner</th>" : ""}<th class="num-cell">Per month</th><th>Risk</th><th class="num-cell">Spend at risk / month</th><th>Main lock-in</th></tr></thead><tbody>` +
      top.map((a) => `<tr><td><strong>${esc(a.name)}</strong></td>${showOwner ? `<td class="nowrap">${esc(a.owner || a.executive || EMPTY)}</td>` : ""}<td class="num-cell">${money(a.monthly_spend)}</td><td><span class="tier-pill" style="--dot:${tierColor(RATING_TIER[a.rating])}">${esc(a.rating)} · ${Math.round(a.score)}</span></td><td class="num-cell">${money(a.spend_at_risk)}</td><td>${esc(a.top_lockin.slice(0, showOwner ? 2 : 3).map((v) => v.service).join(", ") || "none")}</td></tr>`).join("") + "</tbody>";
    renderOnePagerOwners(o);
    $("#opFoot").textContent = `Confidence: ${x.confidence}. ${x.confidence_reasons.join(" ")} Cost and time are ranges for a planning decision, not a delivery quote. Generated ${new Date(m.generated_at).toLocaleDateString("en-GB", { day: "numeric", month: "short", year: "numeric" })} by aws-regulatory-risk-review-framework v${m.tool_version}, scan ${m.scan_id}. The full report has the method, every account and the data gaps.`;
  }

  // The executives to talk to: the top four by spend at risk, and how much spend has no owner tag.
  function renderOnePagerOwners(o) {
    $("#opOwners").hidden = !o;
    if (!o) return;
    const list = $("#opOwnersList"), untagged = o.accounts_with_spend - o.tagged_accounts;
    const gap = untagged ? ` ${plural(untagged, "account")} with spend (${money(o.untagged_monthly)} a month) have no owner tag.` : "";
    list.innerHTML = "";
    if (!o.tagged_accounts) {
      $("#opOwnersLead").textContent = "No account has an owner or executive tag: tag accounts in AWS Organizations so each risk has a named owner.";
      return;
    }
    if (o.single_owner) {
      $("#opOwnersLead").textContent = `${o.single_owner} owns every tagged account.${gap}`;
      return;
    }
    const rows = o.by_executive.slice(0, 4), more = o.by_executive.length - rows.length;
    $("#opOwnersLead").textContent = `${num(o.tagged_accounts)} of ${plural(o.accounts_with_spend, "account")} with spend report to ${plural(o.by_executive.length, "executive or owner", "executives or owners")}${more > 0 ? ` (top ${rows.length} below)` : ""}.` +
      (untagged ? ` ${num(untagged)} (${money(o.untagged_monthly)} a month) have no owner tag.` : "");
    list.innerHTML = rows.map((g) => `<li><strong>${esc(g.name)}</strong> ${money(g.spend_at_risk)}/month at risk <span class="muted">· ${plural(g.accounts, "account")}</span></li>`).join("");
  }

  // ------------------------------------------------------------------ areas of focus
  const FOCUS_LEVEL = { high: 5, medium: 4, low: 2 };
  const PHASES = ["Before mobilisation", "Mobilise", "Wave 1", "Wave 2", "Wave 3", "Cutover"];
  const FOCUS_GROUP = {
    platform: "Decide the target for Critical-tier services",
    critical: "Rehearsed cutover and fallback",
    integrations: "Map and decouple AWS-only integrations",
    data: "Start the bulk data copy",
    lockin: "Re-architect (mostly AWS-only spend)",
    effort: "Dedicated squad, split into workloads",
    evidence: "Dependency scan before committing the plan",
    owner: "Name an accountable owner",
  };
  const phaseChip = (p) => `<span class="chip phase">${esc(p)}</span>`;

  function focusItem(c, who) {
    return `<div class="focus-item" style="--dot:${tierColor(FOCUS_LEVEL[c.level] || 3)}">
      <div class="focus-title"><span class="sev">${esc(c.title)}</span>${phaseChip(c.phase)}${who ? `<span class="hint">${esc(who)}</span>` : ""}</div>
      <div class="focus-detail">${esc(c.detail)}</div>
      <div class="focus-action"><b>How to tackle:</b> ${esc(c.action)}</div>
    </div>`;
  }

  function renderFocus(r) {
    const f = r.focus;
    const sec = $("#sec-focus");
    sec.hidden = !f || (!f.accounts.length && !f.themes.length);
    if (sec.hidden) return;
    const n = f.concern_counts || {};
    $("#focusTiles").innerHTML = [
      tile("Accounts to focus on", num(f.accounts_total), f.accounts.length < f.accounts_total ? `top ${f.accounts.length} shown below` : "all shown below"),
      tile("Their share of the effort", pct(f.effort_pct), `and ${pct(f.spend_pct)} of spend (top ${f.accounts.length})`),
      tile("AWS-only blockers", num(n.platform || 0), "accounts with a Critical-tier service and no like-for-like target"),
      tile("Critical accounts", num(n.critical || 0), n.critical ? "need a rehearsed cutover and fallback" : "none marked: name them under section 6"),
    ].join("");
    $("#focusThemes").innerHTML = f.themes.length ? f.themes.map((t) => focusItem({ ...t, level: "medium" })).join("") : '<p class="hint">No programme-wide themes.</p>';
    // Plan by phase: every concern, grouped, so the project knows what to start first.
    const byPhase = new Map(PHASES.map((p) => [p, []]));
    for (const t of f.themes) byPhase.get(t.phase)?.push(`<strong>${esc(t.title)}</strong>`);
    const groups = new Map();
    for (const a of f.accounts) for (const c of a.concerns) {
      const k = `${c.phase}|${c.key}`;
      if (!groups.has(k)) groups.set(k, { phase: c.phase, label: FOCUS_GROUP[c.key] || c.title, names: [] });
      groups.get(k).names.push(a.name);
    }
    for (const g of groups.values()) byPhase.get(g.phase)?.push(`${esc(g.label)}: ${esc(g.names.join(", "))}`);
    $("#focusPlan").innerHTML = `<thead><tr><th>Phase</th><th>Deal with</th></tr></thead><tbody>${[...byPhase].filter(([, xs]) => xs.length).map(([p, xs]) => `<tr><td>${phaseChip(p)}</td><td>${xs.join("<br>")}</td></tr>`).join("")}</tbody>`;
    $("#focusNote").textContent = f.accounts.length
      ? `Ranked by share of the effort, spend on AWS-only services and the weight of each concern.${f.accounts_total > f.accounts.length ? ` ${plural(f.accounts_total - f.accounts.length, "more account")} also ${f.accounts_total - f.accounts.length === 1 ? "has" : "have"} concerns; filter the report to see them.` : ""}`
      : "No single account stands out: the effort is spread evenly.";
    $("#focusAccounts").innerHTML = f.accounts.map((a, i) => `<article class="card focus-acct">
      <div class="card-head"><h4><span class="rank">${i + 1}</span>${esc(a.name)}${a.critical ? ' <span class="chip crit">Critical</span>' : ""}</h4><span class="chip phase">${esc(a.wave)}</span></div>
      <div class="hint">${esc(a.id)} · ${money(a.monthly_spend)} a month · ${num(a.effort_weeks, 0)} engineer-weeks${a.rating ? ` · ${esc(a.rating)} risk` : ""} · ${a.owner ? `Owner: ${esc(a.owner)}` : "No owner"}</div>
      ${a.concerns.map((c) => focusItem(c)).join("")}
    </article>`).join("");
  }


  // ------------------------------------------------------------------ AI review (optional)
  const range = (p, f) => (Array.isArray(p) && p.length === 2 ? `${f(p[0])} to ${f(p[1])}` : EMPTY);
  const versus = (p, ref) => {
    if (!Array.isArray(p) || !ref) return "";
    const mid = (p[0] + p[1]) / 2, d = Math.round((mid / ref - 1) * 100);
    return Math.abs(d) < 10 ? "close to the model" : `${d > 0 ? "+" : ""}${d}% against the model`;
  };
  const LEVEL_TIER = { Low: 1, Moderate: 3, High: 4, "Very high": 5 };
  const list = (xs) => (xs?.length ? `<ul class="assumptions">${xs.map((x) => `<li>${esc(x)}</li>`).join("")}</ul>` : '<p class="hint">None.</p>');

  function renderAi(r) {
    const el = $("#aiPanel");
    const res = state.ai?.result, run = state.ai?.run;
    $("#aiDot").hidden = !(run?.status === "running" || res);
    $("#aiDot").classList.toggle("running", run?.status === "running");
    $("#focusRulesHead").hidden = !res;
    if (!res && run?.status !== "running") { el.hidden = true; el.innerHTML = ""; return; }
    el.hidden = false;
    if (!res) {
      el.innerHTML = `<h3>AI review running</h3><p class="muted small">${esc(run.stage)}${run.message ? `: ${esc(run.message)}` : ""}. Open <strong>AI review</strong> in the top bar for progress.</p>`;
      return;
    }
    const f = res.final || {}, e = f.estimate || {}, ref = res.model_reference || {};
    const cur = ref.currency || "USD";
    const m = (v) => money(v, cur);
    const sameBasis = res.basis?.filter === r.meta.filter.description;
    const focus = (f.areas_of_focus || []).map((a) => focusItem({
      level: a.priority === "high" ? "high" : "medium", title: a.title, phase: PHASES.includes(a.phase) ? a.phase : "Mobilise",
      detail: a.concern, action: a.how_to_tackle,
    }, (a.account_names || []).join(", "))).join("");
    const accts = (res.accounts || []).slice().sort((a, b) => (LEVEL_TIER[b.entrenchment] || 0) - (LEVEL_TIER[a.entrenchment] || 0));
    const modelWeeks = Object.fromEntries(r.accounts.map((a) => [a.id, a.effort_weeks]));
    el.innerHTML = `
      <div class="card-head"><h3><svg class="ai-icon" viewBox="0 0 24 24" aria-hidden="true"><path d="M12 3l1.8 4.7L18.5 9.5l-4.7 1.8L12 16l-1.8-4.7L5.5 9.5l4.7-1.8z"/></svg>AI review: a second opinion</h3>
        <span class="no-print"><button type="button" class="btn" id="btnAiAgain">Run again</button> <button type="button" class="btn ghost" id="btnAiRemove">Remove</button></span></div>
      <p class="ai-cost">${res.cost_usd != null ? `AI cost of this review: about <strong>$${res.cost_usd < 10 ? res.cost_usd.toFixed(2) : num(res.cost_usd)}</strong>` : "AI cost of this review: price not known for this model"}<span class="hint"> · ${num((res.usage?.input_tokens || 0) / 1000)}k tokens in at $${res.price ? num(res.price.input, 2) : "?"}/M, ${num((res.usage?.output_tokens || 0) / 1000)}k out at $${res.price ? num(res.price.output, 2) : "?"}/M${res.price ? ` (${esc(res.price.source)})` : ""}; negotiated rates, caching and batch discounts not included</span></p>
      <p class="hint">${esc(res.provider_label)} · ${esc(res.model)} · ${esc(fmtWhen(res.created_at))} · ${plural(res.accounts_analysed, "account")} analysed in three passes${res.masked ? " · names hidden from the model" : ""} · ${num(res.usage?.calls)} calls, ${num((res.usage?.input_tokens || 0) / 1000)}k tokens in, ${num((res.usage?.output_tokens || 0) / 1000)}k out, ${num(res.seconds / 60, 0)} min</p>
      ${sameBasis ? "" : `<p class="warn-text">Run on a different filter (${esc(res.basis?.filter || "unknown")}); run it again for the accounts shown now.</p>`}
      <p class="ai-headline">${esc(f.headline || "")}</p>
      <div class="tiles">
        ${tile("Entrenchment", f.entrenchment?.level || EMPTY, "AI judgement")}
        ${tile("AI effort", range(e.effort_engineer_days, (v) => num(v)), `engineer-days, ${versus(e.effort_engineer_days, ref.effort_engineer_days)}`)}
        ${tile("AI time", range(e.duration_months, (v) => num(v)), `months, ${versus(e.duration_months, ref.duration_months)}`)}
        ${tile("AI cost", range(e.cost, m), versus(e.cost, ref.cost))}
      </div>
      <div class="grid-2">
        <div><h4>How it compares with the model</h4><p class="small">${esc(e.compared_with_model || "")}</p>
          <p class="hint">Model: ${num(ref.effort_engineer_days)} engineer-days, ${num(ref.duration_months)} months, ${m(ref.cost)}. AI confidence: ${esc(e.confidence || EMPTY)}.</p>
          <h4>What drives it</h4>${list(e.drivers)}
          ${e.adjustments?.length ? `<h4>Where the AI differs</h4><ul class="assumptions">${e.adjustments.map((x) => `<li><strong>${x.direction === "down" ? "Lower" : "Higher"}: ${esc(x.item)}.</strong> ${esc(x.reason)}</li>`).join("")}</ul>` : ""}
        </div>
        <div><h4>Why: entrenchment</h4><p class="small">${esc(f.entrenchment?.summary || "")}</p>
          <h4>Not included</h4>${list(e.not_included)}</div>
      </div>
      <h4>AI areas of focus</h4><div class="focus-list">${focus || '<p class="hint">None.</p>'}</div>
      ${f.programme_risks?.length ? `<h4>Programme risks</h4><div class="table-wrap"><table class="data compact"><thead><tr><th>Risk</th><th>Impact</th><th>Mitigation</th></tr></thead><tbody>${f.programme_risks.map((x) => `<tr><td>${esc(x.risk)}</td><td>${esc(x.impact)}</td><td>${esc(x.mitigation)}</td></tr>`).join("")}</tbody></table></div>` : ""}
      ${f.sequencing?.length ? `<h4>Sequencing</h4><div class="table-wrap"><table class="data compact"><tbody>${f.sequencing.map((x) => `<tr><td>${phaseChip(x.phase)}</td><td>${esc(x.what)}</td></tr>`).join("")}</tbody></table></div>` : ""}
      <div class="grid-2">
        <div><h4>Quick wins</h4>${list(f.quick_wins)}</div>
        <div><h4>Questions to validate with owners</h4>${list(f.questions_to_validate)}<h4>Evidence that would firm it up</h4>${list(f.evidence_to_collect)}</div>
      </div>
      <details class="ai-more"${PRINT ? " open" : ""}><summary>Review pass: ${plural((res.changes || []).length, "correction")}${res.open_checks?.length ? `, ${plural(res.open_checks.length, "check")} still open` : ", all automated checks pass"}</summary>
        ${(res.changes || []).length ? `<ul class="assumptions">${res.changes.map((c) => `<li><strong>${esc(c.issue)}</strong> ${esc(c.fix)}</li>`).join("")}</ul>` : '<p class="hint">The reviewer changed nothing.</p>'}
        ${res.open_checks?.length ? `<p class="warn-text">Still open after the review:</p>${list(res.open_checks)}` : ""}
        ${res.notes?.length ? `<p class="warn-text">How the run went:</p>${list(res.notes)}` : Array.isArray(res.notes) ? '<p class="hint">Every call came back whole: no answer was cut off, unreadable or missing an account.</p>' : ""}
      </details>
      <details class="ai-more"${PRINT ? " open" : ""}><summary>Every account the AI analysed (${num(accts.length)})</summary>
        <div class="table-wrap"><table class="data compact"><thead><tr><th>Account</th><th>Entrenchment</th><th class="num-cell">AI weeks</th><th class="num-cell">Model weeks</th><th>Phase</th><th>Why, and how to tackle it</th></tr></thead><tbody>
        ${accts.map((a) => `<tr><td><strong>${esc(res.account_names?.[a.id] || a.id)}</strong></td><td><span class="sev" style="--dot:${tierColor(LEVEL_TIER[a.entrenchment] || 3)}">${esc(a.entrenchment || EMPTY)}</span></td><td class="num-cell">${range(a.effort_engineer_weeks, (v) => num(v))}</td><td class="num-cell">${num(modelWeeks[a.id], 0)}</td><td>${esc(a.phase || "")}</td><td class="small">${esc(a.why || "")}${a.approach ? `<div class="hint">${esc(a.approach)}</div>` : ""}</td></tr>`).join("")}
        </tbody></table></div>
      </details>`;
    $("#btnAiAgain").addEventListener("click", openAi);
    $("#btnAiRemove").addEventListener("click", async () => {
      await api(`/api/ai/review/${encodeURIComponent(state.scanId)}?remove=true`, { method: "DELETE" });
      state.ai = null;
      renderAi(state.report);
      toast("AI review removed");
    });
  }

  const AI_CUSTOM = "__custom";
  async function openAi() {
    if (!state.report) { toast("Load a scan first"); return; }
    $("#aiError").textContent = "";
    $("#aiOk").textContent = "";
    $("#aiTests").hidden = true;
    try {
      const [cfg, prof] = await Promise.all([api("/api/ai/settings"), api("/api/profiles").catch(() => ({ profiles: [] }))]);
      state.aiCfg = cfg;
      $("#aiProvider").innerHTML = cfg.providers.map((p) => `<option value="${esc(p.key)}">${esc(p.label)}</option>`).join("");
      $("#aiProfile").innerHTML = `<option value="">Default credentials</option>` + prof.profiles.map((x) => `<option>${esc(x)}</option>`).join("");
      const s = cfg.settings;
      $("#aiProvider").value = s.provider;
      $("#aiRegion").value = s.region;
      $("#aiProfile").value = s.profile;
      $("#aiMask").checked = s.mask_names;
      $("#aiBaseUrl").value = s.base_url || "";
      $("#aiKeyHeader").value = s.key_header || "authorization";
      aiProviderChanged(s.model);
    } catch (e) { $("#aiError").textContent = e.message; }
    $("#aiDialog").showModal();
    if (state.ai?.run?.status === "running") pollAi();
  }

  function aiProvider() { return state.aiCfg.providers.find((p) => p.key === $("#aiProvider").value); }

  function aiProviderChanged(model) {
    const p = aiProvider(), s = state.aiCfg.settings, k = s.keys[p.key];
    $("#aiProviderNote").textContent = p.note + (p.third_party ? " The summary leaves your AWS estate for this provider: check it is approved for this data." : "");
    $("#aiBedrock").hidden = p.key !== "bedrock";
    $("#aiGateway").hidden = p.key !== "gateway";
    // Header values can be secrets (virtual keys, configs): only their names come back, like keys.
    $("#aiHeaders").value = "";
    delete $("#aiHeaders").dataset.touched;
    $("#aiHeaders").placeholder = s.header_names?.length ? `Saved: ${s.header_names.join(", ")}. Type to replace; clear to remove.` : "x-portkey-provider: @bedrock-prod";
    $("#aiKeyLabel").textContent = p.key === "bedrock" ? "Bedrock API key (optional; blank = use the AWS profile)" : p.key === "gateway" ? "Gateway API key" : "API key";
    if (p.key === "gateway" && !model) model = s.gateway_model || "";
    $("#aiKeyLink").href = p.key_url;
    $("#aiKey").value = "";
    hideAiKey();
    $("#aiKey").placeholder = k.set ? (k.env ? `Using ${p.key_env} from the environment` : `Saved (${k.hint}); type to replace`) : p.key === "bedrock" ? "" : `Paste the key, or set ${p.key_env}`;
    if (p.key !== s.provider && $("#aiMask").dataset.touched !== "1") $("#aiMask").checked = p.third_party;
    fillAiModels(p.recommended.map((x) => ({ ...x, recommended: false })), model ?? "");
    loadAiModels(model);
  }

  function hideAiKey() {
    $("#aiKey").type = "password";
    $("#btnAiShowKey").textContent = "Show";
    $("#btnAiShowKey").setAttribute("aria-pressed", "false");
  }

  // Show the key being typed, or fetch the saved one from this computer to check it.
  async function toggleAiKey() {
    if ($("#aiKey").type === "text") { hideAiKey(); return; }
    const p = aiProvider(), k = state.aiCfg.settings.keys[p.key];
    if (!$("#aiKey").value && k?.set) {
      try {
        const { key } = await api("/api/ai/key", { method: "POST", body: { provider: p.key } });
        $("#aiKey").value = key;
      } catch (e) { $("#aiError").textContent = e.message; return; }
    }
    $("#aiKey").type = "text";
    $("#btnAiShowKey").textContent = "Hide";
    $("#btnAiShowKey").setAttribute("aria-pressed", "true");
  }

  function fillAiModels(models, want) {
    const opts = models.map((x) => `<option value="${esc(x.id)}">${esc(x.label)}</option>`).join("");
    $("#aiModel").innerHTML = opts + `<option value="${AI_CUSTOM}">Custom model…</option>`;
    const known = models.some((x) => x.id === want);
    $("#aiModel").value = !want ? models[0]?.id || AI_CUSTOM : known ? want : AI_CUSTOM;
    if (want && !known) $("#aiCustom").value = want;
    $("#aiCustomWrap").hidden = $("#aiModel").value !== AI_CUSTOM;
  }

  // Ask the provider which models this key can use; the recommended list stays if it cannot say.
  async function loadAiModels(want) {
    const seq = (state.aiModelSeq = (state.aiModelSeq || 0) + 1);
    try {
      const { models } = await api("/api/ai/models", { method: "POST", body: aiBody() });
      if (seq !== state.aiModelSeq) return;
      fillAiModels(models, want ?? aiModelId());
    } catch { /* keep the recommended models */ }
  }

  const aiModelId = () => ($("#aiModel").value === AI_CUSTOM ? $("#aiCustom").value.trim() : $("#aiModel").value);
  function aiBody(withKey = true) {
    const key = $("#aiKey").value.trim();
    return {
      provider: $("#aiProvider").value, model: aiModelId(), region: $("#aiRegion").value.trim() || "us-east-1",
      profile: $("#aiProfile").value, mask_names: $("#aiMask").checked, ...(withKey && key ? { api_key: key } : {}),
      base_url: $("#aiBaseUrl").value.trim(), key_header: $("#aiKeyHeader").value,
      ...($("#aiHeaders").dataset.touched === "1" ? { headers: $("#aiHeaders").value } : {}),
    };
  }

  async function saveAi() {
    const cfg = await api("/api/ai/settings", { method: "PUT", body: aiBody() });
    state.aiCfg.settings = cfg.settings;
    $("#aiKey").value = "";
    if ($("#aiHeaders").dataset.touched === "1") aiProviderChanged(aiModelId());  // show the saved header names
    return cfg;
  }

  async function testAi() {
    $("#aiError").textContent = "";
    $("#aiOk").textContent = "";
    busy("#aiBusy", "Testing the connection…");
    $("#aiBusySub").textContent = "";
    try {
      await saveAi();
      const t = await api("/api/ai/test", { method: "POST", body: aiBody(false) });
      if (t.ok) $("#aiOk").textContent = `Working: ${t.model} solved a small reasoning check and answered in valid JSON in ${t.seconds} s${t.reasoning ? ` (reasoning: ${t.reasoning})` : ""}.`;
      else $("#aiError").textContent = t.error;
    } catch (e) { $("#aiError").textContent = e.message; }
    finally { busy("#aiBusy", ""); }
  }

  async function testAllAi() {
    $("#aiError").textContent = "";
    $("#aiOk").textContent = "";
    busy("#aiBusy", "Testing every provider with a key…");
    $("#aiBusySub").textContent = "";
    try {
      await saveAi();
      const { results } = await api("/api/ai/test-all", { method: "POST" });
      $("#aiTests").hidden = false;
      $("#aiTestTable").innerHTML = `<thead><tr><th>Provider</th><th>Model</th><th>Result</th></tr></thead><tbody>${results.map((x) => `<tr><td>${esc(x.label)}</td><td>${esc(x.model || "")}</td><td>${x.ok ? `<span class="sev" style="--dot:var(--good)">Working</span> <span class="hint">${x.seconds} s${x.reasoning ? `, reasoning ${esc(x.reasoning)}` : ""}</span>` : x.ok === null ? `<span class="hint">${esc(x.error)}</span>` : `<span class="sev" style="--dot:var(--t5)">Failed</span> <div class="hint">${esc(x.error)}</div>`}</td></tr>`).join("")}</tbody>`;
    } catch (e) { $("#aiError").textContent = e.message; }
    finally { busy("#aiBusy", ""); }
  }

  async function runAi() {
    $("#aiError").textContent = "";
    $("#aiOk").textContent = "";
    if (!aiModelId()) { $("#aiError").textContent = "Enter the custom model id."; return; }
    try {
      await saveAi();
      const filter = { include: $("#fInclude").value, exclude: $("#fExclude").value, mode: $("#fMode").value };
      const run = await api("/api/ai/review", { method: "POST", body: { scan_id: state.scanId, filter, questionnaire: readQuestionnaire(), weighting: $("#fWeighting").value || "spend" } });
      state.ai = { ...(state.ai || {}), run };
      pollAi();
    } catch (e) { $("#aiError").textContent = e.message; }
  }

  async function pollAi() {
    if (state.aiPolling) return;
    state.aiPolling = true;
    const scan = state.scanId;
    $("#btnAiRun").disabled = true;
    $("#btnAiStop").hidden = false;
    busy("#aiBusy", "Starting the AI review…");
    try {
      for (;;) {
        const got = await api(`/api/ai/review/${encodeURIComponent(scan)}`);
        if (scan !== state.scanId) return;
        const run = got.run;
        if (!run) break;
        // Passes, not calls: "step 1 of 11" read as if only 11 accounts were being analysed.
        $("#aiBusy .busy-text").textContent = `${run.stage}${run.pass ? ` (pass ${run.pass} of 3)` : ""}`;
        $("#aiBusySub").textContent = `${run.message || ""}${run.usage?.calls ? ` · ${run.usage.calls} calls so far` : ""}`;
        if (run.total) busyProgress("#aiBusy", run.done / run.total);
        if (run.status !== "running") {
          state.ai = got;
          if (run.status === "complete") { $("#aiOk").textContent = "Done: the AI review is in section 7."; toast("AI review ready: section 7"); }
          else $("#aiError").textContent = run.status === "cancelled" ? "Stopped." : run.message;
          renderAi(state.report);
          break;
        }
        state.ai = { ...got };
        renderAi(state.report);
        await new Promise((ok) => setTimeout(ok, 3000));
      }
    } catch (e) { $("#aiError").textContent = `Lost track of the AI review: ${e.message}`; }
    finally {
      state.aiPolling = false;
      busy("#aiBusy", "");
      $("#btnAiRun").disabled = false;
      $("#btnAiStop").hidden = true;
    }
  }

  function renderIssues(r) {
    const c = r.issue_counts;
    // Top-bar shortcut: count and colour of the worst severity, so issues are never only at the bottom.
    const worst = ["critical", "error", "warning", "info"].find((s) => c[s]);
    $("#btnIssues").hidden = !r.issues.length;
    $("#issueBadge").textContent = r.issues.length;
    $("#issueBadge").className = `count-badge sev-${worst || "info"}`;
    $("#btnIssues").title = `${plural(r.issues.length, "issue")}${worst ? `, worst: ${worst}` : ""} (section 8)`;
    $("#issueCounts").innerHTML = ["critical", "error", "warning", "info"].map((s) => `<span class="chip"><span class="sev" style="--dot:${css(SEV_COLOR[s])}">${s}: ${c[s] || 0}</span></span>`).join("");
    const names = Object.fromEntries(r.accounts.map((a) => [a.id, a.name]));
    $("#issueTable").innerHTML = r.issues.length
      ? `<thead><tr><th>Severity</th><th>Area</th><th>Account</th><th>Issue</th></tr></thead><tbody>` + r.issues.map((i) => `<tr>
          <td><span class="sev" style="--dot:${css(SEV_COLOR[i.severity] || "--muted")}">${esc(i.severity)}</span></td>
          <td class="cap">${esc(i.category)}${i.region ? `<div class="hint">${esc(i.region)}</div>` : ""}</td>
          <td>${esc(names[i.account_id] || i.account_id || EMPTY)}</td>
          <td>${esc(String(i.message || "").replace(/^./, (ch) => ch.toUpperCase()))}${i.error_code ? ` <span class="chip">${esc(i.error_code)}</span>` : ""}${i.hint ? `<div class="hint">→ ${esc(i.hint)}</div>` : ""}</td></tr>`).join("") + "</tbody>"
      : `<tbody><tr><td class="hint">No issues recorded. Every API call in the scan succeeded.</td></tr></tbody>`;
  }

  // Exclusions dialog: every product with spend in scope; ticks are a draft until "Apply and regenerate".
  function renderExclusions(r) {
    const draft = state.exclDraft || state.exclude;
    const find = $("#exclFilter").value.trim().toLowerCase();
    const choices = r.product_choices || [];
    const rows = choices.filter((p) => !find || p.display.toLowerCase().includes(find) || p.service.toLowerCase().includes(find))
      .sort((a, b) => a.display.localeCompare(b.display, undefined, { sensitivity: "base", numeric: true }));
    $("#exclList").innerHTML = rows.length
      ? rows.map((p) => `<label class="check"><input type="checkbox" data-svc="${esc(p.service)}"${draft.has(p.service) ? " checked" : ""}><span>${esc(p.display)}</span><span class="excl-spend">${money(p.monthly_spend)}/mo</span></label>`).join("")
      : `<p class="muted small">${find ? "No product matches." : "No spend in scope."}</p>`;
    const picked = choices.filter((p) => draft.has(p.service));
    const changed = [...draft].sort().join("|") !== [...state.exclude].sort().join("|");
    $("#exclNote").textContent = (picked.length ? `${plural(picked.length, "product")} ticked: ${money(picked.reduce((a, p) => a + p.monthly_spend, 0))}/month.` : "Nothing ticked.")
      + (changed ? " Not applied yet." : "");
    $("#btnExclApply").disabled = !changed;
    const n = r.summary.excluded_services.length;
    $("#exclCount").hidden = !n;
    $("#exclCount").textContent = n;
  }

  function renderAppendix(r) {
    const cat = state.catalog;
    const used = new Map(r.services.map((s) => [s.service, s]));
    const tierText = {
      1: "Commodity infrastructure or an open standard. Lift-and-shift; config moves, code does not change.",
      2: "Managed flavour of an open engine or de-facto standard API. Data and config migrate; little code change.",
      3: "AWS-specific API with a close equivalent on every major cloud. Code changes at the integration points.",
      4: "Proprietary programming or data model. The workload must be redesigned, not just re-pointed.",
      5: "No equivalent outside AWS. Rebuild, re-platform or replace with a product; often a business change.",
    };
    $("#tierDefs").innerHTML = `<thead><tr><th>Tier</th><th class="num-cell">Score</th><th>Meaning</th></tr></thead><tbody>` +
      [1, 2, 3, 4, 5].map((t) => `<tr><td><span class="tier-pill" style="--dot:${tierColor(t)}">${t} · ${esc(cat.tiers[t].label)}</span></td><td class="num-cell">${cat.tiers[t].score}</td><td>${esc(tierText[t])}</td></tr>`).join("") + "</tbody>";

    const showAll = $("#showAllCatalog").checked;
    const unclassified = r.services.filter((s) => !s.classified);
    let html = "";
    for (const t of [5, 4, 3, 2, 1]) {
      const list = cat.services.filter((s) => s.tier === t && (showAll || used.has(s.service) || s.aliases.some((a) => used.has(a))))
        .sort((a, b) => (used.get(b.service)?.monthly_spend || 0) - (used.get(a.service)?.monthly_spend || 0) || a.display.localeCompare(b.display));
      if (!list.length) continue;
      html += `<div class="cat-group"><h3><span class="tier-pill" style="--dot:${tierColor(t)}">Tier ${t} · ${esc(cat.tiers[t].label)}</span> <span class="muted small">${plural(list.length, "service")}</span></h3>
        <div class="table-wrap"><table class="data catalog"><colgroup><col style="width:15%"><col style="width:27%"><col style="width:28%"><col style="width:20%"><col style="width:10%"></colgroup><thead><tr><th>Service</th><th>Why this tier</th><th>Recommended migration path</th><th>Equivalents</th><th>Typical duration</th></tr></thead><tbody>` +
        list.map((s) => {
          const u = used.get(s.service) || s.aliases.map((a) => used.get(a)).find(Boolean);
          return `<tr><td>${esc(s.display)}<div class="hint">${esc(s.category)}</div><div class="hint" title="How much AI coding agents cut the work when the Exit model says they are used">AI agent help: ${esc(s.agentic)}</div>${u ? `<div class="hint">${money(u.monthly_spend)}/mo in scope</div>` : ""}</td>
          <td>${esc(s.why)}</td><td>${esc(s.migration)}</td>
          <td class="targets">${s.targets.azure ? `<div><strong>Azure:</strong> ${esc(s.targets.azure)}</div>` : ""}${s.targets.gcp ? `<div><strong>GCP:</strong> ${esc(s.targets.gcp)}</div>` : ""}${s.targets.other ? `<div><strong>Neutral:</strong> ${esc(s.targets.other)}</div>` : ""}</td>
          <td>${esc(s.duration)}</td></tr>`;
        }).join("") + "</tbody></table></div></div>";
    }
    if (unclassified.length) {
      html += `<div class="cat-group"><h3>Unclassified services in this estate</h3><p class="muted small">Scored as Moderate (tier 3) until added to the catalog.</p><ul>` +
        unclassified.map((s) => `<li>${esc(s.service)}: ${money(s.monthly_spend)}/month</li>`).join("") + "</ul></div>";
    }
    $("#catalog").innerHTML = html;
  }

  // ------------------------------------------------------------------ multi-region view
  const LS_MR = "exitrisk.multiregion.v1";
  const LS_MR_ACCTS = "exitrisk.multiregion.accounts."; // + scan id: the accounts ticked for a second region
  const MR_DEFAULTS = { recovery: "rto_3h", residency: "any", primary: "", secondary: "", support_plan: "enterprise", allocation_pct: 50, fte_annual_cost: 0, confirmed: false, assume_available: [], not_needed: [] };
  const MR_NUM = ["allocation_pct", "fte_annual_cost"];
  const SEV_TIER = { Low: 1, Moderate: 3, High: 4, Critical: 5 };
  const AVAIL_LABEL = { available: "Available", missing: "Not available", unverified: "Not verified", global: "Global" };
  const AVAIL_TIER = { available: 1, missing: 5, unverified: 3, global: 2 };
  const MR_ROWS = 25;

  function setView(v) {
    state.view = v === "multiregion" ? "multiregion" : "exit";
    document.body.dataset.view = state.view;
    for (const b of document.querySelectorAll(".vtab")) b.setAttribute("aria-pressed", String(b.dataset.view === state.view));
    $("#content").hidden = state.view !== "exit" || !state.report;
    $("#mrContent").hidden = state.view !== "multiregion" || !state.mr;
    if (state.view !== "multiregion") $("#mrError").hidden = true;
    // Export follows the report on screen; the one-page summary exists only for exit risk.
    const mr = state.view === "multiregion";
    $("#btnPdf b").textContent = mr ? "Multi-region report" : "Full report";
    $("#btnPdf span").textContent = mr ? "Every multi-region section, as on screen" : "Every section and the appendix";
    $("#btnOnePage").hidden = mr;
    if (!PRINT) {
      const url = new URL(location.href);
      if (state.view === "multiregion") url.searchParams.set("view", "multiregion"); else url.searchParams.delete("view");
      history.replaceState(null, "", url);
    }
    if (state.view === "multiregion" && !state.mr) loadMultiRegion();
    Object.values(state.charts).forEach((c) => c.resize());
  }

  function loadMrAnswers() {
    const a = { ...MR_DEFAULTS };
    try { Object.assign(a, JSON.parse(localStorage.getItem(LS_MR) || "{}")); } catch { /* ignore */ }
    if (params.get("mr")) {
      try { Object.assign(a, JSON.parse(params.get("mr"))); state.mrFromLink = true; } catch { console.warn("bad mr param"); }
    }
    return a;
  }

  function readMr() {
    if (!state.mrFilled) return loadMrAnswers();
    const f = $("#mrForm");
    const a = { confirmed: !!state.mrConfirmed, assume_available: state.mrFix.assume_available, not_needed: state.mrFix.not_needed };
    for (const el of f.elements) {
      if (!el.name || el.hasAttribute("data-shared")) continue;
      if (el.type === "radio") { if (el.checked) a[el.name] = el.value; }
      else if (MR_NUM.includes(el.name)) a[el.name] = el.value === "" ? undefined : Number(el.value);
      else a[el.name] = el.value;
    }
    if (!state.mrFromLink) { try { localStorage.setItem(LS_MR, JSON.stringify(a)); } catch { /* ignore */ } }
    return a;
  }

  function mrAccounts() {
    if (params.get("mr_accounts")) return params.get("mr_accounts").split(",");
    try { const v = localStorage.getItem(LS_MR_ACCTS + state.scanId); return v ? JSON.parse(v) : null; } catch { return null; }
  }
  function saveMrAccounts(ids) {
    try {
      if (ids) localStorage.setItem(LS_MR_ACCTS + state.scanId, JSON.stringify(ids)); else localStorage.removeItem(LS_MR_ACCTS + state.scanId);
    } catch { /* ignore */ }
  }

  async function loadMultiRegion() {
    if (!state.scanId) return;
    const filter = { include: $("#fInclude").value, exclude: $("#fExclude").value, mode: $("#fMode").value };
    const body = { scan_id: state.scanId, filter, questionnaire: readQuestionnaire(), multiregion: { ...readMr(), accounts: mrAccounts() } };
    const seq = (state.mrSeq = (state.mrSeq || 0) + 1);
    try {
      const mr = await api("/api/multiregion", { method: "POST", body });
      if (seq !== state.mrSeq) return; // a newer request superseded this one
      state.mr = mr;
    } catch (e) {
      if (seq !== state.mrSeq) return;
      showMrError(e);
      return;
    }
    $("#mrError").hidden = true;
    renderMr();
  }

  // A failed calculation must say so in place, not leave a blank tab behind a toast.
  function showMrError(e) {
    console.error("multi-region failed", e);
    const ref = e.requestId ? ` (request ${e.requestId})` : "";
    $("#mrErrorText").textContent = `${e.message}${ref}`;
    $("#mrErrorHint").textContent = e.hint || (e.status >= 500
      ? "This is a bug in the console. Open the Log for the details, and report it with the log lines."
      : "Check the choices in section 2 and try again.");
    $("#mrError").hidden = state.view !== "multiregion";
    if (state.mr) toast(`Multi-region not updated: ${e.message}`);
    if (PRINT) { document.body.dataset.error = e.message; document.body.dataset.ready = "1"; }
  }

  function fillMrForm(m) {
    const f = $("#mrForm"), a = m.answers, q = $("#qForm");
    const opts = (labels, extra) => (extra || "") + Object.entries(labels).map(([v, l]) => `<option value="${esc(v)}">${esc(l)}</option>`).join("");
    const regionOpts = Object.entries(m.regions).map(([k, n]) => `<option value="${esc(k)}">${esc(n)} · ${esc(k)}</option>`).join("");
    const s = m.summary;
    f.residency.innerHTML = opts(m.labels.residency);
    f.support_plan.innerHTML = opts(m.labels.support_plan);
    f.primary.innerHTML = `<option value="">Detected: ${esc(m.regions[s.primary] || s.primary)}</option>` + regionOpts;
    f.secondary.innerHTML = `<option value="">Recommended: ${esc(s.recommended_name || "none allowed")}</option>` + regionOpts;
    f.cicd.innerHTML = q.cicd.innerHTML;
    f.iac.innerHTML = q.iac.innerHTML;
    for (const el of f.elements) {
      if (!el.name) continue;
      if (el.hasAttribute("data-shared")) { el.value = q[el.name].value; continue; }
      if (el.type === "radio") el.checked = el.value === a[el.name];
      else if (a[el.name] != null) el.value = a[el.name];
    }
    state.mrFilled = true;
    state.mrConfirmed = a.confirmed;
    state.mrFix = { assume_available: [...(a.assume_available || [])], not_needed: [...(a.not_needed || [])] };
  }

  function sevBadge(sev) {
    return sev ? `<span class="badge" style="--dot:${tierColor(SEV_TIER[sev])}">${esc(sev)}</span>` : `<span class="muted">n/a</span>`;
  }

  function renderMr() {
    const m = state.mr, s = m.summary, rg = s.ranges, x = s.executive, t = s.target;
    const cur = s.run.currency;
    $("#reportBar").hidden = false;
    fillMrForm(m);
    $("#mrMeta").innerHTML = [
      ["Scope", state.report?.meta.filter.description || "All accounts"],
      ["Accounts going multi-region", `${num(s.accounts_selected)} of ${num(s.accounts_in_scope)}`],
      ["Primary region", `${s.primary_name} (${s.primary})${s.primary_detected ? "" : " · set by you"}`],
      ["Second region", s.secondary_name ? `${s.secondary_name} (${s.secondary})${s.secondary === s.recommended ? " · recommended" : " · chosen by you"}` : EMPTY],
      ["Recovery target", m.labels.recovery[m.answers.recovery]],
      ["Data residency", m.labels.residency[m.answers.residency]],
    ].map(([k, v]) => `<div><dt>${esc(k)}</dt><dd>${esc(v)}</dd></div>`).join("");
    const notes = (m.notes || []).map((n) => n.text);
    if (!s.secondary) notes.push("No AWS region meets the data-residency rule. Relax the rule in section 2 to see candidates.");
    $("#mrCoverage").hidden = !notes.length;
    $("#mrCoverage").innerHTML = notes.map((n) => `<p>${esc(n)}</p>`).join("");

    const lead = (i) => `<li><strong>${esc(i.lead)}</strong> ${esc(i.text)}</li>`;
    $("#mrHeadline").textContent = x.headline;
    $("#mrFindings").innerHTML = x.findings.map(lead).join("");
    $("#mrActions").innerHTML = x.actions.map(lead).join("");
    $("#mrProvisional").hidden = !m.provisional;
    const prov = m.provisional;
    $("#mrTiles").innerHTML = [
      tile("Extra cost to run (a year)", rg.run_annual, rg.uplift_pct ? `${rg.uplift_pct} of the chosen accounts' spend` : "infrastructure, support and people", prov),
      tile("Cost to achieve (one-off)", rg.build_cost, rg.build_effort, prov),
      tile("Time to achieve", rg.build_duration, `bound by ${s.build.constrained_by}`, prov),
      tile("Extra people", rg.staff === EMPTY ? EMPTY : `${rg.staff} FTE`, `${rg.staff_annual} a year`, prov),
      tile("Recommended region", s.recommended_name || EMPTY, t ? `~${t.latency_ms} ms · ${num(t.parity_pct)}% service parity` : "none meets the residency rule"),
      tile("Accounts with failover risk", `${num(s.accounts_blocked)} of ${num(s.accounts_selected)}`, "a material service cannot meet the target as built"),
    ].join("");
    $("#mrStatus").innerHTML = m.provisional
      ? `<span class="prov-tag">Provisional</span> Using default answers. Change any answer, or confirm these.`
      : `<span class="ok-tag">✓ Your answers</span> The estimate uses the answers below.`;

    renderMrAccounts(m);

    const regs = s.by_region.slice(0, 8);
    chart("chMrRegions", {
      type: "bar",
      data: { labels: regs.map((r) => (r.region === "global" ? "Global" : r.region)), datasets: [{ data: regs.map((r) => r.monthly_spend), backgroundColor: regs.map((r) => (r.region === s.primary ? css("--accent") : r.region === s.secondary ? tierColor(2) : css("--axis"))), borderRadius: 4, barPercentage: 0.7 }] },
      options: { indexAxis: "y", plugins: { legend: { display: false }, tooltip: { callbacks: { title: (c) => regs[c[0].dataIndex].name, label: (c) => ` ${money(c.raw)}/month` } } },
        scales: { x: { ticks: { callback: (v) => money(v) }, grid: { color: css("--grid") }, border: { display: false } }, y: { grid: { display: false } } } },
    });
    $("#mrRecName").textContent = s.recommended_name || "none";
    $("#mrRecWhy").textContent = s.secondary && s.secondary !== s.recommended ? `You chose ${s.secondary_name}; the figures below are for it.` : "Best balance of service parity, latency and price for the chosen accounts and recovery target.";
    $("#mrTargetFacts").innerHTML = t ? [
      ["Region", `${t.name} (${t.region})`],
      ["Estimated latency from primary", `~${t.latency_ms} ms round trip`],
      ["Service parity (by spend)", `${num(t.parity_pct, 1)}%`],
      ["Not available there", t.missing.length ? t.missing.map((x) => `${x.display} (${money(x.monthly_spend)}/mo)`).join(", ") : "None"],
      ["Prices against primary", `${t.price_index >= 1 ? "+" : ""}${num(100 * (t.price_index - 1))}%`],
      ["Already runs there", `${num(t.existing_pct, 1)}% of regional spend`],
    ].map(([k, v]) => `<tr><th scope="row">${esc(k)}</th><td>${esc(v)}</td></tr>`).join("") : "";
    const cands = m.candidates.filter((c) => c.residency_ok || c.region === s.secondary).slice(0, 10);
    // A missing service opens two corrections: the AWS list is out of date for this region, or the
    // service will not run in the second region at all.
    const fixChip = (c, x) => PRINT ? `<span class="chip">${esc(x.display)}</span>` : `<details class="fix"><summary class="chip" title="${esc(money(x.monthly_spend))}/month">${esc(x.display)}</summary><div class="fix-pop">
      <button type="button" class="btn sm" data-fix="assume_available" data-key="${esc(`${x.service}@${c.region}`)}">Available in ${esc(c.name)} (AWS list out of date)</button>
      <button type="button" class="btn sm" data-fix="not_needed" data-key="${esc(x.service)}">Not needed in the second region</button></div></details>`;
    const fixes = [
      ...m.answers.assume_available.map((k) => { const [svc, reg] = k.split("@"); return { kind: "assume_available", key: k, text: `${svc.replace(/^(Amazon|AWS) /, "")} available in ${m.regions[reg] || reg}` }; }),
      ...m.answers.not_needed.map((k) => ({ kind: "not_needed", key: k, text: `${(s.not_needed.find((x) => x.service === k)?.display) || k.replace(/^(Amazon|AWS) /, "")} not needed` })),
    ];
    $("#mrFixes").hidden = !fixes.length;
    $("#mrFixes").innerHTML = fixes.length ? `<span class="muted small">Your corrections:</span>` + fixes.map((x) =>
      `<span class="chip">${esc(x.text)}${PRINT ? "" : ` <button type="button" class="chip-x" data-unfix="${esc(x.kind)}" data-key="${esc(x.key)}" aria-label="Undo: ${esc(x.text)}">×</button>`}</span>`).join("") : "";
    $("#mrCandTable").innerHTML = `<thead><tr><th>Region</th><th class="num-cell">Latency</th><th class="num-cell">Parity</th><th>Not available</th><th class="num-cell">Price</th><th class="num-cell">Score</th><th>Why it ranks here</th><th class="no-print"></th></tr></thead><tbody>` +
      cands.map((c) => `<tr class="${c.region === s.secondary ? "chosen" : ""}"><td><strong>${esc(c.name)}</strong> <span class="muted small nowrap">${esc(c.region)}</span>${c.region === s.recommended ? ' <span class="ok-tag">Recommended</span>' : ""}</td>
        <td class="num-cell">~${num(c.latency_ms)} ms</td><td class="num-cell">${num(c.parity_pct, 1)}%</td>
        <td><div class="chips">${c.missing.length ? c.missing.map((x) => fixChip(c, x)).join("") : '<span class="muted">none</span>'}</div></td>
        <td class="num-cell">${c.price_index >= 1 ? "+" : ""}${num(100 * (c.price_index - 1))}%</td><td class="num-cell">${num(c.score)}</td>
        <td class="small">${esc([c.why, ...c.notes.map((n) => `${n[0].toUpperCase()}${n.slice(1)}.`)].join(" "))}</td>
        <td class="no-print">${c.region === s.secondary ? "" : `<button type="button" class="btn" data-use-region="${esc(c.region)}">Use</button>`}</td></tr>`).join("") + "</tbody>";

    const reg = s.regulation || [];
    $("#mrRegCard").hidden = !reg.length;
    $("#mrRegRegion").textContent = s.secondary_name || "";
    $("#mrRegList").innerHTML = reg.map((x) => `<li><strong>${esc(x.name)}</strong><span>${esc(x.text)}</span></li>`).join("");

    $("#mrRunTiles").innerHTML = [
      tile("Second-region infrastructure", rg.infra_annual, "a year, incl. replication traffic", prov),
      tile("AWS Support uplift", rg.support_annual, `${m.labels.support_plan[m.answers.support_plan]} plan, a year`, prov),
      tile("Extra people", rg.staff_annual, `${rg.staff} FTE a year`, prov),
    ].join("");
    const cls = s.run.by_class;
    chart("chMrClass", {
      type: "bar",
      data: { labels: cls.map((c) => c.label), datasets: [{ data: cls.map((c) => c.monthly), backgroundColor: css("--accent"), borderRadius: 4, barPercentage: 0.7 }] },
      options: { indexAxis: "y", plugins: { legend: { display: false }, tooltip: { callbacks: { label: (c) => ` ${money(c.raw)}/month` } } },
        scales: { x: { ticks: { callback: (v) => money(v) }, grid: { color: css("--grid") }, border: { display: false } }, y: { grid: { display: false } } } },
    });
    $("#mrStaffTable").innerHTML = `<thead><tr><th>Role</th><th class="num-cell">FTE (midpoint)</th></tr></thead><tbody>` +
      s.staff.parts.map((p) => `<tr><td>${esc(p.role)}</td><td class="num-cell">${num(p.fte, 1)}</td></tr>`).join("") +
      `<tr class="total"><td><strong>Total</strong> <span class="muted small">(quoted as ${esc(rg.staff)})</span></td><td class="num-cell"><strong>${num(s.staff.fte, 1)}</strong></td></tr></tbody>` +
      `<caption class="muted small" style="caption-side:bottom;text-align:left;padding-top:8px">At ${money(s.staff.fte_annual_cost, cur)} per FTE a year.</caption>`;

    $("#mrBuildTiles").innerHTML = [
      tile("Cost to achieve (one-off)", rg.build_cost, "engineering, plus running the region while it is built", prov),
      tile("Time to achieve", rg.build_duration, `bound by ${s.build.constrained_by} · ${teamSize(s.build.capacity_fte)}`, prov),
      tile("Engineering effort", rg.build_effort, plural(s.build.material_accounts, "material account"), prov),
    ].join("");
    const parts = s.build.parts;
    chart("chMrBuild", {
      type: "bar",
      data: { labels: parts.map((p) => p.part), datasets: [{ data: parts.map((p) => Math.round(p.weeks / 4.33)), backgroundColor: css("--ink-2"), borderRadius: 4, barPercentage: 0.7 }] },
      options: { indexAxis: "y", plugins: { legend: { display: false }, tooltip: { callbacks: { label: (c) => ` ${num(c.raw)} person-months` } } },
        scales: { x: { grid: { color: css("--grid") }, border: { display: false } }, y: { grid: { display: false } } } },
    });
    $("#mrParityTable").innerHTML = `<thead><tr><th>Service</th><th>Class</th><th class="num-cell">Accounts</th><th class="num-cell">Spend / month</th><th>In ${esc(s.secondary || EMPTY)}</th></tr></thead><tbody>` +
      (PRINT ? m.parity.filter((p) => p.availability !== "available" || p.monthly_spend >= 1000) : m.parity.slice(0, 40)).map((p) => `<tr><td>${esc(p.service)}</td><td class="small">${esc(p.class_label)}</td><td class="num-cell">${num(p.accounts)}</td><td class="num-cell">${money(p.monthly_spend)}</td>
        <td><span class="badge" style="--dot:${tierColor(AVAIL_TIER[p.availability])}">${esc(AVAIL_LABEL[p.availability])}</span></td></tr>`).join("") + "</tbody>";
    $("#mrAssumptions").innerHTML = m.assumptions.map((a) => `<li>${esc(a)}</li>`).join("");
    $("#mrFooter").textContent = $("#footer").textContent;
    $("#mrContent").hidden = state.view !== "multiregion";
    if (PRINT) document.querySelectorAll("#mrContent details").forEach((d) => { d.open = true; });
    if (state.view === "multiregion") document.body.dataset.ready = "1";
  }

  function renderMrAccounts(m) {
    const rows = m.accounts;
    const shown = PRINT ? rows : state.mrShowAll ? rows : rows.slice(0, MR_ROWS);
    const counts = (c) => ["Critical", "High", "Moderate", "Low"].filter((k) => c[k]).map((k) => `<span class="chip"><span class="sev" style="--dot:${tierColor(SEV_TIER[k])}">${esc(k)} ${c[k]}</span></span>`).join("");
    $("#mrAcctCount").textContent = `${num(m.summary.accounts_selected)} of ${num(rows.length)} accounts selected`;
    $("#mrAcctTable").innerHTML = `<thead><tr><th class="no-print"></th><th>Account</th><th class="num-cell">Spend / month</th><th>Readiness</th><th>Multi-region risks</th></tr></thead><tbody>` +
      shown.map((a) => `<tr class="${a.selected ? "" : "off"}"><td class="sel no-print"><input type="checkbox" data-acct="${esc(a.id)}" ${a.selected ? "checked" : ""} aria-label="Make ${esc(a.name)} multi-region"></td>
        <td><strong>${esc(a.name)}</strong><div class="muted small">${esc(a.id)} · ${esc(a.ou_path)}</div></td>
        <td class="num-cell">${money(a.monthly_spend)}</td><td>${sevBadge(a.readiness)}</td>
        <td>${a.risks.length ? `<details><summary><span class="chips" style="display:inline-flex">${counts(a.risk_counts)}</span></summary><ul class="risk-list">${a.risks.slice(0, 12).map((r) => `<li>${sevBadge(r.severity)} <strong>${esc(r.service)}</strong> <span class="muted">${money(r.monthly_spend)}/mo · ${esc(r.failover_label)}</span><br>${esc(r.note)}</li>`).join("")}${a.risks.length > 12 ? `<li class="muted">and ${a.risks.length - 12} smaller service(s)</li>` : ""}</ul></details>` : '<span class="muted">No regional spend</span>'}</td></tr>`).join("") + "</tbody>";
    const more = rows.length > MR_ROWS && !PRINT;
    $("#btnMrAcctMore").hidden = !more;
    $("#btnMrAcctMore").textContent = state.mrShowAll ? "Show fewer" : `Show all ${num(rows.length)}`;
    $("#mrAcctMoreNote").textContent = more && !state.mrShowAll ? `Showing the ${MR_ROWS} largest of ${num(rows.length)}.` : "";
  }

  function setMrSelection(ids) {
    saveMrAccounts(ids);
    clearTimeout(state.mrTimer);
    state.mrTimer = setTimeout(loadMultiRegion, 250);
  }

  function bindMultiRegion() {
    $("#btnMrRetry").addEventListener("click", () => loadMultiRegion());
    $("#btnMrLog").addEventListener("click", () => $("#btnLogs").click());
    for (const b of document.querySelectorAll(".vtab")) b.addEventListener("click", () => setView(b.dataset.view));
    $("#mrForm").addEventListener("change", (ev) => {
      const el = ev.target;
      if (el.hasAttribute?.("data-shared")) { $("#qForm")[el.name].value = el.value; readQuestionnaire(); state.report && loadReport(); }
      state.mrConfirmed = true;
      loadMultiRegion();
    });
    $("#btnMrConfirm").addEventListener("click", () => { state.mrConfirmed = true; loadMultiRegion(); });
    $("#mrAcctTable").addEventListener("change", (ev) => {
      const id = ev.target.dataset?.acct;
      if (!id || !state.mr) return;
      const sel = new Set(state.mr.accounts.filter((a) => a.selected).map((a) => a.id));
      if (ev.target.checked) sel.add(id); else sel.delete(id);
      for (const a of state.mr.accounts) if (a.id === id) a.selected = ev.target.checked;
      ev.target.closest("tr").classList.toggle("off", !ev.target.checked);
      setMrSelection([...sel]);
    });
    $("#btnMrAll").addEventListener("click", () => setMrSelection(null));
    $("#btnMrNone").addEventListener("click", () => setMrSelection([]));
    $("#btnMrTop").addEventListener("click", () => state.mr && setMrSelection(state.mr.accounts.slice(0, 10).map((a) => a.id)));
    $("#btnMrAcctMore").addEventListener("click", () => { state.mrShowAll = !state.mrShowAll; renderMrAccounts(state.mr); });
    const toggleFix = (kind, key, on) => {
      const list = new Set(state.mrFix[kind]);
      if (on) list.add(key); else list.delete(key);
      state.mrFix[kind] = [...list];
      loadMultiRegion();
    };
    $("#mrFixes").addEventListener("click", (ev) => {
      const b = ev.target.closest("[data-unfix]");
      if (b) toggleFix(b.dataset.unfix, b.dataset.key, false);
    });
    $("#mrCandTable").addEventListener("click", (ev) => {
      const fix = ev.target.closest("[data-fix]");
      if (fix) { toggleFix(fix.dataset.fix, fix.dataset.key, true); return; }
      const r = ev.target.dataset?.useRegion;
      if (!r) return;
      $("#mrForm").secondary.value = r;
      state.mrConfirmed = true;
      loadMultiRegion();
    });
    window.addEventListener("beforeprint", () => { if (state.view === "multiregion") document.querySelectorAll("#mrContent details").forEach((d) => { d.open = true; }); });
  }

  // ------------------------------------------------------------------ new scan dialog
  async function openScanDialog(selectProfile) {
    const dlg = $("#scanDialog");
    $("#scanError").textContent = "";
    $("#scanProgress").hidden = true;
    $("#btnStartScan").disabled = false;
    $("#sTarget").innerHTML = Object.entries(state.options.target).map(([v, l]) => `<option value="${esc(v)}">${esc(l)}</option>`).join("");
    $("#sTarget").value = $("#qForm").target.value || "azure";
    try {
      const profiles = await fillProfiles($("#sProfile"), typeof selectProfile === "string" ? selectProfile : null);
      if (profiles.length) loadOus();
    } catch (e) { $("#scanError").textContent = e.message; }
    dlg.showModal();
  }

  // Accounts in an OU and everything below it (null if the tree came without counts).
  function ouAccounts(node) {
    if (node.accounts == null) return null;
    return node.children.reduce((n, c) => n + (ouAccounts(c) ?? 0), node.accounts);
  }
  function flattenOus(node, depth = 0, out = [], parent = null) {
    out.push({ id: node.id, name: node.name, depth, parent, accounts: ouAccounts(node) });
    node.children.forEach((c) => flattenOus(c, depth + 1, out, node.id));
    return out;
  }

  // Ticking an OU covers its children, so they show ticked and locked; the scan counts each account once.
  function syncOus() {
    const boxes = [...$("#sOu").querySelectorAll("input[type=checkbox]")];
    const byId = new Map(boxes.map((b) => [b.value, b]));
    for (const b of boxes) {
      let p = b.dataset.parent, covered = false;
      while (p && byId.has(p)) { if (byId.get(p).checked && !byId.get(p).disabled) { covered = true; break; } p = byId.get(p).dataset.parent; }
      if (covered) { b.checked = true; b.disabled = true; } else if (b.disabled) { b.disabled = false; b.checked = false; }
    }
    const picked = boxes.filter((b) => b.checked && !b.disabled);
    $("#ouChosen").innerHTML = picked.length
      ? `<span class="ou-chosen-k">Scanning</span>${picked.map((b) => `<span class="chip">${esc(b.dataset.name)}</span>`).join("")}`
      : `<span class="ou-chosen-k">Scanning</span><span class="chip">Whole organisation</span>`;
  }
  const pickedOus = () => [...$("#sOu").querySelectorAll("input[type=checkbox]:checked:not(:disabled)")].map((b) => b.value);

  async function loadOus(ev) {
    const refresh = ev?.currentTarget?.id === "btnLoadOus";
    const was = new Set(pickedOus());
    $("#sOu").innerHTML = busyPanel("Loading organizational units…", "Usually a few seconds. Approve Touch ID if prompted.");
    $("#ouStatus").textContent = "";
    $("#btnLoadOus").disabled = true;
    const seq = (state.ouSeq = (state.ouSeq || 0) + 1); // a later profile change wins over a slow earlier reply
    try {
      const { tree, org } = await api("/api/org", { method: "POST", body: { profile: $("#sProfile").value || null, refresh } });
      if (seq !== state.ouSeq) return;
      $("#sOu").innerHTML = flattenOus(tree).filter((o) => o.depth > 0).map((o) =>
        `<label class="ou-item${o.depth > 1 ? " nested" : ""}" style="padding-left:${(o.depth - 1) * 22 + 12}px"><input type="checkbox" value="${esc(o.id)}" data-name="${esc(o.name)}" data-parent="${o.parent === tree.id ? "" : esc(o.parent)}"${was.has(o.id) ? " checked" : ""}><span class="ou-name">${esc(o.name)}</span>${o.accounts == null ? "" : `<span class="ou-n">${plural(o.accounts, "account")}</span>`}</label>`).join("") ||
        `<p class="muted small">No OUs: the scan covers the whole organisation.</p>`;
      syncOus();
      const n = flattenOus(tree).length - 1;
      $("#ouStatus").textContent = `${plural(n, "OU")} in organization ${org.id}, management account ${org.management_account_id}.`;
      state.mgmtAccount = org.management_account_id;
      try { if ($("#sProfile").value) localStorage.setItem(LS_ORG_PROFILE, $("#sProfile").value); } catch { /* ignore */ }
    } catch (e) {
      if (seq !== state.ouSeq) return;
      $("#sOu").innerHTML = `<p class="muted small">Whole organisation</p>`;
      $("#ouChosen").textContent = "";
      const cur = $("#sProfile").value;
      const others = [...$("#sProfile").options].map((o) => o.value).filter((v) => v && v !== cur);
      const known = others.filter((v) => state.profileAccounts?.[v] && state.mgmtAccount && state.profileAccounts[v] === state.mgmtAccount);
      const likely = known.length ? known : others.filter((v) => MGMT_RE.test(v));
      const denied = /AccessDenied|NotInUse|AWSOrganizationsNotInUse/i.test(e.code || e.message);
      $("#ouStatus").innerHTML = (denied
        ? `<strong>${esc(cur || "This profile")}</strong> cannot list OUs (${esc(e.code || e.message)}): it is probably not in the organisation's <strong>management account</strong>. `
        : `OUs unavailable with this profile (${esc(e.code || e.message)}). `) +
        (likely.length ? `Try ${likely.map((v) => `<a href="#" class="ou-try" data-p="${esc(v)}">${esc(v)}</a>`).join(" or ")}. ` : "Pick a management-account profile, or sign in with SSO and choose the management account. ") +
        "Without OUs the scan covers only what this profile can see.";
      $("#ouStatus").querySelectorAll(".ou-try").forEach((a) => a.addEventListener("click", (ev) => {
        ev.preventDefault(); $("#sProfile").value = a.dataset.p; loadOus();
      }));
    } finally { if (seq === state.ouSeq) { $("#btnLoadOus").disabled = false; } }
  }

  async function startScan() {
    const f = $("#scanForm");
    const body = {
      profile: f.profile.value || null, ou_ids: pickedOus(), months: Number(f.months.value || 12),
      inventory: f.depth.value !== "quick", dependencies: f.depth.value === "dependency",
      inventory_scope: f.material_only.checked ? "material" : "all", role_name: f.role_name.value || null,
      regions: f.regions.value ? f.regions.value.split(",").map((s) => s.trim()).filter(Boolean) : null, label: f.label.value,
      target: f.target.value || "azure",
    };
    $("#qForm").target.value = body.target;
    syncDatacenter();
    readQuestionnaire();
    $("#scanError").textContent = "";
    $("#btnStartScan").disabled = true;
    // Show the bar at once: the first AWS calls can take a few seconds before any progress comes back.
    $("#scanBar").style.width = "2%";
    $("#scanMsg").textContent = "Starting the scan…";
    $("#scanProgress").hidden = false;
    try {
      const job = await api("/api/scans", { method: "POST", body });
      pollScan(job.id);
    } catch (e) {
      $("#scanProgress").hidden = true;
      $("#scanError").textContent = e.message;
      $("#btnStartScan").disabled = false;
    }
  }

  function pollScan(id) {
    clearTimeout(state.pollTimer);
    let misses = 0;
    const tick = async () => {
      try {
        let s;
        try {
          s = await api(`/api/scans/${encodeURIComponent(id)}/status`);
          misses = 0;
        } catch (e) {
          // The scan keeps running on the server: ride out a blip (or a console restart) for about a
          // minute before giving up, so a dropped request never invites a duplicate scan.
          if (e.status !== 404 && ++misses <= 12) {
            $("#scanMsg").textContent = `Lost contact with the console; retrying (${misses})…`;
            state.pollTimer = setTimeout(tick, Math.min(1000 * 2 ** misses, 5000));
            return;
          }
          throw e;
        }
        $("#scanBar").style.width = `${s.pct}%`;
        $("#scanMsg").textContent = `${s.message || s.phase}${s.issues ? ` · ${plural(s.issues, "issue")} so far (listed under Issues when the scan finishes)` : ""}`;
        if (s.status === "running") { state.pollTimer = setTimeout(tick, 1000); return; }
        $("#btnStartScan").disabled = false;
        if (s.status === "failed") {
          $("#scanError").textContent = `Scan failed: ${s.message}. See section 8 and the log for details.`;
        } else {
          $("#scanDialog").close();
          toast(`Scan ${s.status}${s.issues ? ` with ${plural(s.issues, "issue")}: click Issues in the top bar` : ""}`);
        }
        await refreshScans(id);
        state.scanId = id;
        await loadReport();
      } catch (e) {
        // A 404 mid-scan means the console restarted and the in-memory scan was lost.
        $("#scanError").textContent = /scan not found/i.test(e.message)
          ? "The console restarted while this scan was running, so it was lost. Start the scan again."
          : e.message;
        $("#btnStartScan").disabled = false;
      }
    };
    tick();
  }

  // ------------------------------------------------------------------ log dialog
  async function openLog() {
    const only = $("#logThisRun").checked && state.scanId;
    try {
      const { records } = await api(`/api/logs?lines=400${only ? `&run_id=${encodeURIComponent(state.scanId)}` : ""}`);
      $("#logTable").innerHTML = `<thead><tr><th>Time</th><th>Level</th><th>Run</th><th>Message</th></tr></thead><tbody>` +
        (records.reverse().map((r) => `<tr><td>${esc(r.ts?.slice(11, 19))}</td><td>${esc(r.level)}</td><td>${esc(r.run_id)}</td><td>${esc(r.msg)}${r.exc ? `<pre>${esc(r.exc)}</pre>` : ""}</td></tr>`).join("")
          || `<tr><td colspan="4" class="hint">No log records${only ? " for this scan (demo scans make none)" : ""}.</td></tr>`) + "</tbody>";
    } catch (e) { toast(e.message); }
    if (!$("#logDialog").open) $("#logDialog").showModal();
  }

  // ------------------------------------------------------------------ AWS SSO sign-in
  const sso = { sessions: [], loginTimer: null, mgmt: null };
  const LS_SSO = "exitrisk.ssoSession";

  async function refreshSsoBadge() {
    try {
      ({ sessions: sso.sessions } = await api("/api/sso/sessions"));
    } catch (e) { console.error("sso sessions", e); sso.sessions = []; }
    const on = sso.sessions.filter((s) => s.signed_in);
    // A portal is set up but no sign-in is live (never signed in, or it expired): flash the button.
    const needed = sso.sessions.length > 0 && !on.length;
    $("#btnSso").classList.toggle("signed-in", on.length > 0);
    $("#btnSso").classList.toggle("needs-sign-in", needed);
    $("#ssoLabel").textContent = on.length ? `Signed in: ${on.map((s) => s.name).join(", ")}` : needed ? "Signed out: sign in" : "AWS sign-in";
    $("#btnSso").title = on.length ? `Signed in until ${new Date(on[0].expires_at).toLocaleString()}`
      : needed ? "Your AWS sign-in has expired: sign in again before you scan" : "Sign in through your AWS access portal (IAM Identity Center)";
  }

  // An animated bar and a line saying what is being waited for; null text hides it.
  function busy(sel, text) {
    const el = $(sel);
    el.hidden = !text;
    if (text) { el.querySelector(".busy-text").textContent = text; el.dataset.started = Date.now(); tickBusy(); }
    else {
      delete el.dataset.started;
      el.querySelector(".busy-bar")?.classList.remove("det");
      const fill = el.querySelector(".busy-bar i");
      if (fill) fill.style.width = "";
    }
  }

  // Turn a busy() bar into a measured one (0 to 1); busy(sel, null) resets it to the animated kind.
  function busyProgress(sel, frac) {
    const bar = $(sel).querySelector(".busy-bar");
    bar.classList.add("det");
    bar.querySelector("i").style.width = `${Math.round(Math.min(1, Math.max(0, frac)) * 100)}%`;
  }

  // A loading panel for content areas (the OU list): same look as busy(), built in place.
  function busyPanel(title, sub) {
    return `<div class="busy" role="status" aria-live="polite" data-started="${Date.now()}"><div class="busy-head"><span class="spin" aria-hidden="true"></span><span>${esc(title)}</span><span class="busy-time" aria-hidden="true">0s</span></div>${sub ? `<p class="busy-sub">${esc(sub)}</p>` : ""}<div class="busy-bar" aria-hidden="true"><i></i></div></div>`;
  }

  // Seconds waited so far, on every visible loading panel: shows it is alive even with reduced motion.
  function tickBusy() {
    document.querySelectorAll(".busy[data-started]").forEach((el) => {
      const t = el.querySelector(".busy-time");
      if (t) t.textContent = `${Math.floor((Date.now() - Number(el.dataset.started)) / 1000)}s`;
    });
  }
  setInterval(tickBusy, 500);

  function currentSso() { return sso.sessions.find((s) => s.name === $("#ssoSession").value); }

  async function openSsoDialog(ev) {
    ev?.preventDefault?.();
    if ($("#scanDialog").open) $("#scanDialog").close();
    $("#ssoError").textContent = "";
    $("#ssoPending").hidden = true;
    busy("#ssoBusy", null);
    await refreshSsoBadge();
    let want = null;
    try { want = localStorage.getItem(LS_SSO); } catch { /* ignore */ }
    $("#ssoSession").innerHTML = sso.sessions.length
      ? sso.sessions.map((s) => `<option value="${esc(s.name)}">${esc(s.name)} · ${esc(s.start_url.replace("https://", ""))}</option>`).join("")
      : `<option value="">(no portals configured - add one below)</option>`;
    if (want && sso.sessions.some((s) => s.name === want)) $("#ssoSession").value = want;
    $("#ssoAdd").hidden = sso.sessions.length > 0;
    $("#ssoDialog").showModal();
    await showSsoState();
  }

  async function showSsoState() {
    const s = currentSso();
    $("#ssoUse").hidden = true;
    $("#btnSsoUse").hidden = true;
    $("#btnSsoLogout").hidden = true;
    $("#btnSsoLogin").disabled = !s;
    if (!s) { $("#ssoStatus").textContent = ""; return; }
    try { localStorage.setItem(LS_SSO, s.name); } catch { /* ignore */ }
    $("#ssoStatus").textContent = s.signed_in
      ? `Signed in · token valid until ${new Date(s.expires_at).toLocaleString()} · region ${s.region}`
      : `Not signed in · region ${s.region}`;
    $("#btnSsoLogin").textContent = s.signed_in ? "Sign in again" : "Sign in";
    $("#btnSsoLogout").hidden = !s.signed_in;
    if (s.signed_in) await loadSsoAccounts(s);
  }

  async function loadSsoAccounts(s) {
    $("#ssoUse").hidden = false;
    $("#ssoVia").hidden = true;
    $("#ssoPick").hidden = false;
    $("#ssoAccount").innerHTML = `<option>Loading accounts…</option>`;
    $("#ssoRole").innerHTML = "";
    $("#ssoAccount").disabled = $("#ssoRole").disabled = true;
    busy("#ssoBusy", "Loading the accounts and roles you can use (a few seconds)…");
    try {
      const { accounts, management_account_id: mgmt } = await api(`/api/sso/${encodeURIComponent(s.name)}/accounts`);
      sso.mgmt = mgmt;
      const sorted = [...accounts].sort((a, b) => (b.id === mgmt) - (a.id === mgmt));
      $("#ssoAccount").innerHTML = sorted.map((a) => `<option value="${esc(a.id)}">${esc(a.name)} · ${esc(a.id)}${a.id === mgmt ? " · management account" : ""}</option>`).join("");
      const linked = s.profiles.find((p) => p.account_id === mgmt) || s.profiles[0];
      if (linked && accounts.some((a) => a.id === linked.account_id)) $("#ssoAccount").value = linked.account_id;
      $("#ssoStatus").textContent += ` · ${accounts.length} accounts${mgmt ? "" : " · management account not visible"}`;
      $("#ssoAccount").disabled = false;
      // With the management account found, show one line instead of a 300-account list.
      $("#ssoPick").hidden = !!mgmt && $("#ssoAccount").value === mgmt;
      await loadSsoRoles(linked?.role);
    } catch (e) {
      $("#ssoError").textContent = `${e.message}${e.hint ? ". " + e.hint : ""}`;
      $("#ssoAccount").innerHTML = `<option value="">Could not load the accounts: sign in again, or reopen this dialog</option>`;
      $("#ssoRole").innerHTML = "";
      busy("#ssoBusy", null);
    }
  }

  async function loadSsoRoles(prefer) {
    const s = currentSso(), acct = $("#ssoAccount").value;
    $("#btnSsoUse").hidden = true;
    $("#ssoRole").innerHTML = `<option>Loading roles…</option>`;
    $("#ssoRole").disabled = true;
    busy("#ssoBusy", "Loading the roles for this account…");
    try {
      const { roles } = await api(`/api/sso/${encodeURIComponent(s.name)}/accounts/${encodeURIComponent(acct)}/roles`);
      $("#ssoRole").innerHTML = roles.map((r) => `<option>${esc(r)}</option>`).join("") || `<option value="">(no roles)</option>`;
      const ro = prefer && roles.includes(prefer) ? prefer : roles.find((r) => /read|audit|view/i.test(r));
      if (ro) $("#ssoRole").value = ro;
      $("#btnSsoUse").hidden = !roles.length;
      showSsoVia();
    } catch (e) { $("#ssoRole").innerHTML = ""; $("#ssoError").textContent = e.message; }
    finally { $("#ssoRole").disabled = false; busy("#ssoBusy", null); }
  }

  // "Through the management account … as …" with a Change link that opens the account and role lists.
  function showSsoVia() {
    const via = $("#ssoVia"), acct = $("#ssoAccount").selectedOptions[0];
    via.hidden = !$("#ssoPick").hidden || !acct || !$("#ssoRole").value;
    if (via.hidden) return;
    const name = acct.textContent.split(" · ")[0];
    via.innerHTML = `Signing in through the management account <strong>${esc(name)}</strong> (${esc(acct.value)}) as <strong>${esc($("#ssoRole").value)}</strong>. <a href="#" id="lnkSsoChange">Change</a>`;
    $("#lnkSsoChange").addEventListener("click", (ev) => { ev.preventDefault(); $("#ssoPick").hidden = false; via.hidden = true; });
  }

  async function ssoLogout() {
    const s = currentSso();
    if (!s) return;
    $("#ssoError").textContent = "";
    try {
      await api("/api/sso/logout", { method: "POST", body: { session: s.name } });
      toast(`Signed out of ${s.name}`);
      await refreshSsoBadge();
      await showSsoState();
    } catch (e) { $("#ssoError").textContent = e.message; }
  }

  async function ssoLogin() {
    const s = currentSso();
    if (!s) return;
    $("#ssoError").textContent = "";
    // Open the tab inside the click so pop-up blockers allow it, then point it at AWS.
    const tab = window.open("", "_blank");
    try {
      const login = await api("/api/sso/login", { method: "POST", body: { session: s.name } });
      if (tab) { tab.opener = null; tab.location.href = login.verification_uri; }
      $("#ssoLink").href = login.verification_uri;
      $("#ssoCode").textContent = login.user_code;
      $("#ssoPending").hidden = false;
      $("#btnSsoLogin").disabled = true;
      clearInterval(sso.loginTimer);
      sso.loginTimer = setInterval(async () => {
        try {
          const st = await api(`/api/sso/login/${encodeURIComponent(login.id)}`);
          if (st.status === "pending") return;
          clearInterval(sso.loginTimer);
          $("#ssoPending").hidden = true;
          $("#btnSsoLogin").disabled = false;
          if (st.status !== "complete") { $("#ssoError").textContent = st.message; return; }
          toast(`Signed in to ${s.name}`);
          await refreshSsoBadge();
          await showSsoState();
        } catch (e) { clearInterval(sso.loginTimer); $("#ssoError").textContent = e.message; $("#btnSsoLogin").disabled = false; }
      }, 2000);
    } catch (e) {
      tab?.close();
      $("#ssoError").textContent = `${e.message}${e.hint ? ". " + e.hint : ""}`;
    }
  }

  async function ssoAddPortal() {
    const name = $("#ssoNewName").value.trim(), url = $("#ssoNewUrl").value.trim();
    $("#ssoError").textContent = "";
    if (!name || !url) { $("#ssoError").textContent = "Enter a name and the portal's start URL."; return; }
    $("#btnSsoAdd").disabled = true;
    $("#btnSsoAdd").textContent = "Finding region…";
    try {
      const added = await api("/api/sso/sessions", { method: "POST", body: { name, start_url: url } });
      try { localStorage.setItem(LS_SSO, added.name); } catch { /* ignore */ }
      toast(`Added ${added.name} (${added.region})`);
      $("#ssoDialog").close();
      await openSsoDialog();
    } catch (e) { $("#ssoError").textContent = e.message; }
    finally { $("#btnSsoAdd").disabled = false; $("#btnSsoAdd").textContent = "Add portal"; }
  }

  async function ssoUse() {
    const s = currentSso();
    try {
      const { profile } = await api("/api/sso/profile", { method: "POST", body: { session: s.name, account_id: $("#ssoAccount").value, role: $("#ssoRole").value } });
      $("#ssoDialog").close();
      toast(`Using profile ${profile}`);
      await openAccessDialog(profile, true);
    } catch (e) { $("#ssoError").textContent = e.message; }
  }

  // ------------------------------------------------------------------ access check
  async function fillProfiles(sel, want) {
    const { profiles, accounts } = await api("/api/profiles");
    state.profileAccounts = accounts || {};
    sel.innerHTML = profiles.length ? profiles.map((p) => `<option>${esc(p)}</option>`).join("") : `<option value="">(no profiles found - default credential chain)</option>`;
    const pick = preferredProfile(profiles, want);
    if (pick) sel.value = pick;
    return profiles;
  }

  // The profile most likely to see the whole organisation: the one asked for, the last one that
  // could read the OU tree, else one whose name suggests the management account.
  function preferredProfile(profiles, want) {
    let remembered = null;
    try { remembered = localStorage.getItem(LS_ORG_PROFILE); } catch { /* storage may be unavailable */ }
    return [want, remembered, profiles.find((p) => MGMT_RE.test(p))].find((p) => typeof p === "string" && profiles.includes(p)) || null;
  }

  async function openAccessDialog(profile, autoRun) {
    for (const d of ["#scanDialog", "#ssoDialog"]) if ($(d).open) $(d).close();
    $("#aChecks").innerHTML = "";
    $("#aVerdict").hidden = true;
    $("#aAdmin").hidden = true;
    $("#btnAccessScan").hidden = false;
    $("#btnAccessScan").disabled = true;
    $("#aSwitch").hidden = true;
    $("#aError").textContent = "";
    try { await fillProfiles($("#aProfile"), typeof profile === "string" ? profile : null); }
    catch (e) { $("#aError").textContent = e.message; }
    $("#accessDialog").showModal();
    if (autoRun) runAccessCheck();
  }

  function checkRow(c) {
    const icon = { ok: "✓", fail: "✗", warn: "!", skip: "○" };
    return `<li class="${esc(c.status)}"><span class="ic" aria-label="${esc(c.status)}">${icon[c.status] || "?"}</span><strong>${esc(c.label)}</strong>
        ${c.detail ? `<span class="d">${esc(c.detail)}</span>` : ""}${c.fix ? `<span class="f">→ ${esc(c.fix)}</span>` : ""}
        ${c.needs && c.status !== "ok" && c.status !== "skip" ? `<span class="n">Missing: ${c.needs.split(", ").map((a) => `<code>${esc(a)}</code>`).join(" ")}</span>` : ""}</li>`;
  }

  async function runAccessCheck() {
    $("#btnAccessRun").disabled = true;
    $("#aChecks").innerHTML = "";
    $("#aVerdict").hidden = true;
    $("#btnAccessRun").classList.add("primary");
    // Stays in view, disabled, so it is clear a scan can start once the checks pass.
    $("#btnAccessScan").hidden = false;
    $("#btnAccessScan").disabled = true;
    $("#aSwitch").hidden = true;
    $("#aAdmin").hidden = true;
    busy("#aBusy", "Starting the checks…");
    $("#aError").textContent = "";
    // Each check is one AWS call; the server streams them as they return, so the list fills in live
    // and the bar shows how many of the steps are done.
    let steps = [];
    const done = {};
    const prog = {}; // step id -> {done, total} while a step works through the accounts
    const drawSteps = () => {
      const current = steps.find((st) => !done[st.id]);
      const n = steps.filter((st) => done[st.id]).length;
      // The step being checked goes first, so it stays in view; the finished ones follow, then the rest.
      const order = [current, ...steps.filter((st) => done[st.id]), ...steps.filter((st) => !done[st.id] && st !== current)].filter(Boolean);
      $("#aChecks").innerHTML = order.map((st) => done[st.id] ? checkRow(done[st.id])
        : st === current ? `<li class="pending"><span class="ic"><span class="spin" aria-hidden="true"></span></span><strong>${esc(st.label)}</strong><span class="d">${prog[st.id] ? `${num(prog[st.id].done)} of ${num(prog[st.id].total)} accounts checked` : "Checking…"}</span>${prog[st.id] ? `<span class="meter" aria-hidden="true"><i style="width:${(100 * prog[st.id].done / prog[st.id].total).toFixed(1)}%"></i></span>` : ""}</li>`
        : `<li class="wait"><span class="ic" aria-hidden="true">·</span><strong>${esc(st.label)}</strong></li>`).join("");
      if (current) {
        $("#aBusy .busy-text").textContent = `Step ${n + 1} of ${steps.length}: ${current.label}` +
          (current.id === "identity" ? " (approve Touch ID if prompted)" : "") +
          (prog[current.id] ? `: ${num(prog[current.id].done)} of ${num(prog[current.id].total)} accounts` : "");
      }
      const frac = current && prog[current.id] ? prog[current.id].done / prog[current.id].total : 0.5;
      busyProgress("#aBusy", steps.length ? (n + frac) / steps.length : 0);
    };
    try {
      let r = null;
      await apiStream("/api/access-check?stream=1", { profile: $("#aProfile").value || null, role_name: $("#aRole").value || null }, (msg) => {
        if (msg.steps) steps = msg.steps;
        if (msg.check) done[msg.check.id] = msg.check;
        if (msg.progress) prog[msg.progress.id] = msg.progress;
        if (msg.result) r = msg.result;
        if (msg.error) throw new Error(msg.error);
        if (!msg.result) drawSteps();
      });
      if (!r) throw new Error("The access check stopped before it finished. See Settings → Application log.");
      busyProgress("#aBusy", 1);
      $("#aChecks").innerHTML = r.checks.map(checkRow).join("");
      $("#aVerdict").textContent = r.verdict;
      $("#aVerdict").hidden = false;
      $("#aVerdict").style.color = css(r.ready ? "--good" : r.partial ? "--warn-ink" : "--sev-critical");
      const needsAdmin = r.checks.some((c) => c.status !== "ok" && c.status !== "skip" && c.needs) || !r.ready;
      $("#aAdmin").hidden = !needsAdmin || r.checks[0].status !== "ok";
      $("#aAdminText").value = r.admin_request;
      $("#btnAccessScan").disabled = !(r.ready || r.partial);
      // Once a scan can start, that is the next step: Check access steps back to a plain button.
      $("#btnAccessRun").classList.toggle("primary", $("#btnAccessScan").disabled);
      if (r.management_account_id) state.mgmtAccount = r.management_account_id;
      if (r.ready) {
        try { localStorage.setItem(LS_ORG_PROFILE, $("#aProfile").value); } catch { /* ignore */ }
        api("/api/org", { method: "POST", body: { profile: $("#aProfile").value || null } }).catch(() => {}); // warm the OU list for the scan dialog
      }
      // Member account but a local profile points at the management account: offer a one-click switch.
      const mgmtProfile = r.management_account_id && r.account_id !== r.management_account_id &&
        Object.entries(state.profileAccounts || {}).find(([, acct]) => acct === r.management_account_id)?.[0];
      $("#aSwitch").hidden = !mgmtProfile;
      if (mgmtProfile) {
        $("#aSwitch").innerHTML = `<strong>${esc(mgmtProfile)}</strong> on this machine is in the management account ${esc(r.management_account_id)}. <button type="button" class="btn primary" id="btnASwitch">Use ${esc(mgmtProfile)} and re-check</button>`;
        $("#btnASwitch").addEventListener("click", () => { $("#aProfile").value = mgmtProfile; runAccessCheck(); });
      }
    } catch (e) { $("#aError").textContent = e.message; }
    finally { $("#btnAccessRun").disabled = false; busy("#aBusy", null); }
  }

  async function copyAdmin() {
    try { await navigator.clipboard.writeText($("#aAdminText").value); toast("Copied - paste it into an email or ticket"); }
    catch { $("#aAdminText").select(); document.execCommand("copy"); toast("Copied"); }
  }

  function saveAdmin() {
    const url = URL.createObjectURL(new Blob([$("#aAdminText").value], { type: "text/plain" }));
    const a = Object.assign(document.createElement("a"), { href: url, download: "aws-access-request-exit-risk-review.txt" });
    document.body.append(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  async function refreshGettingStarted() {
    try {
      const { profiles } = await api("/api/profiles");
      $("#gsProfiles").textContent = profiles.length ? `or use one of ${profiles.length} AWS profile(s) on this machine` : "No AWS CLI profiles found - sign in with SSO";
    } catch { /* the step still works without the count */ }
  }

  // ------------------------------------------------------------------ boot
  // Every control is wired before the first request, so the buttons work while a large report loads
  // and still work (New scan, AWS sign-in, Log) when the console cannot load one.
  function bindControls() {
    $("#scanSelect").addEventListener("change", (e) => {
      state.scanId = e.target.value;
      state.mrShowAll = false;
      // Each scan remembers the exit target chosen when it was started.
      const t = (state.scans || []).find((s) => s.id === state.scanId)?.target;
      if (t) { $("#qForm").target.value = t; syncDatacenter(); }
      loadReport();
    });
    $("#btnApply").addEventListener("click", loadReport);
    $("#fWeighting").addEventListener("change", loadReport);
    $("#fMinRating").addEventListener("change", () => {
      const url = new URL(location.href);
      if ($("#fMinRating").value) url.searchParams.set("min_rating", $("#fMinRating").value); else url.searchParams.delete("min_rating");
      history.replaceState(null, "", url);
      if (state.report) renderAccountTable(state.report, Math.max(...state.report.accounts.map((a) => a.spend_at_risk), 0.01));
    });
    for (const id of ["#fInclude", "#fExclude"]) $(id).addEventListener("keydown", (e) => { if (e.key === "Enter") loadReport(); });
    // Any answer, or "these answers are right", makes the estimate the organisation's own.
    const confirmAnswers = () => { state.answersFromLink = false; $("#qForm").confirmed.value = "true"; syncDatacenter(); loadReport(); };
    $("#btnRecalc").addEventListener("click", confirmAnswers);
    $("#qForm").addEventListener("change", confirmAnswers);
    for (const id of ["#resForm", "#timeForm"]) {
      $(id).addEventListener("change", loadReport);
      $(id).addEventListener("submit", (ev) => { ev.preventDefault(); loadReport(); });
    }
    // Exit model: one top-level dialog holds every answer; each report section links to its part.
    const openModel = (formId = "qForm") => {
      $("#modelDialog").showModal();
      const f = $(`#${formId}`);
      f.scrollIntoView({ block: "nearest" });
      f.querySelector("input:not([type=hidden]), select")?.focus({ preventScroll: true });
    };
    $("#btnModel").addEventListener("click", () => openModel());
    // The top bar wraps on narrow screens, so track its real height for scroll-padding-top.
    const topbar = document.querySelector(".topbar");
    new ResizeObserver(() => {
      document.documentElement.style.setProperty("--topbar-h", `${topbar.offsetHeight}px`);
    }).observe(topbar);
    $("#btnIssues").addEventListener("click", () => {
      setView("exit");
      $("#sec-issues").scrollIntoView({ behavior: "smooth", block: "start" });
    });
    // Exclusions: tick in a draft, then apply once; closing without applying discards the draft.
    $("#btnExcl").addEventListener("click", () => {
      if (!state.report) { toast("Load a scan first"); return; }
      state.exclDraft = new Set(state.exclude);
      $("#exclFilter").value = "";
      renderExclusions(state.report);
      $("#exclDialog").showModal();
    });
    $("#exclDialog").addEventListener("close", () => { state.exclDraft = null; });
    $("#exclFilter").addEventListener("input", () => state.report && renderExclusions(state.report));
    $("#exclFilter").addEventListener("keydown", (e) => { if (e.key === "Enter") e.preventDefault(); });
    $("#exclList").addEventListener("change", (e) => {
      const svc = e.target.dataset.svc;
      if (!svc || !state.exclDraft) return;
      if (e.target.checked) state.exclDraft.add(svc); else state.exclDraft.delete(svc);
      renderExclusions(state.report);
    });
    $("#btnExclClear").addEventListener("click", () => { state.exclDraft = new Set(); renderExclusions(state.report); });
    for (const id of ["#btnExclCancel", "#btnExclX"]) $(id).addEventListener("click", () => $("#exclDialog").close());
    $("#btnExclApply").addEventListener("click", async () => {
      state.exclude = new Set(state.exclDraft);
      $("#exclDialog").close();
      readQuestionnaire();
      if (!(await loadReport())) return;
      const n = state.exclude.size;
      toast(n ? `Regenerated without ${plural(n, "product")}` : "Regenerated with every product");
    });
    $("#btnAnswerQs").addEventListener("click", (ev) => { ev.preventDefault(); openModel(); });
    $("#briefConfSteps").addEventListener("click", async (ev) => {
      const action = ev.target.closest("[data-conf-action]")?.dataset.confAction;
      if (action === "model") openModel();
      else if (action === "scan" || action === "deep") {
        await openScanDialog();
        if (action === "deep") { $("#sDepth").value = "dependency"; $("#sDepth").dispatchEvent(new Event("change", { bubbles: true })); $("#sDepth").focus(); }
      }
    });
    document.querySelectorAll("[data-model]").forEach((b) => b.addEventListener("click", () => openModel(b.dataset.model)));
    for (const id of ["#btnCloseModel", "#btnCloseModelX"]) $(id).addEventListener("click", () => $("#modelDialog").close());
    $("#btnAcctMore").addEventListener("click", () => {
      state.showAllAccounts = !state.showAllAccounts;
      renderAccountTable(state.report, Math.max(...state.report.accounts.map((a) => a.spend_at_risk), 0.01));
    });
    $("#btnDemo").addEventListener("click", async () => {
      try { const { id } = await api("/api/scans/demo", { method: "POST" }); await refreshScans(id); state.scanId = id; if (await loadReport()) toast("Loaded synthetic demo organisation"); }
      catch (e) { toast(e.message); }
    });
    $("#btnPdf").addEventListener("click", () => {
      if (!state.report) { toast("Load a scan first"); return; }
      toast("Choose “Save as PDF” in the print dialog. For a scripted PDF: exitrisk pdf <scan-id>", 6000);
      setTimeout(() => window.print(), 300);
    });
    $("#btnOnePage").addEventListener("click", () => {
      if (!state.report) { toast("Load a scan first"); return; }
      if (state.view === "multiregion") setView("exit"); // the one-page summary is the exit-risk report
      document.body.classList.add("onepage");
      toast("Choose “Save as PDF” in the print dialog. For a scripted PDF: exitrisk pdf <scan-id> --onepage", 6000);
      setTimeout(() => window.print(), 300);
    });
    window.addEventListener("afterprint", () => { if (params.get("onepage") !== "1") document.body.classList.remove("onepage"); });
    // Top-bar menus (Export PDF, Settings): one open at a time; Escape or a click outside closes.
    const menus = [...document.querySelectorAll(".menu")];
    const closeMenus = (except) => {
      for (const m of menus) {
        if (m === except) continue;
        m.querySelector(".menu-pop").hidden = true;
        m.querySelector("[aria-haspopup]").setAttribute("aria-expanded", "false");
      }
    };
    for (const m of menus) {
      const btn = m.querySelector("[aria-haspopup]");
      const pop = m.querySelector(".menu-pop");
      btn.addEventListener("click", (e) => {
        e.stopPropagation();
        closeMenus(m);
        pop.hidden = !pop.hidden;
        btn.setAttribute("aria-expanded", String(!pop.hidden));
        if (!pop.hidden) pop.querySelector("button")?.focus();
      });
      pop.addEventListener("click", (e) => { if (e.target.closest("[role=menuitem]")) closeMenus(); });
    }
    document.addEventListener("click", (e) => { if (!e.target.closest(".menu-pop")) closeMenus(); });
    document.addEventListener("keydown", (e) => { if (e.key === "Escape") closeMenus(); });
    const markTheme = () => {
      const t = document.documentElement.dataset.theme || "";
      for (const b of document.querySelectorAll("[data-theme-pick]")) b.setAttribute("aria-pressed", String(b.dataset.themePick === t));
    };
    markTheme();
    for (const b of document.querySelectorAll("[data-theme-pick]")) {
      b.addEventListener("click", () => {
        const t = b.dataset.themePick;
        applyTheme(t);
        try { if (t) localStorage.setItem(LS_THEME, t); else localStorage.removeItem(LS_THEME); } catch { /* ignore */ }
        markTheme();
        chartDefaults();
        if (state.report) render();
      });
    }
    matchMedia("(prefers-color-scheme: dark)").addEventListener("change", () => {
      if (document.documentElement.dataset.theme) return;
      chartDefaults();
      if (state.report) render();
    });
    $("#btnNewScan").addEventListener("click", () => openScanDialog());
    $("#btnSso").addEventListener("click", openSsoDialog);
    $("#btnGsSso").addEventListener("click", openSsoDialog);
    $("#btnGsCheck").addEventListener("click", () => openAccessDialog());
    $("#btnGsScan").addEventListener("click", () => openScanDialog());
    $("#lnkDemo").addEventListener("click", (e) => { e.preventDefault(); $("#btnDemo").click(); });
    $("#btnScanCheck").addEventListener("click", () => openAccessDialog($("#sProfile").value, true));
    $("#btnAccessRun").addEventListener("click", runAccessCheck);
    $("#btnAdminCopy").addEventListener("click", copyAdmin);
    $("#btnAdminSave").addEventListener("click", saveAdmin);
    $("#btnAccessScan").addEventListener("click", () => { const p = $("#aProfile").value; $("#accessDialog").close(); openScanDialog(p); });
    refreshGettingStarted();
    $("#lnkSso").addEventListener("click", openSsoDialog);
    $("#ssoSession").addEventListener("change", showSsoState);
    $("#ssoAccount").addEventListener("change", () => loadSsoRoles($("#ssoRole").value));
    $("#btnSsoLogin").addEventListener("click", ssoLogin);
    $("#btnSsoAddToggle").addEventListener("click", () => { $("#ssoAdd").hidden = !$("#ssoAdd").hidden; });
    $("#btnSsoAdd").addEventListener("click", ssoAddPortal);
    $("#btnSsoUse").addEventListener("click", ssoUse);
    $("#btnSsoLogout").addEventListener("click", ssoLogout);
    $("#ssoDialog").addEventListener("close", () => clearInterval(sso.loginTimer));
    refreshSsoBadge();
    // An SSO sign-in lasts hours: check again every few minutes so the button flashes once it expires.
    setInterval(refreshSsoBadge, 5 * 60 * 1000);
    $("#btnLoadOus").addEventListener("click", loadOus);
    $("#sOu").addEventListener("change", syncOus);
    $("#sProfile").addEventListener("change", loadOus);
    $("#btnStartScan").addEventListener("click", startScan);
    // Enter in a text field acts, rather than submitting the dialog form (whose first button is Close).
    const enterDoes = (form, fn) => $(form).addEventListener("keydown", (e) => {
      if (e.key === "Enter" && e.target.matches("input:not([type=checkbox]):not([type=radio])")) { e.preventDefault(); fn(e.target); }
    });
    enterDoes("#scanForm", () => { if (!$("#btnStartScan").disabled) startScan(); });
    enterDoes("#ssoForm", (el) => { if (el.closest("#ssoAdd")) ssoAddPortal(); });
    enterDoes("#accessForm", () => runAccessCheck());
    $("#sDepth").addEventListener("change", (e) => {
      $("#invOpts").hidden = e.target.value === "quick";
      $("#sDepthHint").textContent = DEPTH_HINT[e.target.value];
    });
    $("#showAllCatalog").addEventListener("change", () => state.report && renderAppendix(state.report));
    $("#btnLogs").addEventListener("click", openLog);
    $("#btnAi").addEventListener("click", openAi);
    $("#btnAiClose").addEventListener("click", () => $("#aiDialog").close());
    $("#btnAiTest").addEventListener("click", testAi);
    $("#btnAiTestAll").addEventListener("click", testAllAi);
    $("#btnAiRun").addEventListener("click", runAi);
    $("#btnAiStop").addEventListener("click", () => api(`/api/ai/review/${encodeURIComponent(state.scanId)}`, { method: "DELETE" }).catch(() => {}));
    $("#aiProvider").addEventListener("change", () => aiProviderChanged(""));
    $("#aiModel").addEventListener("change", () => { $("#aiCustomWrap").hidden = $("#aiModel").value !== AI_CUSTOM; if (!$("#aiCustomWrap").hidden) $("#aiCustom").focus(); });
    $("#aiMask").addEventListener("change", () => { $("#aiMask").dataset.touched = "1"; });
    $("#aiKey").addEventListener("change", () => loadAiModels());
    $("#btnAiShowKey").addEventListener("click", toggleAiKey);
    $("#aiHeaders").addEventListener("input", () => { $("#aiHeaders").dataset.touched = "1"; });
    for (const id of ["#aiBaseUrl", "#aiKeyHeader", "#aiHeaders"]) $(id).addEventListener("change", () => loadAiModels());
    $("#aiForm").addEventListener("submit", (e) => e.preventDefault());
    $("#btnCompare").addEventListener("click", openCompare);
    $("#btnSchedule").addEventListener("click", openSchedule);
    $("#btnSchedBannerOpen").addEventListener("click", openSchedule);
    $("#btnSchedClose").addEventListener("click", () => $("#schedDialog").close());
    $("#btnSchedSave").addEventListener("click", saveSchedule);
    $("#btnSchedOff").addEventListener("click", scheduleOff);
    $("#btnSchedRun").addEventListener("click", scheduleRunNow);
    if (!PRINT) refreshSchedule();
    $("#cmpBefore").addEventListener("change", runCompare);
    $("#cmpAfter").addEventListener("change", runCompare);
    $("#btnCmpClose").addEventListener("click", () => $("#compareDialog").close());
    $("#logThisRun").addEventListener("change", openLog);
    $("#btnCloseLog").addEventListener("click", () => $("#logDialog").close());
    window.addEventListener("beforeprint", () => Object.values(state.charts).forEach((c) => c.resize()));
    window.addEventListener("afterprint", () => requestAnimationFrame(redrawCharts));
    window.addEventListener("pageshow", (e) => { if (e.persisted) redrawCharts(); });
    document.addEventListener("visibilitychange", () => { if (!document.hidden) redrawCharts(); });
    document.querySelectorAll("canvas").forEach((c) => c.addEventListener("contextrestored", redrawCharts));
  }

  async function boot() {
    const unexpected = (what, detail) => {
      console.error(what, detail);
      if (!PRINT) toast("Something went wrong in the console. Settings › Application log has the details.", 6000);
    };
    window.addEventListener("error", (e) => unexpected("ui error", e.message));
    window.addEventListener("unhandledrejection", (e) => unexpected("ui promise error", e.reason));
    chartDefaults();
    bindControls();
    const failed = (e) => {
      toast(e.message, 8000);
      if (PRINT) { document.body.dataset.error = e.message; document.body.dataset.ready = "1"; }
    };
    try {
      [state.options, state.catalog] = await Promise.all([api("/api/options"), api("/api/catalog")]);
    } catch (e) { failed(e); return; }
    fillQuestionnaire(loadQuestionnaire());
    state.view = params.get("view") === "multiregion" ? "multiregion" : "exit";
    document.body.dataset.view = state.view;
    for (const b of document.querySelectorAll(".vtab")) b.setAttribute("aria-pressed", String(b.dataset.view === state.view));
    bindMultiRegion();
    if (["balanced", "spend", "equal"].includes(params.get("weighting"))) $("#fWeighting").value = params.get("weighting");
    if (["Moderate", "High"].includes(params.get("min_rating"))) $("#fMinRating").value = params.get("min_rating");
    for (const k of ["include", "exclude", "mode"]) if (params.get(k)) $(`#f${k[0].toUpperCase()}${k.slice(1)}`).value = params.get(k);

    let scans;
    try { scans = await refreshScans(); } catch (e) { failed(e); return; }
    state.scanId = params.get("scan") || scans.find((s) => s.status !== "failed")?.id || null;
    if (state.scanId) { $("#scanSelect").value = state.scanId; await loadReport(); }
    else document.body.dataset.ready = "1";

  }

  document.addEventListener("DOMContentLoaded", boot);
})();
