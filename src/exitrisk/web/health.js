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
    const hits = state.accounts.filter((a) => !q || a.id.includes(q) || `${a.name || ""} ${a.owner || ""} ${a.executive || ""}`.toLowerCase().includes(q));
    const shown = hits.slice(0, 200);
    $("#hcAcctList").innerHTML = shown.length
      ? shown.map((a) => `<label><input type="checkbox" value="${esc(a.id)}" ${state.chosen.has(a.id) ? "checked" : ""}> <span>${esc(a.name || a.id)}</span>${owner(a)}<span class="id">${esc(a.id)}</span></label>`).join("")
        + (hits.length > shown.length ? `<label class="muted">${hits.length - shown.length} more: type more of the name or number</label>` : "")
      : `<label class="muted">${state.accounts.length ? "No account matches" : "No accounts found"}</label>`;
  }

  function owner(a) {
    if (!a.owner && !a.executive) return "";
    const exec = a.executive && a.executive !== a.owner ? ` · exec ${a.executive}` : "";
    return `<span class="hc-owner">${esc(a.owner || "no owner tag")}${esc(exec)}</span>`;
  }

  // The earlier report banner says whether it covers the accounts ticked now; ticks change after it shows.
  function bannerTail() {
    const tail = document.querySelector(".hc-banner-tail");
    if (!tail) return;
    const picked = [...state.chosen.keys()].sort().join(",");
    tail.innerHTML = picked && picked !== state.reportAccounts
      ? "It does <b>not</b> cover the accounts ticked above: press <b>Run health check</b> for those."
      : "Press <b>Run health check</b> above for a fresh one.";
  }

  function renderChosen() {
    bannerTail();
    const box = $("#hcChosen");
    box.innerHTML = state.chosen.size
      ? [...state.chosen.values()].map((a) => `<span class="chip">${esc(a.name || a.id)} <span class="muted">${esc(a.id)}${a.owner ? ` · ${esc(a.owner)}` : ""}</span><button type="button" data-id="${esc(a.id)}" aria-label="Remove ${esc(a.name || a.id)}">×</button></span>`).join("")
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
      follow(job.id, body.accounts.map((a) => a.name || a.id).join(", "));
      $("#hcReport").scrollIntoView({ behavior: "smooth", block: "nearest" });
    } catch (e) {
      $("#hcError").textContent = e.message;
    }
  }

  function ago(iso) {
    const m = Math.round((Date.now() - new Date(iso).getTime()) / 60000);
    if (!Number.isFinite(m)) return "";
    if (m < 1) return "just now";
    if (m < 60) return `${m} min ago`;
    const h = Math.round(m / 60);
    return h < 48 ? `${h} hour${h > 1 ? "s" : ""} ago` : `${Math.round(h / 24)} days ago`;
  }

  // While a run is going, the report area says so: an earlier report left in view reads as the new one.
  function runningCard() {
    const names = state.runNames;
    return `<section class="card hc-running" role="status" aria-live="polite">
        <div class="busy-head"><span class="spin" aria-hidden="true"></span><span>Running a new health check${names ? ` of <b>${esc(names)}</b>` : ""}</span></div>
        <p>The new report replaces this panel when it finishes, usually in 2 to 10 minutes. Progress is shown above.${state.reportId ? " The report below is an earlier one." : ""}</p>
        <span class="busy-bar"><i></i></span>
      </section>`;
  }

  function showRunning() {
    state.reportId = null;
    $("#btnPdf").disabled = true;
    $("#hcReport").innerHTML = runningCard();
  }

  function follow(id, names = "") {
    state.runId = id;
    state.followed = id;
    state.runNames = names;
    showRunning();
    $("#hcRun").disabled = true;
    $("#hcStop").hidden = false;
    $("#hcProgress").hidden = false;
    clearTimeout(state.poll);
    const tick = async () => {
      try {
        const r = await api(`/api/health-check/${encodeURIComponent(id)}`);
        const run = r.run;
        if (!state.runNames && run.accounts?.length) {
          state.runNames = run.accounts.join(", ");
          const head = document.querySelector(".hc-running .busy-head span:last-child");
          if (head) head.innerHTML = `Running a new health check of <b>${esc(state.runNames)}</b>`;
        }
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
    $("#hcReport").scrollIntoView({ behavior: "smooth", block: "start" });
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
    const accts = r.accounts.map((a) => `${esc(a.name || a.id)} <span class="muted">${esc(a.id)}${a.owner ? ` · owner ${esc(a.owner)}` : ""}${a.executive && a.executive !== a.owner ? ` · executive ${esc(a.executive)}` : ""}</span>`).join(", ");
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
    // Which report this is, impossible to miss: the one just run, or an earlier one (and for which accounts).
    const fresh = r.id === state.followed;
    const names = r.accounts.map((a) => a.name || a.id).join(", ");
    state.reportAccounts = r.accounts.map((a) => a.id).sort().join(",");
    const banner = fresh
      ? `<div class="hc-banner fresh"><b>New report</b>, just finished at ${when(r.finished || r.created)}.</div>`
      : `<div class="hc-banner old"><b>Earlier report</b> from ${when(r.created)} (${ago(r.created)}) of <b>${esc(names)}</b>. <span class="hc-banner-tail"></span></div>`;
    $("#hcReport").innerHTML = `${state.runId && state.runId !== r.id ? runningCard() : ""}
      <section class="card">
        ${banner}
        <div class="card-head"><h2>Health check: ${esc(names)}</h2><span class="muted small">window ${when(r.window?.start)} to ${when(r.window?.end)} (${esc(r.window?.hours)} h) · run ${when(r.created)}</span></div>
        <p>${accts}</p>
        ${r.symptoms ? `<p class="muted"><b>Symptoms given:</b> ${esc(r.symptoms)}</p>` : ""}
        ${status}
        ${r.unreachable?.length ? `<p class="error-text">Not reached: ${r.unreachable.map((u) => `${esc(u.name || u.account)} (${esc(u.code)}: ${esc(u.message)})`).join("; ")}</p>` : ""}
        ${intro(`<b>About this report.</b> A read only health check of the AWS account${r.accounts.length > 1 ? "s" : ""} above over the last ${esc(r.window?.hours)} hours, in every region in use. It reads alarms, AWS Health, CloudTrail changes and refused calls, load balancers, containers, functions, databases, queues, networks, certificates, DNS, VPC flow logs, error spikes in the busiest log groups, and service quotas. Each finding is compared with the same hours a day earlier, so new problems stand apart from ones that were already there. Nothing in the accounts was changed.`)}
        <div class="tiles" style="grid-template-columns:repeat(6,minmax(0,1fr))">${tiles.map(([l, v, t, tip]) => `<div class="tile ${t}" title="${esc(tip)}"><div class="tile-label">${l}</div><div class="tile-value">${v}</div></div>`).join("")}</div>
        <dl class="hc-legend">${tiles.map(([l, , , tip]) => `<dt>${l}</dt><dd>${esc(tip)}</dd>`).join("")}</dl>
      </section>

      <section class="card">
        <h2>Top ${top.length || 10} issues</h2>
        ${intro(`<b>What this is.</b> The issues most worth acting on, most critical first. Where several findings tell one story (a change followed by errors), they are joined into one row and the others are listed under <i>Why</i>.
          <ul>
            <li><b>Severity</b> (coloured dot): how bad the finding is in itself. Critical means something is down or refusing work; high means failing or close to it; medium means degraded; low means minor.</li>
            <li><b>Outage likelihood</b>: how likely the issue is to cause an outage users feel, or to be one already. <i>High</i>: failing now and new since yesterday, or it started just before failures it can cause. <i>Medium</i>: pressure that becomes an outage if it grows, or a fault that has stood for over a day. <i>Low</i>: minor, or running at the same level a day earlier without harm. The reason is given under each rating.</li>
            <li><b>Tags</b>: <i>still happening</i> means it was still present at the end of the window; <i>long standing</i> means it was at about the same level a day earlier; <i>unexplained symptom</i> means a failure with no change or AWS event found that explains it; <i>change</i> means a change made by a person or pipeline.</li>
            <li><b>Started</b>: when it first showed in the window; <i>before the window</i> means it was already happening when the window began.</li>
          </ul>
          These are leads, not verdicts: confirm each with its next step before acting.`)}
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
        <h2>Everything found (${r.signals.length})</h2>
        ${intro(`<b>What this is.</b> Every finding the check made, before ranking, so a reader can see the full picture behind the top issues. Each row is a measured fact: an error rate, a count of unhealthy targets, a throttle count, an alarm, a resource in a failed state. Many alike in one place (a dozen throttled functions) are shown once with a count, since they nearly always share a cause.`)}
        <details class="hc-more" open><summary>Show the ${r.signals.length} findings</summary>
        ${signalsTable(r.signals)}</details>
      </section>` : ""}

      ${(r.risks || []).length ? `<section class="card">
        <h2>Other issues in ${r.accounts.length > 1 ? "these accounts" : "this account"} (${r.risks.length})</h2>
        ${intro(`<b>What this is.</b> Weaknesses that are not failing now but could cause the next outage, from the same checks as the Outage Risk report: service limits nearly reached, single points of failure (one zone, one instance, one NAT gateway), resources running hot, and clusters or databases one fault away from trouble. Worst first. These are worth planning work for, separately from any live incident.`)}
        <div class="table-wrap"><table class="data compact"><thead><tr><th>Severity</th><th>Issue</th><th>Resource</th><th>Why</th><th>Where</th></tr></thead><tbody>
          ${r.risks.map((x) => `<tr><td>${sev(x.severity)}</td><td class="small"><b>${esc(x.title)}</b><div class="muted">${esc(x.service_label || "")}</div></td><td class="small">${esc(x.res || "")}${x.note ? `<div class="muted">${esc(x.note)}</div>` : ""}</td><td class="small">${esc(x.why || "")}</td><td class="small">${esc(x.account_name || x.account)}<div class="muted">${esc(x.region || "")}</div></td></tr>`).join("")}
        </tbody></table></div>
      </section>` : ""}

      ${(r.readiness || []).length ? `<section class="card">
        <h2>Turn on to see more (${r.readiness.length})</h2>
        ${intro(`<b>What this is.</b> Logging and monitoring that is switched off in these accounts, so a fault in that area cannot be seen by this check or by anyone diagnosing an incident. For example, VPC flow logs show refused network connections and DNS query logs show failed name lookups. Turning them on costs a little and only covers activity from then on, so it is best done before the next incident.`)}
        <div class="table-wrap"><table class="data compact"><thead><tr><th>What is off</th><th>What it hides</th><th>How to turn it on</th><th>Where</th></tr></thead><tbody>
          ${r.readiness.map((x) => `<tr><td class="small"><b>${esc(x.item)}</b></td><td class="small">${esc(x.why)}</td><td class="small">${esc(x.how)}${x.permission ? `<div class="muted">Needs ${esc(x.permission)}</div>` : ""}</td><td class="small">${esc(x.account_name || x.account)}<div class="muted">${esc(x.region)}</div></td></tr>`).join("")}
        </tbody></table></div>
      </section>` : ""}

      ${r.changes.length ? `<section class="card">
        <h2>Changes in the window (${r.changes.length})</h2>
        ${intro(`<b>What this is.</b> Changes made by people or pipelines during the window that can affect availability, read from CloudTrail: deletes, stops, detaches, scaling and configuration changes, permission and network changes. Changes AWS makes itself are left out. Those marked <i>risky</i> can break things straight away (a delete, a revoked permission, a failover). Repeats of one action are grouped with a count. A change is not a fault in itself; it matters when a failure follows it, and the top issues show that link when there is one.`)}
        <details class="hc-more"><summary>Show the ${r.changes.length} changes</summary>
        ${changesTable(r.changes)}</details>
      </section>` : ""}

      ${r.timeline.length ? `<section class="card">
        <h2>Timeline (${r.timeline.length})</h2>
        ${intro(`<b>What this is.</b> New findings and changes in time order, to show what happened first. A failure that starts a few minutes after a change or an AWS event is often caused by it. Long standing problems are left out, since they did not start in the window.`)}
        <details class="hc-more"><summary>Show the timeline</summary>
        ${r.timeline.length ? `<div class="table-wrap"><table class="data compact"><thead><tr><th>When</th><th>What</th><th>Kind</th><th>Account</th><th>Region</th></tr></thead><tbody>
          ${r.timeline.map((t) => `<tr><td class="nowrap small">${when(t.time)}</td><td class="small">${sev(t.severity)} ${esc(t.what)}</td><td class="small">${esc(t.kind)}</td><td class="small">${esc(t.account)}</td><td class="small">${esc(t.region)}</td></tr>`).join("")}
        </tbody></table></div>` : ""}</details>
      </section>` : ""}

      <section class="card">
        <h2>Coverage</h2>
        ${intro(`<b>What this is.</b> What the check could and could not read. ${r.gaps.length ? "Each row below is a check that was refused or failed in one place, with the reason and the fix. A cause hidden there would not appear in this report, so read the findings above with that in mind." : "Every check ran everywhere, so nothing in scope was hidden from it."}`)}
        ${r.gaps.length ? `<h3>Could not check (${r.gaps.length})</h3><div class="table-wrap"><table class="data compact"><thead><tr><th>Check</th><th>Account</th><th>Region</th><th>Reason</th></tr></thead><tbody>
          ${r.gaps.map((g) => `<tr><td class="small">${esc(g.check)}</td><td class="small">${esc(g.account_name || g.account)}</td><td class="small">${esc(g.region)}</td><td class="small"><b>${esc(g.code)}</b> ${esc(g.message)}${g.hint ? `<div class="muted">${esc(g.hint)}</div>` : ""}</td></tr>`).join("")}
        </tbody></table></div>` : `<p class="muted small">Every check ran in every region in use (${r.accounts.map((a) => `${esc(a.name || a.id)}: ${a.regions.map(esc).join(", ")}`).join("; ")}).</p>`}
        <p class="muted small">Checks: ${r.checks.map(esc).join(", ")}.${s.scanned_gb ? ` Logs Insights read ${esc(s.scanned_gb)} GB (about US$${(s.scanned_gb * 0.005).toFixed(2)}).` : ""}</p>
      </section>
      <p class="report-footer">AWS Cloud Risk Review · Health Check ${esc(r.id)}</p>`;
    for (const tr of document.querySelectorAll("#hcRuns tr[data-id]")) tr.classList.toggle("chosen", tr.dataset.id === r.id);
    bannerTail();
  }

  // A plain words explanation above each part, so the report reads well when sent to someone who never ran it.
  function intro(html) { return `<div class="hc-intro">${html}</div>`; }

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
  // Printing from the browser menu too: hidden sections must be on paper.
  window.addEventListener("beforeprint", () => { for (const d of document.querySelectorAll("details.hc-more")) d.open = true; });
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
