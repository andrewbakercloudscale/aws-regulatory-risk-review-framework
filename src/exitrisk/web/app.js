/* AWS Exit Risk Review - dashboard client.
 * Talks to the local API (see server.py). Every value from the API is escaped before it
 * reaches the DOM: account names and error messages come from AWS and are not trusted HTML.
 */
(() => {
  "use strict";

  const params = new URLSearchParams(location.search);
  const PRINT = params.get("print") === "1";
  const LS_Q = "exitrisk.questionnaire.v1";
  const LS_THEME = "exitrisk.theme";
  const LS_ORG_PROFILE = "exitrisk.orgProfile"; // last profile that could read the OU tree
  const MGMT_RE = /mgmt|management|payer|master|org/i;
  const state = { scanId: null, report: null, catalog: null, options: null, charts: {}, pollTimer: null };

  // ------------------------------------------------------------------ utils
  const $ = (sel) => document.querySelector(sel);
  const esc = (v) => String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  const css = (name) => getComputedStyle(document.documentElement).getPropertyValue(name).trim();
  const tierColor = (t) => css(`--t${t}`);
  const RATING_TIER = { Low: 1, Moderate: 2, Elevated: 3, High: 4, Critical: 5 };
  const SEV_COLOR = { critical: "--sev-critical", error: "--sev-error", warning: "--sev-warning", info: "--sev-info" };

  function money(v, cur = "USD", digits) {
    if (v == null || isNaN(v)) return "–";
    const abs = Math.abs(v);
    const sym = cur === "USD" ? "$" : cur + " ";
    if (abs >= 1e6) return `${sym}${(v / 1e6).toFixed(digits ?? 1)}m`;
    if (abs >= 1e4) return `${sym}${(v / 1e3).toFixed(0)}k`;
    if (abs >= 1e3) return `${sym}${(v / 1e3).toFixed(1)}k`;
    return `${sym}${v.toFixed(0)}`;
  }
  const num = (v, d = 0) => (v == null || isNaN(v) ? "–" : Number(v).toLocaleString(undefined, { maximumFractionDigits: d, minimumFractionDigits: d }));
  const pct = (v, d = 0) => (v == null ? "–" : `${Number(v).toFixed(d)}%`);
  const plural = (n, word, many) => `${num(n)} ${Math.round(n) === 1 ? word : many || word + "s"}`;
  // "2025-10" -> "Oct 2025" (or "Oct 25" for chart axes).
  const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
  function month(m, short) {
    const [y, mo] = String(m || "").split("-").map(Number);
    if (!y || !mo) return String(m ?? "–");
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
    "contingency_pct", "parallel_run_months", "materiality"];

  function loadQuestionnaire() {
    let q = { ...(state.options?.defaults || {}) };
    try { Object.assign(q, JSON.parse(localStorage.getItem(LS_Q) || "{}")); } catch { /* ignore */ }
    if (params.get("q")) {
      try { Object.assign(q, JSON.parse(params.get("q"))); } catch { console.warn("bad q param"); }
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
    for (const [k, v] of Object.entries(q)) {
      if (!f[k]) continue;
      if (f[k].type === "checkbox") f[k].checked = !!v; else f[k].value = v;
    }
  }

  function readQuestionnaire() {
    const f = $("#qForm");
    const q = {};
    for (const el of f.elements) {
      if (!el.name) continue;
      if (el.type === "checkbox") q[el.name] = el.checked;
      else if (el.name === "confirmed") q.confirmed = el.value === "true";
      else if (Q_NUM.includes(el.name)) q[el.name] = el.value === "" ? undefined : Number(el.value);
      else q[el.name] = el.name === "currency" ? el.value.toUpperCase() : el.value;
    }
    try { localStorage.setItem(LS_Q, JSON.stringify(q)); } catch { /* ignore */ }
    return q;
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

  async function loadReport() {
    if (!state.scanId) return;
    const filter = { include: $("#fInclude").value, exclude: $("#fExclude").value, mode: $("#fMode").value };
    const weighting = $("#fWeighting").value || "spend";
    $("#filterError").textContent = "";
    try {
      state.report = await api("/api/report", { method: "POST", body: { scan_id: state.scanId, filter, questionnaire: readQuestionnaire(), weighting } });
    } catch (e) {
      $("#filterError").textContent = e.message;
      toast(e.message);
      return;
    }
    const url = new URL(location.href);
    url.searchParams.set("scan", state.scanId);
    for (const [k, v] of Object.entries(filter)) { if (v && !(k === "mode" && v === "contains")) url.searchParams.set(k, v); else url.searchParams.delete(k); }
    if (weighting !== "spend") url.searchParams.set("weighting", weighting); else url.searchParams.delete("weighting");
    if ($("#fMinRating").value) url.searchParams.set("min_rating", $("#fMinRating").value); else url.searchParams.delete("min_rating");
    if (!PRINT) history.replaceState(null, "", url);
    render();
  }

  // ------------------------------------------------------------------ render
  function render() {
    const r = state.report;
    $("#empty").hidden = true;
    $("#content").hidden = false;
    renderCover(r);
    renderSummary(r);
    renderProfile(r);
    renderAccounts(r);
    renderServices(r);
    renderEstimate(r);
    renderIssues(r);
    renderAppendix(r);
    $("#footer").textContent = `Generated ${new Date(r.meta.generated_at).toLocaleString()} by aws-regulatory-risk-review-framework v${r.meta.tool_version} · catalog ${r.meta.catalog_version} · scan ${r.meta.scan_id}`;
    document.body.dataset.ready = "1";
  }

  function renderCover(r) {
    const m = r.meta;
    $("#title").textContent = m.mode === "demo" ? "AWS exit risk review — demo organisation" : `AWS exit risk review — ${m.ou?.path || "organisation"}`;
    $("#subtitle").textContent = m.mode === "demo"
      ? "Synthetic data for demonstration. Not a real organisation."
      : "How hard it would be to leave AWS, weighted by where the money is spent.";
    const items = [
      ["Scope", m.filter.description],
      ["Organizational unit", m.ou?.path || "–"],
      ["Accounts in scope", `${r.summary.accounts_in_scope} of ${r.summary.accounts_total}`],
      ["Spend period", m.months_in_data?.length ? `${month(m.months_in_data[0])} – ${month(m.months_in_data.at(-1))} (${plural(m.months_in_data.length, "month")}, amortised)` : "–"],
      ["Scanned", m.scanned_at ? new Date(m.scanned_at).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" }) : "–"],
      ["Management account", m.org?.management_account_id || m.identity?.account_id || "–"],
      ["Resource inventory", m.inventory ? "Included (deep scan)" : "Not run (spend only)"],
      ["Exit target assumed", m.target_label],
    ];
    const notes = r.summary.coverage || [];
    $("#coverage").hidden = !notes.length;
    $("#coverage").innerHTML = notes.map((n) => `<p>${esc(n)}</p>`).join("");
    $("#metaList").innerHTML = items.map(([k, v]) => `<div><dt>${esc(k)}</dt><dd>${esc(v)}</dd></div>`).join("");
  }

  function tile(label, value, sub, provisional) {
    return `<div class="tile${provisional ? " is-provisional" : ""}"><div class="tile-label">${esc(label)}</div><div class="tile-value">${esc(value)}${provisional ? ' <span class="prov-tag" title="Uses default answers: answer the questions in section 5">Provisional</span>' : ""}</div>${sub ? `<div class="tile-sub">${esc(sub)}</div>` : ""}</div>`;
  }

  function ratingBadge(el, rating, text) {
    el.textContent = text;
    el.style.setProperty("--dot", RATING_TIER[rating] ? tierColor(RATING_TIER[rating]) : css("--muted"));
  }

  function renderSummary(r) {
    const s = r.summary, e = r.estimate;
    $("#heroScore").textContent = s.score_by_spend == null ? "–" : Math.round(s.score_by_spend);
    ratingBadge($("#heroRating"), s.rating_by_spend, s.score_by_spend == null ? "No spend in scope" : s.rating_by_spend);
    $("#heroScoreAcc").textContent = s.score_by_accounts == null ? "–" : Math.round(s.score_by_accounts);
    ratingBadge($("#heroRatingAcc"), s.rating_by_accounts, s.score_by_accounts == null ? "–" : s.rating_by_accounts);
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
      tile("Spend on High/Critical services", pct(s.high_risk_pct), `${money(s.high_risk_monthly * 12)} a year`),
      tile("Accounts in scope", num(s.accounts_in_scope), `${num(s.accounts_with_spend)} with spend · ${num(s.accounts_excluded)} filtered out`),
      tile("High/Critical accounts", s.accounts_rated ? `${num(s.high_risk_accounts)} of ${num(s.accounts_rated)}` : "–",
        s.accounts_rated ? `${pct(s.high_risk_accounts_spend_pct)} of spend · ${num(s.portable_accounts)} portable (Low/Moderate)` : "No accounts with spend"),
      tile("Bespoke (AWS-only) services", num(s.bespoke_services), s.top_lockin_services.length ? `largest: ${s.top_lockin_services.slice(0, 3).map((x) => x.display).join(", ")}` : "none in use"),
      tile("Spend growth", s.growth?.total?.pct == null ? "–" : `${s.growth.total.pct > 0 ? "+" : ""}${num(s.growth.total.pct, 1)}%`,
        s.growth?.total ? `${month(s.growth.first_month)} → ${month(s.growth.last_month)} · High/Critical ${s.growth.lockin.pct > 0 ? "+" : ""}${num(s.growth.lockin.pct, 1)}%` : "needs 2+ months of history"),
      ...(e.empty ? [tile("Indicative exit cost", "–", "No spend in scope"), tile("Exit window (time to leave AWS)", "–", "No spend in scope"), tile("Engineering effort", "–", "No spend in scope")] : [
        // Ranges only: a single figure would claim precision an early-stage estimate does not have.
        tile("Exit cost (one-off)", e.ranges.cost, e.ranges.pct_of_annual_spend ? `${e.ranges.pct_of_annual_spend} of a year's AWS spend` : "engineering and parallel running", e.provisional),
        tile("Exit window (time to leave AWS)", e.ranges.duration, `bound by ${e.duration.constrained_by}`, e.provisional),
        tile("Engineering effort", e.ranges.effort, `team capacity ${num(e.team.capacity_fte, 1)} FTE`, e.provisional),
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
  }

  // Chart.js defaults - recessive chrome, thin marks, tooltips on.
  function chartDefaults() {
    const C = window.Chart;
    C.defaults.font.family = css("--font") || "system-ui";
    C.defaults.font.size = 12;
    C.defaults.color = css("--ink-2");
    C.defaults.borderColor = css("--grid");
    C.defaults.animation = PRINT ? false : { duration: 400 };
    C.defaults.maintainAspectRatio = false;
    C.defaults.plugins.legend.labels.boxWidth = 10;
    C.defaults.plugins.legend.labels.boxHeight = 10;
    C.defaults.plugins.legend.labels.useBorderRadius = true;
    C.defaults.plugins.legend.labels.borderRadius = 3;
    C.defaults.plugins.tooltip.backgroundColor = css("--ink");
    C.defaults.plugins.tooltip.titleColor = css("--surface");
    C.defaults.plugins.tooltip.bodyColor = css("--surface");
    C.defaults.plugins.tooltip.padding = 10;
    C.defaults.plugins.tooltip.cornerRadius = 6;
  }

  function chart(id, config) {
    if (!window.Chart) { console.error("Chart.js not loaded"); return; }
    state.charts[id]?.destroy();
    state.charts[id] = new window.Chart(document.getElementById(id), config);
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
          backgroundColor: tierColor(t), borderColor: css("--surface"), borderWidth: { top: 2 }, borderRadius: 3, borderSkipped: "bottom", maxBarThickness: 46,
        })),
      },
      options: {
        scales: { x: { stacked: true, grid: { display: false }, ticks: { maxRotation: 0, autoSkipPadding: 8 } }, y: { stacked: true, ticks: { callback: (v) => money(v) }, border: { display: false } } },
        plugins: { legend: { position: "bottom" }, tooltip: { mode: "index", callbacks: { title: (items) => month(r.trend[items[0].dataIndex].month), label: (c) => ` ${c.dataset.label}: ${money(c.raw)}` } } },
        interaction: { mode: "index", intersect: false },
      },
    });
  }

  function renderGrowth(r) {
    const g = r.growth;
    const sgn = (v, d = 1) => v == null ? "–" : `${v > 0 ? "+" : ""}${num(v, d)}%`;
    const usd = (v) => `${v > 0 ? "+" : v < 0 ? "−" : ""}${money(Math.abs(v))}`;
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
    $("#growthCap").textContent = `Monthly spend in ${month(g.last_month)} minus ${month(g.first_month)}, by product type. Red = growth, blue = decline.`;
    const rows = [...g.by_category].sort((a, b) => b.change - a.change);
    // The service that moved a product type most; for Marketplace/Bedrock, the product behind it.
    const driverText = (d) => `${d.products?.length ? d.products[0] : d.display} ${usd(d.change)}`;
    // Match the table beside it so the two cards line up.
    $("#chGrowth").parentElement.style.height = `${Math.max(300, 42 * rows.length + 70)}px`;
    chart("chGrowth", {
      type: "bar",
      data: {
        labels: rows.map((c) => c.drivers?.length ? [c.category, driverText(c.drivers[0])] : c.category),
        datasets: [{ label: "Change in USD / month", data: rows.map((c) => c.change), backgroundColor: rows.map((c) => (c.change >= 0 ? tierColor(5) : tierColor(1))), borderRadius: 3, barPercentage: 0.75 }],
      },
      options: {
        indexAxis: "y",
        scales: { x: { ticks: { callback: (v) => usd(v), maxRotation: 0 }, grid: { color: css("--grid") } }, y: { grid: { display: false } } },
        plugins: { legend: { display: false }, tooltip: { callbacks: { label: (c) => {
          const x = rows[c.dataIndex];
          return [` ${money(x.first)} → ${money(x.last)} a month`, ` ${usd(x.change)} (${sgn(x.pct)})`, ` ${pct(x.lockin_pct)} of it on High/Critical services`,
            ...(x.drivers || []).map((d) => ` ${d.display}: ${usd(d.change)}${d.products?.length ? ` (${d.products.join(", ")})` : ""}`)];
        } } } },
      },
    });
    $("#growthTable").innerHTML = `<thead><tr><th>Product type</th><th class="num-cell">${esc(month(g.first_month))}</th><th class="num-cell">${esc(month(g.last_month))}</th><th class="num-cell">Change</th>${annual ? `<th class="num-cell">Per year</th>` : ""}<th class="num-cell" title="Share of this product type's spend on High or Critical services">Lock-in</th></tr></thead><tbody>` +
      g.by_category.map((c) => `<tr><td>${esc(c.category)}${c.services?.length ? `<div class="hint">${esc(c.services.slice(0, 4).join(", "))}${c.services.length > 4 ? ` +${c.services.length - 4} more` : ""}</div>` : ""}</td><td class="num-cell">${money(c.first)}</td><td class="num-cell">${money(c.last)}</td><td class="num-cell">${sgn(c.pct)}</td>${annual ? `<td class="num-cell">${sgn(c.annualised_pct)}</td>` : ""}<td class="num-cell">${pct(c.lockin_pct)}</td></tr>`).join("") +
      `<tr class="total"><td><strong>Total</strong></td><td class="num-cell">${money(g.total.first)}</td><td class="num-cell">${money(g.total.last)}</td><td class="num-cell"><strong>${sgn(g.total.pct)}</strong></td>${annual ? `<td class="num-cell">${sgn(g.total.annualised_pct)}</td>` : ""}<td></td></tr></tbody>`;
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
      `<tr class="total"><td class="nowrap"><strong>Portable</strong> (Low + Moderate)</td><td class="num-cell"><strong>${num(s.portable_accounts)}</strong></td><td class="num-cell">${s.accounts_rated ? pct(100 * s.portable_accounts / s.accounts_rated, 1) : "–"}</td><td></td><td></td></tr></tbody>`;
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
  }

  function renderAccountTable(r, maxC) {
    // Display filter only: scores, charts and totals still count every account.
    const min = RATING_TIER[$("#fMinRating").value] || 0;
    const all = r.accounts.filter((a) => !min || (a.score != null && RATING_TIER[a.rating] >= min));
    const hidden = r.accounts.length - all.length;
    const limit = state.showAllAccounts ? all.length : PRINT ? 25 : ACCOUNT_ROWS;
    const shown = all.slice(0, limit);
    // Only show the OU path when accounts sit in different OUs; otherwise it repeats on every row.
    const multiOu = new Set(all.map((a) => a.ou_path)).size > 1;
    const rows = shown.map((a, i) => `<tr>
      <td class="num-cell muted">${i + 1}</td>
      <td class="acct"><strong>${esc(a.name)}</strong><div class="hint">${esc(a.id)}${multiOu ? ` · ${esc(a.ou_path)}` : ""}</div></td>
      <td class="num-cell">${money(a.monthly_spend)}</td>
      <td class="risk">${a.score == null ? "–" : `<span class="tier-pill" style="--dot:${tierColor(RATING_TIER[a.rating])}">${esc(a.rating)} · ${Math.round(a.score)}</span><div class="hint">${pct(a.high_risk_pct)} High/Crit spend</div>`}</td>
      <td><div class="contrib"><div class="bar"><i style="width:${(100 * a.spend_at_risk / maxC).toFixed(1)}%"></i></div><span class="num-cell">${money(a.spend_at_risk)}</span></div></td>
      <td><div class="chips">${a.top_lockin.map((s) => `<span class="chip">${esc(s.service)}</span>`).join("") || '<span class="hint">none</span>'}</div></td>
      <td class="num-cell">${num(a.effort_weeks / 4.33, 1)}</td>
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
    const chg = (s) => s.change == null ? "–" : `${s.change > 0 ? "+" : s.change < 0 ? "−" : ""}${money(Math.abs(s.change))}${s.change_pct != null ? `<div class="hint">${s.change_pct > 0 ? "+" : ""}${num(s.change_pct, 0)}%</div>` : ""}`;
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

  function renderEstimate(r) {
    const e = r.estimate;
    $("#estEmpty").hidden = !e.empty;
    $("#estBody").hidden = !!e.empty;
    const prov = e.provisional;
    $("#qStatus").innerHTML = prov
      ? `<span class="prov-tag">Provisional</span> Using default answers. Change any answer, or confirm these, to estimate for your organisation.`
      : `<span class="ok-tag">✓ Your answers</span> The estimate uses the answers below.`;
    $("#estTiles").innerHTML = [
      tile("Total exit cost (indicative)", e.ranges.cost, `${e.ranges.pct_of_annual_spend ? `${e.ranges.pct_of_annual_spend} of a year's AWS spend · ` : ""}about ${Math.round(100 * e.cost.labour / Math.max(e.cost.total, 1))}% engineering, the rest parallel running`, prov),
      tile("Exit window (time to leave AWS)", e.ranges.duration, `bound by ${e.duration.constrained_by}`, prov),
      tile("Engineering effort", e.ranges.effort, plural(e.effort.material_accounts, "material account"), prov),
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
      <div class="g-track" title="months ${num(w.start / WPM)}–${num((w.start + w.weeks) / WPM)}"><div class="g-bar" style="left:${(100 * w.start / total).toFixed(2)}%;width:${Math.max(0.8, 100 * w.weeks / total).toFixed(2)}%;background:${waveColor(w)}"></div></div></div>`).join("") +
      `<div class="g-axis"><div></div><div class="g-ticks">${ticks.map((t, i) => `<span class="${i === 0 ? "first" : ""}" style="left:${(100 * t * WPM / total).toFixed(2)}%">${tickLabel(t)}</span>`).join("")}</div></div>`;

    const parts = [["Landing zone", e.effort.landing_zone_weeks], ["Tier 1–2 workloads", e.effort.by_tier[1] + e.effort.by_tier[2]], ["Tier 3 workloads", e.effort.by_tier[3]],
      ["Tier 4–5 workloads", e.effort.by_tier[4] + e.effort.by_tier[5]], ["Account overhead", e.effort.account_weeks * e.factors.combined], ["Programme mgmt", e.effort.pmo_weeks], ["Contingency", e.effort.contingency_weeks]];
    const pc = [css("--ink-2"), tierColor(1), tierColor(3), tierColor(5), css("--t2"), css("--muted"), css("--axis")];
    chart("chEffort", {
      type: "bar",
      data: { labels: parts.map((p) => p[0]), datasets: [{ label: "Person-months", data: parts.map((p) => Math.round(p[1] / WPM)), backgroundColor: pc, borderRadius: 4, borderSkipped: "start", barPercentage: 0.7 }] },
      options: { indexAxis: "y", scales: { x: { grid: { color: css("--grid") }, border: { display: false } }, y: { grid: { display: false } } },
        plugins: { legend: { display: false }, tooltip: { callbacks: { label: (c) => ` ${num(c.raw)} person-months` } } } },
    });

    const q = e.inputs, o = state.options;
    const ans = [["Standard CI/CD pipeline", o.cicd[q.cicd]], ["Terraform / IaC", o.iac[q.iac]], ["Core cloud team", `${q.cloud_team_size} people at ${q.cloud_team_allocation_pct}%`],
      ["Application engineers", `${q.app_engineers_fte} FTE`], ["Target", o.target[q.target]], ["Blended day rate", `${num(q.day_rate)} ${q.currency}`],
      ["Contingency", `${q.contingency_pct}%`], ["Parallel running", `${q.parallel_run_months} months`], ["Regulated", q.regulated ? "Yes" : "No"]];
    $("#answers").innerHTML = ans.map(([k, v]) => `<div><dt>${esc(k)}</dt><dd>${esc(v)}</dd></div>`).join("");
    $("#assumptions").innerHTML = e.assumptions.map((a) => `<li>${esc(a)}</li>`).join("");
  }

  function renderIssues(r) {
    const c = r.issue_counts;
    $("#issueCounts").innerHTML = ["critical", "error", "warning", "info"].map((s) => `<span class="chip"><span class="sev" style="--dot:${css(SEV_COLOR[s])}">${s}: ${c[s] || 0}</span></span>`).join("");
    const names = Object.fromEntries(r.accounts.map((a) => [a.id, a.name]));
    $("#issueTable").innerHTML = r.issues.length
      ? `<thead><tr><th>Severity</th><th>Area</th><th>Account</th><th>Issue</th></tr></thead><tbody>` + r.issues.map((i) => `<tr>
          <td><span class="sev" style="--dot:${css(SEV_COLOR[i.severity] || "--muted")}">${esc(i.severity)}</span></td>
          <td class="cap">${esc(i.category)}${i.region ? `<div class="hint">${esc(i.region)}</div>` : ""}</td>
          <td>${esc(names[i.account_id] || i.account_id || "–")}</td>
          <td>${esc(String(i.message || "").replace(/^./, (ch) => ch.toUpperCase()))}${i.error_code ? ` <span class="chip">${esc(i.error_code)}</span>` : ""}${i.hint ? `<div class="hint">→ ${esc(i.hint)}</div>` : ""}</td></tr>`).join("") + "</tbody>"
      : `<tbody><tr><td class="hint">No issues recorded. Every API call in the scan succeeded.</td></tr></tbody>`;
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
          return `<tr><td>${esc(s.display)}<div class="hint">${esc(s.category)}</div>${u ? `<div class="hint">${money(u.monthly_spend)}/mo in scope</div>` : ""}</td>
          <td>${esc(s.why)}</td><td>${esc(s.migration)}</td>
          <td class="targets">${s.targets.azure ? `<div><strong>Azure:</strong> ${esc(s.targets.azure)}</div>` : ""}${s.targets.gcp ? `<div><strong>GCP:</strong> ${esc(s.targets.gcp)}</div>` : ""}${s.targets.other ? `<div><strong>Neutral:</strong> ${esc(s.targets.other)}</div>` : ""}</td>
          <td>${esc(s.duration)}</td></tr>`;
        }).join("") + "</tbody></table></div></div>";
    }
    if (unclassified.length) {
      html += `<div class="cat-group"><h3>Unclassified services in this estate</h3><p class="muted small">Scored as Moderate (tier 3) until added to the catalog.</p><ul>` +
        unclassified.map((s) => `<li>${esc(s.service)} — ${money(s.monthly_spend)}/month</li>`).join("") + "</ul></div>";
    }
    $("#catalog").innerHTML = html;
  }

  // ------------------------------------------------------------------ new scan dialog
  async function openScanDialog(selectProfile) {
    const dlg = $("#scanDialog");
    $("#scanError").textContent = "";
    $("#scanProgress").hidden = true;
    $("#btnStartScan").disabled = false;
    $("#sNameFilter").value = $("#fInclude").value;
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
    $("#ouChosen").textContent = picked.length ? `Scanning: ${picked.map((b) => b.dataset.name).join(", ")}` : "Scanning the whole organisation.";
  }
  const pickedOus = () => [...$("#sOu").querySelectorAll("input[type=checkbox]:checked:not(:disabled)")].map((b) => b.value);

  async function loadOus(ev) {
    const refresh = ev?.currentTarget?.id === "btnLoadOus";
    const was = new Set(pickedOus());
    $("#sOu").innerHTML = `<p class="muted small">Loading organizational units…</p>`;
    $("#ouStatus").innerHTML = `<span class="spin" aria-hidden="true"></span> Loading organizational units (a few seconds)… approve Touch ID if prompted.`;
    $("#btnLoadOus").disabled = true;
    const seq = (state.ouSeq = (state.ouSeq || 0) + 1); // a later profile change wins over a slow earlier reply
    try {
      const { tree, org } = await api("/api/org", { method: "POST", body: { profile: $("#sProfile").value || null, refresh } });
      if (seq !== state.ouSeq) return;
      $("#sOu").innerHTML = flattenOus(tree).filter((o) => o.depth > 0).map((o) =>
        `<label class="ou-item" style="padding-left:${(o.depth - 1) * 20 + 6}px"><input type="checkbox" value="${esc(o.id)}" data-name="${esc(o.name)}" data-parent="${o.parent === tree.id ? "" : esc(o.parent)}"${was.has(o.id) ? " checked" : ""}> ${esc(o.name)}${o.accounts == null ? "" : ` <span class="muted">· ${o.accounts} account${o.accounts === 1 ? "" : "s"}</span>`}</label>`).join("") ||
        `<p class="muted small">No OUs: the scan covers the whole organisation.</p>`;
      syncOus();
      const n = flattenOus(tree).length - 1;
      $("#ouStatus").textContent = `${n} OU(s) in organization ${org.id} · management account ${org.management_account_id}`;
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
      inventory: f.inventory.checked, role_name: f.role_name.value || null,
      regions: f.regions.value ? f.regions.value.split(",").map((s) => s.trim()).filter(Boolean) : null, label: f.label.value,
      target: f.target.value || "azure",
    };
    $("#qForm").target.value = body.target;
    readQuestionnaire();
    $("#scanError").textContent = "";
    $("#btnStartScan").disabled = true;
    try {
      const job = await api("/api/scans", { method: "POST", body });
      $("#scanProgress").hidden = false;
      pollScan(job.id);
    } catch (e) {
      $("#scanError").textContent = e.message;
      $("#btnStartScan").disabled = false;
    }
  }

  function pollScan(id) {
    clearTimeout(state.pollTimer);
    const tick = async () => {
      try {
        const s = await api(`/api/scans/${encodeURIComponent(id)}/status`);
        $("#scanBar").style.width = `${s.pct}%`;
        $("#scanMsg").textContent = `${s.message || s.phase}${s.issues ? ` · ${s.issues} issue(s)` : ""}`;
        if (s.status === "running") { state.pollTimer = setTimeout(tick, 1000); return; }
        $("#btnStartScan").disabled = false;
        if (s.status === "failed") {
          $("#scanError").textContent = `Scan failed: ${s.message}. See section 6 and the log for details.`;
        } else {
          $("#scanDialog").close();
          toast(`Scan ${s.status}${s.issues ? ` with ${s.issues} issue(s) - see section 6` : ""}`);
        }
        await refreshScans(id);
        state.scanId = id;
        const nameFilter = $("#sNameFilter").value.trim();
        if (nameFilter && s.status !== "failed") { $("#fInclude").value = nameFilter; $("#fMode").value = "contains"; }
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
    $("#btnSso").classList.toggle("signed-in", on.length > 0);
    $("#ssoLabel").textContent = on.length ? `SSO: ${on.map((s) => s.name).join(", ")}` : "AWS sign-in";
    $("#btnSso").title = on.length ? `Signed in until ${new Date(on[0].expires_at).toLocaleString()}` : "Sign in through your AWS access portal (IAM Identity Center)";
  }

  function currentSso() { return sso.sessions.find((s) => s.name === $("#ssoSession").value); }

  async function openSsoDialog(ev) {
    ev?.preventDefault?.();
    if ($("#scanDialog").open) $("#scanDialog").close();
    $("#ssoError").textContent = "";
    $("#ssoPending").hidden = true;
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
    $("#btnSsoLogin").disabled = !s;
    if (!s) { $("#ssoStatus").textContent = ""; return; }
    try { localStorage.setItem(LS_SSO, s.name); } catch { /* ignore */ }
    $("#ssoStatus").textContent = s.signed_in
      ? `Signed in · token valid until ${new Date(s.expires_at).toLocaleString()} · region ${s.region}`
      : `Not signed in · region ${s.region}`;
    $("#btnSsoLogin").textContent = s.signed_in ? "Sign in again" : "Sign in";
    if (s.signed_in) await loadSsoAccounts(s);
  }

  async function loadSsoAccounts(s) {
    $("#ssoUse").hidden = false;
    $("#ssoAccount").innerHTML = `<option>Loading accounts…</option>`;
    $("#ssoRole").innerHTML = "";
    try {
      const { accounts, management_account_id: mgmt } = await api(`/api/sso/${encodeURIComponent(s.name)}/accounts`);
      sso.mgmt = mgmt;
      const sorted = [...accounts].sort((a, b) => (b.id === mgmt) - (a.id === mgmt));
      $("#ssoAccount").innerHTML = sorted.map((a) => `<option value="${esc(a.id)}">${esc(a.name)} · ${esc(a.id)}${a.id === mgmt ? " · management account" : ""}</option>`).join("");
      const linked = s.profiles.find((p) => p.account_id === mgmt) || s.profiles[0];
      if (linked && accounts.some((a) => a.id === linked.account_id)) $("#ssoAccount").value = linked.account_id;
      $("#ssoStatus").textContent += ` · ${accounts.length} accounts${mgmt ? "" : " · management account not visible"}`;
      await loadSsoRoles(linked?.role);
    } catch (e) { $("#ssoError").textContent = `${e.message}${e.hint ? " — " + e.hint : ""}`; }
  }

  async function loadSsoRoles(prefer) {
    const s = currentSso(), acct = $("#ssoAccount").value;
    $("#btnSsoUse").hidden = true;
    $("#ssoRole").innerHTML = `<option>Loading roles…</option>`;
    try {
      const { roles } = await api(`/api/sso/${encodeURIComponent(s.name)}/accounts/${encodeURIComponent(acct)}/roles`);
      $("#ssoRole").innerHTML = roles.map((r) => `<option>${esc(r)}</option>`).join("") || `<option value="">(no roles)</option>`;
      const ro = prefer && roles.includes(prefer) ? prefer : roles.find((r) => /read|audit|view/i.test(r));
      if (ro) $("#ssoRole").value = ro;
      $("#btnSsoUse").hidden = !roles.length;
    } catch (e) { $("#ssoRole").innerHTML = ""; $("#ssoError").textContent = e.message; }
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
      $("#ssoError").textContent = `${e.message}${e.hint ? " — " + e.hint : ""}`;
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
    $("#btnAccessScan").hidden = true;
    $("#aSwitch").hidden = true;
    $("#aError").textContent = "";
    try { await fillProfiles($("#aProfile"), typeof profile === "string" ? profile : null); }
    catch (e) { $("#aError").textContent = e.message; }
    $("#accessDialog").showModal();
    if (autoRun) runAccessCheck();
  }

  async function runAccessCheck() {
    $("#btnAccessRun").disabled = true;
    $("#aBusy").textContent = "Checking… approve Touch ID if prompted.";
    $("#aError").textContent = "";
    try {
      const r = await api("/api/access-check", { method: "POST", body: { profile: $("#aProfile").value || null, role_name: $("#aRole").value || null } });
      const icon = { ok: "✓", fail: "✗", warn: "!", skip: "–" };
      $("#aChecks").innerHTML = r.checks.map((c) => `<li class="${esc(c.status)}"><span class="ic" aria-label="${esc(c.status)}">${icon[c.status] || "?"}</span><strong>${esc(c.label)}</strong>
        ${c.detail ? `<span class="d">${esc(c.detail)}</span>` : ""}${c.fix ? `<span class="f">→ ${esc(c.fix)}</span>` : ""}</li>`).join("");
      $("#aVerdict").textContent = r.verdict;
      $("#aVerdict").hidden = false;
      $("#aVerdict").style.color = r.ready ? "#2f9e5b" : r.partial ? "#b7791f" : css("--sev-critical");
      const needsAdmin = r.checks.some((c) => c.status === "fail" && c.needs) || !r.ready;
      $("#aAdmin").hidden = !needsAdmin || r.checks[0].status !== "ok";
      $("#aAdminText").value = r.admin_request;
      $("#btnAccessScan").hidden = !(r.ready || r.partial);
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
    finally { $("#btnAccessRun").disabled = false; $("#aBusy").textContent = ""; }
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
  async function boot() {
    window.addEventListener("error", (e) => console.error("ui error", e.message));
    window.addEventListener("unhandledrejection", (e) => console.error("ui promise error", e.reason));
    chartDefaults();
    try {
      [state.options, state.catalog] = await Promise.all([api("/api/options"), api("/api/catalog")]);
    } catch (e) { toast(e.message, 8000); return; }
    fillQuestionnaire(loadQuestionnaire());
    if (["balanced", "spend", "equal"].includes(params.get("weighting"))) $("#fWeighting").value = params.get("weighting");
    if (["Moderate", "High"].includes(params.get("min_rating"))) $("#fMinRating").value = params.get("min_rating");
    for (const k of ["include", "exclude", "mode"]) if (params.get(k)) $(`#f${k[0].toUpperCase()}${k.slice(1)}`).value = params.get(k);

    const scans = await refreshScans();
    state.scanId = params.get("scan") || scans.find((s) => s.status !== "failed")?.id || null;
    if (state.scanId) { $("#scanSelect").value = state.scanId; await loadReport(); }
    else document.body.dataset.ready = "1";

    $("#scanSelect").addEventListener("change", (e) => {
      state.scanId = e.target.value;
      // Each scan remembers the exit target chosen when it was started.
      const t = (state.scans || []).find((s) => s.id === state.scanId)?.target;
      if (t) $("#qForm").target.value = t;
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
    const confirmAnswers = () => { $("#qForm").confirmed.value = "true"; loadReport(); };
    $("#btnRecalc").addEventListener("click", confirmAnswers);
    $("#qForm").addEventListener("change", confirmAnswers);
    $("#btnAnswerQs").addEventListener("click", (ev) => {
      ev.preventDefault();
      $("#sec-estimate").scrollIntoView({ behavior: "smooth", block: "start" });
      setTimeout(() => $("#qForm").cicd.focus({ preventScroll: true }), 400);
    });
    $("#btnAcctMore").addEventListener("click", () => {
      state.showAllAccounts = !state.showAllAccounts;
      renderAccountTable(state.report, Math.max(...state.report.accounts.map((a) => a.spend_at_risk), 0.01));
    });
    $("#btnDemo").addEventListener("click", async () => {
      try { const { id } = await api("/api/scans/demo", { method: "POST" }); await refreshScans(id); state.scanId = id; await loadReport(); toast("Loaded synthetic demo organisation"); }
      catch (e) { toast(e.message); }
    });
    $("#btnPdf").addEventListener("click", () => {
      if (!state.report) { toast("Load a scan first"); return; }
      toast("Choose “Save as PDF” in the print dialog. For a scripted PDF: exitrisk pdf <scan-id>", 6000);
      setTimeout(() => window.print(), 300);
    });
    $("#btnTheme").addEventListener("click", () => {
      const dark = document.documentElement.dataset.theme === "dark" || (!document.documentElement.dataset.theme && matchMedia("(prefers-color-scheme: dark)").matches);
      const next = dark ? "light" : "dark";
      applyTheme(next);
      try { localStorage.setItem(LS_THEME, next); } catch { /* ignore */ }
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
    $("#ssoDialog").addEventListener("close", () => clearInterval(sso.loginTimer));
    refreshSsoBadge();
    $("#btnLoadOus").addEventListener("click", loadOus);
    $("#sOu").addEventListener("change", syncOus);
    $("#sProfile").addEventListener("change", loadOus);
    $("#btnStartScan").addEventListener("click", startScan);
    $("#sInventory").addEventListener("change", (e) => { $("#invOpts").hidden = !e.target.checked; });
    $("#showAllCatalog").addEventListener("change", () => state.report && renderAppendix(state.report));
    $("#btnLogs").addEventListener("click", openLog);
    $("#logThisRun").addEventListener("change", openLog);
    $("#btnCloseLog").addEventListener("click", () => $("#logDialog").close());
    window.addEventListener("beforeprint", () => Object.values(state.charts).forEach((c) => c.resize()));
  }

  document.addEventListener("DOMContentLoaded", boot);
})();
