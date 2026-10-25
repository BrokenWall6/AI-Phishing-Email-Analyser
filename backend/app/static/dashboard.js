/* =====================================================================
   Phishing Email Analyzer - dashboard

   This page shows attacker-controlled text, so:
   - every value taken from an email goes through esc() before it is
     inserted into the page (a subject like <img src=x onerror=...> must
     not run);
   - URLs are shown defanged (hxxp://evil[.]xyz) and are never clickable.
   ===================================================================== */

"use strict";

/* -------------------------------------------------------------- helpers */

const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];

function esc(value) {
    return String(value ?? "")
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#39;");
}

function defang(url) {
    return String(url ?? "")
        .replace(/^http/i, "hxxp")
        .replace(/\./g, "[.]");
}

const num = (v) => (typeof v === "number" && isFinite(v) ? v : 0);

function plural(n, one, many) {
    return `${n} ${n === 1 ? one : many}`;
}

/* ------------------------------------------------------------ constants */

const VERDICTS = {
    "Phishing":   { color: "var(--critical)", icon: "alert" },
    "Suspicious": { color: "var(--serious)",  icon: "alert" },
    "Low Risk":   { color: "var(--warning)",  icon: "info"  },
    "Benign":     { color: "var(--good)",     icon: "check" },
};

const ICONS = {
    alert: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 3 2 20h20L12 3Z" fill="currentColor"/><path d="M12 9.5v4.5" stroke="var(--surface)" stroke-width="2.2" stroke-linecap="round"/><circle cx="12" cy="17" r="1.3" fill="var(--surface)"/></svg>',
    info:  '<svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="10" fill="currentColor"/><path d="M12 11v6" stroke="var(--surface)" stroke-width="2.2" stroke-linecap="round"/><circle cx="12" cy="7.5" r="1.3" fill="var(--surface)"/></svg>',
    check: '<svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="10" fill="currentColor"/><path d="m7.5 12.5 3 3 6-6.5" fill="none" stroke="var(--surface)" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"/></svg>',
};

/* Score components, in a fixed order (colour follows the component). */
const COMPONENTS = [
    { key: "url",                 label: "Links",               color: "var(--s-url)",     tab: "links" },
    { key: "brand",               label: "Brand impersonation", color: "var(--s-brand)",   tab: "sender" },
    { key: "header",              label: "Sender & headers",    color: "var(--s-header)",  tab: "sender" },
    { key: "content",             label: "Message content",     color: "var(--s-content)", tab: null },
    { key: "whois",               label: "Domain age (WHOIS)",  color: "var(--s-whois)",   tab: "domains" },
    { key: "dns",                 label: "DNS",                 color: "var(--s-dns)",     tab: "domains" },
    { key: "threat_intelligence", label: "Threat intelligence", color: "var(--s-ti)",      tab: "ti" },
];

const THRESHOLDS = [
    { at: 20, label: "Low risk" },
    { at: 45, label: "Suspicious" },
    { at: 70, label: "Phishing" },
];

/* --------------------------------------------------------------- theme */

(function initTheme() {
    let saved = null;
    try { saved = localStorage.getItem("theme"); } catch (_) { /* ignore */ }
    if (saved === "light" || saved === "dark") {
        document.documentElement.dataset.theme = saved;
    }

    $("#themeToggle").addEventListener("click", () => {
        const current = document.documentElement.dataset.theme
            || (matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light");
        const next = current === "dark" ? "light" : "dark";
        document.documentElement.dataset.theme = next;
        try { localStorage.setItem("theme", next); } catch (_) { /* ignore */ }
    });
})();

/* --------------------------------------------------------------- views */

function showView(name) {
    $$(".view-tab").forEach((tab) => {
        if (tab.dataset.view === name) tab.setAttribute("aria-current", "page");
        else tab.removeAttribute("aria-current");
    });
    $("#view-analyze").hidden = name !== "analyze";
    $("#view-accuracy").hidden = name !== "accuracy";
    if (name === "accuracy") loadAccuracy();
    history.replaceState(null, "", name === "accuracy" ? "#accuracy" : "#");
}

$$(".view-tab").forEach((tab) =>
    tab.addEventListener("click", () => showView(tab.dataset.view)));

/* ------------------------------------------------------------- tooltip */

const tooltip = $("#tooltip");

function showTip(target, html) {
    tooltip.innerHTML = html;
    tooltip.hidden = false;
    const r = target.getBoundingClientRect();
    const t = tooltip.getBoundingClientRect();
    let left = r.left + r.width / 2 - t.width / 2;
    left = Math.max(8, Math.min(left, window.innerWidth - t.width - 8));
    let top = r.top - t.height - 10;
    if (top < 8) top = r.bottom + 10;
    tooltip.style.left = `${left}px`;
    tooltip.style.top = `${top}px`;
}

function hideTip() { tooltip.hidden = true; }

document.addEventListener("mouseover", (e) => {
    const el = e.target.closest("[data-tip]");
    if (el) showTip(el, el.dataset.tip);
});
document.addEventListener("mouseout", (e) => {
    if (e.target.closest("[data-tip]")) hideTip();
});
document.addEventListener("focusin", (e) => {
    const el = e.target.closest("[data-tip]");
    if (el) showTip(el, el.dataset.tip);
});
document.addEventListener("focusout", hideTip);
window.addEventListener("scroll", hideTip, { passive: true });

/* -------------------------------------------------------------- upload */

const fileInput = $("#fileInput");
const dropzone = $("#dropzone");
const analyzeBtn = $("#analyzeBtn");
const statusEl = $("#status");
const reportEl = $("#report");

function setStatus(text, { busy = false, error = false } = {}) {
    statusEl.classList.toggle("is-error", error);
    statusEl.innerHTML = (busy ? '<span class="spinner" aria-hidden="true"></span>' : "") + esc(text);
}

function setFile(file) {
    if (!file) return;
    const dt = new DataTransfer();
    dt.items.add(file);
    fileInput.files = dt.files;
    $("#dropTitle").textContent = file.name;
    dropzone.classList.add("has-file");
    analyzeBtn.disabled = false;
}

$("#chooseFile").addEventListener("click", () => fileInput.click());

fileInput.addEventListener("change", () => {
    if (fileInput.files[0]) setFile(fileInput.files[0]);
});

["dragenter", "dragover"].forEach((type) =>
    dropzone.addEventListener(type, (e) => {
        e.preventDefault();
        dropzone.classList.add("is-over");
    }));

["dragleave", "drop"].forEach((type) =>
    dropzone.addEventListener(type, (e) => {
        e.preventDefault();
        dropzone.classList.remove("is-over");
    }));

dropzone.addEventListener("drop", (e) => {
    const file = e.dataTransfer.files[0];
    if (file) setFile(file);
});

async function runAnalysis(request, label) {
    const withAi = $("#aiToggle").checked;
    analyzeBtn.disabled = true;
    setStatus(
        withAi
            ? `Analyzing ${label}. Writing the AI report can take up to a minute on CPU.`
            : `Analyzing ${label}…`,
        { busy: true }
    );

    const started = performance.now();

    try {
        const response = await request(withAi);
        let data = null;
        try { data = await response.json(); } catch (_) { /* not JSON */ }

        if (!response.ok) {
            const detail = data && data.detail ? data.detail : response.statusText;
            throw new Error(`The server returned ${response.status}: ${detail}`);
        }

        renderReport(data);
        loadLookupStatus();
        const secs = ((performance.now() - started) / 1000).toFixed(1);
        setStatus(`Analyzed ${label} in ${secs} s.`);
        reportEl.scrollIntoView({ behavior: "smooth", block: "start" });

    } catch (err) {
        setStatus(
            err instanceof TypeError
                ? "Could not reach the API. Check that uvicorn is running."
                : err.message,
            { error: true }
        );
    } finally {
        analyzeBtn.disabled = !fileInput.files[0];
    }
}

dropzone.addEventListener("submit", (e) => {
    e.preventDefault();
    const file = fileInput.files[0];
    if (!file) return;
    runAnalysis((withAi) => {
        const form = new FormData();
        form.append("file", file);
        return fetch(`/analyze-email?include_ai_report=${withAi}`, { method: "POST", body: form });
    }, file.name);
});

/* ------------------------------------------------------ online checks */

let lookupStatus = null;

async function loadLookupStatus() {
    try {
        const res = await fetch("/lookup-status");
        if (res.ok) lookupStatus = await res.json();
    } catch (_) { /* API not reachable yet */ }
    renderLookupStatus();
    renderBatch();
}

function lookupStatusText() {
    const s = lookupStatus;
    if (!s) return "";
    if (!s.network_lookups) {
        return "Online checks are off (ENABLE_NETWORK_LOOKUPS=false in backend/.env): WHOIS, DNS and VirusTotal are skipped.";
    }
    const vt = s.virustotal || {};
    let vtText;
    if (!vt.configured) vtText = "VirusTotal is not configured (add VIRUSTOTAL_API_KEY to backend/.env)";
    else if (!vt.enabled) vtText = "VirusTotal is switched off (ENABLE_THREAT_INTEL=false)";
    else if (vt.paused_seconds) vtText = `VirusTotal quota reached, paused for ${vt.paused_seconds} s`;
    else vtText = `VirusTotal on, up to ${vt.max_lookups_per_email} lookups per email, paced to ${vt.requests_per_minute} a minute`;
    return `Online checks: WHOIS and DNS on (up to ${s.max_domain_lookups} link domains per email). ${vtText}.`;
}

function renderLookupStatus() {
    let el = $("#lookupStatus");
    if (!el) {
        el = document.createElement("p");
        el.id = "lookupStatus";
        el.className = "lookup-status";
        $("#dropzone").after(el);
    }
    el.textContent = lookupStatusText();
    el.hidden = !el.textContent;
}

/* --------------------------------------------------------- welcome state */

function renderWelcome() {
    reportEl.innerHTML = `
        <div class="welcome">
            <h2>Analyze a suspicious email</h2>
            <p>The verdict comes from deterministic checks on the links, sender headers,
            message text and link domains. The local AI model then explains the result;
            it never changes the verdict.</p>
            <ol>
                <li>Save the email as an <span class="mono">.eml</span> file (in Outlook or Gmail: “Download message”).</li>
                <li>Drop it above, or choose it, and select <strong>Analyze email</strong>.</li>
                <li>Untick <strong>Write AI report</strong> for a result in a few seconds.</li>
            </ol>
        </div>`;
}

/* ---------------------------------------------------------- the report */

function renderReport(data) {
    const verdict = data.verdict || {};
    const evidence = data.evidence || {};

    reportEl.innerHTML = `
        <article class="report" aria-label="Analysis report">
            ${renderVerdict(data, verdict)}
            <section class="report-section" aria-labelledby="ledger-title">
                <div class="section-head">
                    <h2 id="ledger-title">How the score was built</h2>
                    <span class="section-note">${plural(num(verdict.signal_count ?? evidence.signal_count), "independent signal", "independent signals")}</span>
                </div>
                ${renderLedger(evidence, verdict)}
            </section>
            <div class="split">
                <section class="report-section" aria-labelledby="findings-title">
                    <div class="section-head"><h2 id="findings-title">Findings</h2></div>
                    ${renderFindings(data, evidence)}
                </section>
                <section class="report-section" aria-labelledby="ai-title">
                    ${renderAi(data.ai_report)}
                    ${renderMitre(data.mitre_attack)}
                </section>
            </div>
            ${renderDetails(data)}
        </article>`;

    wireTabs();
    wireCopy();
}

/* verdict header */

function renderVerdict(data, verdict) {
    const name = verdict.verdict || "Unknown";
    const style = VERDICTS[name] || { color: "var(--unknown)", icon: "info" };
    const narrative = data.attack_narrative || {};
    const type = narrative.attack_type && narrative.attack_type !== "No Clear Attack Pattern"
        ? narrative.attack_type : "";

    return `
        <section class="verdict" style="--verdict-color:${style.color}">
            <div class="verdict-rail" aria-hidden="true"></div>
            <div class="verdict-main">
                <div class="verdict-line">
                    <span class="verdict-icon">${ICONS[style.icon]}</span>
                    <h1 class="verdict-word">${esc(name)}</h1>
                    ${type ? `<span class="verdict-type">${esc(type)}</span>` : ""}
                </div>
                ${narrative.narrative ? `<p class="verdict-narrative">${esc(narrative.narrative)}</p>` : ""}
                <dl class="meta">
                    <dt>From</dt><dd class="mono">${esc(data.from) || '<span class="muted">(missing)</span>'}</dd>
                    ${data.reply_to ? `<dt>Reply-To</dt><dd class="mono">${esc(data.reply_to)}</dd>` : ""}
                    <dt>Subject</dt><dd>${esc(data.subject) || '<span class="muted">(no subject)</span>'}</dd>
                    ${data.date ? `<dt>Date</dt><dd>${esc(data.date)}</dd>` : ""}
                </dl>
            </div>
            <div class="score">
                <div><span class="score-number">${num(verdict.risk_score)}</span><span class="score-of">/100</span></div>
                <div class="score-label">${esc(verdict.confidence || "")} confidence</div>
            </div>
        </section>`;
}

/* the stacked score bar */

function renderLedger(evidence, verdict) {
    const breakdown = evidence.score_breakdown || {};
    const finalScore = num(verdict.risk_score ?? breakdown.final_score);

    const parts = COMPONENTS.map((c) => ({ ...c, value: num(breakdown[c.key]) }));
    const bonus = num(breakdown.contextual_bonus);
    if (bonus > 0) {
        parts.push({ key: "bonus", label: "Agreement bonus", color: null, rule: true, value: bonus });
    }

    const sum = parts.reduce((acc, p) => acc + p.value, 0);
    if (finalScore > sum) {
        parts.push({ key: "floor", label: "Raised by rule", color: null, rule: true, value: finalScore - sum });
    }

    // The axis is always 0-100 (the score range). Points beyond 100 are
    // clipped in the bar; the legend below keeps the full values.
    const pct = (v) => Math.max(0, Math.min(v, 100));
    let start = 0;
    const segs = parts.filter((p) => p.value > 0).map((p) => {
        const width = Math.min(p.value, 100 - start);
        start += p.value;
        if (width <= 0) return "";
        const clipped = width < p.value ? ` (${p.value - width} beyond the 100 cap)` : "";
        const tip = `<strong>${esc(p.label)}</strong>${p.value} points${clipped}`;
        return `<span class="ledger-seg${p.rule ? " is-rule" : ""}" tabindex="0"
                    style="width:${width}%;${p.color ? `background:${p.color}` : ""}"
                    data-tip="${esc(tip)}" aria-label="${esc(p.label)}: ${p.value} points"></span>`;
    }).join("");

    const thresholds = THRESHOLDS.map((t) => `
        <div class="threshold${finalScore >= t.at ? " is-reached" : ""}" style="left:${pct(t.at)}%">
            <span><span class="t-name">${t.label} </span>${t.at}</span>
        </div>`).join("");

    const legend = parts.map((p) => `
        <li class="${p.value === 0 ? "is-zero" : ""}">
            <span class="swatch${p.rule ? " is-rule" : ""}" style="${p.color ? `background:${p.color}` : ""}" aria-hidden="true"></span>
            ${esc(p.label)}
            <span class="pts">${p.value}</span>
        </li>`).join("");

    const explain = [];
    if (sum > finalScore) {
        explain.push(`The components add up to ${sum}, but the final score is limited to ${finalScore}` +
            (finalScore <= 30 && sum > 30 ? " because only infrastructure signals were found." : " (maximum 100)."));
    }
    if (finalScore > sum) {
        explain.push(`The score was raised from ${sum} to ${finalScore} by a verdict rule (for example, three independent signals agreeing).`);
    }
    const unavailable = evidence.unavailable_checks || [];
    if (unavailable.length) {
        explain.push(`Not checked: ${unavailable.map(esc).join(", ")}. These count as unknown, not as safe.`);
    }

    return `
        <div class="ledger">
            <div class="ledger-track" role="img" aria-label="Risk score ${finalScore} out of 100">
                <div class="ledger-fill">${segs}</div>
                ${thresholds}
                <div class="final-marker" style="left:${pct(finalScore)}%" aria-hidden="true"></div>
            </div>
            <div class="ledger-axis" aria-hidden="true"><span>0</span><span class="t-caption">Low risk from 20, Suspicious from 45, Phishing from 70</span><span>100</span></div>
            <ul class="ledger-legend">${legend}</ul>
            ${explain.length ? `<ul class="ledger-explain">${explain.map((e) => `<li>${e}</li>`).join("")}</ul>` : ""}
        </div>`;
}

/* findings, grouped by the component that produced them */

function renderFindings(data, evidence) {
    const breakdown = evidence.score_breakdown || {};
    const suspiciousUrls = (data.url_analysis || []).filter((u) => num(u.risk_score) >= 15);

    const groups = [
        { c: COMPONENTS[0], items: unique(suspiciousUrls.flatMap((u) => u.findings || [])) },
        { c: COMPONENTS[1], items: data.brand_analysis?.findings || [], notes: data.brand_analysis?.notes || [] },
        { c: COMPONENTS[2], items: data.header_analysis?.findings || [], notes: data.header_analysis?.notes || [] },
        { c: COMPONENTS[3], items: data.content_analysis?.findings || [] },
        { c: COMPONENTS[4], items: unique((data.whois_analysis || []).flatMap((w) => (w.findings || []).map((f) => `${f}: ${w.domain}`))) },
        { c: COMPONENTS[5], items: unique((data.dns_analysis || []).flatMap((d) => (d.findings || []).map((f) => `${f}: ${d.domain}`))) },
        { c: COMPONENTS[6], items: data.threat_intelligence?.findings || [] },
    ];

    const html = groups
        .filter((g) => g.items.length)
        .map((g) => `
            <div class="finding-group">
                <h3>
                    <span class="swatch" style="background:${g.c.color}" aria-hidden="true"></span>
                    ${esc(g.c.label)}
                    <span class="pts">+${num(breakdown[g.c.key])}</span>
                </h3>
                <ul class="finding-list">${g.items.map((f) => `<li>${esc(f)}</li>`).join("")}</ul>
            </div>`).join("");

    const notes = groups.flatMap((g) => g.notes || []);

    return `
        ${html || '<p class="empty">No risk indicators were found.</p>'}
        ${notes.length ? `<h3 class="subhead">Checked but not scored</h3>
            <ul class="note-list">${notes.map((n) => `<li>${esc(n)}</li>`).join("")}</ul>` : ""}`;
}

function unique(list) { return [...new Set(list)]; }

/* AI report */

function renderAi(ai) {
    if (!ai) return "";

    const status = ai.status || "generated";
    const statusText = {
        generated:   "Written by the local model",
        unavailable: "Model unavailable, showing fallback text",
        unparseable: "Model answer could not be read, showing fallback text",
        skipped:     "Not requested",
    }[status] || status;

    if (status === "skipped") {
        return `
            <div class="section-head"><h2 id="ai-title">AI report</h2></div>
            <p class="empty">Not requested for this analysis. Tick <strong>Write AI report</strong> and analyze again to get a written explanation.</p>`;
    }

    const recs = (ai.recommendations || []).map((r) => `<li>${esc(r)}</li>`).join("");

    return `
        <div class="section-head">
            <h2 id="ai-title">AI report</h2>
            <span class="ai-status is-${esc(status)}"><span class="dot" aria-hidden="true"></span>${esc(statusText)}</span>
        </div>
        <p class="ai-summary">${esc(ai.summary)}</p>
        ${recs ? `<ol class="ai-recs">${recs}</ol>` : ""}
        ${ai.error ? `<p class="ai-error">${esc(ai.error)}</p>` : ""}`;
}

/* MITRE ATT&CK */

function renderMitre(techniques) {
    const list = techniques || [];
    return `
        <h2 class="subhead">MITRE ATT&amp;CK</h2>
        ${list.length ? `<ul class="technique-list">${list.map((t) => `
            <li>
                <span class="technique-id">${esc(t.id)}</span>
                <span>${esc(t.name)}</span>
                <span class="technique-reason">${esc(t.reason)}</span>
            </li>`).join("")}</ul>`
        : '<p class="empty">No techniques mapped from this evidence.</p>'}`;
}

/* ------------------------------------------------------- detail tabs */

function renderDetails(data) {
    const urls = data.url_analysis || [];
    const domains = (data.whois_analysis || []).length;
    const ioc = data.ioc_analysis || {};
    const iocCount = ["urls", "domains", "email_addresses", "ip_addresses"]
        .reduce((n, k) => n + (ioc[k] || []).length, 0);

    const tabs = [
        { id: "links",   label: "Links",               count: urls.length, html: renderLinks(urls) },
        { id: "sender",  label: "Sender & headers",    count: null,        html: renderSender(data) },
        { id: "domains", label: "Domains",             count: domains,     html: renderDomains(data) },
        { id: "ti",      label: "Threat intelligence", count: null,        html: renderTi(data.threat_intelligence) },
        { id: "iocs",    label: "Indicators",          count: iocCount,    html: renderIocs(ioc) },
        { id: "raw",     label: "Raw result",          count: null,        html: renderRaw(data) },
    ];

    return `
        <div class="report-details">
            <div class="tabs" role="tablist" aria-label="Details">
                ${tabs.map((t, i) => `
                    <button class="tab" role="tab" id="tab-${t.id}" aria-controls="panel-${t.id}"
                        aria-selected="${i === 0}" tabindex="${i === 0 ? 0 : -1}">
                        ${esc(t.label)}${t.count !== null ? `<span class="count">${t.count}</span>` : ""}
                    </button>`).join("")}
            </div>
            ${tabs.map((t, i) => `
                <div class="tabpanel" role="tabpanel" id="panel-${t.id}" aria-labelledby="tab-${t.id}" ${i === 0 ? "" : "hidden"}>
                    ${t.html}
                </div>`).join("")}
        </div>`;
}

function levelColor(score) {
    if (score >= 45) return "var(--critical)";
    if (score >= 15) return "var(--serious)";
    if (score > 0) return "var(--warning)";
    return "var(--good)";
}

function renderLinks(urls) {
    if (!urls.length) return '<p class="empty">The email contains no web links.</p>';

    const sorted = [...urls].sort((a, b) => num(b.risk_score) - num(a.risk_score));

    return `
        <p class="section-note" style="margin-bottom:12px">Links are shown defanged and are not clickable. Use “copy” to get the original address.</p>
        <div class="table-wrap"><table>
            <thead><tr><th>Link</th><th>Rating</th><th class="num">Points</th><th>Why</th></tr></thead>
            <tbody>${sorted.map((u) => `
                <tr>
                    <td class="url-cell"><span class="mono">${esc(defang(u.url))}</span><button class="copy" data-copy="${esc(u.url)}" type="button">copy</button></td>
                    <td><span class="level" style="--level-color:${levelColor(num(u.risk_score))}">${esc(u.status || "")}</span></td>
                    <td class="num">${num(u.risk_score)}</td>
                    <td>${(u.findings || []).length
                        ? (u.findings || []).map(esc).join("<br>")
                        : '<span class="muted">Nothing unusual</span>'}
                        ${(u.informational_findings || []).length
                        ? `<br><span class="muted">${(u.informational_findings || []).map(esc).join("<br>")}</span>` : ""}</td>
                </tr>`).join("")}
            </tbody>
        </table></div>`;
}

function renderSender(data) {
    const h = data.header_analysis || {};
    const b = data.brand_analysis || {};
    return `
        <dl class="kv">
            <dt>From</dt><dd class="mono">${esc(data.from) || "—"}</dd>
            <dt>Reply-To</dt><dd class="mono">${esc(data.reply_to) || '<span class="muted">not set</span>'}</dd>
            <dt>Return-Path</dt><dd class="mono">${esc(data.return_path) || '<span class="muted">not set</span>'}</dd>
            <dt>To</dt><dd class="mono">${esc(data.to) || "—"}</dd>
            <dt>Sender domain</dt><dd class="mono">${esc(h.sender_domain) || "—"}</dd>
            <dt>Reply-To status</dt><dd>${esc(h.reply_to_status || "—")}</dd>
            <dt>Mailing list</dt><dd>${h.mailing_list ? "Yes (List headers present)" : "No"}</dd>
            <dt>Authentication</dt><dd class="mono">${esc(data.authentication_results || data.received_spf) || '<span class="muted">no Authentication-Results header</span>'}</dd>
            <dt>Brands mentioned</dt><dd>${(b.brands_detected || []).length ? b.brands_detected.map(esc).join(", ") : '<span class="muted">none</span>'}</dd>
            <dt>Header points</dt><dd>${num(h.risk_score)}</dd>
            <dt>Brand points</dt><dd>${num(b.risk_score)}</dd>
        </dl>`;
}

function renderDomains(data) {
    const whois = data.whois_analysis || [];
    const dns = data.dns_analysis || [];
    if (!whois.length && !dns.length) {
        return '<p class="empty">No link domains needed a lookup (no links, or only well-known domains).</p>';
    }

    const byDomain = {};
    whois.forEach((w) => { (byDomain[w.domain] ||= {}).whois = w; });
    dns.forEach((d) => { (byDomain[d.domain] ||= {}).dns = d; });

    const dnsText = (rec) => {
        if (!rec || rec.status === "unavailable") return lookup(rec);
        if ((rec.findings || []).length) return esc(rec.findings.join("; "));
        return `${(rec.a_records || []).length} A record(s), ${(rec.mx_records || []).length} MX`;
    };

    const lookup = (rec) => !rec ? '<span class="muted">not checked</span>'
        : rec.status === "unavailable" ? '<span class="muted">unavailable (unknown, not scored)</span>'
        : "";

    return `
        <div class="domain-grid">${Object.entries(byDomain).map(([domain, r]) => {
            const w = r.whois, d = r.dns;
            return `
            <div>
                <h3 class="mono">${esc(defang(domain))}</h3>
                <dl class="kv">
                    <dt>WHOIS</dt><dd>${lookup(w) || `${esc(w.registrar || "registrar hidden")}`}</dd>
                    <dt>Created</dt><dd>${w && w.creation_date ? esc(String(w.creation_date).slice(0, 10)) : "—"}</dd>
                    <dt>Age</dt><dd>${w && w.domain_age_days != null ? `${w.domain_age_days} days` : "—"}</dd>
                    <dt>DNS</dt><dd>${dnsText(d)}</dd>
                    <dt>Points</dt><dd>${num(w && w.risk_score) + num(d && d.risk_score)}</dd>
                </dl>
            </div>`;
        }).join("")}</div>`;
}

function renderTi(ti) {
    if (!ti) return '<p class="empty">Threat intelligence was not run.</p>';
    const checked = ti.checked_indicators || [];
    const missing = ti.unavailable_indicators || [];
    const roles = ti.indicator_roles || {};
    return `
        <dl class="kv">
            <dt>Status</dt><dd>${esc(ti.status || "—")}</dd>
            <dt>Source</dt><dd>${(ti.sources || []).length ? ti.sources.map(esc).join(", ") : '<span class="muted">none</span>'}</dd>
            <dt>Malicious</dt><dd>${ti.malicious ? "Yes" : "No detections"}</dd>
            <dt>Points</dt><dd>${num(ti.risk_score)}</dd>
            <dt>Checked</dt><dd>${checked.length ? `<div class="chips">${checked.map((c) => chipWithRole(c, roles)).join("")}</div>` : '<span class="muted">none</span>'}</dd>
            <dt>Not checked</dt><dd>${missing.length ? `<div class="chips">${missing.map((c) => chipWithRole(c, roles)).join("")}</div>` : '<span class="muted">none</span>'}</dd>
        </dl>
        ${(ti.findings || []).length ? `<ul class="finding-list" style="margin-top:14px">${ti.findings.map((f) => `<li>${esc(f)}</li>`).join("")}</ul>` : ""}
        ${(ti.notes || []).length ? `<p class="unavailable">${ti.notes.map(esc).join(" ")}</p>` : ""}`;
}

function chipWithRole(value, roles) {
    const role = roles[value];
    return `<span class="chip">${esc(defang(value))}${role ? ` <span class="muted">${esc(role)}</span>` : ""}</span>`;
}

function renderIocs(ioc) {
    const block = (title, items, transform = (x) => x) => `
        <div class="ioc-block">
            <h3>${title} <span class="muted">${items.length}</span></h3>
            ${items.length
                ? `<div class="chips">${items.map((i) => `<span class="chip">${esc(transform(i))}</span>`).join("")}</div>`
                : '<p class="empty">None</p>'}
        </div>`;
    return `
        ${block("Domains", ioc.domains || [], defang)}
        ${block("IP addresses", ioc.ip_addresses || [], defang)}
        ${block("Email addresses", ioc.email_addresses || [])}
        ${block("URLs", ioc.urls || [], defang)}`;
}

function renderRaw(data) {
    const copy = { ...data };
    delete copy.body;
    return `
        <p class="section-note" style="margin-bottom:10px">The full API response (email body omitted).
            <button class="copy" type="button" data-copy-json>copy JSON</button></p>
        <pre class="raw">${esc(JSON.stringify(copy, null, 2))}</pre>`;
}

/* tabs: click + arrow keys */

function wireTabs() {
    const tabs = $$(".tab", reportEl);
    const select = (tab) => {
        tabs.forEach((t) => {
            const on = t === tab;
            t.setAttribute("aria-selected", on);
            t.tabIndex = on ? 0 : -1;
            $(`#${t.getAttribute("aria-controls")}`).hidden = !on;
        });
    };
    tabs.forEach((tab, i) => {
        tab.addEventListener("click", () => select(tab));
        tab.addEventListener("keydown", (e) => {
            if (e.key !== "ArrowRight" && e.key !== "ArrowLeft") return;
            const next = tabs[(i + (e.key === "ArrowRight" ? 1 : -1) + tabs.length) % tabs.length];
            select(next);
            next.focus();
        });
    });
}

function wireCopy() {
    $$("[data-copy]", reportEl).forEach((btn) =>
        btn.addEventListener("click", () => copyText(btn, btn.dataset.copy)));
    const jsonBtn = $("[data-copy-json]", reportEl);
    if (jsonBtn) jsonBtn.addEventListener("click", () => copyText(jsonBtn, $("pre.raw", reportEl).textContent));
}

async function copyText(btn, text) {
    try {
        await navigator.clipboard.writeText(text);
        const old = btn.textContent;
        btn.textContent = "copied";
        setTimeout(() => { btn.textContent = old; }, 1200);
    } catch (_) {
        btn.textContent = "copy failed";
    }
}

/* ===================================================================
   Accuracy view
   =================================================================== */

let accuracyData = null;
let accuracyMode = "binary";
let accuracyFilter = "wrong";

const MODES = {
    binary:  { label: "Phishing + Suspicious", hint: "An email counts as flagged when the verdict is Phishing or Suspicious." },
    strict:  { label: "Phishing only",         hint: "Only a Phishing verdict counts as flagged." },
    lenient: { label: "Anything but Benign",   hint: "Low Risk, Suspicious and Phishing all count as flagged (score 20 or more)." },
};

const isFlagged = (verdict, mode) =>
    mode === "strict" ? verdict === "Phishing"
    : mode === "lenient" ? verdict !== "Benign"
    : verdict === "Phishing" || verdict === "Suspicious";

async function loadAccuracy(force = false) {
    const root = $("#accuracy");
    if (accuracyData && !force) return renderAccuracy();

    root.innerHTML = '<p class="status"><span class="spinner" aria-hidden="true"></span>Loading evaluation results…</p>';
    try {
        const res = await fetch("/evaluation-results");
        if (!res.ok) throw new Error(`The server returned ${res.status}.`);
        accuracyData = await res.json();
        renderAccuracy();
    } catch (err) {
        root.innerHTML = `<p class="status is-error">${esc(err instanceof TypeError
            ? "Could not reach the API. Check that uvicorn is running." : err.message)}</p>`;
    }
}

function renderAccuracy() {
    const root = $("#accuracy");
    const d = accuracyData;

    if (!d.available) {
        root.innerHTML = `
            <div class="welcome">
                <h2>No evaluation results yet</h2>
                <p>Use <strong>Test a batch of emails</strong> above, or run the evaluation from the <span class="mono">backend</span> folder and reload this view:</p>
                <code class="command">${esc(d.command)}</code>
                <p style="margin-top:10px">It reads <span class="mono">../datasets/public_2026/phishing</span> and
                <span class="mono">…/benign</span>. Add <span class="mono">--dataset &lt;folder&gt;</span> to test another set.</p>
                <p style="margin-top:14px"><button class="btn" type="button" id="accReload">Reload results</button></p>
            </div>`;
        $("#accReload").addEventListener("click", () => loadAccuracy(true));
        return;
    }

    const m = d.metrics[accuracyMode];
    const when = new Date(d.generated_at * 1000).toLocaleString();
    const rows = d.rows.map((r) => ({ ...r, flagged: isFlagged(r.predicted, accuracyMode) }));
    const wrong = rows.filter((r) => (r.expected === "Phishing") !== r.flagged);
    const shown = accuracyFilter === "wrong" ? wrong : rows;

    root.innerHTML = `
        <div class="acc-head">
            <div>
                <h2>Accuracy on the evaluation set</h2>
                <p>${m.total} emails, results from ${esc(when)}${d.duplicates ? `, including ${d.duplicates} exact duplicate${d.duplicates === 1 ? "" : "s"}` : ""}. ${esc(MODES[accuracyMode].hint)}</p>
            </div>
            <div style="display:flex;gap:10px;flex-wrap:wrap;align-items:center">
                <div class="seg-control" role="group" aria-label="What counts as flagged">
                    ${Object.entries(MODES).map(([key, mode]) => `
                        <button type="button" data-mode="${key}" aria-pressed="${key === accuracyMode}">${esc(mode.label)}</button>`).join("")}
                </div>
                <button class="btn" type="button" id="accReload">Reload</button>
            </div>
        </div>

        <div class="report">
            <div class="acc-grid">
                <section class="report-section" aria-labelledby="matrix-title">
                    <h2 id="matrix-title">Confusion matrix</h2>
                    <div class="matrix" role="table" aria-label="Confusion matrix">
                        <span></span>
                        <span class="h" role="columnheader">Flagged</span>
                        <span class="h" role="columnheader">Not flagged</span>
                        <span class="rh" role="rowheader">Phishing</span>
                        <div class="cell is-right" role="cell"><strong>${m.tp}</strong><span>caught</span></div>
                        <div class="cell is-wrong" role="cell"><strong>${m.fn}</strong><span>missed</span></div>
                        <span class="rh" role="rowheader">Benign</span>
                        <div class="cell is-wrong" role="cell"><strong>${m.fp}</strong><span>false alarms</span></div>
                        <div class="cell is-right" role="cell"><strong>${m.tn}</strong><span>correctly passed</span></div>
                    </div>
                </section>
                <section class="report-section" aria-labelledby="metrics-title">
                    <h2 id="metrics-title" style="margin-bottom:14px">Metrics</h2>
                    <dl class="metric-list">
                        ${metric("Accuracy", m.accuracy, "all emails right")}
                        ${metric("Precision", m.precision, "flags that were real")}
                        ${metric("Recall", m.recall, "phishing caught")}
                        ${metric("F1 score", m.f1, "balance of both")}
                        ${metric("False alarms", m.false_positive_rate, "of benign flagged")}
                    </dl>
                    <h3 class="subhead">Verdicts by true label</h3>
                    ${renderDistribution(d.distribution)}
                </section>
            </div>

            <section class="report-section" aria-labelledby="rows-title">
                <div class="filter-row">
                    <h2 id="rows-title" style="margin-right:auto">${accuracyFilter === "wrong" ? `Misclassified emails (${wrong.length})` : `All emails (${rows.length})`}</h2>
                    <div class="seg-control" role="group" aria-label="Rows to show">
                        <button type="button" data-filter="wrong" aria-pressed="${accuracyFilter === "wrong"}">Misclassified</button>
                        <button type="button" data-filter="all" aria-pressed="${accuracyFilter === "all"}">All</button>
                    </div>
                </div>
                ${shown.length ? `<div class="table-wrap"><table>
                    <thead><tr><th>File</th><th>True label</th><th>Verdict</th><th class="num">Score</th><th>Signals</th><th>Top findings</th></tr></thead>
                    <tbody>${shown.map((r) => `
                        <tr>
                            <td class="mono" title="${esc(r.file)}">${esc(shortName(r.file))}${r.duplicate_of ? `<br><span class="muted">duplicate of ${esc(shortName(r.duplicate_of))}</span>` : ""}</td>
                            <td>${esc(r.expected)}</td>
                            <td><span class="level" style="--level-color:${(VERDICTS[r.predicted] || {}).color || "var(--unknown)"}">${esc(r.predicted)}</span></td>
                            <td class="num">${num(r.risk_score)}</td>
                            <td>${esc((r.signals || "").replace(/\+/g, ", ")) || '<span class="muted">none</span>'}</td>
                            <td>${esc(r.top_findings || "")}</td>
                        </tr>`).join("")}
                    </tbody></table></div>`
                : '<p class="empty">No misclassified emails for this setting.</p>'}
            </section>
        </div>`;

    $$("[data-mode]", root).forEach((b) => b.addEventListener("click", () => { accuracyMode = b.dataset.mode; renderAccuracy(); }));
    $$("[data-filter]", root).forEach((b) => b.addEventListener("click", () => { accuracyFilter = b.dataset.filter; renderAccuracy(); }));
    $("#accReload").addEventListener("click", () => loadAccuracy(true));
}

function shortName(name) {
    // "0002.24b47bb3ce90708ae29d0aec1da08610.eml" -> "0002.24b47bb3…eml"
    const m = String(name).match(/^([^.]+\.)([0-9a-f]{16,})(\.\w+)?$/i);
    return m ? `${m[1]}${m[2].slice(0, 8)}…${m[3] || ""}` : name;
}

function metric(label, value, hint) {
    return `<div class="metric"><dt>${label}</dt><dd>${num(value).toFixed(1)}%<span class="hint">${hint}</span></dd></div>`;
}

function renderDistribution(dist) {
    const order = ["Phishing", "Suspicious", "Low Risk", "Benign"];
    const rows = ["Phishing", "Benign"].map((label) => {
        const counts = dist[label] || {};
        const total = order.reduce((n, v) => n + (counts[v] || 0), 0) || 1;
        const segs = order.filter((v) => counts[v]).map((v) =>
            `<span style="width:${(counts[v] / total) * 100}%;background:${VERDICTS[v].color}"
                data-tip="${esc(`<strong>${v}</strong>${counts[v]} of ${total} ${label.toLowerCase()} emails`)}" tabindex="0"
                aria-label="${v}: ${counts[v]}"></span>`).join("");
        return `<div class="dist-row"><span>${label} emails</span><div class="dist-bar">${segs}</div></div>`;
    }).join("");
    const legend = order.map((v) => `<li><span class="swatch" style="background:${VERDICTS[v].color}" aria-hidden="true"></span>${v}</li>`).join("");
    return `${rows}<ul class="dist-legend">${legend}</ul>`;
}

/* ===================================================================
   Batch test: upload many labelled emails and measure accuracy
   =================================================================== */

const BATCH_CHUNK = 10;
const batch = { Phishing: [], Benign: [], running: false, cancel: false, network: false };
try { batch.network = localStorage.getItem("batchNetwork") === "1"; } catch (_) { /* ignore */ }

function renderBatch() {
    const root = $("#batch");
    const total = batch.Phishing.length + batch.Benign.length;

    const zone = (label, title, hint) => `
        <div class="batch-zone" data-label="${label}">
            <h3>${title} <span class="muted">${batch[label].length}</span></h3>
            <p class="section-note">${hint}</p>
            <div class="batch-actions">
                <button type="button" class="btn" data-pick="${label}">Choose files</button>
                <button type="button" class="btn" data-pick-folder="${label}">Choose folder</button>
                ${batch[label].length ? `<button type="button" class="link-button" data-clear="${label}">Clear</button>` : ""}
            </div>
            <input type="file" multiple hidden data-input="${label}">
            <input type="file" multiple webkitdirectory hidden data-input-folder="${label}">
        </div>`;

    root.innerHTML = `
        <section class="report batch" aria-labelledby="batch-title">
            <div class="report-section">
                <div class="section-head">
                    <h2 id="batch-title">Test a batch of emails</h2>
                    <span class="section-note">Results replace the table below</span>
                </div>
                <p class="batch-intro">Add emails you already know are phishing, and emails you know are legitimate.
                Each one is analysed (without the AI report) and compared with its label.
                You can also drop files onto each box.</p>
                <div class="batch-grid">
                    ${zone("Phishing", "Known phishing", ".eml files or a folder of them")}
                    ${zone("Benign", "Known legitimate", "Normal mail, newsletters, receipts")}
                </div>
                <div class="batch-run">
                    <label class="check">
                        <input type="checkbox" id="batchNetwork" ${batch.network ? "checked" : ""}>
                        <span>Include WHOIS, DNS and VirusTotal <span class="muted">(slower; VirusTotal allows ${(lookupStatus && lookupStatus.virustotal && lookupStatus.virustotal.requests_per_minute) || 4} lookups a minute, so test 20 to 50 emails at a time)</span></span>
                    </label>
                    <button type="button" class="btn btn-primary" id="batchRun" ${total && !batch.running ? "" : "disabled"}>
                        ${batch.running ? "Testing…" : `Run test on ${plural(total, "email", "emails")}`}
                    </button>
                    ${batch.running ? '<button type="button" class="btn" id="batchCancel">Stop</button>' : ""}
                </div>
                <div class="batch-progress" id="batchProgress" ${batch.running ? "" : "hidden"}>
                    <div class="progress"><span id="batchBar" style="width:0%"></span></div>
                    <p class="section-note" id="batchText" role="status" aria-live="polite"></p>
                </div>
            </div>
        </section>`;

    const add = (label, fileList) => {
        const files = [...fileList].filter((f) =>
            f.size > 0 && f.size <= 10 * 1024 * 1024 && f.name !== "cmds" && !f.name.startsWith("."));
        const seen = new Set(batch[label].map((f) => `${f.name}:${f.size}`));
        files.forEach((f) => { if (!seen.has(`${f.name}:${f.size}`)) batch[label].push(f); });
        renderBatch();
    };

    $$("[data-pick]", root).forEach((b) => b.addEventListener("click", () => $(`[data-input="${b.dataset.pick}"]`, root).click()));
    $$("[data-pick-folder]", root).forEach((b) => b.addEventListener("click", () => $(`[data-input-folder="${b.dataset.pickFolder}"]`, root).click()));
    $$("[data-input], [data-input-folder]", root).forEach((input) => input.addEventListener("change", () =>
        add(input.dataset.input || input.dataset.inputFolder, input.files)));
    $$("[data-clear]", root).forEach((b) => b.addEventListener("click", () => { batch[b.dataset.clear] = []; renderBatch(); }));

    $$(".batch-zone", root).forEach((zoneEl) => {
        ["dragenter", "dragover"].forEach((t) => zoneEl.addEventListener(t, (e) => { e.preventDefault(); zoneEl.classList.add("is-over"); }));
        ["dragleave", "drop"].forEach((t) => zoneEl.addEventListener(t, (e) => { e.preventDefault(); zoneEl.classList.remove("is-over"); }));
        zoneEl.addEventListener("drop", (e) => add(zoneEl.dataset.label, e.dataTransfer.files));
    });

    const netBox = $("#batchNetwork", root);
    netBox.addEventListener("change", () => {
        batch.network = netBox.checked;
        try { localStorage.setItem("batchNetwork", batch.network ? "1" : "0"); } catch (_) { /* ignore */ }
    });

    const run = $("#batchRun", root);
    if (run) run.addEventListener("click", runBatch);
    const cancel = $("#batchCancel", root);
    if (cancel) cancel.addEventListener("click", () => { batch.cancel = true; });
}

async function runBatch() {
    const queue = [
        ...batch.Phishing.map((f) => ({ file: f, label: "Phishing" })),
        ...batch.Benign.map((f) => ({ file: f, label: "Benign" })),
    ];
    if (!queue.length) return;

    const network = batch.network;
    batch.running = true;
    batch.cancel = false;
    renderBatch();

    const rows = [];
    const errors = [];
    const started = performance.now();

    const progress = (done) => {
        const bar = $("#batchBar"), text = $("#batchText");
        if (!bar) return;
        bar.style.width = `${(done / queue.length) * 100}%`;
        const secs = (performance.now() - started) / 1000;
        const eta = done ? Math.round((secs / done) * (queue.length - done)) : 0;
        text.textContent = `Analysed ${done} of ${queue.length} emails` + (done && done < queue.length ? `, about ${eta} s left` : "");
    };
    progress(0);

    try {
        for (let i = 0; i < queue.length; i += BATCH_CHUNK) {
            if (batch.cancel) break;
            const chunk = queue.slice(i, i + BATCH_CHUNK);
            const form = new FormData();
            chunk.forEach((item) => {
                form.append("files", item.file, item.file.name);
                form.append("labels", item.label);
            });
            const res = await fetch(`/analyze-batch?network=${network}`, { method: "POST", body: form });
            const data = await res.json().catch(() => null);
            if (!res.ok || !data) throw new Error(`The server returned ${res.status}${data && data.detail ? `: ${data.detail}` : ""}.`);
            data.rows.forEach((r) => (r.error ? errors : rows).push(r));
            progress(Math.min(i + BATCH_CHUNK, queue.length));
        }

        // Mark exact duplicates (same file content) so they can be excluded.
        const firstByHash = {};
        rows.forEach((r) => {
            if (r.sha256 && firstByHash[r.sha256]) r.duplicate_of = firstByHash[r.sha256];
            else if (r.sha256) firstByHash[r.sha256] = r.file;
        });

        if (!rows.length) throw new Error("No emails could be analysed.");

        const save = await fetch("/evaluation-results", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ rows }),
        });
        if (!save.ok) throw new Error(`Saving the results failed (${save.status}).`);

        const secs = ((performance.now() - started) / 1000).toFixed(0);
        batch.running = false;
        renderBatch();
        $("#batchProgress").hidden = false;
        $("#batchBar").style.width = "100%";
        $("#batchText").textContent =
            `${batch.cancel ? "Stopped early. " : ""}Tested ${rows.length} emails in ${secs} s ` +
            (network ? "with WHOIS, DNS and VirusTotal" : "without online checks") +
            (errors.length ? `; ${errors.length} could not be read (${errors.slice(0, 3).map((e) => esc(e.file)).join(", ")}${errors.length > 3 ? "…" : ""})` : "") + ".";
        accuracyData = null;
        await loadAccuracy(true);
    } catch (err) {
        batch.running = false;
        renderBatch();
        $("#batchProgress").hidden = false;
        $("#batchText").textContent = err instanceof TypeError ? "Could not reach the API. Check that uvicorn is running." : err.message;
        $("#batchText").classList.add("is-error");
    }
}

/* ------------------------------------------------------------- start */

renderWelcome();
renderBatch();
loadLookupStatus();
if (location.hash === "#accuracy") showView("accuracy");
