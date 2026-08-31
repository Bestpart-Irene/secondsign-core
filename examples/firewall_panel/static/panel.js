// Copyright 2026 SecondSign contributors
// SPDX-License-Identifier: Apache-2.0
//
// The page holds no policy and decides nothing. Every verdict it shows arrives
// from the server, which got it from the co-signer; this file only renders.

const $ = (id) => document.getElementById(id);
let selected = null;

async function api(path, body) {
  const res = await fetch(path, {
    method: body === undefined ? "GET" : "POST",
    headers: { "Content-Type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const payload = await res.json();
  if (!res.ok || payload.error) throw new Error(payload.error || `HTTP ${res.status}`);
  return payload;
}

function toast(message) {
  const node = document.createElement("div");
  node.className = "toast";
  node.textContent = message;
  document.body.appendChild(node);
  setTimeout(() => node.remove(), 5000);
}

const text = (tag, cls, value) => {
  const node = document.createElement(tag);
  if (cls) node.className = cls;
  if (value !== undefined) node.textContent = value;
  return node;
};

// -- rendering -------------------------------------------------------------

function renderScenarios(state) {
  const host = $("scenarios");
  host.replaceChildren();
  for (const scenario of state.scenarios) {
    const button = text("button", "scenario");
    button.type = "button";
    button.setAttribute("aria-current", String(scenario.key === selected));
    button.append(text("div", "t", scenario.title), text("div", "d", scenario.detail));
    button.addEventListener("click", () => propose(scenario.key));
    host.append(button);
  }
}

function renderKnobs(state) {
  $("cap").value = state.knobs.approval_cap_usdc;
  $("review").value = state.knobs.review_above_usdc;
  $("vouched").textContent = state.knobs.vouched.length ? state.knobs.vouched.join(", ") : "none (fail-closed)";
}

function renderAccount(state) {
  const safe = state.safe;
  const drifted = (a, b) => (String(a).toLowerCase() === String(b).toLowerCase() ? "good" : "bad");
  const rows = [
    ["balance", `${safe.balance} USDC`, ""],
    ["owners", `${safe.owners.length} · ${safe.threshold}-of-${safe.owners.length}`, safe.threshold === 2 ? "good" : "bad"],
    ["chain", `${safe.chain_id}`, drifted(safe.chain_id, safe.attested_chain_id)],
    ["Safe version", safe.safe_version, ""],
    ["tx guard", safe.transaction_guard, safe.transaction_guard === "0x" + "0".repeat(40) ? "bad" : "good"],
    ["module guard", safe.module_guard, ""],
    ["token", safe.token, ""],
    ["token impl", safe.token_implementation, ""],
    ["chain reader", safe.reader_wired ? "wired" : "UNWIRED", safe.reader_wired ? "good" : "bad"],
    ["co-signer", safe.cosigner, ""],
  ];
  const host = $("account");
  host.replaceChildren();
  for (const [key, value, cls] of rows) {
    host.append(text("dt", "", key), text("dd", cls, value));
  }
  $("account-note").textContent = safe.address.slice(0, 10) + "…";
}

function renderTampers(state) {
  const host = $("tampers");
  host.replaceChildren();
  for (const tamper of state.tampers) {
    const row = text("div", `tamper${tamper.applied ? " on" : ""}`);
    const box = document.createElement("input");
    box.type = "checkbox";
    box.checked = tamper.applied;
    box.disabled = tamper.applied;
    box.id = `t-${tamper.key}`;
    box.addEventListener("change", () => act(() => api("/api/tamper", { tamper: tamper.key })));
    const label = text("label", "", tamper.label);
    label.htmlFor = box.id;
    row.append(box, label);
    host.append(row);
  }
  const repair = text("button", "", "Repair the account");
  repair.type = "button";
  repair.style.cssText = "margin-top:10px;padding:5px 12px;width:100%";
  repair.addEventListener("click", () => act(() => api("/api/tamper", { repair: true })));
  host.append(repair);
}

function renderReviews(state) {
  const host = $("reviews");
  host.replaceChildren();
  $("reviews-note").textContent = state.reviews.length ? `${state.reviews.length} open` : "none";
  if (!state.reviews.length) {
    host.append(text("p", "empty", "Nothing is waiting on a human."));
    return;
  }
  for (const review of state.reviews) {
    const item = text("div", "review-item");
    item.append(text("div", "id", review.approval_id.slice(0, 26) + "…"));
    item.append(text("div", "d", `proposed by ${review.maker}`));

    const picker = document.createElement("select");
    for (const checker of state.checkers) {
      const option = document.createElement("option");
      option.value = checker.subject;
      option.textContent = checker.label;
      picker.append(option);
    }
    item.append(text("div", "d", "answer as:"), picker);

    const actions = text("div", "review-actions");
    const approve = text("button", "approve", "Approve");
    const decline = text("button", "decline", "Decline");
    approve.type = decline.type = "button";
    approve.addEventListener("click", () =>
      resolve(review.approval_id, picker.value, true));
    decline.addEventListener("click", () =>
      resolve(review.approval_id, picker.value, false));
    actions.append(approve, decline);
    item.append(actions);
    host.append(item);
  }
}

function renderAudit(state) {
  const host = $("audit");
  host.replaceChildren();
  if (!state.audit.length) {
    host.append(text("p", "empty", "No decision has been made yet."));
    return;
  }
  const table = text("table", "audit");
  const head = document.createElement("tr");
  for (const label of ["#", "digest", "verdict", "receipt"]) head.append(text("th", "", label));
  table.append(head);
  for (const row of state.audit) {
    const tr = document.createElement("tr");
    tr.append(text("td", "", row.sequence), text("td", "", row.digest));
    tr.append(text("td", `v-${row.verdict.toLowerCase()}`, row.verdict));
    tr.append(text("td", "", row.receipt_hash));
    table.append(tr);
  }
  host.append(table);
}

function renderVerdict(outcome, title) {
  const host = $("verdict");
  host.replaceChildren();
  if (!outcome) return;
  const words = { signed: "Signed", held: "Held for a human", refused: "Refused" };
  const banner = text("div", `verdict ${outcome.status}`);
  banner.append(text("span", "big", words[outcome.status] || outcome.status));
  if (outcome.reasons.length) banner.append(text("span", "sig", outcome.reasons.join(", ")));
  banner.append(
    text("span", "sig", outcome.signature
      ? `second signature ${outcome.signature.slice(0, 24)}…`
      : "no second signature — the agent cannot reach the 2-of-2 threshold"));
  host.append(banner);
  $("pipeline-note").textContent = title || "";
}

function renderStations(stations) {
  const host = $("pipeline");
  host.replaceChildren();
  for (const station of stations) {
    const row = text("div", `station ${station.state}`);
    row.append(text("div", "rail"));
    const body = text("div", "st-body");
    const top = text("div", "st-top");
    top.append(text("span", "st-ord", station.ordinal), text("span", "st-title", station.title));
    top.append(text("span", `tag ${station.state}`, station.state));
    top.append(text("span", "prov", station.provenance));
    body.append(top, text("div", "st-sum", station.summary));
    if (station.facts.length) {
      const facts = text("dl", "facts");
      for (const [key, value] of station.facts) {
        facts.append(text("dt", "", key), text("dd", "", value));
      }
      body.append(facts);
    }
    row.append(body);
    host.append(row);
  }
}

function renderState(state) {
  renderScenarios(state);
  renderKnobs(state);
  renderAccount(state);
  renderTampers(state);
  renderReviews(state);
  renderAudit(state);
}

// -- actions ---------------------------------------------------------------

async function act(fn) {
  try {
    const payload = await fn();
    if (payload.state) renderState(payload.state);
    return payload;
  } catch (error) {
    toast(error.message);
    return null;
  }
}

async function propose(key) {
  selected = key;
  const payload = await act(() => api("/api/propose", { scenario: key }));
  if (!payload) return;
  renderVerdict(payload.outcome, payload.scenario.title);
  renderStations(payload.stations);
}

async function resolve(approvalId, checker, approved) {
  const payload = await act(() => api("/api/resolve", { approval_id: approvalId, checker, approved }));
  if (!payload) return;
  renderVerdict(payload.outcome, approved ? "the answer to a held review" : "review declined");
  // The answer's own stations replace the proposal's: `resolve` re-reads the
  // chain, so leaving the earlier PASS on screen under a fresh refusal would
  // have the panel contradict itself.
  renderStations(payload.stations);
}

function knobHandler(field) {
  return () => act(() => api("/api/reconfigure", { [field]: $(field === "approval_cap_usdc" ? "cap" : "review").value }));
}

$("cap").addEventListener("change", knobHandler("approval_cap_usdc"));
$("review").addEventListener("change", knobHandler("review_above_usdc"));
$("reset").addEventListener("click", () => {
  selected = null;
  $("verdict").replaceChildren();
  $("pipeline").replaceChildren(text("p", "empty", "Choose a proposal on the left."));
  $("pipeline-note").textContent = "nothing proposed yet";
  act(() => api("/api/reset", {}));
});

act(() => api("/api/state").then((state) => ({ state })));
