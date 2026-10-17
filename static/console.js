/* SentinelOps AI public console — synthetic, read-only API consumer. */
(function () {
  "use strict";
  const $ = (id) => document.getElementById(id);
  let selected = 1, report = null, controller = null;
  const riskOrder = ["LOW", "MEDIUM", "HIGH", "CRITICAL"];
  const names = {1:"Normal Activity",2:"Authentication Incident",3:"Threat Cluster"};
  const text = (tag, value, className) => {
    const el = document.createElement(tag);
    el.textContent = String(value);
    if (className) el.className = className;
    return el;
  };
  function setState(label, error) {
    $("request-state").textContent = label;
    $("request-state").style.color = error ? "#fc7280" : "#44ddb9";
  }
  function bars(data) {
    const root = $("risk-bars"); root.replaceChildren();
    const max = Math.max(1, data.total_events);
    riskOrder.forEach((risk) => {
      const row = text("div", "", "risk-row");
      row.append(text("b", risk));
      const track = text("div", "", "track");
      const fill = text("div", "", "fill " + risk);
      fill.style.width = Math.max(0, Math.min(100, 100 * (data.risk_distribution[risk] || 0) / max)) + "%";
      track.append(fill);
      row.append(track, text("strong", data.risk_distribution[risk] || 0));
      root.append(row);
    });
  }
  function explain(event, row) {
    const details = document.createElement("tr");
    details.className = "details-row";
    const td = document.createElement("td"); td.colSpan = 7;
    const wrapper = text("div", "", "details-content");
    [["Severity", event.contributions.severity], ["Failed logins", event.contributions.failed_logins],
     ["Suspicious process", event.contributions.suspicious_process]].forEach(([name, score]) => {
      const box = text("div", "", "detail-metric");
      box.append(text("b", "+" + score + " points"), text("span", name));
      wrapper.append(box);
    });
    td.append(wrapper);
    const factors = text("p", event.factors.join(" • "), "details-factors");
    td.append(factors);
    details.append(td);
    row.after(details);
    return details;
  }
  function drawEvents() {
    const tbody = $("event-rows"); tbody.replaceChildren();
    if (!report) return;
    const query = $("filter").value.trim().toLowerCase();
    const events = report.events.filter(ev =>
      ev.id.toLowerCase().includes(query) || ev.source.toLowerCase().includes(query)
      || ev.risk.toLowerCase().includes(query));
    $("event-count").textContent = events.length;
    if (!events.length) {
      const row = document.createElement("tr"), cell = document.createElement("td");
      cell.colSpan = 7; cell.textContent = "No events match this filter.";
      row.append(cell); tbody.append(row); return;
    }
    events.forEach(ev => {
      const row = document.createElement("tr");
      [ev.id, ev.source, ev.severity + " / 10", ev.failed_logins, ev.score + " / 100"].forEach(v => row.append(text("td", v)));
      const riskCell = document.createElement("td");
      riskCell.append(text("span", ev.risk, "risk-tag " + ev.risk));
      row.append(riskCell);
      const actionCell = document.createElement("td");
      const button = text("button", "Explain score", "explain-button"); button.type = "button";
      button.setAttribute("aria-expanded", "false");
      let extra = null;
      button.addEventListener("click", () => {
        if (extra) {extra.remove();extra=null;button.textContent="Explain score";button.setAttribute("aria-expanded","false");}
        else { extra=explain(ev,row);button.textContent="Hide explanation";button.setAttribute("aria-expanded","true"); }
      });
      actionCell.append(button); row.append(actionCell); tbody.append(row);
    });
  }
  function findings(data) {
    const root = $("finding-rows"); root.replaceChildren();
    if (!data.correlations.length) {
      const blank = text("div", "", "no-findings");
      blank.append(text("strong", "✓ No correlation findings"), text("span", "No detection rules triggered for this synthetic scenario."));
      root.append(blank); return;
    }
    data.correlations.forEach(f => {
      const block = text("article", "", "finding");
      const top = text("div", "", "finding-top");
      top.append(text("span", f.rule_id, "rule"), text("span", f.finding_type.replaceAll("_"," "), "finding-type"));
      block.append(top, text("p", f.description), text("small", "Affected: " + f.event_ids.join(", ")));
      root.append(block);
    });
  }
  function render(data) {
    report = data;
    $("total").textContent = data.total_events;
    $("critical").textContent = data.risk_distribution.CRITICAL;
    $("finding-count").textContent = data.correlations.length;
    $("success").textContent = data.total_events ? Math.round(data.success_count * 100 / data.total_events) + "%" : "100%";
    $("findings-count").textContent = data.correlations.length;
    $("active-title").replaceChildren(text("span", names[selected] + " "), text("span", "/ Scenario 0" + selected, "result-marker"));
    $("active-description").textContent = data.description;
    bars(data);drawEvents();findings(data);
  }
  async function load(number) {
    if (![1,2,3].includes(number)) return;
    selected = number;
    for(const item of document.querySelectorAll("[data-scenario]")) {
      const active = Number(item.dataset.scenario) === number;
      item.classList.toggle("is-active", active);
      item.classList.toggle("selected", active);
      item.setAttribute("aria-pressed", String(active));
    }
    if (controller) controller.abort();
    controller = new AbortController();
    $("error").hidden = true;
    setState("ANALYZING...");
    try {
      const response = await fetch("/demo/scenario/" + number, {signal:controller.signal,cache:"no-store",credentials:"same-origin"});
      if (!response.ok) throw new Error("HTTP " + response.status);
      const data = await response.json();
      if (!data || !data.synthetic || data.scenario !== number || !Array.isArray(data.events) ||
          !Array.isArray(data.correlations) || !data.risk_distribution) throw new Error("Invalid report format");
      render(data);
      setState("✓ ANALYSIS COMPLETE");
    } catch (err) {
      if (err.name === "AbortError") return;
      setState("ERROR", true);
      $("error").hidden = false;
      $("error").textContent = "Unable to load this scenario. Check connectivity and select Re-run analysis.";
    }
  }
  document.querySelectorAll("[data-scenario]").forEach(b => b.addEventListener("click", () => load(Number(b.dataset.scenario))));
  $("refresh").addEventListener("click", () => load(selected));
  $("filter").addEventListener("input", drawEvents);
  $("export").addEventListener("click", () => {
    if (!report) return;
    const data = JSON.stringify(report, null, 2);
    const file = new Blob([data],{type:"application/json"});
    const url = URL.createObjectURL(file);
    const anchor = document.createElement("a");
    anchor.href=url; anchor.download="sentinelops-scenario-"+selected+".json";
    document.body.append(anchor); anchor.click(); anchor.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  });
  load(1);
})();