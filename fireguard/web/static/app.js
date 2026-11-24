async function api(path, method = "GET", body = null) {
  const opts = { method, headers: { "Content-Type": "application/json" } };
  if (body !== null) opts.body = JSON.stringify(body);
  const res = await fetch(path, opts);
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || "Request failed");
  return data;
}

function showAlert(msg, isError = false) {
  const box = document.getElementById("alertBox");
  box.textContent = msg;
  box.style.background = isError ? "#7f1d1d" : "#1e3a8a";
  box.classList.remove("hidden");
  setTimeout(() => box.classList.add("hidden"), 6000);
}

let confirmToken = null;
let rbInterval = null;

async function refreshAll() {
  const data = await api("/api/policy");
  const pol = data.policy;

  // Defaults
  document.getElementById("dInbound").value = pol.defaults.default_inbound;
  document.getElementById("dOutbound").value = pol.defaults.default_outbound;
  document.getElementById("dTimeout").value = pol.defaults.rollback_timeout_seconds;
  document.getElementById("dLoopback").checked = pol.defaults.allow_loopback;
  document.getElementById("dEstablished").checked = pol.defaults.allow_established;
  document.getElementById("dIpv6").checked = pol.defaults.handle_ipv6_consistently;
  document.getElementById("jsonBox").value = JSON.stringify(pol, null, 2);

  // Validation
  const valBox = document.getElementById("validationBox");
  const issues = [...data.validation.errors, ...data.validation.warnings];
  valBox.innerHTML = issues.map(i =>
    `<div class="alert" style="background:${i.level === 'error' ? '#7f1d1d' : '#78350f'}">
      <strong>${i.level.toUpperCase()}</strong> [${i.code}]: ${i.message}
    </div>`
  ).join("");

  // Rules
  const list = document.getElementById("rulesList");
  if (!pol.rules.length) {
    list.innerHTML = `<p class="muted">No custom rules yet. Add one above or load a starter policy.</p>`;
  } else {
    list.innerHTML = pol.rules.map((r, idx) => `
      <div class="rule-item ${r.enabled ? "" : "disabled"}">
        <div>
          <strong>#${idx + 1} ${r.name}</strong> <code>[${r.id}]</code>
          <div class="muted">${data.explanations[r.id] || ""}</div>
        </div>
        <div class="row">
          <button class="btn btn-secondary" onclick="moveRule('${r.id}', -1)">Up</button>
          <button class="btn btn-secondary" onclick="moveRule('${r.id}', 1)">Down</button>
          <button class="btn btn-secondary" onclick="toggleRule('${r.id}')">${r.enabled ? "Disable" : "Enable"}</button>
          <button class="btn btn-danger" onclick="deleteRule('${r.id}')">Delete</button>
        </div>
      </div>
    `).join("");
  }
}

async function loadStarters() {
  const data = await api("/api/starters");
  const el = document.getElementById("startersList");
  el.innerHTML = Object.entries(data.starters).map(([name, info]) => `
    <div class="row" style="align-items:center; justify-content:space-between;">
      <div><strong>${name}</strong> <span class="muted">(${info.rule_count} rules) — ${info.description}</span></div>
      <button class="btn btn-secondary" onclick="loadStarter('${name}')">Load</button>
    </div>
  `).join("");
}

window.loadStarter = async (name) => {
  await api("/api/starters/load", "POST", { name });
  showAlert(`Loaded starter policy '${name}' (draft only; not applied).`);
  await refreshAll();
};
window.toggleRule = async (id) => { await api("/api/rules/toggle", "POST", { id }); await refreshAll(); };
window.moveRule = async (id, delta) => { await api("/api/rules/move", "POST", { id, delta }); await refreshAll(); };
window.deleteRule = async (id) => { await api("/api/rules/delete", "POST", { id }); await refreshAll(); };

document.querySelectorAll(".tab").forEach(btn => {
  btn.addEventListener("click", () => {
    document.querySelectorAll(".tab, .tab-panel").forEach(el => el.classList.remove("active"));
    btn.classList.add("active");
    document.getElementById(`tab-${btn.dataset.tab}`).classList.add("active");
  });
});

document.getElementById("quickRuleForm").addEventListener("submit", async (e) => {
  e.preventDefault();
  const splitList = (v) => v.split(",").map(s => s.trim()).filter(Boolean);
  const payload = {
    name: document.getElementById("qName").value,
    direction: document.getElementById("qDir").value,
    action: document.getElementById("qAction").value,
    ip_version: document.getElementById("qIpVer").value,
    protocol: document.getElementById("qProto").value,
    dest_ports: splitList(document.getElementById("qDstPort").value),
    source_ports: splitList(document.getElementById("qSrcPort").value),
    source_ips: splitList(document.getElementById("qSrcIp").value),
    dest_ips: splitList(document.getElementById("qDstIp").value),
    interface: document.getElementById("qIface").value || null,
    application: document.getElementById("qApp").value || null,
    schedule: document.getElementById("qExpires").value ? { expires_at: document.getElementById("qExpires").value } : null,
  };
  try {
    await api("/api/rules", "POST", payload);
    e.target.reset();
    showAlert("Rule added to draft policy.");
    await refreshAll();
  } catch (err) {
    showAlert(err.message, true);
  }
});

document.getElementById("defaultsForm").addEventListener("submit", async (e) => {
  e.preventDefault();
  try {
    await api("/api/defaults", "POST", {
      default_inbound: document.getElementById("dInbound").value,
      default_outbound: document.getElementById("dOutbound").value,
      rollback_timeout_seconds: Number(document.getElementById("dTimeout").value),
      allow_loopback: document.getElementById("dLoopback").checked,
      allow_established: document.getElementById("dEstablished").checked,
      handle_ipv6_consistently: document.getElementById("dIpv6").checked,
    });
    showAlert("System defaults saved.");
    await refreshAll();
  } catch (err) {
    showAlert(err.message, true);
  }
});

document.getElementById("simForm").addEventListener("submit", async (e) => {
  e.preventDefault();
  try {
    const res = await api("/api/simulate", "POST", {
      direction: document.getElementById("sDir").value,
      protocol: document.getElementById("sProto").value,
      source_ip: document.getElementById("sSrcIp").value,
      dest_ip: document.getElementById("sDstIp").value,
      dest_port: document.getElementById("sDstPort").value || null,
      established: document.getElementById("sEst").checked,
    });
    document.getElementById("simResult").textContent = JSON.stringify(res, null, 2);
  } catch (err) {
    showAlert(err.message, true);
  }
});

document.getElementById("btnPreview").addEventListener("click", async () => {
  const backend = document.getElementById("backendSelect").value;
  const prev = await api("/api/preview", "POST", { backend });
  document.getElementById("previewScript").textContent =
    `# Backend: ${prev.platform_name}\n` +
    (prev.warnings.length ? `# Warnings:\n# - ${prev.warnings.join("\n# - ")}\n\n` : "") +
    prev.rendered_script;
  showAlert("Dry-run preview updated in Advanced View.");
});

document.getElementById("btnApply").addEventListener("click", async () => {
  const backend = document.getElementById("backendSelect").value;
  if (!confirm("Apply current policy to the LIVE system firewall? Previous state will be snapshotted for rollback.")) {
    return;
  }
  try {
    const res = await api("/api/apply", "POST", { backend, dry_run: false, confirmed: true });
    if (res.confirm_token) {
      confirmToken = res.confirm_token;
      let left = res.rollback_timeout_seconds || 60;
      document.getElementById("rbTimer").textContent = left;
      document.getElementById("rollbackBanner").classList.remove("hidden");
      clearInterval(rbInterval);
      rbInterval = setInterval(() => {
        left -= 1;
        document.getElementById("rbTimer").textContent = Math.max(0, left);
        if (left <= 0) {
          clearInterval(rbInterval);
          document.getElementById("rollbackBanner").classList.add("hidden");
        }
      }, 1000);
    }
    showAlert(res.message);
  } catch (err) {
    showAlert(err.message, true);
  }
});

document.getElementById("btnConfirmConn").addEventListener("click", async () => {
  if (!confirmToken) return;
  await api("/api/confirm", "POST", { token: confirmToken });
  clearInterval(rbInterval);
  confirmToken = null;
  document.getElementById("rollbackBanner").classList.add("hidden");
  showAlert("Connectivity confirmed. Auto-rollback cancelled.");
});

document.getElementById("btnRollback").addEventListener("click", async () => {
  const backend = document.getElementById("backendSelect").value;
  try {
    const res = await api("/api/rollback", "POST", { backend });
    showAlert(res.message);
  } catch (err) {
    showAlert(err.message, true);
  }
});

document.getElementById("btnImport").addEventListener("click", async () => {
  try {
    await api("/api/import", "POST", { raw_json: document.getElementById("jsonBox").value });
    showAlert("Policy imported and validated.");
    await refreshAll();
  } catch (err) {
    showAlert(err.message, true);
  }
});

document.getElementById("btnExport").addEventListener("click", refreshAll);

document.getElementById("btnRefreshAudit").addEventListener("click", async () => {
  const data = await api("/api/audit");
  document.getElementById("auditBox").textContent = JSON.stringify(data.entries, null, 2);
});

loadStarters();
refreshAll();
