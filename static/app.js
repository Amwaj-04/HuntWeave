(() => {
  const root = document.documentElement;
  const themeButton = document.getElementById('themeToggle');
  const savedTheme = (() => { try { return localStorage.getItem('huntweave-theme'); } catch { return null; } })();
  if (savedTheme === 'light' || savedTheme === 'dark') root.dataset.theme = savedTheme;
  themeButton.addEventListener('click', () => {
    root.dataset.theme = root.dataset.theme === 'light' ? 'dark' : 'light';
    try { localStorage.setItem('huntweave-theme', root.dataset.theme); } catch { /* private browsing */ }
  });

  const backdrop = document.getElementById('modalBackdrop');
  const content = document.getElementById('investigationContent');
  const closeButton = document.getElementById('closeModal');
  let activeHunt = null;
  let openerElement = null;
  const escapeHtml = (v) => String(v ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  const formatTime = (v) => { try { return new Date(v).toLocaleString(undefined, {month:'short',day:'2-digit',hour:'2-digit',minute:'2-digit',second:'2-digit',hour12:false}); } catch { return v; } };
  const labelVerdict = (v) => ({NOT_REVIEWED:'Not reviewed',SUPPORTED:'Supported by evidence',NOT_SUPPORTED:'Not supported',INCONCLUSIVE:'Inconclusive'}[v] || v);

  async function openHunt(id) {
    openerElement = document.activeElement;
    activeHunt = id;
    backdrop.hidden = false;
    document.body.classList.add('modal-open');
    closeButton.focus();
    content.innerHTML = '<div class="loading">Loading investigation…</div>';
    try {
      const response = await fetch(`/api/hunts/${encodeURIComponent(id)}`);
      if (!response.ok) throw new Error('Could not load this investigation.');
      const data = await response.json();
      renderHunt(data);
    } catch (err) { content.innerHTML = `<div class="empty">${escapeHtml(err.message)}</div>`; }
  }

  function renderHunt(data, filters = {}) {
    const h = data.hunt, note = data.note || {};
    const events = data.events || [];
    content.innerHTML = `
      <div class="investigation-top"><div><p class="eyebrow">${escapeHtml(h.id)} · ${escapeHtml(h.category.toUpperCase())}</p><h2 id="modalTitle">${escapeHtml(h.title)}</h2><p class="lede">Start with a question. Gather the relevant events, compare context, and record a conclusion that stays within the evidence.</p></div><span class="tag tag-${h.level.toLowerCase()}">${escapeHtml(h.level)}</span></div>
      <div class="stepbar"><div class="step"><b>01</b>Hypothesis</div><div class="step"><b>02</b>Explore events</div><div class="step"><b>03</b>Weigh evidence</div><div class="step"><b>04</b>Record finding</div></div>
      <section class="panel"><h3>Hunt hypothesis</h3><p>${escapeHtml(h.hypothesis)}</p><p class="small-note"><strong>Look for:</strong> ${escapeHtml(h.look_for)}</p><p class="small-note"><strong>Technique reference:</strong> ${escapeHtml(h.technique)} <span class="muted">· illustrative mapping, validate before operational use</span></p></section>
      <section class="panel"><div class="report-row"><div><h3>Explore related events</h3><p>These records are synthetic and scoped to this scenario. A matching event is a lead, not a verdict.</p></div><span class="case-id">${events.length} EVENTS</span></div>
        <div class="toolbar"><input class="field search" id="eventSearch" placeholder="Search account, host, message…" value="${escapeHtml(filters.q || '')}" aria-label="Search related events"><select class="field" id="sourceFilter" aria-label="Filter event source"><option value="all">All sources</option><option value="identity">Identity</option><option value="endpoint">Endpoint</option><option value="privilege">Privilege</option></select><button class="secondary-btn" id="applyFilter">Filter events</button></div>
        <div class="event-list" id="eventList">${eventMarkup(events)}</div>
      </section>
      <section class="panel"><h3>Analyst finding</h3><p>Choose the conclusion that best reflects the evidence available — not the most dramatic interpretation.</p>
        <label class="form-label" for="verdict">HYPOTHESIS OUTCOME</label><select class="field full" id="verdict"><option value="NOT_REVIEWED">Not reviewed</option><option value="SUPPORTED">Supported by evidence</option><option value="NOT_SUPPORTED">Not supported</option><option value="INCONCLUSIVE">Inconclusive — more data needed</option></select>
        <label class="form-label" for="analystNotes">REASONING / LIMITATIONS / NEXT STEP</label><textarea class="field notes" id="analystNotes" maxlength="2000" placeholder="Which events support or contradict the hypothesis? What remains unknown?">${escapeHtml(note.notes || '')}</textarea>
        <div class="form-actions"><button class="primary-btn" id="saveReview">Save finding</button><a class="secondary-btn" id="downloadReport" href="/api/report/${encodeURIComponent(h.id)}">Export JSON report ↓</a><button class="secondary-btn" id="resetFinding" type="button">Reset finding</button></div><p class="small-note">Reset clears only this scenario’s saved conclusion and notes. Synthetic events remain unchanged.</p><div class="feedback" id="feedback" role="status" aria-live="polite"></div>
      </section>
      <p class="disclaimer">Training only. This lab uses synthetic events and simplified scenarios. It does not ingest live telemetry, run commands on endpoints, or establish that a real system is compromised. A technique label is a learning reference, not proof of attribution.</p>`;
    document.getElementById('verdict').value = note.verdict || 'NOT_REVIEWED';
    document.getElementById('sourceFilter').value = filters.source || 'all';
    document.getElementById('applyFilter').addEventListener('click', () => loadFiltered(h.id));
    document.getElementById('eventSearch').addEventListener('keydown', e => { if (e.key === 'Enter') loadFiltered(h.id); });
    document.getElementById('saveReview').addEventListener('click', () => saveReview(h.id));
    document.getElementById('resetFinding').addEventListener('click', () => resetFinding(h.id));
  }

  function eventMarkup(events) {
    if (!events.length) return '<div class="empty">No events match these filters. Try a broader search.</div>';
    return events.map(e => `<article class="event-row"><div class="event-time">${escapeHtml(formatTime(e.timestamp))}</div><div class="event-main"><span class="event-id">${escapeHtml(e.id)} · ${escapeHtml(e.event_type)}</span><strong>${escapeHtml(e.message)}</strong><p>${escapeHtml(e.account)} · ${escapeHtml(e.host)} · ${escapeHtml(e.source_ip)}<br>${escapeHtml(e.analyst_hint)}</p></div><span class="severity ${escapeHtml(e.severity)}">${escapeHtml(e.severity)}</span></article>`).join('');
  }

  async function loadFiltered(id) {
    const q = document.getElementById('eventSearch').value.trim();
    const source = document.getElementById('sourceFilter').value;
    const list = document.getElementById('eventList');
    list.innerHTML = '<div class="loading">Filtering events…</div>';
    try {
      const res = await fetch(`/api/hunts/${encodeURIComponent(id)}?q=${encodeURIComponent(q)}&source=${encodeURIComponent(source)}`);
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Could not filter events.');
      list.innerHTML = eventMarkup(data.events || []);
      const count = content.querySelector('.report-row .case-id');
      if (count) count.textContent = `${(data.events || []).length} EVENTS`;
    } catch (err) {
      list.innerHTML = `<div class="empty">${escapeHtml(err.message || 'Could not filter events. Try again.')}</div>`;
    }
  }

  async function saveReview(id) {
    const button = document.getElementById('saveReview');
    const feedback = document.getElementById('feedback');
    button.disabled = true; feedback.textContent = 'Saving…';
    try {
      const response = await fetch(`/api/hunts/${encodeURIComponent(id)}/review`, {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({verdict:document.getElementById('verdict').value, notes:document.getElementById('analystNotes').value})});
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || 'Save failed');
      feedback.textContent = 'Finding saved in this workspace.';
      const card = document.querySelector(`[data-hunt="${CSS.escape(id)}"] .state`);
      if (card) { card.textContent = labelVerdict(data.verdict); card.className = `state state-${data.verdict.toLowerCase()}`; }
      feedback.dataset.kind = 'success';
    } catch (err) { feedback.dataset.kind = 'error'; feedback.textContent = err.message; }
    finally { button.disabled = false; }
  }

  async function resetFinding(id) {
    if (!window.confirm('Clear the saved finding and notes for this scenario? Synthetic events will not change.')) return;
    const button = document.getElementById('resetFinding');
    const feedback = document.getElementById('feedback');
    button.disabled = true;
    feedback.dataset.kind = '';
    feedback.textContent = 'Resetting finding…';
    try {
      const response = await fetch(`/api/hunts/${encodeURIComponent(id)}/reset`, {method: 'POST'});
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || 'Reset failed.');
      document.getElementById('verdict').value = 'NOT_REVIEWED';
      document.getElementById('analystNotes').value = '';
      feedback.dataset.kind = 'success';
      feedback.textContent = 'Finding and notes cleared for this scenario.';
      const card = document.querySelector(`[data-hunt="${CSS.escape(id)}"] .state`);
      if (card) { card.textContent = labelVerdict(data.verdict); card.className = `state state-${data.verdict.toLowerCase()}`; }
    } catch (err) { feedback.dataset.kind = 'error'; feedback.textContent = err.message || 'Reset failed.'; }
    finally { button.disabled = false; }
  }

  function closeModal() {
    backdrop.hidden = true;
    document.body.classList.remove('modal-open');
    activeHunt = null;
    if (openerElement && typeof openerElement.focus === 'function') openerElement.focus();
  }
  document.querySelectorAll('.open-hunt').forEach(button => button.addEventListener('click', () => openHunt(button.dataset.id)));
  closeButton.addEventListener('click', closeModal);
  backdrop.addEventListener('click', e => { if (e.target === backdrop) closeModal(); });
  document.addEventListener('keydown', e => {
    if (backdrop.hidden) return;
    if (e.key === 'Escape') { closeModal(); return; }
    if (e.key === 'Tab') {
      const focusable = [...backdrop.querySelectorAll('button:not([disabled]), a[href], input:not([disabled]), select:not([disabled]), textarea:not([disabled])')]
        .filter(el => el.offsetParent !== null);
      if (!focusable.length) return;
      const first = focusable[0], last = focusable[focusable.length - 1];
      if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
      else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
    }
  });
})();
