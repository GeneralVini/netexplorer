'use strict';
// Keep all device metadata in escaped server templates; event payloads contain IDs only.
const form = document.querySelector('#scan-form');
const start = document.querySelector('#start');
const cancel = document.querySelector('#cancel');
const pause = document.querySelector('#pause');
let scanPaused = false;
const statusText = document.querySelector('#status');
const warnings = document.querySelector('#warnings');
const token = document.querySelector('meta[name="csrf-token"]').content;
let scanID = null;
let stream = null;
let refreshTimer = null;
let nmapJob = null;
let nmapTimer = null;
let checkJob = null;
let checkTimer = null;
let pendingJumpIP = null;
let monitorProgress = null;
const selectedCardTabs = new Map();
function refresh() {
  if (refreshTimer !== null) return;
  refreshTimer = setTimeout(() => {
    refreshTimer = null;
    htmx.trigger(document.body, 'inventory-changed');
  }, 250);
}
async function state(keepProgress = false) {
  const response = await fetch(`/api/scans/${scanID}`);
  if (!response.ok) throw new Error('Unable to read scan state.');
  const value = await response.json();
  document.body.dataset.scanStatus = value.status;
  cancel.textContent='Stop';
  const devices = value.report.devices || [];
  scanPaused = !!value.paused;
  pause.disabled = value.status !== 'running' || !value.continuous || !!nmapJob || !!checkJob;
  pause.textContent = scanPaused ? 'Resume' : 'Pause';
  updateMonitorProgress(value);
  const hosts = new Set([...devices.map(device => device.ip), ...(value.report.hosts || []).map(host => host.ip)].filter(Boolean));
  if (!keepProgress) statusText.textContent = `Scan ${value.status}: ${devices.filter(device => device.udn).length} logical devices on ${hosts.size} remote hosts.${value.error ? ' ' + readableNote(value.error) : ''}`;
  warnings.replaceChildren();
  const seenNotes=new Set();
  for (const warning of value.report.warnings || []) {
    const note=readableNote(warning.message);
    if (!note) continue;
    const key=(warning.ip || "")+":"+note;
    if (seenNotes.has(key)) continue;
    seenNotes.add(key);
    const item = document.createElement('li');
    item.textContent = `${warning.ip ? warning.ip + ": " : ""}${note}`;
    warnings.append(item);
  }
  const notes = document.querySelector('#warnings-summary');
  notes.hidden = warnings.children.length === 0;
  notes.textContent = `Scan notes (${warnings.children.length})`;
  if (value.status !== 'running' && !nmapJob && !checkJob) {
    if (stream) stream.close();
    start.disabled = false;
    cancel.disabled = true;
  }
  refresh();
  return value;
}
function follow(id) {
  scanID = id;
  if (stream) stream.close();
  start.disabled = true;
  cancel.disabled = false;
  document.body.dataset.scanStatus = "running";
  stream = new EventSource(`/api/scans/${id}/events`);
  for (const kind of ['scan-started', 'host-found', 'device-found', 'device-updated', 'service-found', 'host-discovery-started', 'host-updated', 'reset']) {
    stream.addEventListener(kind, () => { statusText.textContent = `Scan running — ${kind.replaceAll('-', ' ')}.`; refresh(); });
  }
  stream.addEventListener('monitor-progress', event => updateMonitorProgress(JSON.parse(event.data)));
  stream.addEventListener('pause-changed', () => state(true).catch(showError));
  stream.addEventListener('window-started', event => {
    const value=JSON.parse(event.data);
    statusText.textContent=`Discovery window ${value.window} running…`; refresh();
  });
  stream.addEventListener('window-complete', event => {
    const value=JSON.parse(event.data);
    document.querySelector('#window-notice').textContent=`Round ${value.window} · ${value.new_hosts ? '+' + value.new_hosts + ' new' : 'No new hosts'}`;
    statusText.textContent='Discovery window completed.'; state(true).catch(showError); refresh();
  });
  stream.addEventListener('auto-tcp-started', event => {
    const value=JSON.parse(event.data);showTCPActivity([value.ip], 'Common + notable ports');statusText.textContent='TCP inspection running…';
  });
  stream.addEventListener('auto-tcp-complete', event => {
    const value=JSON.parse(event.data);showTCPActivity([]);statusText.textContent=`Nmap ${value.status} for ${value.ip}.`;state(true).catch(showError);refresh();
  });
  for (const kind of ['scan-complete', 'scan-error']) {
    stream.addEventListener(kind, () => { stream.close(); state().catch(showError); });
  }
  stream.onerror = () => { state().catch(showError); };
}
function showError(error) { if (!nmapJob) showTCPActivity([]); statusText.textContent = error.message; }
form.addEventListener('submit', async (event) => {
  event.preventDefault();
  start.disabled = true;
  showTCPActivity([]);
  document.querySelector("#window-notice").textContent = "";
  warnings.replaceChildren();
  try {
    const response = await fetch('/api/scans', {
      method: 'POST', headers: {'Content-Type': 'application/json', 'X-CSRF-Token': token},
      body: JSON.stringify({interface: form.elements.interface.value, seconds: Number(form.elements.seconds.value), enrich: form.elements.enrich.checked, authorized: form.elements.authorized.checked, all_hosts: form.elements.all_hosts.checked, auto_tcp: form.elements.auto_tcp.checked, continuous: form.elements.continuous.checked, interval_seconds: Number(form.elements.interval_seconds.value)})
    });
    const value = await response.json();
    if (!response.ok) throw new Error(value.error || 'Unable to start scan.');
    follow(value.id);
    cancel.textContent="Stop";
  } catch (error) { start.disabled = false; showError(error); }
});
cancel.addEventListener('click', async () => {
  cancel.disabled = true;
  statusText.textContent = 'Cancelling scan…';
  try {
    const cancelURL = checkJob ? `/api/checks/${checkJob}/cancel` : nmapJob ? `/api/nmap/${nmapJob}/cancel` : `/api/scans/${scanID}/cancel`;
    const response = await fetch(cancelURL, {method: 'POST', headers: {'X-CSRF-Token': token}});
    if (!response.ok) throw new Error('Unable to cancel scan.');
  } catch (error) { cancel.disabled = false; showError(error); }
});
// Recover retained work without silently starting any network action.
async function restoreWork() {
  if (document.body.dataset.latestScan) {
    const response = await fetch('/api/scans/latest');
    if (response.ok) {
      const latest = await response.json();
      scanID = latest.id;
      if (latest.status === 'running') follow(latest.id);
      await state();
    }
  }
  if (document.body.dataset.latestNmap) {
    nmapJob = document.body.dataset.latestNmap;
    document.body.dataset.nmapRunning = 'true';
    start.disabled = true;
    cancel.disabled = false;
    document.body.dataset.scanStatus = 'running';
    statusText.textContent = 'Resuming Nmap job status…';
    await pollNmap();
  }
}
restoreWork().then(async () => {
  if (document.body.dataset.latestCheck) { checkJob=document.body.dataset.latestCheck; setCheckBusy(true); await pollCheck(); }
}).catch(showError);

// Manual enrichment targets existing host IDs; the API validates the LAN again.
document.addEventListener('click', async event => {
  const button = event.target.closest('[data-nmap-host]');
  if (!button || button.disabled || nmapJob || checkJob) return;
  if (!form.elements.authorized.checked) {
    showError(new Error('Confirm LAN authorization before inspecting TCP services.'));
    return;
  }
  const profile = button.closest('.nmap-action').querySelector('.tcp-profile').value;
  button.disabled = true;
  try {
    const response = await fetch(`/api/hosts/${button.dataset.nmapHost}/nmap`, {
      method: 'POST', headers: {'Content-Type': 'application/json', 'X-CSRF-Token': token},
      body: JSON.stringify({authorized:true, profile})
    });
    const result = await response.json();
    if (!response.ok) throw new Error(result.error || 'Unable to start Nmap.');
    nmapJob = result.id;
    document.body.dataset.nmapRunning = 'true';
    document.body.dataset.scanStatus = 'running';
    start.disabled = true;
    cancel.disabled = false;
    showTCPActivity([result.ip], result.profile === "full" ? "All 65,535 TCP ports" : "Common + notable ports");
    statusText.textContent = "TCP inspection running…";
    await pollNmap();
  } catch (error) { button.disabled = false; showError(error); }
});
async function pollNmap() {
  try {
    const response = await fetch(`/api/nmap/${nmapJob}`);
    if (!response.ok) throw new Error('Unable to read Nmap job state.');
    const job = await response.json();
    if (job.status === 'running') { showTCPActivity([job.ip], job.profile === 'full' ? 'All 65,535 TCP ports' : 'Common + notable ports'); nmapTimer = setTimeout(pollNmap, 1000); return; }
    showTCPActivity([]);
    nmapJob = null;
    document.body.dataset.nmapRunning = 'false';
    document.body.dataset.scanStatus = job.status;
    start.disabled = false;
    cancel.disabled = true;
    statusText.textContent = `Nmap ${job.status} for ${job.ip}.${job.error ? ' ' + job.error : ''}`;
    
    refresh();
  } catch (error) {
    showTCPActivity([]);
    nmapJob = null;
    document.body.dataset.nmapRunning = 'false';
    start.disabled = false;
    cancel.disabled = true;
    showError(error);
    refresh();
  }
}
window.addEventListener('pagehide', () => { if (stream) stream.close(); if (nmapTimer) clearTimeout(nmapTimer); if (checkTimer) clearTimeout(checkTimer); });

// Keep catalog controls across SSE fragment refreshes; LAN metadata stays text-only.
const catalog = {filter:'hosts', search:'', vendor:'', page:1, size:12};
function renderCatalog() {
  restoreCardTabs();
  const root = document.querySelector('#devices');
  if (!root) return;
  const cards = [...root.querySelectorAll('.device-card')];
  renderHostIdentities(cards, catalog.filter === 'hosts');
  const search = root.querySelector('[data-inventory-search]');
  const vendor = root.querySelector('[data-inventory-vendor]');
  if (!search || !vendor) return;
  search.value = catalog.search;
  const brands = [...new Set(cards.map(card => card.dataset.vendor).filter(Boolean))].sort((a,b) => a.localeCompare(b));
  vendor.replaceChildren(new Option('All manufacturers',''), ...brands.map(brand => new Option(brand,brand)));
  if (catalog.vendor && !brands.includes(catalog.vendor)) catalog.vendor = '';
  vendor.value = catalog.vendor;
  root.querySelector('[data-page-size]').value = String(catalog.size);
  root.querySelectorAll('[data-inventory-filter]').forEach(button => button.setAttribute('aria-pressed', String(button.dataset.inventoryFilter === catalog.filter)));
  root.querySelector('[data-inventory-reset]').classList.toggle('active', catalog.filter === 'hosts' && !catalog.search && !catalog.vendor);
  const needle = catalog.search.trim().toLocaleLowerCase();
  let matched = cards.filter(card => {
    if (catalog.filter === 'devices' && card.dataset.logical !== 'true') return false;
    if (catalog.filter === 'services' && Number(card.dataset.services) + Number(card.dataset.tcp) === 0) return false;
    if (catalog.filter === 'manufacturers' && !card.dataset.vendor) return false;
    if (catalog.vendor && card.dataset.vendor !== catalog.vendor) return false;
    // Search visible identity fields, not hidden URLs, service payloads or evidence.
    const identity = `${card.querySelector('.device-heading').textContent} ${card.dataset.vendor}`;
    return !needle || identity.toLocaleLowerCase().includes(needle);
  });
  if (catalog.filter === 'hosts') {
    const grouped = new Map();
    for (const card of matched) {
      if (!card.dataset.ip) continue;
      const prior = grouped.get(card.dataset.ip);
      if (!prior || (card.dataset.kind === 'Router' && prior.dataset.kind !== 'Router') || (prior.dataset.kind !== 'Router' && prior.dataset.parent && !card.dataset.parent)) grouped.set(card.dataset.ip, card);
    }
    matched = [...grouped.values()];
  }
  const pages = Math.max(1, Math.ceil(matched.length / catalog.size));
  catalog.page = Math.min(Math.max(1,catalog.page),pages);
  const offset = (catalog.page-1)*catalog.size;
  const visible = new Set(matched.slice(offset,offset+catalog.size));
  cards.forEach(card => { card.hidden = !visible.has(card); });
  const labels = {all:'All records',hosts:'Remote hosts',devices:'Logical devices',services:'With services',manufacturers:'Known manufacturers'};
  root.querySelector('.inventory-results').textContent = `${labels[catalog.filter]} · ${matched.length ? offset+1 : 0}–${Math.min(offset+catalog.size,matched.length)} of ${matched.length}`;
  root.querySelector('.filter-empty').hidden = !cards.length || matched.length > 0;
  root.querySelector('.inventory-pagination').hidden = cards.length === 0;
  root.querySelector('[data-page-label]').textContent = `${catalog.page} / ${pages}`;
  root.querySelector('[data-page-prev]').disabled = catalog.page === 1;
  root.querySelector('[data-page-next]').disabled = catalog.page === pages;
  if (catalog.filter === 'services') document.querySelectorAll('.device-card:not([hidden]) .service-section, .device-card:not([hidden]) .nmap-results').forEach(section => { section.open = true; });
}
document.addEventListener('click', event => {
  const button = event.target.closest('[data-inventory-filter], [data-inventory-reset], [data-page-prev], [data-page-next]');
  if (!button) return;
  if (button.hasAttribute('data-inventory-filter')) { catalog.filter = button.dataset.inventoryFilter; catalog.page = 1; catalog.search = ''; catalog.vendor = '';  }
  if (button.hasAttribute('data-inventory-reset')) { Object.assign(catalog,{filter:'hosts',search:'',vendor:'',page:1}); }
  if (button.hasAttribute('data-page-prev')) catalog.page--;
  if (button.hasAttribute('data-page-next')) catalog.page++;
  renderCatalog();
});
document.addEventListener('input', event => {
  if (!event.target.matches('[data-inventory-search]')) return;
  catalog.search = event.target.value; catalog.page = 1; renderCatalog();
});
document.addEventListener('change', event => {
  if (event.target.matches('[data-inventory-vendor]')) catalog.vendor = event.target.value;
  else if (event.target.matches('[data-page-size]')) catalog.size = Number(event.target.value);
  else return;
  catalog.page = 1; renderCatalog();
});
document.body.addEventListener('htmx:afterSwap', event => { if (event.detail.target.id === 'devices') { renderCatalog(); if (pendingJumpIP) jumpToHost(pendingJumpIP); } });
// Parent links can point to a card on another page or outside the active filter.
window.addEventListener('hashchange', revealLinkedCard);
function revealLinkedCard() {
  const card = document.getElementById(location.hash.slice(1));
  if (!card || !card.matches('.device-card')) return;
  const cards = [...document.querySelectorAll('#devices .device-card')];
  Object.assign(catalog,{filter:'all',search:'',vendor:'',page:Math.floor(cards.indexOf(card)/catalog.size)+1});
  renderCatalog(); card.scrollIntoView({block:'nearest'});
}
renderCatalog();
if (location.hash) revealLinkedCard();

// Translate deadline failures without hiding their retained partial inventory.
function readableNote(message) {
 if (message === 'context canceled') return '';
 if (message.includes('no such network interface')) return 'Network interface unavailable. Reconnect it and select the interface again.';
 // Ignored duplicate identities are retained in JSON, not presented as scan failures.
 if (message.startsWith('duplicate UPnP UDN')) return '';
 if (message.includes('context deadline exceeded')) {
  if (message.includes('LAN host discovery:')) {
   const batches = message.match(/(\d+)\/(\d+) batches incomplete/);
   return batches ? `LAN discovery: ${batches[1]} of ${batches[2]} batches incomplete. Completed results are retained.` : 'LAN discovery reached its time limit. Collected hosts are retained; coverage is partial.';
  }
  if (message.includes('UPnP description enrichment:')) return 'UPnP description reading reached its time limit. Devices are retained; some details remain incomplete.';
  if (message.includes('SSDP discovery:')) return 'SSDP discovery exceeded the scan deadline. Collected announcements are retained.';
  return 'A scan step timed out. Collected results are retained; coverage may be incomplete.';
 }
 return message;
}

// Native dialogs provide focus trapping and Escape; JSON is rendered as plain text.
const jsonDialog = document.querySelector('#json-dialog');
let jsonRequest = null;
document.addEventListener('click', async event => {
 const link = event.target.closest('[data-json-popup]');
 if (!link || event.ctrlKey || event.metaKey || event.shiftKey || event.altKey) return;
 event.preventDefault();
 if (jsonRequest) jsonRequest.abort();
 const request = new AbortController(); jsonRequest = request;
 document.querySelector('#json-title').textContent = link.textContent.includes('Host') ? 'Host JSON' : 'Device JSON';
 document.querySelector('#json-content').replaceChildren();
 jsonDialog.scrollTop = 0;
 document.querySelector('#json-status').textContent = 'Loading…';
 if (!jsonDialog.open) jsonDialog.showModal();
 try {
  const response = await fetch(link.getAttribute('href'), {signal:request.signal});
  if (!response.ok) throw new Error('Unable to load JSON.');
  const data = await response.json();
  if (request.signal.aborted) return;
  renderJSON(data);
  document.querySelector('#json-status').textContent = '';
 } catch(error) { if (error.name !== 'AbortError') document.querySelector('#json-status').textContent = error.message; }
});
document.querySelector('[data-json-close]').addEventListener('click', () => jsonDialog.close());
jsonDialog.addEventListener('close', () => { if (jsonRequest) jsonRequest.abort(); });
jsonDialog.addEventListener('click', event => { if (event.target === jsonDialog) { const box=jsonDialog.getBoundingClientRect(); if(event.clientX<box.left||event.clientX>box.right||event.clientY<box.top||event.clientY>box.bottom) jsonDialog.close(); } });

// Host view groups display records by IP while preserving every logical identity.
function renderHostIdentities(cards, enabled) {
 cards.forEach(card => { const old=card.querySelector('.host-identities'); if(old) old.remove(); });
 if (!enabled) return;
 const groups=new Map();
 for(const card of cards) { if(!card.dataset.ip) continue; if(!groups.has(card.dataset.ip)) groups.set(card.dataset.ip,[]); groups.get(card.dataset.ip).push(card); }
 for(const members of groups.values()) {
  if(members.length<2) continue;
  const card=members.reduce((prior,current) => (current.dataset.kind==='Router' && prior.dataset.kind!=='Router') || (prior.dataset.kind!=='Router' && prior.dataset.parent && !current.dataset.parent) ? current : prior);
   const details=document.createElement('details');details.className='host-identities';
   const summary=document.createElement('summary');summary.textContent=`Device identities (${members.length})`;details.append(summary);
   for(const member of members) {const link=document.createElement('a');link.href='#'+member.id;link.textContent=member.querySelector('h3').textContent;link.title=member.dataset.kind;details.append(link);}
   card.querySelector('.device-details').before(details);
 }
}

// Highlight formatted JSON using text nodes only; LAN strings cannot become HTML.
function renderJSON(data) {
 const output=document.querySelector('#json-content');
 const fragment=document.createDocumentFragment();
 const token=/"(?:\\.|[^"\\])*"(?:\s*:)?|\b(?:true|false|null)\b|-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?/g;
 for(const line of JSON.stringify(data,null,2).split('\n')) {
  const row=document.createElement('span');row.className='json-line';let offset=0;
  for(const match of line.matchAll(token)) {
   row.append(document.createTextNode(line.slice(offset,match.index)));
   const span=document.createElement('span');span.textContent=match[0];
   span.className=match[0].startsWith('"') ? (match[0].endsWith(':')?'json-key':'json-string') : (match[0]==='null'?'json-null':/^(true|false)$/.test(match[0])?'json-boolean':'json-number');
   row.append(span);offset=match.index+match[0].length;
  }
  row.append(document.createTextNode(line.slice(offset)));fragment.append(row);
 }
 output.replaceChildren(fragment);
}

// Service rows are paged before creating DOM nodes, including full-range results.
const serviceDialog = document.querySelector('#services-dialog');
const sharesDialog = document.querySelector('#shares-dialog');
let serviceInventory = null;
let servicePage = 0;
let serviceRequest = null;
let shareRequest = null;
const stateSymbols = {open:'✓', closed:'×', filtered:'◆', 'open|filtered':'◈', unfiltered:'○', 'closed|filtered':'⊗'};
function element(tag, text, className) {
  const node = document.createElement(tag);
  if (text !== undefined) node.textContent = text;
  if (className) node.className = className;
  return node;
}
function serviceLink(label, url, title) {
  const link = element('a', label, 'service-link');
  link.href = url;
  link.target = '_blank';
  link.rel = 'noopener noreferrer';
  if (title) link.title = title;
  return link;
}
function serviceState(state) {
  const icon = element('span', stateSymbols[state] || '?', 'port-state');
  // Unknown remote state strings are never interpolated into class names.
  if (Object.hasOwn(stateSymbols, state)) icon.classList.add(`state-${state}`);
  icon.title = state;
  icon.tabIndex = 0;
  icon.setAttribute('role', 'img');
  icon.setAttribute('aria-label', state);
  return icon;
}
function renderServices() {
  if (!serviceInventory) return;
  const query = document.querySelector('#services-search').value.toLowerCase();
  const state = document.querySelector('#services-state').value;
  const rows = serviceInventory.ports.filter(port => {
    const match = state === 'references' ? port.history || port.cves?.length : !state || port.state === state;
    return match && `${port.number} ${port.service || ''} ${port.product || ''} ${port.version || ''} ${port.history?.label || ''} ${(port.cves || []).map(cve => cve.label).join(' ')}`.toLowerCase().includes(query);
  }).sort((a,b) => Number(b.state === 'open') - Number(a.state === 'open') || a.number-b.number);
  const pages = Math.max(1, Math.ceil(rows.length/50));
  servicePage = Math.min(servicePage, pages-1);
  const content = document.querySelector('#services-content');
  content.replaceChildren();
  for (const port of rows.slice(servicePage*50, (servicePage+1)*50)) {
    const row = element('article', undefined, 'service-result');
    const heading = element('div', undefined, 'service-result-heading');
    const endpoint=port.media_url ? serviceLink(`${port.number}/${port.protocol} ↗`,port.media_url,'Open in an RTSP client such as VLC') : port.web_url ? serviceLink(`${port.number}/${port.protocol} ↗`,port.web_url) : element(port.action === 'rdp' ? 'button' : 'strong',`${port.number}/${port.protocol}${port.action === 'rdp' ? ' ↗' : ''}`,port.action === 'rdp' ? 'endpoint-rdp' : undefined);
    if (port.action === 'rdp') { endpoint.type='button';endpoint.title='Download RDP connection';endpoint.addEventListener('click',()=>downloadRDP(serviceInventory.ip,port.number)); }
    heading.append(serviceState(port.state), endpoint, element('span', port.service || 'Unknown service'));
    row.append(heading);
    if (port.product || port.version) row.append(element('p', [port.product,port.version].filter(Boolean).join(' '), 'service-product'));
    if (port.cpes?.length) {
      const details = element('details', undefined, 'service-evidence');
      details.append(element('summary', 'Product identifiers'), element('p', port.cpes.join('\n')));
      row.append(details);
    }
    const actions = element('div', undefined, 'service-actions');
    if (port.media_url) {
      actions.append(serviceLink('Open RTSP ↗', port.media_url, 'Requires an RTSP client such as VLC; public playback is not confirmed'));
      const copy = element('button', 'Copy RTSP URL', 'btn btn-sm btn-outline-primary');
      copy.type = 'button';
      copy.addEventListener('click', async () => { try { await navigator.clipboard.writeText(port.media_url); copy.textContent = 'Copied'; } catch(error) { showError(new Error('Unable to copy RTSP URL.')); } });
      actions.append(copy);
    }
    if (port.web_url) actions.append(serviceLink('Open web ↗', port.web_url, port.state === 'open' ? 'Open observed HTTP service' : 'Port is filtered; the connection may fail'));
    const copy = element('button', 'Copy endpoint', 'btn btn-sm btn-outline-secondary');
    copy.type = 'button';
    copy.addEventListener('click', async () => {
      try { await navigator.clipboard.writeText(`${serviceInventory.ip}:${port.number}`); copy.textContent = 'Copied'; }
      catch { copy.textContent = `${serviceInventory.ip}:${port.number}`; }
    });
    actions.append(copy);
    if (port.action === 'rdp') {
      const button = element('button', 'Download .rdp', 'btn btn-sm btn-outline-primary');
      button.type = 'button';
      button.addEventListener('click', () => {
        const data = `full address:s:${serviceInventory.ip}:${port.number}\r\nauthentication level:i:2\r\nprompt for credentials:i:1\r\n`;
        const href = URL.createObjectURL(new Blob([data], {type:'application/x-rdp'}));
        const download = element('a'); download.href = href; download.download = `${serviceInventory.ip}.rdp`;
        download.click(); setTimeout(() => URL.revokeObjectURL(href), 1000);
      });
      actions.append(button);
    }
    if (port.action === 'shares' && [139,445].includes(port.number)) {
      const button = element('button', 'Shared folders', 'btn btn-sm btn-outline-primary');
      button.type = 'button'; button.addEventListener('click', () => listSharedFolders(port.number)); actions.append(button);
    }
    if (port.search_url) actions.append(serviceLink('NVD references ↗', port.search_url, 'Manual product/version search; results are not verified matches'));
    for (const spec of port.checks || []) {
      const button = element('button', spec.label, `btn btn-sm ${spec.kind === 'vulnerability' ? 'btn-outline-warning' : 'btn-outline-primary'}`);
      button.type = 'button'; button.title = spec.note;
      button.addEventListener('click', () => openCheck(spec, port.number)); actions.append(button);
    }
    row.append(actions);
    const jobs=(serviceInventory.checks || []).filter(job => job.port === port.number);
    for (const job of jobs) {
      const badge=element('button', `${assessmentSymbol(job)} ${job.check_id}`, 'check-badge');
      badge.type='button';badge.title=job.result?.summary || `${job.status}: ${job.error || 'Check in progress'}`;
      badge.setAttribute('aria-label', `${job.check_id}: ${job.result?.assessment || job.status}`);
      badge.dataset.assessment=job.result?.assessment || job.status;
      badge.addEventListener('click',()=>openRetainedCheck(job));row.append(badge);
    }
    const references = [...(port.history ? [port.history] : []), ...(port.cves || [])];
    for (const reference of references) {
      const note = element('div', undefined, 'service-reference');
      note.append(serviceLink(reference.label, reference.url), element('span', reference.note));
      row.append(note);
    }
    content.append(row);
  }
  if (!rows.length) content.append(element('p', 'No matching port results.'));
  document.querySelector('#services-page').textContent = `${servicePage+1} / ${pages} · ${rows.length} results`;
  document.querySelector('#services-prev').disabled = servicePage === 0;
  document.querySelector('#services-next').disabled = servicePage === pages-1;
}
// Manual actions can explicitly stop discovery, then wait for its network slot.
async function stopDiscoveryForManual(signal) {
 if (checkJob || nmapJob) throw new Error('Another inspection is running. Cancel it before starting this action.');
 if (document.body.dataset.scanStatus !== 'running') return;
 if (!scanID) throw new Error('Reload to recover the running discovery.');
 const response=await fetch(`/api/scans/${scanID}/cancel`,{method:'POST',headers:{'X-CSRF-Token':token},signal});
 if (!response.ok) throw new Error('Unable to stop discovery.');
 for (let i=0;i<100;i++) {
  const response=await fetch(`/api/scans/${scanID}`,{signal});
  if (!response.ok) throw new Error('Unable to read discovery status.');
  const value=await response.json();
  if (value.status !== 'running') { await state(true); return; }
  await new Promise(resolve=>setTimeout(resolve,200));
  if (signal?.aborted) throw new DOMException('Cancelled','AbortError');
 }
 throw new Error('Discovery is still stopping. Wait and retry.');
}
let shareSelection=null;
let shareClock=null;
function downloadRDP(ip,port) {
 const data=`full address:s:${ip}:${port}\r\nauthentication level:i:2\r\nprompt for credentials:i:1\r\n`;
 const href=URL.createObjectURL(new Blob([data],{type:'application/x-rdp'}));
 const link=element('a');link.href=href;link.download=`${ip}.rdp`;link.click();
 setTimeout(()=>URL.revokeObjectURL(href),1000);
}
document.addEventListener('click',event=> {
 const button=event.target.closest('[data-rdp-ip]');
 if (button) downloadRDP(button.dataset.rdpIp,Number(button.dataset.rdpPort));
});
async function listSharedFolders(port, stopFirst=false) {
  if (!form.elements.authorized.checked) { showError(new Error('Confirm LAN authorization before listing shares.')); return; }
  if (shareRequest) return;
  shareSelection={port,id:serviceInventory.id,ip:serviceInventory.ip};
  if (document.body.dataset.scanStatus === 'running' && !stopFirst) {
    document.querySelector('#shares-title').textContent=`Shared folders · ${shareSelection.ip}`;
    document.querySelector('#shares-status').textContent='Discovery is running. Stop it to list folders.';
    document.querySelector('#shares-content').replaceChildren();
    document.querySelector('#shares-start').hidden=false;
    sharesDialog.showModal();return;
  }
  const request = new AbortController(); shareRequest = request;
  document.querySelector('#shares-title').textContent = `Shared folders · ${serviceInventory.ip}`;
  document.querySelector('#shares-content').replaceChildren();
  const status = document.querySelector('#shares-status');
  const selection=shareSelection;
  const began=Date.now();
  document.querySelector('#shares-start').hidden=true;
  document.querySelector('#shares-cancel').disabled=false;
  document.querySelector('#shares-progress').hidden=false;
  const update=()=> { status.textContent=`${stopFirst && document.body.dataset.scanStatus === 'running' ? 'Stopping discovery' : 'Listing announced folders'}… ${Math.floor((Date.now()-began)/1000)}s · request limit 12s`; };
  update();shareClock=setInterval(update,1000);status.classList.add('is-loading');
  if (!sharesDialog.open) sharesDialog.showModal();
  try {
    if (stopFirst) await stopDiscoveryForManual(request.signal);
    const response = await fetch(`/api/hosts/${selection.id}/shares`, {method:'POST', headers:{'Content-Type':'application/json','X-CSRF-Token':token}, body:JSON.stringify({authorized:true,port}), signal:request.signal});
    const result = await response.json();
    if (!response.ok) throw new Error(result.error || 'Unable to list shares.');
    status.textContent = result.shares.length ? 'Announced folders · contents were not accessed.' : 'No public folders announced. Authentication may be required.';
    for (const share of result.shares) {
      const row = element('div', undefined, 'share-result');
      row.append(element('strong', `▱ ${share.name}`), element('span', share.comment || ''));
      document.querySelector('#shares-content').append(row);
    }
  } catch (error) { status.textContent=error.name === 'AbortError' ? 'Request cancelled.' : error.message; }
  finally { if (shareRequest === request) { shareRequest = null; clearInterval(shareClock);shareClock=null;status.classList.remove('is-loading');document.querySelector('#shares-progress').hidden=true;document.querySelector('#shares-cancel').disabled=true; } }
}
document.addEventListener('click', async event => {
  if (event.target.closest('[data-services-close]')) serviceDialog.close();
  if (event.target.closest('[data-shares-close]')) sharesDialog.close();
  const button = event.target.closest('[data-services-host]');
  if (!button) return;
  if (serviceRequest) serviceRequest.abort();
  const request = new AbortController(); serviceRequest = request;
  serviceInventory = null; servicePage = 0;
  document.querySelector('#services-search').value = '';
  document.querySelector('#services-state').value = '';
  document.querySelector('#services-content').replaceChildren();
  document.querySelector('#services-page').textContent = '';
  document.querySelector('#services-prev').disabled = true;
  document.querySelector('#services-next').disabled = true;
  const status = document.querySelector('#services-status');
  status.textContent = 'Loading observed services…';
  serviceDialog.showModal();
  try {
    const response = await fetch(`/api/hosts/${button.dataset.servicesHost}/services`, {signal:request.signal});
    const result = await response.json();
    if (!response.ok) throw new Error(result.error || 'Unable to load services.');
    serviceInventory = result;
    document.querySelector('#services-title').textContent = `TCP services · ${result.ip}`;
    status.textContent = `Observed ${new Date(result.observed_at).toLocaleString()} · references reviewed ${result.catalog_reviewed}.`;
    const coverage = element('details', undefined, 'service-evidence');
    coverage.append(element('summary', 'Scan coverage'), element('p', result.coverage || 'Legacy inspection; requested range unavailable.'));
    status.append(coverage);
    const limits = element('small', 'CVE matches are potential. The reviewed catalog is limited; no match does not mean secure.');
    status.append(limits);
    renderServices();
  } catch (error) { if (error.name !== 'AbortError') status.textContent = error.message; }
  finally { if (serviceRequest === request) serviceRequest = null; }
});
for (const selector of ['#services-search','#services-state']) document.querySelector(selector).addEventListener('input', () => { servicePage=0; renderServices(); });
document.querySelector('#services-prev').addEventListener('click', () => { servicePage=Math.max(0,servicePage-1); renderServices(); serviceDialog.scrollTop=0; });
document.querySelector('#services-next').addEventListener('click', () => { servicePage++; renderServices(); serviceDialog.scrollTop=0; });
serviceDialog.addEventListener('close', () => { if (serviceRequest) serviceRequest.abort(); serviceInventory=null; });
document.querySelector('#shares-start').addEventListener('click',()=> { if (shareSelection) listSharedFolders(shareSelection.port,true); });
document.querySelector('#shares-cancel').addEventListener('click',()=> { if (shareRequest) shareRequest.abort(); });
sharesDialog.addEventListener('close', () => { if (shareRequest) shareRequest.abort(); });

// NSE actions are opt-in; opening a dialog or reloading never executes a script.
const checkDialog = document.querySelector('#check-dialog');
let selectedCheck = null;
function assessmentSymbol(job) {
  if (job.status === 'running') return '◌';
  if (!job.result) return '?';
  return {positive:'⚠', negative:'✓', inconclusive:'?', not_applicable:'ⓘ'}[job.result.assessment] || '?';
}
function setCheckBusy(busy) {
  start.disabled = busy;
  cancel.disabled = !busy;
  document.body.dataset.nmapRunning = String(busy);
  document.body.dataset.scanStatus = busy ? 'running' : 'completed';
  document.querySelector('#check-start').disabled = busy;
  document.querySelector('#check-cancel').disabled = !busy;
}
function openCheck(spec, port) {
  selectedCheck = {spec,port,hostID:serviceInventory.id,ip:serviceInventory.ip};
  document.querySelector('#check-title').textContent = `${spec.label} · ${selectedCheck.ip}:${port}`;
  document.querySelector('#check-note').textContent = spec.note;
  document.querySelector('#check-start').textContent=document.body.dataset.scanStatus === 'running' && !checkJob && !nmapJob ? 'Stop discovery & run check' : 'Run check';
  document.querySelector('#check-result').replaceChildren();
  document.querySelector('#check-verdict').hidden = true;
  document.querySelector('#check-progress').textContent = '';
  document.querySelector('#check-start').disabled = !!checkJob || !!nmapJob || !serviceInventory.ports.find(row=>row.number===port)?.checks?.some(check=>check.id===spec.id);
  document.querySelector('#check-cancel').disabled = !checkJob;
  const retained=(serviceInventory.checks || []).filter(job=>job.check_id === spec.id && job.port === port).at(-1);
  if (retained) renderCheckResult(retained);
  if (!checkDialog.open) checkDialog.showModal();
}
function openRetainedCheck(job) {
  const spec=serviceInventory.check_catalog?.find(spec=>spec.id===job.check_id);
  if (!spec) return;
  openCheck(spec,job.port);renderCheckResult(job);
  if (job.status === 'running' && !checkJob && !serviceInventory.offline) { checkJob=job.id;setCheckBusy(true);pollCheck(); }
}
function renderCheckResult(job) {
  const progress=document.querySelector('#check-progress');
  progress.classList.toggle('is-loading',job.status === 'running');
  document.querySelector('#check-meter').hidden=job.status !== 'running';
  progress.textContent=job.status === 'running' ? `Running ${job.check_id} on ${job.ip}:${job.port}… ${Math.max(0,Math.floor((Date.now()-Date.parse(job.started_at))/1000))}s · limit 60s · Cancel is available below` : `${assessmentSymbol(job)} ${job.result?.summary || `${job.status}: ${job.error || 'No assessment available.'}`}`;
  const verdict=document.querySelector('#check-verdict');
  const assessment=job.result?.assessment;
  const labels={positive:'⚠ VULNERABLE',negative:'✓ NOT VULNERABLE',inconclusive:'? INCONCLUSIVE',not_applicable:'○ INFORMATION / NOT APPLICABLE'};
  verdict.hidden=job.status === 'running';
  verdict.textContent=labels[assessment] || '? INCONCLUSIVE';
  verdict.dataset.assessment=Object.hasOwn(labels,assessment) ? assessment : 'inconclusive';
  const content=document.querySelector('#check-result');content.replaceChildren();
  content.append(element('p', `Started ${new Date(job.started_at).toLocaleString()}${job.finished_at ? ` · finished ${new Date(job.finished_at).toLocaleString()}` : ''}`, 'service-product'));
  if (!job.result) return;
  content.append(element('p', `Nmap ${job.result.nmap_version || 'version unavailable'} · ${job.result.assessment.replaceAll('_',' ')}`, 'service-product'));
  const links=element('div',undefined,'service-actions');
  for (const cve of job.result.cves || []) if (/^CVE-[0-9]{4}-[0-9]{4,}$/.test(cve)) links.append(serviceLink(cve,`https://nvd.nist.gov/vuln/detail/${cve}`));
  if (selectedCheck) links.append(serviceLink('Script reference ↗',selectedCheck.spec.reference));
  content.append(links);
  const evidence=element('details',undefined,'service-evidence');
  evidence.append(element('summary','Script evidence'),element('pre',JSON.stringify(job.result.evidence,null,2),'check-evidence'));
  content.append(evidence);
}
document.querySelector('#check-start').addEventListener('click',async ()=> {
  if (!selectedCheck || checkJob || nmapJob) return;
  if (!form.elements.authorized.checked) { document.querySelector('#check-progress').textContent='Confirm LAN authorization before running this check.';return; }
  const selection=selectedCheck;
  document.querySelector('#check-start').disabled=true;
  document.querySelector('#check-verdict').hidden=true;
  try {
    document.querySelector('#check-progress').textContent='Preparing check…';
    await stopDiscoveryForManual();
    const response=await fetch(`/api/hosts/${selection.hostID}/checks`,{method:'POST',headers:{'Content-Type':'application/json','X-CSRF-Token':token},body:JSON.stringify({authorized:true,check_id:selection.spec.id,port:selection.port})});
    const job=await response.json();if(!response.ok) throw new Error(job.error || 'Unable to start check.');
    checkJob=job.id;setCheckBusy(true);renderCheckResult(job);await pollCheck();
  } catch(error) { document.querySelector('#check-progress').textContent=error.message;document.querySelector('#check-start').disabled=false; }
});
async function pollCheck() {
  try {
    const response=await fetch(`/api/checks/${checkJob}`,{signal:AbortSignal.timeout(8000)});
    if (response.status === 404) {
      checkJob=null;setCheckBusy(false);statusText.textContent='Check status expired. Reopen the service or reload to recover current work.';refresh();return;
    }
    if (!response.ok) throw new Error('Unable to read check status. Reopen the service to recover retained results.');
    const job=await response.json();
    statusText.textContent=job.status === 'running' ? `Running ${job.check_id} on ${job.ip}:${job.port}…` : `Check ${job.status} on ${job.ip}:${job.port}.${job.error ? ' '+job.error : ''}`;
    if (selectedCheck?.hostID === job.host_id && selectedCheck.spec.id === job.check_id && selectedCheck.port === job.port) renderCheckResult(job);
    if (serviceInventory?.id === job.host_id) {
      serviceInventory.checks=(serviceInventory.checks || []).filter(previous=>previous.id!==job.id).concat(job).slice(-8);
      renderServices();
    }
    if (job.status === 'running') {checkTimer=setTimeout(pollCheck,1000);return;}
    checkJob=null;setCheckBusy(false);document.body.dataset.scanStatus=job.status;refresh();
  } catch(error) {
    // A failed poll does not cancel a potentially running server job or free UI admission.
    statusText.textContent=error.message;
    if (selectedCheck && checkJob) document.querySelector('#check-progress').textContent='Status connection interrupted. Retrying… Cancel remains available.';
    if (checkJob) checkTimer=setTimeout(pollCheck,3000);
  }
}
document.querySelector('#check-cancel').addEventListener('click',async ()=> {
  if (!checkJob) return;
  const button=document.querySelector('#check-cancel');button.disabled=true;
  document.querySelector('#check-progress').textContent='Cancelling check…';
  try { const response=await fetch(`/api/checks/${checkJob}/cancel`,{method:'POST',headers:{'X-CSRF-Token':token},signal:AbortSignal.timeout(8000)});if (!response.ok) throw new Error('Unable to cancel check.'); }
  catch(error){button.disabled=false;document.querySelector('#check-progress').textContent=error.message;}
});
document.querySelector('[data-check-close]').addEventListener('click',()=>checkDialog.close());

// Imported endpoint evidence is displayed as text; imports never initiate a LAN probe.
const windowsDialog = document.querySelector('#windows-dialog');
let windowsSelection = null;
let windowsRequest = null;
function renderWindows(report) {
  const content = document.querySelector('#windows-results');
  content.replaceChildren();
  if (!report) return;
  content.append(element('p', `${report.snapshot.caption} · ${report.snapshot.version} · collected ${new Date(report.snapshot.collected_at).toLocaleString()}`));
  for (const finding of report.findings) {
    const row = element('div', undefined, 'service-row');
    const icon = element('span', finding.assessment === 'negative' ? '✓' : finding.assessment === 'not_applicable' ? '○' : '?', 'check-badge');
    icon.dataset.assessment = finding.assessment;
    icon.title = finding.assessment.replaceAll('_',' ');
    icon.setAttribute('aria-label', icon.title); icon.tabIndex = 0;
    row.append(icon, element('strong', `${finding.name} · ${finding.id}`), element('p', finding.summary));
    for (const warning of finding.warnings || []) row.append(element('p', `⚠ ${warning}`));
    row.append(serviceLink('Reference ↗', finding.reference)); content.append(row);
  }
  const evidence = element('details');
  evidence.append(element('summary','Imported evidence'),element('pre',JSON.stringify(report.snapshot,null,2),'check-evidence'));
  content.append(evidence);
}
document.addEventListener('click', async event => {
  if (event.target.closest('[data-windows-close]')) { windowsDialog.close(); return; }
  const button = event.target.closest('[data-windows-host]'); if (!button) return;
  windowsSelection = {id:button.dataset.windowsHost,ip:button.dataset.windowsIp};
  const selection = windowsSelection;
  if (windowsRequest) windowsRequest.abort();
  const request = new AbortController(); windowsRequest = request;
  document.querySelector('#windows-title').textContent = `Windows assessment · ${selection.ip}`;
  document.querySelector('#windows-file').value = '';
  document.querySelector('#windows-status').textContent = 'Loading assessment…';
  document.querySelector('#windows-ssh').disabled=true; renderWindows(null); windowsDialog.showModal();
  try {
    const response = await fetch(`/api/hosts/${selection.id}/windows`,{signal:request.signal});
    const result = await response.json(); if (!response.ok) throw new Error(result.error || 'Unable to load assessment.');
    renderWindows(result.report);
    document.querySelector('#windows-ssh').disabled=!result.ssh_ready;
    document.querySelector('#windows-access').textContent=result.ssh_ready ? 'SSH detected. Existing key access and trusted identity required.' : 'SSH is not available on TCP 22. Remote access must be configured on Windows before this action can run.';
    document.querySelector('#windows-status').textContent = result.report ? 'Imported evidence; no remote vulnerability test performed.' : 'No Windows evidence imported.';
  } catch (error) { if (error.name !== 'AbortError') document.querySelector('#windows-status').textContent = error.message; }
});
document.querySelector('#windows-file').addEventListener('change',async event => {
  const file = event.target.files[0]; if (!file || !windowsSelection) return;
  const selection = windowsSelection;
  if (file.size > 262144) { document.querySelector('#windows-status').textContent = 'Maximum export size is 256 KiB.'; return; }
  if (windowsRequest) windowsRequest.abort();
  const request = new AbortController(); windowsRequest = request;
  document.querySelector('#windows-status').textContent = 'Validating Windows evidence…';
  try {
    const response = await fetch(`/api/hosts/${selection.id}/windows`,{method:'POST',headers:{'Content-Type':'application/json','X-CSRF-Token':token},body:await file.text(),signal:request.signal});
    const result = await response.json(); if (!response.ok) throw new Error(result.error || 'Import failed.');
    renderWindows(result.report); document.querySelector('#windows-status').textContent = 'Evidence imported. Missing patch information remains inconclusive.';
  } catch (error) { if (error.name !== 'AbortError') document.querySelector('#windows-status').textContent = error.message; }
});
windowsDialog.addEventListener('close',()=>{ if (windowsRequest) windowsRequest.abort(); windowsSelection=null; });

// Reveal the matching card even when filters or pagination currently hide it.
function jumpToHost(ip) {
  const cards=[...document.querySelectorAll('#devices .device-card')];
  const card=cards.find(card=>card.dataset.ip===ip);
  if (!card) { pendingJumpIP=ip;refresh();return; }
  pendingJumpIP=null;
  Object.assign(catalog,{filter:'all',search:'',vendor:'',page:Math.floor(cards.indexOf(card)/catalog.size)+1});
  renderCatalog();card.scrollIntoView({behavior:'smooth',block:'center'});
  card.tabIndex=-1;card.focus({preventScroll:true});
}

// Remote collection is explicit and uses only existing key authentication.
document.querySelector('#windows-ssh').addEventListener('click',async()=> {
 if (!windowsSelection) return;
 const status=document.querySelector('#windows-status');
 if (!form.elements.authorized.checked) { status.textContent='Confirm LAN authorization before remote collection.';return; }
 const user=document.querySelector('#windows-user').value;
 if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/.test(user)) { status.textContent='Enter a local Windows username.';return; }
 if (windowsRequest) windowsRequest.abort();
 const request=new AbortController();windowsRequest=request;
 const selection=windowsSelection;
 const button=document.querySelector('#windows-ssh');button.disabled=true;
 status.classList.add('is-loading');status.textContent=`Collecting Windows evidence from ${selection.ip} via SSH…`;
 try {
  const response=await fetch(`/api/hosts/${selection.id}/windows/ssh`,{method:'POST',headers:{'Content-Type':'application/json','X-CSRF-Token':token},body:JSON.stringify({authorized:true,user}),signal:request.signal});
  const result=await response.json();if (!response.ok) throw new Error(result.error || 'SSH collection failed.');
  renderWindows(result.report);status.textContent='Collector executed successfully. JSON imported and assessment completed.';
 } catch(error) { if(error.name!=='AbortError') status.textContent=error.message; }
 finally { button.disabled=false;status.classList.remove('is-loading'); }
});

// Server phase timestamps keep the countdown accurate after reload or SSE replay.
function updateMonitorProgress(value) {
  monitorProgress=value;
  document.querySelector('#monitor-progress').hidden=!value.window;
  document.querySelector('#window-notice').textContent=`Round ${value.window || 1} · ${value.new_hosts ? '+' + value.new_hosts + ' new' : 'No new hosts'}`;
  const scheduled=value.tcp_scheduled || 0, completed=value.tcp_completed || 0, failed=value.tcp_failed || 0;
  const active=value.tcp_active || [];
  if (!nmapJob) showTCPActivity(active);
  const pending=Math.max(0,scheduled-completed-failed-active.length);
  document.querySelector('#tcp-progress').textContent=value.auto_tcp ? `TCP ${completed}/${scheduled} complete${active.length ? ' · ' + active.length + ' active' : ''}${pending ? ' · ' + pending + ' queued' : ''}${failed ? ' · ' + failed + ' failed/cancelled' : ''}` : 'Auto TCP off';
  drawDiscoveryCountdown();
}
function drawDiscoveryCountdown() {
  if (!monitorProgress) return;
  const value=monitorProgress;
  const timed=!value.paused && ['waiting','discovering','hosts'].includes(value.phase);
  const deadline=Date.parse(value.deadline);
  const remaining=timed && Number.isFinite(deadline) ? Math.max(0,Math.ceil((deadline-Date.now())/1000)) : 0;
  const clock=document.querySelector('#discovery-countdown');
  clock.textContent=value.paused ? 'Ⅱ' : timed ? `${String(Math.floor(remaining/60)).padStart(2,'0')}:${String(remaining%60).padStart(2,'0')}` : value.phase === 'tcp' ? 'TCP' : '■';
  const labels={waiting:'Next discovery',discovering:'Discovering devices',hosts:'Finding LAN hosts',tcp:'Inspecting queued hosts',stopped:'Stopped'};
  document.querySelector('#countdown-label').textContent=value.paused ? 'Paused · inventory kept' : labels[value.phase] || 'Starting discovery';
  const total=value.phase === 'waiting' ? value.interval_seconds || 30 : value.phase === 'hosts' ? 60 : Number(form.elements.seconds.value) || 5;
  document.querySelector('#discovery-meter').value=timed ? Math.min(100,Math.max(0,100*(1-remaining/total))) : 100;
}
const discoveryClock=setInterval(drawDiscoveryCountdown,250);
window.addEventListener('pagehide',()=>clearInterval(discoveryClock));

// Registry controls disclose downloads and never transmit observed MAC addresses.
const vendorUpdate=document.querySelector('#vendor-update');
const vendorAuto=document.querySelector('#vendor-auto');
async function vendorStatus() {
 const response=await fetch('/api/vendors');if(!response.ok)return;
 const value=await response.json();
 document.querySelector('#vendor-health').textContent=value.running ? '· Updating…' : value.stale ? '· Outdated' : '· Current';
 document.querySelector('#vendor-status').textContent=`${value.entries.toLocaleString()} records · File date: ${value.modified && !value.modified.startsWith('0001') ? new Date(value.modified).toLocaleString() : 'Unknown'}${value.conflicts ? ' · '+value.conflicts+' ambiguous prefixes excluded' : ''}${value.error ? ' · '+value.error : ''}`;
 vendorAuto.checked=value.automatic;vendorUpdate.disabled=value.running;
 if(value.running)setTimeout(()=>vendorStatus().catch(showError),1000);
}
if(vendorUpdate) {
 vendorStatus().catch(showError);
 vendorUpdate.addEventListener('click',async()=>{
  vendorUpdate.disabled=true;document.querySelector('#vendor-health').textContent='· Updating…';
  try {const response=await fetch('/api/vendors/update',{method:'POST',headers:{'X-CSRF-Token':token}});const value=await response.json();if(!response.ok)throw new Error(value.error || 'Database update failed');refresh();}
  catch(error){showError(error);}finally{vendorUpdate.disabled=false;await vendorStatus();}
 });
 vendorAuto.addEventListener('change',async()=>{
  try {const response=await fetch('/api/vendors/settings',{method:'POST',headers:{'Content-Type':'application/json','X-CSRF-Token':token},body:JSON.stringify({automatic:vendorAuto.checked})});if(!response.ok)throw new Error('Unable to save database settings');}catch(error){showError(error);}finally{await vendorStatus();}
 });
}

// Saved inventories are imported as read-only evidence; network actions remain live-only.
document.addEventListener('change',async event=>{
 if(event.target.id!=='snapshot-file')return;
 const file=event.target.files[0];if(!file)return;
 try {
  if(file.size>16*1024*1024)throw new Error('Snapshot exceeds 16 MiB.');
  const response=await fetch('/api/snapshots/load',{method:'POST',headers:{'Content-Type':'application/json','X-CSRF-Token':token},body:await file.text()});
  const value=await response.json();if(!response.ok)throw new Error(value.error);
  if(stream)stream.close();scanID=null;start.disabled=true;cancel.disabled=true;pause.disabled=true;document.querySelector('#snapshot-note').textContent='Saved inventory · Read-only';
  statusText.textContent=`Saved inventory · ${new Date(value.saved_at).toLocaleString()} · Read-only`;
  refresh();
 }catch(error){showError(error);}finally{event.target.value='';}
});
document.addEventListener('click',async event=>{
 if(!event.target.closest('#snapshot-live'))return;
 try {const response=await fetch('/api/snapshots/live',{method:'POST',headers:{'X-CSRF-Token':token}});if(!response.ok)throw new Error('Unable to return to live inventory');start.disabled=false;document.querySelector('#snapshot-note').textContent='';statusText.textContent='Live inventory';refresh();}catch(error){showError(error);}
});

document.addEventListener('click',async event=>{
 if(event.target.closest('[data-load-snapshot]')) {document.querySelector('#snapshot-file').click();return;}
 const save=event.target.closest('[data-save-snapshot]');if(!save)return;event.preventDefault();
 try {
  const response=await fetch('/api/snapshots/export');if(!response.ok){const value=await response.json();throw new Error(value.error || 'Unable to save inventory');}
  const url=URL.createObjectURL(await response.blob());const link=document.createElement('a');link.href=url;link.download='netexplorer-inventory.json';document.body.append(link);link.click();link.remove();setTimeout(()=>URL.revokeObjectURL(url),1000);
 }catch(error){showError(error);}
});

// Preserve each card's selected tab across inventory updates; keyboard navigation follows ARIA tabs.

function selectCardTab(card, name, focus = false) {
 const tabs = [...card.querySelectorAll('[data-card-tab]')];
 const selected = tabs.find(tab => tab.dataset.cardTab === name);
 if (!selected && name !== null) return;
 for (const tab of tabs) {
  const active = tab === selected;
  tab.setAttribute('aria-selected', String(active));
  tab.tabIndex = active || (name === null && tab === tabs[0]) ? 0 : -1;
 }
 for (const panel of card.querySelectorAll('[data-card-panel]')) panel.hidden = panel.dataset.cardPanel !== name;
 selectedCardTabs.set(card.id, name);
 if (focus && selected) selected.focus();
}
function restoreCardTabs() {
 for (const card of document.querySelectorAll('.device-card')) {
  const name = selectedCardTabs.get(card.id);
  if (selectedCardTabs.has(card.id)) selectCardTab(card, name);
 }
}
document.addEventListener('click', event => {
 const tab = event.target.closest('[data-card-tab]');
 if (tab) selectCardTab(tab.closest('.device-card'), tab.getAttribute('aria-selected') === 'true' ? null : tab.dataset.cardTab);
});
document.addEventListener('keydown', event => {
 const tab = event.target.closest('[data-card-tab]');
 if (!tab || !['ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(event.key)) return;
 event.preventDefault();
 const card = tab.closest('.device-card');
 const tabs = [...card.querySelectorAll('[data-card-tab]')];
 const index = tabs.indexOf(tab);
 const next = event.key === 'Home' ? 0 : event.key === 'End' ? tabs.length - 1 : (index + (event.key === 'ArrowRight' ? 1 : -1) + tabs.length) % tabs.length;
 selectCardTab(card, tabs[next].dataset.cardTab, true);
});

// Indeterminate progress shows activity without inventing a completion percentage.
function showTCPActivity(addresses, label = 'Common + notable ports') {
 const panel = document.querySelector('#tcp-activity');
 panel.hidden = addresses.length === 0;
 document.body.dataset.tcpActive = String(addresses.length > 0);
 document.querySelector('#tcp-activity-host').textContent = addresses.length ? `Inspecting ${addresses.join(', ')}` : '';
 document.querySelector('#tcp-activity-label').textContent = label;
}

// Pause keeps the current session; active bounded work finishes before new work is admitted.
pause.addEventListener('click', async () => {
 if (!scanID) return;
 pause.disabled = true;
 try {
  const response = await fetch(`/api/scans/${scanID}/${scanPaused ? 'resume' : 'pause'}`, {method:'POST',headers:{'X-CSRF-Token':token}});
  if (!response.ok) throw new Error('Unable to change discovery pause state.');
  await state(true);
  statusText.textContent = scanPaused ? 'Paused · active work finishes; inventory preserved.' : 'Discovery resumed · existing inventory preserved.';
 } catch(error) { showError(error); } finally { pause.disabled = false; }
});
