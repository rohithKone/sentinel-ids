const $ = (id) => document.getElementById(id);
let alerts = [];
let clearedAt = 0;
function formatTime(value) { const d = new Date(value); return Number.isNaN(d.valueOf()) ? '—' : d.toLocaleTimeString([], {hour:'2-digit', minute:'2-digit', second:'2-digit', hour12:false}); }
function kindLabel(kind) { return ({port_scan:'Port scan suspected', syn_burst:'SYN burst detected'}[kind] || (kind.startsWith('watched_') ? `Watched port ${kind.slice(8)}` : kind.replaceAll('_',' '))); }
function render() {
  const visible = alerts.filter(a => new Date(a.timestamp).getTime() >= clearedAt);
  $('alerts-total').textContent = visible.length;
  $('high-total').textContent = visible.filter(a => a.severity === 'high').length;
  $('alert-caption').textContent = visible.length ? `${visible.length} detection${visible.length === 1 ? '' : 's'} in this session` : 'No alerts in this session';
  $('stream-count').textContent = `${visible.length} EVENT${visible.length === 1 ? '' : 'S'}`;
  const list = $('alert-list');
  if (!visible.length) {
    list.innerHTML = '<div class="empty-state"><div class="empty-orbit"><span>⌁</span></div><h3>All clear so far</h3><p>When Sentinel spots unusual traffic, detections will appear here.</p><div class="empty-status"><i></i> Listening for signals</div></div>';
    return;
  }
  list.innerHTML = visible.map(a => `<div class="alert-row"><span class="severity ${(a.severity || 'medium').toLowerCase()}">${(a.severity || 'medium').toUpperCase()}</span><span class="kind">${kindLabel(a.kind)}<span class="kind-sub">${a.kind.replaceAll('_',' ').toUpperCase()}</span></span><span class="source">${a.source}</span><span class="detail">${a.detail}</span><span class="time">${formatTime(a.timestamp)}</span></div>`).join('');
}
async function refresh() {
  try {
    const [statusRes, alertsRes] = await Promise.all([fetch('/api/status'), fetch('/api/alerts')]);
    if (!statusRes.ok || !alertsRes.ok) throw new Error('offline');
    const status = await statusRes.json(); alerts = await alertsRes.json();
    document.body.classList.remove('disconnected'); $('status-label').textContent = 'MONITORING'; $('sensor-state').textContent = 'Active · IPv4 / TCP';
    $('packets').textContent = Number(status.packets_seen).toLocaleString(); $('since').textContent = `since ${formatTime(status.started)}`;
    $('last-sync').textContent = new Date().toLocaleTimeString([], {hour:'2-digit',minute:'2-digit',second:'2-digit',hour12:false});
    $('alert-list').dataset.connected = 'yes'; render();
  } catch {
    document.body.classList.add('disconnected'); $('status-label').textContent = 'SENSOR OFFLINE'; $('sensor-state').textContent = 'Waiting for sensor';
    if ($('alert-list').dataset.connected !== 'yes') $('alert-list').innerHTML = '<div class="empty-state"><div class="empty-orbit"><span>⌁</span></div><h3>Waiting for the sensor</h3><p>Start Sentinel with the dashboard option to stream live detections.</p><div class="empty-status"><i></i> Feed reconnects automatically</div></div>';
  }
}
$('clear-btn').addEventListener('click', () => { clearedAt = Date.now(); render(); });
function tick(){ $('clock').textContent = new Date().toLocaleTimeString([], {hour:'2-digit',minute:'2-digit',second:'2-digit',hour12:false}); }
tick(); setInterval(tick,1000); refresh(); setInterval(refresh,2000);

