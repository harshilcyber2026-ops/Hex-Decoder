/* ═══════════════════════════════════════════════════════════════════
   FlagVault CTF — Hex Decoder · Challenge #E1
   ───────────────────────────────────────────────────────────────
   CHALLENGE HEX (spaces = formatting only):
     466c6167566175 6c747b6830785f 6d345f337a707779 7d

   CLEAN HEX:
     466c61675661756c747b6830785f6d345f337a7077797d

   BYTE BREAKDOWN:
     46='F' 6c='l' 61='a' 67='g' 56='V' 61='a' 75='u' 6c='l'
     74='t' 7b='{' 68='h' 30='0' 78='x' 5f='_' 6d='m' 34='4'
     5f='_' 33='3' 7a='z' 70='p' 77='w' 79='y' 7d='}'

   FLAG: FlagVault{h0x_m4_3zpwy}
   ═══════════════════════════════════════════════════════════════════ */

'use strict';

/* ──────── Constants ──────── */
const CHALLENGE_HEX = '466c61675661756c747b6830785f6d345f337a7077797d';
const FLAG          = 'FlagVault{h0x_m4_3zpwy}';

/* ──────── Hex utility ──────── */
function stripHex(input) {
  return input.replace(/[^0-9a-fA-F]/g, '');
}

function hexToAscii(hex) {
  const clean = stripHex(hex);
  if (clean.length === 0 || clean.length % 2 !== 0) return null;
  try {
    let result = '';
    for (let i = 0; i < clean.length; i += 2) {
      const byte = parseInt(clean.slice(i, i + 2), 16);
      result += String.fromCharCode(byte);
    }
    return result;
  } catch {
    return null;
  }
}

function getPairs(hex) {
  const clean = stripHex(hex);
  const pairs = [];
  for (let i = 0; i < clean.length - 1; i += 2) {
    pairs.push(clean.slice(i, i + 2));
  }
  return pairs;
}

/* ──────── "Decode Now" button ──────── */
function runDecode() {
  const input = document.getElementById('dc-input');
  input.value = CHALLENGE_HEX;
  liveDecodeInput(CHALLENGE_HEX);
  input.focus();
}

/* ──────── Live decode (input listener) ──────── */
function liveDecodeInput(raw) {
  const outputEl  = document.getElementById('dc-output');
  const badgeEl   = document.getElementById('dco-badge');
  const breakWrap = document.getElementById('breakdown-wrap');

  if (!raw || !raw.trim()) {
    outputEl.innerHTML  = '<span class="do-dim">Output will appear here…</span>';
    badgeEl.textContent = '—';
    badgeEl.className   = 'dco-badge';
    breakWrap.style.display = 'none';
    return;
  }

  const clean = stripHex(raw);

  if (clean.length === 0) {
    outputEl.innerHTML  = '<span class="do-err">No valid hex characters found</span>';
    badgeEl.textContent = 'ERROR';
    badgeEl.className   = 'dco-badge badge-err';
    breakWrap.style.display = 'none';
    return;
  }

  if (clean.length % 2 !== 0) {
    outputEl.innerHTML  = `<span class="do-err">Odd number of hex digits (${clean.length}) — need even pairs</span>`;
    badgeEl.textContent = 'ODD LENGTH';
    badgeEl.className   = 'dco-badge badge-err';
    breakWrap.style.display = 'none';
    return;
  }

  const result = hexToAscii(clean);
  if (result === null) {
    outputEl.innerHTML  = '<span class="do-err">Invalid hex string</span>';
    badgeEl.textContent = 'ERROR';
    badgeEl.className   = 'dco-badge badge-err';
    return;
  }

  const isFlag = result === FLAG;
  if (isFlag) {
    outputEl.innerHTML  = `<span class="do-flag">${escHtml(result)}</span>`;
    badgeEl.textContent = '✓ FLAG FOUND';
    badgeEl.className   = 'dco-badge badge-ok';
    revealFlag();
  } else {
    outputEl.innerHTML  = escHtml(result);
    badgeEl.textContent = `${clean.length / 2} bytes`;
    badgeEl.className   = 'dco-badge badge-ok';
  }

  // Build byte grid
  buildByteGrid(clean);
  breakWrap.style.display = '';
}

/* ──────── Byte grid ──────── */
function buildByteGrid(clean) {
  const grid = document.getElementById('byte-grid');
  grid.innerHTML = '';

  const pairs = getPairs(clean);
  pairs.forEach((pair, idx) => {
    const dec  = parseInt(pair, 16);
    const char = dec >= 32 && dec < 127 ? String.fromCharCode(dec) : '·';

    const cell = document.createElement('div');
    cell.className = 'byte-cell';

    // Colour coding
    if (idx < 9)               cell.classList.add('bc-flagvault'); // "FlagVault"
    if (char === '{' || char === '}') cell.classList.add('bc-brace');

    cell.title = `0x${pair.toUpperCase()} = ${dec} = '${char}'`;
    cell.innerHTML = `
      <span class="bc-hex">0x${pair}</span>
      <span class="bc-dec">${dec}</span>
      <span class="bc-char">${escHtml(char)}</span>`;

    cell.addEventListener('click', () => {
      highlightTableChar(pair);
    });

    grid.appendChild(cell);
  });
}

/* ──────── Reference table ──────── */
const HEX_TABS = {
  lower:   [...'abcdefghijklmnopqrstuvwxyz'].map(c => [c, c.charCodeAt(0).toString(16).padStart(2,'0')]),
  upper:   [...'ABCDEFGHIJKLMNOPQRSTUVWXYZ'].map(c => [c, c.charCodeAt(0).toString(16).padStart(2,'0')]),
  digits:  [...'0123456789'].map(c => [c, c.charCodeAt(0).toString(16).padStart(2,'0')]),
  special: ['{','}',' ','_','-','.',',','!','?','@','#','$','%','^','&','*','(',')','+','=','/','\\','"',"'",'`','~','<','>','[',']','|',':',';'].map(c => [c, c.charCodeAt(0).toString(16).padStart(2,'0')]),
};

let currentTab = 'lower';

function switchHexTab(tab) {
  currentTab = tab;
  document.querySelectorAll('.htc-tab').forEach(t => t.classList.remove('active'));
  document.querySelector(`[onclick="switchHexTab('${tab}')"]`)?.classList.add('active');
  buildHexTable(tab);
}

function buildHexTable(tab) {
  const grid = document.getElementById('htc-grid');
  grid.innerHTML = '';
  (HEX_TABS[tab] || []).forEach(([char, hex]) => {
    const cell = document.createElement('div');
    cell.className = 'htc-cell';
    cell.id = `htc-${hex}`;
    cell.title = `'${char}' = 0x${hex} = ${parseInt(hex,16)}`;
    cell.onclick = () => handleTableCellClick(hex);
    cell.innerHTML = `<span class="htc-char">${escHtml(char)}</span><span class="htc-hex">${hex}</span>`;
    grid.appendChild(cell);
  });
}

function highlightTableChar(hex) {
  document.querySelectorAll('.htc-cell').forEach(c => c.classList.remove('htc-hl'));
  const cell = document.getElementById(`htc-${hex.toLowerCase()}`);
  if (cell) {
    cell.classList.add('htc-hl');
    cell.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  } else {
    // Switch to the right tab and try again
    const dec  = parseInt(hex, 16);
    const char = String.fromCharCode(dec);
    if (/[a-z]/.test(char))      switchHexTab('lower');
    else if (/[A-Z]/.test(char)) switchHexTab('upper');
    else if (/[0-9]/.test(char)) switchHexTab('digits');
    else                         switchHexTab('special');
    setTimeout(() => highlightTableChar(hex), 50);
  }
}

function handleTableCellClick(hex) {
  const current = document.getElementById('dc-input').value;
  document.getElementById('dc-input').value = current + hex;
  liveDecodeInput(document.getElementById('dc-input').value);
}

/* ──────── Search table ──────── */
function searchHexTable(q) {
  const results = document.getElementById('htc-results');
  if (!q.trim()) { results.innerHTML = ''; return; }

  const matches = [];
  for (let code = 32; code < 127; code++) {
    const char = String.fromCharCode(code);
    const hex  = code.toString(16).padStart(2, '0');
    const dec  = code.toString();
    const qLow = q.toLowerCase();
    if (char.toLowerCase() === qLow ||
        hex  === qLow ||
        dec  === q.trim()) {
      matches.push({ char, hex, dec: code });
    }
  }

  if (matches.length === 0) {
    results.innerHTML = `<div class="htcr-row" style="color:var(--text-dim)">No match for "${escHtml(q)}"</div>`;
    return;
  }

  results.innerHTML = matches.map(m =>
    `<div class="htcr-row">
      char <span>'${escHtml(m.char)}'</span> = hex <span>0x${m.hex}</span> = decimal <span>${m.dec}</span>
    </div>`
  ).join('');

  // Highlight in table
  if (matches.length === 1) highlightTableChar(matches[0].hex);
}

/* ──────── Copy helpers ──────── */
function copyHex() {
  navigator.clipboard.writeText(CHALLENGE_HEX).catch(() => {
    const ta = document.createElement('textarea');
    ta.value = CHALLENGE_HEX;
    document.body.appendChild(ta); ta.select(); document.execCommand('copy'); ta.remove();
  });
}

function copyFlag() {
  const v = document.getElementById('fr-val').textContent;
  const t = document.getElementById('copy-toast');
  navigator.clipboard.writeText(v).catch(() => {
    const ta = document.createElement('textarea');
    ta.value = v; document.body.appendChild(ta); ta.select(); document.execCommand('copy'); ta.remove();
  });
  t.classList.remove('hidden');
  setTimeout(() => t.classList.add('hidden'), 2000);
}

/* ──────── Flag reveal ──────── */
function revealFlag() {
  const wrap = document.getElementById('flag-reveal');
  if (!wrap || !wrap.classList.contains('hidden')) return;
  document.getElementById('fr-val').textContent = FLAG;
  wrap.classList.remove('hidden');
  setTimeout(() => wrap.scrollIntoView({ behavior: 'smooth', block: 'center' }), 300);
}

/* ──────── Hints ──────── */
function toggleHint(n) {
  const b = document.getElementById(`h${n}b`);
  const t = document.getElementById(`h${n}t`);
  const hidden = b.classList.toggle('hidden');
  t.textContent = hidden ? '▼ Reveal' : '▲ Hide';
}

/* ──────── Submit ──────── */
function submitFlag() {
  const v = document.getElementById('flag-input').value.trim();
  const r = document.getElementById('flag-result');
  if (`FlagVault{${v}}` === FLAG) {
    r.className = 'submit-result correct';
    r.innerHTML = '✓ &nbsp;Correct! Flag accepted. +50 pts';
    revealFlag();
  } else {
    r.className = 'submit-result incorrect';
    r.innerHTML = '✗ &nbsp;Incorrect. Decode the hex string above — the flag is right there!';
  }
}

/* ──────── Utility ──────── */
function escHtml(s) {
  return String(s)
    .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')
    .replace(/"/g,'&quot;').replace(/'/g,'&#39;');
}

/* ──────── Boot ──────── */
document.addEventListener('DOMContentLoaded', () => {
  buildHexTable('lower');

  document.getElementById('flag-input')?.addEventListener('keydown', e => {
    if (e.key === 'Enter') submitFlag();
  });

  document.getElementById('dc-input')?.addEventListener('keydown', e => {
    if (e.key === 'Enter') liveDecodeInput(e.target.value);
  });

  console.log('%c🔢 FlagVault CTF — Hex Decoder', 'font-size:14px;font-weight:bold;color:#00e8c8;');
  console.log('%cChallenge hex: ' + CHALLENGE_HEX, 'color:#ff2d6b;font-family:monospace;');
  console.log('%cPython: bytes.fromhex("' + CHALLENGE_HEX + '").decode()', 'color:#f5a623;font-family:monospace;');
  console.log('%cFlag: ' + FLAG, 'color:#00e8c8;font-family:monospace;');
});
