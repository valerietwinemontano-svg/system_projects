/* =========================================================
   SELF SECURITY SYSTEM — single-file logic
   ========================================================= */

const $  = sel => document.querySelector(sel);
const $$ = sel => Array.from(document.querySelectorAll(sel));

/* ---------- STORAGE KEYS ---------- */
const PWSCORE_KEY = 'redshield_pwscore';
const CHECK_KEY   = 'redshield_checklist';
const SALT_KEY    = 'redshield_salt';
const VERIFY_KEY  = 'redshield_verify';
const NOTES_KEY   = 'redshield_notes';
const PROFILE_KEY = 'redshield_profile';

const DEFAULT_NAME = 'Self Security System';

/* =========================================================
   TOAST
   ========================================================= */
let toastTimer;
function toast(msg){
  const t = $('#toast');
  t.textContent = msg;
  t.classList.add('show');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => t.classList.remove('show'), 2200);
}

/* =========================================================
   TABS
   ========================================================= */
$$('.tab').forEach(btn => {
  btn.addEventListener('click', () => {
    $$('.tab').forEach(b => b.classList.remove('active'));
    $$('.panel').forEach(p => p.classList.remove('active'));
    btn.classList.add('active');
    $('#' + btn.dataset.tab).classList.add('active');
  });
});

/* =========================================================
   PROFILE (SETTINGS)
   ========================================================= */
function loadProfile(){
  try{
    return JSON.parse(localStorage.getItem(PROFILE_KEY)) || {};
  }catch(e){
    return {};
  }
}

function persistProfile(p){
  localStorage.setItem(PROFILE_KEY, JSON.stringify(p));
}

function applyProfile(){
  const p = loadProfile();
  const name = (p.name && p.name.trim()) || DEFAULT_NAME;
  const avatar = p.avatar || '';

  /* Header */
  $('#brandName').textContent = name;
  document.title = name + ' — Personal Security Suite';

  const img      = $('#avatarImg');
  const logo     = $('#logoFallback');
  const big      = $('#profileBig');
  const bigFall  = $('#profileBigFallback');

  if(avatar){
    img.src = avatar;
    img.classList.add('show');
    logo.classList.add('hide');

    big.src = avatar;
    big.classList.remove('hidden');
    bigFall.classList.add('hidden');
  }else{
    img.removeAttribute('src');
    img.classList.remove('show');
    logo.classList.remove('hide');

    big.removeAttribute('src');
    big.classList.add('hidden');
    bigFall.classList.remove('hidden');
  }

  /* Settings input reflects saved name */
  $('#profileName').value = name;
}

/* Resize + convert image to a small square data URL */
function processImageFile(file){
  return new Promise((resolve, reject) => {
    if(!file || !file.type || !file.type.startsWith('image/')){
      reject(new Error('Please choose a valid image file.'));
      return;
    }
    if(file.size > 5 * 1024 * 1024){
      reject(new Error('Image is too large (max 5 MB).'));
      return;
    }

    const reader = new FileReader();

    reader.onload = () => {
      const img = new Image();
      img.onload = () => {
        const size = 256;
        const canvas = document.createElement('canvas');
        canvas.width = size;
        canvas.height = size;

        const ctx = canvas.getContext('2d');
        // cover-crop to a centered square
        const scale = Math.max(size / img.width, size / img.height);
        const w = img.width * scale;
        const h = img.height * scale;

        ctx.drawImage(img, (size - w) / 2, (size - h) / 2, w, h);

        try{
          resolve(canvas.toDataURL('image/jpeg', 0.85));
        }catch(err){
          reject(new Error('Could not process this image.'));
        }
      };
      img.onerror = () => reject(new Error('Could not read this image.'));
      img.src = reader.result;
    };

    reader.onerror = () => reject(new Error('Could not read the file.'));
    reader.readAsDataURL(file);
  });
}

$('#uploadBtn').addEventListener('click', () => $('#photoInput').click());

$('#photoInput').addEventListener('change', async e => {
  const file = e.target.files && e.target.files[0];
  e.target.value = ''; // allow selecting the same file again
  if(!file) return;

  const msg = $('#profileMsg');
  msg.textContent = '';
  msg.className = 'msg';

  try{
    const dataUrl = await processImageFile(file);
    const p = loadProfile();
    p.avatar = dataUrl;
    persistProfile(p);
    applyProfile();
    toast('Profile photo updated');
  }catch(err){
    msg.textContent = err.message;
    msg.classList.add('err');
  }
});

$('#removePhotoBtn').addEventListener('click', () => {
  const p = loadProfile();
  delete p.avatar;
  persistProfile(p);
  applyProfile();
  $('#profileMsg').textContent = '';
  $('#profileMsg').className = 'msg';
  toast('Profile photo removed');
});

$('#saveProfileBtn').addEventListener('click', () => {
  const p = loadProfile();
  const name = $('#profileName').value.trim() || DEFAULT_NAME;
  p.name = name;
  persistProfile(p);
  applyProfile();
  toast('Profile saved');
});

/* Live preview of the name while typing */
$('#profileName').addEventListener('input', e => {
  $('#brandName').textContent = e.target.value.trim() || DEFAULT_NAME;
});

/* Reset everything */
$('#resetAllBtn').addEventListener('click', () => {
  const ok = confirm(
    'This will delete your profile, checklist, password score and ALL encrypted vault notes from this browser. Continue?'
  );
  if(!ok) return;

  [
    PWSCORE_KEY, CHECK_KEY, SALT_KEY, VERIFY_KEY, NOTES_KEY, PROFILE_KEY
  ].forEach(k => localStorage.removeItem(k));

  location.reload();
});

/* =========================================================
   PASSWORD ANALYZER
   ========================================================= */
const COMMON_PATTERNS = [
  'password','123456','12345678','123456789','qwerty','abc123','letmein',
  'monkey','dragon','iloveyou','admin','welcome','111111','000000',
  'password1','sunshine','princess','football','charlie','aa123456','donald',
  'qwerty123','1q2w3e4r','zxcvbnm','asdfgh'
];

function analyzePassword(pw){
  if(!pw) return null;

  const len = pw.length;
  const hasLower  = /[a-z]/.test(pw);
  const hasUpper  = /[A-Z]/.test(pw);
  const hasDigit  = /\d/.test(pw);
  const hasSymbol = /[^A-Za-z0-9]/.test(pw);

  const issues = [];
  const strengths = [];
  let score = 0;

  /* Length */
  if(len >= 16){ score += 30; strengths.push('Excellent length (16+ characters)'); }
  else if(len >= 12){ score += 22; strengths.push('Good length (12+ characters)'); }
  else if(len >= 8){ score += 12; }
  else { issues.push('Too short — use at least 12 characters'); }

  /* Character classes */
  if(hasLower) score += 10; else issues.push('Add lowercase letters');
  if(hasUpper) score += 10; else issues.push('Add uppercase letters');
  if(hasDigit) score += 10; else issues.push('Add digits');
  if(hasSymbol) score += 15; else issues.push('Add symbols (!@#$…)');
  if(hasLower && hasUpper && hasDigit && hasSymbol) strengths.push('Uses all character types');

  /* Repeats */
  if(/(.)\1{2,}/.test(pw)){
    score -= 10;
    issues.push('Avoid repeated characters (e.g. aaa)');
  }

  /* Sequences */
  if(/(123|234|345|456|567|678|789|abc|bcd|cde|qwe|wer|asd|zxc)/i.test(pw)){
    score -= 10;
    issues.push('Avoid keyboard sequences (e.g. 123, qwe)');
  }

  /* Common patterns */
  if(COMMON_PATTERNS.some(c => pw.toLowerCase().includes(c))){
    score -= 30;
    issues.push('Contains a very common password pattern');
  }

  /* Only one character type */
  const typeCount = [hasLower, hasUpper, hasDigit, hasSymbol].filter(Boolean).length;
  if(typeCount <= 1) issues.push('Use more than one character type');
  if(typeCount >= 3) strengths.push('Mixes multiple character types');

  score = Math.max(0, Math.min(100, score));

  /* Entropy */
  let pool = 0;
  if(hasLower)  pool += 26;
  if(hasUpper)  pool += 26;
  if(hasDigit)  pool += 10;
  if(hasSymbol) pool += 32;
  const entropy = pool > 0 ? len * Math.log2(pool) : 0;

  /* Crack time estimate: 10 billion guesses/sec (offline attack) */
  const guesses = Math.pow(2, entropy - 1);
  const seconds = guesses / 1e10;

  return { score, entropy, seconds, issues, strengths, len };
}

function formatCrackTime(seconds){
  if(!isFinite(seconds) || seconds <= 0) return 'instantly';
  if(seconds < 1) return 'instantly';

  const years = seconds / 31557600;
  if(years > 1000) return 'centuries';
  if(years >= 1) return years.toFixed(1) + ' years';

  const units = [
    ['day', 86400],
    ['hour', 3600],
    ['minute', 60],
    ['second', 1]
  ];
  for(const [name, s] of units){
    if(seconds >= s){
      const v = seconds / s;
      return (v >= 10 ? Math.round(v) : v.toFixed(1)) + ' ' + name + (v >= 2 ? 's' : '');
    }
  }
  return seconds.toFixed(1) + ' seconds';
}

function scoreLabel(score){
  if(score < 25) return ['Very Weak', '#ff2b2b'];
  if(score < 50) return ['Weak',      '#ff5a3c'];
  if(score < 70) return ['Fair',      '#ff8a6b'];
  if(score < 85) return ['Good',      '#ffc2c2'];
  return ['Strong', '#ffffff'];
}

function resetAnalyzer(){
  $('#meterFill').style.width = '0%';
  $('#pwLabel').textContent = '—';
  $('#pwLabel').style.color = '#ff5a3c';
  $('#pwScoreTxt').textContent = '0 / 100';
  $('#issueList').innerHTML    = '<li class="muted">No analysis yet.</li>';
  $('#strengthList').innerHTML = '<li class="muted">No analysis yet.</li>';
  $('#chipLen').textContent     = '0';
  $('#chipEntropy').textContent = '0 bits';
  $('#chipCrack').textContent   = '—';
}

function renderAnalyzer(res){
  if(!res){ resetAnalyzer(); return; }

  const [label, color] = scoreLabel(res.score);

  $('#meterFill').style.width = res.score + '%';
  $('#pwLabel').textContent = label;
  $('#pwLabel').style.color = color;
  $('#pwScoreTxt').textContent = res.score + ' / 100';

  $('#issueList').innerHTML = res.issues.length
    ? res.issues.map(i => '<li>' + i + '</li>').join('')
    : '<li class="muted">No issues found 🎉</li>';

  $('#strengthList').innerHTML = res.strengths.length
    ? res.strengths.map(s => '<li>' + s + '</li>').join('')
    : '<li class="muted">No notable strengths yet.</li>';

  $('#chipLen').textContent     = res.len;
  $('#chipEntropy').textContent = res.entropy.toFixed(1) + ' bits';
  $('#chipCrack').textContent   = formatCrackTime(res.seconds);
}

$('#pwInput').addEventListener('input', e => {
  const res = analyzePassword(e.target.value);
  renderAnalyzer(res);
  localStorage.setItem(PWSCORE_KEY, res ? res.score : 0);
  refreshDashboard();
});

$('#pwToggle').addEventListener('click', () => {
  const input = $('#pwInput');
  const show = input.type === 'password';
  input.type = show ? 'text' : 'password';
  $('#pwToggle').textContent = show ? 'Hide' : 'Show';
});

$('#masterToggle').addEventListener('click', () => {
  const input = $('#masterPw');
  const show = input.type === 'password';
  input.type = show ? 'text' : 'password';
  $('#masterToggle').textContent = show ? 'Hide' : 'Show';
});

/* =========================================================
   PASSWORD GENERATOR
   ========================================================= */
const UINT32_MAX = 4294967296;

function randInt(max){
  const limit = Math.floor(UINT32_MAX / max) * max;
  const arr = new Uint32Array(1);
  let x;
  do {
    crypto.getRandomValues(arr);
    x = arr[0];
  } while (x >= limit);
  return x % max;
}

function shuffle(arr){
  for(let i = arr.length - 1; i > 0; i--){
    const j = randInt(i + 1);
    [arr[i], arr[j]] = [arr[j], arr[i]];
  }
  return arr;
}

function generatePassword(){
  const len = parseInt($('#genLen').value, 10);

  const sets = [];
  if($('#optLower').checked)   sets.push('abcdefghijklmnopqrstuvwxyz');
  if($('#optUpper').checked)   sets.push('ABCDEFGHIJKLMNOPQRSTUVWXYZ');
  if($('#optDigits').checked)  sets.push('0123456789');
  if($('#optSymbols').checked) sets.push('!@#$%^&*()-_=+[]{};:,.<>?/');

  if(sets.length === 0){
    toast('Select at least one character set');
    return;
  }

  const all = sets.join('');
  const chars = [];

  // guarantee at least one character from every selected set
  sets.forEach(set => chars.push(set[randInt(set.length)]));

  // fill the rest randomly
  for(let i = chars.length; i < len; i++){
    chars.push(all[randInt(all.length)]);
  }

  const password = shuffle(chars).slice(0, len).join('');
  $('#genOut').value = password;
}

$('#genLen').addEventListener('input', e => {
  $('#genLenLabel').textContent = e.target.value;
});

$('#genBtn').addEventListener('click', generatePassword);

$('#genCopy').addEventListener('click', async () => {
  const value = $('#genOut').value;
  if(!value || value === 'Click Generate'){
    toast('Generate a password first');
    return;
  }
  try{
    await navigator.clipboard.writeText(value);
    toast('Password copied to clipboard');
  }catch(e){
    const ta = document.createElement('textarea');
    ta.value = value;
    document.body.appendChild(ta);
    ta.select();
    document.execCommand('copy');
    ta.remove();
    toast('Password copied');
  }
});

/* =========================================================
   SECURE VAULT  (AES-256-GCM + PBKDF2)
   ========================================================= */
let vaultKey = null;
let vaultNotes = [];

function bufToB64(buf){
  const bytes = new Uint8Array(buf);
  let s = '';
  for(let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return btoa(s);
}

function b64ToBuf(str){
  const bin = atob(str);
  const bytes = new Uint8Array(bin.length);
  for(let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

async function deriveKey(password, saltBytes){
  const enc = new TextEncoder();
  const baseKey = await crypto.subtle.importKey(
    'raw',
    enc.encode(password),
    'PBKDF2',
    false,
    ['deriveKey']
  );
  return crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: saltBytes,
      iterations: 150000,
      hash: 'SHA-256'
    },
    baseKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

async function encryptJSON(key, obj){
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const data = new TextEncoder().encode(JSON.stringify(obj));
  const ct = await crypto.subtle.encrypt({ name:'AES-GCM', iv }, key, data);
  return { iv: bufToB64(iv), ct: bufToB64(ct) };
}

async function decryptJSON(key, payload){
  const iv = b64ToBuf(payload.iv);
  const ct = b64ToBuf(payload.ct);
  const pt = await crypto.subtle.decrypt({ name:'AES-GCM', iv }, key, ct);
  return JSON.parse(new TextDecoder().decode(pt));
}

function vaultExists(){
  return !!localStorage.getItem(SALT_KEY);
}

function updateVaultUI(){
  const exists = vaultExists();
  $('#confirmWrap').classList.toggle('hidden', exists);
  $('#vaultUnlockBtn').textContent = exists ? 'Unlock Vault' : 'Create Vault';
  $('#vaultHint').textContent = exists
    ? 'Vault found. Enter your master password to unlock.'
    : 'Create a master password. It never leaves your browser.';
  $('#masterPw').value = '';
  $('#masterPw2').value = '';
  $('#masterPw').type = 'password';
  $('#masterToggle').textContent = 'Show';
  $('#vaultMsg').textContent = '';
  $('#vaultMsg').className = 'msg';
}

async function createVault(password){
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const key = await deriveKey(password, salt);

  const verifier = await encryptJSON(key, { check: 'SELF_SECURITY_SYSTEM_VERIFY' });
  const emptyNotes = await encryptJSON(key, []);

  localStorage.setItem(SALT_KEY, bufToB64(salt));
  localStorage.setItem(VERIFY_KEY, JSON.stringify(verifier));
  localStorage.setItem(NOTES_KEY, JSON.stringify(emptyNotes));

  vaultKey = key;
  vaultNotes = [];
}

async function unlockVault(password){
  const salt = b64ToBuf(localStorage.getItem(SALT_KEY));
  const key = await deriveKey(password, salt);

  try{
    await decryptJSON(key, JSON.parse(localStorage.getItem(VERIFY_KEY)));
  }catch(e){
    throw new Error('Wrong master password');
  }

  vaultKey = key;

  const notesPayload = JSON.parse(localStorage.getItem(NOTES_KEY) || 'null');
  vaultNotes = notesPayload ? await decryptJSON(key, notesPayload) : [];
}

async function saveNotes(){
  if(!vaultKey) return;
  const payload = await encryptJSON(vaultKey, vaultNotes);
  localStorage.setItem(NOTES_KEY, JSON.stringify(payload));
}

function showVaultApp(){
  $('#vaultLockCard').classList.add('hidden');
  $('#vaultApp').classList.remove('hidden');
  renderNotes();
}

function hideVaultApp(){
  $('#vaultApp').classList.add('hidden');
  $('#vaultLockCard').classList.remove('hidden');
}

function esc(str){
  return String(str).replace(/[&<>"']/g, c => ({
    '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'
  }[c]));
}

function renderNotes(){
  const list = $('#noteList');

  if(vaultNotes.length === 0){
    list.innerHTML = '<li class="muted">No notes yet.</li>';
    return;
  }

  list.innerHTML = vaultNotes.map(note => `
    <li>
      <div class="note-head">
        <strong>${esc(note.title)}</strong>
        <div class="note-actions">
          <button data-act="show" data-id="${esc(note.id)}">Show</button>
          <button data-act="del"  data-id="${esc(note.id)}">Delete</button>
        </div>
      </div>
      <pre class="note-body hidden">${esc(note.body)}</pre>
    </li>
  `).join('');
}

$('#vaultUnlockBtn').addEventListener('click', async () => {
  const pw  = $('#masterPw').value;
  const msg = $('#vaultMsg');
  msg.textContent = '';
  msg.className = 'msg';

  if(pw.length < 8){
    msg.textContent = 'Master password must be at least 8 characters.';
    msg.classList.add('err');
    return;
  }

  try{
    if(vaultExists()){
      await unlockVault(pw);
      toast('Vault unlocked');
    }else{
      const pw2 = $('#masterPw2').value;
      if(pw !== pw2){
        msg.textContent = 'Passwords do not match.';
        msg.classList.add('err');
        return;
      }
      await createVault(pw);
      toast('Vault created & unlocked');
    }

    $('#masterPw').value = '';
    $('#masterPw2').value = '';
    showVaultApp();
    refreshDashboard();
  }catch(e){
    msg.textContent = e.message || 'Could not unlock vault.';
    msg.classList.add('err');
    vaultKey = null;
  }
});

$('#vaultLockBtn').addEventListener('click', () => {
  vaultKey = null;
  vaultNotes = [];
  hideVaultApp();
  updateVaultUI();
  toast('Vault locked');
});

$('#noteSave').addEventListener('click', async () => {
  if(!vaultKey){
    toast('Unlock the vault first');
    return;
  }

  const title = $('#noteTitle').value.trim() || 'Untitled';
  const body  = $('#noteBody').value;

  if(!body.trim()){
    toast('Secret content is empty');
    return;
  }

  const id = (crypto.randomUUID)
    ? crypto.randomUUID()
    : String(Date.now()) + '-' + Math.random().toString(36).slice(2);

  vaultNotes.push({ id, title, body, createdAt: Date.now() });

  await saveNotes();

  $('#noteTitle').value = '';
  $('#noteBody').value  = '';
  renderNotes();
  toast('Note encrypted & saved');
});

$('#noteList').addEventListener('click', async e => {
  const btn = e.target.closest('button[data-act]');
  if(!btn) return;

  const id = btn.dataset.id;

  if(btn.dataset.act === 'del'){
    vaultNotes = vaultNotes.filter(n => n.id !== id);
    await saveNotes();
    renderNotes();
    toast('Note deleted');
  }

  if(btn.dataset.act === 'show'){
    const pre = btn.closest('li').querySelector('.note-body');
    pre.classList.toggle('hidden');
    btn.textContent = pre.classList.contains('hidden') ? 'Show' : 'Hide';
  }
});

/* =========================================================
   CHECKLIST
   ========================================================= */
const CHECK_ITEMS = [
  { id:'manager',  text:'Use a password manager for all accounts' },
  { id:'unique',   text:'Use a unique password for every account' },
  { id:'2fa-mail', text:'Enable two-factor authentication on email' },
  { id:'2fa-bank', text:'Enable two-factor authentication on banking' },
  { id:'updates',  text:'Keep your OS and apps updated' },
  { id:'vpn',      text:'Use a VPN on public Wi-Fi' },
  { id:'disk',     text:'Encrypt your device disk (BitLocker / FileVault / LUKS)' },
  { id:'perms',    text:'Review app permissions on phone and browser' },
  { id:'backup',   text:'Keep regular offline backups of important data' },
  { id:'breach',   text:'Check your email against known data breaches' }
];

function loadChecklist(){
  try{
    return JSON.parse(localStorage.getItem(CHECK_KEY)) || {};
  }catch(e){
    return {};
  }
}

function renderChecklist(){
  const state = loadChecklist();
  const ul = $('#checkList');

  ul.innerHTML = CHECK_ITEMS.map(item => `
    <li>
      <label class="check">
        <input type="checkbox" data-id="${item.id}" ${state[item.id] ? 'checked' : ''}>
        <span>${item.text}</span>
      </label>
    </li>
  `).join('');

  ul.querySelectorAll('input[type=checkbox]').forEach(cb => {
    cb.addEventListener('change', () => {
      const s = loadChecklist();
      s[cb.dataset.id] = cb.checked;
      localStorage.setItem(CHECK_KEY, JSON.stringify(s));
      refreshDashboard();
    });
  });
}

/* =========================================================
   DASHBOARD / GLOBAL SCORE
   ========================================================= */
function renderTips(checkedCount, pwScore){
  const tips = [];
  const total = CHECK_ITEMS.length;

  if(!vaultExists()){
    tips.push('Create the encrypted vault — worth 30 points.');
  }
  if(checkedCount < total){
    tips.push('Complete the security checklist (' + (total - checkedCount) + ' remaining).');
  }
  if(pwScore < 70){
    tips.push('Test a password in the Analyzer and aim for 70+.');
  }
  if(!loadProfile().avatar){
    tips.push('Personalise your profile in Settings (photo + name).');
  }
  if(tips.length === 0){
    tips.push('Everything looks good. Re-check your security monthly.');
  }

  $('#tipsList').innerHTML = tips.map(t => '<li>' + t + '</li>').join('');
}

function refreshDashboard(){
  const state = loadChecklist();
  const checkedCount = CHECK_ITEMS.filter(i => state[i.id]).length;
  const total = CHECK_ITEMS.length;

  const pwScore = Number(localStorage.getItem(PWSCORE_KEY) || 0);
  const vault   = vaultExists();

  const globalScore = Math.round(
    (checkedCount / total) * 40 +
    (pwScore / 100) * 30 +
    (vault ? 30 : 0)
  );

  $('#statChecklist').textContent = checkedCount + ' / ' + total;
  $('#statPassword').textContent  = pwScore ? pwScore + ' / 100' : '—';
  $('#statVault').textContent     = vault ? 'Created' : 'Not created';

  $('#scoreValue').textContent  = globalScore;
  $('#headerScore').textContent = globalScore;
  $('#scoreRing').style.setProperty('--p', globalScore);

  $('#scoreHint').textContent =
    globalScore >= 80 ? 'Excellent — your local security posture is strong.' :
    globalScore >= 50 ? 'Good progress. Finish the remaining actions.' :
                        'Start with the checklist and create your vault.';

  renderTips(checkedCount, pwScore);
}

/* =========================================================
   INIT
   ========================================================= */
function init(){
  applyProfile();
  updateVaultUI();
  renderChecklist();
  resetAnalyzer();
  refreshDashboard();
}

init();

/* =========================================================
   PWA: service worker + install button
   ========================================================= */
if('serviceWorker' in navigator){
  window.addEventListener('load', () => navigator.serviceWorker.register('sw.js').catch(() => {}));
}
let deferredInstall = null;
window.addEventListener('beforeinstallprompt', e => {
  e.preventDefault();
  deferredInstall = e;
  $('#installBtn').classList.remove('hidden');
});
$('#installBtn').addEventListener('click', async () => {
  if(!deferredInstall) return;
  deferredInstall.prompt();
  await deferredInstall.userChoice;
  deferredInstall = null;
  $('#installBtn').classList.add('hidden');
});
window.addEventListener('appinstalled', () => toast('App installed'));

