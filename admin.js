// ============================================================
//  admin.js — Auth + Writeup CRUD for Castro Nicholas Portfolio
//
//  HOW TO CHANGE YOUR PASSWORD:
//  1. Open browser console on any page
//  2. Run: hashPassword('your-new-password').then(h => console.log(h))
//  3. Copy the hash and replace ADMIN_HASH below
// ============================================================


const ADMIN_HASH = '8d1ea7ec54d18959f02a370f0fc7c85630285b8f2905a8f0fc2298ae578a2f4a';

// ── Hashing utility ──────────────────────────────────────────
async function hashPassword(pw) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(pw));
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
}

// ── Session state ─────────────────────────────────────────────
let adminLoggedIn = false;

async function attemptLogin(pw) {
  const hash = await hashPassword(pw);
  if (hash === ADMIN_HASH) {
    adminLoggedIn = true;
    sessionStorage.setItem('cn_admin', hash);
    return true;
  }
  return false;
}

function checkSession() {
  const stored = sessionStorage.getItem('cn_admin');
  if (stored === ADMIN_HASH) {
    adminLoggedIn = true;
  }
}

function adminLogout() {
  adminLoggedIn = false;
  sessionStorage.removeItem('cn_admin');
}

// ── Data layer ────────────────────────────────────────────────
// Priority: localStorage edits > writeups.js defaults
function getPosts() {
  const local = localStorage.getItem('cn_posts_v2');
  if (local) return JSON.parse(local);
  // Fall back to writeups.js
  return window.WRITEUPS ? [...window.WRITEUPS] : [];
}

function savePosts(posts) {
  localStorage.setItem('cn_posts_v2', JSON.stringify(posts));
}

function resetToDefaults() {
  localStorage.removeItem('cn_posts_v2');
}

// Export updated writeups.js content for the user to commit
function exportWriteupsJS(posts) {
  const json = JSON.stringify(posts, null, 2)
    .replace(/"body": "/g, 'body: `')
    .replace(/\\n/g, '\n')
    .replace(/\\`/g, '`')
    .replace(/",\n(\s+)(flag|id|platform|difficulty|date|title|category|tags|excerpt)/g, ',\n  $2');

  // Simpler approach: proper JS template
  const entries = posts.map(p => {
    const safe = { ...p };
    return `  {
    id: ${JSON.stringify(safe.id)},
    platform: ${JSON.stringify(safe.platform)},
    difficulty: ${JSON.stringify(safe.difficulty)},
    date: ${JSON.stringify(safe.date)},
    title: ${JSON.stringify(safe.title)},
    category: ${JSON.stringify(safe.category)},
    tags: ${JSON.stringify(safe.tags)},
    excerpt: ${JSON.stringify(safe.excerpt)},
    body: ${JSON.stringify(safe.body)},
    flag: ${JSON.stringify(safe.flag)}
  }`;
  }).join(',\n');

  const content = `// ============================================================
//  writeups.js — CTF Writeup Data
//  Auto-exported from admin panel on ${new Date().toISOString()}
// ============================================================

window.WRITEUPS = [\n${entries}\n];\n`;

  const blob = new Blob([content], { type: 'text/javascript' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = 'writeups.js';
  a.click();
  URL.revokeObjectURL(a.href);
}