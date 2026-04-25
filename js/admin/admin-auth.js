/* ============================================================
   ZENMARKET — ADMIN AUTH  (v3 — Magic Link + sessionStorage)
   ============================================================
   Auth strategy:
   ┌─ Hardcoded ADMIN_EMAIL (env / demo mode)
   │   └─ hash-based password check → direct session
   │
   └─ Supabase users with profiles.role = 'admin'
       1. signInWithPassword  → verify credentials
       2. check profiles.role = 'admin' + active = true
       3. signInWithOtp (magic link) → email redirect to /admin/dashboard.html
       4. handleMagicLinkCallback → verify role → grant sessionStorage session

   Session storage: sessionStorage (auto-clears on window close/tab kill)
   ============================================================ */
import { LS, ADMIN_EMAIL, ADMIN_PASSWORD } from '../config.js';
import { setAdminToken, clearAdminToken } from '../admin-api.js';
import {
  hashPassword, verifyPassword,
  checkBruteForce, recordFailedAttempt, clearFailedAttempts,
} from '../security-utils.js';
import { getSupabase } from '../supabase.js';

const PW_KEY = 'zm_admin_password_hash';

// ── Legacy password hash (env-admin only) ─────────────────────
async function getActivePasswordHash() {
  try {
    const res = await fetch('/api/admin/config?key=password_hash');
    if (res.ok) {
      const { value } = await res.json();
      if (value) { sessionStorage.setItem(PW_KEY, value); return value; }
    }
  } catch { /* offline */ }

  try {
    const cached = sessionStorage.getItem(PW_KEY);
    if (cached) return cached;
    if (!ADMIN_PASSWORD) return null;
    const h = await hashPassword(ADMIN_PASSWORD);
    sessionStorage.setItem(PW_KEY, h);
    return h;
  } catch { return null; }
}

const SESSION_TTL_MS = 8 * 60 * 60 * 1000; // 8 hours

// ── Session helpers ───────────────────────────────────────────
export function requireAdmin() {
  const session = getAdminSession();
  if (!session) {
    const base = window.location.pathname.includes('/admin/') ? '' : 'admin/';
    window.location.href = base;
    return null;
  }
  if (session.loginAt && (Date.now() - session.loginAt > SESSION_TTL_MS)) {
    adminLogout();
    return null;
  }
  return session;
}

export function getAdminSession() {
  // sessionStorage: auto-cleared when browser window/tab is closed
  try { return JSON.parse(sessionStorage.getItem(LS.adminSession) || 'null'); }
  catch { return null; }
}

// ── Login (Step 1 — email + password) ─────────────────────────
export async function adminLogin(email, password) {
  const lockout = checkBruteForce();
  if (lockout) return { success: false, error: lockout };

  // ── A) Legacy env-admin ───────────────────────────────────────
  if (email === ADMIN_EMAIL) {
    const activeHash = await getActivePasswordHash();
    const { match } = await verifyPassword(password, activeHash);
    if (!match) {
      recordFailedAttempt();
      return { success: false, error: 'Invalid credentials' };
    }
    clearFailedAttempts();
    const session = { email, role: 'admin', name: 'Admin User', loginAt: Date.now() };
    sessionStorage.setItem(LS.adminSession, JSON.stringify(session));
    // Token not set client-side — ADMIN_API_TOKEN is server-only.
    return { success: true, session };
  }

  // ── B) Supabase multi-admin with magic link ───────────────────
  const sb = getSupabase();
  if (!sb) {
    recordFailedAttempt();
    return { success: false, error: 'Invalid credentials' };
  }

  // Step 1: verify password via Supabase Auth
  const { data: authData, error: authError } = await sb.auth.signInWithPassword({ email, password });
  if (authError || !authData?.user) {
    recordFailedAttempt();
    return { success: false, error: 'Invalid credentials' };
  }

  // Step 2: confirm admin role in profiles table
  const { data: profile, error: profileError } = await sb
    .from('profiles')
    .select('role, name, active')
    .eq('id', authData.user.id)
    .single();

  if (profileError || !profile) {
    await sb.auth.signOut();
    recordFailedAttempt();
    return { success: false, error: 'Invalid credentials' };
  }

  if (profile.role !== 'admin') {
    await sb.auth.signOut();
    recordFailedAttempt();
    return { success: false, error: 'Access denied. Admin privileges required.' };
  }

  if (profile.active === false) {
    await sb.auth.signOut();
    return { success: false, error: 'This account has been suspended.' };
  }

  // Step 3: sign out password session, then send magic link
  await sb.auth.signOut();

  const redirectTo = `${window.location.origin}/admin/dashboard.html`;
  const { error: magicError } = await sb.auth.signInWithOtp({
    email,
    options: {
      shouldCreateUser: false,
      emailRedirectTo: redirectTo,
    },
  });

  if (magicError) {
    console.error('[AdminAuth] Magic link send error:', magicError);
    return { success: false, error: 'Failed to send magic link. Try again.' };
  }

  clearFailedAttempts();
  return { success: true, magicLinkPending: true, email, name: profile.name || email.split('@')[0] };
}

// ── Magic Link Callback (called on dashboard.html load) ───────
// Processes the Supabase hash fragment set by the magic link redirect.
// Returns true if a valid admin session was established.
export async function handleMagicLinkCallback() {
  const hash = window.location.hash;
  if (!hash || !hash.includes('access_token')) return false;

  const sb = getSupabase();
  if (!sb) return false;

  // Supabase v2 auto-detects the hash — wait for SIGNED_IN event
  return new Promise((resolve) => {
    let resolved = false;
    const done = (val) => {
      if (resolved) return;
      resolved = true;
      resolve(val);
    };

    // Timeout fallback — 6 seconds
    const timer = setTimeout(() => done(false), 6000);

    const { data: { subscription } } = sb.auth.onAuthStateChange(async (event, session) => {
      if (event !== 'SIGNED_IN') return;
      subscription.unsubscribe();
      clearTimeout(timer);

      if (!session?.user) { done(false); return; }

      // Re-verify admin role (defense in depth)
      const { data: profile } = await sb
        .from('profiles')
        .select('role, name, active')
        .eq('id', session.user.id)
        .single();

      if (!profile || profile.role !== 'admin' || profile.active === false) {
        await sb.auth.signOut();
        window.location.href = '/';
        done(false);
        return;
      }

      // Grant admin session in sessionStorage
      const adminSession = {
        email:      session.user.email,
        role:       'admin',
        name:       profile.name || session.user.email.split('@')[0],
        supabaseId: session.user.id,
        loginAt:    Date.now(),
      };
      sessionStorage.setItem(LS.adminSession, JSON.stringify(adminSession));
      // Token not set client-side — ADMIN_API_TOKEN is server-only.

      // Clean URL — remove hash so back/reload won't re-trigger
      history.replaceState(null, '', window.location.pathname + window.location.search);

      done(true);
    });
  });
}

// ── Logout ────────────────────────────────────────────────────
export function adminLogout() {
  try { const sb = getSupabase(); if (sb) sb.auth.signOut(); } catch { /* noop */ }
  sessionStorage.removeItem(LS.adminSession);
  clearAdminToken();
  const base = window.location.pathname.includes('/admin/') ? '' : 'admin/';
  window.location.href = base;
}

// ── Change password (legacy admin only) ──────────────────────
export async function changeAdminPassword(currentPw, newPw) {
  if (!currentPw || !newPw) return { success: false, error: 'All fields are required.' };
  if (newPw.length < 8)     return { success: false, error: 'New password must be at least 8 characters.' };
  if (newPw === currentPw)  return { success: false, error: 'New password must be different from current.' };

  const activeHash = await getActivePasswordHash();
  const { match } = await verifyPassword(currentPw, activeHash);
  if (!match) return { success: false, error: 'Current password is incorrect.' };

  const newHash = await hashPassword(newPw);
  try {
    const res = await fetch('/api/admin/config', {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ key: 'password_hash', currentPassword: currentPw, newValue: newHash }),
    });
    const json = await res.json().catch(() => ({}));
    if (!res.ok && res.status !== 0 && res.status < 500) {
      return { success: false, error: json.error || 'Failed to save password.' };
    }
  } catch {
    console.warn('[ZenMarket] Admin config API unavailable — saving to localStorage only.');
  }

  sessionStorage.setItem(PW_KEY, newHash);
  sessionStorage.removeItem(LS.adminSession);
  clearAdminToken();
  return { success: true };
}
