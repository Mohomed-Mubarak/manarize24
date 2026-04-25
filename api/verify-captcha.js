/* ============================================================
   ZENMARKET — hCaptcha Server Verification  (Vercel Serverless)
   ============================================================
   Endpoint: POST /api/verify-captcha
   Body:     { token: "<hcaptcha-response-token>", action?: string }
   Returns:  { success: true } | { success: false, error: string }

   Requires env var: HCAPTCHA_SECRET  (never expose in browser)
   ============================================================ */

// In-memory rate limiter (per IP, resets on cold start)
const _rl = new Map(); // ip → { count, resetAt }
const RL_WINDOW_MS = 60_000; // 1 minute
const RL_MAX       = 20;     // 20 verifications per IP per minute

function checkRateLimit(ip) {
  const now  = Date.now();
  const entry = _rl.get(ip) || { count: 0, resetAt: now + RL_WINDOW_MS };
  if (now > entry.resetAt) { entry.count = 0; entry.resetAt = now + RL_WINDOW_MS; }
  entry.count++;
  _rl.set(ip, entry);
  return entry.count > RL_MAX;
}

async function readJson(req) {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', c => { body += c; });
    req.on('end', () => {
      try { resolve(JSON.parse(body || '{}')); }
      catch { reject(new Error('Invalid JSON')); }
    });
    req.on('error', reject);
  });
}

module.exports = async function handler(req, res) {
  const origin = process.env.SITE_URL || null;
  if (origin) res.setHeader('Access-Control-Allow-Origin', origin);
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') return res.status(204).end();
  if (req.method !== 'POST')   return res.status(405).json({ error: 'Method not allowed' });

  const ip = (req.headers['x-forwarded-for'] || '127.0.0.1').split(',')[0].trim();
  if (checkRateLimit(ip)) {
    return res.status(429).json({ success: false, error: 'Too many requests' });
  }

  let body;
  try { body = await readJson(req); }
  catch { return res.status(400).json({ success: false, error: 'Invalid request body' }); }

  const token = typeof body.token === 'string' ? body.token.trim() : '';
  if (!token) return res.status(400).json({ success: false, error: 'Missing captcha token' });

  const secret = process.env.HCAPTCHA_SECRET;
  if (!secret) {
    console.error('[verify-captcha] HCAPTCHA_SECRET env var not set');
    // Fail-closed: if secret is missing, reject the request
    return res.status(503).json({ success: false, error: 'Captcha service not configured' });
  }

  try {
    const params = new URLSearchParams({ secret, response: token });
    // Optional: include remoteip for extra validation
    if (ip && ip !== '127.0.0.1') params.set('remoteip', ip);

    const hcRes = await fetch('https://hcaptcha.com/siteverify', {
      method:  'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body:    params.toString(),
    });

    if (!hcRes.ok) {
      console.error('[verify-captcha] hCaptcha API error:', hcRes.status);
      return res.status(502).json({ success: false, error: 'Captcha service unavailable' });
    }

    const data = await hcRes.json();

    if (!data.success) {
      const codes = data['error-codes'] || [];
      console.warn('[verify-captcha] Verification failed:', codes);
      return res.status(400).json({ success: false, error: 'Captcha verification failed' });
    }

    return res.status(200).json({ success: true });

  } catch (err) {
    console.error('[verify-captcha] Unexpected error:', err.message);
    return res.status(500).json({ success: false, error: 'Internal server error' });
  }
};
