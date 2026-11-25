// Vercel serverless function. Set these Environment Variables in Vercel:
//   APP_USER, APP_PASS, AUTH_SECRET (any long random string)
const crypto = require('crypto');
const sign = (p) => crypto.createHmac('sha256', process.env.AUTH_SECRET).update(p).digest('hex');
const eq = (a, b) => {
  const x = Buffer.from(String(a)), y = Buffer.from(String(b));
  return x.length === y.length && crypto.timingSafeEqual(x, y);
};

module.exports = (req, res) => {
  const { APP_USER, APP_PASS, AUTH_SECRET } = process.env;
  if (!APP_USER || !APP_PASS || !AUTH_SECRET) return res.status(500).json({ error: 'not configured' });

  if (req.method === 'POST') {
    const { u, p } = req.body || {};
    if (typeof u === 'string' && typeof p === 'string' && eq(u, APP_USER) && eq(p, APP_PASS)) {
      const exp = String(Date.now() + 12 * 3600 * 1000);
      return res.status(200).json({ token: exp + '.' + sign(exp) });
    }
    return res.status(401).json({ error: 'invalid' });
  }

  const t = (req.headers.authorization || '').replace('Bearer ', '');
  const [exp, sig] = t.split('.');
  if (exp && sig && Number(exp) > Date.now() && eq(sig, sign(exp))) return res.status(200).json({ ok: true });
  return res.status(401).json({ error: 'auth' });
};
