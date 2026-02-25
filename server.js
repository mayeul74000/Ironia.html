require('dotenv').config();
const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const rateLimit = require('express-rate-limit');
const Anthropic = require('@anthropic-ai/sdk');
const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'dev_secret';
const FREE_MESSAGES = parseInt(process.env.FREE_MESSAGES_PER_MONTH || '10');
const USERS = {};
app.use(cors({ origin: '*', methods: ['GET', 'POST', 'OPTIONS'], allowedHeaders: ['Content-Type', 'Authorization'] }));
app.use(express.json({ limit: '10kb' }));
const globalLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 100 });
app.use(globalLimiter);
const chatLimiter = rateLimit({ windowMs: 60 * 1000, max: 10 });
function monthKey() { const d = new Date(); return d.getFullYear() + '-' + (d.getMonth() + 1); }
function generateId() { return Math.random().toString(36).substring(2) + Date.now().toString(36); }
function authMiddleware(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith('Bearer ')) return res.status(401).json({ error: 'Token manquant' });
  try {
    const payload = jwt.verify(auth.substring(7), JWT_SECRET);
    const user = USERS[payload.email];
    if (!user) return res.status(401).json({ error: 'Introuvable' });
    req.user = user; next();
  } catch (e) { return res.status(401).json({ error: 'Token invalide' }); }
}
app.post('/auth/register', async (req, res) => {
  const { email, password, prenom } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email et mot de passe requis' });
  if (password.length < 6) return res.status(400).json({ error: 'Mot de passe trop court' });
  if (USERS[email]) return res.status(409).json({ error: 'Email deja utilise' });
  const passwordHash = await bcrypt.hash(password, 10);
  USERS[email] = { id: generateId(), email, prenom: prenom || '', passwordHash, plan: 'free', messagesThisMonth: 0, monthKey: monthKey(), createdAt: new Date().toISOString() };
  const token = jwt.sign({ email }, JWT_SECRET, { expiresIn: '30d' });
  res.json({ token, user: { email, prenom: prenom || '', plan: 'free', messagesLeft: FREE_MESSAGES } });
});
app.post('/auth/login', async (req, res) => {
  const { email, password } = req.body;
  const user = USERS[email];
  if (!user) return res.status(401).json({ error: 'Email ou mot de passe incorrect' });
  if (!await bcrypt.compare(password, user.passwordHash)) return res.status(401).json({ error: 'Email ou mot de passe incorrect' });
  if (user.monthKey !== monthKey()) { user.messagesThisMonth = 0; user.monthKey = monthKey(); }
  const token = jwt.sign({ email }, JWT_SECRET, { expiresIn: '30d' });
  const messagesLeft = user.plan === 'premium' ? 999 : Math.max(0, FREE_MESSAGES - user.messagesThisMonth);
  res.json({ token, user: { email, prenom: user.prenom, plan: user.plan, messagesLeft } });
});
app.get('/auth/me', authMiddleware, (req, res) => {
  const user = req.user;
  if (user.monthKey !== monthKey()) { user.messagesThisMonth = 0; user.monthKey = monthKey(); }
  const messagesLeft = user.plan === 'premium' ? 999 : Math.max(0, FREE_MESSAGES - user.messagesThisMonth);
  res.json({ email: user.email, prenom: user.prenom, plan: user.plan, messagesLeft });
});
app.post('/coach/chat', authMiddleware, chatLimiter, async (req, res) => {
  const user = req.user;
  if (user.monthKey !== monthKey()) { user.messagesThisMonth = 0; user.monthKey = monthKey(); }
  if (user.plan === 'free' && user.messagesThisMonth >= FREE_MESSAGES) {
    return res.status(402).json({ error: 'quota_exceeded', message: 'Messages gratuits epuises.', messagesLeft: 0 });
  }
  const { messages, systemPrompt } = req.body;
  if (!messages || !Array.isArray(messages)) return res.status(400).json({ error: 'Messages requis' });
  const cleanMessages = messages.slice(-10).map(m => ({ role: m.role === 'assistant' ? 'assistant' : 'user', content: String(m.content).substring(0, 2000) }));
  try {
    const client = new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY });
    const response = await client.messages.create({ model: 'claude-opus-4-6', max_tokens: 600, system: systemPrompt || 'Tu es IronCoach, expert musculation. Reponds en francais.', messages: cleanMessages });
    user.messagesThisMonth++;
    const messagesLeft = user.plan === 'premium' ? 999 : Math.max(0, FREE_MESSAGES - user.messagesThisMonth);
    res.json({ text: response.content[0] ? response.content[0].text : '', messagesLeft });
  } catch (err) { res.status(500).json({ error: 'Erreur serveur.' }); }
});
app.get('/admin/users', (req, res) => {
  const k = req.headers['x-admin-key'];
  if (!k || k.length < 8) return res.status(403).json({ error: 'Acces refuse' });
  res.json({ total: Object.keys(USERS).length, users: Object.values(USERS).map(u => ({ email: u.email, plan: u.plan, msgs: u.messagesThisMonth })) });
});
app.post('/admin/upgrade', (req, res) => {
  const k = req.headers['x-admin-key'];
  if (!k || k.length < 8) return res.status(403).json({ error: 'Acces refuse' });
  const { email, plan } = req.body;
  if (!USERS[email]) return res.status(404).json({ error: 'Introuvable' });
  USERS[email].plan = plan || 'premium';
  res.json({ success: true });
});
app.get('/', (req, res) => { res.json({ status: 'ok', app: 'IronAI Backend', users: Object.keys(USERS).length }); });
app.listen(PORT, () => { console.log('IronAI Backend running on port ' + PORT); });
