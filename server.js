require('dotenv').config();
const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const Anthropic = require('@anthropic-ai/sdk');
const app = express();
const PORT = process.env.PORT || 8080;
const JWT_SECRET = 'IronAI_MonApp_Secret_2026_Perso';
const FREE_MESSAGES = 10;
const ANTHROPIC_KEY = process.env.ANTHROPIC_API_KEY;
const USERS = {};
app.use(cors({ origin: '*', methods: ['GET', 'POST', 'OPTIONS'], allowedHeaders: ['Content-Type', 'Authorization'] }));
app.use(express.json({ limit: '10kb' }));
function monthKey() { const d = new Date(); return d.getFullYear() + '-' + (d.getMonth() + 1); }
function generateId() { return Math.random().toString(36).substring(2) + Date.now().toString(36); }
function authMiddleware(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith('Bearer ')) return res.status(401).json({ error: 'Token manquant' });
  try {
    const payload = jwt.verify(auth.substring(7), JWT_SECRET);
    const user = USERS[payload.email];
    if (!user) return res.status(401).json({ error: 'Introuvable' });
    req.user = user;
    next();
  } catch (e) {
    return res.status(401).json({ error: 'Token invalide' });
  }
}
app.post('/auth/register', async function(req, res) {
  const email = req.body.email;
  const password = req.body.password;
  const prenom = req.body.prenom || '';
  if (!email || !password) return res.status(400).json({ error: 'Email et mot de passe requis' });
  if (password.length < 6) return res.status(400).json({ error: 'Mot de passe trop court' });
  if (USERS[email]) return res.status(409).json({ error: 'Email deja utilise' });
  const passwordHash = await bcrypt.hash(password, 10);
  USERS[email] = { id: generateId(), email: email, prenom: prenom, passwordHash: passwordHash, plan: 'free', messagesThisMonth: 0, monthKey: monthKey(), createdAt: new Date().toISOString() };
  const token = jwt.sign({ email: email }, JWT_SECRET, { expiresIn: '30d' });
  res.json({ token: token, user: { email: email, prenom: prenom, plan: 'free', messagesLeft: FREE_MESSAGES } });
});
app.post('/auth/login', async function(req, res) {
  const email = req.body.email;
  const password = req.body.password;
  const user = USERS[email];
  if (!user) return res.status(401).json({ error: 'Email ou mot de passe incorrect' });
  const valid = await bcrypt.compare(password, user.passwordHash);
  if (!valid) return res.status(401).json({ error: 'Email ou mot de passe incorrect' });
  if (user.monthKey !== monthKey()) { user.messagesThisMonth = 0; user.monthKey = monthKey(); }
  const token = jwt.sign({ email: email }, JWT_SECRET, { expiresIn: '30d' });
  const messagesLeft = user.plan === 'premium' ? 999 : Math.max(0, FREE_MESSAGES - user.messagesThisMonth);
  res.json({ token: token, user: { email: user.email, prenom: user.prenom, plan: user.plan, messagesLeft: messagesLeft } });
});
app.get('/auth/me', authMiddleware, function(req, res) {
  const user = req.user;
  if (user.monthKey !== monthKey()) { user.messagesThisMonth = 0; user.monthKey = monthKey(); }
  const messagesLeft = user.plan === 'premium' ? 999 : Math.max(0, FREE_MESSAGES - user.messagesThisMonth);
  res.json({ email: user.email, prenom: user.prenom, plan: user.plan, messagesLeft: messagesLeft });
});
app.post('/coach/chat', authMiddleware, async function(req, res) {
  const user = req.user;
  if (user.monthKey !== monthKey()) { user.messagesThisMonth = 0; user.monthKey = monthKey(); }
  if (user.plan === 'free' && user.messagesThisMonth >= FREE_MESSAGES) {
    return res.status(402).json({ error: 'quota_exceeded', message: 'Messages gratuits epuises.', messagesLeft: 0 });
  }
  const messages = req.body.messages;
  const systemPrompt = req.body.systemPrompt;
  if (!messages || !Array.isArray(messages)) return res.status(400).json({ error: 'Messages requis' });
  const cleanMessages = messages.slice(-10).map(function(m) {
    return { role: m.role === 'assistant' ? 'assistant' : 'user', content: String(m.content).substring(0, 2000) };
  });
  try {
    const client = new Anthropic({ apiKey: ANTHROPIC_KEY });
    const response = await client.messages.create({
      model: 'claude-opus-4-6',
      max_tokens: 600,
      system: systemPrompt || 'Tu es IronCoach, expert musculation. Reponds en francais.',
      messages: cleanMessages
    });
    user.messagesThisMonth++;
    const messagesLeft = user.plan === 'premium' ? 999 : Math.max(0, FREE_MESSAGES - user.messagesThisMonth);
    res.json({ text: response.content[0] ? response.content[0].text : '', messagesLeft: messagesLeft });
  } catch (err) {
    res.status(500).json({ error: 'Erreur serveur.' });
  }
});
app.get('/', function(req, res) {
  res.json({ status: 'ok', app: 'IronAI Backend', users: Object.keys(USERS).length });
});
app.listen(PORT, function() {
  console.log('IronAI Backend running on port ' + PORT);
});
