require('dotenv').config();
const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const rateLimit = require('express-rate-limit');
const Anthropic = require('@anthropic-ai/sdk');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'dev_secret_change_in_production';
const FREE_MESSAGES = parseInt(process.env.FREE_MESSAGES_PER_MONTH || '10');

const USERS = {};
const SESSIONS = {};

app.use(cors({ origin: '*', methods: ['GET', 'POST', 'OPTIONS'], allowedHeaders: ['Content-Type', 'Authorization'] }));
app.use(express.json({ limit: '10kb' }));

const globalLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 100, message: { error: 'Trop de requetes.' } });
app.use(globalLimiter);

const chatLimiter = rateLimit({ windowMs: 60 * 1000, max: 10, message: { error: 'Attends 1 minute.' } });

function monthKey() { const d = new Date(); return d.getFullYear() + '-' + (d.getMonth() + 1); }
function generateId() { return Math.random().toString(36).substring(2) + Date.now().toString(36); }

function authMiddleware(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith('Bearer ')) return res.status(401).json({ error: 'Token manquant' });
  const token = auth.substring(7);
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    const user = USERS[payload.email];
    if (!user) return res.status(401).json({ error: 'Utilisateur introuvable' });
    req.user = user;
    next();
  } catch (e) { return res.status(401).json({ error: 'Token invalide' }); }
}

app.post('/auth/register', async (req, res) => {
  const { email, password, prenom } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email et mot de passe requis' });
  if (password.length < 6) return res.status(400).json({ error: 'Mot de passe trop court' });
  if (USERS[email]) return res.status(409).json({ error: 'Cet email est deja utilise' });
  const passwordHash = await bcrypt.hash(password, 10);
  const user = { id: generateId(), email, prenom: prenom || '', passwordHash, plan: 'free', messagesThisMonth: 0, monthKey: monthKey(), createdAt: new Date().toISOString() };
  USERS[email] = user;
  const token = jwt.sign({ email, id: user.id }, JWT_SECRET, { expiresIn: '30d' });
  res.json({ token, user: { email, prenom: user.prenom, plan: user.plan, messagesLeft​​​​​​​​​​​​​​​​
