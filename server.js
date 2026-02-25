// ============================================================
// IRONAI BACKEND — server.js
// Node.js + Express — proxy Anthropic API + auth utilisateurs
// ============================================================

require(‘dotenv’).config();
const express = require(‘express’);
const cors = require(‘cors’);
const jwt = require(‘jsonwebtoken’);
const bcrypt = require(‘bcryptjs’);
const rateLimit = require(‘express-rate-limit’);
const Anthropic = require(’@anthropic-ai/sdk’);

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || ‘dev_secret_change_in_production’;
const FREE_MESSAGES = parseInt(process.env.FREE_MESSAGES_PER_MONTH || ‘10’);

// ============================================================
// BASE DE DONNÉES EN MÉMOIRE (à remplacer par SQLite/PostgreSQL)
// Pour le lancement, suffisant pour tester et valider le concept
// ============================================================
const USERS = {};      // { email: { id, email, passwordHash, plan, messagesThisMonth, monthKey } }
const SESSIONS = {};   // { token: { userId, createdAt } }

// ============================================================
// MIDDLEWARE
// ============================================================
app.use(cors({
origin: ‘*’, // En production, mettre ton domaine exact
methods: [‘GET’, ‘POST’, ‘OPTIONS’],
allowedHeaders: [‘Content-Type’, ‘Authorization’]
}));
app.use(express.json({ limit: ‘10kb’ }));

// Rate limiter global — protection anti-abus
const globalLimiter = rateLimit({
windowMs: 15 * 60 * 1000, // 15 minutes
max: 100,
message: { error: ‘Trop de requetes. Reessaie dans 15 minutes.’ }
});
app.use(globalLimiter);

// Rate limiter strict pour le chat (evite les abus API)
const chatLimiter = rateLimit({
windowMs: 60 * 1000, // 1 minute
max: 10,
message: { error: ‘Trop de messages. Attends 1 minute.’ }
});

// ============================================================
// UTILITAIRES
// ============================================================
function monthKey() {
const d = new Date();
return `${d.getFullYear()}-${d.getMonth() + 1}`;
}

function generateId() {
return Math.random().toString(36).substring(2) + Date.now().toString(36);
}

function authMiddleware(req, res, next) {
const auth = req.headers.authorization;
if (!auth || !auth.startsWith(’Bearer ’)) {
return res.status(401).json({ error: ‘Token manquant’ });
}
const token = auth.substring(7);
try {
const payload = jwt.verify(token, JWT_SECRET);
const user = USERS[payload.email];
if (!user) return res.status(401).json({ error: ‘Utilisateur introuvable’ });
req.user = user;
next();
} catch (e) {
return res.status(401).json({ error: ‘Token invalide ou expire’ });
}
}

// ============================================================
// ROUTES AUTH
// ============================================================

// POST /auth/register — Inscription
app.post(’/auth/register’, async (req, res) => {
const { email, password, prenom } = req.body;

if (!email || !password) {
return res.status(400).json({ error: ‘Email et mot de passe requis’ });
}
if (password.length < 6) {
return res.status(400).json({ error: ‘Mot de passe trop court (min 6 caracteres)’ });
}
if (USERS[email]) {
return res.status(409).json({ error: ‘Cet email est deja utilise’ });
}

const passwordHash = await bcrypt.hash(password, 10);
const user = {
id: generateId(),
email,
prenom: prenom || ‘’,
passwordHash,
plan: ‘free’,            // ‘free’ ou ‘premium’
messagesThisMonth: 0,
monthKey: monthKey(),
createdAt: new Date().toISOString()
};
USERS[email] = user;

const token = jwt.sign({ email, id: user.id }, JWT_SECRET, { expiresIn: ‘30d’ });
console.log(`[REGISTER] ${email} (${prenom})`);

res.json({
token,
user: { email, prenom: user.prenom, plan: user.plan, messagesLeft: FREE_MESSAGES }
});
});

// POST /auth/login — Connexion
app.post(’/auth/login’, async (req, res) => {
const { email, password } = req.body;
const user = USERS[email];

if (!user) return res.status(401).json({ error: ‘Email ou mot de passe incorrect’ });

const valid = await bcrypt.compare(password, user.passwordHash);
if (!valid) return res.status(401).json({ error: ‘Email ou mot de passe incorrect’ });

const token = jwt.sign({ email, id: user.id }, JWT_SECRET, { expiresIn: ‘30d’ });
console.log(`[LOGIN] ${email}`);

// Reset compteur si nouveau mois
if (user.monthKey !== monthKey()) {
user.messagesThisMonth = 0;
user.monthKey = monthKey();
}

const messagesLeft = user.plan === ‘premium’
? 999
: Math.max(0, FREE_MESSAGES - user.messagesThisMonth);

res.json({
token,
user: { email, prenom: user.prenom, plan: user.plan, messagesLeft }
});
});

// GET /auth/me — Infos utilisateur connecte
app.get(’/auth/me’, authMiddleware, (req, res) => {
const user = req.user;
if (user.monthKey !== monthKey()) {
user.messagesThisMonth = 0;
user.monthKey = monthKey();
}
const messagesLeft = user.plan === ‘premium’
? 999
: Math.max(0, FREE_MESSAGES - user.messagesThisMonth);

res.json({
email: user.email,
prenom: user.prenom,
plan: user.plan,
messagesLeft
});
});

// ============================================================
// ROUTE COACH IA — Proxy Anthropic
// ============================================================

// POST /coach/chat — Envoie un message au coach IA
app.post(’/coach/chat’, authMiddleware, chatLimiter, async (req, res) => {
const user = req.user;

// Reset compteur si nouveau mois
if (user.monthKey !== monthKey()) {
user.messagesThisMonth = 0;
user.monthKey = monthKey();
}

// Verifier quota pour les utilisateurs gratuits
if (user.plan === ‘free’ && user.messagesThisMonth >= FREE_MESSAGES) {
return res.status(402).json({
error: ‘quota_exceeded’,
message: `Tu as utilise tes ${FREE_MESSAGES} messages gratuits ce mois-ci. Passe en Premium pour continuer.`,
messagesLeft: 0
});
}

const { messages, systemPrompt } = req.body;

if (!messages || !Array.isArray(messages) || messages.length === 0) {
return res.status(400).json({ error: ‘Messages requis’ });
}

// Verifier que les messages sont valides (securite)
const cleanMessages = messages.slice(-10).map(m => ({
role: m.role === ‘assistant’ ? ‘assistant’ : ‘user’,
content: String(m.content).substring(0, 2000) // Limite la taille
}));

try {
const client = new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY });

```
const response = await client.messages.create({
  model: 'claude-opus-4-6',
  max_tokens: 600,
  system: systemPrompt || 'Tu es IronCoach, coach IA expert en musculation. Reponds en francais.',
  messages: cleanMessages
});

const text = response.content[0]?.text || '';

// Incrementer le compteur de messages
user.messagesThisMonth++;

const messagesLeft = user.plan === 'premium'
  ? 999
  : Math.max(0, FREE_MESSAGES - user.messagesThisMonth);

console.log(`[CHAT] ${user.email} | plan:${user.plan} | msgs:${user.messagesThisMonth}/${FREE_MESSAGES}`);

res.json({ text, messagesLeft });
```

} catch (err) {
console.error(’[CHAT ERROR]’, err.message);
res.status(500).json({ error: ‘Erreur serveur. Reessaie.’ });
}
});

// ============================================================
// ROUTE ADMIN (TOI UNIQUEMENT) — Acces avec mot de passe admin
// ============================================================

// GET /admin/users — Liste des utilisateurs
app.get(’/admin/users’, (req, res) => {
const adminKey = req.headers[‘x-admin-key’];
if (adminKey !== process.env.ADMIN_KEY) {
return res.status(403).json({ error: ‘Acces refuse’ });
}

const users = Object.values(USERS).map(u => ({
id: u.id,
email: u.email,
prenom: u.prenom,
plan: u.plan,
messagesThisMonth: u.messagesThisMonth,
createdAt: u.createdAt
}));

res.json({ total: users.length, users });
});

// POST /admin/upgrade — Passe un user en premium
app.post(’/admin/upgrade’, (req, res) => {
const adminKey = req.headers[‘x-admin-key’];
if (adminKey !== process.env.ADMIN_KEY) {
return res.status(403).json({ error: ‘Acces refuse’ });
}

const { email, plan } = req.body;
if (!USERS[email]) return res.status(404).json({ error: ‘Utilisateur introuvable’ });

USERS[email].plan = plan || ‘premium’;
console.log(`[ADMIN] ${email} passe en ${plan || 'premium'}`);
res.json({ success: true, email, plan: USERS[email].plan });
});

// ============================================================
// HEALTHCHECK
// ============================================================
app.get(’/’, (req, res) => {
res.json({
status: ‘ok’,
app: ‘IronAI Backend’,
version: ‘1.0.0’,
users: Object.keys(USERS).length
});
});

// ============================================================
// DEMARRAGE
// ============================================================
app.listen(PORT, () => {
console.log(`\n🏋️  IronAI Backend running on port ${PORT}`);
console.log(`📡  Environnement: ${process.env.NODE_ENV || 'development'}`);
console.log(`🆓  Messages gratuits/mois: ${FREE_MESSAGES}`);
console.log(`🔑  Cle Anthropic: ${process.env.ANTHROPIC_API_KEY ? 'OK ✓' : 'MANQUANTE ✗'}\n`);
});
