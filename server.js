'use strict';

const express      = require('express');
const crypto       = require('crypto');
const cookieSession = require('cookie-session');
const path         = require('path');
const admin        = require('firebase-admin');
const multer       = require('multer');
const os           = require('os');

// ── Firebase ──────────────────────────────────────────────────────────────────
if (!admin.apps.length) {
  const cred = process.env.FIREBASE_SERVICE_ACCOUNT
    ? JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT)
    : (() => { try { return require('./serviceAccountKey.json'); } catch(e) { throw new Error('Configure FIREBASE_SERVICE_ACCOUNT'); } })();
  admin.initializeApp({ credential: admin.credential.cert(cred) });
}
const fdb = admin.firestore();

// ── Config ────────────────────────────────────────────────────────────────────
const app    = express();
const PORT   = process.env.PORT || 3000;
let ACCESS_PASSWORD = process.env.ACCESS_PASSWORD || 'rmhacking2024';
const SESSION_SECRET = process.env.SESSION_SECRET || 'rmhacking-secret-xyz-2024';

// ── Helpers ───────────────────────────────────────────────────────────────────
function now() { return new Date().toISOString().replace('T',' ').substring(0,19); }

async function nextInvId() {
  const snap = await fdb.collection('investigations').get();
  let max = 0;
  snap.forEach(d => { const n = d.data().id||0; if (n>max) max=n; });
  return max + 1;
}

async function nextItemId(col, invId) {
  const snap = await fdb.collection(col).where('investigation_id','==',Number(invId)).get();
  let max = 0;
  snap.forEach(d => { const n = d.data().id||0; if (n>max) max=n; });
  return max + 1;
}

async function nextWlId() {
  const snap = await fdb.collection('watchlist').get();
  let max = 0;
  snap.forEach(d => { const n = d.data().id||0; if (n>max) max=n; });
  return max + 1;
}

// ── Senha segura (PBKDF2) ─────────────────────────────────────────────────────
function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.pbkdf2Sync(password, salt, 10000, 64, 'sha512').toString('hex');
  return salt + ':' + hash;
}
function verifyPassword(password, stored) {
  if (!stored || !stored.includes(':')) return password === stored; // legado
  const [salt, hash] = stored.split(':');
  return crypto.pbkdf2Sync(password, salt, 10000, 64, 'sha512').toString('hex') === hash;
}

// ── Criar admin inicial se nao houver usuarios ────────────────────────────────
async function initUsers() {
  const snap = await fdb.collection('users').limit(1).get();
  if (snap.empty) {
    const adminUser = {
      id: 'admin_' + Date.now(),
      username: (process.env.ADMIN_USERNAME || 'admin').toLowerCase(),
      password_hash: hashPassword(ACCESS_PASSWORD),
      role: 'admin',
      created_at: now()
    };
    await fdb.collection('users').doc(adminUser.id).set(adminUser);
    console.log('Admin criado:', adminUser.username);
  }
}

// ── Load password from Firestore ──────────────────────────────────────────────
let _dbReady = null;
function ensureDB() {
  if (!_dbReady) _dbReady = Promise.all([
    fdb.collection('config').doc('app').get()
      .then(d => { if (d.exists && d.data().password) ACCESS_PASSWORD = d.data().password; })
      .catch(() => {}),
    initUsers().catch(() => {})
  ]);
  return _dbReady;
}

// ── Middleware ────────────────────────────────────────────────────────────────
app.set('trust proxy', 1);
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(cookieSession({
  name: 'rmh',
  keys: [SESSION_SECRET],
  maxAge: 8 * 60 * 60 * 1000,
  sameSite: 'lax',
  secure: process.env.NODE_ENV === 'production'
}));
app.use(async (req, res, next) => { try { await ensureDB(); next(); } catch(e) { next(e); } });

function requireAuth(req, res, next) {
  if (req.session && req.session.auth) return next();
  if (req.path.startsWith('/api/')) return res.status(401).json({ error: 'Nao autenticado' });
  res.redirect('/login');
}

function requireAdmin(req, res, next) {
  if (req.session && req.session.role === 'admin') return next();
  res.status(403).json({ error: 'Acesso restrito ao administrador' });
}

// ── Upload (arq temporários — use Vercel Blob para persistência) ──────────────
const upload = multer({
  storage: multer.diskStorage({
    destination: (req, file, cb) => cb(null, os.tmpdir()),
    filename: (req, file, cb) => {
      const ext = path.extname(file.originalname);
      const base = path.basename(file.originalname, ext).replace(/[^a-zA-Z0-9\-_]/g,'_').substring(0,40);
      cb(null, Date.now() + '_' + base + ext);
    }
  }),
  limits: { fileSize: 50 * 1024 * 1024 }
});

// ── Auth ──────────────────────────────────────────────────────────────────────
app.get('/login', (req, res) => {
  if (req.session && req.session.auth) return res.redirect('/');
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  // Login com username + senha
  if (username) {
    const snap = await fdb.collection('users').where('username','==',username.toLowerCase().trim()).limit(1).get();
    if (!snap.empty) {
      const user = snap.docs[0].data();
      if (verifyPassword(password, user.password_hash)) {
        // Verificar 2FA
        if (user.totp_enabled && user.totp_secret) {
          // Guarda estado pendente na sessão — aguarda código TOTP
          req.session.pending_2fa = true;
          req.session.pending_userId = user.id;
          req.session.pending_username = user.username;
          req.session.pending_role = user.role;
          return res.json({ success: false, twofa_required: true });
        }
        req.session.auth = true;
        req.session.userId = user.id;
        req.session.username = user.username;
        req.session.role = user.role;
        // Log de acesso
        fdb.collection('logs').add({ type:'login', username:user.username, role:user.role, ip:req.headers['x-forwarded-for']||req.ip||'', ua:req.headers['user-agent']||'', at:now() }).catch(()=>{});
        return res.json({ success: true, role: user.role });
      }
    }
    // Log tentativa falha
    fdb.collection('logs').add({ type:'login_fail', username:username.toLowerCase().trim(), ip:req.headers['x-forwarded-for']||req.ip||'', at:now() }).catch(()=>{});
    return res.status(401).json({ success: false, message: 'Usuário ou senha incorretos.' });
  }
  // Legado: só senha (compatibilidade)
  if (password === ACCESS_PASSWORD) {
    req.session.auth = true;
    req.session.role = 'admin';
    return res.json({ success: true, role: 'admin' });
  }
  res.status(401).json({ success: false, message: 'Senha incorreta' });
});

app.post('/api/logout', (req, res) => {
  req.session = null;
  res.json({ success: true });
});

app.post('/api/change-password', async (req, res) => {
  const { current_password, new_password } = req.body;
  if (!new_password || new_password.length < 6)
    return res.status(400).json({ success:false, message:'Minimo 6 caracteres.' });
  // Usuário autenticado com conta
  if (req.session && req.session.auth && req.session.userId) {
    const doc = await fdb.collection('users').doc(req.session.userId).get();
    if (!doc.exists) return res.status(404).json({ success:false, message:'Usuário não encontrado.' });
    if (!verifyPassword(current_password, doc.data().password_hash)) {
      // Tenta fallback com ACCESS_PASSWORD para conta admin sem hash migrado
      if (doc.data().role !== 'admin' || current_password !== ACCESS_PASSWORD)
        return res.status(401).json({ success:false, message:'Senha atual incorreta.' });
    }
    await fdb.collection('users').doc(req.session.userId).update({ password_hash: hashPassword(new_password) });
    // Se for admin, atualiza ACCESS_PASSWORD também
    if (doc.data().role === 'admin') {
      ACCESS_PASSWORD = new_password;
      await fdb.collection('config').doc('app').set({ password: new_password }, { merge:true });
    }
    return res.json({ success: true });
  }
  // Legado: senha master
  if (current_password !== ACCESS_PASSWORD)
    return res.status(401).json({ success:false, message:'Senha atual incorreta.' });
  ACCESS_PASSWORD = new_password;
  const newHash = hashPassword(new_password);
  // Atualiza config e hash de todos os admins no Firestore
  await fdb.collection('config').doc('app').set({ password: ACCESS_PASSWORD }, { merge:true });
  const adminSnap = await fdb.collection('users').where('role','==','admin').get();
  await Promise.all(adminSnap.docs.map(d => fdb.collection('users').doc(d.id).update({ password_hash: newHash })));
  res.json({ success: true });
});

// ── 2FA (TOTP) ────────────────────────────────────────────────────────────────
const speakeasy = (() => { try { return require('speakeasy'); } catch(e) { return null; } })();

// Verificar código TOTP após login com senha correta
app.post('/api/2fa/login', async (req, res) => {
  if (!req.session.pending_2fa || !req.session.pending_userId)
    return res.status(400).json({ success:false, message:'Sessão inválida. Faça login novamente.' });
  const { token } = req.body;
  if (!token) return res.status(400).json({ success:false, message:'Código obrigatório.' });
  const doc = await fdb.collection('users').doc(req.session.pending_userId).get();
  if (!doc.exists) return res.status(404).json({ success:false, message:'Usuário não encontrado.' });
  const user = doc.data();
  if (!speakeasy) return res.status(500).json({ success:false, message:'2FA não disponível.' });
  const ok = speakeasy.totp.verify({ secret:user.totp_secret, encoding:'base32', token, window:1 });
  if (!ok) {
    fdb.collection('logs').add({ type:'2fa_fail', username:user.username, ip:req.headers['x-forwarded-for']||req.ip||'', at:now() }).catch(()=>{});
    return res.status(401).json({ success:false, message:'Código inválido ou expirado.' });
  }
  req.session.auth = true;
  req.session.userId = user.id;
  req.session.username = user.username;
  req.session.role = user.role;
  req.session.pending_2fa = false;
  req.session.pending_userId = null;
  fdb.collection('logs').add({ type:'login', username:user.username, role:user.role, ip:req.headers['x-forwarded-for']||req.ip||'', via:'2fa', at:now() }).catch(()=>{});
  res.json({ success:true, role:user.role });
});

// Gerar segredo TOTP para configuração
app.post('/api/2fa/setup', requireAuth, async (req, res) => {
  if (!speakeasy) return res.status(500).json({ error:'2FA não disponível.' });
  const secret = speakeasy.generateSecret({ name:`RMHacking (${req.session.username||'usuario'})`, length:20 });
  // Salva o segredo temporário até confirmar com um token
  await fdb.collection('users').doc(req.session.userId).update({ totp_pending_secret: secret.base32 });
  res.json({ secret: secret.base32, otpauth_url: secret.otpauth_url });
});

// Confirmar ativação do 2FA com primeiro token
app.post('/api/2fa/enable', requireAuth, async (req, res) => {
  if (!speakeasy) return res.status(500).json({ error:'2FA não disponível.' });
  const { token } = req.body;
  const doc = await fdb.collection('users').doc(req.session.userId).get();
  if (!doc.exists) return res.status(404).json({ error:'Usuário não encontrado.' });
  const pending = doc.data().totp_pending_secret;
  if (!pending) return res.status(400).json({ error:'Nenhum segredo pendente. Gere primeiro.' });
  const ok = speakeasy.totp.verify({ secret:pending, encoding:'base32', token, window:1 });
  if (!ok) return res.status(401).json({ error:'Código inválido. Tente novamente.' });
  await fdb.collection('users').doc(req.session.userId).update({ totp_secret:pending, totp_enabled:true, totp_pending_secret:null });
  res.json({ success:true });
});

// Desabilitar 2FA
app.post('/api/2fa/disable', requireAuth, async (req, res) => {
  await fdb.collection('users').doc(req.session.userId).update({ totp_secret:null, totp_enabled:false, totp_pending_secret:null });
  res.json({ success:true });
});

// Status do 2FA do usuário atual
app.get('/api/2fa/status', requireAuth, async (req, res) => {
  const doc = await fdb.collection('users').doc(req.session.userId).get();
  if (!doc.exists) return res.json({ enabled:false });
  res.json({ enabled: doc.data().totp_enabled||false });
});

// ── Gestão de Usuários ────────────────────────────────────────────────────────
app.get('/api/users', requireAuth, requireAdmin, async (req, res) => {
  const snap = await fdb.collection('users').get();
  const users = snap.docs.map(d => {
    const u = d.data();
    return { id:u.id, username:u.username, role:u.role, temporary:u.temporary||false, created_at:u.created_at };
  });
  res.json(users);
});

app.post('/api/users', requireAuth, requireAdmin, async (req, res) => {
  const { username, password, role, temporary } = req.body;
  if (!username || !password) return res.status(400).json({ error:'Username e senha obrigatórios' });
  if (password.length < 6) return res.status(400).json({ error:'Senha mínimo 6 caracteres' });
  const existing = await fdb.collection('users').where('username','==',username.toLowerCase().trim()).get();
  if (!existing.empty) return res.status(400).json({ error:'Usuário já existe' });
  const user = { id:'u_'+Date.now(), username:username.toLowerCase().trim(), password_hash:hashPassword(password), role:role||'user', temporary:temporary===true, created_at:now() };
  await fdb.collection('users').doc(user.id).set(user);
  res.json({ id:user.id, username:user.username, role:user.role, temporary:user.temporary, created_at:user.created_at });
});

app.put('/api/users/:id/password', requireAuth, requireAdmin, async (req, res) => {
  const { new_password } = req.body;
  if (!new_password || new_password.length < 6) return res.status(400).json({ error:'Mínimo 6 caracteres' });
  await fdb.collection('users').doc(req.params.id).update({ password_hash: hashPassword(new_password) });
  res.json({ success: true });
});

app.delete('/api/users/:id', requireAuth, requireAdmin, async (req, res) => {
  const doc = await fdb.collection('users').doc(req.params.id).get();
  if (!doc.exists) return res.status(404).json({ error:'Não encontrado' });
  if (doc.data().role === 'admin') {
    const admins = await fdb.collection('users').where('role','==','admin').get();
    if (admins.size <= 1) return res.status(400).json({ error:'Não é possível excluir o único administrador' });
  }
  await fdb.collection('users').doc(req.params.id).delete();
  res.json({ success: true });
});

app.get('/api/stats', requireAuth, async (req, res) => {
  const snap = await fdb.collection('investigations').get();
  const invs = snap.docs.map(d => d.data());
  res.json({ total:invs.length, open:invs.filter(i=>i.status==='open').length, todo:invs.filter(i=>i.status==='todo').length, closed:invs.filter(i=>i.status==='closed').length });
});

app.post('/api/investigations/:id/upload', requireAuth, upload.single('file'), (req, res) => {
  if (!req.file) return res.status(400).json({ error:'Nenhum arquivo enviado' });
  res.json({ success:true, url:'', original_name:req.file.originalname, size:req.file.size, mimetype:req.file.mimetype, note:'Upload temporario. Migrar para Firebase Storage para persistencia.' });
});

// ── Static (protegido) ────────────────────────────────────────────────────────
app.use('/', requireAuth, express.static(path.join(__dirname, 'public')));

// ── Investigations ────────────────────────────────────────────────────────────
app.get('/api/investigations', requireAuth, async (req, res) => {
  const snap = await fdb.collection('investigations').get();
  const userId = req.session.userId || '';
  const role = req.session.role || '';
  const list = snap.docs.map(d=>d.data())
    .filter(inv => role === 'admin' || !inv.shared_with || inv.shared_with.length === 0 || inv.shared_with.includes(userId))
    .sort((a,b)=>b.updated_at>a.updated_at?1:-1);
  res.json(list);
});

app.get('/api/investigations/:id', requireAuth, async (req, res) => {
  const doc = await fdb.collection('investigations').doc(req.params.id).get();
  if (!doc.exists) return res.status(404).json({ error:'Nao encontrado' });
  res.json(doc.data());
});

app.post('/api/investigations', requireAuth, async (req, res) => {
  const b = req.body;
  const id = await nextInvId();
  const inv = { id, title:b.title||'', description:b.description||'', status:b.status||'open', tags:b.tags||'', color:b.color||'#4f46e5', priority:b.priority||'medium', target:b.target||'', deadline:b.deadline||'', folder:b.folder||'', shared_with:[], overview:'', empresa_notes:'', dossie:{}, created_at:now(), updated_at:now() };
  // Log atividade
  fdb.collection('activity').add({ action:'create_investigation', title:inv.title, username:req.session.username||'admin', at:now() }).catch(()=>{});
  await fdb.collection('investigations').doc(String(id)).set(inv);
  res.json(inv);
});

app.put('/api/investigations/:id', requireAuth, async (req, res) => {
  const doc = await fdb.collection('investigations').doc(req.params.id).get();
  if (!doc.exists) return res.status(404).json({ error:'Nao encontrado' });
  const cur = doc.data(); const b = req.body;
  const u = {};
  ['title','description','status','tags','color','priority','target','deadline','folder','overview','empresa_notes'].forEach(k => {
    if (b[k] !== undefined) u[k] = b[k];
  });
  u.updated_at = now();
  await fdb.collection('investigations').doc(req.params.id).update(u);
  res.json(Object.assign({}, cur, u));
});

app.delete('/api/investigations/:id', requireAuth, async (req, res) => {
  const id = Number(req.params.id);
  for (const col of ['nodes','edges','notes','evidence','events','osint','custody','entities','entity_links']) {
    const snap = await fdb.collection(col).where('investigation_id','==',id).get();
    if (!snap.empty) { const b=fdb.batch(); snap.docs.forEach(d=>b.delete(d.ref)); await b.commit(); }
  }
  await fdb.collection('investigations').doc(req.params.id).delete();
  res.json({ success:true });
});

// ── Compartilhar investigação ─────────────────────────────────────────────────
app.post('/api/investigations/:id/share', requireAuth, requireAdmin, async (req, res) => {
  const { user_ids } = req.body; // array of user IDs to share with
  if (!Array.isArray(user_ids)) return res.status(400).json({ error:'user_ids deve ser array' });
  const doc = await fdb.collection('investigations').doc(req.params.id).get();
  if (!doc.exists) return res.status(404).json({ error:'Não encontrado' });
  await fdb.collection('investigations').doc(req.params.id).update({ shared_with: user_ids, updated_at: now() });
  res.json({ success: true, shared_with: user_ids });
});

// ── Dossie ────────────────────────────────────────────────────────────────────
app.post('/api/investigations/:id/dossie', requireAuth, async (req, res) => {
  await fdb.collection('investigations').doc(req.params.id).update({ dossie:req.body, updated_at:now() });
  res.json({ success:true });
});

// ── Nodes ─────────────────────────────────────────────────────────────────────
app.get('/api/investigations/:id/nodes', requireAuth, async (req, res) => {
  const snap = await fdb.collection('nodes').where('investigation_id','==',Number(req.params.id)).get();
  res.json(snap.docs.map(d=>d.data()));
});

app.post('/api/investigations/:id/nodes', requireAuth, async (req, res) => {
  const b = req.body;
  const node = { id:b.id, investigation_id:Number(req.params.id), label:b.label||'', type:b.type||'default', x:b.x||0, y:b.y||0, color:b.color||'#4f46e5', bg_color:b.bg_color||'#eef2ff', notes:b.notes||'', url:b.url||'', shape:b.shape||'ellipse', created_at:now() };
  await fdb.collection('nodes').doc(b.id).set(node);
  res.json({ success:true });
});

app.put('/api/investigations/:id/nodes/:nodeId', requireAuth, async (req, res) => {
  const b = req.body;
  await fdb.collection('nodes').doc(req.params.nodeId).update({ label:b.label, type:b.type, x:b.x, y:b.y, color:b.color, bg_color:b.bg_color, notes:b.notes, url:b.url, shape:b.shape });
  res.json({ success:true });
});

app.delete('/api/investigations/:id/nodes/:nodeId', requireAuth, async (req, res) => {
  await fdb.collection('nodes').doc(req.params.nodeId).delete();
  const snap = await fdb.collection('edges').where('investigation_id','==',Number(req.params.id)).get();
  const batch = fdb.batch();
  snap.docs.forEach(d=>{ const e=d.data(); if(e.from_node===req.params.nodeId||e.to_node===req.params.nodeId) batch.delete(d.ref); });
  await batch.commit();
  res.json({ success:true });
});

// ── Edges ─────────────────────────────────────────────────────────────────────
app.get('/api/investigations/:id/edges', requireAuth, async (req, res) => {
  const snap = await fdb.collection('edges').where('investigation_id','==',Number(req.params.id)).get();
  res.json(snap.docs.map(d=>d.data()));
});

app.post('/api/investigations/:id/edges', requireAuth, async (req, res) => {
  const b = req.body;
  const edge = { id:b.id, investigation_id:Number(req.params.id), from_node:b.from_node, to_node:b.to_node, label:b.label||'', color:b.color||'#94a3b8', arrows:b.arrows||'to', created_at:now() };
  await fdb.collection('edges').doc(b.id).set(edge);
  res.json({ success:true });
});

app.delete('/api/investigations/:id/edges/:edgeId', requireAuth, async (req, res) => {
  await fdb.collection('edges').doc(req.params.edgeId).delete();
  res.json({ success:true });
});

// ── Notes ─────────────────────────────────────────────────────────────────────
app.get('/api/investigations/:id/notes', requireAuth, async (req, res) => {
  const snap = await fdb.collection('notes').where('investigation_id','==',Number(req.params.id)).get();
  const list = snap.docs.map(d=>d.data()).sort((a,b)=>b.created_at>a.created_at?1:-1);
  res.json(list);
});

app.post('/api/investigations/:id/notes', requireAuth, async (req, res) => {
  const b = req.body;
  const id = await nextItemId('notes', req.params.id);
  const note = { id, investigation_id:Number(req.params.id), title:b.title||'Nota', content:b.content||'', color:b.color||'#fef9c3', file_url:b.file_url||'', file_name:b.file_name||'', file_type:b.file_type||'', created_at:now(), updated_at:now() };
  await fdb.collection('notes').doc(req.params.id+'_'+id).set(note);
  res.json(note);
});

app.put('/api/investigations/:id/notes/:noteId', requireAuth, async (req, res) => {
  await fdb.collection('notes').doc(req.params.id+'_'+req.params.noteId).update({ title:req.body.title, content:req.body.content, color:req.body.color, updated_at:now() });
  res.json({ success:true });
});

app.delete('/api/investigations/:id/notes/:noteId', requireAuth, async (req, res) => {
  await fdb.collection('notes').doc(req.params.id+'_'+req.params.noteId).delete();
  res.json({ success:true });
});

// ── Evidence ──────────────────────────────────────────────────────────────────
app.get('/api/investigations/:id/evidence', requireAuth, async (req, res) => {
  const snap = await fdb.collection('evidence').where('investigation_id','==',Number(req.params.id)).get();
  const list = snap.docs.map(d=>d.data()).sort((a,b)=>b.created_at>a.created_at?1:-1);
  res.json(list);
});

app.post('/api/investigations/:id/evidence', requireAuth, async (req, res) => {
  const b = req.body;
  const id = await nextItemId('evidence', req.params.id);
  const ev = { id, investigation_id:Number(req.params.id), title:b.title||'', type:b.type||'text', content:b.content||'', tags:b.tags||'', hash:b.hash||b.hash_value||'', source:b.source||'', chain_of_custody:b.chain_of_custody||b.custody_chain||'', file_url:b.file_url||'', file_name:b.file_name||'', file_type:b.file_type||'', created_at:now() };
  await fdb.collection('evidence').doc(req.params.id+'_'+id).set(ev);
  res.json(ev);
});

app.delete('/api/investigations/:id/evidence/:evId', requireAuth, async (req, res) => {
  await fdb.collection('evidence').doc(req.params.id+'_'+req.params.evId).delete();
  res.json({ success:true });
});

// ── Events ────────────────────────────────────────────────────────────────────
app.get('/api/investigations/:id/events', requireAuth, async (req, res) => {
  const snap = await fdb.collection('events').where('investigation_id','==',Number(req.params.id)).get();
  const list = snap.docs.map(d=>d.data()).sort((a,b)=>a.event_date>b.event_date?1:-1);
  res.json(list);
});

app.post('/api/investigations/:id/events', requireAuth, async (req, res) => {
  const b = req.body;
  const id = await nextItemId('events', req.params.id);
  const evt = { id, investigation_id:Number(req.params.id), title:b.title||'', description:b.description||'', event_date:b.event_date||'', importance:b.importance||'normal', file_url:b.file_url||'', file_name:b.file_name||'', file_type:b.file_type||'', created_at:now() };
  await fdb.collection('events').doc(req.params.id+'_'+id).set(evt);
  res.json(evt);
});

app.delete('/api/investigations/:id/events/:evtId', requireAuth, async (req, res) => {
  await fdb.collection('events').doc(req.params.id+'_'+req.params.evtId).delete();
  res.json({ success:true });
});

// ── OSINT ─────────────────────────────────────────────────────────────────────
app.get('/api/investigations/:id/osint', requireAuth, async (req, res) => {
  const snap = await fdb.collection('osint').where('investigation_id','==',Number(req.params.id)).get();
  const list = snap.docs.map(d=>d.data()).sort((a,b)=>b.created_at>a.created_at?1:-1);
  res.json(list);
});

app.post('/api/investigations/:id/osint', requireAuth, async (req, res) => {
  const b = req.body;
  const id = await nextItemId('osint', req.params.id);
  const entry = { id, investigation_id:Number(req.params.id), query:b.query||'', type:b.type||'general', result:b.result||'', source:b.source||'', file_url:b.file_url||'', file_name:b.file_name||'', file_type:b.file_type||'', created_at:now() };
  await fdb.collection('osint').doc(req.params.id+'_'+id).set(entry);
  res.json(entry);
});

app.delete('/api/investigations/:id/osint/:searchId', requireAuth, async (req, res) => {
  await fdb.collection('osint').doc(req.params.id+'_'+req.params.searchId).delete();
  res.json({ success:true });
});

// ── Watchlist ─────────────────────────────────────────────────────────────────
app.get('/api/watchlist', requireAuth, async (req, res) => {
  const snap = await fdb.collection('watchlist').get();
  res.json(snap.docs.map(d=>d.data()));
});

app.post('/api/watchlist', requireAuth, async (req, res) => {
  const b = req.body;
  const id = await nextWlId();
  const entry = { id, investigation_id:b.investigation_id||null, type:b.type||'domain', target:b.target||'', label:b.label||'', interval:b.interval||'daily', last_check:null, last_status:'pending', notes:b.notes||'', created_at:now() };
  await fdb.collection('watchlist').doc(String(id)).set(entry);
  res.json(entry);
});

app.put('/api/watchlist/:id', requireAuth, async (req, res) => {
  const b = req.body; const u = { last_check:now() };
  if (b.label) u.label = b.label;
  if (b.notes !== undefined) u.notes = b.notes;
  if (b.last_status) u.last_status = b.last_status;
  await fdb.collection('watchlist').doc(req.params.id).update(u);
  const doc = await fdb.collection('watchlist').doc(req.params.id).get();
  res.json(doc.data());
});

app.delete('/api/watchlist/:id', requireAuth, async (req, res) => {
  await fdb.collection('watchlist').doc(req.params.id).delete();
  res.json({ success:true });
});

// ── Custody ───────────────────────────────────────────────────────────────────
app.get('/api/investigations/:id/custody', requireAuth, async (req, res) => {
  const snap = await fdb.collection('custody').where('investigation_id','==',Number(req.params.id)).get();
  const list = snap.docs.map(d=>d.data()).sort((a,b)=>a.created_at>b.created_at?1:-1);
  res.json(list);
});

app.post('/api/investigations/:id/custody', requireAuth, async (req, res) => {
  const b = req.body;
  const id = await nextItemId('custody', req.params.id);
  const entry = { id, investigation_id:Number(req.params.id), evidence_title:b.evidence_title||'', evidence_hash:b.evidence_hash||'', action:b.action||'coleta', responsible:b.responsible||'', responsible_role:b.responsible_role||'', location:b.location||'', method:b.method||'', seal_number:b.seal_number||'', notes:b.notes||'', created_at:now() };
  await fdb.collection('custody').doc(req.params.id+'_'+id).set(entry);
  res.json(entry);
});

app.delete('/api/investigations/:id/custody/:cId', requireAuth, async (req, res) => {
  await fdb.collection('custody').doc(req.params.id+'_'+req.params.cId).delete();
  res.json({ success:true });
});

// ── Entities ──────────────────────────────────────────────────────────────────
app.get('/api/investigations/:id/entities', requireAuth, async (req, res) => {
  const snap = await fdb.collection('entities').where('investigation_id','==',Number(req.params.id)).get();
  res.json(snap.docs.map(d=>d.data()));
});

app.post('/api/investigations/:id/entities', requireAuth, async (req, res) => {
  const b = req.body;
  const entity = { id:b.id||('e'+Date.now()), investigation_id:Number(req.params.id), type:b.type||'person', label:b.label||'', notes:b.notes||'', x:b.x||0, y:b.y||0, created_at:now() };
  await fdb.collection('entities').doc(entity.id).set(entity);
  res.json({ success:true });
});

app.delete('/api/investigations/:id/entities/:eId', requireAuth, async (req, res) => {
  await fdb.collection('entities').doc(req.params.eId).delete();
  const snap = await fdb.collection('entity_links').where('investigation_id','==',Number(req.params.id)).get();
  const batch = fdb.batch();
  snap.docs.forEach(d=>{ const l=d.data(); if(l.from===req.params.eId||l.to===req.params.eId) batch.delete(d.ref); });
  await batch.commit();
  res.json({ success:true });
});

app.get('/api/investigations/:id/entity-links', requireAuth, async (req, res) => {
  const snap = await fdb.collection('entity_links').where('investigation_id','==',Number(req.params.id)).get();
  res.json(snap.docs.map(d=>d.data()));
});

app.post('/api/investigations/:id/entity-links', requireAuth, async (req, res) => {
  const b = req.body;
  const link = { id:b.id||('l'+Date.now()), investigation_id:Number(req.params.id), from:b.from, to:b.to, label:b.label||'', created_at:now() };
  await fdb.collection('entity_links').doc(link.id).set(link);
  res.json({ success:true });
});

app.delete('/api/investigations/:id/entity-links/:lId', requireAuth, async (req, res) => {
  await fdb.collection('entity_links').doc(req.params.lId).delete();
  res.json({ success:true });
});

// ── Backup / Restore ──────────────────────────────────────────────────────────
app.get('/api/investigations/:id/backup', requireAuth, async (req, res) => {
  const invId = Number(req.params.id);
  const doc = await fdb.collection('investigations').doc(req.params.id).get();
  if (!doc.exists) return res.status(404).json({ error:'Nao encontrado' });
  const backup = { _version:2, _exported_at:now(), _app:'RMHacking-Digital', investigation:doc.data() };
  for (const col of ['nodes','edges','notes','evidence','events','osint','custody']) {
    const snap = await fdb.collection(col).where('investigation_id','==',invId).get();
    backup[col] = snap.docs.map(d=>d.data());
  }
  const filename = 'backup_inv'+invId+'_'+new Date().toISOString().slice(0,10)+'.rmh.json';
  res.setHeader('Content-Disposition','attachment; filename="'+filename+'"');
  res.setHeader('Content-Type','application/json');
  res.send(JSON.stringify(backup,null,2));
});

app.post('/api/restore', requireAuth, async (req, res) => {
  try {
    const backup = req.body;
    if (!backup||!backup.investigation||!backup._app) return res.status(400).json({ error:'Arquivo invalido.' });
    const newId = await nextInvId();
    const newInv = Object.assign({}, backup.investigation, { id:newId, title:backup.investigation.title+' (Restaurado)', created_at:now(), updated_at:now() });
    await fdb.collection('investigations').doc(String(newId)).set(newInv);
    const cols = ['nodes','edges','notes','evidence','events','osint','custody'];
    for (const col of cols) {
      if (!backup[col] || !backup[col].length) continue;
      const batch = fdb.batch();
      backup[col].forEach((item, i) => {
        const newItem = Object.assign({}, item, { investigation_id:newId });
        const docId = (col==='nodes'||col==='edges') ? (newItem.id||('r'+i)) : (String(newId)+'_'+newItem.id);
        batch.set(fdb.collection(col).doc(docId), newItem);
      });
      await batch.commit();
    }
    res.json({ success:true, new_id:newId, title:newInv.title });
  } catch(e) { res.status(500).json({ error:'Erro: '+e.message }); }
});

// ── Relatorio IA ──────────────────────────────────────────────────────────────
app.post('/api/investigations/:id/ai-report', requireAuth, async (req, res) => {
  const apiKey = process.env.ANTHROPIC_API_KEY;
  if (!apiKey) return res.status(400).json({ error:'ANTHROPIC_API_KEY nao configurada.' });
  const invId = Number(req.params.id);
  const doc = await fdb.collection('investigations').doc(req.params.id).get();
  if (!doc.exists) return res.status(404).json({ error:'Investigacao nao encontrada' });
  const inv = doc.data();
  const mode = req.body.mode||'full'; const templateText = req.body.template||'';
  const [notesSnap, evSnap, evtSnap, osintSnap] = await Promise.all([
    fdb.collection('notes').where('investigation_id','==',invId).get(),
    fdb.collection('evidence').where('investigation_id','==',invId).get(),
    fdb.collection('events').where('investigation_id','==',invId).get(),
    fdb.collection('osint').where('investigation_id','==',invId).get()
  ]);
  let dataStr = 'INVESTIGACAO: '+inv.title+'\nAlvo: '+inv.target+'\nStatus: '+inv.status+'\nDescricao: '+inv.description+'\n\n';
  dataStr += 'EVIDENCIAS:\n'; evSnap.forEach(d=>{ const e=d.data(); dataStr+='- ['+e.type+'] '+e.title+': '+(e.content||'').substring(0,200)+'\n'; });
  dataStr += '\nNOTAS:\n'; notesSnap.forEach(d=>{ const n=d.data(); dataStr+='- '+n.title+': '+(n.content||'').substring(0,200)+'\n'; });
  dataStr += '\nEVENTOS:\n'; evtSnap.forEach(d=>{ const e=d.data(); dataStr+='- ['+e.event_date+'] '+e.title+': '+(e.description||'').substring(0,150)+'\n'; });
  dataStr += '\nOSINT:\n'; osintSnap.forEach(d=>{ const o=d.data(); dataStr+='- ['+o.type+'] '+o.query+': '+(o.result||'').substring(0,200)+'\n'; });
  const systemMsg = mode==='template' ? 'Use a estrutura do modelo fornecido, preenchendo com os dados reais.' : 'Voce e um especialista em investigacao digital. Gere um relatorio tecnico-profissional completo.';
  const userMsg = mode==='template' ? 'MODELO:\n'+templateText+'\n\nDADOS:\n'+dataStr : dataStr;
  const https = require('https');
  const payload = JSON.stringify({ model:'claude-haiku-4-5-20251001', max_tokens:4096, messages:[{role:'user',content:userMsg}], system:systemMsg });
  const options = { hostname:'api.anthropic.com', path:'/v1/messages', method:'POST', headers:{'Content-Type':'application/json','x-api-key':apiKey,'anthropic-version':'2023-06-01','Content-Length':Buffer.byteLength(payload)} };
  const apiReq = https.request(options, apiRes => {
    let body = '';
    apiRes.on('data', c=>body+=c);
    apiRes.on('end', ()=>{ try { const p=JSON.parse(body); if(p.error) return res.status(500).json({error:p.error.message}); res.json({report:p.content[0].text}); } catch(e){ res.status(500).json({error:'Erro ao processar resposta'}); } });
  });
  apiReq.on('error', e=>res.status(500).json({error:e.message}));
  apiReq.write(payload); apiReq.end();
});

// ── Ferramentas OSINT ─────────────────────────────────────────────────────────
const https_mod = require('https');
const dns_mod   = require('dns').promises;

function httpGet(url) {
  return new Promise((resolve, reject) => {
    https_mod.get(url, { headers:{'User-Agent':'RMHacking-Digital/1.0','Accept':'application/json'} }, res => {
      let body='';
      res.on('data',c=>body+=c);
      res.on('end',()=>{ try{resolve(JSON.parse(body));}catch(e){resolve({_raw:body});} });
    }).on('error', reject);
  });
}

// CNPJ — ReceitaWS (gratuito)
app.get('/api/tools/cnpj/:cnpj', requireAuth, async (req, res) => {
  try {
    const cnpj = req.params.cnpj.replace(/\D/g,'');
    if (cnpj.length!==14) return res.status(400).json({error:'CNPJ inválido'});
    const data = await httpGet('https://receitaws.com.br/v1/cnpj/'+cnpj);
    if (data.status==='ERROR') return res.status(404).json({error:data.message||'CNPJ não encontrado'});
    res.json(data);
  } catch(e) { res.status(500).json({error:'Erro ao consultar CNPJ: '+e.message}); }
});

// IPInfo (gratuito, 50k/mês)
app.get('/api/tools/ipinfo/:target', requireAuth, async (req, res) => {
  try {
    const target = decodeURIComponent(req.params.target);
    const data = await httpGet('https://ipinfo.io/'+encodeURIComponent(target)+'/json');
    res.json(data);
  } catch(e) { res.status(500).json({error:'Erro ao consultar IP: '+e.message}); }
});

// WHOIS via api.whoapi.com (demo) ou fallback DNS
app.get('/api/tools/whois/:domain', requireAuth, async (req, res) => {
  try {
    const domain = decodeURIComponent(req.params.domain).replace(/^https?:\/\//,'').split('/')[0];
    const data = await httpGet('https://api.whoapi.com/?apikey=demokey&r=whois&q='+encodeURIComponent(domain));
    if (data && data.whois) {
      res.json({result: data.whois});
    } else {
      // Fallback: resolve DNS básico
      const [a, mx, ns] = await Promise.allSettled([
        dns_mod.resolve4(domain),
        dns_mod.resolveMx(domain),
        dns_mod.resolveNs(domain)
      ]);
      const lines = ['=== DNS INFO (fallback) ===','Domínio: '+domain,''];
      if (a.status==='fulfilled') lines.push('A (IPv4): '+a.value.join(', '));
      if (ns.status==='fulfilled') lines.push('NS: '+ns.value.join(', '));
      if (mx.status==='fulfilled') lines.push('MX: '+mx.value.map(m=>m.exchange).join(', '));
      res.json({result: lines.join('\n')});
    }
  } catch(e) { res.status(500).json({error:'Erro WHOIS: '+e.message}); }
});

// DNS Lookup
app.get('/api/tools/dns/:domain', requireAuth, async (req, res) => {
  try {
    const domain = decodeURIComponent(req.params.domain).replace(/^https?:\/\//,'').split('/')[0];
    const [a, aaaa, mx, ns, txt, cname] = await Promise.allSettled([
      dns_mod.resolve4(domain),
      dns_mod.resolve6(domain),
      dns_mod.resolveMx(domain),
      dns_mod.resolveNs(domain),
      dns_mod.resolveTxt(domain),
      dns_mod.resolveCname(domain),
    ]);
    const lines = ['=== DNS LOOKUP ===','Domínio: '+domain,''];
    if (a.status==='fulfilled')     lines.push('A (IPv4):  '+a.value.join(', '));
    if (aaaa.status==='fulfilled')  lines.push('AAAA (v6): '+aaaa.value.join(', '));
    if (ns.status==='fulfilled')    lines.push('NS:        '+ns.value.join(', '));
    if (mx.status==='fulfilled')    lines.push('MX:        '+mx.value.map(m=>m.priority+' '+m.exchange).join(' | '));
    if (cname.status==='fulfilled') lines.push('CNAME:     '+cname.value.join(', '));
    if (txt.status==='fulfilled')   lines.push('TXT:       '+txt.value.map(t=>t.join('')).join('\n           '));
    res.json({result: lines.join('\n')});
  } catch(e) { res.status(500).json({error:'Erro DNS: '+e.message}); }
});

// URLScan.io (gratuito, sem chave para busca)
app.get('/api/tools/urlscan/:target', requireAuth, async (req, res) => {
  try {
    const target = decodeURIComponent(req.params.target).replace(/^https?:\/\//,'').split('/')[0];
    const data = await httpGet('https://urlscan.io/api/v1/search/?q=domain:'+encodeURIComponent(target)+'&size=5');
    res.json(data);
  } catch(e) { res.status(500).json({error:'Erro URLScan: '+e.message}); }
});

// ── Logs de Acesso ────────────────────────────────────────────────────────────
app.get('/api/logs', requireAuth, requireAdmin, async (req, res) => {
  try {
    const snap = await fdb.collection('logs').orderBy('at','desc').limit(200).get();
    res.json(snap.docs.map(d=>d.data()));
  } catch(e) { res.status(500).json({ error:e.message }); }
});

// ── Histórico de Atividade ────────────────────────────────────────────────────
app.get('/api/activity', requireAuth, requireAdmin, async (req, res) => {
  try {
    const snap = await fdb.collection('activity').orderBy('at','desc').limit(100).get();
    res.json(snap.docs.map(d=>d.data()));
  } catch(e) { res.status(500).json({ error:e.message }); }
});

// ── Screenshot de sites (via screenshotone-compatível) ────────────────────────
app.get('/api/tools/screenshot', requireAuth, async (req, res) => {
  const url = req.query.url;
  if (!url) return res.status(400).json({ error:'URL obrigatória' });
  // Usa thum.io (free, no-key) para captura básica
  const thumbUrl = 'https://image.thum.io/get/width/1280/crop/768/allowJPG/wait/2/noanimate/' + encodeURIComponent(url);
  res.json({ screenshot_url: thumbUrl, source: 'thum.io' });
});

// ── Chat Interno ──────────────────────────────────────────────────────────────
// Verifica se o usuário tem acesso a uma investigação específica
async function canAccessInvestigation(invId, session) {
  if (session.role === 'admin') return true;
  try {
    const doc = await fdb.collection('investigations').doc(String(invId)).get();
    if (!doc.exists) return false;
    const inv = doc.data();
    const shared = inv.shared_with || [];
    return shared.length === 0 || shared.includes(session.userId);
  } catch(e) { return false; }
}

// GET /api/investigations/:id/chat — últimas 60 mensagens
app.get('/api/investigations/:id/chat', requireAuth, async (req, res) => {
  try {
    if (!(await canAccessInvestigation(req.params.id, req.session)))
      return res.status(403).json({ error: 'Sem acesso a esta investigação' });
    const snap = await fdb.collection('investigations').doc(String(req.params.id))
      .collection('chat').orderBy('at','asc').limitToLast(60).get();
    const msgs = snap.docs.map(d => ({ id: d.id, ...d.data() }));
    res.json(msgs);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// POST /api/investigations/:id/chat — enviar mensagem
app.post('/api/investigations/:id/chat', requireAuth, async (req, res) => {
  try {
    if (!(await canAccessInvestigation(req.params.id, req.session)))
      return res.status(403).json({ error: 'Sem acesso a esta investigação' });
    const { message } = req.body;
    if (!message || !message.trim()) return res.status(400).json({ error: 'Mensagem vazia' });
    const doc = {
      message: message.trim(),
      username: req.session.username || req.session.userId || 'usuário',
      at: now(),
      userId: req.session.userId,
    };
    const ref = await fdb.collection('investigations').doc(String(req.params.id))
      .collection('chat').add(doc);
    res.json({ id: ref.id, ...doc });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── Rastreador de Links ───────────────────────────────────────────────────────
function genCode(len=8) {
  return crypto.randomBytes(len).toString('base64url').substring(0,len);
}

// Rota pública — captura clique e redireciona
app.get('/r/:code', async (req, res) => {
  try {
    const snap = await fdb.collection('tracker_links').where('code','==',req.params.code).limit(1).get();
    if (snap.empty) return res.status(404).send('<h2>Link não encontrado</h2>');
    const doc = snap.docs[0];
    const link = doc.data();
    // Captura dados do visitante
    const ip = req.headers['x-forwarded-for']?.split(',')[0].trim() || req.socket.remoteAddress || '?';
    const ua = req.headers['user-agent'] || '?';
    const referer = req.headers['referer'] || '—';
    // Geolocalização via ipinfo.io
    let geo = {};
    try {
      geo = await httpGet('https://ipinfo.io/'+encodeURIComponent(ip)+'/json');
    } catch(e) {}
    const click = {
      ip, ua, referer,
      city: geo.city||'?', region: geo.region||'?', country: geo.country||'?',
      org: geo.org||'?', loc: geo.loc||'?', timezone: geo.timezone||'?',
      at: now(),
    };
    // Salva o clique
    await fdb.collection('tracker_links').doc(doc.id).update({
      clicks: admin.firestore.FieldValue.arrayUnion(click),
      last_click: now(),
    });
    // Redireciona para o alvo
    res.redirect(link.target_url || 'https://google.com');
  } catch(e) { res.redirect('https://google.com'); }
});

// POST /api/tracker — criar link rastreável
app.post('/api/tracker', requireAuth, async (req, res) => {
  try {
    const { title, target_url, inv_id } = req.body;
    if (!target_url) return res.status(400).json({ error: 'URL alvo obrigatória' });
    const code = genCode(7);
    const doc = {
      code, title: title||'Link rastreável', target_url,
      inv_id: inv_id||null,
      created_by: req.session.username || req.session.userId,
      created_at: now(),
      clicks: [],
      last_click: null,
    };
    const ref = await fdb.collection('tracker_links').add(doc);
    const baseUrl = `${req.protocol}://${req.get('host')}`;
    res.json({ id: ref.id, ...doc, track_url: `${baseUrl}/r/${code}` });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// GET /api/tracker — listar links do usuário
app.get('/api/tracker', requireAuth, async (req, res) => {
  try {
    const isAdmin = req.session.role === 'admin';
    let query = fdb.collection('tracker_links').orderBy('created_at','desc').limit(100);
    const snap = await query.get();
    let links = snap.docs.map(d => ({ id: d.id, ...d.data() }));
    if (!isAdmin) links = links.filter(l => l.created_by === (req.session.username||req.session.userId));
    // Adiciona URL de rastreamento
    const base = `${req.protocol}://${req.get('host')}`;
    links = links.map(l => ({ ...l, track_url: `${base}/r/${l.code}` }));
    res.json(links);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// DELETE /api/tracker/:id
app.delete('/api/tracker/:id', requireAuth, async (req, res) => {
  try {
    await fdb.collection('tracker_links').doc(req.params.id).delete();
    res.json({ success: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});


// ── Encurtador de URL (proxy TinyURL sem CORS) ───────────────────────────────
app.post('/api/shorten', requireAuth, async (req, res) => {
  const { url } = req.body;
  if (!url) return res.status(400).json({ error: 'URL obrigatória' });
  try {
    const short = await new Promise((resolve, reject) => {
      https_mod.get('https://tinyurl.com/api-create.php?url=' + encodeURIComponent(url), r => {
        let body = '';
        r.on('data', c => body += c);
        r.on('end', () => {
          if (body.startsWith('http')) resolve(body.trim());
          else reject(new Error('Resposta inválida: ' + body.substring(0, 100)));
        });
      }).on('error', reject);
    });
    res.json({ short });
  } catch(e) { res.status(500).json({ error: 'Erro ao encurtar: ' + e.message }); }
});

// ── Start ─────────────────────────────────────────────────────────────────────
if (require.main === module) {
  app.listen(PORT, () => console.log('RMHacking Digital — porta ' + PORT));
}
module.exports = app;
