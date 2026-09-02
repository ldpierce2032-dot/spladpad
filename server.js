const path = require('path');
const fs = require('fs');
const http = require('http');
const express = require('express');
const helmet = require('helmet');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const Database = require('better-sqlite3');
const { WebSocketServer } = require('ws');
const crypto = require('crypto');

const PORT = Number(process.env.PORT || 3000);
const JWT_SECRET = process.env.JWT_SECRET || 'CHANGE_ME_BEFORE_PUBLIC_DEPLOYMENT';
if (JWT_SECRET === 'CHANGE_ME_BEFORE_PUBLIC_DEPLOYMENT') console.warn('WARNING: set JWT_SECRET before deploying publicly.');

const dataDir = process.env.DATA_DIR || path.join(__dirname, 'data');
fs.mkdirSync(dataDir, { recursive: true });
const db = new Database(path.join(dataDir, 'spladpad.sqlite'));
db.pragma('journal_mode = WAL');

db.exec(`
CREATE TABLE IF NOT EXISTS users (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 username TEXT NOT NULL UNIQUE COLLATE NOCASE,
 password_hash TEXT NOT NULL,
 bio TEXT NOT NULL DEFAULT 'New Spladpad player!',
 avatar_color TEXT NOT NULL DEFAULT 'blue',
 avatar_type TEXT NOT NULL DEFAULT 'starter',
 coins INTEGER NOT NULL DEFAULT 1000,
 inventory_json TEXT NOT NULL DEFAULT '[]',
 equipped_json TEXT NOT NULL DEFAULT '{}',
 badges_json TEXT NOT NULL DEFAULT '["player"]',
 joined_at INTEGER NOT NULL,
 banned INTEGER NOT NULL DEFAULT 0,
 ban_reason TEXT NOT NULL DEFAULT '',
 banned_at INTEGER
);
CREATE TABLE IF NOT EXISTS friend_requests (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 sender_id INTEGER NOT NULL,
 receiver_id INTEGER NOT NULL,
 created_at INTEGER NOT NULL,
 UNIQUE(sender_id, receiver_id)
);
CREATE TABLE IF NOT EXISTS friendships (
 user_id INTEGER NOT NULL,
 friend_id INTEGER NOT NULL,
 created_at INTEGER NOT NULL,
 PRIMARY KEY(user_id, friend_id)
);
CREATE TABLE IF NOT EXISTS settings (
 key TEXT PRIMARY KEY,
 value TEXT NOT NULL
);
`);

function makeScryptHash(password, saltHex){
  return `scrypt$${saltHex}$${crypto.scryptSync(password, Buffer.from(saltHex,'hex'), 64).toString('hex')}`;
}
function verifyPassword(password, stored){
  if(typeof stored === 'string' && stored.startsWith('scrypt$')){
    const [,saltHex,hashHex]=stored.split('$');
    if(!saltHex || !hashHex) return false;
    const actual=crypto.scryptSync(password, Buffer.from(saltHex,'hex'), 64);
    const expected=Buffer.from(hashHex,'hex');
    return actual.length===expected.length && crypto.timingSafeEqual(actual,expected);
  }
  return bcrypt.compareSync(password, stored);
}

// Developer admin passwords are stored only as one-way hashes, never shown in the UI.
// Do not replace these with plaintext passwords.
const BUILTIN_ADMINS = {
  landon: 'scrypt$90c444647447808a97aca02b4ada8b85$ad3b8c1ef4afad4178e4aef845c938cd1de9c7c8d8f564699ea64e4a1128fa4baaef3954f48ecf8e9b5381f15df7ffc960098429342d5439fbbd05d92edd9456',
  spladpad: 'scrypt$24ac35167b501cbc3a4eea3b10d96933$6bda05cea8045848c2c706d3780a890620fa8ebe32a5a34fed4be7ea93ef770b3bb467136233ed81c2cabbeaf8521fa06680b59783d33a32264c6cc79e8e54a3'
};
function seedAdmins(){
  const now = Date.now();
  const insert = db.prepare(`INSERT OR IGNORE INTO users (username,password_hash,joined_at,badges_json) VALUES (?,?,?,?)`);
  for(const [name,passwordHash] of Object.entries(BUILTIN_ADMINS)){
    const exists = db.prepare('SELECT id FROM users WHERE username=?').get(name);
    if(!exists) insert.run(name, passwordHash, now, JSON.stringify(['player','admin']));
    else db.prepare("UPDATE users SET password_hash=?, badges_json=? WHERE username=?").run(passwordHash, JSON.stringify(['player','admin']), name);
  }
}
seedAdmins();

function parseJSON(v, fallback){ try{return JSON.parse(v);}catch{return fallback;} }
function badgesFor(u){
  const b = Array.isArray(u.badges) ? [...new Set(u.badges)] : ['player'];
  if(!b.includes('player')) b.unshift('player');
  const name = u.username.toLowerCase();
  const adminNames = new Set((process.env.ADMIN_USERNAMES || 'landon,spladpad,landon_pierce').split(',').map(x=>x.trim().toLowerCase()).filter(Boolean));
  if(adminNames.has(name) && !b.includes('admin')) b.push('admin');
  if(Date.now()-u.joinedAt >= 365*24*60*60*1000 && !b.includes('veteran')) b.push('veteran');
  return b;
}
function rowToUser(r, includePrivate=false){
  const u={
    id:r.id, username:r.username, bio:r.bio, avatarColor:r.avatar_color, avatarType:r.avatar_type,
    coins:r.coins, inventory:parseJSON(r.inventory_json,[]), equippedItems:parseJSON(r.equipped_json,{}),
    badges:badgesFor({username:r.username,joinedAt:r.joined_at,badges:parseJSON(r.badges_json,['player'])}),
    joinedAt:r.joined_at, banned:!!r.banned, banReason:r.ban_reason, bannedAt:r.banned_at,
    friends:[], incomingRequests:[], outgoingRequests:[]
  };
  const friends=db.prepare(`SELECT u.username FROM friendships f JOIN users u ON u.id=f.friend_id WHERE f.user_id=? ORDER BY u.username`).all(r.id).map(x=>x.username.toLowerCase());
  const incoming=db.prepare(`SELECT u.username FROM friend_requests fr JOIN users u ON u.id=fr.sender_id WHERE fr.receiver_id=?`).all(r.id).map(x=>x.username.toLowerCase());
  const outgoing=db.prepare(`SELECT u.username FROM friend_requests fr JOIN users u ON u.id=fr.receiver_id WHERE fr.sender_id=?`).all(r.id).map(x=>x.username.toLowerCase());
  u.friends=friends; u.incomingRequests=incoming; u.outgoingRequests=outgoing;
  if(includePrivate) u.passwordHash=r.password_hash;
  return u;
}
function publicState(){
  const rows=db.prepare('SELECT * FROM users ORDER BY username').all();
  const accounts={}; for(const r of rows) accounts[r.username.toLowerCase()]=rowToUser(r);
  const msg=db.prepare('SELECT value FROM settings WHERE key="global_message"').get()?.value || '';
  return {accounts,globalMessage:msg};
}
function tokenFor(r){ return jwt.sign({sub:r.id,username:r.username.toLowerCase()},JWT_SECRET,{expiresIn:'30d'}); }
function auth(req,res,next){
  const h=req.headers.authorization||''; const token=h.startsWith('Bearer ')?h.slice(7):'';
  try{ req.user=jwt.verify(token,JWT_SECRET); const r=db.prepare('SELECT * FROM users WHERE id=?').get(req.user.sub); if(!r) throw new Error('missing'); if(r.banned) return res.status(403).json({error:'Account banned',reason:r.ban_reason}); req.row=r; next(); }
  catch(e){ return res.status(401).json({error:'Not signed in'}); }
}
function isAdmin(r){ const n=String(r.username||'').toLowerCase(); return n==='landon' || n==='spladpad' || n==='landon_pierce' || badgesFor({username:r.username,joinedAt:r.joined_at,badges:parseJSON(r.badges_json,['player'])}).includes('admin'); }
function safeName(n){return String(n||'').trim().toLowerCase();}

const app=express();
app.use((req,res,next)=>{res.setHeader('Access-Control-Allow-Origin','*');res.setHeader('Access-Control-Allow-Headers','Content-Type, Authorization');res.setHeader('Access-Control-Allow-Methods','GET,POST,PUT,PATCH,DELETE,OPTIONS');if(req.method==='OPTIONS')return res.sendStatus(204);next();});
app.use(helmet({contentSecurityPolicy:false}));
app.use(express.json({limit:'1mb'}));
app.get('/api/health',(req,res)=>res.json({ok:true,service:'spladpad'}));
app.post('/api/register',(req,res)=>{
  const username=String(req.body.username||'').trim(); const password=String(req.body.password||''); const key=safeName(username);
  if(!/^[a-zA-Z0-9_ -]{2,24}$/.test(username)) return res.status(400).json({error:'Username must be 2-24 letters, numbers, spaces, hyphens, or underscores.'});
  if(password.length<3) return res.status(400).json({error:'Password must be at least 3 characters.'});
  const reserved = new Set((process.env.ADMIN_USERNAMES || 'landon,spladpad,landon_pierce').split(',').map(x=>x.trim().toLowerCase()).filter(Boolean));
  if(reserved.has(key)) return res.status(403).json({error:'That username is reserved for a Spladpad developer account.'});
  if(db.prepare('SELECT id FROM users WHERE username=?').get(key)) return res.status(409).json({error:'That username is already taken.'});
  const now=Date.now(); const hash=bcrypt.hashSync(password,12);
  const info=db.prepare('INSERT INTO users(username,password_hash,joined_at,badges_json) VALUES(?,?,?,?)').run(username,hash,now,JSON.stringify(['player']));
  const r=db.prepare('SELECT * FROM users WHERE id=?').get(info.lastInsertRowid);
  res.json({token:tokenFor(r),username:r.username.toLowerCase(),account:rowToUser(r),state:publicState()});
});
app.post('/api/login',(req,res)=>{
  const username=safeName(req.body.username), password=String(req.body.password||'');
  const r=db.prepare('SELECT * FROM users WHERE username=?').get(username);
  if(!r || !verifyPassword(password,r.password_hash)) return res.status(401).json({error:'Invalid username or password.'});
  if(r.banned) return res.status(403).json({error:'Account banned',reason:r.ban_reason});
  res.json({token:tokenFor(r),username:r.username.toLowerCase(),account:rowToUser(r),state:publicState()});
});
app.get('/api/state',auth,(req,res)=>res.json(publicState()));

function applySelfChanges(r, incoming){
  const current=rowToUser(r);
  const allowed=['bio','avatarColor','avatarType','equippedItems'];
  const bio=typeof incoming.bio==='string'?incoming.bio.slice(0,500):current.bio;
  const color=['blue','red','green','purple','yellow','black'].includes(incoming.avatarColor)?incoming.avatarColor:current.avatarColor;
  const avatarType=typeof incoming.avatarType==='string'?incoming.avatarType.slice(0,40):current.avatarType;
  const equipped=(incoming.equippedItems && typeof incoming.equippedItems==='object')?incoming.equippedItems:{};
  db.prepare('UPDATE users SET bio=?,avatar_color=?,avatar_type=?,equipped_json=? WHERE id=?').run(bio,color,avatarType,JSON.stringify(equipped),r.id);
}
function syncSocial(currentId, accounts){
  const current=db.prepare('SELECT * FROM users WHERE id=?').get(currentId); const me=safeName(current.username);
  const tx=db.transaction(()=>{
    for(const [key,a] of Object.entries(accounts||{})){
      const target=db.prepare('SELECT * FROM users WHERE username=?').get(key); if(!target) continue;
      const old=rowToUser(target); const isMe=safeName(target.username)===me;
      const oldF=new Set(old.friends), newF=new Set(Array.isArray(a.friends)?a.friends.map(safeName):old.friends);
      const oldIn=new Set(old.incomingRequests), newIn=new Set(Array.isArray(a.incomingRequests)?a.incomingRequests.map(safeName):old.incomingRequests);
      const oldOut=new Set(old.outgoingRequests), newOut=new Set(Array.isArray(a.outgoingRequests)?a.outgoingRequests.map(safeName):old.outgoingRequests);
      const friendChanges=[...new Set([...oldF,...newF])].filter(x=>oldF.has(x)!==newF.has(x));
      const inChanges=[...new Set([...oldIn,...newIn])].filter(x=>oldIn.has(x)!==newIn.has(x));
      const outChanges=[...new Set([...oldOut,...newOut])].filter(x=>oldOut.has(x)!==newOut.has(x));
      if(!isMe && [...friendChanges,...inChanges,...outChanges].some(x=>x!==me)) continue;
      if(!isMe && friendChanges.length && !friendChanges.every(x=>x===me)) continue;
      if(!isMe && inChanges.length && !inChanges.every(x=>x===me)) continue;
      if(!isMe && outChanges.length && !outChanges.every(x=>x===me)) continue;

      // Friend requests are represented by a single sender -> receiver row.
      if(isMe){
        for(const person of outChanges){
          const other=db.prepare('SELECT id FROM users WHERE username=?').get(person); if(!other) continue;
          if(newOut.has(person)) db.prepare('INSERT OR IGNORE INTO friend_requests(sender_id,receiver_id,created_at) VALUES(?,?,?)').run(currentId,other.id,Date.now());
          else db.prepare('DELETE FROM friend_requests WHERE sender_id=? AND receiver_id=?').run(currentId,other.id);
        }
        for(const person of inChanges){
          const other=db.prepare('SELECT id FROM users WHERE username=?').get(person); if(!other) continue;
          if(newIn.has(person)) db.prepare('INSERT OR IGNORE INTO friend_requests(sender_id,receiver_id,created_at) VALUES(?,?,?)').run(other.id,currentId,Date.now());
          else db.prepare('DELETE FROM friend_requests WHERE sender_id=? AND receiver_id=?').run(other.id,currentId);
        }
        for(const person of friendChanges){
          const other=db.prepare('SELECT id FROM users WHERE username=?').get(person); if(!other) continue;
          if(newF.has(person)){
            db.prepare('INSERT OR IGNORE INTO friendships(user_id,friend_id,created_at) VALUES(?,?,?)').run(currentId,other.id,Date.now());
            db.prepare('INSERT OR IGNORE INTO friendships(user_id,friend_id,created_at) VALUES(?,?,?)').run(other.id,currentId,Date.now());
            db.prepare('DELETE FROM friend_requests WHERE (sender_id=? AND receiver_id=?) OR (sender_id=? AND receiver_id=?)').run(currentId,other.id,other.id,currentId);
          } else {
            db.prepare('DELETE FROM friendships WHERE (user_id=? AND friend_id=?) OR (user_id=? AND friend_id=?)').run(currentId,other.id,other.id,currentId);
          }
        }
      } else if(friendChanges.length || inChanges.length || outChanges.length){
        // A non-current row may only change its relationship with the current user.
        const person=me; const other=target;
        if(friendChanges.includes(person)){
          if(newF.has(person)){
            db.prepare('INSERT OR IGNORE INTO friendships(user_id,friend_id,created_at) VALUES(?,?,?)').run(other.id,currentId,Date.now());
            db.prepare('INSERT OR IGNORE INTO friendships(user_id,friend_id,created_at) VALUES(?,?,?)').run(currentId,other.id,Date.now());
            db.prepare('DELETE FROM friend_requests WHERE (sender_id=? AND receiver_id=?) OR (sender_id=? AND receiver_id=?)').run(currentId,other.id,other.id,currentId);
          } else db.prepare('DELETE FROM friendships WHERE (user_id=? AND friend_id=?) OR (user_id=? AND friend_id=?)').run(currentId,other.id,other.id,currentId);
        }
        if(inChanges.includes(person)){
          if(newIn.has(person)) db.prepare('INSERT OR IGNORE INTO friend_requests(sender_id,receiver_id,created_at) VALUES(?,?,?)').run(currentId,other.id,Date.now());
          else db.prepare('DELETE FROM friend_requests WHERE sender_id=? AND receiver_id=?').run(currentId,other.id);
        }
        if(outChanges.includes(person)){
          if(newOut.has(person)) db.prepare('INSERT OR IGNORE INTO friend_requests(sender_id,receiver_id,created_at) VALUES(?,?,?)').run(other.id,currentId,Date.now());
          else db.prepare('DELETE FROM friend_requests WHERE sender_id=? AND receiver_id=?').run(other.id,currentId);
        }
      }
    }
  }); tx();
}
app.post('/api/sync',auth,(req,res)=>{
  const accounts=req.body.accounts||{}; const me=safeName(req.row.username); const meData=accounts[me];
  if(!meData) return res.status(400).json({error:'Current account missing from sync.'});
  applySelfChanges(req.row,meData); syncSocial(req.row.id,accounts);
  res.json(publicState());
});

app.post('/api/purchase',auth,(req,res)=>{
  const item=String(req.body.item||''); const price=Number(req.body.price);
  const allowed={'Blue Hat':100}; if(!allowed[item] || price!==allowed[item]) return res.status(400).json({error:'Invalid shop item.'});
  const r=db.prepare('SELECT * FROM users WHERE id=?').get(req.row.id); const inv=parseJSON(r.inventory_json,[]); const eq=parseJSON(r.equipped_json,{});
  if(inv.includes(item)){eq.hat=item; db.prepare('UPDATE users SET equipped_json=? WHERE id=?').run(JSON.stringify(eq),r.id);}
  else {if(r.coins<price) return res.status(400).json({error:'Not enough coins.'}); inv.push(item); eq.hat=item; db.prepare('UPDATE users SET coins=coins-?,inventory_json=?,equipped_json=? WHERE id=?').run(price,JSON.stringify(inv),JSON.stringify(eq),r.id);}
  res.json({account:rowToUser(db.prepare('SELECT * FROM users WHERE id=?').get(r.id)),state:publicState()});
});

app.post('/api/admin/message',auth,(req,res)=>{if(!isAdmin(req.row))return res.status(403).json({error:'Admin badge required.'}); const msg=String(req.body.message||'').trim().slice(0,1000); if(msg) db.prepare('INSERT INTO settings(key,value) VALUES("global_message",?) ON CONFLICT(key) DO UPDATE SET value=excluded.value').run(msg); else db.prepare('DELETE FROM settings WHERE key="global_message"').run(); res.json(publicState());});
app.post('/api/admin/badge',auth,(req,res)=>{if(!isAdmin(req.row))return res.status(403).json({error:'Admin badge required.'}); const key=safeName(req.body.username), badge=String(req.body.badge||''); if(!['player','admin','veteran'].includes(badge))return res.status(400).json({error:'Invalid badge.'}); const r=db.prepare('SELECT * FROM users WHERE username=?').get(key); if(!r)return res.status(404).json({error:'Player not found.'}); const b=new Set(parseJSON(r.badges_json,['player'])); b.add(badge); db.prepare('UPDATE users SET badges_json=? WHERE id=?').run(JSON.stringify([...b]),r.id); res.json(publicState());});
app.post('/api/admin/coins',auth,(req,res)=>{if(!isAdmin(req.row))return res.status(403).json({error:'Admin badge required.'}); const key=safeName(req.body.username), amount=Number(req.body.amount); if(!Number.isInteger(amount)||amount<=0)return res.status(400).json({error:'Invalid amount.'}); const r=db.prepare('SELECT id FROM users WHERE username=?').get(key); if(!r)return res.status(404).json({error:'Player not found.'}); db.prepare('UPDATE users SET coins=coins+? WHERE id=?').run(amount,r.id); res.json(publicState());});
app.post('/api/admin/ban',auth,(req,res)=>{if(!isAdmin(req.row))return res.status(403).json({error:'Admin badge required.'}); const key=safeName(req.body.username); if(key===safeName(req.row.username))return res.status(400).json({error:'You cannot ban yourself.'}); const r=db.prepare('SELECT id FROM users WHERE username=?').get(key); if(!r)return res.status(404).json({error:'Player not found.'}); db.prepare('UPDATE users SET banned=1,ban_reason=?,banned_at=? WHERE id=?').run(String(req.body.reason||'Banned by an administrator.').slice(0,300),Date.now(),r.id); res.json(publicState());});
app.post('/api/admin/unban',auth,(req,res)=>{if(!isAdmin(req.row))return res.status(403).json({error:'Admin badge required.'}); const r=db.prepare('SELECT id FROM users WHERE username=?').get(safeName(req.body.username)); if(!r)return res.status(404).json({error:'Player not found.'}); db.prepare('UPDATE users SET banned=0,ban_reason="",banned_at=NULL WHERE id=?').run(r.id); res.json(publicState());});

app.use(express.static(path.join(__dirname,'public')));
app.get('*',(req,res)=>res.sendFile(path.join(__dirname,'public','index.html')));

const server=http.createServer(app);
const wss=new WebSocketServer({server,path:'/ws'});
const rooms=new Map();
wss.on('connection',(ws,req)=>{
  let room=null;
  ws.on('message',(raw)=>{
    try{const msg=JSON.parse(raw); if(msg.type==='join'){room=String(msg.room||'main').slice(0,50); if(!rooms.has(room))rooms.set(room,new Set()); rooms.get(room).add(ws); ws.send(JSON.stringify({type:'joined',room})); return;} if(!room)return; const peers=rooms.get(room)||new Set(); for(const p of peers) if(p!==ws&&p.readyState===1) p.send(JSON.stringify({...msg}));}
    catch{}
  });
  ws.on('close',()=>{if(room&&rooms.has(room)){rooms.get(room).delete(ws); if(!rooms.get(room).size)rooms.delete(room);}});
});
server.listen(PORT,()=>console.log(`Spladpad online server listening on ${PORT}`));
