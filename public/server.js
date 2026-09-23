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

if (JWT_SECRET === 'CHANGE_ME_BEFORE_PUBLIC_DEPLOYMENT') {
  console.warn('WARNING: set JWT_SECRET before deploying publicly.');
}

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

CREATE TABLE IF NOT EXISTS published_worlds (
 world_id TEXT PRIMARY KEY,
 owner_id INTEGER NOT NULL,
 name TEXT NOT NULL,
 thumbnail TEXT NOT NULL DEFAULT '',
 world_json TEXT NOT NULL,
 published_at INTEGER NOT NULL,
 updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS game_servers (
 server_id TEXT PRIMARY KEY,
 world_id TEXT NOT NULL,
 owner_id INTEGER NOT NULL,
 server_name TEXT NOT NULL,
 max_players INTEGER NOT NULL DEFAULT 12,
 created_at INTEGER NOT NULL,
 last_active_at INTEGER NOT NULL
);
`);

function makeScryptHash(password, saltHex) {
  return `scrypt$${saltHex}$${crypto
    .scryptSync(password, Buffer.from(saltHex, 'hex'), 64)
    .toString('hex')}`;
}

function verifyPassword(password, stored) {
  if (typeof stored === 'string' && stored.startsWith('scrypt$')) {
    const [, saltHex, hashHex] = stored.split('$');

    if (!saltHex || !hashHex) return false;

    const actual = crypto.scryptSync(
      password,
      Buffer.from(saltHex, 'hex'),
      64
    );

    const expected = Buffer.from(hashHex, 'hex');

    return (
      actual.length === expected.length &&
      crypto.timingSafeEqual(actual, expected)
    );
  }

  return bcrypt.compareSync(password, stored);
}

/*
  Built-in admins use environment-provided password hashes.
  Set these in Render environment variables if you use built-in accounts.
*/
const BUILTIN_ADMINS = {};

function seedAdmins() {
  const now = Date.now();

  const insert = db.prepare(`
    INSERT OR IGNORE INTO users
    (username, password_hash, joined_at, badges_json)
    VALUES (?, ?, ?, ?)
  `);

  for (const [name, passwordHash] of Object.entries(BUILTIN_ADMINS)) {
    const exists = db
      .prepare('SELECT id FROM users WHERE username=?')
      .get(name);

    if (!exists) {
      insert.run(
        name,
        passwordHash,
        now,
        JSON.stringify(['player', 'admin'])
      );
    } else {
      db.prepare(`
        UPDATE users
        SET password_hash=?, badges_json=?
        WHERE username=?
      `).run(
        passwordHash,
        JSON.stringify(['player', 'admin']),
        name
      );
    }
  }
}

seedAdmins();

function parseJSON(value, fallback) {
  try {
    return JSON.parse(value);
  } catch {
    return fallback;
  }
}

function badgesFor(u) {
  const badges = Array.isArray(u.badges)
    ? [...new Set(u.badges)]
    : ['player'];

  if (!badges.includes('player')) {
    badges.unshift('player');
  }

  const name = String(u.username || '').toLowerCase();

  const adminNames = new Set(
    (
      process.env.ADMIN_USERNAMES ||
      'landon,spladpad,landon_pierce,player1'
    )
      .split(',')
      .map(x => x.trim().toLowerCase())
      .filter(Boolean)
  );

  if (
    adminNames.has(name) &&
    !badges.includes('admin')
  ) {
    badges.push('admin');
  }

  if (
    Date.now() - Number(u.joinedAt) >=
      365 * 24 * 60 * 60 * 1000 &&
    !badges.includes('veteran')
  ) {
    badges.push('veteran');
  }

  return badges;
}

function rowToUser(r, includePrivate = false) {
  const user = {
    id: r.id,
    playerNumber: 'SP' + String(r.id).padStart(6, '0'),
    username: r.username,
    bio: r.bio,
    avatarColor: r.avatar_color,
    avatarType: r.avatar_type,
    coins: r.coins,
    inventory: parseJSON(r.inventory_json, []),
    equippedItems: parseJSON(r.equipped_json, {}),
    badges: badgesFor({
      username: r.username,
      joinedAt: r.joined_at,
      badges: parseJSON(r.badges_json, ['player'])
    }),
    joinedAt: r.joined_at,
    banned: !!r.banned,
    banReason: r.ban_reason,
    bannedAt: r.banned_at,
    friends: [],
    incomingRequests: [],
    outgoingRequests: []
  };

  const friends = db.prepare(`
    SELECT u.username
    FROM friendships f
    JOIN users u ON u.id=f.friend_id
    WHERE f.user_id=?
    ORDER BY u.username
  `)
    .all(r.id)
    .map(x => x.username.toLowerCase());

  const incoming = db.prepare(`
    SELECT u.username
    FROM friend_requests fr
    JOIN users u ON u.id=fr.sender_id
    WHERE fr.receiver_id=?
  `)
    .all(r.id)
    .map(x => x.username.toLowerCase());

  const outgoing = db.prepare(`
    SELECT u.username
    FROM friend_requests fr
    JOIN users u ON u.id=fr.receiver_id
    WHERE fr.sender_id=?
  `)
    .all(r.id)
    .map(x => x.username.toLowerCase());

  user.friends = friends;
  user.incomingRequests = incoming;
  user.outgoingRequests = outgoing;

  if (includePrivate) {
    user.passwordHash = r.password_hash;
  }

  return user;
}

function publicState() {
  const rows = db
    .prepare('SELECT * FROM users ORDER BY username')
    .all();

  const accounts = {};

  for (const r of rows) {
    accounts[r.username.toLowerCase()] = rowToUser(r);
  }

  const msg =
    db.prepare(
      'SELECT value FROM settings WHERE key="global_message"'
    ).get()?.value || '';

  return {
    accounts,
    globalMessage: msg
  };
}

function tokenFor(r) {
  return jwt.sign(
    {
      sub: r.id,
      username: r.username.toLowerCase()
    },
    JWT_SECRET,
    {
      expiresIn: '30d'
    }
  );
}

function auth(req, res, next) {
  const header = req.headers.authorization || '';

  const token = header.startsWith('Bearer ')
    ? header.slice(7)
    : '';

  try {
    req.user = jwt.verify(token, JWT_SECRET);

    const r = db
      .prepare('SELECT * FROM users WHERE id=?')
      .get(req.user.sub);

    if (!r) {
      throw new Error('missing');
    }

    if (r.banned) {
      return res.status(403).json({
        error: 'Account banned',
        reason: r.ban_reason
      });
    }

    req.row = r;
    next();
  } catch {
    return res.status(401).json({
      error: 'Not signed in'
    });
  }
}

function isAdmin(r) {
  const name = String(r.username || '').toLowerCase();

  const adminNames = new Set(
    (
      process.env.ADMIN_USERNAMES ||
      'landon,spladpad,landon_pierce,player1'
    )
      .split(',')
      .map(x => x.trim().toLowerCase())
      .filter(Boolean)
  );

  return adminNames.has(name) ||
    badgesFor({
      username: r.username,
      joinedAt: r.joined_at,
      badges: parseJSON(r.badges_json, ['player'])
    }).includes('admin');
}

function safeName(n) {
  return String(n || '')
    .trim()
    .toLowerCase();
}

const app = express();

app.use((req, res, next) => {
  res.setHeader(
    'Access-Control-Allow-Origin',
    '*'
  );

  res.setHeader(
    'Access-Control-Allow-Headers',
    'Content-Type, Authorization'
  );

  res.setHeader(
    'Access-Control-Allow-Methods',
    'GET,POST,PUT,PATCH,DELETE,OPTIONS'
  );

  if (req.method === 'OPTIONS') {
    return res.sendStatus(204);
  }

  next();
});

app.use(
  helmet({
    contentSecurityPolicy: false
  })
);

app.use(
  express.json({
    limit: '1mb'
  })
);

app.get('/api/health', (req, res) => {
  res.json({
    ok: true,
    service: 'spladpad'
  });
});

app.post('/api/register', (req, res) => {
  const username = String(
    req.body.username || ''
  ).trim();

  const password = String(
    req.body.password || ''
  );

  const key = safeName(username);

  if (
    !/^[a-zA-Z0-9_ -]{2,24}$/.test(username)
  ) {
    return res.status(400).json({
      error:
        'Username must be 2-24 letters, numbers, spaces, hyphens, or underscores.'
    });
  }

  if (password.length < 3) {
    return res.status(400).json({
      error:
        'Password must be at least 3 characters.'
    });
  }

  const reserved = new Set(
    (
      process.env.ADMIN_USERNAMES ||
      'landon,spladpad,landon_pierce,player1'
    )
      .split(',')
      .map(x => x.trim().toLowerCase())
      .filter(Boolean)
  );

  if (reserved.has(key)) {
    return res.status(403).json({
      error:
        'That username is reserved for a Spladpad developer account.'
    });
  }

  if (
    db.prepare(
      'SELECT id FROM users WHERE username=?'
    ).get(key)
  ) {
    return res.status(409).json({
      error:
        'That username is already taken.'
    });
  }

  const now = Date.now();
  const hash = bcrypt.hashSync(
    password,
    12
  );

  const info = db.prepare(`
    INSERT INTO users
    (username,password_hash,joined_at,badges_json)
    VALUES(?,?,?,?)
  `).run(
    username,
    hash,
    now,
    JSON.stringify(['player'])
  );

  const r = db
    .prepare(
      'SELECT * FROM users WHERE id=?'
    )
    .get(info.lastInsertRowid);

  res.json({
    token: tokenFor(r),
    username: r.username.toLowerCase(),
    account: rowToUser(r),
    state: publicState()
  });
});

app.post('/api/login', (req, res) => {
  const username = safeName(
    req.body.username
  );

  const password = String(
    req.body.password || ''
  );

  const r = db
    .prepare(
      'SELECT * FROM users WHERE username=?'
    )
    .get(username);

  if (
    !r ||
    !verifyPassword(
      password,
      r.password_hash
    )
  ) {
    return res.status(401).json({
      error: 'Invalid username or password.'
    });
  }

  if (r.banned) {
    return res.status(403).json({
      error: 'Account banned',
      reason: r.ban_reason
    });
  }

  res.json({
    token: tokenFor(r),
    username: r.username.toLowerCase(),
    account: rowToUser(r),
    state: publicState()
  });
});

app.get('/api/state', auth, (req, res) => {
  res.json(publicState());
});

app.get('/api/players', auth, (req, res) => {
  const q = String(
    req.query.q || ''
  ).trim().toLowerCase();

  const rows = db
    .prepare(
      'SELECT * FROM users ORDER BY username'
    )
    .all();

  const players = rows
    .map(r => rowToUser(r))
    .filter(user => {
      return (
        !q ||
        user.username
          .toLowerCase()
          .includes(q) ||
        user.playerNumber
          .toLowerCase()
          .includes(q)
      );
    });

  res.json({
    players
  });
});

function applySelfChanges(r, incoming) {
  const current = rowToUser(r);

  const bio =
    typeof incoming.bio === 'string'
      ? incoming.bio.slice(0, 500)
      : current.bio;

  const color =
    [
      'blue',
      'red',
      'green',
      'purple',
      'yellow',
      'black'
    ].includes(incoming.avatarColor)
      ? incoming.avatarColor
      : current.avatarColor;

  const avatarType =
    typeof incoming.avatarType === 'string'
      ? incoming.avatarType.slice(0, 40)
      : current.avatarType;

  const equipped =
    incoming.equippedItems &&
    typeof incoming.equippedItems === 'object'
      ? incoming.equippedItems
      : {};

  db.prepare(`
    UPDATE users
    SET
      bio=?,
      avatar_color=?,
      avatar_type=?,
      equipped_json=?
    WHERE id=?
  `).run(
    bio,
    color,
    avatarType,
    JSON.stringify(equipped),
    r.id
  );
}

function syncSocial(currentId, accounts) {
  const current = db
    .prepare('SELECT * FROM users WHERE id=?')
    .get(currentId);

  const me = safeName(
    current.username
  );

  const tx = db.transaction(() => {
    for (
      const [key, a] of Object.entries(
        accounts || {}
      )
    ) {
      const target = db
        .prepare(
          'SELECT * FROM users WHERE username=?'
        )
        .get(key);

      if (!target) continue;

      const old = rowToUser(target);

      const isMe =
        safeName(target.username) === me;

      const oldF = new Set(old.friends);

      const newF = new Set(
        Array.isArray(a.friends)
          ? a.friends.map(safeName)
          : old.friends
      );

      const oldIn = new Set(
        old.incomingRequests
      );

      const newIn = new Set(
        Array.isArray(a.incomingRequests)
          ? a.incomingRequests.map(safeName)
          : old.incomingRequests
      );

      const oldOut = new Set(
        old.outgoingRequests
      );

      const newOut = new Set(
        Array.isArray(a.outgoingRequests)
          ? a.outgoingRequests.map(safeName)
          : old.outgoingRequests
      );

      const friendChanges = [
        ...new Set([
          ...oldF,
          ...newF
        ])
      ].filter(
        x => oldF.has(x) !== newF.has(x)
      );

      const inChanges = [
        ...new Set([
          ...oldIn,
          ...newIn
        ])
      ].filter(
        x => oldIn.has(x) !== newIn.has(x)
      );

      const outChanges = [
        ...new Set([
          ...oldOut,
          ...newOut
        ])
      ].filter(
        x => oldOut.has(x) !== newOut.has(x)
      );

      if (
        !isMe &&
        [
          ...friendChanges,
          ...inChanges,
          ...outChanges
        ].some(x => x !== me)
      ) {
        continue;
      }

      if (
        !isMe &&
        friendChanges.length &&
        !friendChanges.every(
          x => x === me
        )
      ) {
        continue;
      }

      if (
        !isMe &&
        inChanges.length &&
        !inChanges.every(
          x => x === me
        )
      ) {
        continue;
      }

      if (
        !isMe &&
        outChanges.length &&
        !outChanges.every(
          x => x === me
        )
      ) {
        continue;
      }

      if (isMe) {
        for (
          const person of outChanges
        ) {
          const other = db
            .prepare(
              'SELECT id FROM users WHERE username=?'
            )
            .get(person);

          if (!other) continue;

          if (newOut.has(person)) {
            db.prepare(`
              INSERT OR IGNORE INTO
              friend_requests
              (sender_id,receiver_id,created_at)
              VALUES(?,?,?)
            `).run(
              currentId,
              other.id,
              Date.now()
            );
          } else {
            db.prepare(`
              DELETE FROM friend_requests
              WHERE sender_id=? AND receiver_id=?
            `).run(
              currentId,
              other.id
            );
          }
        }

        for (
          const person of inChanges
        ) {
          const other = db
            .prepare(
              'SELECT id FROM users WHERE username=?'
            )
            .get(person);

          if (!other) continue;

          if (newIn.has(person)) {
            db.prepare(`
              INSERT OR IGNORE INTO
              friend_requests
              (sender_id,receiver_id,created_at)
              VALUES(?,?,?)
            `).run(
              other.id,
              currentId,
              Date.now()
            );
          } else {
            db.prepare(`
              DELETE FROM friend_requests
              WHERE sender_id=? AND receiver_id=?
            `).run(
              other.id,
              currentId
            );
          }
        }

        for (
          const person of friendChanges
        ) {
          const other = db
            .prepare(
              'SELECT id FROM users WHERE username=?'
            )
            .get(person);

          if (!other) continue;

          if (newF.has(person)) {
            db.prepare(`
              INSERT OR IGNORE INTO friendships
              (user_id,friend_id,created_at)
              VALUES(?,?,?)
            `).run(
              currentId,
              other.id,
              Date.now()
            );

            db.prepare(`
              INSERT OR IGNORE INTO friendships
              (user_id,friend_id,created_at)
              VALUES(?,?,?)
            `).run(
              other.id,
              currentId,
              Date.now()
            );

            db.prepare(`
              DELETE FROM friend_requests
              WHERE
                (sender_id=? AND receiver_id=?)
                OR
                (sender_id=? AND receiver_id=?)
            `).run(
              currentId,
              other.id,
              other.id,
              currentId
            );
          } else {
            db.prepare(`
              DELETE FROM friendships
              WHERE
                (user_id=? AND friend_id=?)
                OR
                (user_id=? AND friend_id=?)
            `).run(
              currentId,
              other.id,
              other.id,
              currentId
            );
          }
        }
      } else if (
        friendChanges.length ||
        inChanges.length ||
        outChanges.length
      ) {
        const person = me;
        const other = target;

        if (friendChanges.includes(person)) {
          if (newF.has(person)) {
            db.prepare(`
              INSERT OR IGNORE INTO friendships
              (user_id,friend_id,created_at)
              VALUES(?,?,?)
            `).run(
              other.id,
              currentId,
              Date.now()
            );

            db.prepare(`
              INSERT OR IGNORE INTO friendships
              (user_id,friend_id,created_at)
              VALUES(?,?,?)
            `).run(
              currentId,
              other.id,
              Date.now()
            );

            db.prepare(`
              DELETE FROM friend_requests
              WHERE
                (sender_id=? AND receiver_id=?)
                OR
                (sender_id=? AND receiver_id=?)
            `).run(
              currentId,
              other.id,
              other.id,
              currentId
            );
          } else {
            db.prepare(`
              DELETE FROM friendships
              WHERE
                (user_id=? AND friend_id=?)
                OR
                (user_id=? AND friend_id=?)
            `).run(
              currentId,
              other.id,
              other.id,
              currentId
            );
          }
        }

        if (inChanges.includes(person)) {
          if (newIn.has(person)) {
            db.prepare(`
              INSERT OR IGNORE INTO
              friend_requests
              (sender_id,receiver_id,created_at)
              VALUES(?,?,?)
            `).run(
              currentId,
              other.id,
              Date.now()
            );
          } else {
            db.prepare(`
              DELETE FROM friend_requests
              WHERE sender_id=? AND receiver_id=?
            `).run(
              currentId,
              other.id
            );
          }
        }

        if (outChanges.includes(person)) {
          if (newOut.has(person)) {
            db.prepare(`
              INSERT OR IGNORE INTO
              friend_requests
              (sender_id,receiver_id,created_at)
              VALUES(?,?,?)
            `).run(
              other.id,
              currentId,
              Date.now()
            );
          } else {
            db.prepare(`
              DELETE FROM friend_requests
              WHERE sender_id=? AND receiver_id=?
            `).run(
              other.id,
              currentId
            );
          }
        }
      }
    }
  });

  tx();
}

app.post('/api/sync', auth, (req, res) => {
  const accounts =
    req.body.accounts || {};

  const me =
    safeName(req.row.username);

  const meData =
    accounts[me];

  if (!meData) {
    return res.status(400).json({
      error:
        'Current account missing from sync.'
    });
  }

  applySelfChanges(
    req.row,
    meData
  );

  syncSocial(
    req.row.id,
    accounts
  );

  res.json(publicState());
});

app.post('/api/purchase', auth, (req, res) => {
  const item = String(
    req.body.item || ''
  );

  const price =
    Number(req.body.price);

  const allowed = {
    'Blue Hat': 100
  };

  if (
    !allowed[item] ||
    price !== allowed[item]
  ) {
    return res.status(400).json({
      error: 'Invalid shop item.'
    });
  }

  const r = db
    .prepare(
      'SELECT * FROM users WHERE id=?'
    )
    .get(req.row.id);

  const inventory =
    parseJSON(
      r.inventory_json,
      []
    );

  const equipped =
    parseJSON(
      r.equipped_json,
      {}
    );

  if (inventory.includes(item)) {
    equipped.hat = item;

    db.prepare(`
      UPDATE users
      SET equipped_json=?
      WHERE id=?
    `).run(
      JSON.stringify(equipped),
      r.id
    );
  } else {
    if (r.coins < price) {
      return res.status(400).json({
        error:
          'Not enough coins.'
      });
    }

    inventory.push(item);
    equipped.hat = item;

    db.prepare(`
      UPDATE users
      SET
        coins=coins-?,
        inventory_json=?,
        equipped_json=?
      WHERE id=?
    `).run(
      price,
      JSON.stringify(inventory),
      JSON.stringify(equipped),
      r.id
    );
  }

  res.json({
    account: rowToUser(
      db.prepare(
        'SELECT * FROM users WHERE id=?'
      ).get(r.id)
    ),
    state: publicState()
  });
});

app.post(
  '/api/admin/message',
  auth,
  (req, res) => {
    if (!isAdmin(req.row)) {
      return res.status(403).json({
        error:
          'Admin badge required.'
      });
    }

    const msg = String(
      req.body.message || ''
    )
      .trim()
      .slice(0, 1000);

    if (msg) {
      db.prepare(`
        INSERT INTO settings(key,value)
        VALUES("global_message",?)
        ON CONFLICT(key)
        DO UPDATE SET value=excluded.value
      `).run(msg);
    } else {
      db.prepare(`
        DELETE FROM settings
        WHERE key="global_message"
      `).run();
    }

    res.json(
      publicState()
    );
  }
);

app.post(
  '/api/admin/badge',
  auth,
  (req, res) => {
    if (!isAdmin(req.row)) {
      return res.status(403).json({
        error:
          'Admin badge required.'
      });
    }

    const key =
      safeName(req.body.username);

    const badge =
      String(req.body.badge || '');

    if (
      ![
        'player',
        'admin',
        'veteran'
      ].includes(badge)
    ) {
      return res.status(400).json({
        error:
          'Invalid badge.'
      });
    }

    const r = db
      .prepare(
        'SELECT * FROM users WHERE username=?'
      )
      .get(key);

    if (!r) {
      return res.status(404).json({
        error:
          'Player not found.'
      });
    }

    const badges = new Set(
      parseJSON(
        r.badges_json,
        ['player']
      )
    );

    badges.add(badge);

    db.prepare(`
      UPDATE users
      SET badges_json=?
      WHERE id=?
    `).run(
      JSON.stringify([
        ...badges
      ]),
      r.id
    );

    res.json(
      publicState()
    );
  }
);

app.post(
  '/api/admin/coins',
  auth,
  (req, res) => {
    if (!isAdmin(req.row)) {
      return res.status(403).json({
        error:
          'Admin badge required.'
      });
    }

    const key =
      safeName(req.body.username);

    const amount =
      Number(req.body.amount);

    if (
      !Number.isInteger(amount) ||
      amount <= 0
    ) {
      return res.status(400).json({
        error:
          'Invalid amount.'
      });
    }

    const r = db
      .prepare(
        'SELECT id FROM users WHERE username=?'
      )
      .get(key);

    if (!r) {
      return res.status(404).json({
        error:
          'Player not found.'
      });
    }

    db.prepare(`
      UPDATE users
      SET coins=coins+?
      WHERE id=?
    `).run(
      amount,
      r.id
    );

    res.json(
      publicState()
    );
  }
);

app.post(
  '/api/admin/ban',
  auth,
  (req, res) => {
    if (!isAdmin(req.row)) {
      return res.status(403).json({
        error:
          'Admin badge required.'
      });
    }

    const key =
      safeName(req.body.username);

    if (
      key ===
      safeName(req.row.username)
    ) {
      return res.status(400).json({
        error:
          'You cannot ban yourself.'
      });
    }

    const r = db
      .prepare(
        'SELECT id FROM users WHERE username=?'
      )
      .get(key);

    if (!r) {
      return res.status(404).json({
        error:
          'Player not found.'
      });
    }

    db.prepare(`
      UPDATE users
      SET
        banned=1,
        ban_reason=?,
        banned_at=?
      WHERE id=?
    `).run(
      String(
        req.body.reason ||
          'Banned by an administrator.'
      ).slice(0, 300),
      Date.now(),
      r.id
    );

    res.json(
      publicState()
    );
  }
);

app.post(
  '/api/admin/unban',
  auth,
  (req, res) => {
    if (!isAdmin(req.row)) {
      return res.status(403).json({
        error:
          'Admin badge required.'
      });
    }

    const r = db
      .prepare(
        'SELECT id FROM users WHERE username=?'
      )
      .get(
        safeName(
          req.body.username
        )
      );

    if (!r) {
      return res.status(404).json({
        error:
          'Player not found.'
      });
    }

    db.prepare(`
      UPDATE users
      SET
        banned=0,
        ban_reason="",
        banned_at=NULL
      WHERE id=?
    `).run(r.id);

    res.json(
      publicState()
    );
  }
);

// =========================
// SPLADPAD CREATOR WORLDS
// + GAME SERVERS
// =========================

function cleanWorld(world) {
  if (
    !world ||
    typeof world !== 'object'
  ) {
    throw new Error(
      'Invalid world.'
    );
  }

  const id =
    String(
      world.id || ''
    ).slice(0, 80);

  if (!id) {
    throw new Error(
      'World ID is required.'
    );
  }

  const name =
    String(
      world.name ||
        'My Spladpad World'
    )
      .trim()
      .slice(0, 80) ||
    'My Spladpad World';

  const thumbnail =
    typeof world.thumbnail === 'string'
      ? world.thumbnail.slice(
          0,
          800000
        )
      : '';

  const scripts =
    world.scripts &&
    typeof world.scripts === 'object'
      ? world.scripts
      : {};

  const objects =
    Array.isArray(world.objects)
      ? world.objects
          .slice(0, 500)
          .map(o => ({
            id: String(
              o.id || ''
            ).slice(0, 80),
            type: String(
              o.type || 'block'
            ).slice(0, 30),
            x: Number(o.x) || 0,
            y: Number(o.y) || 0,
            w: Math.max(
              1,
              Number(o.w) || 50
            ),
            h: Math.max(
              1,
              Number(o.h) || 50
            ),
            color:
              typeof o.color === 'string'
                ? o.color.slice(
                    0,
                    30
                  )
                : '#1688e8',
            anchored:
              !!o.anchored,
            label:
              String(
                o.label || ''
              ).slice(0, 80)
          }))
      : [];

  const connections =
    Array.isArray(
      world.connections
    )
      ? world.connections.slice(
          0,
          1000
        )
      : [];

  return {
    id,
    name,
    published:
      !!world.published,
    thumbnail,
    scripts: {
      html: String(
        scripts.html || ''
      ).slice(
        0,
        200000
      ),
      python: String(
        scripts.python || ''
      ).slice(
        0,
        200000
      )
    },
    objects,
    connections
  };
}

function publishedWorldRow(r) {
  const owner = db
    .prepare(
      'SELECT username FROM users WHERE id=?'
    )
    .get(r.owner_id);

  return {
    id: r.world_id,
    ownerId:
      r.owner_id,
    ownerUsername:
      owner?.username ||
      'Creator',
    name: r.name,
    thumbnail:
      r.thumbnail,
    published: true,
    publishedAt:
      r.published_at,
    updatedAt:
      r.updated_at,
    world: parseJSON(
      r.world_json,
      {}
    )
  };
}

app.get(
  '/api/worlds/published',
  (req, res) => {
    const rows = db
      .prepare(
        'SELECT * FROM published_worlds ORDER BY published_at DESC'
      )
      .all();

    res.json({
      worlds:
        rows.map(
          publishedWorldRow
        )
    });
  }
);

app.post(
  '/api/worlds/publish',
  auth,
  (req, res) => {
    let world;

    try {
      world = cleanWorld(
        req.body.world
      );

      world.published = true;
    } catch (e) {
      return res.status(400).json({
        error: e.message
      });
    }

    const now =
      Date.now();

    db.prepare(`
      INSERT INTO published_worlds
      (
        world_id,
        owner_id,
        name,
        thumbnail,
        world_json,
        published_at,
        updated_at
      )
      VALUES(?,?,?,?,?,?,?)

      ON CONFLICT(world_id)
      DO UPDATE SET
        owner_id=excluded.owner_id,
        name=excluded.name,
        thumbnail=excluded.thumbnail,
        world_json=excluded.world_json,
        updated_at=excluded.updated_at
    `).run(
      world.id,
      req.row.id,
      world.name,
      world.thumbnail,
      JSON.stringify(world),
      now,
      now
    );

    res.json({
      world: publishedWorldRow(
        db.prepare(
          'SELECT * FROM published_worlds WHERE world_id=?'
        ).get(world.id)
      )
    });
  }
);

app.post(
  '/api/worlds/unpublish',
  auth,
  (req, res) => {
    const id =
      String(
        req.body.worldId || ''
      );

    const r = db
      .prepare(
        'SELECT owner_id FROM published_worlds WHERE world_id=?'
      )
      .get(id);

    if (!r) {
      return res.status(404).json({
        error:
          'Published world not found.'
      });
    }

    if (
      r.owner_id !== req.row.id &&
      !isAdmin(req.row)
    ) {
      return res.status(403).json({
        error:
          'Only the owner can unpublish this world.'
      });
    }

    db.prepare(`
      DELETE FROM published_worlds
      WHERE world_id=?
    `).run(id);

    db.prepare(`
      DELETE FROM game_servers
      WHERE world_id=?
    `).run(id);

    for (
      const [sid, room] of liveServers
    ) {
      if (room.worldId === id) {
        for (
          const client of room.clients
        ) {
          try {
            client.ws.send(
              JSON.stringify({
                type:
                  'server:closed',
                reason:
                  'World unpublished'
              })
            );

            client.ws.close();
          } catch {}
        }

        liveServers.delete(
          sid
        );
      }
    }

    res.json({
      ok: true
    });
  }
);

function serverSummary(r) {
  const room =
    liveServers.get(
      r.server_id
    );

  return {
    id:
      r.server_id,
    worldId:
      r.world_id,
    name:
      r.server_name,
    maxPlayers:
      r.max_players,
    players:
      room
        ? room.clients.size
        : 0,
    ownerId:
      r.owner_id,
    createdAt:
      r.created_at
  };
}

const liveServers =
  new Map();

function makeServerId() {
  return crypto
    .randomBytes(5)
    .toString('hex');
}

app.get(
  '/api/servers',
  (req, res) => {
    const worldId =
      String(
        req.query.worldId || ''
      );

    const rows =
      worldId
        ? db.prepare(`
            SELECT *
            FROM game_servers
            WHERE world_id=?
            ORDER BY created_at DESC
          `).all(worldId)
        : db.prepare(`
            SELECT *
            FROM game_servers
            ORDER BY created_at DESC
          `).all();

    res.json({
      servers:
        rows.map(
          serverSummary
        )
    });
  }
);

app.post(
  '/api/servers/create',
  auth,
  (req, res) => {
    const worldId =
      String(
        req.body.worldId || ''
      );

    const world =
      db.prepare(`
        SELECT *
        FROM published_worlds
        WHERE world_id=?
      `).get(worldId);

    if (!world) {
      return res.status(404).json({
        error:
          'Publish the game before creating a server.'
      });
    }

    let maxPlayers =
      Math.floor(
        Number(
          req.body.maxPlayers ||
            12
        )
      );

    if (
      !Number.isFinite(
        maxPlayers
      )
    ) {
      maxPlayers = 12;
    }

    maxPlayers =
      Math.max(
        2,
        Math.min(
          24,
          maxPlayers
        )
      );

    const serverId =
      makeServerId();

    const name =
      String(
        req.body.name ||
          'Spladpad Server'
      )
        .trim()
        .slice(0, 50) ||
      'Spladpad Server';

    const now =
      Date.now();

    db.prepare(`
      INSERT INTO game_servers
      (
        server_id,
        world_id,
        owner_id,
        server_name,
        max_players,
        created_at,
        last_active_at
      )
      VALUES(?,?,?,?,?,?,?)
    `).run(
      serverId,
      worldId,
      req.row.id,
      name,
      maxPlayers,
      now,
      now
    );

    liveServers.set(
      serverId,
      {
        worldId,
        ownerId:
          req.row.id,
        clients:
          new Set(),
        createdAt:
          now
      }
    );

    res.json({
      server:
        serverSummary(
          db.prepare(`
            SELECT *
            FROM game_servers
            WHERE server_id=?
          `).get(serverId)
        )
    });
  }
);

app.post(
  '/api/servers/close',
  auth,
  (req, res) => {
    const id =
      String(
        req.body.serverId || ''
      );

    const r =
      db.prepare(`
        SELECT *
        FROM game_servers
        WHERE server_id=?
      `).get(id);

    if (!r) {
      return res.status(404).json({
        error:
          'Server not found.'
      });
    }

    if (
      r.owner_id !== req.row.id &&
      !isAdmin(req.row)
    ) {
      return res.status(403).json({
        error:
          'Only the server owner can close this server.'
      });
    }

    const room =
      liveServers.get(
        id
      );

    if (room) {
      for (
        const client of room.clients
      ) {
        try {
          client.ws.send(
            JSON.stringify({
              type:
                'server:closed',
              reason:
                'Server closed by owner'
            })
          );

          client.ws.close();
        } catch {}
      }

      liveServers.delete(
        id
      );
    }

    db.prepare(`
      DELETE FROM game_servers
      WHERE server_id=?
    `).run(id);

    res.json({
      ok: true
    });
  }
);

app.use(
  express.static(
    path.join(
      __dirname,
      'public'
    )
  )
);

app.get('*', (req, res) => {
  res.sendFile(
    path.join(
      __dirname,
      'public',
      'index.html'
    )
  );
});

const server =
  http.createServer(app);

const wss =
  new WebSocketServer({
    server,
    path: '/ws'
  });

function verifyWsToken(token) {
  try {
    const decoded =
      jwt.verify(
        String(token || ''),
        JWT_SECRET
      );

    const r =
      db.prepare(
        'SELECT * FROM users WHERE id=?'
      ).get(decoded.sub);

    if (
      !r ||
      r.banned
    ) {
      return null;
    }

    return r;
  } catch {
    return null;
  }
}

function broadcastRoom(
  room,
  payload,
  except
) {
  const text =
    JSON.stringify(
      payload
    );

  for (
    const client of room.clients
  ) {
    if (
      client !== except &&
      client.ws.readyState === 1
    ) {
      client.ws.send(
        text
      );
    }
  }
}

function roomState(room) {
  return [
    ...room.clients
  ].map(c => ({
    id:
      c.playerId,
    playerNumber:
      c.playerNumber,
    username:
      c.username,
    avatarColor:
      c.avatarColor,
    x:
      c.x || 0,
    y:
      c.y || 0,
    equippedItems:
      c.equippedItems ||
      {},
    badges:
      c.badges ||
      ['player']
  }));
}

wss.on(
  'connection',
  ws => {
    let room = null;
    let player = null;

    ws.on(
      'message',
      raw => {
        try {
          const msg =
            JSON.parse(raw);

          if (
            msg.type === 'join'
          ) {
            const user =
              verifyWsToken(
                msg.token
              );

            if (!user) {
              ws.send(
                JSON.stringify({
                  type:
                    'error',
                  error:
                    'Sign in required.'
                })
              );

              return;
            }

            const serverId =
              String(
                msg.serverId ||
                  ''
              );

            const dbRoom =
              db.prepare(`
                SELECT *
                FROM game_servers
                WHERE server_id=?
              `).get(
                serverId
              );

            if (!dbRoom) {
              ws.send(
                JSON.stringify({
                  type:
                    'error',
                  error:
                    'Server not found.'
                })
              );

              return;
            }

            const published =
              db.prepare(`
                SELECT *
                FROM published_worlds
                WHERE world_id=?
              `).get(
                dbRoom.world_id
              );

            if (!published) {
              ws.send(
                JSON.stringify({
                  type:
                    'error',
                  error:
                    'Published game not found.'
                })
              );

              return;
            }

            if (
              !liveServers.has(
                serverId
              )
            ) {
              liveServers.set(
                serverId,
                {
                  worldId:
                    dbRoom.world_id,
                  ownerId:
                    dbRoom.owner_id,
                  clients:
                    new Set(),
                  createdAt:
                    dbRoom.created_at
                }
              );
            }

            room =
              liveServers.get(
                serverId
              );

            if (
              room.clients.size >=
              dbRoom.max_players
            ) {
              ws.send(
                JSON.stringify({
                  type:
                    'error',
                  error:
                    'That server is full.'
                })
              );

              return;
            }

            player = {
              ws,
              playerId:
                crypto
                  .randomBytes(
                    6
                  )
                  .toString(
                    'hex'
                  ),
              playerNumber:
                'SP' +
                String(
                  user.id
                ).padStart(
                  6,
                  '0'
                ),
              username:
                user.username,
              avatarColor:
                user.avatar_color,
              equippedItems:
                parseJSON(
                  user.equipped_json,
                  {}
                ),
              badges:
                badgesFor({
                  username:
                    user.username,
                  joinedAt:
                    user.joined_at,
                  badges:
                    parseJSON(
                      user.badges_json,
                      ['player']
                    )
                }),
              x: 60,
              y: 0
            };

            room.clients.add(
              player
            );

            db.prepare(`
              UPDATE game_servers
              SET last_active_at=?
              WHERE server_id=?
            `).run(
              Date.now(),
              serverId
            );

            ws.send(
              JSON.stringify({
                type:
                  'joined',
                server:
                  serverSummary(
                    dbRoom
                  ),
                world:
                  publishedWorldRow(
                    published
                  ),
                playerId:
                  player.playerId,
                players:
                  roomState(
                    room
                  )
              })
            );

            broadcastRoom(
              room,
              {
                type:
                  'player:joined',
                player: {
                  id:
                    player.playerId,
                  playerNumber:
                    player.playerNumber,
                  username:
                    player.username,
                  avatarColor:
                    player.avatarColor,
                  x:
                    player.x,
                  y:
                    player.y,
                  equippedItems:
                    player.equippedItems,
                  badges:
                    player.badges
                }
              },
              ws
            );

            return;
          }

          if (
            !room ||
            !player
          ) {
            return;
          }

          if (
            msg.type ===
            'player:update'
          ) {
            player.x =
              Math.max(
                -10000,
                Math.min(
                  10000,
                  Number(
                    msg.x
                  ) || 0
                )
              );

            player.y =
              Math.max(
                -10000,
                Math.min(
                  10000,
                  Number(
                    msg.y
                  ) || 0
                )
              );

            broadcastRoom(
              room,
              {
                type:
                  'player:update',
                player: {
                  id:
                    player.playerId,
                  playerNumber:
                    player.playerNumber,
                  username:
                    player.username,
                  avatarColor:
                    player.avatarColor,
                  x:
                    player.x,
                  y:
                    player.y,
                  equippedItems:
                    player.equippedItems,
                  badges:
                    player.badges
                }
              },
              ws
            );

            const serverId =
              [
                ...liveServers.entries()
              ].find(
                ([, v]) =>
                  v === room
              )?.[0];

            if (serverId) {
              db.prepare(`
                UPDATE game_servers
                SET last_active_at=?
                WHERE server_id=?
              `).run(
                Date.now(),
                serverId
              );
            }
          } else if (
            msg.type ===
            'game:event'
          ) {
            broadcastRoom(
              room,
              {
                type:
                  'game:event',
                event:
                  msg.event ||
                  null,
                data:
                  msg.data ||
                  null
              },
              ws
            );
          } else if (
            msg.type ===
            'ping'
          ) {
            ws.send(
              JSON.stringify({
                type:
                  'pong'
              })
            );
          }
        } catch {}
      }
    );

    ws.on(
      'close',
      () => {
        if (
          room &&
          player
        ) {
          room.clients.delete(
            player
          );

          broadcastRoom(
            room,
            {
              type:
                'player:left',
              playerId:
                player.playerId
            }
          );

          const serverId =
            [
              ...liveServers.entries()
            ].find(
              ([, v]) =>
                v === room
            )?.[0];

          if (serverId) {
            db.prepare(`
              UPDATE game_servers
              SET last_active_at=?
              WHERE server_id=?
            `).run(
              Date.now(),
              serverId
            );
          }

          if (
            room.clients.size === 0 &&
            serverId
          ) {
            liveServers.delete(
              serverId
            );
          }
        }
      }
    );
  }
);

// Remove abandoned server records
// after 24 hours with no activity.
setInterval(
  () => {
    const cutoff =
      Date.now() -
      24 *
        60 *
        60 *
        1000;

    db.prepare(`
      DELETE FROM game_servers
      WHERE last_active_at<?
    `).run(cutoff);
  },
  60 * 60 * 1000
);

server.listen(
  PORT,
  () =>
    console.log(
      `Spladpad online server listening on ${PORT}`
    )
);
