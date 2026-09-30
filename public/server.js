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

const JWT_SECRET =
  process.env.JWT_SECRET ||
  'CHANGE_ME_BEFORE_PUBLIC_DEPLOYMENT';

if (
  JWT_SECRET === 'CHANGE_ME_BEFORE_PUBLIC_DEPLOYMENT'
) {
  console.warn(
    'WARNING: set JWT_SECRET before deploying publicly.'
  );
}

const dataDir =
  process.env.DATA_DIR ||
  path.join(__dirname, 'data');

fs.mkdirSync(dataDir, {
  recursive: true
});

const db = new Database(
  path.join(dataDir, 'spladpad.sqlite')
);

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
 max_players INTEGER NOT NULL DEFAULT 15,
 created_at INTEGER NOT NULL,
 last_active_at INTEGER NOT NULL
);
`);

function verifyPassword(password, stored) {
  if (
    typeof stored === 'string' &&
    stored.startsWith('scrypt$')
  ) {
    const [
      ,
      saltHex,
      hashHex
    ] = stored.split('$');

    if (!saltHex || !hashHex) {
      return false;
    }

    const actual =
      crypto.scryptSync(
        password,
        Buffer.from(saltHex, 'hex'),
        64
      );

    const expected =
      Buffer.from(hashHex, 'hex');

    return (
      actual.length === expected.length &&
      crypto.timingSafeEqual(
        actual,
        expected
      )
    );
  }

  return bcrypt.compareSync(
    password,
    stored
  );
}

function parseJSON(value, fallback) {
  try {
    return JSON.parse(value);
  } catch {
    return fallback;
  }
}

function adminUsernames() {
  return new Set(
    (
      process.env.ADMIN_USERNAMES ||
      'landon,spladpad,landon_pierce,player1'
    )
      .split(',')
      .map(x => x.trim().toLowerCase())
      .filter(Boolean)
  );
}

function badgesFor(user) {
  const badges = Array.isArray(user.badges)
    ? [...new Set(user.badges)]
    : ['player'];

  if (!badges.includes('player')) {
    badges.unshift('player');
  }

  const username =
    String(user.username || '').toLowerCase();

  if (
    adminUsernames().has(username) &&
    !badges.includes('admin')
  ) {
    badges.push('admin');
  }

  if (
    Date.now() - Number(user.joinedAt) >=
      365 * 24 * 60 * 60 * 1000 &&
    !badges.includes('veteran')
  ) {
    badges.push('veteran');
  }

  return badges;
}

function rowToUser(row, includePrivate = false) {
  const user = {
    id: row.id,

    playerNumber:
      'SP' +
      String(row.id).padStart(6, '0'),

    username: row.username,
    bio: row.bio,
    avatarColor: row.avatar_color,
    avatarType: row.avatar_type,

    coins: row.coins,

    inventory:
      parseJSON(
        row.inventory_json,
        []
      ),

    equippedItems:
      parseJSON(
        row.equipped_json,
        {}
      ),

    badges:
      badgesFor({
        username: row.username,
        joinedAt: row.joined_at,
        badges:
          parseJSON(
            row.badges_json,
            ['player']
          )
      }),

    joinedAt: row.joined_at,

    banned:
      !!row.banned,

    banReason:
      row.ban_reason,

    bannedAt:
      row.banned_at,

    friends: [],
    incomingRequests: [],
    outgoingRequests: []
  };

  user.friends =
    db
      .prepare(`
        SELECT u.username
        FROM friendships f
        JOIN users u
          ON u.id = f.friend_id
        WHERE f.user_id = ?
        ORDER BY u.username
      `)
      .all(row.id)
      .map(x =>
        x.username.toLowerCase()
      );

  user.incomingRequests =
    db
      .prepare(`
        SELECT u.username
        FROM friend_requests fr
        JOIN users u
          ON u.id = fr.sender_id
        WHERE fr.receiver_id = ?
      `)
      .all(row.id)
      .map(x =>
        x.username.toLowerCase()
      );

  user.outgoingRequests =
    db
      .prepare(`
        SELECT u.username
        FROM friend_requests fr
        JOIN users u
          ON u.id = fr.receiver_id
        WHERE fr.sender_id = ?
      `)
      .all(row.id)
      .map(x =>
        x.username.toLowerCase()
      );

  if (includePrivate) {
    user.passwordHash =
      row.password_hash;
  }

  return user;
}

function publicState() {
  const rows =
    db
      .prepare(
        'SELECT * FROM users ORDER BY username'
      )
      .all();

  const accounts = {};

  for (const row of rows) {
    accounts[
      row.username.toLowerCase()
    ] = rowToUser(row);
  }

  const globalMessage =
    db
      .prepare(`
        SELECT value
        FROM settings
        WHERE key = "global_message"
      `)
      .get()?.value || '';

  return {
    accounts,
    globalMessage
  };
}

function tokenFor(row) {
  return jwt.sign(
    {
      sub: row.id,
      username:
        row.username.toLowerCase()
    },
    JWT_SECRET,
    {
      expiresIn: '30d'
    }
  );
}

function auth(req, res, next) {
  const header =
    req.headers.authorization || '';

  const token =
    header.startsWith('Bearer ')
      ? header.slice(7)
      : '';

  try {
    req.user =
      jwt.verify(
        token,
        JWT_SECRET
      );

    const row =
      db
        .prepare(
          'SELECT * FROM users WHERE id=?'
        )
        .get(req.user.sub);

    if (!row) {
      throw new Error(
        'User not found'
      );
    }

    if (row.banned) {
      return res.status(403).json({
        error: 'Account banned',
        reason: row.ban_reason
      });
    }

    req.row = row;

    next();
  } catch {
    return res.status(401).json({
      error: 'Not signed in'
    });
  }
}

function isAdmin(row) {
  const username =
    String(
      row.username || ''
    ).toLowerCase();

  if (
    adminUsernames().has(username)
  ) {
    return true;
  }

  return badgesFor({
    username: row.username,
    joinedAt: row.joined_at,
    badges:
      parseJSON(
        row.badges_json,
        ['player']
      )
  }).includes('admin');
}

function safeName(value) {
  return String(value || '')
    .trim()
    .toLowerCase();
}

const app = express();

app.use(
  (req, res, next) => {
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
  }
);

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

app.get(
  '/api/health',
  (req, res) => {
    res.json({
      ok: true,
      service: 'spladpad'
    });
  }
);

app.post(
  '/api/register',
  (req, res) => {
    const username =
      String(
        req.body.username || ''
      ).trim();

    const password =
      String(
        req.body.password || ''
      );

    const key =
      safeName(username);

    if (
      !/^[a-zA-Z0-9_ -]{2,24}$/.test(
        username
      )
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

    if (
      adminUsernames().has(key)
    ) {
      return res.status(403).json({
        error:
          'That username is reserved for a Spladpad developer account.'
      });
    }

    if (
      db
        .prepare(
          'SELECT id FROM users WHERE username=?'
        )
        .get(key)
    ) {
      return res.status(409).json({
        error:
          'That username is already taken.'
      });
    }

    const now =
      Date.now();

    const hash =
      bcrypt.hashSync(
        password,
        12
      );

    const info =
      db
        .prepare(`
          INSERT INTO users
          (
            username,
            password_hash,
            joined_at,
            badges_json
          )
          VALUES(?,?,?,?)
        `)
        .run(
          username,
          hash,
          now,
          JSON.stringify(
            ['player']
          )
        );

    const row =
      db
        .prepare(
          'SELECT * FROM users WHERE id=?'
        )
        .get(
          info.lastInsertRowid
        );

    res.json({
      token:
        tokenFor(row),

      username:
        row.username.toLowerCase(),

      account:
        rowToUser(row),

      state:
        publicState()
    });
  }
);

app.post(
  '/api/login',
  (req, res) => {
    const username =
      safeName(
        req.body.username
      );

    const password =
      String(
        req.body.password || ''
      );

    const row =
      db
        .prepare(
          'SELECT * FROM users WHERE username=?'
        )
        .get(username);

    if (
      !row ||
      !verifyPassword(
        password,
        row.password_hash
      )
    ) {
      return res.status(401).json({
        error:
          'Invalid username or password.'
      });
    }

    if (row.banned) {
      return res.status(403).json({
        error:
          'Account banned',
        reason:
          row.ban_reason
      });
    }

    res.json({
      token:
        tokenFor(row),

      username:
        row.username.toLowerCase(),

      account:
        rowToUser(row),

      state:
        publicState()
    });
  }
);

app.get(
  '/api/state',
  auth,
  (req, res) => {
    res.json(
      publicState()
    );
  }
);

app.get(
  '/api/players',
  auth,
  (req, res) => {
    const query =
      String(
        req.query.q || ''
      )
        .trim()
        .toLowerCase();

    const rows =
      db
        .prepare(
          'SELECT * FROM users ORDER BY username'
        )
        .all();

    const players =
      rows
        .map(rowToUser)
        .filter(user => {
          return (
            !query ||
            user.username
              .toLowerCase()
              .includes(query) ||
            user.playerNumber
              .toLowerCase()
              .includes(query)
          );
        });

    res.json({
      players
    });
  }
);

function applySelfChanges(
  row,
  incoming
) {
  const current =
    rowToUser(row);

  const bio =
    typeof incoming.bio ===
    'string'
      ? incoming.bio.slice(
          0,
          500
        )
      : current.bio;

  const avatarColor =
    [
      'blue',
      'red',
      'green',
      'purple',
      'yellow',
      'black'
    ].includes(
      incoming.avatarColor
    )
      ? incoming.avatarColor
      : current.avatarColor;

  const avatarType =
    typeof incoming.avatarType ===
    'string'
      ? incoming.avatarType.slice(
          0,
          40
        )
      : current.avatarType;

  const equippedItems =
    incoming.equippedItems &&
    typeof incoming.equippedItems ===
      'object'
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
    avatarColor,
    avatarType,
    JSON.stringify(
      equippedItems
    ),
    row.id
  );
}

function syncSocial(
  currentId,
  accounts
) {
  const current =
    db
      .prepare(
        'SELECT * FROM users WHERE id=?'
      )
      .get(currentId);

  if (!current) {
    return;
  }

  const me =
    safeName(
      current.username
    );

  const transaction =
    db.transaction(() => {
      for (
        const [
          key,
          account
        ]
        of Object.entries(
          accounts || {}
        )
      ) {
        const target =
          db
            .prepare(
              'SELECT * FROM users WHERE username=?'
            )
            .get(key);

        if (!target) {
          continue;
        }

        const old =
          rowToUser(target);

        const isMe =
          safeName(
            target.username
          ) === me;

        const oldFriends =
          new Set(
            old.friends
          );

        const newFriends =
          new Set(
            Array.isArray(
              account.friends
            )
              ? account.friends.map(
                  safeName
                )
              : old.friends
          );

        const oldIncoming =
          new Set(
            old.incomingRequests
          );

        const newIncoming =
          new Set(
            Array.isArray(
              account.incomingRequests
            )
              ? account.incomingRequests.map(
                  safeName
                )
              : old.incomingRequests
          );

        const oldOutgoing =
          new Set(
            old.outgoingRequests
          );

        const newOutgoing =
          new Set(
            Array.isArray(
              account.outgoingRequests
            )
              ? account.outgoingRequests.map(
                  safeName
                )
              : old.outgoingRequests
          );

        const friendChanges =
          [
            ...new Set([
              ...oldFriends,
              ...newFriends
            ])
          ].filter(
            x =>
              oldFriends.has(x) !==
              newFriends.has(x)
          );

        const incomingChanges =
          [
            ...new Set([
              ...oldIncoming,
              ...newIncoming
            ])
          ].filter(
            x =>
              oldIncoming.has(x) !==
              newIncoming.has(x)
          );

        const outgoingChanges =
          [
            ...new Set([
              ...oldOutgoing,
              ...newOutgoing
            ])
          ].filter(
            x =>
              oldOutgoing.has(x) !==
              newOutgoing.has(x)
          );

        if (
          !isMe &&
          [
            ...friendChanges,
            ...incomingChanges,
            ...outgoingChanges
          ].some(
            x => x !== me
          )
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
          incomingChanges.length &&
          !incomingChanges.every(
            x => x === me
          )
        ) {
          continue;
        }

        if (
          !isMe &&
          outgoingChanges.length &&
          !outgoingChanges.every(
            x => x === me
          )
        ) {
          continue;
        }

        if (isMe) {
          for (
            const person
              of outgoingChanges
          ) {
            const other =
              db
                .prepare(
                  'SELECT id FROM users WHERE username=?'
                )
                .get(person);

            if (!other) {
              continue;
            }

            if (
              newOutgoing.has(person)
            ) {
              db.prepare(`
                INSERT OR IGNORE INTO
                friend_requests
                (
                  sender_id,
                  receiver_id,
                  created_at
                )
                VALUES(?,?,?)
              `).run(
                currentId,
                other.id,
                Date.now()
              );
            } else {
              db.prepare(`
                DELETE FROM friend_requests
                WHERE
                  sender_id=?
                  AND
                  receiver_id=?
              `).run(
                currentId,
                other.id
              );
            }
          }

          for (
            const person
              of incomingChanges
          ) {
            const other =
              db
                .prepare(
                  'SELECT id FROM users WHERE username=?'
                )
                .get(person);

            if (!other) {
              continue;
            }

            if (
              newIncoming.has(person)
            ) {
              db.prepare(`
                INSERT OR IGNORE INTO
                friend_requests
                (
                  sender_id,
                  receiver_id,
                  created_at
                )
                VALUES(?,?,?)
              `).run(
                other.id,
                currentId,
                Date.now()
              );
            } else {
              db.prepare(`
                DELETE FROM friend_requests
                WHERE
                  sender_id=?
                  AND
                  receiver_id=?
              `).run(
                other.id,
                currentId
              );
            }
          }

          for (
            const person
              of friendChanges
          ) {
            const other =
              db
                .prepare(
                  'SELECT id FROM users WHERE username=?'
                )
                .get(person);

            if (!other) {
              continue;
            }

            if (
              newFriends.has(person)
            ) {
              db.prepare(`
                INSERT OR IGNORE INTO
                friendships
                (
                  user_id,
                  friend_id,
                  created_at
                )
                VALUES(?,?,?)
              `).run(
                currentId,
                other.id,
                Date.now()
              );

              db.prepare(`
                INSERT OR IGNORE INTO
                friendships
                (
                  user_id,
                  friend_id,
                  created_at
                )
                VALUES(?,?,?)
              `).run(
                other.id,
                currentId,
                Date.now()
              );

              db.prepare(`
                DELETE FROM friend_requests
                WHERE
                  (
                    sender_id=?
                    AND
                    receiver_id=?
                  )
                  OR
                  (
                    sender_id=?
                    AND
                    receiver_id=?
                  )
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
                  (
                    user_id=?
                    AND
                    friend_id=?
                  )
                  OR
                  (
                    user_id=?
                    AND
                    friend_id=?
                  )
              `).run(
                currentId,
                other.id,
                other.id,
                currentId
              );
            }
          }
        }
      }
    });

  transaction();
}

app.post(
  '/api/sync',
  auth,
  (req, res) => {
    const accounts =
      req.body.accounts || {};

    const me =
      safeName(
        req.row.username
      );

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

    res.json(
      publicState()
    );
  }
);

app.post(
  '/api/purchase',
  auth,
  (req, res) => {
    const item =
      String(
        req.body.item || ''
      );

    const price =
      Number(
        req.body.price
      );

    const allowed = {
      'Blue Hat': 100
    };

    if (
      !allowed[item] ||
      price !== allowed[item]
    ) {
      return res.status(400).json({
        error:
          'Invalid shop item.'
      });
    }

    const row =
      db
        .prepare(
          'SELECT * FROM users WHERE id=?'
        )
        .get(req.row.id);

    const inventory =
      parseJSON(
        row.inventory_json,
        []
      );

    const equipped =
      parseJSON(
        row.equipped_json,
        {}
      );

    if (
      inventory.includes(item)
    ) {
      equipped.hat =
        item;

      db.prepare(`
        UPDATE users
        SET equipped_json=?
        WHERE id=?
      `).run(
        JSON.stringify(
          equipped
        ),
        row.id
      );
    } else {
      if (
        row.coins < price
      ) {
        return res.status(400).json({
          error:
            'Not enough coins.'
        });
      }

      inventory.push(
        item
      );

      equipped.hat =
        item;

      db.prepare(`
        UPDATE users
        SET
          coins=coins-?,
          inventory_json=?,
          equipped_json=?
        WHERE id=?
      `).run(
        price,
        JSON.stringify(
          inventory
        ),
        JSON.stringify(
          equipped
        ),
        row.id
      );
    }

    res.json({
      account:
        rowToUser(
          db
            .prepare(
              'SELECT * FROM users WHERE id=?'
            )
            .get(row.id)
        ),

      state:
        publicState()
    });
  }
);

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

    const message =
      String(
        req.body.message || ''
      )
        .trim()
        .slice(0, 1000);

    if (message) {
      db.prepare(`
        INSERT INTO settings
        (
          key,
          value
        )
        VALUES
        (
          "global_message",
          ?
        )
        ON CONFLICT(key)
        DO UPDATE SET
          value=excluded.value
      `).run(
        message
      );
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

    const username =
      safeName(
        req.body.username
      );

    const badge =
      String(
        req.body.badge || ''
      );

    if (
      ![
        'player',
        'admin',
        'veteran'
      ].includes(
        badge
      )
    ) {
      return res.status(400).json({
        error:
          'Invalid badge.'
      });
    }

    const row =
      db
        .prepare(
          'SELECT * FROM users WHERE username=?'
        )
        .get(username);

    if (!row) {
      return res.status(404).json({
        error:
          'Player not found.'
      });
    }

    const badges =
      new Set(
        parseJSON(
          row.badges_json,
          ['player']
        )
      );

    badges.add(
      badge
    );

    db.prepare(`
      UPDATE users
      SET badges_json=?
      WHERE id=?
    `).run(
      JSON.stringify(
        [
          ...badges
        ]
      ),
      row.id
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

    const username =
      safeName(
        req.body.username
      );

    const amount =
      Number(
        req.body.amount
      );

    if (
      !Number.isInteger(
        amount
      ) ||
      amount <= 0
    ) {
      return res.status(400).json({
        error:
          'Invalid amount.'
      });
    }

    const row =
      db
        .prepare(
          'SELECT id FROM users WHERE username=?'
        )
        .get(username);

    if (!row) {
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
      row.id
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

    const username =
      safeName(
        req.body.username
      );

    if (
      username ===
      safeName(
        req.row.username
      )
    ) {
      return res.status(400).json({
        error:
          'You cannot ban yourself.'
      });
    }

    const row =
      db
        .prepare(
          'SELECT id FROM users WHERE username=?'
        )
        .get(username);

    if (!row) {
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
      ).slice(
        0,
        300
      ),
      Date.now(),
      row.id
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

    const row =
      db
        .prepare(
          'SELECT id FROM users WHERE username=?'
        )
        .get(
          safeName(
            req.body.username
          )
        );

    if (!row) {
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
    `).run(
      row.id
    );

    res.json(
      publicState()
    );
  }
);

/* =========================================
   PUBLISHED CREATOR WORLDS
   ========================================= */

function cleanWorld(
  world
) {
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
    ).slice(
      0,
      80
    );

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
      .slice(
        0,
        80
      ) ||
    'My Spladpad World';

  const thumbnail =
    typeof world.thumbnail ===
    'string'
      ? world.thumbnail.slice(
          0,
          800000
        )
      : '';

  const scripts =
    world.scripts &&
    typeof world.scripts ===
      'object'
      ? world.scripts
      : {};

  const objects =
    Array.isArray(
      world.objects
    )
      ? world.objects
          .slice(
            0,
            500
          )
          .map(o => ({
            id:
              String(
                o.id || ''
              ).slice(
                0,
                80
              ),

            type:
              String(
                o.type ||
                  'block'
              ).slice(
                0,
                30
              ),

            x:
              Number(o.x) ||
              0,

            y:
              Number(o.y) ||
              0,

            w:
              Math.max(
                1,
                Number(o.w) ||
                  50
              ),

            h:
              Math.max(
                1,
                Number(o.h) ||
                  50
              ),

            color:
              typeof o.color ===
              'string'
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
              ).slice(
                0,
                80
              )
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
      html:
        String(
          scripts.html ||
            ''
        ).slice(
          0,
          200000
        ),

      python:
        String(
          scripts.python ||
            ''
        ).slice(
          0,
          200000
        )
    },

    objects,

    connections
  };
}

function publishedWorldRow(
  row
) {
  const owner =
    db
      .prepare(
        'SELECT username FROM users WHERE id=?'
      )
      .get(
        row.owner_id
      );

  return {
    id:
      row.world_id,

    ownerId:
      row.owner_id,

    ownerUsername:
      owner?.username ||
      'Creator',

    name:
      row.name,

    thumbnail:
      row.thumbnail,

    published:
      true,

    publishedAt:
      row.published_at,

    updatedAt:
      row.updated_at,

    world:
      parseJSON(
        row.world_json,
        {}
      )
  };
}

app.get(
  '/api/worlds/published',
  (req, res) => {
    const rows =
      db
        .prepare(`
          SELECT *
          FROM published_worlds
          ORDER BY published_at DESC
        `)
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
      world =
        cleanWorld(
          req.body.world
        );

      world.published =
        true;
    } catch (error) {
      return res.status(400).json({
        error:
          error.message
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
      world:
        publishedWorldRow(
          db
            .prepare(`
              SELECT *
              FROM published_worlds
              WHERE world_id=?
            `)
            .get(world.id)
        )
    });
  }
);

app.post(
  '/api/worlds/unpublish',
  auth,
  (req, res) => {
    const worldId =
      String(
        req.body.worldId ||
          ''
      );

    const row =
      db
        .prepare(`
          SELECT owner_id
          FROM published_worlds
          WHERE world_id=?
        `)
        .get(
          worldId
        );

    if (!row) {
      return res.status(404).json({
        error:
          'Published world not found.'
      });
    }

    if (
      row.owner_id !==
        req.row.id &&
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
    `).run(
      worldId
    );

    db.prepare(`
      DELETE FROM game_servers
      WHERE world_id=?
    `).run(
      worldId
    );

    for (
      const [serverId, room]
      of liveServers
    ) {
      if (
        room.worldId ===
        worldId
      ) {
        for (
          const client
          of room.clients
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
          serverId
        );
      }
    }

    res.json({
      ok: true
    });
  }
);

/* =========================================
   MULTIPLAYER GAME SERVERS
   ========================================= */

const liveServers =
  new Map();

function makeServerId() {
  return crypto
    .randomBytes(
      5
    )
    .toString(
      'hex'
    );
}

function serverSummary(
  row
) {
  const room =
    liveServers.get(
      row.server_id
    );

  return {
    id:
      row.server_id,

    worldId:
      row.world_id,

    name:
      row.server_name,

    maxPlayers:
      row.max_players,

    players:
      room
        ? room.clients.size
        : 0,

    ownerId:
      row.owner_id,

    createdAt:
      row.created_at
  };
}

app.get(
  '/api/servers',
  (req, res) => {
    const worldId =
      String(
        req.query.worldId ||
          ''
      );

    const rows =
      worldId
        ? db
            .prepare(`
              SELECT *
              FROM game_servers
              WHERE world_id=?
              ORDER BY created_at DESC
            `)
            .all(
              worldId
            )
        : db
            .prepare(`
              SELECT *
              FROM game_servers
              ORDER BY created_at DESC
            `)
            .all();

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
        req.body.worldId ||
          ''
      );

    const world =
      db
        .prepare(`
          SELECT *
          FROM published_worlds
          WHERE world_id=?
        `)
        .get(
          worldId
        );

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
            15
        )
      );

    if (
      !Number.isFinite(
        maxPlayers
      )
    ) {
      maxPlayers = 15;
    }

    maxPlayers =
      Math.max(
        2,
        Math.min(
          15,
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
        .slice(
          0,
          50
        ) ||
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

    const row =
      db
        .prepare(`
          SELECT *
          FROM game_servers
          WHERE server_id=?
        `)
        .get(
          serverId
        );

    res.json({
      server:
        serverSummary(
          row
        )
    });
  }
);

app.post(
  '/api/servers/close',
  auth,
  (req, res) => {
    const serverId =
      String(
        req.body.serverId ||
          ''
      );

    const row =
      db
        .prepare(`
          SELECT *
          FROM game_servers
          WHERE server_id=?
        `)
        .get(
          serverId
        );

    if (!row) {
      return res.status(404).json({
        error:
          'Server not found.'
      });
    }

    if (
      row.owner_id !==
        req.row.id &&
      !isAdmin(req.row)
    ) {
      return res.status(403).json({
        error:
          'Only the server owner can close this server.'
      });
    }

    const room =
      liveServers.get(
        serverId
      );

    if (room) {
      for (
        const client
        of room.clients
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
        serverId
      );
    }

    db.prepare(`
      DELETE FROM game_servers
      WHERE server_id=?
    `).run(
      serverId
    );

    res.json({
      ok: true
    });
  }
);

/* =========================================
   WEBSITE
   ========================================= */

app.use(
  express.static(
    path.join(
      __dirname,
      'public'
    )
  )
);

app.get(
  '*',
  (req, res) => {
    res.sendFile(
      path.join(
        __dirname,
        'public',
        'index.html'
      )
    );
  }
);

/* =========================================
   WEBSOCKET MULTIPLAYER
   ========================================= */

const server =
  http.createServer(
    app
  );

const wss =
  new WebSocketServer({
    server,
    path: '/ws'
  });

function verifyWsToken(
  token
) {
  try {
    const decoded =
      jwt.verify(
        String(
          token || ''
        ),
        JWT_SECRET
      );

    const row =
      db
        .prepare(
          'SELECT * FROM users WHERE id=?'
        )
        .get(
          decoded.sub
        );

    if (
      !row ||
      row.banned
    ) {
      return null;
    }

    return row;
  } catch {
    return null;
  }
}

function broadcastRoom(
  room,
  payload,
  except
) {
  const message =
    JSON.stringify(
      payload
    );

  for (
    const client
    of room.clients
  ) {
    if (
      client !== except &&
      client.ws.readyState === 1
    ) {
      client.ws.send(
        message
      );
    }
  }
}

function roomState(
  room
) {
  return [
    ...room.clients
  ].map(
    client => ({
      id:
        client.playerId,

      playerNumber:
        client.playerNumber,

      username:
        client.username,

      avatarColor:
        client.avatarColor,

      x:
        client.x || 0,

      y:
        client.y || 0,

      equippedItems:
        client.equippedItems ||
        {},

      badges:
        client.badges ||
        ['player']
    })
  );
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
          const message =
            JSON.parse(
              raw
            );

          if (
            message.type ===
            'join'
          ) {
            const user =
              verifyWsToken(
                message.token
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
                message.serverId ||
                  ''
              );

            const dbRoom =
              db
                .prepare(`
                  SELECT *
                  FROM game_servers
                  WHERE server_id=?
                `)
                .get(
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
              db
                .prepare(`
                  SELECT *
                  FROM published_worlds
                  WHERE world_id=?
                `)
                .get(
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

              x:
                60,

              y:
                0
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
            message.type ===
            'player:update'
          ) {
            player.x =
              Math.max(
                -10000,

                Math.min(
                  10000,
                  Number(
                    message.x
                  ) || 0
                )
              );

            player.y =
              Math.max(
                -10000,

                Math.min(
                  10000,
                  Number(
                    message.y
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
                ([, value]) =>
                  value === room
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
          }

          else if (
            message.type ===
            'game:event'
          ) {
            broadcastRoom(
              room,
              {
                type:
                  'game:event',

                event:
                  message.event ||
                  null,

                data:
                  message.data ||
                  null
              },
              ws
            );
          }

          else if (
            message.type ===
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
              ([, value]) =>
                value === room
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
            room.clients.size ===
              0 &&
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

/* =========================================
   CLEANUP
   ========================================= */

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
    `).run(
      cutoff
    );
  },
  60 * 60 * 1000
);

server.listen(
  PORT,
  () => {
    console.log(
      `Spladpad online server listening on ${PORT}`
    );
  }
);
