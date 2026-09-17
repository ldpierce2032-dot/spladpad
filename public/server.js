const express = require("express");
const http = require("http");
const path = require("path");
const fs = require("fs");
const sqlite3 = require("sqlite3").verbose();
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const { WebSocketServer } = require("ws");

const app = express();
const server = http.createServer(app);

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || "spladpad-development-secret";

app.use(express.json({ limit: "10mb" }));

const publicPath = path.join(__dirname, "public");

if (fs.existsSync(publicPath)) {
  app.use(express.static(publicPath));
}

const dbPath = path.join(__dirname, "spladpad.db");
const db = new sqlite3.Database(dbPath);

db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      coins INTEGER DEFAULT 1000,
      avatar_color TEXT DEFAULT '#e53935',
      hat TEXT DEFAULT '',
      badges TEXT DEFAULT 'Player',
      banned INTEGER DEFAULT 0,
      created_at INTEGER NOT NULL
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS published_worlds (
      world_id TEXT PRIMARY KEY,
      owner_id INTEGER NOT NULL,
      name TEXT NOT NULL,
      thumbnail TEXT DEFAULT '',
      world_json TEXT NOT NULL,
      published_at INTEGER NOT NULL,
      updated_at INTEGER NOT NULL
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS game_servers (
      server_id TEXT PRIMARY KEY,
      world_id TEXT NOT NULL,
      owner_id INTEGER NOT NULL,
      server_name TEXT NOT NULL,
      max_players INTEGER DEFAULT 12,
      created_at INTEGER NOT NULL,
      last_active_at INTEGER NOT NULL
    )
  `);
});

// --------------------------------------------------
// ADMIN
// --------------------------------------------------

const ADMIN_USERNAMES = new Set([
  "landon",
  "spladpad",
  "landon_pierce",
  "player1"
]);

function isAdmin(username) {
  if (!username) return false;
  return ADMIN_USERNAMES.has(username.toLowerCase());
}

// --------------------------------------------------
// HELPERS
// --------------------------------------------------

function makeToken(user) {
  return jwt.sign(
    {
      id: user.id,
      username: user.username
    },
    JWT_SECRET,
    { expiresIn: "30d" }
  );
}

function auth(req, res, next) {
  try {
    const header = req.headers.authorization || "";

    if (!header.startsWith("Bearer ")) {
      return res.status(401).json({
        error: "Not logged in"
      });
    }

    const token = header.slice(7);

    req.user = jwt.verify(token, JWT_SECRET);

    next();
  } catch {
    return res.status(401).json({
      error: "Invalid login"
    });
  }
}

function adminAuth(req, res, next) {
  auth(req, res, () => {
    if (!isAdmin(req.user.username)) {
      return res.status(403).json({
        error: "Admin access required"
      });
    }

    next();
  });
}

function randomId(prefix) {
  return (
    prefix +
    "_" +
    Date.now().toString(36) +
    "_" +
    Math.random().toString(36).slice(2, 10)
  );
}

function getUserById(id, callback) {
  db.get(
    `SELECT * FROM users WHERE id = ?`,
    [id],
    callback
  );
}

// --------------------------------------------------
// AUTH
// --------------------------------------------------

app.post("/api/register", async (req, res) => {
  try {
    const username = String(req.body.username || "").trim();
    const password = String(req.body.password || "");

    if (username.length < 2) {
      return res.status(400).json({
        error: "Username must be at least 2 characters."
      });
    }

    if (username.length > 20) {
      return res.status(400).json({
        error: "Username is too long."
      });
    }

    if (password.length < 3) {
      return res.status(400).json({
        error: "Password must be at least 3 characters."
      });
    }

    if (password.length > 40) {
      return res.status(400).json({
        error: "Password is too long."
      });
    }

    const hashed = await bcrypt.hash(password, 10);

    db.run(
      `
      INSERT INTO users
      (username, password, coins, badges, created_at)
      VALUES (?, ?, 1000, ?, ?)
      `,
      [
        username,
        hashed,
        isAdmin(username) ? "Player,Admin" : "Player",
        Date.now()
      ],
      function (err) {
        if (err) {
          return res.status(400).json({
            error: "Username already exists."
          });
        }

        const user = {
          id: this.lastID,
          username
        };

        res.json({
          token: makeToken(user),
          username,
          coins: 1000,
          isAdmin: isAdmin(username)
        });
      }
    );
  } catch {
    res.status(500).json({
      error: "Could not create account."
    });
  }
});

app.post("/api/login", (req, res) => {
  const username = String(req.body.username || "").trim();
  const password = String(req.body.password || "");

  db.get(
    `SELECT * FROM users WHERE username = ?`,
    [username],
    async (err, user) => {
      if (err || !user) {
        return res.status(401).json({
          error: "Invalid username or password."
        });
      }

      if (user.banned) {
        return res.status(403).json({
          error: "This account is banned."
        });
      }

      const good = await bcrypt.compare(password, user.password);

      if (!good) {
        return res.status(401).json({
          error: "Invalid username or password."
        });
      }

      res.json({
        token: makeToken(user),
        username: user.username,
        coins: user.coins,
        avatarColor: user.avatar_color,
        hat: user.hat,
        badges: user.badges,
        isAdmin: isAdmin(user.username)
      });
    }
  );
});

app.get("/api/me", auth, (req, res) => {
  getUserById(req.user.id, (err, user) => {
    if (err || !user) {
      return res.status(404).json({
        error: "User not found."
      });
    }

    res.json({
      id: user.id,
      username: user.username,
      coins: user.coins,
      avatarColor: user.avatar_color,
      hat: user.hat,
      badges: user.badges,
      isAdmin: isAdmin(user.username),
      banned: !!user.banned
    });
  });
});

// --------------------------------------------------
// PROFILE
// --------------------------------------------------

app.post("/api/profile", auth, (req, res) => {
  const avatarColor = String(
    req.body.avatarColor || "#e53935"
  );

  const hat = String(req.body.hat || "");

  db.run(
    `
    UPDATE users
    SET avatar_color = ?, hat = ?
    WHERE id = ?
    `,
    [avatarColor, hat, req.user.id],
    err => {
      if (err) {
        return res.status(500).json({
          error: "Could not save profile."
        });
      }

      res.json({
        ok: true
      });
    }
  );
});

// --------------------------------------------------
// SHOP / COINS
// --------------------------------------------------

const SHOP_ITEMS = {
  "Blue Hat": 100
};

app.get("/api/coins", auth, (req, res) => {
  db.get(
    `SELECT coins FROM users WHERE id = ?`,
    [req.user.id],
    (err, user) => {
      if (err || !user) {
        return res.status(404).json({
          error: "User not found."
        });
      }

      res.json({
        coins: user.coins
      });
    }
  );
});

app.post("/api/purchase", auth, (req, res) => {
  const item = String(req.body.item || "");

  const price = SHOP_ITEMS[item];

  if (!price) {
    return res.status(400).json({
      error: "Item is not available."
    });
  }

  db.get(
    `SELECT coins, hat FROM users WHERE id = ?`,
    [req.user.id],
    (err, user) => {
      if (err || !user) {
        return res.status(404).json({
          error: "User not found."
        });
      }

      if (user.coins < price) {
        return res.status(400).json({
          error: "Not enough coins."
        });
      }

      db.run(
        `
        UPDATE users
        SET coins = coins - ?, hat = ?
        WHERE id = ?
        `,
        [price, item, req.user.id],
        error => {
          if (error) {
            return res.status(500).json({
              error: "Purchase failed."
            });
          }

          res.json({
            ok: true,
            item,
            coins: user.coins - price,
            hat: item
          });
        }
      );
    }
  );
});

// --------------------------------------------------
// PUBLISHED WORLDS
// --------------------------------------------------

app.get("/api/worlds/published", (req, res) => {
  db.all(
    `
    SELECT
      world_id,
      owner_id,
      name,
      thumbnail,
      world_json,
      published_at,
      updated_at
    FROM published_worlds
    ORDER BY published_at DESC
    `,
    [],
    (err, worlds) => {
      if (err) {
        return res.status(500).json({
          error: "Could not load worlds."
        });
      }

      res.json(worlds || []);
    }
  );
});

app.post("/api/worlds/publish", auth, (req, res) => {
  const worldId =
    String(req.body.worldId || "") ||
    randomId("world");

  const name =
    String(req.body.name || "Untitled World")
      .slice(0, 100);

  const thumbnail =
    String(req.body.thumbnail || "");

  const worldJson =
    typeof req.body.world === "string"
      ? req.body.world
      : JSON.stringify(req.body.world || {});

  const now = Date.now();

  db.run(
    `
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
    VALUES (?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(world_id)
    DO UPDATE SET
      name = excluded.name,
      thumbnail = excluded.thumbnail,
      world_json = excluded.world_json,
      updated_at = excluded.updated_at
    `,
    [
      worldId,
      req.user.id,
      name,
      thumbnail,
      worldJson,
      now,
      now
    ],
    err => {
      if (err) {
        return res.status(500).json({
          error: "Could not publish world."
        });
      }

      res.json({
        ok: true,
        worldId
      });
    }
  );
});

app.post("/api/worlds/unpublish", auth, (req, res) => {
  const worldId = String(req.body.worldId || "");

  db.run(
    `
    DELETE FROM published_worlds
    WHERE world_id = ?
    AND owner_id = ?
    `,
    [worldId, req.user.id],
    function (err) {
      if (err) {
        return res.status(500).json({
          error: "Could not unpublish world."
        });
      }

      res.json({
        ok: true,
        removed: this.changes > 0
      });
    }
  );
});

// --------------------------------------------------
// GAME SERVERS
// --------------------------------------------------

app.get("/api/servers", (req, res) => {
  const worldId = String(req.query.worldId || "");

  if (!worldId) {
    return res.status(400).json({
      error: "worldId is required."
    });
  }

  db.all(
    `
    SELECT
      server_id,
      world_id,
      owner_id,
      server_name,
      max_players,
      created_at,
      last_active_at
    FROM game_servers
    WHERE world_id = ?
    ORDER BY created_at ASC
    `,
    [worldId],
    (err, servers) => {
      if (err) {
        return res.status(500).json({
          error: "Could not load servers."
        });
      }

      const result = (servers || []).map(s => ({
        ...s,
        players: liveServers.has(s.server_id)
          ? liveServers.get(s.server_id).players.size
          : 0
      }));

      res.json(result);
    }
  );
});

app.post("/api/servers/create", auth, (req, res) => {
  const worldId = String(req.body.worldId || "");

  const serverName =
    String(req.body.serverName || "Spladpad Server")
      .slice(0, 80);

  let maxPlayers =
    Number(req.body.maxPlayers || 12);

  if (!Number.isFinite(maxPlayers)) {
    maxPlayers = 12;
  }

  maxPlayers = Math.max(
    2,
    Math.min(24, Math.floor(maxPlayers))
  );

  db.get(
    `
    SELECT world_id
    FROM published_worlds
    WHERE world_id = ?
    `,
    [worldId],
    (err, world) => {
      if (err || !world) {
        return res.status(404).json({
          error: "World not found."
        });
      }

      const serverId = randomId("server");
      const now = Date.now();

      db.run(
        `
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
        VALUES (?, ?, ?, ?, ?, ?, ?)
        `,
        [
          serverId,
          worldId,
          req.user.id,
          serverName,
          maxPlayers,
          now,
          now
        ],
        error => {
          if (error) {
            return res.status(500).json({
              error: "Could not create server."
            });
          }

          liveServers.set(serverId, {
            players: new Map(),
            ownerId: req.user.id,
            maxPlayers,
            worldId
          });

          res.json({
            ok: true,
            serverId,
            serverName,
            maxPlayers
          });
        }
      );
    }
  );
});

app.post("/api/servers/close", auth, (req, res) => {
  const serverId = String(req.body.serverId || "");

  db.get(
    `
    SELECT owner_id
    FROM game_servers
    WHERE server_id = ?
    `,
    [serverId],
    (err, row) => {
      if (err || !row) {
        return res.status(404).json({
          error: "Server not found."
        });
      }

      if (
        row.owner_id !== req.user.id &&
        !isAdmin(req.user.username)
      ) {
        return res.status(403).json({
          error: "You cannot close this server."
        });
      }

      closeLiveServer(serverId);

      db.run(
        `
        DELETE FROM game_servers
        WHERE server_id = ?
        `,
        [serverId],
        error => {
          if (error) {
            return res.status(500).json({
              error: "Could not close server."
            });
          }

          res.json({
            ok: true
          });
        }
      );
    }
  );
});

// --------------------------------------------------
// ADMIN TOOLS
// --------------------------------------------------

app.get("/api/admin/players", adminAuth, (req, res) => {
  db.all(
    `
    SELECT
      id,
      username,
      coins,
      badges,
      banned,
      created_at
    FROM users
    ORDER BY username
    `,
    [],
    (err, players) => {
      if (err) {
        return res.status(500).json({
          error: "Could not load players."
        });
      }

      res.json(players || []);
    }
  );
});

app.post("/api/admin/coins", adminAuth, (req, res) => {
  const username = String(req.body.username || "").trim();
  const amount = Number(req.body.amount || 0);

  if (!Number.isFinite(amount)) {
    return res.status(400).json({
      error: "Invalid amount."
    });
  }

  db.run(
    `
    UPDATE users
    SET coins = MAX(0, coins + ?)
    WHERE username = ?
    `,
    [Math.floor(amount), username],
    function (err) {
      if (err) {
        return res.status(500).json({
          error: "Could not change coins."
        });
      }

      if (!this.changes) {
        return res.status(404).json({
          error: "Player not found."
        });
      }

      res.json({
        ok: true
      });
    }
  );
});

app.post("/api/admin/badge", adminAuth, (req, res) => {
  const username = String(req.body.username || "").trim();
  const badge = String(req.body.badge || "").trim();

  if (!badge) {
    return res.status(400).json({
      error: "Badge required."
    });
  }

  db.get(
    `SELECT badges FROM users WHERE username = ?`,
    [username],
    (err, user) => {
      if (err || !user) {
        return res.status(404).json({
          error: "Player not found."
        });
      }

      const badges = user.badges
        ? user.badges
            .split(",")
            .map(x => x.trim())
            .filter(Boolean)
        : [];

      if (!badges.includes(badge)) {
        badges.push(badge);
      }

      db.run(
        `
        UPDATE users
        SET badges = ?
        WHERE username = ?
        `,
        [badges.join(","), username],
        error => {
          if (error) {
            return res.status(500).json({
              error: "Could not give badge."
            });
          }

          res.json({
            ok: true,
            badges
          });
        }
      );
    }
  );
});

app.post("/api/admin/ban", adminAuth, (req, res) => {
  const username = String(req.body.username || "").trim();

  if (isAdmin(username)) {
    return res.status(400).json({
      error: "Admin accounts cannot be banned."
    });
  }

  db.run(
    `
    UPDATE users
    SET banned = 1
    WHERE username = ?
    `,
    [username],
    function (err) {
      if (err) {
        return res.status(500).json({
          error: "Could not ban player."
        });
      }

      res.json({
        ok: this.changes > 0
      });
    }
  );
});

app.post("/api/admin/unban", adminAuth, (req, res) => {
  const username = String(req.body.username || "").trim();

  db.run(
    `
    UPDATE users
    SET banned = 0
    WHERE username = ?
    `,
    [username],
    function (err) {
      if (err) {
        return res.status(500).json({
          error: "Could not unban player."
        });
      }

      res.json({
        ok: this.changes > 0
      });
    }
  );
});

// --------------------------------------------------
// WEBSOCKET MULTIPLAYER
// --------------------------------------------------

const wss = new WebSocketServer({
  server,
  path: "/ws"
});

const liveServers = new Map();

function send(ws, data) {
  if (ws.readyState === 1) {
    ws.send(JSON.stringify(data));
  }
}

function broadcast(room, data, exceptWs = null) {
  if (!room) return;

  for (const player of room.players.values()) {
    if (player.ws !== exceptWs) {
      send(player.ws, data);
    }
  }
}

function closeLiveServer(serverId) {
  const room = liveServers.get(serverId);

  if (!room) return;

  broadcast(room, {
    type: "server:closed"
  });

  for (const player of room.players.values()) {
    try {
      player.ws.close();
    } catch {}
  }

  liveServers.delete(serverId);
}

wss.on("connection", ws => {
  let currentServerId = null;
  let currentPlayerId = null;
  let currentUsername = null;

  ws.on("message", raw => {
    let message;

    try {
      message = JSON.parse(raw.toString());
    } catch {
      return send(ws, {
        type: "error",
        error: "Invalid message."
      });
    }

    // ------------------------------
    // JOIN
    // ------------------------------

    if (message.type === "join") {
      try {
        const token = String(message.token || "");
        const decoded = jwt.verify(token, JWT_SECRET);

        const serverId =
          String(message.serverId || "");

        db.get(
          `
          SELECT *
          FROM game_servers
          WHERE server_id = ?
          `,
          [serverId],
          (err, serverRow) => {
            if (err || !serverRow) {
              return send(ws, {
                type: "error",
                error: "Server not found."
              });
            }

            db.get(
              `
              SELECT *
              FROM users
              WHERE id = ?
              `,
              [decoded.id],
              (userErr, user) => {
                if (userErr || !user) {
                  return send(ws, {
                    type: "error",
                    error: "User not found."
                  });
                }

                if (user.banned) {
                  return send(ws, {
                    type: "error",
                    error: "This account is banned."
                  });
                }

                let room = liveServers.get(serverId);

                if (!room) {
                  room = {
                    players: new Map(),
                    ownerId: serverRow.owner_id,
                    maxPlayers: serverRow.max_players,
                    worldId: serverRow.world_id
                  };

                  liveServers.set(serverId, room);
                }

                if (
                  room.players.size >=
                  room.maxPlayers
                ) {
                  return send(ws, {
                    type: "error",
                    error: "Server is full."
                  });
                }

                currentServerId = serverId;
                currentPlayerId =
                  `${decoded.id}_${randomId("player")}`;
                currentUsername = user.username;

                const player = {
                  id: currentPlayerId,
                  userId: user.id,
                  username: user.username,
                  ws,
                  x: 100,
                  y: 100,
                  avatarColor:
                    user.avatar_color ||
                    "#e53935",
                  hat: user.hat || ""
                };

                room.players.set(
                  currentPlayerId,
                  player
                );

                db.run(
                  `
                  UPDATE game_servers
                  SET last_active_at = ?
                  WHERE server_id = ?
                  `,
                  [Date.now(), serverId]
                );

                const existingPlayers = [];

                for (const p of room.players.values()) {
                  if (p.id !== currentPlayerId) {
                    existingPlayers.push({
                      id: p.id,
                      username: p.username,
                      x: p.x,
                      y: p.y,
                      avatarColor: p.avatarColor,
                      hat: p.hat
                    });
                  }
                }

                send(ws, {
                  type: "joined",
                  serverId,
                  playerId: currentPlayerId,
                  players: existingPlayers
                });

                broadcast(
                  room,
                  {
                    type: "player:joined",
                    player: {
                      id: currentPlayerId,
                      username: player.username,
                      x: player.x,
                      y: player.y,
                      avatarColor: player.avatarColor,
                      hat: player.hat
                    }
                  },
                  ws
                );
              }
            );
          }
        );
      } catch {
        send(ws, {
          type: "error",
          error: "Invalid server login."
        });
      }

      return;
    }

    // ------------------------------
    // PLAYER UPDATE
    // ------------------------------

    if (message.type === "player:update") {
      if (!currentServerId || !currentPlayerId) {
        return;
      }

      const room =
        liveServers.get(currentServerId);

      if (!room) return;

      const player =
        room.players.get(currentPlayerId);

      if (!player) return;

      if (Number.isFinite(Number(message.x))) {
        player.x = Number(message.x);
      }

      if (Number.isFinite(Number(message.y))) {
        player.y = Number(message.y);
      }

      if (message.avatarColor) {
        player.avatarColor =
          String(message.avatarColor);
      }

      if (message.hat !== undefined) {
        player.hat = String(message.hat || "");
      }

      broadcast(
        room,
        {
          type: "player:update",
          player: {
            id: currentPlayerId,
            username: player.username,
            x: player.x,
            y: player.y,
            avatarColor: player.avatarColor,
            hat: player.hat
          }
        },
        ws
      );

      return;
    }

    // ------------------------------
    // GAME EVENT
    // ------------------------------

    if (message.type === "game:event") {
      if (!currentServerId || !currentPlayerId) {
        return;
      }

      const room =
        liveServers.get(currentServerId);

      if (!room) return;

      broadcast(
        room,
        {
          type: "game:event",
          playerId: currentPlayerId,
          event: message.event || {}
        },
        ws
      );

      return;
    }

    // ------------------------------
    // PING
    // ------------------------------

    if (message.type === "ping") {
      send(ws, {
        type: "pong",
        time: Date.now()
      });

      return;
    }

    // ------------------------------
    // LEAVE
    // ------------------------------

    if (message.type === "leave") {
      ws.close();
      return;
    }
  });

  ws.on("close", () => {
    if (!currentServerId || !currentPlayerId) {
      return;
    }

    const room =
      liveServers.get(currentServerId);

    if (!room) return;

    room.players.delete(currentPlayerId);

    broadcast(room, {
      type: "player:left",
      playerId: currentPlayerId
    });

    db.run(
      `
      UPDATE game_servers
      SET last_active_at = ?
      WHERE server_id = ?
      `,
      [Date.now(), currentServerId]
    );

    if (room.players.size === 0) {
      liveServers.delete(currentServerId);
    }

    currentServerId = null;
    currentPlayerId = null;
    currentUsername = null;
  });
});

// --------------------------------------------------
// CLEAN OLD SERVERS
// --------------------------------------------------

setInterval(() => {
  const cutoff =
    Date.now() - 24 * 60 * 60 * 1000;

  db.all(
    `
    SELECT server_id
    FROM game_servers
    WHERE last_active_at < ?
    `,
    [cutoff],
    (err, rows) => {
      if (err) return;

      for (const row of rows || []) {
        closeLiveServer(row.server_id);

        db.run(
          `
          DELETE FROM game_servers
          WHERE server_id = ?
          `,
          [row.server_id]
        );
      }
    }
  );
}, 60 * 60 * 1000);

// --------------------------------------------------
// SPA FALLBACK
// --------------------------------------------------

app.get("*", (req, res, next) => {
  if (
    req.path.startsWith("/api/") ||
    req.path === "/ws"
  ) {
    return next();
  }

  const indexFile =
    path.join(publicPath, "index.html");

  if (fs.existsSync(indexFile)) {
    return res.sendFile(indexFile);
  }

  next();
});

// --------------------------------------------------
// START
// --------------------------------------------------

server.listen(PORT, "0.0.0.0", () => {
  console.log(
    `Spladpad online server listening on ${PORT}`
  );
});
