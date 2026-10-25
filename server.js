import express from "express";
import { promises as fs } from "node:fs";
import path from "node:path";
import os from "node:os";
import crypto from "node:crypto";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import rateLimit from "express-rate-limit";

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { mcpAuthRouter, mcpAuthMetadataRouter, createOAuthMetadata, getOAuthProtectedResourceMetadataUrl } from "@modelcontextprotocol/sdk/server/auth/router.js";
import { requireBearerAuth } from "@modelcontextprotocol/sdk/server/auth/middleware/bearerAuth.js";
import * as z from "zod/v4";

const execFileAsync = promisify(execFile);
const HOME = os.homedir();
const BASE = path.join(HOME, "termux-mcp", "workspace");
const CONFIG = path.join(HOME, ".config", "termux-mcp");
const DB_FILE = path.join(CONFIG, "oauth-db.json");
const PASSWORD_FILE = path.join(CONFIG, "oauth-password");
const PORT = 8000;
const ISSUER = new URL("https://api2.vinzgd.space");
const RESOURCE = new URL("https://api2.vinzgd.space/mcp");
const SCOPE = "mcp:tools";

await fs.mkdir(BASE, { recursive: true });
await fs.mkdir(CONFIG, { recursive: true, mode: 0o700 });
await fs.chmod(CONFIG, 0o700);

if (!(await exists(PASSWORD_FILE))) {
  const password = crypto.randomBytes(18).toString("base64url");
  await fs.writeFile(PASSWORD_FILE, password + "\n", { mode: 0o600, flag: "wx" });
  await fs.chmod(PASSWORD_FILE, 0o600);
  console.log("\n========================================");
  console.log("OAUTH PASSWORD BARU:");
  console.log(password);
  console.log("SIMPAN PASSWORD INI. HANYA DITAMPILKAN SEKALI.");
  console.log("========================================\n");
}

const LOGIN_PASSWORD = (await fs.readFile(PASSWORD_FILE, "utf8")).trim();

async function exists(p) {
  try { await fs.access(p); return true; } catch { return false; }
}

const emptyDB = () => ({ clients: {}, codes: {}, access: {}, refresh: {} });
let db = emptyDB();

if (await exists(DB_FILE)) {
  try {
    db = { ...emptyDB(), ...JSON.parse(await fs.readFile(DB_FILE, "utf8")) };
  } catch {
    throw new Error(`Database OAuth rusak: ${DB_FILE}. Jangan hapus backup.`);
  }
}

async function saveDB() {
  const tmp = DB_FILE + ".tmp";
  await fs.writeFile(tmp, JSON.stringify(db, null, 2), { mode: 0o600 });
  await fs.chmod(tmp, 0o600);
  await fs.rename(tmp, DB_FILE);
}

const randomToken = () => crypto.randomBytes(32).toString("base64url");
const now = () => Math.floor(Date.now() / 1000);
const pendingLogins = new Map();

function safeFile(name) {
  if (
    typeof name !== "string" || !name || name === "." || name === ".." ||
    name.includes("/") || name.includes("\\") ||
    name.includes("\0")
  ) throw new Error("Gunakan nama file langsung di workspace.");
  return path.join(BASE, name);
}

function safeEqual(a, b) {
  const x = Buffer.from(String(a));
  const y = Buffer.from(String(b));
  return x.length === y.length && crypto.timingSafeEqual(x, y);
}

function makeTokens(clientId, scopes = [SCOPE], resource = RESOURCE) {
  const accessToken = randomToken();
  const refreshToken = randomToken();
  const expiresAt = now() + 3600;
  const resourceString = resource?.toString();

  db.access[accessToken] = {
    clientId, scopes, expiresAt, resource: resourceString
  };
  db.refresh[refreshToken] = {
    clientId, scopes, resource: resourceString
  };

  return {
    access_token: accessToken,
    token_type: "Bearer",
    expires_in: 3600,
    refresh_token: refreshToken,
    scope: scopes.join(" ")
  };
}

const provider = {
  get clientsStore() {
    return {
      getClient: async (clientId) => db.clients[clientId],
      registerClient: async (client) => {
        const full = {
          ...client,
          client_id: randomToken(),
          client_id_issued_at: now()
        };
        db.clients[full.client_id] = full;
        await saveDB();
        return full;
      }
    };
  },

  async authorize(client, params, res) {
    console.log("[OAuth] authorize dimulai; client:", client.client_id);
    const loginId = randomToken();
    pendingLogins.set(loginId, {
      clientId: client.client_id,
      redirectUri: params.redirectUri,
      state: params.state,
      codeChallenge: params.codeChallenge,
      scopes: params.scopes?.length ? params.scopes : [SCOPE],
      resource: params.resource?.toString(),
      expiresAt: now() + 300
    });

    const html = `<!doctype html>
<html><head><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Termux MCP Login</title>
<style>
body{font:16px system-ui;max-width:420px;margin:12vh auto;padding:24px}
input,button{box-sizing:border-box;width:100%;padding:13px;margin:8px 0}
button{cursor:pointer}small{color:#666}
</style></head><body>
<h2>Termux MCP</h2>
<p>Masukkan password OAuth Termux untuk mengizinkan koneksi.</p>
<form method="post" action="/oauth-login">
<input type="hidden" name="loginId" value="${loginId}">
<input type="password" name="password" autocomplete="current-password"
placeholder="Password OAuth" required autofocus>
<button type="submit">Login dan lanjutkan</button>
</form><small>Jangan bagikan password ini kepada siapa pun.</small>
</body></html>`;

    res.status(200).type("html").send(html);
  },

  async challengeForAuthorizationCode(client, code) {
    const record = db.codes[code];
    if (!record || record.clientId !== client.client_id || record.expiresAt < now()) {
      throw new Error("Kode otorisasi tidak valid atau kedaluwarsa.");
    }
    return record.codeChallenge;
  },

  async exchangeAuthorizationCode(client, code, verifier, redirectUri, resource) {
    console.log("[OAuth] pertukaran authorization code dimulai");
    try {
    console.log("[OAuth] cek kode, client, verifier, redirect URI");
    const record = db.codes[code];
    if (!record || record.clientId !== client.client_id || record.expiresAt < now()) {
      throw new Error("Kode otorisasi tidak valid atau kedaluwarsa.");
    }
    if (redirectUri && redirectUri !== record.redirectUri) {
      throw new Error("Redirect URI tidak cocok.");
    }

    delete db.codes[code];
    const tokens = makeTokens(
      client.client_id,
      record.scopes,
      resource || (record.resource ? new URL(record.resource) : RESOURCE)
    );
    await saveDB();
    return tokens;
    } catch (err) {
      console.error("[OAuth] token exchange gagal:", err?.message || String(err));
      throw err;
    }
  },

  async exchangeRefreshToken(client, refreshToken, scopes, resource) {
    const record = db.refresh[refreshToken];
    if (!record || record.clientId !== client.client_id) {
      throw new Error("Refresh token tidak valid.");
    }

    const granted = scopes?.length
      ? scopes.filter(s => record.scopes.includes(s))
      : record.scopes;

    if (scopes?.some(s => !record.scopes.includes(s))) {
      throw new Error("Scope tidak diizinkan.");
    }

    delete db.refresh[refreshToken];
    const tokens = makeTokens(
      client.client_id,
      granted,
      resource || (record.resource ? new URL(record.resource) : RESOURCE)
    );
    await saveDB();
    return tokens;
  },

  async verifyAccessToken(token) {
    console.log("[OAuth] validasi access token diminta");
    const record = db.access[token];
    if (!record || record.expiresAt <= now()) {
      if (record) {
        delete db.access[token];
        await saveDB();
      }
      throw new Error("Access token tidak valid atau kedaluwarsa.");
    }

    return {
      token,
      clientId: record.clientId,
      scopes: record.scopes,
      expiresAt: record.expiresAt,
      resource: record.resource ? new URL(record.resource) : undefined
    };
  },

  async revokeToken(client, request) {
    const token = request.token;
    if (db.access[token]?.clientId === client.client_id) delete db.access[token];
    if (db.refresh[token]?.clientId === client.client_id) delete db.refresh[token];
    await saveDB();
  }
};

const app = express();
app.disable("x-powered-by");
app.set("trust proxy", 1);
app.use(express.urlencoded({ extended: false, limit: "10kb" }));
app.use(express.json({ limit: "1mb" }));

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: true,
  legacyHeaders: false
});

app.post("/oauth-login", loginLimiter, async (req, res) => {
  console.log("[OAuth] permintaan login diterima");
  const { loginId, password } = req.body || {};
  const pending = pendingLogins.get(loginId);

  if (!pending || pending.expiresAt < now()) {
    pendingLogins.delete(loginId);
    return res.status(400).send("Login kedaluwarsa. Kembali ke Claude dan coba lagi.");
  }

  if (!safeEqual(password || "", LOGIN_PASSWORD)) {
    return res.status(401).type("html").send(
      "<h2>Password salah</h2><p>Kembali ke halaman sebelumnya dan coba lagi.</p>"
    );
  }

  pendingLogins.delete(loginId);
  const code = randomToken();

  db.codes[code] = {
    ...pending,
    expiresAt: now() + 120
  };
  await saveDB();

  const redirect = new URL(pending.redirectUri);
  redirect.searchParams.set("code", code);
  if (pending.state) redirect.searchParams.set("state", pending.state);

  res.redirect(302, redirect.toString());
});

const oauthOptions = {
  provider,
  issuerUrl: ISSUER,
  scopesSupported: [SCOPE],
  resourceName: "Termux MCP"
};

app.use(mcpAuthRouter(oauthOptions));

app.use(mcpAuthMetadataRouter({
  oauthMetadata: createOAuthMetadata(oauthOptions),
  resourceServerUrl: RESOURCE,
  scopesSupported: [SCOPE],
  resourceName: "Termux MCP"
}));

app.use("/mcp", requireBearerAuth({
  verifier: provider,
  requiredScopes: [SCOPE],
  resourceMetadataUrl: getOAuthProtectedResourceMetadataUrl(RESOURCE),
  expectedResource: RESOURCE
}));

app.post("/mcp", async (req, res) => {
  const server = new McpServer({
    name: "termux-remote",
    version: "1.0.0"
  });

  server.registerTool("list_files", {
    description: "Daftar file workspace Termux.",
    inputSchema: {}
  }, async () => {
    const items = await fs.readdir(BASE, { withFileTypes: true });
    return { content: [{ type: "text", text:
      items.map(x => `${x.isDirectory() ? "[DIR]" : "[FILE]"} ${x.name}`).join("\n")
      || "(workspace kosong)"
    }] };
  });

  server.registerTool("read_file", {
    description: "Membaca file teks di workspace.",
    inputSchema: { name: z.string() }
  }, async ({ name }) => {
    const p = safeFile(name);
    const info = await fs.stat(p);
    if (!info.isFile()) throw new Error("Bukan file biasa.");
    if (info.size > 200000) throw new Error("File terlalu besar.");
    return { content: [{ type: "text", text: await fs.readFile(p, "utf8") }] };
  });

  server.registerTool("write_file", {
    description: "Membuat atau mengganti file teks di workspace.",
    inputSchema: { name: z.string(), content: z.string() }
  }, async ({ name, content }) => {
    if (content.length > 200000) throw new Error("Konten terlalu besar.");
    await fs.writeFile(safeFile(name), content, "utf8");
    return { content: [{ type: "text", text: `Berhasil menyimpan ${name}` }] };
  });

  server.registerTool("run_script", {
    description: "Menjalankan file .py atau .js di workspace. Jalankan hanya skrip yang sudah diperiksa.",
    inputSchema: { name: z.string() }
  }, async ({ name }) => {
    const p = safeFile(name);
    const ext = path.extname(p).toLowerCase();
    if (![".py", ".js"].includes(ext)) throw new Error("Hanya file .py dan .js.");

    const info = await fs.stat(p);
    if (!info.isFile()) throw new Error("Bukan file biasa.");

    try {
      const result = await execFileAsync(
        ext === ".py" ? "python" : process.execPath,
        [p],
        { cwd: BASE, timeout: 30000, maxBuffer: 1024 * 1024 }
      );
      return { content: [{ type: "text", text:
        (result.stdout + "\n" + result.stderr).slice(0, 12000) ||
        "(skrip selesai tanpa output)"
      }] };
    } catch (e) {
      return { content: [{ type: "text", text:
        `Proses gagal atau timeout.\n${(e.stdout || "") + "\n" + (e.stderr || e.message || "")}`.slice(0, 12000)
      }] };
    }
  });

  const transport = new StreamableHTTPServerTransport({
    sessionIdGenerator: undefined
  });

  try {
    await server.connect(transport);
    res.on("close", () => {
      void transport.close();
      void server.close();
    });
    await transport.handleRequest(req, res, req.body);
  } catch (e) {
    console.error("MCP error:", e);
    if (!res.headersSent) res.status(500).json({ error: "Internal MCP error" });
    void transport.close();
    void server.close();
  }
});

app.all("/mcp", (req, res) => res.status(405).send("Method not allowed"));

app.listen(PORT, "127.0.0.1", () => {
  console.log(`Termux MCP + OAuth aktif di http://127.0.0.1:${PORT}`);
  console.log(`Issuer: ${ISSUER}`);
  console.log(`Resource: ${RESOURCE}`);
  console.log("Password disimpan di ~/.config/termux-mcp/oauth-password");
});
