// server.js
import "dotenv/config";
import express from "express";
import cors from "cors";
import morgan from "morgan";
import { z } from "zod";
import slugify from "slugify";
import { putFile } from "./github.js";

const app = express();
app.use(express.json({ limit: "25mb" }));
app.use(morgan("tiny"));
app.use(cors({
  origin: (origin, cb) => cb(null, true), // controle fino via ALLOWED_ORIGINS se necessário
  credentials: false
}));

// Segurança simples por chave
app.use((req, res, next) => {
  const key = process.env.API_KEY;
  if (!key) return next();
  const provided = req.header("x-api-key");
  if (provided !== key) return res.status(401).json({ error: "unauthorized" });
  next();
});

const cfg = {
  token: process.env.GITHUB_TOKEN,
  owner: process.env.GITHUB_OWNER,
  repo: process.env.GITHUB_REPO,
  branch: process.env.DEFAULT_BRANCH || "main"
};

const Scope = z.enum(["global", "demand"]);

function vpad(n) { return String(n).padStart(3, "0"); }
function sanitizeSlug(s) {
  return slugify(s, { lower: true, strict: true, trim: true });
}
function b64(str) {
  return Buffer.from(str, "utf8").toString("base64");
}
function b64bin(binBase64) {
  // já vem base64; apenas normaliza string
  return binBase64.replace(/^data:.*;base64,/, "");
}

function basePaths({ scope, demandSlug, version }) {
  if (scope === "global") return { base: "knowledge/_global", notes: "knowledge/_global/notes" };
  const v = `v${vpad(version || 1)}`;
  const slug = sanitizeSlug(demandSlug || "sem-slug");
  const root = `demands/${slug}/${v}`;
  return {
    base: root,
    notes: `${root}/notes`,
    inputs: `${root}/inputs`,
    outputs: `${root}/outputs`
  };
}

// ---------- Endpoints ----------

// Health
app.get("/api/health", (_req, res) => res.json({ ok: true }));

// Cria estrutura mínima (placeholders) para global ou demanda
app.post("/api/repo/ensure-structure", async (req, res) => {
  const schema = z.object({
    scope: Scope,
    demandSlug: z.string().optional(),
    version: z.number().int().min(1).optional(),
    title: z.string().optional(),
    dryRun: z.boolean().optional()
  });
  const p = schema.parse(req.body);
  const paths = basePaths(p);

  const files = [];
  if (p.scope === "global") {
    files.push({ path: `${paths.base}/README.md`, content: `# Knowledge global\n\n` });
    files.push({ path: `${paths.notes}/.keep`, content: "" });
  } else {
    const title = p.title || p.demandSlug || "Demanda";
    files.push({ path: `${paths.base}/README.md`, content: `# ${title}\n\n` });
    files.push({ path: `${paths.base}/index.json`, content: JSON.stringify({ title, version: p.version || 1 }, null, 2) });
    files.push({ path: `${paths.notes}/.keep`, content: "" });
    files.push({ path: `${paths.inputs}/.keep`, content: "" });
    files.push({ path: `${paths.outputs}/.keep`, content: "" });
  }

  if (p.dryRun) return res.json({ created: files.map(f => f.path) });

  const results = [];
  for (const f of files) {
    const r = await putFile({
      token: cfg.token, owner: cfg.owner, repo: cfg.repo, branch: cfg.branch,
      path: f.path, contentBase64: b64(f.content), message: `ensure-structure: ${f.path}`
    });
    results.push(r);
  }
  res.json({ ok: true, paths, results });
});

// Inicializa demanda com slug e versão
app.post("/api/demand/init", async (req, res) => {
  const schema = z.object({
    slug: z.string().min(1),
    title: z.string().optional(),
    version: z.number().int().min(1).default(1),
    dryRun: z.boolean().optional()
  });
  const p = schema.parse(req.body);
  const args = { scope: "demand", demandSlug: p.slug, version: p.version, title: p.title, dryRun: p.dryRun };
  req.body = args;
  return app._router.handle(req, res, () => {}, "post", "/api/repo/ensure-structure");
});

// Salva nota de conhecimento (global ou demanda)
app.post("/api/knowledge/save", async (req, res) => {
  const schema = z.object({
    scope: Scope,
    demandSlug: z.string().optional(),
    version: z.number().int().min(1).optional(),
    filename: z.string().min(1),     // ex: resumo.md ou metas.json
    content: z.union([z.string(), z.record(z.any())]),
    area: z.enum(["notes","inputs","outputs"]).default("notes")
  });
  const p = schema.parse(req.body);
  const paths = basePaths(p);
  const dir = paths[p.area];

  const text = typeof p.content === "string" ? p.content : JSON.stringify(p.content, null, 2);
  const r = await putFile({
    token: cfg.token, owner: cfg.owner, repo: cfg.repo, branch: cfg.branch,
    path: `${dir}/${p.filename}`,
    contentBase64: b64(text),
    message: `knowledge-save: ${dir}/${p.filename}`
  });
  res.json({ ok: true, path: `${dir}/${p.filename}`, urls: r });
});

// Salva arquivo binário base64 na área indicada e retorna URL raw canônica
app.post("/api/file/save-base64", async (req, res) => {
  const schema = z.object({
    scope: Scope,
    demandSlug: z.string().optional(),
    version: z.number().int().min(1).optional(),
    area: z.enum(["inputs","outputs"]).default("inputs"),
    filename: z.string().min(1), // ex: export.json, imagem.png
    base64: z.string().min(1)
  });
  const p = schema.parse(req.body);
  const paths = basePaths(p);
  const dir = paths[p.area];

  const r = await putFile({
    token: cfg.token, owner: cfg.owner, repo: cfg.repo, branch: cfg.branch,
    path: `${dir}/${p.filename}`,
    contentBase64: b64bin(p.base64),
    message: `file-save: ${dir}/${p.filename}`
  });
  res.json({ ok: true, path: `${dir}/${p.filename}`, urls: r });
});

// Constrói URL canônica raw para qualquer caminho
app.get("/api/url/canonicalize", (req, res) => {
  const path = String(req.query.path || "");
  const url = `https://raw.githubusercontent.com/${cfg.owner}/${cfg.repo}/${cfg.branch}/${path}`;
  res.json({ path, url });
});

app.get("/", (_req, res) => res.json({ service: "orquestrador-ia", docs: "/openapi.yaml" }));

app.listen(process.env.PORT || 3000, () => {
  console.log("listening on", process.env.PORT || 3000);
});
