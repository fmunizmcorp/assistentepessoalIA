import "dotenv/config";
import express from "express";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import cors from "cors";
import morgan from "morgan";
import axios from "axios";
import PQueue from "p-queue";
import pRetry from "p-retry";
import { v4 as uuidv4 } from "uuid";
import { z } from "zod";
import slugify from "slugify";
import CryptoJS from "crypto-js";
import { putFile } from "./github.js";

// -------- app base --------
const app = express();
app.use(express.json({ limit: "10mb" }));
app.use(helmet());
app.use(rateLimit({ windowMs: 60_000, max: 80 }));
app.use(morgan("tiny"));
app.use(cors({
  origin: (origin, cb) => {
    const allowed = process.env.ALLOWED_ORIGINS?.split(",").map(s=>s.trim()) || ["*"];
    if (allowed.includes("*") || (origin && allowed.includes(origin))) return cb(null, true);
    return cb(null, false);
  }
}));

// auth por chave
app.use((req,res,next)=>{
  const key = process.env.API_KEY;
  if (!key) return next();
  if (req.headers["x-api-key"] !== key) return res.status(401).json({ error: "unauthorized" });
  next();
});

// cfg repo GitHub
const cfg = {
  token: process.env.GITHUB_TOKEN,
  owner: process.env.GITHUB_OWNER,
  repo: process.env.GITHUB_REPO,
  branch: process.env.DEFAULT_BRANCH || "main"
};

// util
const Scope = z.enum(["global","demand"]);
const b64 = s => Buffer.from(s,"utf8").toString("base64");
const b64bin = s => s.replace(/^data:.*;base64,/, "");
const vpad = n => String(n).padStart(3,"0");
const sanitize = s => slugify(s || "sem-slug", { lower: true, strict: true, trim: true });

function basePaths({ scope, demandSlug, version }) {
  if (scope === "global") return { base:"knowledge/_global", notes:"knowledge/_global/notes" };
  const v = `v${vpad(version || 1)}`, slug = sanitize(demandSlug);
  const root = `demands/${slug}/${v}`;
  return { base:root, notes:`${root}/notes`, inputs:`${root}/inputs`, outputs:`${root}/outputs` };
}

// -------- health --------
app.get("/", (_req,res)=>res.json({ service:"ai-orchestrator", docs:"/openapi.yaml" }));
app.get("/api/health", (_req,res)=>res.json({ ok:true }));
app.get("/health", (_req,res)=>res.json({ ok:true })); // compat

// -------- estrutura de repositório (anti-transferência entre IAs) --------
app.post("/api/repo/ensure-structure", async (req,res)=>{
  const schema = z.object({ scope: Scope, demandSlug:z.string().optional(), version:z.number().int().min(1).optional(), title:z.string().optional(), dryRun:z.boolean().optional() });
  const p = schema.parse(req.body);
  const paths = basePaths(p);
  const files = [];
  if (p.scope === "global") {
    files.push({ path:`${paths.base}/README.md`, content:"# Knowledge global\n\n" });
    files.push({ path:`${paths.notes}/.keep`, content:"" });
  } else {
    const title = p.title || p.demandSlug || "Demanda";
    files.push({ path:`${paths.base}/README.md`, content:`# ${title}\n\n` });
    files.push({ path:`${paths.base}/index.json`, content: JSON.stringify({ title, version: p.version || 1 }, null, 2) });
    files.push({ path:`${paths.notes}/.keep`, content:"" });
    files.push({ path:`${paths.inputs}/.keep`, content:"" });
    files.push({ path:`${paths.outputs}/.keep`, content:"" });
  }
  if (p.dryRun) return res.json({ created: files.map(f=>f.path) });
  const results=[];
  for (const f of files) {
    const r = await putFile({ token:cfg.token, owner:cfg.owner, repo:cfg.repo, branch:cfg.branch, path:f.path, contentBase64:b64(f.content), message:`ensure-structure: ${f.path}` });
    results.push(r);
  }
  res.json({ ok:true, paths, results });
});

app.post("/api/demand/init", async (req,res)=>{
  const body = z.object({ slug:z.string().min(1), title:z.string().optional(), version:z.number().int().min(1).default(1), dryRun:z.boolean().optional() }).parse(req.body);
  req.url = "/api/repo/ensure-structure";
  req.body = { scope:"demand", demandSlug: body.slug, version: body.version, title: body.title, dryRun: body.dryRun };
  app._router.handle(req,res);
});

app.post("/api/knowledge/save", async (req,res)=>{
  const body = z.object({
    scope: Scope, demandSlug: z.string().optional(), version: z.number().int().min(1).optional(),
    filename: z.string().min(1),
    content: z.union([z.string(), z.record(z.any())]),
    area: z.enum(["notes","inputs","outputs"]).default("notes")
  }).parse(req.body);
  const paths = basePaths(body);
  const dir = paths[body.area];
  const text = typeof body.content === "string" ? body.content : JSON.stringify(body.content, null, 2);
  const r = await putFile({ token:cfg.token, owner:cfg.owner, repo:cfg.repo, branch:cfg.branch, path:`${dir}/${body.filename}`, contentBase64:b64(text), message:`knowledge-save: ${dir}/${body.filename}` });
  res.json({ ok:true, path:`${dir}/${body.filename}`, urls:r });
});

app.post("/api/file/save-base64", async (req,res)=>{
  const body = z.object({
    scope: Scope, demandSlug:z.string().optional(), version:z.number().int().min(1).optional(),
    area: z.enum(["inputs","outputs"]).default("inputs"),
    filename: z.string().min(1),
    base64: z.string().min(1)
  }).parse(req.body);
  const paths = basePaths(body);
  const dir = paths[body.area];
  const r = await putFile({ token:cfg.token, owner:cfg.owner, repo:cfg.repo, branch:cfg.branch, path:`${dir}/${body.filename}`, contentBase64:b64bin(body.base64), message:`file-save: ${dir}/${body.filename}` });
  res.json({ ok:true, path:`${dir}/${body.filename}`, urls:r });
});

app.get("/api/url/canonicalize", (req,res)=>{
  const path = String(req.query.path||"");
  const url = `https://raw.githubusercontent.com/${cfg.owner}/${cfg.repo}/${cfg.branch}/${path}`;
  res.json({ path, url });
});

// -------- orquestração (demandas, passos, fan-out, cross-review) --------
const queue = new PQueue({ concurrency: 6 });
const COST_TABLE = { openai:{input:0.30, output:0.60}, grok:{input:0.20, output:0.40}, genspark:{input:0.15, output:0.30}, manus:{input:0.12, output:0.24} };

const RepoTarget = z.object({ kind:z.enum(["gitlab","github","none"]).default("none"), projectId:z.string().optional(), ownerRepo:z.string().optional() });
const ProvidersCfg = z.object({
  openai: z.object({ apiKey:z.string() }).optional(),
  grok: z.object({ apiKey:z.string(), baseUrl:z.string().url().optional() }).optional(),
  genspark: z.object({ apiKey:z.string(), baseUrl:z.string().url().optional() }).optional(),
  manus: z.object({ apiKey:z.string(), baseUrl:z.string().url().optional() }).optional(),
  replicate: z.object({ apiToken:z.string(), baseUrl:z.string().url().optional() }).optional()
}).default({});

const DemandNewBody = z.object({ title:z.string().min(3), description:z.string().optional(), tags:z.array(z.string()).optional(), owner:z.string().optional(), repoTarget:RepoTarget.optional() });
const StepAppendBody = z.object({
  demandId:z.string(),
  title:z.string(),
  kind:z.enum(["research","code","browser-test","doc","presentation","cost-review","plan-review","image","video","ops","summary"]),
  input:z.any(),
  acceptance: z.object({ mustInclude: z.array(z.string()).optional(), maxTokens: z.number().optional() }).optional(),
  routeHint: z.enum(["cheap","balanced","best","force-openai","force-grok","force-genspark","force-manus"]).default("balanced"),
  fallbackProviders: z.array(z.enum(["openai","grok","genspark","manus"])).optional(),
  realign: z.object({ mode:z.enum(["switch","same","both"]).default("both"), revisedInput:z.any().optional(), maxSame:z.number().int().min(1).max(3).default(1) }).optional(),
  providers: ProvidersCfg
});
const PromptComposeBody = z.object({ taskType:z.enum(["doc","presentation","cost-review","plan-review","code","browser-test","image","video","summary"]), context:z.any().optional(), constraints:z.any().optional(), style:z.any().optional(), outputFormat:z.enum(["markdown","json","ppt-md","plan-md","prompt"]).default("markdown") });
const AutoRunBody = z.object({
  demandId:z.string(),
  plan:z.array(z.object({
    title:z.string(), kind:StepAppendBody.shape.kind, input:z.any(),
    acceptance:StepAppendBody.shape.acceptance.optional(),
    routeHint:StepAppendBody.shape.routeHint.optional(),
    fallbackProviders:StepAppendBody.shape.fallbackProviders.optional(),
    realign:StepAppendBody.shape.realign.optional()
  })),
  providers: ProvidersCfg,
  maxSwitches: z.number().int().min(0).max(10).default(3)
});
const FanoutBody = z.object({
  demandId:z.string(), title:z.string(),
  branches:z.array(z.object({ title:z.string(), kind:StepAppendBody.shape.kind, input:z.any(), provider:z.enum(["openai","grok","genspark","manus"]).optional(), routeHint:StepAppendBody.shape.routeHint.optional(), acceptance:StepAppendBody.shape.acceptance.optional() })).min(2),
  consolidate:z.object({ enabled:z.boolean().default(true), provider:z.enum(["openai","grok","genspark","manus"]).optional(), routeHint:StepAppendBody.shape.routeHint.optional(), acceptance:StepAppendBody.shape.acceptance.optional(), instructions:z.string().optional() }).optional(),
  providers: ProvidersCfg
});
const CrossReviewBody = z.object({
  demandId:z.string(), title:z.string(),
  producer:z.object({ title:z.string(), kind:StepAppendBody.shape.kind, input:z.any(), provider:z.enum(["openai","grok","genspark","manus"]).optional(), routeHint:StepAppendBody.shape.routeHint.optional(), acceptance:StepAppendBody.shape.acceptance.optional() }),
  reviewers:z.array(z.object({ title:z.string(), kind:StepAppendBody.shape.kind.optional(), instruction:z.string().optional(), provider:z.enum(["openai","grok","genspark","manus"]).optional(), routeHint:StepAppendBody.shape.routeHint.optional(), acceptance:StepAppendBody.shape.acceptance.optional() })).min(1),
  iterations:z.number().int().min(1).max(5).default(1),
  providers: ProvidersCfg
});
const SaveDocBody = z.object({
  demandId:z.string(), target:z.enum(["gitlab","github","gdrive"]), path:z.string(), content:z.string(), message:z.string().default("update from ai-orchestrator"),
  tokens:z.object({
    gitlab:z.object({ token:z.string(), projectId:z.string() }).optional(),
    github:z.object({ token:z.string(), ownerRepo:z.string() }).optional(),
    gdrive:z.object({ token:z.string(), parentId:z.string().optional() }).optional()
  })
});

const catalog = new Map();

app.post("/api/orch/demand/new",(req,res)=>{
  const b = DemandNewBody.parse(req.body);
  const id = uuidv4();
  catalog.set(id,{ meta:{ id, createdAt:new Date().toISOString(), ...b }, steps:[], status:"open", providersUsed:[], decisions:[] });
  res.json({ ok:true, demandId:id });
});
app.get("/api/orch/demand", (_req,res)=>res.json([...catalog.values()].map(d=>d.meta)));
app.get("/api/orch/demand/:id", (req,res)=>{ const d=catalog.get(req.params.id); if(!d) return res.status(404).json({ error:"not found" }); res.json(d); });

app.post("/api/orch/prompt/compose",(req,res)=>{
  const b = PromptComposeBody.parse(req.body);
  const systemHead = [
    "Seja sério, sóbrio e honesto.",
    "Sem elogios, sem autopromoção, sem otimismo indevido.",
    "Use dados reais verificáveis; nunca invente; evite mock.",
    "Planeje antes; hiperfracionar; só avance após TESTAR.",
    "Perspectiva do usuário final; quando possível, testes via navegador.",
    "Se houver desvio/saturação, re-prompt na mesma IA ou troque de provedor; documente."
  ].join(" ");
  const tasks = {
    doc:"Documento com seções, fontes e checklist.",
    presentation:"Slides em Markdown (título, bullets, notas).",
    "cost-review":"Revisão de custos: premissas, fontes, tabela, riscos.",
    "plan-review":"Auditoria de plano: lacunas, dependências, marcos, KPIs.",
    code:"Código com testes e passos de execução/validação.",
    "browser-test":"Testes E2E de navegação com evidências.",
    image:"Brief detalhado de imagem.",
    video:"Roteiro de vídeo curto.",
    summary:"Resumo executivo e próximos passos."
  };
  res.json({ ok:true, prompt:{ tipo:b.taskType, sistema:systemHead, tarefa:tasks[b.taskType], contexto:b.context??{}, restricoes:b.constraints??{}, estilo:b.style??{}, formato:b.outputFormat } });
});

function pickProvider(kind, routeHint){
  if (routeHint?.startsWith("force-")) return routeHint.replace("force-","");
  if (["image","video"].includes(kind)) return "openai";
  if (kind==="code") return "openai";
  if (["browser-test","research"].includes(kind)) return "grok";
  if (["doc","presentation","summary","plan-review","cost-review"].includes(kind)) return "manus";
  if (kind==="ops") return "genspark";
  return "openai";
}

async function runProvider(provider, input, providersCfg){
  if (provider==="openai"){
    if (!providersCfg.openai?.apiKey) throw new Error("openai apiKey ausente");
    const r = await axios.post("https://api.openai.com/v1/chat/completions", {
      model:"gpt-4o-mini",
      messages:[
        { role:"system", content:"Preciso, sóbrio e conciso. Sem hype. Dados reais." },
        { role:"user", content: JSON.stringify(input) }
      ]
    }, { headers:{ Authorization:`Bearer ${providersCfg.openai.apiKey}` }});
    return { provider, data:r.data, cost:COST_TABLE.openai };
  }
  if (provider==="grok"){
    if (!providersCfg.grok?.apiKey) throw new Error("grok apiKey ausente");
    const base = providersCfg.grok.baseUrl || "https://api.x.ai";
    const r = await axios.post(`${base}/v1/chat/completions`, { model:"grok-2-latest", messages:[{ role:"user", content: JSON.stringify(input) }] }, { headers:{ Authorization:`Bearer ${providersCfg.grok.apiKey}` }});
    return { provider, data:r.data, cost:COST_TABLE.grok };
  }
  if (provider==="genspark"){
    if (!providersCfg.genspark?.apiKey) throw new Error("genspark apiKey ausente");
    const base = providersCfg.genspark.baseUrl || "https://api.genspark.ai";
    const r = await axios.post(`${base}/v1/chat/completions`, { model:"genspark-latest", messages:[{ role:"user", content: JSON.stringify(input) }] }, { headers:{ Authorization:`Bearer ${providersCfg.genspark.apiKey}` }});
    return { provider, data:r.data, cost:COST_TABLE.genspark };
  }
  if (provider==="manus"){
    if (!providersCfg.manus?.apiKey) throw new Error("manus apiKey ausente");
    const base = providersCfg.manus.baseUrl || "https://api.manus.ai";
    const r = await axios.post(`${base}/v1/chat/completions`, { model:"manus-doc-latest", messages:[{ role:"user", content: JSON.stringify(input) }] }, { headers:{ Authorization:`Bearer ${providersCfg.manus.apiKey}` }});
    return { provider, data:r.data, cost:COST_TABLE.manus };
  }
  throw new Error("provider inválido");
}

function validate(text, acceptance){
  if (!acceptance) return { ok:true, reasons:[] };
  const reasons=[];
  for (const req of acceptance.mustInclude || []) {
    if (!text || !text.toLowerCase().includes(req.toLowerCase())) reasons.push(`faltou: ${req}`);
  }
  return { ok: reasons.length===0, reasons };
}

app.post("/api/orch/step/append", async (req,res)=>{
  const b = StepAppendBody.parse(req.body);
  const d = catalog.get(b.demandId);
  if (!d) return res.status(404).json({ error:"demandId not found" });

  const primary = pickProvider(b.kind, b.routeHint);
  const order = [primary, ...(b.fallbackProviders||[]).filter(p=>p!==primary)];
  const realign = b.realign ?? { mode:"both", maxSame:1 };

  let last=null;

  // tentativa principal
  try{
    const s=Date.now(); const out=await pRetry(()=>queue.add(()=>runProvider(primary,b.input,b.providers)),{ retries:1 });
    const e=Date.now(); const text=JSON.stringify(out.data); const v=validate(text,b.acceptance);
    const rec={ id:uuidv4(), title:b.title, kind:b.kind, provider:primary, input:b.input, output:out.data, ms:e-s, costEstimatePer1k:out.cost, compliance:v };
    d.steps.push(rec); d.providersUsed.push(primary); d.decisions.push({ when:new Date().toISOString(), action:"run", provider:primary, ok:v.ok, reasons:v.reasons||[] });
    if (v.ok) return res.json({ ok:true, step:rec, tried:[primary] });

    if (realign.mode==="same" || realign.mode==="both"){
      for (let i=0;i<realign.maxSame;i++){
        const revised = realign.revisedInput ?? { ...b.input, corrective_instructions:"Realinhar: cumprir acceptance.mustInclude com evidências reais." };
        const s2=Date.now(); const o2=await pRetry(()=>queue.add(()=>runProvider(primary,revised,b.providers)),{ retries:0 });
        const e2=Date.now(); const t2=JSON.stringify(o2.data); const v2=validate(t2,b.acceptance);
        const rec2={ id:uuidv4(), title:`${b.title} (realign:${i+1})`, kind:b.kind, provider:primary, input:revised, output:o2.data, ms:e2-s2, costEstimatePer1k:o2.cost, compliance:v2 };
        d.steps.push(rec2); d.decisions.push({ when:new Date().toISOString(), action:"realign", provider:primary, ok:v2.ok, reasons:v2.reasons||[] });
        if (v2.ok) return res.json({ ok:true, step:rec2, tried:[primary] });
      }
    }
  }catch(e){ last=e; d.decisions.push({ when:new Date().toISOString(), action:"error", provider:primary, err:String(e) }); }

  if (realign.mode==="switch" || realign.mode==="both"){
    for (const prov of order.filter(p=>p!==primary)){
      try{
        const s=Date.now(); const o=await pRetry(()=>queue.add(()=>runProvider(prov,b.input,b.providers)),{ retries:1 });
        const e=Date.now(); const t=JSON.stringify(o.data); const v=validate(t,b.acceptance);
        const rec={ id:uuidv4(), title:`${b.title} (fallback:${prov})`, kind:b.kind, provider:prov, input:b.input, output:o.data, ms:e-s, costEstimatePer1k:o.cost, compliance:v };
        d.steps.push(rec); d.providersUsed.push(prov); d.decisions.push({ when:new Date().toISOString(), action:"fallback", provider:prov, ok:v.ok, reasons:v.reasons||[] });
        if (v.ok) return res.json({ ok:true, step:rec, tried:[primary,...order.filter(p=>p!==primary)] });
        last = new Error("não conformidade");
      }catch(e){ last=e; d.decisions.push({ when:new Date().toISOString(), action:"error", provider:prov, err:String(e) }); }
    }
  }
  res.status(400).json({ error:String(last||"falha"), tried:order });
});

app.post("/api/orch/auto/run", async (req,res)=>{
  const b = AutoRunBody.parse(req.body);
  const d = catalog.get(b.demandId);
  if (!d) return res.status(404).json({ error:"demandId not found" });

  const results=[];
  for (const p of b.plan){
    const r = await axios.post("http://localhost:"+ (process.env.PORT || 8080) +"/api/orch/step/append", {
      demandId:b.demandId, title:p.title, kind:p.kind, input:p.input,
      acceptance:p.acceptance, routeHint:p.routeHint || "balanced",
      fallbackProviders:p.fallbackProviders || ["openai","grok","manus","genspark"],
      realign:p.realign || { mode:"both", maxSame:1 },
      providers:b.providers
    }).then(x=>x.data).catch(e=>({ ok:false, error:String(e) }));
    results.push(r);
  }
  res.json({ ok:true, results });
});

app.post("/api/orch/fanout", async (req,res)=>{
  const b = FanoutBody.parse(req.body);
  const d = catalog.get(b.demandId);
  if (!d) return res.status(404).json({ error:"demandId not found" });

  const runBranch = (br, idx)=> async ()=>{
    const prov = br.provider ?? pickProvider(br.kind, br.routeHint);
    const s=Date.now(); const o=await runProvider(prov, br.input, b.providers); const e=Date.now();
    const t=JSON.stringify(o.data); const v=validate(t, br.acceptance);
    const rec={ id:uuidv4(), title:`${b.title} / ${br.title}`, kind:br.kind, provider:prov, input:br.input, output:o.data, ms:e-s, costEstimatePer1k:o.cost, compliance:v, branchIndex:idx };
    d.steps.push(rec); d.providersUsed.push(prov); d.decisions.push({ when:new Date().toISOString(), action:"fanout-branch", provider:prov, ok:v.ok, reasons:v.reasons||[] });
    return rec;
  };

  let branchResults=[];
  try{ branchResults = await Promise.all(b.branches.map((br,i)=>queue.add(runBranch(br,i)))); }
  catch(e){ return res.status(400).json({ error:String(e) }); }

  let consolidation=null;
  if (b.consolidate?.enabled){
    const consProv = b.consolidate.provider ?? "manus";
    const input = { instruction: b.consolidate.instructions || "Consolidar resultados: comparar, remover redundâncias, resolver conflitos, citar fontes, prós/contras por provedor e conclusão executável.", branches: branchResults.map(r=>({ provider:r.provider, title:r.title, output:r.output })) };
    const s=Date.now(); const o=await runProvider(consProv, input, b.providers); const e=Date.now();
    consolidation = { id:uuidv4(), title:`${b.title} / Consolidação`, kind:"summary", provider:consProv, input, output:o.data, ms:e-s, costEstimatePer1k:o.cost, compliance:{ ok:true, reasons:[] } };
    d.steps.push(consolidation); d.providersUsed.push(consProv); d.decisions.push({ when:new Date().toISOString(), action:"fanout-consolidate", provider:consProv, ok:true, reasons:[] });
  }
  res.json({ ok:true, branches:branchResults, consolidation });
});

app.post("/api/orch/cross-review", async (req,res)=>{
  const b = CrossReviewBody.parse(req.body);
  const d = catalog.get(b.demandId);
  if (!d) return res.status(404).json({ error:"demandId not found" });

  const prodProv = b.producer.provider ?? pickProvider(b.producer.kind, b.producer.routeHint);
  const s=Date.now(); const o=await runProvider(prodProv, b.producer.input, b.providers); const e=Date.now();
  let current = { id:uuidv4(), title:`${b.title} / Producer`, kind:b.producer.kind, provider:prodProv, input:b.producer.input, output:o.data, ms:e-s, costEstimatePer1k:o.cost, compliance:validate(JSON.stringify(o.data), b.producer.acceptance) };
  d.steps.push(current); d.providersUsed.push(prodProv); d.decisions.push({ when:new Date().toISOString(), action:"produce", provider:prodProv, ok:true, reasons:[] });

  const trail=[current];
  for (let it=0; it<b.iterations; it++){
    for (const rv of b.reviewers){
      const rvProv = rv.provider ?? pickProvider(rv.kind ?? "doc", rv.routeHint);
      const rvInput = { instruction: rv.instruction || "Revisar e corrigir para conformidade integral. Aponte falhas e corrija.", previousOutput: current.output };
      const s2=Date.now(); const o2=await runProvider(rvProv, rvInput, b.providers); const e2=Date.now();
      const step = { id:uuidv4(), title:`${b.title} / Review by ${rvProv}`, kind: rv.kind ?? "doc", provider:rvProv, input:rvInput, output:o2.data, ms:e2-s2, costEstimatePer1k:o2.cost, compliance:validate(JSON.stringify(o2.data), rv.acceptance), reviewedStepId: current.id };
      d.steps.push(step); d.providersUsed.push(rvProv); d.decisions.push({ when:new Date().toISOString(), action:"review", provider:rvProv, ok:true, reasons:[] });
      trail.push(step); current = step;
    }
  }
  res.json({ ok:true, trail });
});

// -------- integrações (salvar docs, webhooks) --------
app.post("/api/integrations/save-doc", async (req,res)=>{
  const b = SaveDocBody.parse(req.body);
  if (!catalog.has(b.demandId)) return res.status(404).json({ error:"demandId not found" });
  try{
    if (b.target==="gitlab"){
      const { token, projectId } = b.tokens.gitlab || {}; if(!token||!projectId) throw new Error("gitlab token/projectId ausentes");
      const encPath = encodeURIComponent(b.path);
      try{
        await axios.put(`https://gitlab.com/api/v4/projects/${encodeURIComponent(projectId)}/repository/files/${encPath}`, { branch:"main", content:b.content, commit_message:b.message, encoding:"text" }, { headers:{ "PRIVATE-TOKEN": token }});
      }catch{
        await axios.post(`https://gitlab.com/api/v4/projects/${encodeURIComponent(projectId)}/repository/files/${encPath}`, { branch:"main", content:b.content, commit_message:b.message, encoding:"text" }, { headers:{ "PRIVATE-TOKEN": token }});
      }
    }
    if (b.target==="github"){
      const { token, ownerRepo } = b.tokens.github || {}; if(!token||!ownerRepo) throw new Error("github token/ownerRepo ausentes");
      let sha=null;
      try{ const g=await axios.get(`https://api.github.com/repos/${ownerRepo}/contents/${b.path}`, { headers:{ Authorization:`Bearer ${token}` }}); sha=g.data.sha; }catch{}
      const b64c = Buffer.from(b.content,"utf8").toString("base64");
      await axios.put(`https://api.github.com/repos/${ownerRepo}/contents/${b.path}`, { message:b.message, content:b64c, sha }, { headers:{ Authorization:`Bearer ${token}` }});
    }
    if (b.target==="gdrive"){
      const { token, parentId } = b.tokens.gdrive || {}; if(!token) throw new Error("gdrive token ausente");
      const metadata = { name: b.path.split("/").pop(), mimeType: "text/markdown", parents: parentId ? [parentId] : [] };
      const boundary = "BOUND"+Date.now();
      const multipart =
        `--${boundary}\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n`+JSON.stringify(metadata)+
        `\r\n--${boundary}\r\nContent-Type: text/markdown\r\n\r\n`+b.content+`\r\n--${boundary}--`;
      await axios.post("https://www.googleapis.com/upload/drive/v3/files?uploadType=multipart", multipart, { headers:{ Authorization:`Bearer ${token}`, "Content-Type":`multipart/related; boundary=${boundary}` }});
    }
    res.json({ ok:true });
  }catch(e){ res.status(400).json({ error:String(e.message||e) }); }
});

function encryptJson(obj, pass){ return CryptoJS.AES.encrypt(JSON.stringify(obj), pass).toString(); }
function decryptToJson(cipher, pass){ const bytes = CryptoJS.AES.decrypt(cipher, pass); return JSON.parse(bytes.toString(CryptoJS.enc.Utf8)); }

app.post("/api/credentials/put", async (req,res)=>{
  const body = z.object({
    passphrase:z.string().min(6),
    secrets: ProvidersCfg,
    target:z.enum(["gitlab","github"]).default("github"),
    path:z.string().default("secrets/providers.enc"),
    tokens:z.object({ gitlab:z.object({ token:z.string(), projectId:z.string() }).optional(), github:z.object({ token:z.string(), ownerRepo:z.string() }).optional() })
  }).parse(req.body);

  const cipher = encryptJson(body.secrets, body.passphrase);
  if (body.target==="gitlab"){
    const { token, projectId } = body.tokens.gitlab || {}; if(!token||!projectId) return res.status(400).json({ error:"gitlab token/projectId ausentes" });
    const encPath = encodeURIComponent(body.path);
    try{
      await axios.put(`https://gitlab.com/api/v4/projects/${encodeURIComponent(projectId)}/repository/files/${encPath}`, { branch:"main", content:cipher, commit_message:"store encrypted providers", encoding:"text" }, { headers:{ "PRIVATE-TOKEN": token }});
    }catch{
      await axios.post(`https://gitlab.com/api/v4/projects/${encodeURIComponent(projectId)}/repository/files/${encPath}`, { branch:"main", content:cipher, commit_message:"store encrypted providers", encoding:"text" }, { headers:{ "PRIVATE-TOKEN": token }});
    }
    return res.json({ ok:true, path:body.path });
  }
  const { token, ownerRepo } = body.tokens.github || {}; if(!token||!ownerRepo) return res.status(400).json({ error:"github token/ownerRepo ausentes" });
  let sha=null;
  try{ const g=await axios.get(`https://api.github.com/repos/${ownerRepo}/contents/${body.path}`, { headers:{ Authorization:`Bearer ${token}` }}); sha=g.data.sha; }catch{}
  const b64c = Buffer.from(cipher,"utf8").toString("base64");
  await axios.put(`https://api.github.com/repos/${ownerRepo}/contents/${body.path}`, { message:"store encrypted providers", content:b64c, sha }, { headers:{ Authorization:`Bearer ${token}` }});
  res.json({ ok:true, path:body.path });
});

app.post("/api/credentials/get", async (req,res)=>{
  const body = z.object({
    passphrase:z.string().min(6),
    target:z.enum(["gitlab","github"]).default("github"),
    path:z.string().default("secrets/providers.enc"),
    tokens:z.object({ gitlab:z.object({ token:z.string(), projectId:z.string() }).optional(), github:z.object({ token:z.string(), ownerRepo:z.string() }).optional() })
  }).parse(req.body);

  let cipher=null;
  if (body.target==="gitlab"){
    const { token, projectId } = body.tokens.gitlab || {}; if(!token||!projectId) return res.status(400).json({ error:"gitlab token/projectId ausentes" });
    const encPath = encodeURIComponent(body.path);
    const r = await axios.get(`https://gitlab.com/api/v4/projects/${encodeURIComponent(projectId)}/repository/files/${encPath}/raw?ref=main`, { headers:{ "PRIVATE-TOKEN": token }});
    cipher = r.data;
  } else {
    const { token, ownerRepo } = body.tokens.github || {}; if(!token||!ownerRepo) return res.status(400).json({ error:"github token/ownerRepo ausentes" });
    const r = await axios.get(`https://api.github.com/repos/${ownerRepo}/contents/${body.path}`, { headers:{ Authorization:`Bearer ${token}` }});
    cipher = Buffer.from(r.data.content,"base64").toString("utf8");
  }
  try{ const secrets = decryptToJson(cipher, body.passphrase); res.json({ ok:true, secrets }); }
  catch{ res.status(400).json({ error:"passphrase inválida" }); }
});

// -------- termos / privacidade --------
app.get("/privacy", (_req,res)=>res.type("text/html").send(`<!doctype html><meta charset="utf-8"><title>Política de Privacidade</title><h1>Política de Privacidade</h1><p>Contato: <a href="mailto:fmunizm@gmail.com">fmunizm@gmail.com</a></p><p>Persistência ocorre nos repositórios/Drives indicados por você. Credenciais podem ser salvas cifradas (AES) no seu repositório, sob sua decisão.</p>`));
app.get("/terms", (_req,res)=>res.type("text/html").send(`<!doctype html><meta charset="utf-8"><title>Termos de Uso</title><h1>Termos de Uso</h1><p>Contato: <a href="mailto:fmunizm@gmail.com">fmunizm@gmail.com</a></p><ol><li>Serviço "como está".</li><li>Você controla repositórios, integrações e retenção.</li><li>Valide antes de uso crítico.</li></ol>`));

// start
const PORT = process.env.PORT || 8080;
app.listen(PORT, "0.0.0.0", ()=>console.log("up:"+PORT));
