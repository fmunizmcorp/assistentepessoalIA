import express from "express";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import cors from "cors";
import axios from "axios";
import PQueue from "p-queue";
import pRetry from "p-retry";
import { v4 as uuidv4 } from "uuid";
import { z } from "zod";
import CryptoJS from "crypto-js";
import slugify from "slugify";
import mime from "mime-types";

const app = express();
app.use(express.json({ limit: "5mb" }));
app.use(helmet());
app.use(rateLimit({ windowMs: 60_000, max: 60 }));

// ---------- Allowed Domains ----------
const DEFAULT_ALLOWED = [
  "https://assistentepessoalia.onrender.com"
];
const ALLOWED = (process.env.ALLOWED_ORIGINS || "")
  .split(",")
  .map(s => s.trim())
  .filter(Boolean)
  .concat(DEFAULT_ALLOWED);

app.use(cors({
  origin: (origin, cb) => {
    if (!origin) return cb(null, true);
    if (ALLOWED.includes(origin)) return cb(null, true);
    return cb(new Error("Origin not allowed"), false);
  }
}));

app.get("/allowed-origins", (_req,res)=> res.json({ allowed: ALLOWED }));

app.get("/", (_req, res) => res.type("text/plain").send("ok"));
app.get("/health", (_req, res) => res.json({ ok: true }));

// ---------- Execução ----------
const queue = new PQueue({ concurrency: 6 });

// custos estimados por 1k tokens (indicativo)
const COST_TABLE = {
  openai:  { input: 0.30, output: 0.60 },
  grok:    { input: 0.20, output: 0.40 },
  genspark:{ input: 0.15, output: 0.30 },
  manus:   { input: 0.12, output: 0.24 }
};

// ---------- Schemas ----------
const RepoTarget = z.object({
  kind: z.enum(["gitlab","github","none"]).default("none"),
  projectId: z.string().optional(),  // GitLab
  ownerRepo: z.string().optional()   // GitHub "owner/repo"
});

const ProvidersCfg = z.object({
  openai:   z.object({ apiKey: z.string() }).optional(),
  grok:     z.object({ apiKey: z.string(), baseUrl: z.string().url().optional() }).optional(),
  genspark: z.object({ apiKey: z.string(), baseUrl: z.string().url().optional() }).optional(),
  manus:    z.object({ apiKey: z.string(), baseUrl: z.string().url().optional() }).optional(),
  replicate:z.object({ apiToken: z.string(), baseUrl: z.string().url().optional() }).optional()
}).default({});

const DemandNewBody = z.object({
  title: z.string().min(3),
  description: z.string().optional(),
  tags: z.array(z.string()).optional(),
  owner: z.string().optional(),
  repoTarget: RepoTarget.optional()
});

const StepAppendBody = z.object({
  demandId: z.string(),
  title: z.string(),
  kind: z.enum([
    "research","code","browser-test","doc","presentation","cost-review",
    "plan-review","image","video","ops","summary"
  ]),
  input: z.any(),
  acceptance: z.object({
    mustInclude: z.array(z.string()).optional(),
    maxTokens: z.number().optional()
  }).optional(),
  routeHint: z.enum(["cheap","balanced","best","force-openai","force-grok","force-genspark","force-manus"]).default("balanced"),
  fallbackProviders: z.array(z.enum(["openai","grok","genspark","manus"])).optional(),
  realign: z.object({
    mode: z.enum(["switch","same","both"]).default("both"),
    revisedInput: z.any().optional(),
    maxSame: z.number().int().min(1).max(3).default(1)
  }).optional(),
  providers: ProvidersCfg
});

const PromptComposeBody = z.object({
  taskType: z.enum(["doc","presentation","cost-review","plan-review","code","browser-test","image","video","summary"]),
  context: z.any().optional(),
  constraints: z.any().optional(),
  style: z.any().optional(),
  outputFormat: z.enum(["markdown","json","ppt-md","plan-md","prompt"]).default("markdown")
});

const AutoRunBody = z.object({
  demandId: z.string(),
  plan: z.array(z.object({
    title: z.string(),
    kind: StepAppendBody.shape.kind,
    input: z.any(),
    acceptance: StepAppendBody.shape.acceptance.optional(),
    routeHint: StepAppendBody.shape.routeHint.optional(),
    fallbackProviders: StepAppendBody.shape.fallbackProviders.optional(),
    realign: StepAppendBody.shape.realign.optional()
  })),
  providers: ProvidersCfg,
  maxSwitches: z.number().int().min(0).max(10).default(3)
});

// Fan-out
const FanoutBody = z.object({
  demandId: z.string(),
  title: z.string(),
  branches: z.array(z.object({
    title: z.string(),
    kind: StepAppendBody.shape.kind,
    input: z.any(),
    provider: z.enum(["openai","grok","genspark","manus"]).optional(),
    routeHint: StepAppendBody.shape.routeHint.optional(),
    acceptance: StepAppendBody.shape.acceptance.optional()
  })).min(2),
  consolidate: z.object({
    enabled: z.boolean().default(true),
    provider: z.enum(["openai","grok","genspark","manus"]).optional(),
    routeHint: StepAppendBody.shape.routeHint.optional(),
    acceptance: StepAppendBody.shape.acceptance.optional(),
    instructions: z.string().optional()
  }).optional(),
  providers: ProvidersCfg
});

// Cross-review
const CrossReviewBody = z.object({
  demandId: z.string(),
  title: z.string(),
  producer: z.object({
    title: z.string(),
    kind: StepAppendBody.shape.kind,
    input: z.any(),
    provider: z.enum(["openai","grok","genspark","manus"]).optional(),
    routeHint: StepAppendBody.shape.routeHint.optional(),
    acceptance: StepAppendBody.shape.acceptance.optional()
  }),
  reviewers: z.array(z.object({
    title: z.string(),
    kind: StepAppendBody.shape.kind.optional(),
    instruction: z.string().optional(),
    provider: z.enum(["openai","grok","genspark","manus"]).optional(),
    routeHint: StepAppendBody.shape.routeHint.optional(),
    acceptance: StepAppendBody.shape.acceptance.optional()
  })).min(1),
  iterations: z.number().int().min(1).max(5).default(1),
  providers: ProvidersCfg
});

const SaveDocBody = z.object({
  demandId: z.string(),
  target: z.enum(["gitlab","github","gdrive"]),
  path: z.string(),
  content: z.string(),
  message: z.string().default("update from ai-orchestrator"),
  tokens: z.object({
    gitlab: z.object({ token: z.string(), projectId: z.string() }).optional(),
    github: z.object({ token: z.string(), ownerRepo: z.string() }).optional(),
    gdrive: z.object({ token: z.string(), parentId: z.string().optional() }).optional()
  })
});

// ---------- Catálogo em memória ----------
const catalog = new Map(); // id -> { meta, steps[], status, providersUsed[], decisions[] }

app.post("/api/orch/demand/new", (req,res)=>{
  const b = DemandNewBody.parse(req.body);
  const id = uuidv4();
  catalog.set(id, { meta:{ id, createdAt:new Date().toISOString(), ...b }, steps:[], status:"open", providersUsed:[], decisions:[] });
  res.json({ ok:true, demandId:id });
});

app.get("/api/orch/demand", (_req,res)=>{ res.json([ ...catalog.values() ].map(d=>d.meta)); });
app.get("/api/orch/demand/:id", (req,res)=>{ const d=catalog.get(req.params.id); if(!d) return res.status(404).json({ error:"not found" }); res.json(d); });

// ---------- Prompt composer rígido ----------
app.post("/api/orch/prompt/compose", (req,res)=>{
  const b = PromptComposeBody.parse(req.body);
  const systemHead = [
    "Você é uma IA séria, sóbria e honesta.",
    "Sem elogios, sem autopromoção, sem otimismo indevido.",
    "Use apenas dados reais, verificáveis; nunca invente; evite mock.",
    "Planeje antes de executar; hiperfracionar em etapas pequenas.",
    "Só avance após concluir e TESTAR a etapa anterior.",
    "Perspectiva do usuário final/cliente; quando possível, testes via navegador com evidências.",
    "Evitar transferência direta de arquivos entre IAs; publicar em repositórios e referenciar URLs.",
    "Se houver desvio/saturação, re-prompt na mesma IA ou mudar de provedor; documente."
  ].join(" ");
  const tasks = {
    "doc":"Documento completo com seções, referências, checklist.",
    "presentation":"Slides em Markdown (título, bullets, notas).",
    "cost-review":"Revisão de custos: premissas, fontes, faixas, tabela, riscos.",
    "plan-review":"Auditoria de plano: lacunas, riscos, dependências, marcos, KPIs.",
    "code":"Código com testes e passos de execução/validação.",
    "browser-test":"Testes E2E de navegação com evidências.",
    "image":"Brief detalhado de imagem.",
    "video":"Roteiro de vídeo curto.",
    "summary":"Resumo executivo e próximos passos."
  };
  res.json({ ok:true, prompt:{ tipo:b.taskType, sistema:systemHead, tarefa:tasks[b.taskType], contexto:b.context??{}, restricoes:b.constraints??{}, estilo:b.style??{}, formato:b.outputFormat } });
});

// ---------- Helpers de repositório ----------
function ghRaw(ownerRepo, path){ return `https://raw.githubusercontent.com/${ownerRepo}/main/${path}`; }
function glRaw(projectId, path){ return `https://gitlab.com/api/v4/projects/${encodeURIComponent(projectId)}/repository/files/${encodeURIComponent(path)}/raw?ref=main`; }

async function githubPut(token, ownerRepo, path, content, message, isBinary=false){
  let sha=null;
  try{
    const g = await axios.get(`https://api.github.com/repos/${ownerRepo}/contents/${path}`, { headers:{ Authorization:`Bearer ${token}` }});
    sha = g.data.sha;
  }catch{}
  const payload = isBinary
    ? { message: message, content: content, sha }
    : { message: message, content: Buffer.from(content,"utf8").toString("base64"), sha };
  await axios.put(`https://api.github.com/repos/${ownerRepo}/contents/${path}`, payload, { headers:{ Authorization:`Bearer ${token}` }});
  return ghRaw(ownerRepo, path);
}

async function gitlabPut(token, projectId, path, content, message, isBinary=false){
  const encPath = encodeURIComponent(path);
  const body = { branch: "main", commit_message: message, encoding: isBinary ? "base64" : "text", content };
  try{
    await axios.put(`https://gitlab.com/api/v4/projects/${encodeURIComponent(projectId)}/repository/files/${encPath}`, body, { headers: { "PRIVATE-TOKEN": token }});
  }catch{
    await axios.post(`https://gitlab.com/api/v4/projects/${encodeURIComponent(projectId)}/repository/files/${encPath}`, body, { headers: { "PRIVATE-TOKEN": token }});
  }
  return glRaw(projectId, path);
}

// ---------- Escolha de provedor ----------
function pickProvider(kind, routeHint){
  if(routeHint?.startsWith("force-")) return routeHint.replace("force-","");
  if(kind==="image" || kind==="video") return "openai";
  if(kind==="code") return "openai";
  if(kind==="browser-test" || kind==="research") return "grok";
  if(["doc","presentation","summary","plan-review","cost-review"].includes(kind)) return "manus";
  if(kind==="ops") return "genspark";
  return "openai";
}

async function runProvider(provider, input, providersCfg){
  if(provider==="openai"){
    if(!providersCfg.openai?.apiKey) throw new Error("openai apiKey ausente");
    const resp = await axios.post("https://api.openai.com/v1/chat/completions", {
      model: "gpt-4o-mini",
      messages: [
        { role:"system", content:"You are precise, sober and terse. No hype. Use real data only." },
        { role:"user", content: JSON.stringify(input) }
      ]
    }, { headers: { Authorization: `Bearer ${providersCfg.openai.apiKey}` }});
    return { provider, data: resp.data, cost: COST_TABLE.openai };
  }
  if(provider==="grok"){
    if(!providersCfg.grok?.apiKey) throw new Error("grok apiKey ausente");
    const base = providersCfg.grok.baseUrl || "https://api.x.ai";
    const resp = await axios.post(`${base}/v1/chat/completions`, {
      model: "grok-2-latest",
      messages: [{ role:"user", content: JSON.stringify(input) }]
    }, { headers: { Authorization: `Bearer ${providersCfg.grok.apiKey}` }});
    return { provider, data: resp.data, cost: COST_TABLE.grok };
  }
  if(provider==="genspark"){
    if(!providersCfg.genspark?.apiKey) throw new Error("genspark apiKey ausente");
    const base = providersCfg.genspark.baseUrl || "https://api.genspark.ai";
    const resp = await axios.post(`${base}/v1/chat/completions`, {
      model: "genspark-latest",
      messages: [{ role:"user", content: JSON.stringify(input) }]
    }, { headers: { Authorization: `Bearer ${providersCfg.genspark.apiKey}` }});
    return { provider, data: resp.data, cost: COST_TABLE.genspark };
  }
  if(provider==="manus"){
    if(!providersCfg.manus?.apiKey) throw new Error("manus apiKey ausente");
    const base = providersCfg.manus.baseUrl || "https://api.manus.ai";
    const resp = await axios.post(`${base}/v1/chat/completions`, {
      model: "manus-doc-latest",
      messages: [{ role:"user", content: JSON.stringify(input) }]
    }, { headers: { Authorization: `Bearer ${providersCfg.manus.apiKey}` }});
    return { provider, data: resp.data, cost: COST_TABLE.manus };
  }
  throw new Error("provider inválido");
}

function simpleValidate(outputText, acceptance){
  if(!acceptance) return { ok:true, reasons:[] };
  const reasons=[];
  if(acceptance.mustInclude?.length){
    for(const req of acceptance.mustInclude){
      if(!outputText || !outputText.toLowerCase().includes(req.toLowerCase())) reasons.push(`faltou: ${req}`);
    }
  }
  return { ok: reasons.length===0, reasons };
}

// ---------- Passo unitário com realinhamento e fallback ----------
app.post("/api/orch/step/append", async (req,res)=>{
  const b = StepAppendBody.parse(req.body);
  const d = catalog.get(b.demandId);
  if(!d) return res.status(404).json({ error:"demandId not found" });

  const primary = pickProvider(b.kind, b.routeHint);
  const tryOrder = [primary, ...(b.fallbackProviders||[]).filter(p=>p!==primary)];
  const realign = b.realign ?? { mode:"both", maxSame:1 };

  let lastErr=null, stepRec=null;

  try{
    const started = Date.now();
    const out = await pRetry(()=>queue.add(()=>runProvider(primary, b.input, b.providers)), { retries: 1 });
    const ended = Date.now();
    const textOut = JSON.stringify(out.data);
    const v = simpleValidate(textOut, b.acceptance);
    stepRec = { id:uuidv4(), title:b.title, kind:b.kind, provider:primary, input:b.input, output:out.data, ms:ended-started, costEstimatePer1k:out.cost, compliance:v };
    d.steps.push(stepRec); d.providersUsed.push(primary);
    d.decisions.push({ when:new Date().toISOString(), action:"run", provider:primary, ok:v.ok, reasons:v.reasons||[] });
    if(v.ok) return res.json({ ok:true, step:stepRec, tried:[primary] });

    if(realign.mode==="same" || realign.mode==="both"){
      for(let i=0;i<realign.maxSame;i++){
        const revised = realign.revisedInput ?? { ...b.input, corrective_instructions:"Realinhar: atender acceptance.mustInclude com dados reais e evidências. Sem floreios." };
        const s2 = Date.now();
        const o2 = await pRetry(()=>queue.add(()=>runProvider(primary, revised, b.providers)), { retries: 0 });
        const e2 = Date.now();
        const t2 = JSON.stringify(o2.data);
        const v2 = simpleValidate(t2, b.acceptance);
        const step2 = { id:uuidv4(), title:`${b.title} (realign:${i+1})`, kind:b.kind, provider:primary, input:revised, output:o2.data, ms:e2-s2, costEstimatePer1k:o2.cost, compliance:v2 };
        d.steps.push(step2);
        d.decisions.push({ when:new Date().toISOString(), action:"realign", provider:primary, ok:v2.ok, reasons:v2.reasons||[] });
        if(v2.ok) return res.json({ ok:true, step:step2, tried:[primary] });
      }
    }
  }catch(e){ lastErr=e; d.decisions.push({ when:new Date().toISOString(), action:"error", provider:primary, err:String(e) }); }

  if(realign.mode==="switch" || realign.mode==="both"){
    for(const prov of tryOrder.filter(p=>p!==primary)){
      try{
        const s = Date.now();
        const o = await pRetry(()=>queue.add(()=>runProvider(prov, b.input, b.providers)), { retries: 1 });
        const e = Date.now();
        const t = JSON.stringify(o.data);
        const v = simpleValidate(t, b.acceptance);
        const step2 = { id:uuidv4(), title:`${b.title} (fallback:${prov})`, kind:b.kind, provider:prov, input:b.input, output:o.data, ms:e-s, costEstimatePer1k:o.cost, compliance:v };
        d.steps.push(step2); d.providersUsed.push(prov);
        d.decisions.push({ when:new Date().toISOString(), action:"fallback", provider:prov, ok:v.ok, reasons:v.reasons||[] });
        if(v.ok) return res.json({ ok:true, step:step2, tried:[primary,...tryOrder.filter(p=>p!==primary)] });
        lastErr = new Error("não conformidade");
      }catch(e){ lastErr=e; d.decisions.push({ when:new Date().toISOString(), action:"error", provider:prov, err:String(e) }); }
    }
  }

  return res.status(400).json({ error:String(lastErr||"falha"), tried:tryOrder });
});

// ---------- Auto-run sequencial ----------
app.post("/api/orch/auto/run", async (req,res)=>{
  const b = AutoRunBody.parse(req.body);
  const d = catalog.get(b.demandId);
  if(!d) return res.status(404).json({ error:"demandId not found" });

  const results=[];
  for(const p of b.plan){
    const r = await axios.post("http://localhost:8080/api/orch/step/append", {
      demandId: b.demandId, title: p.title, kind: p.kind, input: p.input,
      acceptance: p.acceptance, routeHint: p.routeHint || "balanced",
      fallbackProviders: p.fallbackProviders || ["openai","grok","manus","genspark"],
      realign: p.realign || { mode:"both", maxSame:1 },
      providers: b.providers
    }).then(x=>x.data).catch(e=>({ ok:false, error:String(e) }));
    results.push(r);
  }
  res.json({ ok:true, results });
});

// ---------- Fan-out ----------
app.post("/api/orch/fanout", async (req,res)=>{
  const b = FanoutBody.parse(req.body);
  const d = catalog.get(b.demandId);
  if(!d) return res.status(404).json({ error:"demandId not found" });

  const tasks = b.branches.map((br, idx)=> async ()=>{
    const prov = br.provider ?? pickProvider(br.kind, br.routeHint);
    const s = Date.now();
    const o = await runProvider(prov, br.input, b.providers);
    const e = Date.now();
    const t = JSON.stringify(o.data);
    const v = simpleValidate(t, br.acceptance);
    const rec = {
      id: uuidv4(), title: `${b.title} / ${br.title}`, kind: br.kind, provider: prov,
      input: br.input, output: o.data, ms: e-s, costEstimatePer1k: o.cost, compliance: v, branchIndex: idx
    };
    d.steps.push(rec); d.providersUsed.push(prov);
    d.decisions.push({ when:new Date().toISOString(), action:"fanout-branch", provider:prov, ok:v.ok, reasons:v.reasons||[] });
    return rec;
  });

  let branchResults=[];
  try{
    branchResults = await Promise.all(tasks.map(fn=>queue.add(fn)));
  }catch(e){ return res.status(400).json({ error:String(e) }); }

  let consolidation=null;
  if(b.consolidate?.enabled){
    const consProv = b.consolidate.provider ?? "manus";
    const input = {
      instruction: b.consolidate.instructions || "Consolidar resultados: comparar, remover redundâncias, resolver conflitos, citar fontes, listar prós/contras por provedor e gerar conclusão aplicável.",
      branches: branchResults.map(r=>({ provider:r.provider, title:r.title, output:r.output }))
    };
    const s2 = Date.now();
    const o2 = await runProvider(consProv, input, b.providers);
    const e2 = Date.now();
    consolidation = {
      id: uuidv4(), title: `${b.title} / Consolidação`, kind: "summary", provider: consProv,
      input, output: o2.data, ms: e2-s2, costEstimatePer1k: o2.cost, compliance: { ok:true, reasons:[] }
    };
    d.steps.push(consolidation); d.providersUsed.push(consProv);
    d.decisions.push({ when:new Date().toISOString(), action:"fanout-consolidate", provider:consProv, ok:true, reasons:[] });
  }

  res.json({ ok:true, branches: branchResults, consolidation });
});

// ---------- Cross-review ----------
app.post("/api/orch/cross-review", async (req,res)=>{
  const b = CrossReviewBody.parse(req.body);
  const d = catalog.get(b.demandId);
  if(!d) return res.status(404).json({ error:"demandId not found" });

  const prodProv = b.producer.provider ?? pickProvider(b.producer.kind, b.producer.routeHint);
  const s = Date.now();
  const o = await runProvider(prodProv, b.producer.input, b.providers);
  const e = Date.now();
  let current = {
    id: uuidv4(), title: `${b.title} / Producer`, kind: b.producer.kind, provider: prodProv,
    input: b.producer.input, output: o.data, ms: e-s, costEstimatePer1k: o.cost,
    compliance: simpleValidate(JSON.stringify(o.data), b.producer.acceptance)
  };
  d.steps.push(current); d.providersUsed.push(prodProv);
  d.decisions.push({ when:new Date().toISOString(), action:"produce", provider:prodProv, ok:true, reasons:[] });

  const fullTrail=[current];
  for(let it=0; it<b.iterations; it++){
    for(const rv of b.reviewers){
      const rvProv = rv.provider ?? pickProvider(rv.kind ?? "doc", rv.routeHint);
      const rvInput = {
        instruction: rv.instruction || "Revisar e corrigir para plena conformidade. Aponte falhas e corrija.",
        previousOutput: current.output
      };
      const s2 = Date.now();
      const o2 = await runProvider(rvProv, rvInput, b.providers);
      const e2 = Date.now();
      const step = {
        id: uuidv4(), title: `${b.title} / Review by ${rvProv}`, kind: rv.kind ?? "doc", provider: rvProv,
        input: rvInput, output: o2.data, ms: e2-s2, costEstimatePer1k: o2.cost,
        compliance: simpleValidate(JSON.stringify(o2.data), rv.acceptance), reviewedStepId: current.id
      };
      d.steps.push(step); d.providersUsed.push(rvProv);
      d.decisions.push({ when:new Date().toISOString(), action:"review", provider:rvProv, ok:true, reasons:[] });
      fullTrail.push(step);
      current = step;
    }
  }
  res.json({ ok:true, trail: fullTrail });
});

// ---------- Salvar documentos (texto) ----------
app.post("/api/integrations/save-doc", async (req,res)=>{
  const b = SaveDocBody.parse(req.body);
  if(!catalog.has(b.demandId)) return res.status(404).json({ error:"demandId not found" });

  try{
    let url=null;
    if(b.target==="gitlab"){
      const { token, projectId } = b.tokens.gitlab || {};
      if(!token || !projectId) throw new Error("gitlab token/projectId ausentes");
      url = await gitlabPut(token, projectId, b.path, b.content, b.message, false);
    }
    if(b.target==="github"){
      const { token, ownerRepo } = b.tokens.github || {};
      if(!token || !ownerRepo) throw new Error("github token/ownerRepo ausentes");
      url = await githubPut(token, ownerRepo, b.path, b.content, b.message, false);
    }
    if(b.target==="gdrive"){
      const { token, parentId } = b.tokens.gdrive || {};
      if(!token) throw new Error("gdrive token ausente");
      const metadata = { name: b.path.split("/").pop(), mimeType: "text/markdown", parents: parentId ? [parentId] : [] };
      const boundary = "BOUND"+Date.now();
      const multipart =
        `--${boundary}\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n`+
        JSON.stringify(metadata)+
        `\r\n--${boundary}\r\nContent-Type: text/markdown\r\n\r\n`+
        b.content+`\r\n--${boundary}--`;
      await axios.post("https://www.googleapis.com/upload/drive/v3/files?uploadType=multipart", multipart, {
        headers: { Authorization:`Bearer ${token}`, "Content-Type": `multipart/related; boundary=${boundary}` }
      });
      url = "gdrive://created";
    }
    res.json({ ok:true, url });
  }catch(e){
    res.status(400).json({ error:String(e.message||e) });
  }
});

// ---------- Upload binário base64 -> repo (gera URL canônica) ----------
app.post("/api/files/put-b64", async (req,res)=>{
  const body = z.object({
    target: z.enum(["gitlab","github"]),
    path: z.string(),
    base64: z.string(),
    contentType: z.string().optional(),
    message: z.string().default("asset upload"),
    tokens: z.object({
      gitlab: z.object({ token: z.string(), projectId: z.string() }).optional(),
      github: z.object({ token: z.string(), ownerRepo: z.string() }).optional()
    })
  }).parse(req.body);

  try{
    const isBinary = true;
    let url=null;
    if(body.target==="github"){
      const { token, ownerRepo } = body.tokens.github || {};
      if(!token || !ownerRepo) throw new Error("github token/ownerRepo ausentes");
      url = await githubPut(token, ownerRepo, body.path, body.base64, body.message, isBinary);
    }else{
      const { token, projectId } = body.tokens.gitlab || {};
      if(!token || !projectId) throw new Error("gitlab token/projectId ausentes");
      url = await gitlabPut(token, projectId, body.path, body.base64, body.message, isBinary);
    }
    res.json({ ok:true, url, contentType: body.contentType || mime.lookup(body.path) || "application/octet-stream" });
  }catch(e){
    res.status(400).json({ error:String(e.message||e) });
  }
});

// ---------- Credenciais criptografadas ----------
function encryptJson(obj, pass){ return CryptoJS.AES.encrypt(JSON.stringify(obj), pass).toString(); }
function decryptToJson(cipher, pass){ const bytes = CryptoJS.AES.decrypt(cipher, pass); return JSON.parse(bytes.toString(CryptoJS.enc.Utf8)); }

app.post("/api/credentials/put", async (req,res)=>{
  const body = z.object({
    passphrase: z.string().min(6),
    secrets: ProvidersCfg,
    target: z.enum(["gitlab","github"]).default("gitlab"),
    path: z.string().default("secrets/providers.enc"),
    tokens: z.object({
      gitlab: z.object({ token:z.string(), projectId:z.string() }).optional(),
      github: z.object({ token:z.string(), ownerRepo:z.string() }).optional()
    })
  }).parse(req.body);

  const cipher = encryptJson(body.secrets, body.passphrase);
  try{
    let url=null;
    if(body.target==="gitlab"){
      const { token, projectId } = body.tokens.gitlab || {};
      if(!token || !projectId) return res.status(400).json({ error:"gitlab token/projectId ausentes" });
      url = await gitlabPut(token, projectId, body.path, cipher, "store encrypted providers", false);
    }else{
      const { token, ownerRepo } = body.tokens.github || {};
      if(!token || !ownerRepo) return res.status(400).json({ error:"github token/ownerRepo ausentes" });
      url = await githubPut(token, ownerRepo, body.path, cipher, "store encrypted providers", false);
    }
    res.json({ ok:true, path: body.path, url });
  }catch(e){
    res.status(400).json({ error:String(e.message||e) });
  }
});

app.post("/api/credentials/get", async (req,res)=>{
  const body = z.object({
    passphrase: z.string().min(6),
    target: z.enum(["gitlab","github"]).default("gitlab"),
    path: z.string().default("secrets/providers.enc"),
    tokens: z.object({
      gitlab: z.object({ token:z.string(), projectId:z.string() }).optional(),
      github: z.object({ token:z.string(), ownerRepo:z.string() }).optional()
    })
  }).parse(req.body);

  try{
    let cipher=null;
    if(body.target==="gitlab"){
      const { token, projectId } = body.tokens.gitlab || {};
      if(!token || !projectId) return res.status(400).json({ error:"gitlab token/projectId ausentes" });
      const r = await axios.get(glRaw(projectId, body.path), { headers: { "PRIVATE-TOKEN": token }});
      cipher = r.data;
    }else{
      const { token, ownerRepo } = body.tokens.github || {};
      if(!token || !ownerRepo) return res.status(400).json({ error:"github token/ownerRepo ausentes" });
      const r = await axios.get(`https://api.github.com/repos/${ownerRepo}/contents/${body.path}`, { headers:{ Authorization:`Bearer ${token}` }});
      cipher = Buffer.from(r.data.content, "base64").toString("utf8");
    }
    const secrets = decryptToJson(cipher, body.passphrase);
    res.json({ ok:true, secrets });
  }catch{
    res.status(400).json({ error:"falha ao ler/decifrar credenciais" });
  }
});

// ---------- Estrutura de conhecimento e versões ----------
const EnsureStructBody = z.object({
  target: z.enum(["gitlab","github"]),
  tokens: z.object({
    gitlab: z.object({ token: z.string(), projectId: z.string() }).optional(),
    github: z.object({ token: z.string(), ownerRepo: z.string() }).optional()
  }),
  demandTitle: z.string(),
  version: z.string().regex(/^v\d{3}$/).default("v001")
});

app.post("/api/repo/ensure-structure", async (req,res)=>{
  const b = EnsureStructBody.parse(req.body);
  const slug = slugify(b.demandTitle, { lower:true, strict:true });
  const baseGlobal = "knowledge/_global";
  const baseDemand = `demands/${slug}/${b.version}`;

  const write = async (path, content) => {
    if(b.target==="github"){
      const { token, ownerRepo } = b.tokens.github || {};
      if(!token || !ownerRepo) throw new Error("github token/ownerRepo ausentes");
      return await githubPut(token, ownerRepo, path, content, "ensure structure", false);
    }else{
      const { token, projectId } = b.tokens.gitlab || {};
      if(!token || !projectId) throw new Error("gitlab token/projectId ausentes");
      return await gitlabPut(token, projectId, path, content, "ensure structure", false);
    }
  };

  const indexJson = JSON.stringify({ slug, version: b.version, createdAt: new Date().toISOString() }, null, 2);
  const readmeGlobal = "# Conhecimento Global\n\nArmazene aqui guias, padrões e instruções gerais.\n";
  const readmeDemand = `# Demanda ${b.demandTitle}\n\nVersão: ${b.version}\nPadrões: sem transferência direta entre IAs. Artefatos via repositório.\n`;

  const urls = [];
  urls.push(await write(`${baseGlobal}/README.md`, readmeGlobal));
  urls.push(await write(`${baseDemand}/README.md`, readmeDemand));
  urls.push(await write(`${baseDemand}/index.json`, indexJson));

  res.json({
    ok:true,
    slug,
    version:b.version,
    paths: { global: baseGlobal, demand: baseDemand },
    urls
  });
});

const SaveKnowledgeBody = z.object({
  target: z.enum(["gitlab","github"]),
  tokens: z.object({
    gitlab: z.object({ token: z.string(), projectId: z.string() }).optional(),
    github: z.object({ token: z.string(), ownerRepo: z.string() }).optional()
  }),
  scope: z.object({
    kind: z.enum(["global","demand"]),
    demandSlug: z.string().optional(),
    version: z.string().optional()
  }),
  relPath: z.string(), // ex: "notes/decision-001.md"
  content: z.string(),
  message: z.string().default("save knowledge")
});

app.post("/api/knowledge/save", async (req,res)=>{
  const b = SaveKnowledgeBody.parse(req.body);
  let base = "knowledge/_global";
  if(b.scope.kind==="demand"){
    if(!b.scope.demandSlug || !b.scope.version) return res.status(400).json({ error:"demandSlug e version são obrigatórios no escopo demand" });
    base = `demands/${b.scope.demandSlug}/${b.scope.version}`;
  }
  const fullPath = `${base}/${b.relPath}`;
  try{
    let url=null;
    if(b.target==="github"){
      const { token, ownerRepo } = b.tokens.github || {};
      if(!token || !ownerRepo) throw new Error("github token/ownerRepo ausentes");
      url = await githubPut(token, ownerRepo, fullPath, b.content, b.message, false);
    }else{
      const { token, projectId } = b.tokens.gitlab || {};
      if(!token || !projectId) throw new Error("gitlab token/projectId ausentes");
      url = await gitlabPut(token, projectId, fullPath, b.content, b.message, false);
    }
    res.json({ ok:true, path: fullPath, url });
  }catch(e){
    res.status(400).json({ error:String(e.message||e) });
  }
});

// ---------- Webhook (runners/CI) ----------
app.post("/api/integrations/webhook", async (req,res)=>{
  const body = z.object({ url:z.string().url(), secret:z.string().optional(), payload:z.any().optional() }).parse(req.body);
  try{
    const r = await axios.post(body.url, body.payload ?? {}, body.secret ? { headers:{ "X-Auth-Token": body.secret }} : {});
    res.json({ ok:true, status:r.status, data:r.data });
  }catch(e){ res.status(400).json({ error:String(e.message||e) }); }
});

// ---------- Política e Termos ----------
app.get("/privacy", (_req,res)=>res.type("text/html").send(`
<!doctype html><meta charset="utf-8">
<title>Política de Privacidade — AI Orchestrator</title>
<h1>Política de Privacidade — AI Orchestrator</h1>
<p>Contato: <a href="mailto:fmunizm@gmail.com">fmunizm@gmail.com</a></p>
<h2>Resumo</h2>
<ul>
<li>Sem transferência direta entre IAs. Artefatos ficam em repositórios/Drive do usuário.</li>
<li>Não armazenamos chaves no servidor. Credenciais podem ser cifradas (AES) no seu repositório.</li>
<li>Allowed domains controlados neste serviço.</li>
</ul>
<h2>Dados processados</h2>
<p>Pedidos, prompts, arquivos gerados, logs mínimos (horário, rota, status HTTP).</p>
<h2>Base legal</h2>
<p>Execução de contrato e legítimo interesse do controlador (você).</p>
<h2>Compartilhamento</h2>
<p>Somente com provedores e integrações que você habilitar.</p>
<h2>Retenção</h2>
<p>Sem banco local. Persistência ocorre nos destinos escolhidos.</p>
<h2>Segurança</h2>
<p>HTTPS. Criptografia AES com sua frase-secreta para credenciais.</p>
`));

app.get("/terms", (_req,res)=>res.type("text/html").send(`
<!doctype html><meta charset="utf-8">
<title>Termos de Uso — AI Orchestrator</title>
<h1>Termos de Uso — AI Orchestrator</h1>
<p>Contato: <a href="mailto:fmunizm@gmail.com">fmunizm@gmail.com</a></p>
<ol>
<li>Serviço "como está". Você assume riscos de uso e custos dos provedores.</li>
<li>Você decide integrações, repositórios, allowed domains e retenção.</li>
<li>Conteúdos gerados podem conter erros; valide antes de uso crítico.</li>
<li>Proibido uso ilegal ou violação de direitos.</li>
<li>Responsabilidade limitada; disponibilidade best-effort.</li>
<li>Alterações poderão ocorrer; versão vigente nestes endpoints.</li>
</ol>
`));

// ---- start
const PORT = process.env.PORT || 8080;
app.listen(PORT, "0.0.0.0", ()=>console.log("up:"+PORT));
