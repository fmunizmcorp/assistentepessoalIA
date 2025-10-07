import express from 'express'
import helmet from 'helmet'
import rateLimit from 'express-rate-limit'
import { v4 as uuid } from 'uuid'
import { saveDoc } from './lib/saveDocClient.js'
import { setSecret, getSecret } from './lib/secrets.js'
import fs from 'fs'

const app = express()
app.use(express.json({ limit: '10mb' }))
app.use(helmet())
app.use(rateLimit({ windowMs: 60_000, max: 120 }))

const API_KEY = process.env.API_KEY
function auth(req, res, next) {
  if (!API_KEY) return res.status(500).json({ error: 'API_KEY ausente' })
  if (req.headers['x-api-key'] !== API_KEY) return res.status(401).json({ error: 'unauthorized' })
  next()
}

const demands = new Map() // memória. troque por storage persistente se quiser

app.get('/health', (req, res) => res.json({ ok: true }))
app.get('/openapi.yaml', (req, res) => {
  res.setHeader('Content-Type', 'text/yaml')
  res.send(fs.readFileSync('./openapi.yaml', 'utf8'))
})

app.post('/api/orch/demand/new', auth, (req, res) => {
  const { title, slug } = req.body
  const id = uuid()
  demands.set(id, { id, title, slug, createdAt: Date.now() })
  res.json({ id })
})

app.post('/api/integrations/save-doc', auth, async (req, res) => {
  const { demandId, relPath, contentBase64 } = req.body
  if (!demandId || !relPath || !contentBase64) return res.status(400).json({ error: 'parâmetros' })
  try {
    await saveDoc({ demandId, relPath, contentBase64 })
    res.json({ ok: true })
  } catch (e) {
    res.status(500).json({ error: e.message })
  }
})

app.post('/api/secrets/set', auth, async (req, res) => {
  const { provider, key, value, plaintext } = req.body
  if (!provider || !key || typeof value !== 'string') return res.status(400).json({ error: 'parâmetros' })
  await setSecret({ provider, key, value, plaintext: !!plaintext })
  res.json({ ok: true })
})

app.post('/api/secrets/get', auth, async (req, res) => {
  const { provider, key } = req.body
  if (!provider || !key) return res.status(400).json({ error: 'parâmetros' })
  const v = await getSecret({ provider, key })
  res.json({ value: v || null })
})

// Fanout mínimo que envia tarefas ao Runner
app.post('/api/orch/fanout', auth, async (req, res) => {
  const { demandId, steps } = req.body
  if (!demandId || !Array.isArray(steps)) return res.status(400).json({ error: 'parâmetros' })
  const runnerUrl = `http://localhost:${process.env.RUNNER_PORT || 8090}`
  const results = []
  for (const s of steps) {
    if (s.kind === 'browser-action') {
      const r = await fetch(`${runnerUrl}/api/browser/task`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'x-api-key': API_KEY },
        body: JSON.stringify({ ...s, demandId, repoTarget: 'demands' })
      })
      results.push(await r.json())
    }
  }
  res.json({ queued: results })
})

const PORT = process.env.PORT || 8080
app.listen(PORT, () => console.log(`Orchestrator on :${PORT}`))
