import express from 'express'
import { chromium } from 'playwright'
import PQueue from 'p-queue'
import { v4 as uuid } from 'uuid'
import { runChatGPT } from './actions/chatgpt.js'
import { runGenSpark } from './actions/genspark.js'
import { runGrok } from './actions/grok.js'
import { runManus } from './actions/manus.js'

const app = express()
app.use(express.json({ limit: '10mb' }))

const API_KEY = process.env.API_KEY
function auth(req, res, next) {
  if (!API_KEY) return res.status(500).json({ error: 'API_KEY ausente' })
  if (req.headers['x-api-key'] !== API_KEY) return res.status(401).json({ error: 'unauthorized' })
  next()
}

const HEADLESS = String(process.env.RUNNER_HEADLESS || 'true') === 'true'
const USER_DATA = process.env.RUNNER_USER_DATA || '.pw-user'
const MAX_CONC = Number(process.env.RUNNER_MAX_CONCURRENCY || 2)
const TASK_TIMEOUT_MS = Number(process.env.TASK_TIMEOUT_MS || 240000)

const queue = new PQueue({ concurrency: MAX_CONC })
const tasks = new Map()

async function withBrowser(fn) {
  const browser = await chromium.launchPersistentContext(USER_DATA, {
    headless: HEADLESS,
    args: [
      '--disable-blink-features=AutomationControlled',
      '--no-sandbox',
      '--disable-dev-shm-usage'
    ]
  })
  try { return await fn(browser) } finally { await browser.close() }
}

app.post('/api/browser/task', auth, async (req, res) => {
  const id = uuid()
  const task = { id, status: 'queued', req: req.body }
  tasks.set(id, task)

  queue.add(async () => {
    task.status = 'running'
    try {
      const result = await withBrowser(async (ctx) => {
        const { provider, action, payload, demandId, repoTarget } = task.req
        if (action !== 'prompt') throw new Error('action não suportada')
        if (provider === 'chatgpt') return runChatGPT({ ctx, payload, demandId, repoTarget })
        if (provider === 'genspark') return runGenSpark({ ctx, payload, demandId, repoTarget })
        if (provider === 'grok') return runGrok({ ctx, payload, demandId, repoTarget })
        if (provider === 'manus') return runManus({ ctx, payload, demandId, repoTarget })
        throw new Error('provider inválido')
      })
      task.status = 'done'
      task.result = result
    } catch (e) {
      task.status = 'error'
      task.error = e.message
    }
  }, { timeout: TASK_TIMEOUT_MS }).catch(e => {
    tasks.get(id).status = 'error'
    tasks.get(id).error = String(e)
  })

  res.json({ id, status: 'queued' })
})

app.get('/api/browser/status/:id', auth, (req, res) => {
  const t = tasks.get(req.params.id)
  if (!t) return res.status(404).json({ error: 'not found' })
  res.json(t)
})

const PORT = process.env.RUNNER_PORT || 8090
app.listen(PORT, () => console.log(`Runner on :${PORT}`))
