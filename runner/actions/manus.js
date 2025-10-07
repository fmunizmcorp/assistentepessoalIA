import { captureAndSave } from './helpers.js'
import { toB64, saveDoc } from '../../lib/saveDocClient.js'

export async function runManus({ ctx, payload, demandId, repoTarget }) {
  const page = await ctx.newPage()
  try {
    const email = process.env.MANUS_EMAIL
    const password = process.env.MANUS_PASSWORD
    if (!email || !password) throw new Error('MANUS_EMAIL/PASSWORD ausentes')

    await page.goto('https://manus.ai/login', { waitUntil: 'domcontentloaded' })
    await page.fill('input[type=email]', email)
    await page.fill('input[type=password]', password)
    await page.click('button[type=submit]')
    await page.waitForLoadState('networkidle')

    await page.click('textarea, [contenteditable="true"]')
    await page.keyboard.type(payload.prompt)
    await page.keyboard.press('Enter')

    await page.waitForTimeout(8000)
    const text = await page.textContent('main')

    const base = `${repoTarget}/${demandId}/latest/manus`
    await saveDoc({ demandId, relPath: `${base}/response.txt`, contentBase64: toB64(text || '') })
    await captureAndSave({ page, demandId, relPathBase: `${base}`, saveFn: saveDoc })

    return { ok: true, text }
  } finally { await page.close() }
}
