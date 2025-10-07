import { captureAndSave } from './helpers.js'
import { toB64, saveDoc } from '../../lib/saveDocClient.js'

export async function runGrok({ ctx, payload, demandId, repoTarget }) {
  const page = await ctx.newPage()
  try {
    const email = process.env.GROK_EMAIL
    const password = process.env.GROK_PASSWORD
    if (!email || !password) throw new Error('GROK_EMAIL/PASSWORD ausentes')

    await page.goto('https://x.ai/', { waitUntil: 'domcontentloaded' })
    // Ajustar fluxo real de login

    await page.click('textarea, [contenteditable="true"]')
    await page.keyboard.type(payload.prompt)
    await page.keyboard.press('Enter')

    await page.waitForTimeout(8000)
    const text = await page.textContent('main')

    const base = `${repoTarget}/${demandId}/latest/grok`
    await saveDoc({ demandId, relPath: `${base}/response.txt`, contentBase64: toB64(text || '') })
    await captureAndSave({ page, demandId, relPathBase: `${base}`, saveFn: saveDoc })

    return { ok: true, text }
  } finally { await page.close() }
}
