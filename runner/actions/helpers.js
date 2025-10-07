import { toB64 } from '../../lib/saveDocClient.js'

export async function ensureLoggedIn({ page, loginUrl, email, password, emailSel, passSel, submitSel, okSelector }) {
  await page.goto(loginUrl, { waitUntil: 'domcontentloaded' })
  if (await page.$(okSelector)) return
  await page.fill(emailSel, email)
  await page.fill(passSel, password)
  await page.click(submitSel)
  await page.waitForSelector(okSelector, { timeout: 60000 })
}

export async function captureAndSave({ page, demandId, relPathBase, saveFn }) {
  const html = await page.content()
  const png = await page.screenshot({ fullPage: true })
  await saveFn({ demandId, relPath: `${relPathBase}/page.html`, contentBase64: toB64(html) })
  await saveFn({ demandId, relPath: `${relPathBase}/page.png`, contentBase64: toB64(png) })
}
