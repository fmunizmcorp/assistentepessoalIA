import fs from 'fs'

const API_KEY = process.env.API_KEY
const SAVE_DOC_ENDPOINT = process.env.SAVE_DOC_ENDPOINT

export async function saveDoc({ demandId, relPath, contentBase64 }) {
  if (!SAVE_DOC_ENDPOINT) throw new Error('SAVE_DOC_ENDPOINT ausente')
  const r = await fetch(SAVE_DOC_ENDPOINT, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'x-api-key': API_KEY },
    body: JSON.stringify({ demandId, relPath, contentBase64 })
  })
  if (!r.ok) throw new Error(`save-doc falhou: ${r.status}`)
}

export function toB64(strOrBuffer) {
  if (Buffer.isBuffer(strOrBuffer)) return strOrBuffer.toString('base64')
  return Buffer.from(String(strOrBuffer), 'utf8').toString('base64')
}
