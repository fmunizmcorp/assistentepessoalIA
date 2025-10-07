import CryptoJS from 'crypto-js'
import fs from 'fs'
import path from 'path'

const BASE = '.secrets'
if (!fs.existsSync(BASE)) fs.mkdirSync(BASE)
const ALLOW_PLAINTEXT = String(process.env.ALLOW_PLAINTEXT_SECRETS || 'false') === 'true'
const PASSPHRASE = process.env.SECRETS_PASSPHRASE || ''

function fileFor(provider, key) {
  return path.join(BASE, `${provider}__${key}.secret`)
}

export async function setSecret({ provider, key, value, plaintext }) {
  const p = fileFor(provider, key)
  if (ALLOW_PLAINTEXT && plaintext) {
    fs.writeFileSync(p, JSON.stringify({ mode: 'plain', v: value }), 'utf8')
    return
  }
  if (!PASSPHRASE) throw new Error('SECRETS_PASSPHRASE não definida e plaintext não permitido')
  const enc = CryptoJS.AES.encrypt(value, PASSPHRASE).toString()
  fs.writeFileSync(p, JSON.stringify({ mode: 'enc', v: enc }), 'utf8')
}

export async function getSecret({ provider, key }) {
  const p = fileFor(provider, key)
  if (!fs.existsSync(p)) return null
  const { mode, v } = JSON.parse(fs.readFileSync(p, 'utf8'))
  if (mode === 'plain') return v
  if (!PASSPHRASE) throw new Error('SECRETS_PASSPHRASE ausente para desencriptar')
  const bytes = CryptoJS.AES.decrypt(v, PASSPHRASE)
  return bytes.toString(CryptoJS.enc.Utf8)
}
