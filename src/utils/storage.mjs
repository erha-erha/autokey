import fs from 'node:fs'
import path from 'node:path'
import crypto from 'node:crypto'

export function appError(message, statusCode = 400) {
  return Object.assign(new Error(message), { statusCode })
}

// Replace complete files atomically; never truncate the only copy of a private key.
export function writeJson(file, value) {
  if (fs.existsSync(file) && fs.lstatSync(file).isSymbolicLink()) throw appError('Symbolic links are not allowed for account data')
  const temp = path.join(path.dirname(file), `.${path.basename(file)}.${crypto.randomUUID()}.tmp`)
  try {
    fs.writeFileSync(temp, JSON.stringify(value, null, 2), { encoding: 'utf8', mode: 0o600, flag: 'wx' })
    fs.renameSync(temp, file)
  } finally {
    fs.rmSync(temp, { force: true })
  }
}
