import { closeSync, readSync } from "node:fs"

const ACCESS_KEY_ENV = "AccessKey"
export const ACCESS_KEY_HANDOFF_FD = 198

function captureAccessKey(): string | undefined {
  const chunks: Buffer[] = []
  const buffer = Buffer.alloc(64 * 1024)
  let descriptorRead = false
  try {
    while (true) {
      const count = readSync(ACCESS_KEY_HANDOFF_FD, buffer, 0, buffer.length, null)
      descriptorRead = true
      if (count === 0) break
      chunks.push(Buffer.from(buffer.subarray(0, count)))
    }
  } catch {
    return undefined
  } finally {
    if (descriptorRead) {
      try {
        closeSync(ACCESS_KEY_HANDOFF_FD)
      } catch {
        // The trusted host owns cleanup if descriptor close fails here.
      }
    }
  }
  const value = Buffer.concat(chunks).toString("utf8")
  return value === "" ? undefined : value
}

// The host runner never places AccessKey in the OpenCode environment. The
// inherited descriptor is consumed before provider/model work can start; the
// value remains only in this trusted host/tool module and trusted core child
// launch path.
export const trustedAccessKey = captureAccessKey()
delete process.env[ACCESS_KEY_ENV]
