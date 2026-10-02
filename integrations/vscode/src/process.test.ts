import {test} from "node:test"
import assert from "node:assert/strict"
import {runProcess} from "./process"

const options = {cwd: process.cwd(), env: process.env, timeoutMs: 3_000}
test("large simultaneous pipes cannot deadlock and input stays off argv", async () => {
  const result = await runProcess(process.execPath, ["-e", 'process.stderr.write("x".repeat(200000)); process.stdin.on("data", d=>process.stdout.write(d));'], {...options, input: "private-input"})
  assert.equal(result, "private-input")
})
test("diagnostics and oversized output fail with source-free errors", async () => {
  for (const stream of ["stdout", "stderr"]) {
    await assert.rejects(runProcess(process.execPath, ["-e", `process.${stream}.write("secret-canary".repeat(10000));`], {...options, maxBytes: 1024}), error => {
      assert(!String(error).includes("secret-canary"))
      return true
    })
  }
})
test("timeout terminates a process that ignores SIGTERM", async () => {
  const start = Date.now()
  await assert.rejects(runProcess(process.execPath, ["-e", 'process.on("SIGTERM",()=>{}); setInterval(()=>{},1000)'], {...options, timeoutMs: 100}), /timed out/)
  assert(Date.now() - start < 2_500)
})
test("cancellation interrupts work and pre-cancel never starts it", async () => {
  const controller = new AbortController()
  const work = runProcess(process.execPath, ["-e", 'setInterval(()=>{},1000)'], {...options, signal: controller.signal})
  setTimeout(() => controller.abort(), 50)
  await assert.rejects(work, /canceled/)
  await assert.rejects(runProcess("missing-runtime", [], {...options, signal: controller.signal}), /canceled/)
})
