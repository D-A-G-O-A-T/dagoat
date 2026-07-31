#!/usr/bin/env node
// contracts/build-safe-wiring-batch.mjs
//
// Emit the Stream B wiring calls as a SINGLE Gnosis Safe batch, and verify every
// call against the live chain before writing it.
//
// ---------------------------------------------------------------------------
// WHY
// ---------------------------------------------------------------------------
//
// `safe` is `immutable` on all five contracts that have one, so a Safe cannot be
// adopted by an already-deployed stack -- it has to be the constructor argument
// of the NEXT deployment. At that moment `contracts/testnet-up.ps1` stops
// working: it signs its wiring calls directly with the SAFE key, and against a
// Safe every `onlySafe` call fails `NotSafe()` because the sender is an EOA.
//
// The recommended shape (migration spec §5, option a) is: deploy with an EOA --
// deployment itself is permissionless -- then hand the wiring to the Safe as ONE
// batched transaction. One payload to review, one signature round, atomic.
//
// ---------------------------------------------------------------------------
// WHAT THIS PROVES, AND WHAT IT DOES NOT
// ---------------------------------------------------------------------------
//
// PROVES: that each call's target, selector and ARGUMENT ENCODING are correct,
// by simulating every one with `eth_call` from the address that currently holds
// `safe` on the deployed stack. A wrong selector, a transposed argument or a
// bad address surfaces here as a revert, before anything is signed.
//
// DOES NOT PROVE: that a Safe can execute the batch. That needs a deployed Safe,
// which is the outstanding blocker for the P2 rehearsal. This tool deliberately
// says so in its own output rather than letting a green run be mistaken for a
// full rehearsal -- the distinction this repo keeps having to relearn is that a
// tool printing success is not the same as the thing having been done.
//
// USAGE
//   node contracts/build-safe-wiring-batch.mjs [--chain 84532] [--out <file>]
// Exit 0 = every call verified. 1 = a call reverted. 2 = could not check.

import { readFileSync, existsSync, writeFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
// Reuses the SAME keccak the node parity fixtures use, rather than a second
// implementation. That file carries its own erratum about once having been
// SHA-256 while named keccak, which is exactly why this does not roll another.
import { keccak256Utf8Hex } from './test/keccak256.mjs'

const HERE = dirname(fileURLToPath(import.meta.url))
const args = process.argv.slice(2)
const argOf = (f, d) => {
  const i = args.indexOf(f)
  return i >= 0 && args[i + 1] ? args[i + 1] : d
}
const CHAIN = argOf('--chain', '84532')
const OUT = argOf('--out', join(HERE, `safe-wiring-batch.${CHAIN}.json`))

let RPC = argOf('--rpc', '')
const envPath = join(HERE, '.env')
let SAFE = ''
if (existsSync(envPath)) {
  for (const line of readFileSync(envPath, 'utf8').split(/\r?\n/)) {
    let m = /^\s*(BASE_SEPOLIA_RPC_URL|RPC_URL)\s*=\s*(.+)$/.exec(line)
    if (m && !RPC) RPC = m[2].trim()
    m = /^\s*SAFE_ADDRESS\s*=\s*(.+)$/.exec(line)
    if (m) SAFE = m[1].trim()
  }
}
if (!RPC || !SAFE) {
  console.error('need RPC_URL/BASE_SEPOLIA_RPC_URL and SAFE_ADDRESS in contracts/.env')
  process.exit(2)
}

const readManifest = (f) => {
  const p = join(HERE, 'deployments', f)
  if (!existsSync(p)) return null
  return JSON.parse(readFileSync(p, 'utf8').replace(/^﻿/, ''))
}
const base = readManifest(`${CHAIN}.json`)
const fact = readManifest(`${CHAIN}.factory.json`)
const epoch = readManifest(`${CHAIN}.epoch.json`)
if (!base || !epoch) {
  console.error(`missing deployment manifests for chain ${CHAIN}`)
  process.exit(2)
}

// --- minimal ABI encoding. Only the shapes this batch needs, so there is no
//     dependency to drift and nothing generic to get subtly wrong.
const sel = (sig) => '0x' + keccak256Utf8Hex(sig).replace(/^0x/, '').slice(0, 8)
const padAddr = (a) => a.toLowerCase().replace(/^0x/, '').padStart(64, '0')
const padUint = (n) => BigInt(n).toString(16).padStart(64, '0')
const padBool = (b) => (b ? '1' : '0').padStart(64, '0')
const padB32 = (h) => h.replace(/^0x/, '').padStart(64, '0')

function encode(sig, types, vals) {
  let data = sel(sig)
  for (let i = 0; i < types.length; i++) {
    const t = types[i]
    const v = vals[i]
    if (t === 'address') data += padAddr(v)
    else if (t === 'uint256' || t === 'uint64' || t === 'uint16') data += padUint(v)
    else if (t === 'bool') data += padBool(v)
    else if (t === 'bytes32') data += padB32(v)
    else throw new Error(`unsupported type ${t}`)
  }
  return data
}

const FOUNDER = process.env.FOUNDER_ADDRESS || SAFE
const calls = []
const add = (label, to, sig, types, vals) =>
  calls.push({ label, to, sig, data: encode(sig, types, vals), types, vals })

// The onlySafe wiring, in the order testnet-up.ps1 performs it. Mint/approve/
// session calls are deliberately EXCLUDED: they are not onlySafe, they are
// mock-token and desk-owner operations that an EOA can and should keep doing.
add('escrow.setVault(workMinter)', base.holdbackEscrow, 'setVault(address)', ['address'], [base.workMinter])
add('goat.setMinter(workMinter,true)', base.goatCoin, 'setMinter(address,bool)', ['address', 'bool'], [base.workMinter, true])
for (const [name, addr] of [
  ['holdbackEscrow', base.holdbackEscrow],
  ['workMinter', base.workMinter],
  ['buyDesk', base.buyDesk],
  ['founder', FOUNDER],
]) {
  add(`registry.setSystemAddress(${name})`, base.enrollmentRegistry, 'setSystemAddress(address,bool)', ['address', 'bool'], [addr, true])
}
add('epochEscrow.setVault(epochSettlement)', epoch.epochHoldbackEscrow, 'setVault(address)', ['address'], [epoch.epochSettlement])
add('goat.setMinter(epochSettlement,true)', base.goatCoin, 'setMinter(address,bool)', ['address', 'bool'], [epoch.epochSettlement, true])
add('registry.setSystemAddress(epochSettlement)', base.enrollmentRegistry, 'setSystemAddress(address,bool)', ['address', 'bool'], [epoch.epochSettlement, true])
add('registry.setSystemAddress(epochHoldbackEscrow)', base.enrollmentRegistry, 'setSystemAddress(address,bool)', ['address', 'bool'], [epoch.epochHoldbackEscrow, true])
add('epochSettlement.setResolver(founderResolver)', epoch.epochSettlement, 'setResolver(address)', ['address'], [epoch.founderResolver])
add('registry.setEnrolled(founder)', base.enrollmentRegistry, 'setEnrolled(address,bool,bytes32)', ['address', 'bool', 'bytes32'], [FOUNDER, true, '0x' + '0'.repeat(64)])
// DELIBERATELY ABSENT: registry.setSystemAddress(founderDesk).
//
// The founder desk address is not known until `factory.createDesk` has run and
// `deskOf(founder)` can be read, so on a fresh deployment it does not exist when
// this batch is built. An earlier draft emitted a PLACEHOLDER address here,
// which is the worst possible thing to put in a payload whose entire purpose is
// to be signed after review: it would have flagged an arbitrary address as a
// system address. Better a batch that is honestly incomplete than one that is
// quietly wrong.
//
// So the desk step is a SECOND, smaller Safe transaction after the desk exists.
// Recorded here rather than in a comment elsewhere, because the omission is
// invisible in the emitted JSON.

async function ethCall(to, data, from) {
  const res = await fetch(RPC, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'eth_call', params: [{ to, data, from }, 'latest'] }),
  })
  const j = await res.json()
  return j.error ? { err: j.error.message || JSON.stringify(j.error), data: j.error.data } : { ok: j.result }
}

console.log(`=== Safe wiring batch, chain ${CHAIN} ===`)
console.log(`simulating every call from the CURRENT holder of safe: ${SAFE}\n`)

// Reverts that are reached ONLY AFTER the sender passed `onlySafe` and the
// calldata decoded -- so hitting one is positive evidence the call is
// well-formed and authorised, not a failure of it.
//
// This exists because the simulation target and the batch's target are not the
// same stack. The batch is FOR a fresh deployment where `safe` is the Safe;
// the only stack available to simulate against is this one, already wired. The
// difference shows up exactly on one-shot calls.
//
// It is NOT a list for making red things green. The only entries permitted are
// errors that cannot be reached before authorisation and ABI decoding, so
// reaching them is strictly more information than a plain success would be.
// `VaultAlreadySet` qualifies: HoldbackEscrow.setVault is onlySafe and the guard
// fires after the argument is decoded.
const POST_AUTH_STATE_GUARDS = {
  '0x1bb0ddfb': 'VaultAlreadySet -- one-shot, already applied on this stack; would apply on a fresh deploy',
}

let bad = 0
let viaGuard = 0
const w = Math.max(...calls.map((c) => c.label.length))
for (const c of calls) {
  const r = await ethCall(c.to, c.data, SAFE)
  const blob = JSON.stringify(r)
  const guard = Object.keys(POST_AUTH_STATE_GUARDS).find((s) => blob.includes(s.slice(2)))
  let tag
  if (!r.err) tag = 'OK  '
  else if (guard) { tag = 'PAST'; viaGuard++ }
  else { tag = 'FAIL'; bad++ }
  console.log(`  ${tag}  ${c.label.padEnd(w)}  ${c.sig}`)
  if (tag === 'PAST') console.log(`        reached the state guard: ${POST_AUTH_STATE_GUARDS[guard]}`)
  if (tag === 'FAIL') console.log(`        ${r.err}${r.data ? ' ' + r.data : ''}`)
}
if (viaGuard > 0) {
  console.log(`\n  ${viaGuard} call(s) marked PAST: they got through onlySafe and ABI decoding and`)
  console.log('  stopped at a one-shot state guard. That is stronger evidence of a correct')
  console.log('  call than a bare success, because it proves auth AND decode AND arrival.')
}

// A control: the SAME call from an address that is NOT safe must revert
// NotSafe(). Without it, every OK above could mean "this contract lets anyone
// do it", which would be a far worse finding reported as a pass.
const NOT_SAFE = '0x9dc4246e'
const probe = calls.find((c) => c.sig === 'setVault(address)')
const ctl = await ethCall(probe.to, probe.data, '0x000000000000000000000000000000000000dEaD')
const ctlOk = ctl.err && JSON.stringify(ctl).includes(NOT_SAFE.slice(2))
console.log(`\n  control: the same call from a non-safe address is ${ctlOk ? 'REJECTED (NotSafe)' : 'NOT rejected'}`)
if (!ctlOk) {
  console.log('  ^ the OK results above therefore prove encoding, but NOT that these are gated.')
}

const batch = {
  version: '1.0',
  chainId: String(CHAIN),
  createdAt: 0,
  meta: {
    name: `GOAT Stream B wiring (chain ${CHAIN})`,
    description:
      'onlySafe wiring calls, to be executed as ONE Safe transaction after deploying with safe = <the Safe>. ' +
      'Generated and simulated by contracts/build-safe-wiring-batch.mjs.',
  },
  transactions: calls.map((c) => ({ to: c.to, value: '0', data: c.data })),
}
writeFileSync(OUT, JSON.stringify(batch, null, 2) + '\n')
console.log(`\n  wrote ${calls.length} call(s) -> ${OUT}`)

console.log(`
  SCOPE OF THIS RUN. Every call above was simulated against the LIVE stack and
  its encoding verified. This does NOT rehearse Safe execution: that needs a
  deployed Safe, which is the outstanding blocker. Do not read a green run here
  as "the batch flow is rehearsed".`)

if (bad > 0) { console.log(`\nRESULT: ${bad} call(s) reverted. exit 1`); process.exit(1) }
console.log('\nRESULT: every call encodes and simulates cleanly. exit 0')
process.exit(0)
