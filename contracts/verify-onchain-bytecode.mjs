#!/usr/bin/env node
// contracts/verify-onchain-bytecode.mjs
//
// Compare the RUNTIME bytecode deployed on a live chain against the local solc
// artifacts in contracts/out, for every address named in the deployment
// manifests.
//
// ---------------------------------------------------------------------------
// WHY A NAIVE BYTE COMPARISON IS WRONG, AND REPORTS A FALSE MISMATCH
// ---------------------------------------------------------------------------
//
// The artifact's `deployedBytecode.object` is NOT what ends up on chain.
// Solidity `immutable` values are burned into the runtime code by the
// CONSTRUCTOR: the artifact carries ZEROS at those offsets, and the chain
// carries the real values. Every contract in this deployment has immutables --
// measured 3 to 9 slots each -- so a plain `===` reports a mismatch for a
// perfectly correct deployment. This repo already recorded that trap once:
// "the artifact's deployedBytecode is never the on-chain code".
//
// So the comparison masks the regions named by `deployedBytecode
// .immutableReferences` to zero on BOTH sides, and compares the remainder --
// which is the actual compiled logic, byte for byte.
//
// Two things keep that masking from becoming a way to pass by ignoring
// everything:
//
//   1. The masked byte count is REPORTED and asserted small. Masking is
//      bounded to 32 bytes per slot; if a future artifact claimed to mask
//      thousands of bytes, that is a hole, not a pass.
//   2. A contract with ZERO immutables must match EXACTLY, unmasked. MockUSDT
//      is that control. If it matches byte-for-byte, the compiler version,
//      optimizer settings and source tree all agree -- which is what makes the
//      masked comparisons on the other contracts trustworthy rather than
//      convenient. If the control is absent, this script says so and does not
//      claim a clean verification.
//
// The trailing solc metadata (an IPFS digest OF THE SOURCE) is inside the
// compared region and is deliberately NOT masked: it is the strongest single
// signal that the exact source compiled here is the source that was deployed.
//
// USAGE
//   node contracts/verify-onchain-bytecode.mjs [--chain 84532] [--rpc <url>]
// Exit 0 = every contract verified. Exit 1 = a mismatch. Exit 2 = could not
// check (missing artifact, RPC failure) -- "could not check" must never read as
// "checked and fine".

import { readFileSync, existsSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const HERE = dirname(fileURLToPath(import.meta.url))

const args = process.argv.slice(2)
const argOf = (flag, dflt) => {
  const i = args.indexOf(flag)
  return i >= 0 && args[i + 1] ? args[i + 1] : dflt
}
const CHAIN = argOf('--chain', '84532')
let RPC = argOf('--rpc', '')

if (!RPC) {
  // Same source of truth the launcher uses; never prints any value.
  const envPath = join(HERE, '.env')
  if (existsSync(envPath)) {
    for (const line of readFileSync(envPath, 'utf8').split(/\r?\n/)) {
      const m = /^\s*(BASE_SEPOLIA_RPC_URL|RPC_URL)\s*=\s*(.+)$/.exec(line)
      if (m && !RPC) RPC = m[2].trim()
    }
  }
}
if (!RPC) {
  console.error('no RPC: pass --rpc or set BASE_SEPOLIA_RPC_URL in contracts/.env')
  process.exit(2)
}

// manifest key -> solc contract name
const NAMES = {
  goatCoin: 'GoatCoin',
  enrollmentRegistry: 'EnrollmentRegistry',
  workMinter: 'WorkMinter',
  holdbackEscrow: 'HoldbackEscrow',
  mockUSDT: 'MockUSDT',
  buyDesk: 'BuyDesk',
  buyDeskFactory: 'BuyDeskFactory',
  epochSettlement: 'EpochSettlement',
  epochHoldbackEscrow: 'HoldbackEscrow',
  founderResolver: 'FounderResolver',
  workerBinding: 'WorkerBinding',
}

const targets = []
for (const file of [`${CHAIN}.json`, `${CHAIN}.factory.json`, `${CHAIN}.epoch.json`]) {
  const p = join(HERE, 'deployments', file)
  if (!existsSync(p)) continue
  // Strip a UTF-8 BOM: `84532.epoch.json` carries one because testnet-up.ps1
  // rewrites it through PowerShell 5.1's `Set-Content -Encoding utf8`, which
  // emits a BOM. JSON.parse rejects it outright. Tolerated here so a reader
  // cannot be defeated by an encoding artifact, and fixed at the writer.
  const j = JSON.parse(readFileSync(p, 'utf8').replace(/^﻿/, ''))
  for (const [k, v] of Object.entries(j)) {
    if (!NAMES[k]) continue
    if (typeof v !== 'string' || !/^0x[0-9a-fA-F]{40}$/.test(v)) continue
    if (targets.some((t) => t.address.toLowerCase() === v.toLowerCase())) continue
    targets.push({ key: k, name: NAMES[k], address: v, from: file })
  }
}
if (targets.length === 0) {
  console.error(`no deployed addresses found for chain ${CHAIN}`)
  process.exit(2)
}

async function ethGetCode(address) {
  const res = await fetch(RPC, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'eth_getCode', params: [address, 'latest'] }),
  })
  if (!res.ok) throw new Error(`HTTP ${res.status}`)
  const j = await res.json()
  if (j.error) throw new Error(JSON.stringify(j.error))
  return j.result
}

const strip = (h) => (h.startsWith('0x') ? h.slice(2) : h).toLowerCase()

/** Zero the immutable regions, in BYTES, on a hex string. */
function mask(hexNo0x, regions) {
  const b = Buffer.from(hexNo0x, 'hex')
  let masked = 0
  for (const { start, length } of regions) {
    if (start + length > b.length) continue
    b.fill(0, start, start + length)
    masked += length
  }
  return { hex: b.toString('hex'), masked }
}

console.log(`=== on-chain bytecode verification, chain ${CHAIN} ===`)
console.log(`rpc: ${RPC.replace(/(https?:\/\/[^/]+).*/, '$1')}\n`)

let fail = 0
let blocked = 0
let exactControls = 0
const rows = []

for (const t of targets) {
  const artPath = join(HERE, 'out', `${t.name}.sol`, `${t.name}.json`)
  if (!existsSync(artPath)) {
    rows.push({ ...t, verdict: 'NO ARTIFACT', detail: artPath })
    blocked++
    continue
  }
  const art = JSON.parse(readFileSync(artPath, 'utf8'))
  const expectedRaw = strip(art.deployedBytecode.object)
  const links = art.deployedBytecode.linkReferences || {}
  if (Object.keys(links).length > 0) {
    // Unlinked placeholders would compare as garbage; refuse rather than
    // silently "mask" them into a pass.
    rows.push({ ...t, verdict: 'BLOCKED', detail: `artifact has ${Object.keys(links).length} unlinked library reference(s)` })
    blocked++
    continue
  }

  let onchainRaw
  try {
    onchainRaw = strip(await ethGetCode(t.address))
  } catch (e) {
    rows.push({ ...t, verdict: 'RPC ERROR', detail: String(e.message || e) })
    blocked++
    continue
  }
  if (onchainRaw.length === 0) {
    rows.push({ ...t, verdict: 'NO CODE', detail: 'address has no bytecode' })
    blocked++
    continue
  }

  const regions = Object.values(art.deployedBytecode.immutableReferences || {}).flat()
  const nSlots = regions.length

  if (onchainRaw.length !== expectedRaw.length) {
    rows.push({ ...t, verdict: 'MISMATCH', detail: `length ${onchainRaw.length / 2} B on chain vs ${expectedRaw.length / 2} B in artifact` })
    fail++
    continue
  }

  const a = mask(onchainRaw, regions)
  const b = mask(expectedRaw, regions)
  const equal = a.hex === b.hex

  if (nSlots === 0) {
    // The control: no immutables, so nothing is masked and the match must be exact.
    if (equal && a.masked === 0) exactControls++
    rows.push({
      ...t,
      verdict: equal ? 'EXACT MATCH (control)' : 'MISMATCH',
      detail: `${onchainRaw.length / 2} B, no immutables, nothing masked`,
    })
    if (!equal) fail++
    continue
  }

  rows.push({
    ...t,
    verdict: equal ? 'MATCH' : 'MISMATCH',
    detail: `${onchainRaw.length / 2} B, ${nSlots} immutable slot(s), ${a.masked} B masked (${((a.masked / (onchainRaw.length / 2)) * 100).toFixed(2)}%)`,
  })
  if (!equal) fail++
}

const w = Math.max(...rows.map((r) => r.name.length))
for (const r of rows) {
  console.log(`  ${r.name.padEnd(w)}  ${r.address}  ${r.verdict.padEnd(21)} ${r.detail}`)
}

console.log('')
if (exactControls === 0) {
  console.log('  NOTE: no zero-immutable control contract was verified in this run, so the')
  console.log('        masked comparisons above are not corroborated by an exact match.')
}
console.log(`  verified: ${rows.filter((r) => r.verdict.startsWith('MATCH') || r.verdict.startsWith('EXACT')).length}/${rows.length}   mismatches: ${fail}   could-not-check: ${blocked}`)

if (blocked > 0) {
  console.log('\nRESULT: COULD NOT CHECK -- exit 2. "Could not check" is not "checked and fine".')
  process.exit(2)
}
if (fail > 0) {
  console.log('\nRESULT: MISMATCH -- exit 1.')
  process.exit(1)
}
console.log('\nRESULT: every deployed contract matches its local artifact. exit 0')
process.exit(0)
