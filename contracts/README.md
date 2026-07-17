# GoatCoin contracts (Season 0 pilot)

**[TARGET] — testnet only.** No mainnet deployment until the counsel memo
(spec §0). No claim in this directory exceeds `RUNTIME_VS_SPEC.md`.

**Season-0 scope note (updated 2026-07-11):** the **free-market mint (v2)**
contracts are now implemented: `WorkMinter` (GOAT minted from verified
work units — no USDT cap; manifestRoot replay-guarded) and `BuyDesk`
(voluntary `sell()` at a posted bid; owner-funded; budget-bounded, no
solvency-vs-supply promise) — spec:
`docs/superpowers/specs/2026-07-11-goatcoin-freemarket-mint-design.md`,
deploy: `script/DeployFreeMarket.s.sol`, runbook: `SEASON0_UI_RUNBOOK.md`.
`JobVault`/`RedemptionDesk` remain in-repo as the retired **backed pilot**
(mint ≤ escrow) for history and the live Sepolia v1 instances.
Desk sales are voluntary trades at a posted bid, never wages; no
holder is ever forced to sell.

- Build: `forge build` · Test: `forge test` · Lint: `forge fmt --check`
- Deploy (Base Sepolia ONLY): see `script/Deploy.s.sol`
- Spec: `docs/superpowers/specs/2026-07-11-goatcoin-onchain-wallet-design.md`

## Base Sepolia deployment (Season 0 rehearsal)

**[TARGET] — PENDING.** Nothing is deployed to a public network yet. No
claim below implies a live token, live mint, or live desk.

**Local proof already done** (anvil, not a public network):
- `--chain-id 84532` (Base Sepolia's id): `forge script script/Deploy.s.sol
  --broadcast` deploys all 6 contracts and logs their addresses; broadcast
  succeeds.
- `--chain-id 8453` (Base mainnet's id) or any other non-allowlisted chain:
  the same script call reverts with `Deploy.ChainNotAllowed()` — the
  deploy script only allows Base Sepolia (84532) and local anvil (31337);
  the counsel-memo gate (spec §0) works before any real deployment is
  attempted.

### PENDING — founder runs:

Requires a funded Base Sepolia deployer key (`contracts/.env`, from
`.env.example` — never commit it). Then:

```bash
cd contracts && source .env
forge script script/Deploy.s.sol --rpc-url $BASE_SEPOLIA_RPC_URL --broadcast
```

Record the 6 logged addresses here, replacing the placeholders:

| Contract | Address |
| --- | --- |
| MockUSDT | `$MOCK_USDT` |
| EnrollmentRegistry | `$REGISTRY` |
| GoatCoin | `$GOAT` |
| HoldbackEscrow | `$ESCROW` |
| RedemptionDesk | `$DESK` |
| JobVault | `$VAULT` |

Then perform the post-deploy wiring from `$SAFE_ADDRESS` (`$SAFE_KEY` below
is that Safe/EOA's signing key, e.g. via `cast send ... --private-key
$SAFE_KEY`):

```bash
# After the deploy run above, export the 6 logged addresses and the Safe key
# (on testnet the SAFE_ADDRESS owner key; NEVER a real-funds key):
export SAFE_KEY=0x...          # key controlling SAFE_ADDRESS
export MOCK_USDT=0x...         # from deploy log
export REGISTRY=0x...
export GOAT=0x...
export ESCROW=0x...
export DESK=0x...
export VAULT=0x...

cast send $ESCROW "setVault(address)" $VAULT \
  --private-key $SAFE_KEY --rpc-url $BASE_SEPOLIA_RPC_URL

cast send $GOAT "setMinter(address,bool)" $VAULT true \
  --private-key $SAFE_KEY --rpc-url $BASE_SEPOLIA_RPC_URL

cast send $REGISTRY "setSystemAddress(address,bool)" $ESCROW true \
  --private-key $SAFE_KEY --rpc-url $BASE_SEPOLIA_RPC_URL
cast send $REGISTRY "setSystemAddress(address,bool)" $VAULT true \
  --private-key $SAFE_KEY --rpc-url $BASE_SEPOLIA_RPC_URL
cast send $REGISTRY "setSystemAddress(address,bool)" $DESK true \
  --private-key $SAFE_KEY --rpc-url $BASE_SEPOLIA_RPC_URL
# load-bearing: RedemptionDesk.redeem() reverts with GoatCoin.TransferRestricted
# unless the beneficiary is a registered system address — see the
# "DEPLOY PRECONDITION" doc comment on RedemptionDesk.
cast send $REGISTRY "setSystemAddress(address,bool)" $FOUNDER_ADDRESS true \
  --private-key $SAFE_KEY --rpc-url $BASE_SEPOLIA_RPC_URL
cast send $REGISTRY "setSystemAddress(address,bool)" $RESERVE_ADDRESS true \
  --private-key $SAFE_KEY --rpc-url $BASE_SEPOLIA_RPC_URL
cast send $REGISTRY "setSystemAddress(address,bool)" $SAFE_ADDRESS true \
  --private-key $SAFE_KEY --rpc-url $BASE_SEPOLIA_RPC_URL
```

Verify:

```bash
cast call $GOAT "isMinter(address)(bool)" $VAULT --rpc-url $BASE_SEPOLIA_RPC_URL
# expect: true
```

### Operational notes

- **Backstop bricks further minting on a jobId:** after `releaseAfterDeadline` fires (30 days past last mint), later `mintBatch` calls on that job revert; recover with `closeJob` + a fresh jobId.
- **Never open a redemption window while one is active** — a new window supersedes the old and resets per-account caps.
- **`escrow.setVault` is permanent** — double-check the vault address; a typo requires redeploying the escrow+vault pair.
