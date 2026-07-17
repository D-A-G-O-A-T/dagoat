// A viem account whose private key lives ONLY in the Rust backend.
//
// The webview never holds key material. Every signing operation is an
// `invoke()` to a Tauri command (see the wallet_* contract in
// docs/superpowers/specs/2026-07-13-stronghold-wallet-design.md §3.1): Rust
// decrypts the key from the Stronghold vault into its own memory, signs with
// `alloy`, zeroizes, and returns only the signature / signed raw tx. The bytes
// never cross the IPC bridge into JS, never appear in devtools, never in logs.
//
// `toAccount` gives us a real viem LocalAccount whose signMessage /
// signTransaction / signTypedData are backed by those commands, so every
// existing tx path (getWalletClient → writeContract / sendRawTransaction, and
// simulateContract's `account`) works unchanged.
import { toAccount } from "viem/accounts";
import { toHex } from "viem";
import { invoke } from "@tauri-apps/api/core";

// viem hands `signMessage` either a UTF-8 string or `{ raw: Hex | ByteArray }`.
// The Rust command (`wallet_sign_message`) does the EIP-191 personal_sign over
// the RAW bytes decoded from this hex — it adds the "\x19Ethereum Signed
// Message:\n<len>" prefix itself — so we pass the message payload as hex, never
// the prefixed digest.
function messageToHex(message) {
  if (typeof message === "string") return toHex(message); // UTF-8 → 0x hex
  const raw = message?.raw;
  if (raw == null) throw new Error("Unsupported message: expected a string or { raw }.");
  return typeof raw === "string" ? raw : toHex(raw); // ByteArray → 0x hex
}

function bigintToDecimalString(value) {
  // value may be a bigint (viem's prepared request) or an already-stringified
  // number; normalize to a decimal string the Rust U256 parser accepts.
  return typeof value === "bigint" ? value.toString(10) : String(value);
}

// Pick exactly the EIP-1559 fields the `wallet_sign_transaction` contract
// expects and JSON-encode them safely (bigints can't go through
// JSON.stringify). Numeric wei/gas/fee fields become decimal strings; chainId
// and nonce stay small integers. viem fills nonce/gas/fees before it calls us.
function transactionToJson(tx) {
  const out = { type: "eip1559" };
  if (tx.chainId != null) out.chainId = Number(tx.chainId);
  if (tx.nonce != null) out.nonce = Number(tx.nonce);
  if (tx.to != null) out.to = tx.to;
  if (tx.value != null) out.value = bigintToDecimalString(tx.value);
  if (tx.gas != null) out.gas = bigintToDecimalString(tx.gas);
  if (tx.maxFeePerGas != null) out.maxFeePerGas = bigintToDecimalString(tx.maxFeePerGas);
  if (tx.maxPriorityFeePerGas != null) out.maxPriorityFeePerGas = bigintToDecimalString(tx.maxPriorityFeePerGas);
  if (tx.data != null) out.data = tx.data;
  if (tx.accessList != null) out.accessList = tx.accessList;
  return JSON.stringify(out);
}

// Typed-data (EIP-712) values (domain.chainId, message uint fields) can be
// bigints; stringify them as decimal so the JSON survives and alloy's dynamic
// EIP-712 encoder can parse them.
function bigintReplacer(_key, value) {
  return typeof value === "bigint" ? value.toString(10) : value;
}

/// Build a viem account for `address` whose signing is delegated to Rust.
/// `address` is the public EIP-55 address from wallet_create/import/unlock —
/// no key material is passed or held. The active wallet in the Rust session
/// determines which key actually signs; `address` is bound here and sent as
/// `expectedAddress` on every sign call, so if the user switched wallets
/// mid-flow the Rust side refuses rather than sign with the wrong key/nonce.
export function createRustAccount(address) {
  return toAccount({
    address,
    async signMessage({ message }) {
      // returns a 0x 65-byte EIP-191 signature, verbatim from Rust
      return invoke("wallet_sign_message", {
        expectedAddress: address,
        messageHex: messageToHex(message),
      });
    },
    async signTransaction(transaction) {
      // returns the 0x-prefixed SIGNED RAW EIP-1559 (type-0x02) tx hex,
      // ready for eth_sendRawTransaction — viem sends it as-is.
      return invoke("wallet_sign_transaction", {
        expectedAddress: address,
        txJson: transactionToJson(transaction),
      });
    },
    async signTypedData(typedData) {
      // typedData = { domain, types, primaryType, message }; returns a 0x
      // 65-byte EIP-712 signature, verbatim from Rust.
      return invoke("wallet_sign_typed_data", {
        expectedAddress: address,
        typedJson: JSON.stringify(typedData, bigintReplacer),
      });
    },
  });
}

// Exported for unit tests (encoding is the load-bearing contract detail).
export const __test = { messageToHex, transactionToJson, bigintReplacer };
