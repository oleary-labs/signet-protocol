#!/usr/bin/env node
// verify-solana-ed25519.mjs — Verify a FROST Ed25519 signature on Solana devnet
// using the native Ed25519SigVerify precompile.
//
// Usage:
//   node scripts/verify-solana-ed25519.mjs \
//     --pubkey <32-byte-hex> \
//     --message <hex> \
//     --signature <64-byte-hex>
//
// The script:
// 1. Generates an ephemeral Solana keypair (funded via airdrop)
// 2. Constructs an Ed25519SigVerify instruction with the given signature
// 3. Submits the transaction to Solana devnet
// 4. Reports whether verification succeeded

import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

import {
  Connection,
  Keypair,
  Transaction,
  TransactionInstruction,
  PublicKey,
  LAMPORTS_PER_SOL,
} from "@solana/web3.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// Ed25519 precompile program ID.
const ED25519_PROGRAM_ID = new PublicKey(
  "Ed25519SigVerify111111111111111111111111111"
);

function parseArgs() {
  const args = process.argv.slice(2);
  const parsed = {};
  for (let i = 0; i < args.length; i++) {
    if (args[i].startsWith("--")) {
      const key = args[i].slice(2);
      const val = args[i + 1];
      parsed[key] = val;
      i++;
    }
  }
  return parsed;
}

function hexToBytes(hex) {
  hex = hex.replace(/^0x/, "");
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
  }
  return bytes;
}

// Build the Ed25519SigVerify instruction data.
// See: https://docs.solanalabs.com/runtime/programs#ed25519-program
//
// Layout:
//   num_signatures (u8)
//   padding (u8)
//   -- per signature (repeated num_signatures times): --
//   signature_offset (u16 LE)
//   signature_instruction_index (u16 LE) — 0xFFFF = same txn
//   public_key_offset (u16 LE)
//   public_key_instruction_index (u16 LE) — 0xFFFF = same txn
//   message_data_offset (u16 LE)
//   message_data_size (u16 LE)
//   message_instruction_index (u16 LE) — 0xFFFF = same txn
//   -- end per signature --
//   signature bytes (64)
//   public key bytes (32)
//   message bytes (variable)
function buildEd25519Instruction(pubkey, message, signature) {
  const numSigs = 1;
  const headerSize = 2; // num_signatures + padding
  const perSigSize = 14; // 7 x u16
  const dataStart = headerSize + perSigSize * numSigs;

  const sigOffset = dataStart;
  const pubkeyOffset = sigOffset + 64;
  const messageOffset = pubkeyOffset + 32;
  const messageSize = message.length;

  const totalLen = messageOffset + messageSize;
  const data = Buffer.alloc(totalLen);

  // Header
  data.writeUInt8(numSigs, 0);
  data.writeUInt8(0, 1); // padding

  // Per-signature entry
  let off = 2;
  data.writeUInt16LE(sigOffset, off);
  off += 2;
  data.writeUInt16LE(0xffff, off); // same instruction
  off += 2;
  data.writeUInt16LE(pubkeyOffset, off);
  off += 2;
  data.writeUInt16LE(0xffff, off); // same instruction
  off += 2;
  data.writeUInt16LE(messageOffset, off);
  off += 2;
  data.writeUInt16LE(messageSize, off);
  off += 2;
  data.writeUInt16LE(0xffff, off); // same instruction
  off += 2;

  // Signature (64 bytes)
  Buffer.from(signature).copy(data, sigOffset);
  // Public key (32 bytes)
  Buffer.from(pubkey).copy(data, pubkeyOffset);
  // Message
  Buffer.from(message).copy(data, messageOffset);

  return new TransactionInstruction({
    keys: [],
    programId: ED25519_PROGRAM_ID,
    data,
  });
}

async function main() {
  const args = parseArgs();
  if (!args.pubkey || !args.message || !args.signature) {
    console.error(
      "usage: verify-solana-ed25519.mjs --pubkey <hex> --message <hex> --signature <hex>"
    );
    process.exit(1);
  }

  const pubkey = hexToBytes(args.pubkey);
  const message = hexToBytes(args.message);
  const signature = hexToBytes(args.signature);

  if (pubkey.length !== 32) {
    console.error(`pubkey must be 32 bytes, got ${pubkey.length}`);
    process.exit(1);
  }
  if (signature.length !== 64) {
    console.error(`signature must be 64 bytes, got ${signature.length}`);
    process.exit(1);
  }

  console.log(`Pubkey:    ${Buffer.from(pubkey).toString("hex")}`);
  console.log(`Message:   ${Buffer.from(message).toString("hex")} (${message.length} bytes)`);
  console.log(`Signature: ${Buffer.from(signature).toString("hex")}`);

  const rpcUrl = args.rpc || "https://api.devnet.solana.com";
  const connection = new Connection(rpcUrl, "confirmed");

  // Load payer keypair from file (pre-funded).
  const keypairPath = args.keypair || path.join(__dirname, ".solana-test-keypair.json");
  if (!fs.existsSync(keypairPath)) {
    console.error(`Keypair file not found: ${keypairPath}`);
    console.error("Generate one: node -e \"...\" (see scripts/README)");
    process.exit(1);
  }
  const secret = Uint8Array.from(JSON.parse(fs.readFileSync(keypairPath, "utf8")));
  const payer = Keypair.fromSecretKey(secret);
  const balance = await connection.getBalance(payer.publicKey);
  console.log(`\nPayer: ${payer.publicKey.toBase58()} (${balance / LAMPORTS_PER_SOL} SOL)`);

  // Build and send the transaction.
  const ix = buildEd25519Instruction(pubkey, message, signature);
  const tx = new Transaction().add(ix);
  tx.feePayer = payer.publicKey;
  tx.recentBlockhash = (await connection.getLatestBlockhash()).blockhash;
  tx.sign(payer);

  console.log("\nSubmitting Ed25519SigVerify transaction...");

  try {
    const txSig = await connection.sendRawTransaction(tx.serialize(), {
      skipPreflight: false,
      preflightCommitment: "confirmed",
    });
    await connection.confirmTransaction(txSig, "confirmed");
    console.log(`\nOK: Solana Ed25519SigVerify succeeded`);
    console.log(`Transaction: ${txSig}`);
    console.log(`Explorer: https://explorer.solana.com/tx/${txSig}?cluster=devnet`);
  } catch (err) {
    console.error(`\nFAIL: Solana Ed25519SigVerify failed`);
    console.error(err.message || err);
    process.exit(1);
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
