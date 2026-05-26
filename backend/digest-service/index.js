import { ethers } from 'ethers'
import pg from 'pg'
import { readFileSync } from 'fs'
import { randomUUID } from 'crypto'
import * as dotenv from 'dotenv'
dotenv.config()

const { Pool } = pg
const pool = new Pool({
  host:     process.env.PGHOST,
  port:     process.env.PGPORT,
  database: process.env.PGDATABASE,
  user:     process.env.PGUSER,
  password: process.env.PGPASSWORD,
})

const CONTRACT_ABI = JSON.parse(readFileSync('./abi.json', 'utf8'))
const provider = new ethers.JsonRpcProvider(process.env.SEPOLIA_RPC_URL)
const wallet   = new ethers.Wallet(process.env.WALLET_PRIVATE_KEY, provider)
const contract = new ethers.Contract(process.env.CONTRACT_ADDRESS, CONTRACT_ABI, wallet)

export async function onMessageSent(messageId, ciphertext) {
  const digest = ethers.keccak256(Buffer.from(ciphertext, 'base64'))
  await pool.query(
    `INSERT INTO digest_queue (message_id, digest)
     VALUES ($1, $2)`,
    [messageId, digest]
  )
  console.log(`Queued digest for message ${messageId}`)
}

async function flushWithRetry(rows, attempt = 1) {
  const MAX_ATTEMPTS = 5
  const BACKOFF_MS   = [0, 5000, 15000, 30000, 60000]

  if (attempt > 1) {
    const delay = BACKOFF_MS[attempt - 1]
    console.log(`Retry attempt ${attempt}/${MAX_ATTEMPTS} — waiting ${delay / 1000}s...`)
    await new Promise(r => setTimeout(r, delay))
  }

  try {
    const combined  = rows.map(r => r.digest).join('')
    const batchHash = ethers.keccak256(ethers.toUtf8Bytes(combined))

    const tx      = await contract.recordDigest(batchHash)
    console.log(`Transaction sent: ${tx.hash} — waiting for confirmation...`)
    const receipt = await tx.wait()
    console.log(`Confirmed in block ${receipt.blockNumber}`)

    const batchId = randomUUID()
    await pool.query(
      `INSERT INTO blockchain_records
       (batch_id, batch_hash, tx_hash, block_number)
       VALUES ($1, $2, $3, $4)`,
      [batchId, batchHash, tx.hash, receipt.blockNumber]
    )

    await pool.query(
      `UPDATE digest_queue
       SET batch_id = $1
       WHERE id = ANY($2::uuid[])`,
      [batchId, rows.map(r => r.id)]
    )

    console.log(`Batch flushed: ${rows.length} messages → tx: ${tx.hash}`)

  } catch (err) {
    console.error(`Flush attempt ${attempt} failed: ${err.message}`)
    if (attempt < MAX_ATTEMPTS) {
      return flushWithRetry(rows, attempt + 1)
    }
    console.error(`Flush failed after ${MAX_ATTEMPTS} attempts — batch will retry on next scheduled flush`)
  }
}

async function flushDigestBatch() {
  const { rows } = await pool.query(
    `SELECT id, message_id, digest
     FROM digest_queue
     WHERE batch_id IS NULL
     ORDER BY queued_at ASC`
  )
  if (rows.length === 0) {
    console.log('Digest queue empty — nothing to flush')
    return
  }

  console.log(`Flushing ${rows.length} queued digest(s)...`)
  await flushWithRetry(rows)
}

setInterval(flushDigestBatch, 10 * 60 * 1000)
console.log('Digest service started — flushing every 10 minutes')
flushDigestBatch()