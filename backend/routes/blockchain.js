import pool from '../db/index.js'

export default async function blockchainRoutes(app) {

  // No auth required — public endpoint so the verification page can query
  // digest status without a user session.
  // GET /api/blockchain/digest/:message_id
  app.get('/blockchain/digest/:message_id', async (req, reply) => {
    const { message_id } = req.params

    const { rows } = await pool.query(
      `SELECT
         dq.message_id,
         dq.digest,
         dq.batch_id,
         br.batch_hash,
         br.tx_hash,
         br.block_number,
         br.recorded_at
       FROM digest_queue dq
       LEFT JOIN blockchain_records br ON br.batch_id = dq.batch_id
       WHERE dq.message_id = $1`,
      [message_id]
    )

    if (rows.length === 0) {
      return reply.code(404).send({ error: 'NOT_FOUND', message: 'No on-chain record yet' })
    }

    const r = rows[0]
    // batch_id is null while the message is still queued but not yet flushed
    // to the chain — return 404 rather than a partial response.
    if (r.batch_id === null) {
      return reply.code(404).send({ error: 'NOT_FOUND', message: 'No on-chain record yet' })
    }
    return reply.send({
      message_id:   r.message_id,
      digest:       r.digest,
      batch_id:     r.batch_id,
      batch_hash:   r.batch_hash,
      tx_hash:      r.tx_hash,
      block_number: r.block_number,
      recorded_at:  r.recorded_at,
      sepolia_url:  `https://sepolia.etherscan.io/tx/${r.tx_hash}`
    })
  })

  // GET /api/blockchain/batch/:batch_id
  // Returns all per-message digests in a batch in flush order.
  // Callers use this to independently recompute the batch hash and verify it
  // against the on-chain DigestRecorded event without trusting the server.
  app.get('/blockchain/batch/:batch_id', async (req, reply) => {
    const { batch_id } = req.params

    // Returns digests in queued_at order — callers must use this same order
    // to reproduce the batch hash (keccak256 is order-sensitive).
    const { rows } = await pool.query(
      `SELECT dq.message_id, dq.digest
       FROM digest_queue dq
       WHERE dq.batch_id = $1
       ORDER BY dq.queued_at ASC`,
      [batch_id]
    )

    if (rows.length === 0) {
      return reply.code(404).send({ error: 'NOT_FOUND', message: 'Batch not found' })
    }

    return reply.send({
      batch_id,
      digests: rows.map(r => ({ message_id: r.message_id, digest: r.digest }))
    })
  })

  // GET /api/blockchain/tx/:tx_hash
  // Proxies eth_getTransactionReceipt to Sepolia server-side so the browser
  // avoids CORS restrictions on public RPC endpoints.
  app.get('/blockchain/tx/:tx_hash', async (req, reply) => {
    const { tx_hash } = req.params
    const CONTRACT_ADDRESS = (process.env.CONTRACT_ADDRESS || '0x932d2B7D1e0E5B43792D21a28849E8Cae85D0783').toLowerCase()
    const RPC_URL = process.env.SEPOLIA_RPC_URL || 'https://rpc.sepolia.org'

    let receipt
    try {
      const rpcRes = await fetch(RPC_URL, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          jsonrpc: '2.0', id: 1,
          method: 'eth_getTransactionReceipt',
          params: [tx_hash]
        })
      })
      const json = await rpcRes.json()
      receipt = json.result
    } catch (e) {
      return reply.code(502).send({ error: 'RPC_ERROR', message: `Sepolia RPC error: ${e.message}` })
    }
    if (!receipt) {
      return reply.code(404).send({ error: 'NOT_FOUND', message: 'Transaction not found or not yet confirmed' })
    }

    // batchHash is the first indexed param of DigestRecorded → topics[1]
    for (const log of receipt.logs) {
      if (log.address.toLowerCase() === CONTRACT_ADDRESS) {
        return reply.send({
          on_chain_batch_hash: log.topics[1],
          // blockNumber comes back from the RPC as a hex string - parse to decimal.
          block_number: parseInt(receipt.blockNumber, 16),
          tx_hash: receipt.transactionHash
        })
      }
    }

    return reply.code(404).send({ error: 'NOT_FOUND', message: 'DigestRecorded event not found in transaction' })
  })
}
