import pool from '../db/index.js'

export default async function blockchainRoutes(app) {

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
}
