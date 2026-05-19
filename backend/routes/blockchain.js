import pool from '../db/index.js'

export default async function blockchainRoutes(app) {

  // GET /api/blockchain/digest/:message_id
  app.get('/blockchain/digest/:message_id', {
    onRequest: [app.authenticate]
  }, async (req, reply) => {
    const { message_id } = req.params

    const { rows } = await pool.query(
      `SELECT
         dq.message_id,
         dq.batch_id,
         br.batch_hash,
         br.tx_hash,
         br.block_number,
         br.recorded_at,
         m.sender_id,
         m.recipient_id
       FROM digest_queue dq
       JOIN messages m ON m.id = dq.message_id
       LEFT JOIN blockchain_records br ON br.batch_id = dq.batch_id
       WHERE dq.message_id = $1`,
      [message_id]
    )

    if (rows.length === 0) {
      return reply.code(404).send({ error: 'NOT_FOUND', message: 'No on-chain record yet' })
    }

    const r = rows[0]
    if (r.sender_id !== req.user.user_id && r.recipient_id !== req.user.user_id) {
      return reply.code(403).send({ error: 'FORBIDDEN', message: 'Not your message' })
    }

    if (r.batch_id === null) {
      return reply.code(404).send({ error: 'NOT_FOUND', message: 'No on-chain record yet' })
    }
    return reply.send({
      message_id:  r.message_id,
      batch_hash:  r.batch_hash,
      tx_hash:     r.tx_hash,
      block_number: r.block_number,
      recorded_at: r.recorded_at,
      sepolia_url: `https://sepolia.etherscan.io/tx/${r.tx_hash}`
    })
  })
}
