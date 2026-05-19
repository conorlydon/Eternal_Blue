import pool from '../db/index.js'

export default async function conversationRoutes(app) {

  // GET /api/conversations
  app.get('/conversations', {
    onRequest: [app.authenticate]
  }, async (req, reply) => {
    const userId = req.user.user_id
    const { rows } = await pool.query(
      `SELECT
         c.id AS conversation_id,
         CASE WHEN c.user_a_id = $1 THEN c.user_b_id ELSE c.user_a_id END AS with_user_id,
         CASE WHEN c.user_a_id = $1 THEN ub.username ELSE ua.username END AS with_username,
         c.last_message_at,
         COUNT(m.id) FILTER (
           WHERE m.recipient_id = $1
           AND m.read_at IS NULL
           AND m.deleted_by_recipient = FALSE
         ) AS unread_count
       FROM conversations c
       JOIN users ua ON ua.id = c.user_a_id
       JOIN users ub ON ub.id = c.user_b_id
       LEFT JOIN messages m ON m.conversation_id = c.id
       WHERE c.user_a_id = $1 OR c.user_b_id = $1
       GROUP BY c.id, ua.username, ub.username
       ORDER BY c.last_message_at DESC NULLS LAST`,
      [userId]
    )
    return reply.send({ conversations: rows, total: rows.length })
  })

  // GET /api/conversations/:conversation_id/messages
  app.get('/conversations/:conversation_id/messages', {
    onRequest: [app.authenticate]
  }, async (req, reply) => {
    const userId = req.user.user_id
    const { conversation_id } = req.params
    const limit  = Math.min(parseInt(req.query.limit) || 50, 100)
    const before = req.query.before || new Date().toISOString()

    // verify user is a participant
    const { rows: conv } = await pool.query(
      `SELECT * FROM conversations WHERE id = $1
       AND (user_a_id = $2 OR user_b_id = $2)`,
      [conversation_id, userId]
    )
    if (conv.length === 0) {
      return reply.code(403).send({ error: 'FORBIDDEN', message: 'Not a participant' })
    }

    const { rows } = await pool.query(
      `SELECT
         m.id AS message_id,
         m.sender_id,
         su.username AS sender_username,
         m.recipient_id,
         ru.username AS recipient_username,
         m.ciphertext,
         m.encapsulated_key,
         m.nonce,
         m.sent_at,
         m.read_at,
         m.is_forwarded,
         m.original_message_id
       FROM messages m
       JOIN users su ON su.id = m.sender_id
       JOIN users ru ON ru.id = m.recipient_id
       WHERE m.conversation_id = $1
         AND m.sent_at < $2
         AND (m.deleted_by_sender = FALSE OR m.sender_id != $3)
         AND (m.deleted_by_recipient = FALSE OR m.recipient_id != $3)
       ORDER BY m.sent_at ASC
       LIMIT $4`,
      [conversation_id, before, userId, limit]
    )
    return reply.send({
      conversation_id,
      messages: rows,
      total: rows.length
    })
  })

  // POST /api/conversations/:conversation_id/read
  app.post('/conversations/:conversation_id/read', {
    onRequest: [app.authenticate]
  }, async (req, reply) => {
    const userId = req.user.user_id
    const { conversation_id } = req.params

    const { rows: conv } = await pool.query(
      `SELECT * FROM conversations WHERE id = $1
       AND (user_a_id = $2 OR user_b_id = $2)`,
      [conversation_id, userId]
    )
    if (conv.length === 0) {
      return reply.code(403).send({ error: 'FORBIDDEN', message: 'Not a participant' })
    }

    const { rowCount } = await pool.query(
      `UPDATE messages SET read_at = NOW()
       WHERE conversation_id = $1
         AND recipient_id = $2
         AND read_at IS NULL`,
      [conversation_id, userId]
    )
    return reply.send({ conversation_id, marked_read: rowCount })
  })
}
