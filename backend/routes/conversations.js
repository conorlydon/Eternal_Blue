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
    // Cap at 100 to prevent a client requesting an unbounded number of messages.
    // Defaults to 50 if no limit query param is provided.
    const limit  = Math.min(parseInt(req.query.limit) || 50, 100)
    // Cursor-based pagination — only return messages sent before this timestamp.
    // Defaults to now so the first request gets the most recent window.
    const before = req.query.before || new Date().toISOString()

    const { rows: conv } = await pool.query(
      `SELECT c.*, ua.username AS user_a_username, ub.username AS user_b_username
       FROM conversations c
       JOIN users ua ON ua.id = c.user_a_id
       JOIN users ub ON ub.id = c.user_b_id
       WHERE c.id = $1`,
      [conversation_id]
    )
    if (conv.length === 0) {
      return reply.code(404).send({ error: 'NOT_FOUND', message: 'Conversation not found' })
    }
    if (conv[0].user_a_id !== userId && conv[0].user_b_id !== userId) {
      return reply.code(403).send({ error: 'FORBIDDEN', message: 'Not a participant' })
    }
    const with_user_id  = conv[0].user_a_id === userId ? conv[0].user_b_id       : conv[0].user_a_id
    const with_username = conv[0].user_a_id === userId ? conv[0].user_b_username  : conv[0].user_a_username

    // Exclude messages the user has soft-deleted and any that have been revoked.
    // r.id IS NULL filters out revoked messages via the LEFT JOIN.
    const { rows: countRows } = await pool.query(
      `SELECT COUNT(*) AS total
       FROM messages m
       LEFT JOIN revocations r ON r.message_id = m.id
       WHERE m.conversation_id = $1
         AND (m.deleted_by_sender = FALSE OR m.sender_id != $2)
         AND (m.deleted_by_recipient = FALSE OR m.recipient_id != $2)
         AND r.id IS NULL`,
      [conversation_id, userId]
    )

    const { rows } = await pool.query(
      `SELECT
         m.id AS message_id,
         m.sender_id,
         su.username AS sender_username,
         m.recipient_id,
         ru.username AS recipient_username,
         m.ciphertext,
         m.encapsulated_key,
         m.sent_at_ms,
         m.sent_at,
         m.read_at,
         m.is_forwarded,
         m.original_message_id
       FROM messages m
       JOIN users su ON su.id = m.sender_id
       JOIN users ru ON ru.id = m.recipient_id
       LEFT JOIN revocations r ON r.message_id = m.id
       WHERE m.conversation_id = $1
         AND m.sent_at < $2
         AND (m.deleted_by_sender = FALSE OR m.sender_id != $3)
         AND (m.deleted_by_recipient = FALSE OR m.recipient_id != $3)
         AND r.id IS NULL
       ORDER BY m.sent_at ASC
       LIMIT $4`,
      [conversation_id, before, userId, limit]
    )
    return reply.send({
      conversation_id,
      with_user_id,
      with_username,
      messages: rows,
      total: parseInt(countRows[0].total)
    })
  })

  // POST /api/conversations/:conversation_id/read
  app.post('/conversations/:conversation_id/read', {
    onRequest: [app.authenticate]
  }, async (req, reply) => {
    const userId = req.user.user_id
    const { conversation_id } = req.params

    const { rows: conv } = await pool.query(
      `SELECT * FROM conversations WHERE id = $1`,
      [conversation_id]
    )
    if (conv.length === 0) {
      return reply.code(404).send({ error: 'NOT_FOUND', message: 'Conversation not found' })
    }
    if (conv[0].user_a_id !== userId && conv[0].user_b_id !== userId) {
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
