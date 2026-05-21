import pool from '../db/index.js'
import { keccak256 } from 'ethers'

export default async function messageRoutes(app) {

  // POST /api/messages
  app.post('/messages', {
    onRequest: [app.authenticate],
    schema: {
      body: {
        type: 'object',
        required: ['recipient_username', 'ciphertext', 'encapsulated_key', 'sent_at_ms'],
        properties: {
          recipient_username: { type: 'string' },
          ciphertext:         { type: 'string' },
          encapsulated_key:   { type: 'string' },
          sent_at_ms:         { type: 'integer', minimum: 0 }
        },
        additionalProperties: false
      }
    }
  }, async (req, reply) => {
    const senderId = req.user.user_id
    const { recipient_username, ciphertext, encapsulated_key, sent_at_ms } = req.body

    // look up recipient
    const { rows: recipientRows } = await pool.query(
      'SELECT id FROM users WHERE username = $1',
      [recipient_username]
    )
    if (recipientRows.length === 0) {
      return reply.code(404).send({ error: 'NOT_FOUND', message: 'Recipient not found' })
    }
    const recipientId = recipientRows[0].id

    // get or create conversation
    let { rows: convRows } = await pool.query(
      `SELECT id FROM conversations
       WHERE (user_a_id = $1 AND user_b_id = $2)
          OR (user_a_id = $2 AND user_b_id = $1)`,
      [senderId, recipientId]
    )
    if (convRows.length === 0) {
      const [user_a_id, user_b_id] = senderId < recipientId
        ? [senderId, recipientId]
        : [recipientId, senderId]
      const inserted = await pool.query(
        `INSERT INTO conversations (user_a_id, user_b_id)
         VALUES ($1, $2) RETURNING id`,
        [user_a_id, user_b_id]
      )
      convRows = inserted.rows
    }
    const conversationId = convRows[0].id

    // insert message + queue digest in one transaction
    const client = await pool.connect()
    try {
      await client.query('BEGIN')

      const { rows: msgRows } = await client.query(
        `INSERT INTO messages
           (conversation_id, sender_id, recipient_id, ciphertext, encapsulated_key, sent_at_ms)
         VALUES ($1, $2, $3, $4, $5, $6)
         RETURNING id, sent_at, sent_at_ms`,
        [conversationId, senderId, recipientId, ciphertext, encapsulated_key, sent_at_ms]
      )
      const message = msgRows[0]

      // update conversation timestamp
      await client.query(
        `UPDATE conversations SET last_message_at = NOW() WHERE id = $1`,
        [conversationId]
      )

      // queue digest
      const digest = keccak256(Buffer.from(ciphertext, 'base64'))
      await client.query(
        `INSERT INTO digest_queue (message_id, digest) VALUES ($1, $2)`,
        [message.id, digest]
      )

      await client.query('COMMIT')
      return reply.code(201).send({ message_id: message.id, sent_at: message.sent_at, sent_at_ms: message.sent_at_ms })

    } catch (err) {
      await client.query('ROLLBACK')
      throw err
    } finally {
      client.release()
    }
  })

  // GET /api/messages
  app.get('/messages', {
    onRequest: [app.authenticate],
    schema: {
      querystring: {
        type: 'object',
        properties: {
          box:   { type: 'string', enum: ['inbox', 'outbox', 'all'] },
          limit: { type: 'integer', minimum: 1, maximum: 100 },
          since: { type: 'string', format: 'date-time' }
        },
        additionalProperties: false
      }
    }
  }, async (req, reply) => {
    const userId = req.user.user_id
    const box    = req.query.box   || 'all'
    const limit  = Math.min(req.query.limit || 50, 100)
    const since  = req.query.since || null

    let boxFilter
    if (box === 'inbox')  boxFilter = `m.recipient_id = $1`
    else if (box === 'outbox') boxFilter = `m.sender_id = $1`
    else boxFilter = `(m.sender_id = $1 OR m.recipient_id = $1)`

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
         m.is_forwarded,
         m.original_message_id
       FROM messages m
       JOIN users su ON su.id = m.sender_id
       JOIN users ru ON ru.id = m.recipient_id
       WHERE ${boxFilter}
         AND (m.sender_id    != $1 OR m.deleted_by_sender    = FALSE)
         AND (m.recipient_id != $1 OR m.deleted_by_recipient = FALSE)
         ${since ? 'AND m.sent_at > $3' : ''}
       ORDER BY m.sent_at DESC
       LIMIT $2`,
      since ? [userId, limit, since] : [userId, limit]
    )
    return reply.send({ messages: rows, total: rows.length })
  })

  // GET /api/messages/:id
  app.get('/messages/:id', {
    onRequest: [app.authenticate]
  }, async (req, reply) => {
    const userId = req.user.user_id
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
         m.original_message_id,
         m.deleted_by_sender,
         m.deleted_by_recipient
       FROM messages m
       JOIN users su ON su.id = m.sender_id
       JOIN users ru ON ru.id = m.recipient_id
       WHERE m.id = $1`,
      [req.params.id]
    )
    if (rows.length === 0) {
      return reply.code(404).send({ error: 'NOT_FOUND', message: 'Message not found' })
    }
    const msg = rows[0]
    if (msg.sender_id !== userId && msg.recipient_id !== userId) {
      return reply.code(403).send({ error: 'FORBIDDEN', message: 'Not your message' })
    }
    if ((msg.sender_id === userId && msg.deleted_by_sender) ||
        (msg.recipient_id === userId && msg.deleted_by_recipient)) {
      return reply.code(404).send({ error: 'NOT_FOUND', message: 'Message not found' })
    }
    const { deleted_by_sender, deleted_by_recipient, ...response } = msg
    return reply.send(response)
  })

  // DELETE /api/messages/:id
  app.delete('/messages/:id', {
    onRequest: [app.authenticate]
  }, async (req, reply) => {
    const userId = req.user.user_id
    const { rows } = await pool.query(
      'SELECT * FROM messages WHERE id = $1',
      [req.params.id]
    )
    if (rows.length === 0) {
      return reply.code(404).send({ error: 'NOT_FOUND', message: 'Message not found' })
    }
    const msg = rows[0]
    if (msg.sender_id === userId) {
      await pool.query(
        'UPDATE messages SET deleted_by_sender = TRUE WHERE id = $1',
        [req.params.id]
      )
    } else if (msg.recipient_id === userId) {
      await pool.query(
        'UPDATE messages SET deleted_by_recipient = TRUE WHERE id = $1',
        [req.params.id]
      )
    } else {
      return reply.code(403).send({ error: 'FORBIDDEN', message: 'Not your message' })
    }
    return reply.send({ deleted: true, message_id: req.params.id, deleted_at: new Date().toISOString() })
  })

  // POST /api/messages/:id/forward
  app.post('/messages/:id/forward', {
    onRequest: [app.authenticate],
    schema: {
      body: {
        type: 'object',
        required: ['forward_to_username', 'ciphertext', 'encapsulated_key', 'sent_at_ms'],
        properties: {
          forward_to_username: { type: 'string' },
          ciphertext:          { type: 'string' },
          encapsulated_key:    { type: 'string' },
          sent_at_ms:          { type: 'integer', minimum: 0 }
        },
        additionalProperties: false
      }
    }
  }, async (req, reply) => {
    const userId = req.user.user_id
    const { forward_to_username, ciphertext, encapsulated_key, sent_at_ms } = req.body

    // fetch original message
    const { rows: origRows } = await pool.query(
      'SELECT * FROM messages WHERE id = $1',
      [req.params.id]
    )
    if (origRows.length === 0) {
      return reply.code(404).send({ error: 'NOT_FOUND', message: 'Message not found' })
    }
    const original = origRows[0]
    if (original.sender_id !== userId && original.recipient_id !== userId) {
      return reply.code(403).send({ error: 'FORBIDDEN', message: 'Not your message' })
    }

    // look up forward target
    const { rows: targetRows } = await pool.query(
      'SELECT id FROM users WHERE username = $1',
      [forward_to_username]
    )
    if (targetRows.length === 0) {
      return reply.code(404).send({ error: 'NOT_FOUND', message: 'User not found' })
    }
    const targetId = targetRows[0].id

    // get or create conversation between forwarder and target
    let { rows: convRows } = await pool.query(
      `SELECT id FROM conversations
       WHERE (user_a_id = $1 AND user_b_id = $2)
          OR (user_a_id = $2 AND user_b_id = $1)`,
      [userId, targetId]
    )
    if (convRows.length === 0) {
      const [user_a_id, user_b_id] = userId < targetId
        ? [userId, targetId]
        : [targetId, userId]
      const inserted = await pool.query(
        `INSERT INTO conversations (user_a_id, user_b_id) VALUES ($1, $2) RETURNING id`,
        [user_a_id, user_b_id]
      )
      convRows = inserted.rows
    }
    const conversationId = convRows[0].id

    // insert forwarded message + digest in one transaction
    const client = await pool.connect()
    try {
      await client.query('BEGIN')

      const { rows: msgRows } = await client.query(
        `INSERT INTO messages
           (conversation_id, sender_id, recipient_id, ciphertext, encapsulated_key,
            sent_at_ms, is_forwarded, original_message_id)
         VALUES ($1, $2, $3, $4, $5, $6, TRUE, $7)
         RETURNING id, sent_at, sent_at_ms`,
        [conversationId, userId, targetId, ciphertext, encapsulated_key, sent_at_ms, req.params.id]
      )
      const forwarded = msgRows[0]

      await client.query(
        `UPDATE conversations SET last_message_at = NOW() WHERE id = $1`,
        [conversationId]
      )

      const digest = keccak256(Buffer.from(ciphertext, 'base64'))
      await client.query(
        `INSERT INTO digest_queue (message_id, digest) VALUES ($1, $2)`,
        [forwarded.id, digest]
      )

      await client.query('COMMIT')
      return reply.code(201).send({
        message_id:          forwarded.id,
        forwarded_at:        forwarded.sent_at,
        sent_at_ms:          forwarded.sent_at_ms,
        original_message_id: req.params.id
      })
    } catch (err) {
      await client.query('ROLLBACK')
      throw err
    } finally {
      client.release()
    }
  })

  // DELETE /api/messages/:id/revoke
  app.delete('/messages/:id/revoke', {
    onRequest: [app.authenticate]
  }, async (req, reply) => {
    const userId = req.user.user_id
    const { rows } = await pool.query(
      `SELECT m.*, om.sender_id AS original_sender_id
       FROM messages m
       LEFT JOIN messages om ON om.id = m.original_message_id
       WHERE m.id = $1`,
      [req.params.id]
    )
    if (rows.length === 0) {
      return reply.code(404).send({ error: 'NOT_FOUND', message: 'Message not found' })
    }
    const msg = rows[0]
    if (!msg.is_forwarded) {
      return reply.code(403).send({ error: 'FORBIDDEN', message: 'Only forwarded messages can be revoked' })
    }
    if (msg.original_sender_id !== userId) {
      return reply.code(403).send({ error: 'FORBIDDEN', message: 'Only original sender can revoke' })
    }
    await pool.query(
      `INSERT INTO revocations (message_id, revoked_by) VALUES ($1, $2)`,
      [req.params.id, userId]
    )
    return reply.send({ revoked: true, message_id: req.params.id, revoked_at: new Date().toISOString() })
  })
}
