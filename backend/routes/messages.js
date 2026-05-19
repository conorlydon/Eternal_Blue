import pool from '../db/index.js'
import { keccak256, toUtf8Bytes } from 'ethers'

export default async function messageRoutes(app) {

  // POST /api/messages
  app.post('/messages', {
    onRequest: [app.authenticate],
    schema: {
      body: {
        type: 'object',
        required: ['recipient_username', 'ciphertext', 'encapsulated_key', 'nonce'],
        properties: {
          recipient_username: { type: 'string' },
          ciphertext:         { type: 'string' },
          encapsulated_key:   { type: 'string' },
          nonce:              { type: 'string' }
        },
        additionalProperties: false
      }
    }
  }, async (req, reply) => {
    const senderId = req.user.user_id
    const { recipient_username, ciphertext, encapsulated_key, nonce } = req.body

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
      const inserted = await pool.query(
        `INSERT INTO conversations (user_a_id, user_b_id)
         VALUES ($1, $2) RETURNING id`,
        [senderId, recipientId]
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
           (conversation_id, sender_id, recipient_id, ciphertext, encapsulated_key, nonce)
         VALUES ($1, $2, $3, $4, $5, $6)
         RETURNING id, sent_at`,
        [conversationId, senderId, recipientId, ciphertext, encapsulated_key, nonce]
      )
      const message = msgRows[0]

      // update conversation timestamp
      await client.query(
        `UPDATE conversations SET last_message_at = NOW() WHERE id = $1`,
        [conversationId]
      )

      // queue digest
      const digest = keccak256(toUtf8Bytes(ciphertext))
      await client.query(
        `INSERT INTO digest_queue (message_id, digest) VALUES ($1, $2)`,
        [message.id, digest]
      )

      await client.query('COMMIT')
      return reply.code(201).send({ message_id: message.id, sent_at: message.sent_at })

    } catch (err) {
      await client.query('ROLLBACK')
      throw err
    } finally {
      client.release()
    }
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

  // POST /api/messages/:id/forward — stub for Person A to integrate
  app.post('/messages/:id/forward', {
    onRequest: [app.authenticate]
  }, async (req, reply) => {
    return reply.code(501).send({ error: 'NOT_IMPLEMENTED', message: 'Coming soon' })
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
