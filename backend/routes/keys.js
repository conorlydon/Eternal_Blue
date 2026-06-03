import pool from '../db/index.js'

export default async function keyRoutes(app) {

  // Public key lookup — any authenticated user can fetch another user's
  // public key to encrypt a message to them (TOFU trust model).
  // GET /api/keys/:username
  app.get('/keys/:username', {
    onRequest: [app.authenticate]
  }, async (req, reply) => {
    const { rows } = await pool.query(
      `SELECT id, username, public_key, key_version, created_at
       FROM users WHERE username = $1`,
      [req.params.username]
    )
    if (rows.length === 0) {
      return reply.code(404).send({ error: 'NOT_FOUND', message: 'User not found' })
    }
    const u = rows[0]
    return reply.send({
      username:     u.username,
      user_id:      u.id,
      public_key:   u.public_key,
      key_version:  u.key_version,
      published_at: u.created_at
    })
  })

  // PUT /api/keys/update
  app.put('/keys/update', {
    onRequest: [app.authenticate],
    schema: {
      body: {
        type: 'object',
        required: ['public_key'],
        properties: {
          public_key: { type: 'string', minLength: 43, maxLength: 44 }
        },
        additionalProperties: false
      }
    }
    // Incrementing key_version lets clients detect if a peer's key has changed
    // since they last fetched it which is important for TOFU key pinning.
  }, async (req, reply) => {
    const { rows } = await pool.query(
      `UPDATE users
       SET public_key = $1, key_version = key_version + 1
       WHERE id = $2
       RETURNING key_version`,
      [req.body.public_key, req.user.user_id]
    )
    return reply.send({
      key_version: rows[0].key_version,
      updated_at:  new Date().toISOString()
    })
  })
}
