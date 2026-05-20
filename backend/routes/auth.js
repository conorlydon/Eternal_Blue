import argon2 from 'argon2'
import pool from '../db/index.js'

export default async function authRoutes(app) {

  // POST /api/auth/register
  app.post('/auth/register', {
    schema: {
      body: {
        type: 'object',
        required: ['username', 'password', 'public_key'],
        properties: {
          username:   { type: 'string', minLength: 3, maxLength: 32, pattern: '^[a-zA-Z0-9_]+$' },
          password:   { type: 'string', minLength: 12, maxLength: 128 },
          public_key: { type: 'string', minLength: 43, maxLength: 44 }
        },
        additionalProperties: false
      }
    }
  }, async (req, reply) => {
    const { username, password, public_key } = req.body
    try {
      const hash = await argon2.hash(password, {
        type: argon2.argon2id,
        memoryCost: 65536,
        timeCost: 3,
        parallelism: 1
      })
      const { rows } = await pool.query(
        `INSERT INTO users (username, password_hash, public_key)
         VALUES ($1, $2, $3)
         RETURNING id, username`,
        [username, hash, public_key]
      )
      return reply.code(201).send({ user_id: rows[0].id, username: rows[0].username })
    } catch (err) {
      if (err.code === '23505') {
        return reply.code(409).send({ error: 'CONFLICT', message: 'Username already taken' })
      }
      throw err
    }
  })

  // POST /api/auth/login
  app.post('/auth/login', {
    config: {
      rateLimit: { max: 10, timeWindow: '1 minute' }
    },
    schema: {
      body: {
        type: 'object',
        required: ['username', 'password'],
        properties: {
          username: { type: 'string' },
          password: { type: 'string' }
        },
        additionalProperties: false
      }
    }
  }, async (req, reply) => {
    const { username, password } = req.body
    const { rows } = await pool.query(
      'SELECT * FROM users WHERE username = $1',
      [username]
    )
    if (rows.length === 0) {
      return reply.code(401).send({ error: 'UNAUTHORIZED', message: 'Invalid credentials' })
    }
    const user = rows[0]
    const valid = await argon2.verify(user.password_hash, password)
    if (!valid) {
      return reply.code(401).send({ error: 'UNAUTHORIZED', message: 'Invalid credentials' })
    }
    const token = app.jwt.sign(
      { user_id: user.id, username: user.username },
      { expiresIn: '24h' }
    )
    return reply.send({
      token,
      expires_at: new Date(Date.now() + 86400000).toISOString(),
      user_id: user.id
    })
  })

  // PATCH /api/auth/password
  app.patch('/auth/password', {
    onRequest: [app.authenticate],
    config: {
      rateLimit: { max: 5, timeWindow: '1 minute' }
    },
    schema: {
      body: {
        type: 'object',
        required: ['current_password', 'new_password'],
        properties: {
          current_password: { type: 'string', minLength: 1,  maxLength: 128 },
          new_password:     { type: 'string', minLength: 12, maxLength: 128 }
        },
        additionalProperties: false
      }
    }
  }, async (req, reply) => {
    const { current_password, new_password } = req.body
    const { rows } = await pool.query(
      'SELECT id, password_hash FROM users WHERE id = $1',
      [req.user.user_id]
    )
    const user = rows[0]
    const valid = await argon2.verify(user.password_hash, current_password)
    if (!valid) {
      return reply.code(401).send({ error: 'UNAUTHORIZED', message: 'Current password is incorrect' })
    }
    if (current_password === new_password) {
      return reply.code(400).send({ error: 'INVALID_INPUT', message: 'New password must differ from current password' })
    }
    const newHash = await argon2.hash(new_password, {
      type: argon2.argon2id,
      memoryCost: 65536,
      timeCost: 3,
      parallelism: 1
    })
    await pool.query(
      'UPDATE users SET password_hash = $1 WHERE id = $2',
      [newHash, user.id]
    )
    return reply.send({ updated: true, updated_at: new Date().toISOString() })
  })
}
