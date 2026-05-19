import argon2 from 'argon2'
import { randomUUID } from 'crypto'
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
      return reply.code(201).send(rows[0])
    } catch (err) {
      if (err.code === '23505') {
        return reply.code(409).send({ error: 'CONFLICT', message: 'Username already taken' })
      }
      throw err
    }
  })

  // POST /api/auth/login
  app.post('/auth/login', {
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
      return reply.code(404).send({ error: 'NOT_FOUND', message: 'User not found' })
    }
    const user = rows[0]
    const valid = await argon2.verify(user.password_hash, password)
    if (!valid) {
      return reply.code(401).send({ error: 'UNAUTHORIZED', message: 'Invalid password' })
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
}
