import Fastify from 'fastify'
import helmet from '@fastify/helmet'
import jwt from '@fastify/jwt'
import rateLimit from '@fastify/rate-limit'
import dotenv from 'dotenv'
import fs from 'node:fs'
dotenv.config()

import authRoutes         from './routes/auth.js'
import keyRoutes          from './routes/keys.js'
import conversationRoutes from './routes/conversations.js'
import messageRoutes      from './routes/messages.js'

// Local dev terminates TLS in Fastify itself (self-signed cert).
// The VM terminates TLS in nginx and proxies plain HTTP to here — in that
// deployment, TLS_CERT/TLS_KEY are unset and Fastify falls back to plain HTTP.
const useTls = process.env.TLS_CERT && process.env.TLS_KEY
const app = Fastify({
  logger: true,
  ...(useTls && {
    https: {
      key:  fs.readFileSync(process.env.TLS_KEY),
      cert: fs.readFileSync(process.env.TLS_CERT),
    }
  })
})

// security headers
await app.register(helmet)

// rate limiting
await app.register(rateLimit, {
  max: 100,
  timeWindow: '1 minute'
})

// jwt
await app.register(jwt, {
  secret: process.env.JWT_SECRET
})

// auth decorator — add to any route with onRequest: [app.authenticate]
app.decorate('authenticate', async (req, reply) => {
  try {
    await req.jwtVerify()
  } catch (err) {
    return reply.code(401).send({ error: 'UNAUTHORIZED', message: 'Invalid or expired token' })
  }
})

// routes
await app.register(authRoutes,         { prefix: '/api' })
await app.register(keyRoutes,          { prefix: '/api' })
await app.register(conversationRoutes, { prefix: '/api' })
await app.register(messageRoutes,      { prefix: '/api' })

// health check
app.get('/health', async () => ({
  status: 'ok',
  team: 'eternal-blue',
  timestamp: new Date().toISOString()
}))

// start
const port = parseInt(process.env.PORT) || 3000
await app.listen({ port, host: '0.0.0.0' })
console.log(`Server running on port ${port}`)
