import Fastify from 'fastify'
import helmet from '@fastify/helmet'
import cors from '@fastify/cors'
import jwt from '@fastify/jwt'
import rateLimit from '@fastify/rate-limit'
import dotenv from 'dotenv'
import fs from 'node:fs'
dotenv.config()

import authRoutes         from './routes/auth.js'
import keyRoutes          from './routes/keys.js'
import conversationRoutes from './routes/conversations.js'
import messageRoutes      from './routes/messages.js'
import blockchainRoutes   from './routes/blockchain.js'

import staticFiles from '@fastify/static'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

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

// CORS — locked to the project domain; override via CORS_ORIGIN for local dev
await app.register(cors, {
  origin: process.env.CORS_ORIGIN || 'https://eternal-blue.theburkenator.com',
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
})

// security headers
await app.register(helmet, {
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      // app.js is served from 'self'; it imports from esm.sh — no unsafe-inline needed
      scriptSrc:  ["'self'", "https://esm.sh", "https://cdn.esm.sh"],
      // no scriptSrcAttr — zero inline event handlers in the HTML
      connectSrc: ["'self'"],
      imgSrc:     ["'self'", "data:"],
      styleSrc:   ["'self'", "'unsafe-inline'"],
    }
  }
})

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

const __dirname = path.dirname(fileURLToPath(import.meta.url))
await app.register(staticFiles, {
  root: path.join(__dirname, '../frontend'),
  prefix: '/'
})

// routes
await app.register(authRoutes,         { prefix: '/api' })
await app.register(keyRoutes,          { prefix: '/api' })
await app.register(conversationRoutes, { prefix: '/api' })
await app.register(messageRoutes,      { prefix: '/api' })
await app.register(blockchainRoutes,   { prefix: '/api' })

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
