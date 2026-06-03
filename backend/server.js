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
// The VM terminates TLS in nginx and proxies plain HTTP to here - in that
// deployment, TLS_CERT/TLS_KEY are unset and Fastify falls back to plain HTTP.
const useTls = process.env.TLS_CERT && process.env.TLS_KEY
const app = Fastify({
  logger: true,
  // Behind nginx, the socket peer is always the proxy. Trust X-Forwarded-For so
  // req.ip reflects the real client (needed for IP-keyed limits on login/register,
  // which have no token to key on). See nginx note below - the proxy must set XFF.
  trustProxy: true,
  ...(useTls && {
    https: {
      key:  fs.readFileSync(process.env.TLS_KEY),
      cert: fs.readFileSync(process.env.TLS_CERT),
    }
  })
})

// CORS - locked to the project domain; override via CORS_ORIGIN for local dev
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
      // app.js and the HPKE library are served from 'self' (/vendor). The only inline
      // script is the import map, allowed by its sha256 hash - no 'unsafe-inline'.
      // If the import map text in index.html changes, recompute this hash.
      scriptSrc:  ["'self'", "'sha256-TMKMuhwQvSPejQxV+RsbyUBVIAdRnbuGy23zdMdJMXs='"],
      // no scriptSrcAttr - zero inline event handlers in the HTML
      connectSrc: ["'self'"],
      imgSrc:     ["'self'", "data:"],
      styleSrc:   ["'self'", "'unsafe-inline'"],
    }
  },
  frameguard: { action: 'deny' },
  noSniff: true,
})

// jwt - registered before the rate limiter so its keyGenerator can verify tokens
await app.register(jwt, {
  secret: process.env.JWT_SECRET
})

// rate limiting - key by the authenticated user when a valid bearer token is
// present, otherwise fall back to client IP. This is what makes limiting work
// behind nginx: authenticated traffic is bucketed per user (the proxy's shared
// IP no longer collapses everyone into one bucket), while unauthenticated routes
// (login/register) stay IP-keyed via trustProxy + X-Forwarded-For.

// The limiter's onRequest hook runs before route-level app.authenticate, so
// req.user isn't set yet here - we verify the token ourselves. A bad/expired
// token falls through to IP so it can't be used to dodge the limit.
await app.register(rateLimit, {
  max: 100,
  timeWindow: '1 minute',
  keyGenerator: (req) => {
    const auth = req.headers.authorization
    if (auth && auth.startsWith('Bearer ')) {
      try {
        const { user_id } = app.jwt.verify(auth.slice(7))
        return `user:${user_id}`
      } catch {
        // invalid/expired - fall through to IP
      }
    }
    return req.ip
  }
})

// auth decorator - add to any route with onRequest: [app.authenticate]
app.decorate('authenticate', async (req, reply) => {
  try {
    await req.jwtVerify()
  } catch (err) {
    return reply.code(401).send({ error: 'UNAUTHORIZED', message: 'Invalid or expired token' })
  }
})

// ES modules lack __dirname — reconstruct it from import.meta.url, then serve
// the frontend folder as static files at the root path.
const __dirname = path.dirname(fileURLToPath(import.meta.url))
await app.register(staticFiles, {
  root: path.join(__dirname, '../frontend'),
  prefix: '/'
})

// Serve the npm-installed HPKE library ESM files for the browser import map
// (frontend/app/index.html). decorateReply:false because @fastify/static is
// already registered above and the reply decorator can only be added once.
await app.register(staticFiles, {
  root: path.join(__dirname, 'node_modules/@hpke'),
  prefix: '/vendor/@hpke/',
  decorateReply: false,
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
