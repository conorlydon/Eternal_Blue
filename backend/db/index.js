/*
* PostgreSQL connection pool for the Eternal-Blue backend.
* Creates a single shared pool that all route handlers import and query against.
* Using a pool (rather than one persistent connection) lets Fastify handle
* concurrent requests safely. Each query borrows a connection, uses it, and
* returns it automatically.
*/
import pg from 'pg'
import dotenv from 'dotenv'
dotenv.config() // Load DB credentials from .env into process.env

const { Pool, types } = pg

// return BIGINT (oid 20) as a JS number - sent_at_ms fits well within Number.MAX_SAFE_INTEGER
types.setTypeParser(20, (v) => parseInt(v, 10))

// Initialise the pool using credentials from environment variables.
const pool = new Pool({
  host:     process.env.DB_HOST,
  port:     process.env.DB_PORT,
  database: process.env.DB_NAME,
  user:     process.env.DB_USER,
  password: process.env.DB_PASSWORD,
})

// Log a confirmation each time a new physical connection is established.
pool.on('connect', () => {
  console.log('Connected to PostgreSQL')
})

// Surface unexpected connection/query errors so they don't fail silently.
// Without this handler, idle connection errors would crash the process.
pool.on('error', (err) => {
  console.error('PostgreSQL error:', err.message)
})

export default pool
