import pg from 'pg'
import dotenv from 'dotenv'
dotenv.config()

const { Pool, types } = pg

// return BIGINT (oid 20) as a JS number — sent_at_ms fits well within Number.MAX_SAFE_INTEGER
types.setTypeParser(20, (v) => parseInt(v, 10))

const pool = new Pool({
  host:     process.env.DB_HOST,
  port:     process.env.DB_PORT,
  database: process.env.DB_NAME,
  user:     process.env.DB_USER,
  password: process.env.DB_PASSWORD,
})

pool.on('connect', () => {
  console.log('Connected to PostgreSQL')
})

pool.on('error', (err) => {
  console.error('PostgreSQL error:', err.message)
})

export default pool
