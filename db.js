import { Pool } from "pg";

export const SessionPool = new Pool({
  connectionString: process.env.DB_URL,
  ssl: { rejectUnauthorized: false }
});
