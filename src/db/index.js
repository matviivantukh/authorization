import pg from "pg";

const pool = new pg.Pool({
  user: process.env.DATABASE_USER,
  host: process.env.DATABASE_HOST,
  database: process.env.DATABASE_NAME,
  password: process.env.DATABASE_PASSWORD,
  port: process.env.DATABASE_PORT,
});

export const query = (query, params) => {
  return pool.query(query, params);
};

export const createTransaction = async () => {
  const client = await pool.connect();
  await client.query("BEGIN");
  return {
    commit: async () => {
      await client.query("COMMIT");
      client.release();
    },
    rollback: async () => {
      await client.query("ROLLBACK");
      client.release();
    },
    query: (query, params) => client.query(query, params),
  };
};
