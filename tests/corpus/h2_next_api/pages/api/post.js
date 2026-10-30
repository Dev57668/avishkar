export default async function handler(req, res) {
  const { id } = req.query;
  const rows = await pool.query(`SELECT * FROM posts WHERE id = ${id}`);
  res.status(200).json(rows);
}
