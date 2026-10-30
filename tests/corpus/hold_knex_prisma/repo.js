function byId(knex, id) {
  return knex.raw(`SELECT * FROM users WHERE id = ${id}`);
}

async function byName(prisma, name) {
  return prisma.$queryRawUnsafe(`SELECT * FROM users WHERE name = '${name}'`);
}

function safe(knex, id) {
  return knex.raw('SELECT * FROM users WHERE id = ?', [id]);
}
