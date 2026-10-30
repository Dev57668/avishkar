// Never use eval(code) or el.innerHTML = x; do not set rejectUnauthorized: false.
/* child_process.exec(`rm -rf ${dir}`) is dangerous */
const doc = `Example: db.query("SELECT * FROM t WHERE id=" + id) is vulnerable`;
const msg = 'document.write(userInput) is a classic XSS sink';
const ok = 1 / 2 / 3;
module.exports = { doc, msg, ok };
