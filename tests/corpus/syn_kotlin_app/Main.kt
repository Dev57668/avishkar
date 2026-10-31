// A small notes service in Kotlin. Intentionally insecure, for education.
package notes

import java.io.ObjectInputStream
import java.security.MessageDigest
import java.sql.DriverManager
import java.util.Random

const val ADMIN_PASSWORD = "kotlin-admin-pass-9b27e4c1"

fun search(term: String): Boolean {
    val conn = DriverManager.getConnection("jdbc:h2:mem:notes")
    val stmt = conn.createStatement()
    val rs = stmt.executeQuery("SELECT * FROM notes WHERE title LIKE '%$term%'")
    return rs.next()
}

fun listDir(dir: String): Int {
    return Runtime.getRuntime().exec("ls $dir").waitFor()
}

fun hashPassword(password: String): ByteArray {
    val md = MessageDigest.getInstance("MD5")
    return md.digest(password.toByteArray())
}

fun newSessionToken(): Long {
    return Random().nextLong()
}

fun restore(input: java.io.InputStream): Any {
    val ois = ObjectInputStream(input)
    return ois.readObject()
}
