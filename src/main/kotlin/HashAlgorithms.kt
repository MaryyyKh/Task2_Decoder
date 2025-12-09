import at.favre.lib.crypto.bcrypt.BCrypt
import de.mkammerer.argon2.Argon2
import de.mkammerer.argon2.Argon2Factory
import java.math.BigInteger
import java.security.MessageDigest

/** Общий интерфейс для всех алгоритмов */
interface HashAlgorithm {
    val name: String
    fun matches(candidate: String, targetHash: String): Boolean
}

/** MD5 */
class Md5Algorithm : HashAlgorithm {
    override val name: String = "MD5"

    override fun matches(candidate: String, targetHash: String): Boolean {
        val md = MessageDigest.getInstance("MD5")
        val hash = BigInteger(1, md.digest(candidate.toByteArray()))
            .toString(16)
            .padStart(32, '0')
        return hash.equals(targetHash, ignoreCase = true)
    }
}

/** SHA-1 */
class Sha1Algorithm : HashAlgorithm {
    override val name: String = "SHA-1"

    override fun matches(candidate: String, targetHash: String): Boolean {
        val md = MessageDigest.getInstance("SHA-1")
        val hash = BigInteger(1, md.digest(candidate.toByteArray()))
            .toString(16)
            .padStart(40, '0')
        return hash.equals(targetHash, ignoreCase = true)
    }
}

/** bcrypt ($2a$…$…) */
class BcryptAlgorithm : HashAlgorithm {
    override val name: String = "bcrypt"

    override fun matches(candidate: String, targetHash: String): Boolean {
        return BCrypt.verifyer()
            .verify(candidate.toCharArray(), targetHash.toCharArray())
            .verified
    }
}

/** Argon2id — принимает полный строковый хэш $argon2id$... */
class Argon2idAlgorithm : HashAlgorithm {
    override val name: String = "Argon2id"

    // Один общий экземпляр, потокобезопасен
    private val argon2: Argon2 = Argon2Factory.create()

    override fun matches(candidate: String, targetHash: String): Boolean {
        return argon2.verify(targetHash, candidate.toByteArray())
    }
}
