fun main() {

    val charset = "abcdefghijklmnopqrstuvwxyz0123456789"
    val bruteForcer = HashBruteForcer(charset = charset)

    val md5 = Md5Algorithm()
    val sha1 = Sha1Algorithm()
    val bcrypt = BcryptAlgorithm()
    val argon2id = Argon2idAlgorithm()

    data class Test(
        val label: String,
        val algorithm: HashAlgorithm,
        val hash: String,
        val maxLength: Int
    )

    val tests = listOf(

        // ---------- SHA-1 ----------
        Test("SHA-1 лёгкий", sha1, "7c4a8d09ca3762af61e59520943dc26494f8941b", 6),
        Test("SHA-1 средний", sha1, "d0be2dc421be4fcd0172e5afceea3970e2f3d940", 8),
        Test("SHA-1 сложный", sha1, "666846867fc5e0a46a7afc53eb8060967862f333", 8),
//        Test("SHA-1 очень сложный", sha1, "6e157c5da4410b7e9de85f5c93026b9176e69064", 10),

        // ---------- MD5 ----------
        Test("MD5 лёгкий", md5, "e10adc3949ba59abbe56e057f20f883e", 6),
        Test("MD5 средний", md5, "1f3870be274f6c49b3e31a0c6728957f", 8),
        Test("MD5 сложный", md5, "77892341aa9dc66e97f5c248782b5d92", 8),
//        Test("MD5 очень сложный", md5, "686e697538050e4664636337cc3b834f", 10),

        // ---------- bcrypt (cost=10) ----------
        Test("bcrypt лёгкий", bcrypt, "\$2a\$10\$YQak9uaePYz6Hap5Rz8D3OOwd/HKH7bFRxg6dzSmmu04qlcJSwSei", 4),
        Test("bcrypt средний", bcrypt, "\$2a\$10\$9YKVe37kUMmlq69W81aB5OkQF.GtDQP8UZ/OlEr6QBi9Kopwxb17y", 5),
        Test("bcrypt сложный", bcrypt, "\$2a\$10\$.EUZO097Xcfx.LutPjCbj.V2FZzmP3ao9dcYGDs682cZ/cNFEiOi6", 5),
//        Test("bcrypt очень сложный", bcrypt, "\$2a\$10\$yZBadi8Szw0nItV2g96P6eqctI2kbG/.mb0uD/ID9tlof0zpJLLL2", 6),

        // ---------- Argon2id (salt="saltsalt") ----------
        Test(
            "Argon2 лёгкий",
            argon2id,
            "\$argon2id\$v=19\$m=65536,t=3,p=2\$c2FsdHNhbHQ\$a6TuQSkbk9NwDTPa4v7Gq6zYphIw+UedX0vFHNIJqKY",
            4
        ),
        Test(
            "Argon2 средний",
            argon2id,
            "\$argon2id\$v=19\$m=65536,t=3,p=2\$c2FsdHNhbHQ\$O2tAeujYtzyK+Hot59S2rRmvPF4hrXjFZEZDyYKMBtM",
            4
        ),
        Test(
            "Argon2 сложный",
            argon2id,
            "\$argon2id\$v=19\$m=65536,t=3,p=2\$c2FsdHNhbHQ\$0EX5WjG9WZNmUJh6g7FNl4zhYOyyDCtkDLM6I0tqjP4",
            4
        ),
//        Test(
//            "Argon2 очень сложный",
//            argon2id,
//            "\$argon2id\$v=19\$m=65536,t=3,p=2\$c2FsdHNhbHQ\$+smq45/czydGj0lYNdZVXF++FOXJwrkXt6VUIcEauvo",
//            4
//        )
    )

    val results = mutableListOf<BruteForceResult>()

    for (test in tests) {
        val res = bruteForcer.bruteForce(
            hashLabel = test.label,
            targetHash = test.hash,
            algorithm = test.algorithm,
            maxLength = test.maxLength
        )
        results.add(res)
    }

    println("\n================= СВОДНАЯ ТАБЛИЦА =================")
    println("Алгоритм | Хэш | Найден | Пароль | Время, сек | Макс. длина")
    for (r in results) {
        println(
            "%-8s | %-18s | %-6s | %-10s | %-9.3f | %d".format(
                r.algorithmName,
                r.hashLabel,
                if (r.foundPassword != null) "да" else "нет",
                r.foundPassword ?: "-",
                r.timeMs / 1000.0,
                r.maxLength
            )
        )
    }
}
