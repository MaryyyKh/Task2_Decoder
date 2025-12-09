import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference
import kotlin.math.pow
import kotlin.system.measureTimeMillis

data class BruteForceResult(
    val algorithmName: String,
    val hashLabel: String,
    val targetHash: String,
    val foundPassword: String?,
    val maxLength: Int,
    val charset: String,
    val timeMs: Long,
    val triedCombinations: Long
)

class HashBruteForcer(
    private val charset: String = "abcdefghijklmnopqrstuvwxyz0123456789",
    private val threads: Int = Runtime.getRuntime().availableProcessors().coerceAtLeast(1)
) {

    fun bruteForce(
        hashLabel: String,
        targetHash: String,
        algorithm: HashAlgorithm,
        maxLength: Int
    ): BruteForceResult {

        println("\n==== Тест: $hashLabel | Алгоритм: ${algorithm.name} ====")
        println("Хэш: $targetHash")
        println("Алфавит: '$charset' (size=${charset.length}), потоков=$threads")

        var found: String? = null
        var tried = 0L

        val totalTime = measureTimeMillis {
            for (length in 1..maxLength) {
                val combosForLen = charset.length.toDouble().pow(length).toLong()
                println("\nДлина пароля = $length, комбинаций = $combosForLen")

                val resultForLen = bruteForceLength(length, targetHash, algorithm, combosForLen)
                tried += combosForLen

                if (resultForLen != null) {
                    found = resultForLen
                    println(">>> Пароль найден на длине $length: '$found'")
                    break
                } else {
                    println("Пароль длины $length не найден")
                }
            }
        }

        println("Время поиска: ${totalTime / 1000.0} сек.")
        if (found == null) println("Итог: пароль не найден (maxLength = $maxLength)")

        return BruteForceResult(
            algorithmName = algorithm.name,
            hashLabel = hashLabel,
            targetHash = targetHash,
            foundPassword = found,
            maxLength = maxLength,
            charset = charset,
            timeMs = totalTime,
            triedCombinations = tried
        )
    }

    private fun bruteForceLength(
        length: Int,
        targetHash: String,
        algorithm: HashAlgorithm,
        totalCombinations: Long
    ): String? {

        val foundPassword = AtomicReference<String?>(null)
        val stop = AtomicBoolean(false)

        val executor = Executors.newFixedThreadPool(threads)
        val chunkSize = (totalCombinations + threads - 1) / threads  // делим диапазон

        for (threadId in 0 until threads) {
            val start = threadId * chunkSize
            val end = minOf(totalCombinations, (threadId + 1L) * chunkSize)

            if (start >= totalCombinations) break

            executor.execute {
                var i = start
                while (i < end && !stop.get()) {
                    val candidate = numberToPassword(i, length)
                    if (algorithm.matches(candidate, targetHash)) {
                        if (stop.compareAndSet(false, true)) {
                            foundPassword.set(candidate)
                            println("Поток $threadId нашёл пароль: '$candidate' (i=$i)")
                        }
                        break
                    }
                    i++
                }
            }
        }

        executor.shutdown()
        executor.awaitTermination(7, TimeUnit.DAYS)

        return foundPassword.get()
    }

    private fun numberToPassword(index: Long, length: Int): String {
        val base = charset.length
        var n = index
        val chars = CharArray(length)

        for (pos in length - 1 downTo 0) {
            val digit = (n % base).toInt()
            chars[pos] = charset[digit]
            n /= base
        }
        return String(chars)
    }
}
