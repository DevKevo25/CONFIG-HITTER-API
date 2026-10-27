import java.io.File
import java.nio.charset.StandardCharsets
import java.util.zip.Inflater
import javax.crypto.Cipher
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

val MAGIC = byteArrayOf(0xA7.toByte(), 0x19, 0xD2.toByte(), 0x4C)

// CONFIRMED from logcat:
val KDF_INPUT = "REESE-CUSTOM/RSE5|||SIG:D834BF8D60BFEA09A80A51CCD1A77DE3EF966E7833EBB2D0B8DC1F750E38BBA7"
val ITER = 32768

fun pbkdf2(password: ByteArray, salt: ByteArray, iter: Int, keyLen: Int): ByteArray {
    val spec = PBEKeySpec(String(password, StandardCharsets.UTF_8).toCharArray(),
                          salt, iter, keyLen * 8)
    return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).encoded
}

fun aesGcmDecrypt(key: ByteArray, iv: ByteArray, aad: ByteArray, ctAndTag: ByteArray): ByteArray {
    val c = Cipher.getInstance("AES/GCM/NoPadding")
    c.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, iv))
    c.updateAAD(aad)
    return c.doFinal(ctAndTag)
}

fun inflate(data: ByteArray): ByteArray {
    val inf = Inflater(true)
    inf.setInput(data)
    val out = java.io.ByteArrayOutputStream()
    val buf = ByteArray(4096)
    try {
        while (!inf.finished()) {
            val n = inf.inflate(buf)
            if (n <= 0) break
            out.write(buf, 0, n)
        }
    } catch (_: Exception) {}
    inf.end()
    return out.toByteArray()
}

fun decodeRt(path: String) {
    val bytes = File(path).readBytes()
    for (i in MAGIC.indices) require(bytes[i] == MAGIC[i]) { "not RT file" }
    println("[*] file: $path  size=${bytes.size}")

    // CONFIRMED: salt = file[6..22]
    val salt = bytes.copyOfRange(6, 22)
    println("[*] salt = ${salt.toHex()}")

    // Derive key with the EXACT string from logcat
    val key = pbkdf2(KDF_INPUT.toByteArray(StandardCharsets.UTF_8), salt, ITER, 32)
    println("[*] key  = ${key.toHex()}")

    // Try IV / AAD / CT candidates
    // IV likely [22..34] (12 bytes)
    // AAD likely [0..N] for N in {32, 34, 40, 44}
    // CT likely [N..end] for matching N
    val ivCandidates = linkedMapOf(
        "iv[22..34]" to bytes.copyOfRange(22, 34),
        "iv[20..32]" to bytes.copyOfRange(20, 32),
        "iv[6..18]"  to bytes.copyOfRange(6, 18),   // in case salt overlaps
    )
    val ctStartCandidates = listOf(32, 34, 40, 44)

    var success = false
    outer@ for ((ivName, iv) in ivCandidates) {
        for (ctStart in ctStartCandidates) {
            val aad = bytes.copyOfRange(0, ctStart)
            val ctAndTag = bytes.copyOfRange(ctStart, bytes.size)
            val plain = try {
                aesGcmDecrypt(key, iv, aad, ctAndTag)
            } catch (_: Exception) { null } ?: continue

            println("\n[✓] GCM SUCCESS")
            println("    iv:      $ivName")
            println("    ctStart: $ctStart (aad = file[0..$ctStart], ${aad.size} bytes)")
            println("    ct+tag:  ${ctAndTag.size} bytes")
            println("    plain:   ${plain.size} bytes")
            println("    plain[0..16]: ${plain.copyOfRange(0, minOf(16, plain.size)).toHex()}")

            // Try to extract JSON at multiple offsets (E() strip + inflate)
            extractJson(plain, path)
            success = true
            break@outer
        }
    }

    if (!success) {
        println("\n[!] no combination worked")
        println("[*] key    = ${key.toHex()}")
        println("[*] salt   = ${salt.toHex()}")
        println("[*] try changing IV/AAD offsets in the code")
    }
}

fun applyF(plain: ByteArray): ByteArray {
    if (plain.isEmpty()) throw IllegalArgumentException("empty")
    val n = plain[0].toInt() and 0xFF
    val lengthOff = n + 17
    if (lengthOff + 4 > plain.size) throw IllegalArgumentException("length field beyond end (n=$n)")
    val len = ((plain[lengthOff].toInt() and 0xFF) shl 24) or
              ((plain[lengthOff + 1].toInt() and 0xFF) shl 16) or
              ((plain[lengthOff + 2].toInt() and 0xFF) shl 8) or
              (plain[lengthOff + 3].toInt() and 0xFF)
    val payloadOff = n + 21
    if (len < 0) throw IllegalArgumentException("negative length")
    if (payloadOff + len > plain.size) throw IllegalArgumentException("truncated (n=$n len=$len off=$payloadOff size=${plain.size})")
    return plain.copyOfRange(payloadOff, payloadOff + len)
}

fun extractJson(plain: ByteArray, path: String) {
    println("[*] plain[0..64]: ${plain.copyOfRange(0, minOf(64, plain.size)).toHex()}")

    val fOut = try { applyF(plain) } catch (e: Exception) {
        println("[!] F() failed: ${e.message}")
        ByteArray(0)
    }
    if (fOut.isNotEmpty()) {
        println("[*] after F(): ${fOut.size} bytes, first 16 = ${fOut.copyOfRange(0, minOf(16, fOut.size)).toHex()}")

        val inf = try { inflate(fOut) } catch (_: Exception) { ByteArray(0) }
        if (inf.size > 20) {
            val txt = String(inf, StandardCharsets.UTF_8)
            if (txt.startsWith("{") || txt.contains("\"config\"")) {
                println("\n[✓✓✓] JSON via F()+inflate!")
                File(path + ".json").writeText(txt)
                println(txt.take(3000))
                return
            }
        }
    }

    // Also try raw inflate
    val rawInf = try { inflate(plain) } catch (_: Exception) { ByteArray(0) }
    if (rawInf.size > 20) {
        val txt = String(rawInf, StandardCharsets.UTF_8)
        if (txt.startsWith("{") || txt.contains("\"config\"")) {
            println("\n[✓✓✓] JSON via raw inflate!")
            File(path + ".json").writeText(txt)
            println(txt.take(3000))
            return
        }
    }

    // Also try strip-a-few-bytes + inflate
    for (skip in listOf(1, 4, 16, 32)) {
        if (skip >= plain.size) continue
        val slice = plain.copyOfRange(skip, plain.size)
        val inf = try { inflate(slice) } catch (_: Exception) { ByteArray(0) }
        if (inf.size > 20) {
            val txt = String(inf, StandardCharsets.UTF_8)
            if (txt.startsWith("{")) {
                println("\n[✓✓✓] JSON via skip=$skip+inflate!")
                File(path + ".json").writeText(txt)
                println(txt.take(3000))
                return
            }
        }
    }

    println("\n[!] no JSON found")
    File(path + ".plain").writeBytes(plain)
    println("[*] dumped to ${path}.plain")
}

fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }

fun main(args: Array<String>) {
    if (args.isEmpty()) { println("Usage: rt-decode <file.rt>"); return }
    try { decodeRt(args[0]) } catch (e: Throwable) { println("[!] ${e.message}"); e.printStackTrace() }
}