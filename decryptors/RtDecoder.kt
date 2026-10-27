import java.io.File
import java.nio.charset.StandardCharsets
import java.util.zip.Inflater
import javax.crypto.Cipher
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

// ============================================================================
// REESE TUNNEL .RT file decoder — RSE5 format
//
// File layout:
//   [0..4]    magic         a7 19 d2 4c
//   [4]       version       0xc4 (RSE5)
//   [5]       flags         bit0=lockAll, bit1=hwidLocked, bit2=sigBound
//   [6..22]   salt          16 bytes
//   [22..34]  iv            12 bytes
//   [34..end] ciphertext + 16-byte GCM tag
//
// KDF (from logcat):
//   PBKDF2-HMAC-SHA256(
//     "REESE-CUSTOM/RSE5|||SIG:<signer>",
//     salt, iter=32768, keyLen=32
//   )
//
// AAD = file[0..34] (magic + version + flags + salt + iv)
// Cipher = AES-256-GCM
//
// After decrypt:
//   plain[0]     = N (pad length 0..255)
//   plain[N+17]  = 4-byte BE payload length
//   plain[N+21..N+21+len] = deflated JSON payload
//   inflate(payload) → Envelope { meta, config }
// ============================================================================

val MAGIC = byteArrayOf(0xA7.toByte(), 0x19, 0xD2.toByte(), 0x4C)
const val SIG_PREFIX = "REESE-CUSTOM/RSE5|||SIG:"
const val ITER = 32768
const val KEY_LEN = 32

fun pbkdf2(password: ByteArray, salt: ByteArray, iter: Int, keyLen: Int): ByteArray {
    val spec = PBEKeySpec(String(password, StandardCharsets.UTF_8).toCharArray(),
                          salt, iter, keyLen * 8)
    return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
        .generateSecret(spec).encoded
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

// F() — extract the deflated payload from the padded plaintext
fun applyF(plain: ByteArray): ByteArray {
    require(plain.isNotEmpty()) { "empty plaintext" }
    val n = plain[0].toInt() and 0xFF
    val lengthOff = n + 17
    val payloadOff = n + 21
    require(lengthOff + 4 <= plain.size) { "length field OOB" }
    val len = ((plain[lengthOff].toInt() and 0xFF) shl 24) or
              ((plain[lengthOff + 1].toInt() and 0xFF) shl 16) or
              ((plain[lengthOff + 2].toInt() and 0xFF) shl 8) or
              (plain[lengthOff + 3].toInt() and 0xFF)
    require(len >= 0) { "negative payload length" }
    require(payloadOff + len <= plain.size) { "payload OOB (len=$len off=$payloadOff size=${plain.size})" }
    return plain.copyOfRange(payloadOff, payloadOff + len)
}

fun decodeRt(path: String): String {
    val bytes = File(path).readBytes()
    require(bytes.size >= 50) { "file too small: ${bytes.size}" }
    for (i in MAGIC.indices) require(bytes[i] == MAGIC[i]) { "not an RT file (magic mismatch)" }

    val version = bytes[4].toInt() and 0xFF
    val flags   = bytes[5].toInt() and 0xFF
    require(version == 0xC4) { "expected RSE5 (0xc4), got 0x%02x".format(version) }

    println("=== $path ===")
    println("size     : ${bytes.size} bytes")
    println("version  : 0x%02x (RSE5)".format(version))
    println("flags    : 0x%02x  lockAll=${(flags and 0x01) != 0} hwidLocked=${(flags and 0x02) != 0} sigBound=${(flags and 0x04) != 0}")

    val salt = bytes.copyOfRange(6, 22)
    val iv   = bytes.copyOfRange(22, 34)
    val aad  = bytes.copyOfRange(0, 34)
    val ct   = bytes.copyOfRange(34, bytes.size - 16)
    val tag  = bytes.copyOfRange(bytes.size - 16, bytes.size)
    val ctAndTag = ct + tag

    println("salt     : ${salt.toHex()}")
    println("iv       : ${iv.toHex()}")
    println("ct+tag   : ${ctAndTag.size} bytes")

    // Signer: read from plaintext after we decrypt — but we need it BEFORE to build the KDF.
    // For files exported by the original app, the signer is always the original cert hash.
    // For files exported by your patched build, it's baked in during export.
    // Solution: try candidate signer hashes until GCM succeeds.
    val signerCandidates = listOf(
        "D834BF8D60BFEA09A80A51CCD1A77DE3EF966E7833EBB2D0B8DC1F750E38BBA7",  // original debug cert
        "A40DA80A59D170CAA950CF15C18C454D47A39B26989D8B640ECD745BA71BF5DC",  // your re-signed cert (if you exported)
        "",                                                                     // no signer (unlikely)
    )

    var plain: ByteArray? = null
    var usedSigner = ""

    for (signer in signerCandidates) {
        val kdfInput = SIG_PREFIX + signer
        val key = pbkdf2(kdfInput.toByteArray(StandardCharsets.UTF_8), salt, ITER, KEY_LEN)
        val result = try {
            aesGcmDecrypt(key, iv, aad, ctAndTag)
        } catch (_: Exception) { null }
        if (result != null) {
            plain = result
            usedSigner = signer
            break
        }
    }

    require(plain != null) { "GCM failed for all signer candidates — file was made by an unknown build" }

    println("signer   : ${if (usedSigner.isEmpty()) "(none)" else usedSigner}")
    println("plain    : ${plain.size} bytes (decrypted)")

    // F(): extract deflated payload
    val deflated = try { applyF(plain) } catch (e: Exception) {
        throw IllegalStateException("F() failed: ${e.message}")
    }
    println("payload  : ${deflated.size} bytes (deflated)")

    // Inflate → JSON
    val jsonBytes = inflate(deflated)
    val json = String(jsonBytes, StandardCharsets.UTF_8)
    require(json.startsWith("{")) { "payload doesn't start with '{' — got: ${json.take(80)}" }
    println("json     : ${json.length} chars")

    // Save raw JSON
    val basePath = path.removeSuffix(".RT").removeSuffix(".rt")
    File(basePath + ".json").writeText(prettyJson(json))               // full pretty
    File(basePath + ".clean.json").writeText(scrubNoisy(json))         // scrubbed pretty

    return json
}

// Replace long base64/data fields with a short placeholder
fun scrubNoisy(json: String): String {
    // Line-based scrub — works on pretty-printed JSON
    val lines = prettyJson(json).lines()
    return lines.joinToString("\n") { line ->
        when {
            line.contains("\"bannerImage\"") && line.length > 150 -> {
                val indent = line.takeWhile { it == ' ' }
                "$indent\"bannerImage\": \"<banner: ${line.length} chars scrubbed>\""
            }
            line.contains("\"note\"") && line.length > 250 -> {
                val indent = line.takeWhile { it == ' ' }
                "$indent\"note\": \"<note: ${line.length} chars scrubbed>\""
            }
            else -> line
        }
    }
}

// Lightweight JSON pretty-printer (no external deps)
fun prettyJson(input: String, indent: String = "  "): String {
    val sb = StringBuilder()
    var depth = 0
    var inString = false
    var escaped = false
    for (c in input) {
        if (inString) {
            sb.append(c)
            if (escaped) escaped = false
            else if (c == '\\') escaped = true
            else if (c == '"') inString = false
            continue
        }
        when (c) {
            '"' -> { inString = true; sb.append(c) }
            '{', '[' -> {
                sb.append(c)
                depth++
                sb.append('\n').append(indent.repeat(depth))
            }
            '}', ']' -> {
                depth--
                sb.append('\n').append(indent.repeat(depth))
                sb.append(c)
            }
            ',' -> { sb.append(c).append('\n').append(indent.repeat(depth)) }
            ':' -> sb.append(": ")
            ' ', '\n', '\r', '\t' -> {}
            else -> sb.append(c)
        }
    }
    return sb.toString()
}

fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }

fun main(args: Array<String>) {
    if (args.isEmpty()) {
        println("Usage: rt-decode <file.RT> [--scrub]")
        return
    }
    val path = args[0]
    val scrub = args.contains("--scrub")
    try {
        val json = decodeRt(path)
        val display = if (scrub) scrubNoisy(json) else prettyJson(json)
        println("\n----- JSON -----")
        println(display)
    } catch (e: Throwable) {
        println("[!] ${e.message}")
        e.printStackTrace()
    }
}