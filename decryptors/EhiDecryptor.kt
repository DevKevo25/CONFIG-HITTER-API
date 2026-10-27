// EhiDecryptor.kt
// Compile: kotlinc EhiDecryptor.kt -include-runtime -cp bcprov-jdk18on-1.78.1.jar -d ehi.jar
// Run:     java -cp "ehi.jar:bcprov-jdk18on-1.78.1.jar" EhiDecryptorKt source.ehi

import org.bouncycastle.crypto.generators.Argon2BytesGenerator
import org.bouncycastle.crypto.params.Argon2Parameters
import org.bouncycastle.crypto.modes.ChaCha20Poly1305
import org.bouncycastle.crypto.params.AEADParameters
import org.bouncycastle.crypto.params.KeyParameter
import java.io.ByteArrayInputStream
import java.io.DataInputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Paths
import java.security.MessageDigest
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec
import kotlin.system.exitProcess

object Constants {
    val L1_KEY = hex("7e1210f7aab956f7a668bda6e57feddb7f84ad840aef8d27b1b969959be3ab6c")
    val L2_KEY_STATIC = hex("b2bc617c32d8b9eb1943a5ffa8051eea")
    val EOO_MASTER_KEY = "null=V5kU5+FFrY\u0000".toByteArray(StandardCharsets.ISO_8859_1)

    val BYPASS_IVS = listOf(
        hex("221d572349555f1d112133236b1f4a3f"),
        hex("5543494c53443e3f4a6a4539384e776a"),
        hex("374c2541575e4d531a3c327b75431e5f")
    )
    val STANDARD_IVS = listOf(
        hex("2c5d1147bbad422b3b334d4d235f1a53"),
        hex("522b01433a5e8b2fc7549e1ad368e541"),
        hex("337a1035aaedf3458ca167e92d74b839")
    )

    const val STD_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    const val CUSTOM_ALPHABET = "RkLC2QaVMPYgGJW/A4f7qzDb9e+t6Hr0Zp8OlNyjuxKcTw1o5EIimhBn3UvdSFXs"

    val TRANSLATION: CharArray = CharArray(128) { '\u0000' }.also { t ->
        CUSTOM_ALPHABET.forEachIndexed { i, c -> if (c.code < 128) t[c.code] = STD_ALPHABET[i] }
    }
}

fun hex(s: String): ByteArray =
    ByteArray(s.length / 2) { i ->
        ((Character.digit(s[i * 2], 16) shl 4) or Character.digit(s[i * 2 + 1], 16)).toByte()
    }

fun customB64Decode(encoded: String): ByteArray {
    val clean = encoded.replace("?", "").map { c ->
        if (c.code < 128 && Constants.TRANSLATION[c.code] != '\u0000') Constants.TRANSLATION[c.code] else c
    }.joinToString("").let { s ->
        val rem = s.length % 4
        if (rem != 0) s + "=".repeat(4 - rem) else s
    }
    return Base64.getDecoder().decode(clean)
}

fun decryptXorLayer(ciphertext: String?, key: String): String? {
    if (ciphertext.isNullOrBlank()) return ciphertext
    return try {
        val hexStr = customB64Decode(ciphertext.reversed()).toString(StandardCharsets.ISO_8859_1)
            .let { if (it.length % 2 != 0) "0$it" else it }
        val raw = hex(hexStr)
        val out = ByteArray(raw.size) { i ->
            ((raw[i].toInt() and 0xFF) xor (key[i % key.length].code and 0xFF)).toByte()
        }.filter { it != 0.toByte() }.toByteArray()
        val plain = out.toString(StandardCharsets.UTF_8)
        if (!plain.toByteArray(StandardCharsets.UTF_8).contentEquals(out)) return null
        if (plain.isNotEmpty()) {
            val ctrl = plain.count { it.code < 32 && it !in listOf('\t', '\n', '\r') }
            if (ctrl.toDouble() / plain.length > 0.5) return null
        }
        plain
    } catch (e: Exception) { null }
}

fun decodeConfigMessage(ciphertext: String?): String? {
    if (ciphertext.isNullOrBlank()) return ciphertext
    return try {
        val pad = (4 - ciphertext.length % 4) % 4
        val raw = Base64.getDecoder().decode(ciphertext + "=".repeat(pad))
        val utf8 = raw.toString(StandardCharsets.UTF_8)
        val u16 = utf8.toByteArray(StandardCharsets.UTF_16BE)
        val n = u16.size / 2
        val bb = ByteBuffer.wrap(u16).order(ByteOrder.BIG_ENDIAN)
        val keyChars = "EHIMSG".toCharArray()
        val xored = ByteBuffer.allocate(n * 2).order(ByteOrder.BIG_ENDIAN)
        for (i in 0 until n) {
            val ch = (bb.short.toInt() and 0xFFFF) xor keyChars[i % keyChars.size].code
            xored.putShort(ch.toShort())
        }
        xored.array().toString(StandardCharsets.UTF_16BE)
    } catch (e: Exception) { ciphertext }
}

fun xxteaDecrypt(dataIn: ByteArray, key: ByteArray): ByteArray {
    if (dataIn.isEmpty()) return dataIn
    val data = if (dataIn.size % 4 != 0) dataIn.copyOf(dataIn.size + (4 - dataIn.size % 4)) else dataIn
    val n = data.size / 4
    val v = LongArray(n)
    ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN).let { bb -> for (i in 0 until n) v[i] = bb.int.toLong() and 0xFFFFFFFFL }

    val kPad = ByteArray(16).also { System.arraycopy(key, 0, it, 0, minOf(key.size, 16)) }
    val k = LongArray(4)
    ByteBuffer.wrap(kPad).order(ByteOrder.LITTLE_ENDIAN).let { kb -> for (i in 0..3) k[i] = kb.int.toLong() and 0xFFFFFFFFL }

    val delta = 0x9e3779b9L
    var sum = ((6 + 52 / n) * delta) and 0xFFFFFFFFL
    var y = v[0]

    while (sum != 0L) {
        val e = ((sum shr 2) and 3).toInt()
        for (p in n - 1 downTo 1) {
            val z = v[p - 1]
            val mx = ((((z ushr 5) xor (y shl 2)) + ((y ushr 3) xor (z shl 4))) and 0xFFFFFFFFL) xor
                     (((sum xor y) + (k[(p and 3) xor e] xor z)) and 0xFFFFFFFFL)
            y = v[p].let { (it - mx) and 0xFFFFFFFFL }
            v[p] = y
        }
        val z = v[n - 1]
        val mx = ((((z ushr 5) xor (y shl 2)) + ((y ushr 3) xor (z shl 4))) and 0xFFFFFFFFL) xor
                 (((sum xor y) + (k[(0 and 3) xor e] xor z)) and 0xFFFFFFFFL)
        y = v[0].let { (it - mx) and 0xFFFFFFFFL }
        v[0] = y
        sum = (sum - delta) and 0xFFFFFFFFL
    }

    val out = ByteBuffer.allocate(n * 4).order(ByteOrder.LITTLE_ENDIAN).also { ob -> for (i in 0 until n) ob.putInt(v[i].toInt()) }.array()
    val length = v[n - 1]
    return if (length in 1..(n * 4).toLong()) out.copyOf(length.toInt()) else out.dropLastWhile { it == 0.toByte() }.toByteArray()
}

fun parseEhiBytes(fileBytes: ByteArray): ByteArray {
    val dis = DataInputStream(ByteArrayInputStream(fileBytes))
    dis.readUnsignedShort().also { dis.skipBytes(it) }
    dis.skipBytes(8)
    dis.readUnsignedShort().also { dis.skipBytes(it) }
    dis.skipBytes(8)
    val payloadLen = dis.readInt()
    dis.skipBytes(8)
    return ByteArray(payloadLen).also { dis.readFully(it) }
}

fun generateMasterKey(config: Map<String, Any?>): ByteArray {
    val fields = listOf("configAesKey", "configIdentifier", "configSalt", "configTimestamp",
        "configExpiryTimestamp", "lockModes", "lockModesHash", "configHwid", "configLockMobileOperatorId")
    val parts = mutableListOf<String>()
    for (k in fields) {
        val v = config[k]
        // Python: str(v) inside the tuple; .get(k, default) for missing
        val s = when (v) {
            null -> if (k == "configTimestamp" || k == "configExpiryTimestamp") "0" else ""
            is Double -> if (v == v.toLong().toDouble()) v.toLong().toString() else v.toString()
            else -> v.toString()
        }
        // Python's `if p` checks truthiness of the STRINGIFIED value
        if (s.isNotEmpty()) parts.add(s)
    }
    val payload = parts.joinToString("")
    return MessageDigest.getInstance("SHA-256").digest(payload.toByteArray(StandardCharsets.UTF_8))
}

fun generateMasterKeyDebug(config: Map<String, Any?>): Pair<ByteArray, String> {
    val fields = listOf("configAesKey", "configIdentifier", "configSalt", "configTimestamp",
        "configExpiryTimestamp", "lockModes", "lockModesHash", "configHwid", "configLockMobileOperatorId")
    val parts = mutableListOf<String>()
    for (k in fields) {
        val v = config[k]
        val s = when (v) {
            null -> if (k == "configTimestamp" || k == "configExpiryTimestamp") "0" else ""
            is Double -> if (v == v.toLong().toDouble()) v.toLong().toString() else v.toString()
            else -> v.toString()
        }
        val truthy = when (v) {
            null -> false
            is String -> v.isNotEmpty()
            is Number -> v.toDouble() != 0.0
            is Boolean -> v
            else -> true
        }
        if (truthy) parts.add(s)
    }
    val payload = parts.joinToString("")
    val raw = payload.toByteArray(StandardCharsets.UTF_8)
    val digest = MessageDigest.getInstance("SHA-256").digest(payload.toByteArray(StandardCharsets.UTF_8))
    return digest to payload
}

fun aesCbcDecrypt(key: ByteArray, iv: ByteArray, data: ByteArray): ByteArray {
    val c = Cipher.getInstance("AES/CBC/NoPadding")
    c.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), IvParameterSpec(iv))
    val out = c.doFinal(data)
    val pad = out.last().toInt() and 0xFF
    return if (pad in 1..16) out.copyOf(out.size - pad) else out
}

fun argon2id(secret: ByteArray, salt: ByteArray, timeCost: Int, memoryCost: Int, parallelism: Int, hashLen: Int): ByteArray {
    val params = Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
        .withVersion(Argon2Parameters.ARGON2_VERSION_13)
        .withIterations(timeCost)
        .withMemoryAsKB(memoryCost)
        .withParallelism(parallelism)
        .withSalt(salt)
        .build()
    val gen = Argon2BytesGenerator()
    gen.init(params)
    return ByteArray(hashLen).also { gen.generateBytes(secret, it) }
}

fun hchacha20(key: ByteArray, nonce16: ByteArray): ByteArray {
    require(key.size == 32) { "key must be 32 bytes" }
    require(nonce16.size == 16) { "nonce must be 16 bytes" }
    val bbK = ByteBuffer.wrap(key).order(ByteOrder.LITTLE_ENDIAN)
    val bbN = ByteBuffer.wrap(nonce16).order(ByteOrder.LITTLE_ENDIAN)
    val x = IntArray(16)
    x[0] = 0x61707865; x[1] = 0x3320646e; x[2] = 0x79622d32; x[3] = 0x6b206574
    for (i in 0 until 8) x[4 + i] = bbK.int
    for (i in 0 until 4) x[12 + i] = bbN.int

    fun rotl(v: Int, c: Int) = (v shl c) or (v ushr (32 - c))
    fun qr(a: Int, b: Int, c: Int, d: Int) {
        x[a] += x[b]; x[d] = rotl(x[d] xor x[a], 16)
        x[c] += x[d]; x[b] = rotl(x[b] xor x[c], 12)
        x[a] += x[b]; x[d] = rotl(x[d] xor x[a], 8)
        x[c] += x[d]; x[b] = rotl(x[b] xor x[c], 7)
    }
    repeat(10) {
        qr(0, 4, 8, 12); qr(1, 5, 9, 13); qr(2, 6, 10, 14); qr(3, 7, 11, 15)
        qr(0, 5, 10, 15); qr(1, 6, 11, 12); qr(2, 7, 8, 13); qr(3, 4, 9, 14)
    }
    val out = ByteBuffer.allocate(32).order(ByteOrder.LITTLE_ENDIAN)
    for (i in 0..3) out.putInt(x[i])
    for (i in 12..15) out.putInt(x[i])
    return out.array()
}

fun chachaDecrypt(key: ByteArray, nonce: ByteArray, aad: ByteArray, ct: ByteArray, tag: ByteArray): ByteArray {
    val (subKey, realNonce) = if (nonce.size == 24) {
        val sub = hchacha20(key, nonce.copyOfRange(0, 16))
        val rn = ByteArray(12)
        System.arraycopy(nonce, 16, rn, 4, 8) // IETF: 0x00000000 || nonce[16:24]
        sub to rn
    } else key to nonce

    val cipher = ChaCha20Poly1305()
    cipher.init(false, AEADParameters(KeyParameter(subKey), 128, realNonce, aad))
    val combined = ByteArray(ct.size + tag.size)
    System.arraycopy(ct, 0, combined, 0, ct.size)
    System.arraycopy(tag, 0, combined, ct.size, tag.size)
    val out = ByteArray(cipher.getOutputSize(combined.size))
    val len = cipher.processBytes(combined, 0, combined.size, out, 0)
    val fin = cipher.doFinal(out, len)
    return out.copyOf(len + fin)
}

fun decodeInnerFields(parsed: Map<String, Any?>, saltKey: String): MutableMap<String, Any?> {
    val out = linkedMapOf<String, Any?>()
    val vital = setOf("overwriteServerData")
    for ((k, v) in parsed) {
        if (v is String && v.isNotBlank()) {
            val dec = if (k == "configMessage") decodeConfigMessage(v) else decryptXorLayer(v, saltKey)
            when {
                dec != null -> out[k] = dec
                k in vital -> out[k] = v
            }
        } else out[k] = v
    }
    return out
}

fun scrubNoisy(json: String): String {
    val lines = json.lines()
    return lines.joinToString("\n") { line ->
        when {
            line.contains("\"configMessage\"") && line.length > 250 -> {
                val indent = line.takeWhile { it == ' ' }
                "$indent\"configMessage\": \"<configMessage: ${line.length} chars scrubbed>\""
            }
            line.contains("\"payload\"") && line.length > 250 -> {
                val indent = line.takeWhile { it == ' ' }
                "$indent\"payload\": \"<payload: ${line.length} chars scrubbed>\""
            }
            else -> line
        }
    }
}

@Suppress("UNCHECKED_CAST")
fun execute(fileBytes: ByteArray, srcPath: String): String {
    val payload = try { parseEhiBytes(fileBytes) } catch (e: Exception) {
        return "[!] Failed to parse .ehi file: ${e.message}"
    }

    var config: Map<String, Any?>? = null
    var matchedIv: ByteArray? = null
    var ivKind = ""

    for (iv in Constants.BYPASS_IVS + Constants.STANDARD_IVS) {
        try {
            val l1 = aesCbcDecrypt(Constants.L1_KEY, iv, payload)
            val parts = l1.toString(StandardCharsets.UTF_8).split(":")
            if (parts.size >= 3) {
                val iv2 = Base64.getDecoder().decode(parts[0])
                val garbage = aesCbcDecrypt(Constants.L2_KEY_STATIC, iv2, Base64.getDecoder().decode(parts[2]))
                val finalRaw = xxteaDecrypt(garbage, Constants.EOO_MASTER_KEY)
                val start = finalRaw.indexOf('{'.code.toByte())
                if (start != -1) {
                    config = parseJson(finalRaw.copyOfRange(start, finalRaw.size).toString(StandardCharsets.UTF_8)) as Map<String, Any?>
                    matchedIv = iv
                    ivKind = if (Constants.BYPASS_IVS.any { it.contentEquals(iv) }) "BYPASS" else "STANDARD"
                    break
                }
            }
        } catch (_: Exception) {}
    }

    if (config == null) return "[!] Failed to decrypt .ehi file"

    val targetSalt = (config["configSalt"] ?: "EVZJNI").toString()
    var parsedFinal: Map<String, Any?> = config
    var meta: Map<String, Any?> = mapOf(
        "version"   to "EHI",
        "iv"        to matchedIv!!.toHex(),
        "ivKind"    to ivKind,
        "payload"   to "${payload.size} bytes",
        "configSalt" to targetSalt
    )

    val isBypass = ivKind == "BYPASS"

    if (!isBypass) {
        val targetData = config["configData"]?.toString() ?: return "[!] Failed to decrypt config data"
        val aaaResult = decryptXorLayer(targetData, targetSalt) ?: return "[!] Failed to decrypt config data"
        val rawPayload = try { Base64.getDecoder().decode(aaaResult) } catch (e: Exception) {
            return "[!] Invalid base64 payload: ${e.message}"
        }
        if (rawPayload.size <= 50) return "[!] Invalid payload length"

        val timeCost = ByteBuffer.wrap(rawPayload, 1, 4).order(ByteOrder.LITTLE_ENDIAN).int
        val memCost = ByteBuffer.wrap(rawPayload, 5, 4).order(ByteOrder.LITTLE_ENDIAN).int
        val parallelism = rawPayload[9].toInt() and 0xFF
        val salt = rawPayload.copyOfRange(0x0a, 0x1a)
        val nonce = rawPayload.copyOfRange(0x1a, 0x32)
        val aad = rawPayload.copyOfRange(0, 0x1a)
        val ct = rawPayload.copyOfRange(0x32, rawPayload.size - 16)
        val tag = rawPayload.copyOfRange(rawPayload.size - 16, rawPayload.size)

        val masterKey = generateMasterKey(config)
        val argonKey = argon2id(masterKey, salt, timeCost, memCost, parallelism, 32)
        val decrypted = try { chachaDecrypt(argonKey, nonce, aad, ct, tag) } catch (e: Exception) {
            return "[!] ChaCha20-Poly1305 failed: ${e.message}"
        }
        parsedFinal = parseJson(decrypted.toString(StandardCharsets.UTF_8)) as Map<String, Any?>

        meta = meta + mapOf(
            "kdf"         to "Argon2id",
            "timeCost"    to timeCost,
            "memCost"     to memCost,
            "parallelism" to parallelism,
            "salt"        to salt.toHex(),
            "nonce"       to nonce.toHex(),
            "aadLen"      to aad.size,
            "ctLen"       to ct.size,
            "tag"         to tag.toHex()
        )
    }

    val cleaned = decodeInnerFields(parsedFinal, targetSalt)

    for (field in listOf("v2rRawJson", "overwriteServerData")) {
        val v = cleaned[field]
        if (v is String) {
            val start = v.indexOf('{')
            val end = v.lastIndexOf('}')
            if (start != -1 && end != -1) {
                try {
                    var parsed = parseJson(v.substring(start, end + 1))
                    if (parsed is String) parsed = parseJson(parsed)
                    cleaned[field] = parsed
                } catch (e: Exception) {
                    cleaned["${field}_PARSING_ERROR"] = e.message ?: "unknown"
                }
            }
        }
    }

    // Save artifacts next to the input, same as RT decoder
    val basePath = srcPath.removeSuffix(".ehi").removeSuffix(".EHI")
    val fullJson = toJson(cleaned, 4)
    try {
        java.io.File(basePath + ".json").writeText(fullJson)
        java.io.File(basePath + ".clean.json").writeText(scrubNoisy(fullJson))
    } catch (e: Exception) {
        return "[!] Decrypt OK but failed to write .json: ${e.message}"
    }

    return buildString {
        appendLine("=== EHI ===")
        appendLine("// --- file meta ---")
        appendLine(prettyMap(meta))
        appendLine()
        appendLine("// --- config envelope ---")
        appendLine(toJson(cleaned, 4))
    }
}

fun prettyMap(m: Map<String, Any?>): String =
    m.entries.joinToString("\n") { (k, v) -> "  $k: $v" }

fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }

// ===== tiny JSON =====
fun parseJson(s: String): Any? = JsonParser(s).parse()
fun toJson(o: Any?, indent: Int): String = JsonWriter.write(o, indent, 0)

class JsonParser(private val s: String) {
    private var i = 0
    fun parse(): Any? { skipWs(); return parseValue() }
    private fun skipWs() { while (i < s.length && s[i].isWhitespace()) i++ }
    private fun parseValue(): Any? {
        skipWs()
        if (i >= s.length) return null
        return when (s[i]) {
            '{' -> parseObject()
            '[' -> parseArray()
            '"' -> parseString()
            't' -> { i += 4; true }
            'f' -> { i += 5; false }
            'n' -> { i += 4; null }
            else -> parseNumber()
        }
    }
    private fun parseObject(): Map<String, Any?> {
        val m = linkedMapOf<String, Any?>()
        i++; skipWs()
        if (i < s.length && s[i] == '}') { i++; return m }
        while (i < s.length) {
            skipWs(); val k = parseString(); skipWs()
            if (i < s.length && s[i] == ':') i++
            m[k] = parseValue(); skipWs()
            if (i < s.length && s[i] == ',') { i++; continue }
            if (i < s.length && s[i] == '}') { i++; break }
            break
        }
        return m
    }
    private fun parseArray(): List<Any?> {
        val l = mutableListOf<Any?>()
        i++; skipWs()
        if (i < s.length && s[i] == ']') { i++; return l }
        while (i < s.length) {
            l.add(parseValue()); skipWs()
            if (i < s.length && s[i] == ',') { i++; continue }
            if (i < s.length && s[i] == ']') { i++; break }
            break
        }
        return l
    }
    private fun parseString(): String {
        val sb = StringBuilder(); i++
        while (i < s.length) {
            val c = s[i++]
            if (c == '"') break
            if (c == '\\') {
                when (val e = s[i++]) {
                    '"' -> sb.append('"'); '\\' -> sb.append('\\'); '/' -> sb.append('/')
                    'b' -> sb.append('\b'); 'f' -> sb.append('\u000C'); 'n' -> sb.append('\n')
                    'r' -> sb.append('\r'); 't' -> sb.append('\t')
                    'u' -> { sb.append(s.substring(i, i + 4).toInt(16).toChar()); i += 4 }
                    else -> sb.append(e)
                }
            } else sb.append(c)
        }
        return sb.toString()
    }
    private fun parseNumber(): Any {
        val start = i
        while (i < s.length && "-+.eE0123456789".indexOf(s[i]) >= 0) i++
        val num = s.substring(start, i)
        return if (num.any { it in ".eE" }) num.toDouble() else num.toLongOrNull() ?: num
    }
}

object JsonWriter {
    fun write(o: Any?, indent: Int, level: Int): String = when (o) {
        null -> "null"
        is String -> quote(o)
        is Number, is Boolean -> o.toString()
        is Map<*, *> -> {
            if (o.isEmpty()) "{}" else buildString {
                append("{\n"); var first = true
                for ((k, v) in o) {
                    if (!first) append(",\n"); first = false
                    append(" ".repeat((level + 1) * indent))
                    append(quote(k.toString())).append(": ").append(write(v, indent, level + 1))
                }
                append("\n").append(" ".repeat(level * indent)).append("}")
            }
        }
        is List<*> -> {
            if (o.isEmpty()) "[]" else buildString {
                append("[\n")
                o.forEachIndexed { idx, v ->
                    append(" ".repeat((level + 1) * indent)).append(write(v, indent, level + 1))
                    if (idx < o.size - 1) append(",")
                    append("\n")
                }
                append(" ".repeat(level * indent)).append("]")
            }
        }
        else -> quote(o.toString())
    }
    fun quote(s: String): String = buildString {
        append('"')
        for (c in s) when (c) {
            '"' -> append("\\\""); '\\' -> append("\\\\"); '\n' -> append("\\n")
            '\r' -> append("\\r"); '\t' -> append("\\t"); '\b' -> append("\\b"); '\u000C' -> append("\\f")
            else -> if (c.code < 32) append("\\u%04x".format(c.code)) else append(c)
        }
        append('"')
    }
}

fun main(args: Array<String>) {
    if (args.isEmpty()) {
        System.err.println("Usage: java EhiDecryptorKt <source.ehi>")
        exitProcess(1)
    }
    val path = args[0]
    val bytes = Files.readAllBytes(Paths.get(path))
    println(execute(bytes, path))
}