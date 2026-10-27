// DtDecryptor.kt
// Compile: kotlinc DtDecryptor.kt -include-runtime -cp "bcprov-jdk18on-1.78.1.jar:msgpack-core-0.9.8.jar" -d dt.jar
// Run:     java -cp "dt.jar:bcprov-jdk18on-1.78.1.jar:msgpack-core-0.9.8.jar" DtDecryptorKt source.dt

import org.msgpack.core.MessagePack
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Paths
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec
import kotlin.system.exitProcess

object DtConstants {
    val KEY_256: ByteArray = "\$B&E)H@McQfThWmZq4t7w!z%C*F-JaNd".toByteArray(StandardCharsets.ISO_8859_1)
    val KEY_192: ByteArray = "F)J@NcRfUjXn2r4u7x!A%D*G".toByteArray(StandardCharsets.ISO_8859_1)
    val IV: ByteArray = hex("232e39185523184a5723586242200e05")
}

fun hex(s: String): ByteArray =
    ByteArray(s.length / 2) { i ->
        ((Character.digit(s[i * 2], 16) shl 4) or Character.digit(s[i * 2 + 1], 16)).toByte()
    }

fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }

// ===== Base64 URL-safe decode =====
fun base64DecodeSafe(s: String): ByteArray {
    var clean = s.replace("-", "+").replace("_", "/")
    val pad = clean.length % 4
    if (pad != 0) clean += "=".repeat(4 - pad)
    return Base64.getDecoder().decode(clean)
}

// ===== AES-CFB (segment 128) =====
fun aesCfbDecrypt(data: ByteArray, key: ByteArray, iv: ByteArray): ByteArray {
    val c = Cipher.getInstance("AES/CFB/NoPadding")
    c.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), IvParameterSpec(iv))
    return c.doFinal(data)
}

// ===== printable UTF-8 check =====
fun isUtf8Printable(b: ByteArray): Boolean {
    if (b.isEmpty()) return false
    return try {
        val s = String(b, StandardCharsets.UTF_8)
        // Python regex: [^\x00-\x08\x0B\x0C\x0E-\x1F\x7F]*
        // matches if NO byte is in the disallowed control range
        s.all { c ->
            val code = c.code
            !((code in 0x00..0x08) || code == 0x0B || code == 0x0C || (code in 0x0E..0x1F) || code == 0x7F)
        }
    } catch (e: Exception) { false }
}

// ===== JSON-like normalizer =====
// Python: if value is string starting with { or [ and ending with } or ]
//         try to parse as JSON (after fixing bare $vars)
fun tryParseJsonString(value: String): Any? {
    val stripped = value.trim()
    val looksLikeJson = (stripped.startsWith("{") && stripped.endsWith("}")) ||
                        (stripped.startsWith("[") && stripped.endsWith("]"))
    if (!looksLikeJson) return value
    return try {
        // fix bare $vars:  ": $FOO" -> ": \"$FOO\""
        val fixed = Regex(""":\s*(\$[A-Za-z0-9_]+)""").replace(stripped) { m ->
            ": \"${m.groupValues[1]}\""
        }
        val parsed = SimpleJson.parse(fixed)
        normalizeForJson(parsed)
    } catch (e: Exception) { value }
}

fun normalizeForJson(value: Any?): Any? {
    return when (value) {
        is Map<*, *> -> {
            val out = linkedMapOf<String, Any?>()
            for ((k, v) in value) {
                if (k is String && k == "Password") continue
                out[k.toString()] = normalizeForJson(v)
            }
            out
        }
        is List<*> -> value.map { normalizeForJson(it) }
        is ByteArray -> if (isUtf8Printable(value)) tryParseJsonString(String(value, StandardCharsets.UTF_8)) else value.map { it.toInt() and 0xFF }
        is String -> tryParseJsonString(value)
        else -> value
    }
}

// ===== Recursive decrypt of fields starting with "Encrypted" =====
fun cleanEncrypted(value: Any?, key: ByteArray, iv: ByteArray): Any? {
    return when (value) {
        is Map<*, *> -> {
            val out = linkedMapOf<String, Any?>()
            for ((k, v) in value) {
                val keyStr = k?.toString() ?: continue
                if (keyStr.startsWith("Encrypted") && v is ByteArray && v.isNotEmpty()) {
                    out[keyStr] = try { aesCfbDecrypt(v, key, iv) } catch (e: Exception) { v }
                } else {
                    out[keyStr] = cleanEncrypted(v, key, iv)
                }
            }
            out
        }
        is List<*> -> value.map { cleanEncrypted(it, key, iv) }
        else -> value
    }
}

// ===== MsgPack unpack → Map/List/primitives =====
fun msgpackUnpack(data: ByteArray): Any? {
    val unpacker = MessagePack.newDefaultUnpacker(data)
    return readValue(unpacker)
}

private fun readValue(u: org.msgpack.core.MessageUnpacker): Any? {
    return when (val fmt = u.nextFormat) {
        else -> when (fmt.valueType) {
            org.msgpack.value.ValueType.NIL -> { u.unpackNil(); null }
            org.msgpack.value.ValueType.BOOLEAN -> u.unpackBoolean()
            org.msgpack.value.ValueType.INTEGER -> u.unpackLong()
            org.msgpack.value.ValueType.FLOAT -> u.unpackDouble()
            org.msgpack.value.ValueType.STRING -> u.unpackString()
            org.msgpack.value.ValueType.BINARY -> u.readPayload(u.unpackBinaryHeader())
            org.msgpack.value.ValueType.ARRAY -> {
                val n = u.unpackArrayHeader()
                (0 until n).map { readValue(u) }
            }
            org.msgpack.value.ValueType.MAP -> {
                val n = u.unpackMapHeader()
                val m = linkedMapOf<String, Any?>()
                repeat(n) {
                    val k = readValue(u)
                    val v = readValue(u)
                    m[k.toString()] = v
                }
                m
            }
            org.msgpack.value.ValueType.EXTENSION -> {
                val extLen = u.unpackExtensionTypeHeader().let { it.length }
                u.readPayload(extLen)
            }
        }
    }
}

// ===== Main =====
fun execute(fileBytes: ByteArray): String? {
    return try {
        var raw = String(fileBytes, StandardCharsets.UTF_8).trim()
        if (raw.isEmpty()) return null
        if ("://" in raw) raw = raw.split("://", limit = 2)[1]

        val outerJson = String(base64DecodeSafe(raw), StandardCharsets.UTF_8)
        val outer = SimpleJson.parse(outerJson) as? Map<*, *> ?: return null
        if (!outer.containsKey("encryptedLockedConfig")) return null

        val encLocked = base64DecodeSafe(outer["encryptedLockedConfig"].toString())
        val decOuter = aesCfbDecrypt(encLocked, DtConstants.KEY_256, DtConstants.IV)
        val unpackedOuter = (msgpackUnpack(decOuter) as? MutableMap<String, Any?>)
            ?: (msgpackUnpack(decOuter) as? Map<String, Any?>)?.toMutableMap()
            ?: return null

        if (unpackedOuter.containsKey("EncryptedLockedConfig")) {
            val innerBytes = unpackedOuter["EncryptedLockedConfig"] as? ByteArray
            if (innerBytes != null) {
                val decInner = aesCfbDecrypt(innerBytes, DtConstants.KEY_192, DtConstants.IV)
                val unpackedInner = msgpackUnpack(decInner)
                unpackedOuter["EncryptedLockedConfig"] = cleanEncrypted(unpackedInner, DtConstants.KEY_192, DtConstants.IV)
            }
        }

        val result = linkedMapOf<String, Any?>()
        for ((k, v) in outer) result[k.toString()] = v
        result["encryptedLockedConfig"] = unpackedOuter

        val normalized = normalizeForJson(result)
        val jsonStr = SimpleJson.write(normalized, 4)

        buildString {
            appendLine("KEVO LOVES DARK TUNNEL SCRIPT")
            appendLine("=".repeat(30))
            appendLine()
            appendLine(jsonStr)
            appendLine("=".repeat(30))
            append("code : @KEVO_LOVES")
        }
    } catch (e: Exception) {
        System.err.println("[!] ${e.message}")
        null
    }
}

fun main(args: Array<String>) {
    if (args.isEmpty()) {
        System.err.println("Usage: DtDecryptorKt <source.dt>")
        exitProcess(1)
    }
    val bytes = Files.readAllBytes(Paths.get(args[0]))
    val out = execute(bytes)
    if (out != null) println(out) else System.err.println("[!] failed to decrypt")
}

// ===== Tiny JSON parser + writer (same as EhiDecoder) =====
object SimpleJson {
    fun parse(s: String): Any? = Parser(s).parse()
    fun write(o: Any?, indent: Int): String = Writer.write(o, indent, 0)

    private class Parser(private val s: String) {
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
            return num.toLongOrNull() ?: num.toDoubleOrNull() ?: num
        }
    }

    private object Writer {
        fun write(o: Any?, indent: Int, level: Int): String = when (o) {
            null -> "null"
            is String -> quote(o)
            is ByteArray -> "[" + o.joinToString(",") { (it.toInt() and 0xFF).toString() } + "]"
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
}