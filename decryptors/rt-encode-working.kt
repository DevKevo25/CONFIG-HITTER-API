// kotlinc rt-encode.kt -include-runtime -d rt-encode.jar
// java -jar rt-encode.jar test1.json test1-rebuilt.RT

// ============================================================================
// REESE TUNNEL .RT file encoder — RSE5 format (UNLOCKED variant)
//
// Same crypto as before. The difference: before encryption, we walk the
// JSON as a tree (not regex) and force every lock/binding field to its
// unlocked value. This survives notes/banners that contain literal
// "locked":true text — a regex replace would corrupt those.
// ============================================================================

import java.io.File
import java.nio.charset.StandardCharsets
import java.security.SecureRandom
import java.util.zip.Deflater
import javax.crypto.Cipher
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

val MAGIC = byteArrayOf(0xA7.toByte(), 0x19, 0xD2.toByte(), 0x4C)
const val SIG_PREFIX = "REESE-CUSTOM/RSE5|||SIG:"
const val ITER = 32768
const val KEY_LEN = 32

val RNG = SecureRandom()

fun pbkdf2(password: ByteArray, salt: ByteArray, iter: Int, keyLen: Int): ByteArray {
    val spec = PBEKeySpec(String(password, StandardCharsets.UTF_8).toCharArray(),
                          salt, iter, keyLen * 8)
    return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
        .generateSecret(spec).encoded
}

fun aesGcmEncrypt(key: ByteArray, iv: ByteArray, aad: ByteArray, plain: ByteArray): ByteArray {
    val c = Cipher.getInstance("AES/GCM/NoPadding")
    c.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, iv))
    c.updateAAD(aad)
    return c.doFinal(plain)
}

fun deflate(data: ByteArray): ByteArray {
    val def = Deflater(1, true)
    def.setInput(data)
    def.finish()
    val out = java.io.ByteArrayOutputStream()
    val buf = ByteArray(4096)
    while (!def.finished()) {
        val n = def.deflate(buf)
        if (n <= 0) break
        out.write(buf, 0, n)
    }
    def.end()
    return out.toByteArray()
}

fun randBytes(n: Int): ByteArray {
    val b = ByteArray(n)
    RNG.nextBytes(b)
    return b
}

fun uint32BE(v: Int): ByteArray = byteArrayOf(
    (v ushr 24).toByte(), (v ushr 16).toByte(), (v ushr 8).toByte(), v.toByte(),
)

fun buildPaddedPayload(payload: ByteArray): ByteArray {
    val n = RNG.nextInt(256)
    val filler = randBytes(n + 16)
    val lenField = uint32BE(payload.size)
    val trailingSizeRaw = 262144 + RNG.nextInt(65536) - (n + 21 + payload.size)
    val trailingSize = if (trailingSizeRaw < 0) 0 else trailingSizeRaw
    val trailing = randBytes(trailingSize)
    val out = java.io.ByteArrayOutputStream()
    out.write(byteArrayOf(n.toByte()))
    out.write(filler)
    out.write(lenField)
    out.write(payload)
    out.write(trailing)
    return out.toByteArray()
}

// ---------------------------------------------------------------------------
// Minimal JSON tree — enough to walk and mutate without pulling in a library.
// ---------------------------------------------------------------------------
sealed class JVal {
    object JNull : JVal()
    data class JBool(val v: Boolean) : JVal()
    data class JNum(val raw: String) : JVal()          // keep original text form
    data class JStr(val v: String) : JVal()
    data class JArr(val items: MutableList<JVal>) : JVal()
    data class JObj(val fields: LinkedHashMap<String, JVal>) : JVal()
}

class JParser(private val s: String) {
    private var i = 0
    fun parse(): JVal {
        skipWs()
        val v = parseVal()
        skipWs()
        require(i == s.length) { "trailing data at $i" }
        return v
    }
    private fun skipWs() { while (i < s.length && s[i].isWhitespace()) i++ }
    private fun parseVal(): JVal {
        skipWs()
        require(i < s.length) { "unexpected EOF" }
        return when (s[i]) {
            '{' -> parseObj()
            '[' -> parseArr()
            '"' -> JVal.JStr(parseStr())
            't' -> { expect("true");  JVal.JBool(true) }
            'f' -> { expect("false"); JVal.JBool(false) }
            'n' -> { expect("null");  JVal.JNull }
            else -> parseNum()
        }
    }
    private fun expect(word: String) {
        require(s.regionMatches(i, word, 0, word.length)) { "expected $word at $i" }
        i += word.length
    }
    private fun parseObj(): JVal.JObj {
        i++ // {
        val m = LinkedHashMap<String, JVal>()
        skipWs()
        if (i < s.length && s[i] == '}') { i++; return JVal.JObj(m) }
        while (true) {
            skipWs()
            val k = parseStr()
            skipWs(); require(s[i] == ':') { "expected : at $i" }; i++
            val v = parseVal()
            m[k] = v
            skipWs()
            when (s[i]) {
                ',' -> { i++; continue }
                '}' -> { i++; break }
                else -> error("expected , or } at $i")
            }
        }
        return JVal.JObj(m)
    }
    private fun parseArr(): JVal.JArr {
        i++ // [
        val m = ArrayList<JVal>()
        skipWs()
        if (i < s.length && s[i] == ']') { i++; return JVal.JArr(m) }
        while (true) {
            m.add(parseVal())
            skipWs()
            when (s[i]) {
                ',' -> { i++; continue }
                ']' -> { i++; break }
                else -> error("expected , or ] at $i")
            }
        }
        return JVal.JArr(m)
    }
    private fun parseStr(): String {
        require(s[i] == '"') { "expected \" at $i" }; i++
        val sb = StringBuilder()
        while (true) {
            val c = s[i++]
            when (c) {
                '"' -> return sb.toString()
                '\\' -> {
                    when (val e = s[i++]) {
                        '"' -> sb.append('"')
                        '\\' -> sb.append('\\')
                        '/' -> sb.append('/')
                        'b' -> sb.append('\b')
                        'f' -> sb.append('\u000C')
                        'n' -> sb.append('\n')
                        'r' -> sb.append('\r')
                        't' -> sb.append('\t')
                        'u' -> {
                            val hex = s.substring(i, i + 4); i += 4
                            sb.append(hex.toInt(16).toChar())
                        }
                        else -> error("bad escape \\$e")
                    }
                }
                else -> sb.append(c)
            }
        }
    }
    private fun parseNum(): JVal.JNum {
        val start = i
        if (s[i] == '-') i++
        while (i < s.length && (s[i].isDigit() || s[i] in ".eE+-")) i++
        return JVal.JNum(s.substring(start, i))
    }
}

fun JVal.serialize(sb: StringBuilder = StringBuilder()): StringBuilder {
    when (this) {
        is JVal.JNull -> sb.append("null")
        is JVal.JBool -> sb.append(if (v) "true" else "false")
        is JVal.JNum -> sb.append(raw)
        is JVal.JStr -> {
            sb.append('"')
            for (c in v) when (c) {
                '"' -> sb.append("\\\"")
                '\\' -> sb.append("\\\\")
                '\n' -> sb.append("\\n")
                '\r' -> sb.append("\\r")
                '\t' -> sb.append("\\t")
                else -> if (c < ' ') sb.append("\\u%04x".format(c.code)) else sb.append(c)
            }
            sb.append('"')
        }
        is JVal.JArr -> {
            sb.append('[')
            items.forEachIndexed { idx, it ->
                if (idx > 0) sb.append(',')
                it.serialize(sb)
            }
            sb.append(']')
        }
        is JVal.JObj -> {
            sb.append('{')
            var first = true
            for ((k, v) in fields) {
                if (!first) sb.append(',')
                first = false
                JVal.JStr(k).serialize(sb)
                sb.append(':')
                v.serialize(sb)
            }
            sb.append('}')
        }
    }
    return sb
}

// ---------------------------------------------------------------------------
// Unlock: walk the tree, force every lock/binding field to unlocked value.
// Rules are keyed on field NAME, applied wherever they appear (meta + config
// both have `lockAll`, `lockConfig`, etc., so name-based is what we want).
// ---------------------------------------------------------------------------
val FORCE_FALSE_KEYS = setOf(
    "locked", "lockAll", "lockPayloadUnlockServer", "unlockUserPass",
    "lockRemoteProxy", "blockRoot", "lockConfig", "importLocked",
    "bannerImageEnabled", "useRemoteProxy",          // remote proxy unlocked
)

fun unlockTree(v: JVal): JVal {
    return when (v) {
        is JVal.JObj -> {
            val out = LinkedHashMap<String, JVal>()
            for ((k, child) in v.fields) {
                out[k] = when {
                    // booleans that gate locking -> false
                    k in FORCE_FALSE_KEYS && child is JVal.JBool -> JVal.JBool(false)
                    // credential / binding fields -> empty
                    k in setOf("password", "hwid", "boundHwid", "vault",
                               "customServerMessage", "authorSignature",
                               "importedFrom") && child is JVal.JStr -> JVal.JStr("")
                    // device whitelist -> empty array
                    k == "allowedHwids" && child is JVal.JArr -> JVal.JArr(mutableListOf())
                    // expiry -> 0
                    k == "expiresAt" && child is JVal.JNum -> JVal.JNum("0")
                    // recurse otherwise (handles nested config, v2rayProfiles, etc.)
                    else -> unlockTree(child)
                }
            }
            JVal.JObj(out)
        }
        is JVal.JArr -> JVal.JArr(v.items.map { unlockTree(it) }.toMutableList())
        else -> v
    }
}

// ---------------------------------------------------------------------------
// Encode
// ---------------------------------------------------------------------------
fun encodeRt(json: String, signer: String, outPath: String, forceUnlock: Boolean) {
    // 1. Parse + optionally unlock the tree
    val parsed = JParser(json).parse()
    require(parsed is JVal.JObj) { "top-level JSON must be an object" }
    val finalTree = if (forceUnlock) unlockTree(parsed) else parsed
    val finalJson = finalTree.serialize().toString()
    if (forceUnlock) println("[*] tree unlocked (name-based walk)")

    // 2. Deflate
    val jsonBytes = finalJson.toByteArray(StandardCharsets.UTF_8)
    val deflated = deflate(jsonBytes)
    println("[*] json      : ${jsonBytes.size} bytes")
    println("[*] deflated  : ${deflated.size} bytes")

    // 3. Pad
    val padded = buildPaddedPayload(deflated)
    println("[*] padded    : ${padded.size} bytes")

    // 4. Salt + IV
    val salt = randBytes(16)
    val iv   = randBytes(12)
    println("[*] salt      : ${salt.toHex()}")
    println("[*] iv        : ${iv.toHex()}")

    // 5. KDF
    val kdfInput = SIG_PREFIX + signer
    val key = pbkdf2(kdfInput.toByteArray(StandardCharsets.UTF_8), salt, ITER, KEY_LEN)
    println("[*] key       : ${key.toHex()}")

    // 6. Header / AAD. flags = 0x04 (sigBound only; lockAll + hwidLocked cleared)
    val header = java.io.ByteArrayOutputStream()
    header.write(MAGIC)
    header.write(0xC4)   // RSE5
    header.write(0x04)   // bit0 lockAll=0, bit1 hwidLocked=0, bit2 sigBound=1
    header.write(salt)
    header.write(iv)
    val headerBytes = header.toByteArray()
    require(headerBytes.size == 34) { "header must be 34 bytes, got ${headerBytes.size}" }

    // 7. Encrypt
    val ctAndTag = aesGcmEncrypt(key, iv, headerBytes, padded)
    println("[*] ct+tag    : ${ctAndTag.size} bytes")

    // 8. Write
    File(outPath).writeBytes(headerBytes + ctAndTag)
    println("[*] wrote     : $outPath (${headerBytes.size + ctAndTag.size} bytes)")
}

fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }

fun main(args: Array<String>) {
    if (args.size < 2) {
        println("Usage: rt-encode <input.json> <output.RT> [--no-unlock] [--signer <hash>]")
        println("  default: JSON is unlocked (all lock flags false, creds/hwid cleared)")
        println("  --no-unlock   keep the JSON exactly as given")
        println("  --signer <h>  override signer hash (default: original cert)")
        return
    }
    val inPath  = args[0]
    val outPath = args[1]
    val signer = if (args.contains("--signer"))
                    args[args.indexOf("--signer") + 1]
                 else "D834BF8D60BFEA09A80A51CCD1A77DE3EF966E7833EBB2D0B8DC1F750E38BBA7"
    val forceUnlock = !args.contains("--no-unlock")

    try {
        val json = File(inPath).readText()
        require(json.trimStart().startsWith("{")) { "input doesn't look like JSON" }
        encodeRt(json, signer, outPath, forceUnlock)
        println("\n[✓] done")
    } catch (e: Throwable) {
        println("[!] ${e.message}")
        e.printStackTrace()
    }
}