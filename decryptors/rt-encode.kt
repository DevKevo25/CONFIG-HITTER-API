// kotlinc rt-encode.kt -include-runtime -d rt-encode.jar
// java -jar rt-encode.jar test1.json test1-rebuilt.RT
// ============================================================================
// REESE TUNNEL .RT file encoder — RSE5 format (0xC4 unlocked, 0xC6 locked)
//
// Modes (interactive menu):
//   1. export (unlocked)                    version 0xC4, flags 0x04, pbkdf2(32k)
//   2. export with password                 version 0xC6, flags 0x02, customKdf(600k)
//   3. export with hwid                     version 0xC6, flags 0x01, customKdf(600k)
//   4. export with hwid + password          version 0xC6, flags 0x03, customKdf(600k)
//
// KDF input template:
//   "REESE-CUSTOM/RSE5|" + HWID_UPPER + "|" + PASSWORD + ("|SIG:" + signer if 0xC4)
//
// Tree-walk unlock runs before encryption so notes/banners containing
// "locked":true aren't corrupted.
// ============================================================================
import java.io.File
import java.nio.charset.StandardCharsets
import java.security.SecureRandom
import java.util.zip.Deflater
import javax.crypto.Cipher
import javax.crypto.SecretKeyFactory
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

val MAGIC = byteArrayOf(0xA7.toByte(), 0x19, 0xD2.toByte(), 0x4C)
const val KDF_PREFIX = "REESE-CUSTOM/RSE5|"
const val SIG_SUFFIX = "|SIG:"
const val ITER_C4 = 32768
const val ITER_C6 = 600000
const val KEY_LEN = 32
const val DEFAULT_SIGNER = "D834BF8D60BFEA09A80A51CCD1A77DE3EF966E7833EBB2D0B8DC1F750E38BBA7"
val RNG = SecureRandom()

// ---- crypto helpers --------------------------------------------------------

fun pbkdf2(password: ByteArray, salt: ByteArray, iter: Int, keyLen: Int): ByteArray {
    val spec = PBEKeySpec(String(password, StandardCharsets.UTF_8).toCharArray(),
        salt, iter, keyLen * 8)
    return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
        .generateSecret(spec).encoded
}

// Native rse5Open KDF (0xC6): iterated HMAC-SHA256 chain with XOR accumulator.
// First: HMAC(key=input, data=salt || 00 00 00 01)  [BE32 counter 1]
// Then:  599,999 iterations of h = HMAC(key=input, data=h), acc ^= h
fun customKdf(input: ByteArray, salt: ByteArray, iterations: Int): ByteArray {
    val mac = Mac.getInstance("HmacSHA256")
    mac.init(SecretKeySpec(input, "HmacSHA256"))
    mac.reset()
    mac.update(salt)
    mac.update(byteArrayOf(0x00, 0x00, 0x00, 0x01))  // BE32 counter = 1
    var h = mac.doFinal()
    val acc = h.copyOf()
    for (i in 1 until iterations) {
        mac.reset()
        h = mac.doFinal(h)
        for (j in 0 until 32) acc[j] = (acc[j].toInt() xor h[j].toInt()).toByte()
    }
    return acc
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

fun randBytes(n: Int): ByteArray = ByteArray(n).also { RNG.nextBytes(it) }

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

// ---- minimal JSON tree (unchanged) ----------------------------------------
sealed class JVal {
    object JNull : JVal()
    data class JBool(val v: Boolean) : JVal()
    data class JNum(val raw: String) : JVal()
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
        i++
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
        i++
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

// ---- unlock walk (unchanged) ----------------------------------------------
val FORCE_FALSE_KEYS = setOf(
    "locked", "lockAll", "lockPayloadUnlockServer", "unlockUserPass",
    "lockRemoteProxy", "blockRoot", "lockConfig", "importLocked",
    "bannerImageEnabled", "useRemoteProxy",
)

fun unlockTree(v: JVal): JVal {
    return when (v) {
        is JVal.JObj -> {
            val out = LinkedHashMap<String, JVal>()
            for ((k, child) in v.fields) {
                out[k] = when {
                    k in FORCE_FALSE_KEYS && child is JVal.JBool -> JVal.JBool(false)
                    k in setOf("password", "hwid", "boundHwid", "vault",
                        "customServerMessage", "authorSignature",
                        "importedFrom") && child is JVal.JStr -> JVal.JStr("")
                    k == "allowedHwids" && child is JVal.JArr -> JVal.JArr(mutableListOf())
                    k == "expiresAt" && child is JVal.JNum -> JVal.JNum("0")
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
// Lock mode
// ---------------------------------------------------------------------------
data class LockMode(
    val label: String,
    val hwidLocked: Boolean,
    val pwLocked: Boolean,
    val sigBound: Boolean,
    val isC6: Boolean,
) {
    val flags: Int
        get() = (if (hwidLocked) 0x01 else 0) or
                (if (pwLocked)   0x02 else 0) or
                (if (sigBound)   0x04 else 0)
}

fun prompt(label: String): String {
    print(label)
    System.out.flush()
    return readlnOrNull()?.trim() ?: ""
}

fun promptPassword(label: String): String {
    val console = System.console()
    if (console != null) {
        val chars = console.readPassword(label)
        return if (chars == null) "" else String(chars)
    }
    return prompt(label)
}

fun showMenu(): LockMode {
    println()
    println("================ EXPORT MODE ================")
    println(" 1. Export (unlocked)                 [0xC4, pbkdf2 32k]")
    println(" 2. Export with password              [0xC6, customKdf 600k]")
    println(" 3. Export with HWID                  [0xC6, customKdf 600k]")
    println(" 4. Export with HWID + password       [0xC6, customKdf 600k]")
    println(" 0. Cancel")
    println("=============================================")
    while (true) {
        val choice = prompt("Choose [0-4]: ")
        when (choice) {
            "1" -> return LockMode("unlocked",      hwidLocked = false, pwLocked = false, sigBound = true,  isC6 = false)
            "2" -> return LockMode("password",      hwidLocked = false, pwLocked = true,  sigBound = false, isC6 = true)
            "3" -> return LockMode("hwid",          hwidLocked = true,  pwLocked = false, sigBound = false, isC6 = true)
            "4" -> return LockMode("hwid+password", hwidLocked = true,  pwLocked = true,  sigBound = false, isC6 = true)
            "0" -> { println("[*] cancelled"); kotlin.system.exitProcess(0) }
            else -> println("  invalid choice, try again")
        }
    }
}

// ---------------------------------------------------------------------------
// Encode
// ---------------------------------------------------------------------------
fun encodeRt(
    json: String,
    outPath: String,
    mode: LockMode,
    hwid: String,
    password: String,
    signer: String,
    forceUnlock: Boolean,
) {
    val parsed = JParser(json).parse()
    require(parsed is JVal.JObj) { "top-level JSON must be an object" }
    val finalTree = if (forceUnlock) unlockTree(parsed) else parsed
    val finalJson = finalTree.serialize().toString()
    if (forceUnlock) println("[*] tree unlocked (name-based walk)")

    val jsonBytes = finalJson.toByteArray(StandardCharsets.UTF_8)
    val deflated = deflate(jsonBytes)
    println("[*] json      : ${jsonBytes.size} bytes")
    println("[*] deflated  : ${deflated.size} bytes")

    val padded = buildPaddedPayload(deflated)
    println("[*] padded    : ${padded.size} bytes")

    val salt = randBytes(16)
    val iv   = randBytes(12)
    println("[*] salt      : ${salt.toHex()}")
    println("[*] iv        : ${iv.toHex()}")

    // KDF input + key
    val hwidUpper = hwid.trim().uppercase()
    val kdfBase   = KDF_PREFIX + hwidUpper + "|" + password.trim()
    val kdfInput  = if (mode.sigBound) kdfBase + SIG_SUFFIX + signer else kdfBase
    val kdfBytes  = kdfInput.toByteArray(StandardCharsets.UTF_8)

    val key = if (mode.isC6)
        customKdf(kdfBytes, salt, ITER_C6)
    else
        pbkdf2(kdfBytes, salt, ITER_C4, KEY_LEN)

    println("[*] kdfInput  : \"${kdfInput}\"")
    println("[*] kdf       : ${if (mode.isC6) "customKdf(600k)" else "pbkdf2(32k)"}")
    println("[*] key       : ${key.toHex()}")

    // Header
    val versionByte = if (mode.isC6) 0xC6 else 0xC4
    val header = java.io.ByteArrayOutputStream()
    header.write(MAGIC)
    header.write(versionByte)
    header.write(mode.flags)
    header.write(salt)
    header.write(iv)
    val headerBytes = header.toByteArray()
    require(headerBytes.size == 34) { "header must be 34 bytes, got ${headerBytes.size}" }
    println("[*] version   : 0x%02x".format(versionByte))
    println("[*] flags     : 0x%02x (hwid=%s pw=%s sig=%s)".format(
        mode.flags, mode.hwidLocked, mode.pwLocked, mode.sigBound))

    // Encrypt
    val ctAndTag = aesGcmEncrypt(key, iv, headerBytes, padded)
    println("[*] ct+tag    : ${ctAndTag.size} bytes")

    // Write
    File(outPath).writeBytes(headerBytes + ctAndTag)
    println("[*] wrote     : $outPath (${headerBytes.size + ctAndTag.size} bytes)")
}

fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }

fun main(args: Array<String>) {
    if (args.size < 2) {
        println("Usage: rt-encode <input.json> <output.RT> [--no-unlock] [--signer <hash>]")
        println("  prompts for export mode + credentials interactively")
        return
    }
    val inPath  = args[0]
    val outPath = args[1]
    val signer = if (args.contains("--signer"))
        args[args.indexOf("--signer") + 1]
    else DEFAULT_SIGNER
    val forceUnlock = !args.contains("--no-unlock")

    try {
        val json = File(inPath).readText()
        require(json.trimStart().startsWith("{")) { "input doesn't look like JSON" }

        val mode = showMenu()
        var hwid = ""
        var password = ""

        if (mode.hwidLocked) {
            println()
            println("HWID string (e.g. John-Reese-AENB-K4CR-ZSVX-G5WA)")
            while (hwid.isBlank()) {
                hwid = prompt("Enter HWID: ").uppercase()
                if (hwid.isBlank()) println("  HWID cannot be empty for this mode")
            }
        }
        if (mode.pwLocked) {
            println()
            while (password.isBlank()) {
                password = promptPassword("Enter password: ")
                if (password.isBlank()) println("  password cannot be empty for this mode")
            }
        }

        println()
        println("[*] mode      : ${mode.label}")
        encodeRt(json, outPath, mode, hwid, password, signer, forceUnlock)
        println("\n[✓] done")
    } catch (e: Throwable) {
        println("[!] ${e.message}")
        e.printStackTrace()
    }
}
