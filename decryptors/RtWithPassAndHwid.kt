import java.io.Console
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
//   [5]       flags         bit0=hwidLocked, bit1=passwordLocked, bit2=sigBound
//   [6..22]   salt          16 bytes
//   [22..34]  iv            12 bytes
//   [34..end] ciphertext + 16-byte GCM tag
//
// KDF input template (confirmed from working unlocked file):
//   "REESE-CUSTOM/RSE5|" + HWID_UPPER + "|" + PASSWORD + "|SIG:" + signer
//   (omit "|SIG:"+signer when sigBound=false)
//
// AAD = file[0..34]
// Cipher = AES-256-GCM
//
// After decrypt:
//   plain[0]     = N (pad length 0..255)
//   plain[N+17]  = 4-byte BE payload length
//   plain[N+21..N+21+len] = deflated JSON payload
//   inflate(payload) → Envelope { meta, config }
// ============================================================================

val MAGIC = byteArrayOf(0xA7.toByte(), 0x19, 0xD2.toByte(), 0x4C)
const val KDF_PREFIX = "REESE-CUSTOM/RSE5|"
const val SIG_SUFFIX = "|SIG:"
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

// ---- credential prompting -------------------------------------------------

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
    // fallback when no tty (e.g. piped input)
    return prompt(label)
}

// ---- lock-mode description -------------------------------------------------

fun describeFlags(flags: Int): String {
    val hwid = (flags and 0x01) != 0
    val pw   = (flags and 0x02) != 0
    val sig  = (flags and 0x04) != 0
    val parts = mutableListOf<String>()
    if (hwid) parts += "HWID-locked"
    if (pw)   parts += "password-locked"
    if (sig)  parts += "signature-bound"
    if (parts.isEmpty()) parts += "unlocked"
    return parts.joinToString(", ")
}

// ---- main decode -----------------------------------------------------------

fun decodeRt(path: String): String {
    val bytes = File(path).readBytes()
    require(bytes.size >= 50) { "file too small: ${bytes.size}" }
    for (i in MAGIC.indices) require(bytes[i] == MAGIC[i]) { "not an RT file (magic mismatch)" }

    val version = bytes[4].toInt() and 0xFF
    val flags   = bytes[5].toInt() and 0xFF
    require(version == 0xC4 || version == 0xC5) {
        "expected RSE5 (0xc4 or 0xc5), got 0x%02x".format(version)
    }
    if (version == 0xC5) println("version  : 0x%02x (RSE5.1 / locked variant)".format(version))

    val hwidLocked = (flags and 0x01) != 0
    val pwLocked   = (flags and 0x02) != 0
    val sigBound   = (flags and 0x04) != 0

    println("=== $path ===")
    println("size     : ${bytes.size} bytes")
    println("version  : 0x%02x (RSE5)".format(version))
    println("flags    : 0x%02x  %s".format(flags, describeFlags(flags)))

    val salt = bytes.copyOfRange(6, 22)
    val iv   = bytes.copyOfRange(22, 34)
    val aad  = bytes.copyOfRange(0, 34)
    val ct   = bytes.copyOfRange(34, bytes.size - 16)
    val tag  = bytes.copyOfRange(bytes.size - 16, bytes.size)
    val ctAndTag = ct + tag

    println("salt     : ${salt.toHex()}")
    println("iv       : ${iv.toHex()}")
    println("ct+tag   : ${ctAndTag.size} bytes")

    // signer candidates (sig-bound files need the original APK cert hash)
    val signerCandidates = listOf(
        "D834BF8D60BFEA09A80A51CCD1A77DE3EF966E7833EBB2D0B8DC1F750E38BBA7",
        "A40DA80A59D170CAA950CF15C18C454D47A39B26989D8B640ECD745BA71BF5DC",
        "",
    )

    // ---- collect credentials once, retry on GCM failure --------------------
    var hwid = ""
    var password = ""

    if (hwidLocked) {
        println()
        println("This file is locked to a device (HWID).")
        println("You need the original device's HWID string, e.g. John-Reese-AENB-K4CR-ZSVX-G5WA")
        hwid = prompt("Enter HWID: ").uppercase()
    }
    if (pwLocked) {
        println()
        println("This file is password-protected.")
        password = promptPassword("Enter password: ")
    }

    var plain: ByteArray? = null
    var usedSigner = ""

    while (true) {
        val kdfBase = KDF_PREFIX + hwid + "|" + password
        val candidates: List<Pair<String, String>> =
            if (sigBound) signerCandidates.map { it to (kdfBase + SIG_SUFFIX + it) }
            else listOf("" to kdfBase)

        plain = null
        usedSigner = ""
        for ((signer, kdfInput) in candidates) {
            if (sigBound) println("  trying signer=${signer.take(16)}… kdfInput=\"${kdfInput}\"")
            else          println("  kdfInput=\"${kdfInput}\"")
            val key = pbkdf2(kdfInput.toByteArray(StandardCharsets.UTF_8), salt, ITER, KEY_LEN)
            val result = try { aesGcmDecrypt(key, iv, aad, ctAndTag) } catch (_: Exception) { null }
            if (result != null) {
                plain = result
                usedSigner = signer
                break
            }
        }

        if (plain != null) break

        // GCM failed on every candidate — wrong credentials (or unknown build)
        println()
        if (hwidLocked || pwLocked) {
            println("[!] Decryption failed — wrong HWID/password (or unknown signer).")
            val again = prompt("Retry with different credentials? (y/n): ").lowercase()
            if (again != "y" && again != "yes") {
                error("aborted by user")
            }
            if (hwidLocked) {
                hwid = prompt("Enter HWID: ").uppercase()
            }
            if (pwLocked) {
                password = promptPassword("Enter password: ")
            }
        } else {
            error("decryption failed — file was made by an unknown build (no matching signer)")
        }
    }

    println("signer   : ${if (usedSigner.isEmpty()) "(none)" else usedSigner}")
    println("plain    : ${plain.size} bytes (decrypted)")

    val deflated = try { applyF(plain) } catch (e: Exception) {
        throw IllegalStateException("F() failed: ${e.message}")
    }
    println("payload  : ${deflated.size} bytes (deflated)")

    val jsonBytes = inflate(deflated)
    val json = String(jsonBytes, StandardCharsets.UTF_8)
    require(json.startsWith("{")) { "payload doesn't start with '{' — got: ${json.take(80)}" }
    println("json     : ${json.length} chars")

    val basePath = path.removeSuffix(".RT").removeSuffix(".rt")
    File(basePath + ".json").writeText(prettyJson(json))
    File(basePath + ".clean.json").writeText(scrubNoisy(json))

    return json
}

fun scrubNoisy(json: String): String {
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
                sb.append(c); depth++
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
