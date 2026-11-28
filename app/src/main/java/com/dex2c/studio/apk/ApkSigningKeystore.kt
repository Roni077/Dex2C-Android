package com.dex2c.studio.apk

import android.content.Context
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.File
import java.security.KeyPairGenerator
import java.security.SecureRandom
import java.security.Signature
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.Base64

data class ApkSigningMaterial(
  val privateKeyPkcs8Der: ByteArray,
  val certificateX509Der: ByteArray,
  val label: String,
)

/**
 * Pure Android/JVM persistent debug RSA-2048 keystore generator and custom `.pk8`/`.der` loader.
 * Eliminates any dependency on `ring`, `rcgen`, `$HOME`, or `BouncyCastle` on Android or host JVMs.
 */
object ApkSigningKeystore {

  private const val KEYSTORE_DIR = "dex2c_signing"
  private const val DEBUG_PK8_NAME = "debug_rsa2048.pk8"
  private const val DEBUG_CERT_NAME = "debug_rsa2048.der"

  /**
   * Returns a persistent debug RSA-2048 `(privateKeyPkcs8Der, certificateX509Der)` pair stored
   * under [Context.getFilesDir]. Generates and validates a fresh self-signed X.509 v3 certificate
   * on first use. Returns null only if keystore I/O or security providers fail.
   */
  fun getOrCreateDebugKeystore(context: Context): ApkSigningMaterial? {
    return runCatching {
      val dir = File(context.filesDir, KEYSTORE_DIR).apply { mkdirs() }
      val pkFile = File(dir, DEBUG_PK8_NAME)
      val certFile = File(dir, DEBUG_CERT_NAME)

      if (pkFile.exists() && certFile.exists()) {
        val pk = pkFile.readBytes()
        val cert = certFile.readBytes()
        if (isValidX509Cert(cert) && pk.isNotEmpty()) {
          return ApkSigningMaterial(pk, cert, "Debug RSA-2048 (Persistent)")
        }
      }

      val generated = generateEphemeralRsaDebugKeystore()
      pkFile.writeBytes(generated.privateKeyPkcs8Der)
      certFile.writeBytes(generated.certificateX509Der)
      generated.copy(label = "Debug RSA-2048 (Persistent)")
    }.getOrNull()
  }

  /**
   * Generates a standalone RSA-2048 PKCS#8 private key and self-signed X.509 v3 DER certificate
   * without writing to disk (useful for tests and stateless fallback).
   */
  fun generateEphemeralRsaDebugKeystore(): ApkSigningMaterial {
    val kpg = KeyPairGenerator.getInstance("RSA")
    kpg.initialize(2048, SecureRandom())
    val pair = kpg.generateKeyPair()
    val pkcs8 = pair.private.encoded
    val spkiDer = pair.public.encoded

    val serial = ByteArray(8).also { SecureRandom().nextBytes(it) }
    serial[0] = (serial[0].toInt() and 0x7F).toByte().let { if (it == 0.toByte()) 1 else it }

    // SHA256withRSA OID: 1.2.840.113549.1.1.11 + NULL
    val sha256RsaAlgId =
      derSequence(
        derOid(byteArrayOf(0x2A, 0x86.toByte(), 0x48, 0x86.toByte(), 0xF7.toByte(), 0x0D, 0x01, 0x01, 0x0B)),
        derNull(),
      )

    // CN=Dex2C Studio Debug, O=Dex2C Studio
    val rdnCn = derSet(derSequence(derOid(byteArrayOf(0x55, 0x04, 0x03)), derUtf8("Dex2C Studio Debug")))
    val rdnOrg = derSet(derSequence(derOid(byteArrayOf(0x55, 0x04, 0x0A)), derUtf8("Dex2C Studio")))
    val nameDer = derSequence(rdnCn, rdnOrg)

    // Validity: 2025-01-01 to 2049-12-31 (UTCTime YYMMDDHHMMSSZ)
    val validityDer = derSequence(derUtcTime("250101000000Z"), derUtcTime("491231235959Z"))

    // BasicConstraints (2.5.29.19) = CA:FALSE
    val basicConstraintsExt =
      derSequence(
        derOid(byteArrayOf(0x55, 0x1D, 0x13)),
        derOctetString(derSequence()),
      )
    val extensions = derTagged(0xA3, derSequence(basicConstraintsExt))

    val tbsCert =
      derSequence(
        derTagged(0xA0, derIntegerBytes(byteArrayOf(0x02))), // v3
        derIntegerBytes(serial),
        sha256RsaAlgId,
        nameDer,
        validityDer,
        nameDer,
        spkiDer,
        extensions,
      )

    val signatureBytes =
      Signature.getInstance("SHA256withRSA").run {
        initSign(pair.private)
        update(tbsCert)
        sign()
      }

    val fullCertDer = derSequence(tbsCert, sha256RsaAlgId, derBitString(signatureBytes))
    check(isValidX509Cert(fullCertDer)) { "Generated X.509 certificate failed self-validation" }

    return ApkSigningMaterial(
      privateKeyPkcs8Der = pkcs8,
      certificateX509Der = fullCertDer,
      label = "Debug RSA-2048",
    )
  }

  /**
   * Loads a user-supplied custom keystore from raw DER or PEM bytes (`.pk8` + `.x509.pem`/`.der`).
   */
  fun loadCustomKeystore(
    privateKeyBytes: ByteArray,
    certificateBytes: ByteArray,
    label: String = "Custom PKCS#8 Keystore",
  ): ApkSigningMaterial {
    val pkDer = decodePemOrDer(privateKeyBytes)
    val certDer = decodePemOrDer(certificateBytes)
    require(pkDer.isNotEmpty()) { "Private key bytes cannot be empty." }
    require(isValidX509Cert(certDer)) { "Certificate is not a valid X.509 DER/PEM certificate." }
    return ApkSigningMaterial(pkDer, certDer, label)
  }

  internal fun isValidX509Cert(certDer: ByteArray): Boolean {
    return runCatching {
      val factory = CertificateFactory.getInstance("X.509")
      val cert = factory.generateCertificate(ByteArrayInputStream(certDer)) as X509Certificate
      cert.verify(cert.publicKey)
      true
    }.getOrDefault(false)
  }

  private fun decodePemOrDer(raw: ByteArray): ByteArray {
    val text = raw.toString(Charsets.US_ASCII)
    if (!text.contains("-----BEGIN ")) return raw
    val body =
      text
        .lines()
        .filter { line -> !line.startsWith("-----BEGIN ") && !line.startsWith("-----END ") }
        .joinToString("")
        .replace(Regex("\\s+"), "")
    return Base64.getDecoder().decode(body)
  }

  private fun derTag(tag: Int, content: ByteArray): ByteArray {
    val out = ByteArrayOutputStream(2 + content.size + 4)
    out.write(tag)
    val len = content.size
    when {
      len < 0x80 -> out.write(len)
      len <= 0xFF -> {
        out.write(0x81)
        out.write(len)
      }
      len <= 0xFFFF -> {
        out.write(0x82)
        out.write((len ushr 8) and 0xFF)
        out.write(len and 0xFF)
      }
      else -> {
        out.write(0x83)
        out.write((len ushr 16) and 0xFF)
        out.write((len ushr 8) and 0xFF)
        out.write(len and 0xFF)
      }
    }
    out.write(content)
    return out.toByteArray()
  }

  private fun concat(vararg parts: ByteArray): ByteArray {
    val out = ByteArrayOutputStream()
    parts.forEach { out.write(it) }
    return out.toByteArray()
  }

  private fun derSequence(vararg parts: ByteArray) = derTag(0x30, concat(*parts))
  private fun derSet(vararg parts: ByteArray) = derTag(0x31, concat(*parts))
  private fun derTagged(tag: Int, inner: ByteArray) = derTag(tag, inner)
  private fun derOid(encodedOidBody: ByteArray) = derTag(0x06, encodedOidBody)
  private fun derNull() = byteArrayOf(0x05, 0x00)
  private fun derUtf8(s: String) = derTag(0x0C, s.toByteArray(Charsets.UTF_8))
  private fun derUtcTime(s: String) = derTag(0x17, s.toByteArray(Charsets.US_ASCII))
  private fun derOctetString(content: ByteArray) = derTag(0x04, content)
  private fun derIntegerBytes(unsignedPositive: ByteArray) = derTag(0x02, unsignedPositive)
  private fun derBitString(bytes: ByteArray) = derTag(0x03, concat(byteArrayOf(0x00), bytes))
}
