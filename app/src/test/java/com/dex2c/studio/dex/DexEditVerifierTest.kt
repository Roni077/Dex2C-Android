package com.dex2c.studio.dex

import com.dex2c.studio.apk.ApkSigningKeystore
import java.io.ByteArrayInputStream
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.Base64
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class DexEditVerifierTest {

  private fun createDummyClass(descriptor: String): DexClassInfo {
    return DexClassInfo(
      classIndex = 0,
      descriptor = descriptor,
      fullName = descriptor.removePrefix("L").removeSuffix(";").replace('/', '.'),
      simpleName = descriptor.substringAfterLast('/').removeSuffix(";"),
      packageName = descriptor.removePrefix("L").substringBeforeLast('/', "").replace('/', '.'),
      superclass = "Ljava/lang/Object;",
      interfaces = emptyList(),
      sourceFile = null,
      accessFlags = 1,
      directMethods = emptyList(),
      virtualMethods = emptyList(),
      instanceFields = emptyList(),
      staticFields = emptyList(),
    )
  }

  private fun createDummyDex(classes: List<DexClassInfo>): DexParsedFile {
    val hdr = DexHeaderInfo(
      magic = "dex\n035",
      version = "035",
      checksum = 1234L,
      sha1Hex = "0123456789abcdef",
      fileSize = 100,
      endianTag = 0x12345678L,
      stringIdsSize = 1,
      typeIdsSize = 1,
      protoIdsSize = 1,
      fieldIdsSize = 1,
      methodIdsSize = 1,
      classDefsSize = classes.size,
    )
    return DexParsedFile(
      sourceLabel = "test.apk",
      entryName = "classes.dex",
      rawBytes = ByteArray(100),
      header = hdr,
      classes = classes,
    )
  }

  @Test
  fun testVerifyClassPresentSuccess() {
    val c1 = createDummyClass("Lcom/example/TargetClass;")
    val dex = createDummyDex(listOf(c1))

    val result = DexEditVerifier.verifyClassPresent(dex, "Lcom/example/TargetClass;")
    assertNull(result)
  }

  @Test
  fun testVerifyClassPresentFailsWhenAbsent() {
    val c1 = createDummyClass("Lcom/example/OtherClass;")
    val dex = createDummyDex(listOf(c1))

    val result = DexEditVerifier.verifyClassPresent(dex, "Lcom/example/TargetClass;")
    assertNotNull(result)
    assertTrue(result!!.contains("Lcom/example/TargetClass;"))
  }

  @Test
  fun testVerifyClassesDeletedSuccess() {
    val c1 = createDummyClass("Lcom/example/RetainedClass;")
    val dex = createDummyDex(listOf(c1))

    val result = DexEditVerifier.verifyClassesDeleted(
      dex,
      setOf("Lcom/example/DeletedClass1;", "Lcom/example/DeletedClass2;"),
    )
    assertNull(result)
  }

  @Test
  fun testVerifyClassesDeletedFailsWhenClassRemains() {
    val c1 = createDummyClass("Lcom/example/DeletedClass1;")
    val c2 = createDummyClass("Lcom/example/RetainedClass;")
    val dex = createDummyDex(listOf(c1, c2))

    val result = DexEditVerifier.verifyClassesDeleted(
      dex,
      setOf("Lcom/example/DeletedClass1;"),
    )
    assertNotNull(result)
    assertTrue(result!!.contains("Failed to remove 1 class(es)"))
  }

  @Test
  fun testVerifyReplacementCount() {
    assertNull(DexEditVerifier.verifyReplacementCount(5, "oldString"))
    val resultZero = DexEditVerifier.verifyReplacementCount(0, "oldString")
    assertNotNull(resultZero)
    assertTrue(resultZero!!.contains("oldString"))

    val resultNegative = DexEditVerifier.verifyReplacementCount(-1, "oldString")
    assertNotNull(resultNegative)
  }

  @Test
  fun testVerifyCompiledClassBytecodeValidAndTruncated() {
    val c1 = createDummyClass("Lcom/example/TargetClass;")
    val validHeader = createDummyDex(listOf(c1)).let { base ->
      val raw = ByteArray(0x80)
      "dex\n039\u0000".toByteArray(Charsets.US_ASCII).copyInto(raw, 0)
      base.copy(rawBytes = raw)
    }
    assertNull(
      DexEditVerifier.verifyCompiledClassBytecode(
        validHeader.rawBytes,
        validHeader,
        "Lcom/example/TargetClass;",
      )
    )
    val invalidHeader = validHeader.copy(rawBytes = ByteArray(16))
    assertNotNull(
      DexEditVerifier.verifyCompiledClassBytecode(
        invalidHeader.rawBytes,
        invalidHeader,
        "Lcom/example/TargetClass;",
      )
    )
    assertNotNull(
      DexEditVerifier.verifyCompiledClassBytecode(
        validHeader.rawBytes,
        validHeader,
        "Lcom/example/MissingClass;",
      )
    )
  }

  @Test
  fun testEphemeralDebugKeystoreAndPemLoaderProduceValidX509Cert() {
    val mat = ApkSigningKeystore.generateEphemeralRsaDebugKeystore()
    assertTrue(mat.privateKeyPkcs8Der.isNotEmpty())
    assertTrue(mat.certificateX509Der.isNotEmpty())

    val cf = CertificateFactory.getInstance("X.509")
    val x509 = cf.generateCertificate(ByteArrayInputStream(mat.certificateX509Der)) as X509Certificate
    x509.verify(x509.publicKey)
    assertTrue(x509.subjectX500Principal.name.contains("Dex2C Studio Debug"))

    val pkPem =
      ("-----BEGIN PRIVATE KEY-----\n" +
        Base64.getEncoder().encodeToString(mat.privateKeyPkcs8Der) +
        "\n-----END PRIVATE KEY-----\n").toByteArray(Charsets.US_ASCII)
    val certPem =
      ("-----BEGIN CERTIFICATE-----\n" +
        Base64.getEncoder().encodeToString(mat.certificateX509Der) +
        "\n-----END CERTIFICATE-----\n").toByteArray(Charsets.US_ASCII)

    val loaded = ApkSigningKeystore.loadCustomKeystore(pkPem, certPem, "Custom Test")
    assertEquals("Custom Test", loaded.label)
    assertTrue(loaded.privateKeyPkcs8Der.contentEquals(mat.privateKeyPkcs8Der))
    assertTrue(loaded.certificateX509Der.contentEquals(mat.certificateX509Der))
  }
}
