package com.dex2c.studio

import android.content.Context
import android.net.Uri
import androidx.test.core.app.ApplicationProvider
import com.dex2c.studio.apk.ApkMetadataInspector
import com.dex2c.studio.apk.ApkSigningKeystore
import com.dex2c.studio.apk.BinarySourceType
import com.dex2c.studio.dex.DexParser
import com.dex2c.studio.dex.SmaliDexCompiler
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.FileOutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [36])
class ApkInspectorTest {

  @Test
  fun inspectMultiDexApkDetectsDexContainersAndAbis() {
    val context = ApplicationProvider.getApplicationContext<Context>()
    val tempApk = File.createTempFile("sample_multi_", ".apk", context.cacheDir)
    try {
      ZipOutputStream(FileOutputStream(tempApk)).use { zos ->
        zos.putNextEntry(ZipEntry("classes.dex"))
        zos.write(ByteArray(32) { 0x01 })
        zos.closeEntry()

        zos.putNextEntry(ZipEntry("classes2.dex"))
        zos.write(ByteArray(64) { 0x02 })
        zos.closeEntry()

        zos.putNextEntry(ZipEntry("lib/arm64-v8a/libdemo.so"))
        zos.write(byteArrayOf(0x7F, 'E'.code.toByte(), 'L'.code.toByte(), 'F'.code.toByte()))
        zos.closeEntry()

        zos.putNextEntry(ZipEntry("lib/armeabi-v7a/libdemo.so"))
        zos.write(byteArrayOf(0x7F, 'E'.code.toByte(), 'L'.code.toByte(), 'F'.code.toByte()))
        zos.closeEntry()
      }

      val preview = ApkMetadataInspector.inspectFromFilePath(context, tempApk.absolutePath, "sample.apk")
      assertFalse(preview.isSingleDex)
      assertEquals(BinarySourceType.INSTALLED_APK, preview.sourceType)
      assertEquals(listOf("classes.dex", "classes2.dex"), preview.dexEntries.map { it.entryName })
      assertEquals(listOf("arm64-v8a", "armeabi-v7a"), preview.nativeAbis)
      assertTrue(preview.dexByteMap.containsKey("classes2.dex"))
    } finally {
      tempApk.delete()
    }
  }

  @Test
  fun inspectSafUriPopulatesFullManifestMetadataWithoutPackageManager() {
    val context = ApplicationProvider.getApplicationContext<Context>()
    val tempApk = File.createTempFile("saf_meta_", ".apk", context.cacheDir)
    try {
      val manifestXml =
        """
        <manifest xmlns:android="http://schemas.android.com/apk/res/android"
            package="com.example.safdemo"
            android:versionCode="17"
            android:versionName="2.5.0">
          <uses-sdk android:minSdkVersion="24" android:targetSdkVersion="36" />
          <uses-permission android:name="android.permission.CAMERA" />
          <application android:label="Saf Demo" android:name=".DemoApplication" />
        </manifest>
        """.trimIndent().toByteArray(Charsets.UTF_8)

      ZipOutputStream(FileOutputStream(tempApk)).use { zos ->
        zos.putNextEntry(ZipEntry("AndroidManifest.xml"))
        zos.write(manifestXml)
        zos.closeEntry()
        zos.putNextEntry(ZipEntry("classes.dex"))
        zos.write(buildMinimalDexBytes("Lcom/example/safdemo/Main;", dexVersion = "039"))
        zos.closeEntry()
        zos.putNextEntry(ZipEntry("META-INF/CERT.RSA"))
        zos.write(byteArrayOf(0x30, 0x00))
        zos.closeEntry()
      }

      val preview =
        ApkMetadataInspector.inspectFromUri(context, Uri.fromFile(tempApk), "saf_demo.apk")
      assertEquals("com.example.safdemo", preview.packageName)
      assertEquals("Saf Demo", preview.appLabel)
      assertEquals("com.example.safdemo.DemoApplication", preview.applicationName)
      assertEquals("2.5.0", preview.versionName)
      assertEquals(17L, preview.versionCode)
      assertEquals(24, preview.minSdk)
      assertEquals(36, preview.targetSdk)
      assertEquals(1, preview.permissionsCount)
      assertTrue("v1" in preview.signatureSchemes)
    } finally {
      tempApk.delete()
    }
  }

  @Test
  fun inspectApkmBundleUnwrapsBaseApkAndCollectsSplitAbis() {
    val context = ApplicationProvider.getApplicationContext<Context>()
    val tempApkm = File.createTempFile("bundle_", ".apkm", context.cacheDir)
    try {
      val baseApkOut = ByteArrayOutputStream()
      ZipOutputStream(baseApkOut).use { zos ->
        zos.putNextEntry(ZipEntry("AndroidManifest.xml"))
        zos.write(
          """<manifest package="com.example.bundle" android:versionCode="99" android:versionName="4.2"><uses-sdk android:minSdkVersion="26" android:targetSdkVersion="35"/><application android:label="Bundle App" android:name="com.example.bundle.MyApp"/></manifest>"""
            .toByteArray(Charsets.UTF_8)
        )
        zos.closeEntry()
        zos.putNextEntry(ZipEntry("classes.dex"))
        zos.write(buildMinimalDexBytes("Lcom/example/bundle/Entry;", dexVersion = "039"))
        zos.closeEntry()
      }

      val splitAbiOut = ByteArrayOutputStream()
      ZipOutputStream(splitAbiOut).use { zos ->
        zos.putNextEntry(ZipEntry("lib/arm64-v8a/libengine.so"))
        zos.write(byteArrayOf(0x7F, 'E'.code.toByte(), 'L'.code.toByte(), 'F'.code.toByte()))
        zos.closeEntry()
      }

      ZipOutputStream(FileOutputStream(tempApkm)).use { zos ->
        zos.putNextEntry(ZipEntry("base.apk"))
        zos.write(baseApkOut.toByteArray())
        zos.closeEntry()
        zos.putNextEntry(ZipEntry("split_config.arm64_v8a.apk"))
        zos.write(splitAbiOut.toByteArray())
        zos.closeEntry()
      }

      val preview =
        ApkMetadataInspector.inspectFromFilePath(context, tempApkm.absolutePath, "bundle.apkm")
      assertTrue(preview.isApkmBundle)
      assertEquals("com.example.bundle", preview.packageName)
      assertEquals("Bundle App", preview.appLabel)
      assertEquals("com.example.bundle.MyApp", preview.applicationName)
      assertEquals(99L, preview.versionCode)
      assertEquals(listOf("arm64-v8a"), preview.nativeAbis)
      assertEquals(listOf("classes.dex"), preview.dexEntries.map { it.entryName })
    } finally {
      tempApkm.delete()
    }
  }

  @Test
  fun inspectDex041ContainerSplitsMultiSectionDex() {
    val context = ApplicationProvider.getApplicationContext<Context>()
    val dex1 = buildMinimalDexBytes("Lcom/example/SectionOne;", dexVersion = "041")
    val dex2 = buildMinimalDexBytes("Lcom/example/SectionTwo;", dexVersion = "041")
    relocateMinimalDexOffsets(dex2, dex1.size)

    val container = dex1 + dex2
    val (entries, byteMap) = DexParser.extractDexContainers(container, "classes.dex")
    assertEquals(listOf("classes.dex!classes1.dex", "classes.dex!classes2.dex"), entries.map { it.entryName })
    assertTrue(entries.all { it.isSplitFromDex041 })

    val parsed1 = DexParser.parseDex(byteMap.getValue("classes.dex!classes1.dex"), "container", "classes.dex!classes1.dex")
    val parsed2 = DexParser.parseDex(byteMap.getValue("classes.dex!classes2.dex"), "container", "classes.dex!classes2.dex")
    assertEquals("Lcom/example/SectionOne;", parsed1.classes.first().descriptor)
    assertEquals("Lcom/example/SectionTwo;", parsed2.classes.first().descriptor)

    val tempDex = File.createTempFile("multi041_", ".dex", context.cacheDir)
    try {
      tempDex.writeBytes(container)
      val preview = ApkMetadataInspector.inspectFromFilePath(context, tempDex.absolutePath, "multi041.dex")
      assertTrue(preview.hasDex041Container)
      assertFalse(preview.isSingleDex)
      assertEquals(2, preview.dexEntries.size)
    } finally {
      tempDex.delete()
    }
  }

  @Test
  fun persistentDebugKeystoreAndRepackFallbackWorkEndToEnd() {
    val context = ApplicationProvider.getApplicationContext<Context>()
    val first = ApkSigningKeystore.getOrCreateDebugKeystore(context)
    val second = ApkSigningKeystore.getOrCreateDebugKeystore(context)
    assertTrue(first != null && second != null)
    assertTrue(first!!.privateKeyPkcs8Der.contentEquals(second!!.privateKeyPkcs8Der))
    assertTrue(first.certificateX509Der.contentEquals(second.certificateX509Der))

    val out = ByteArrayOutputStream()
    val signResult =
      SmaliDexCompiler.repackAndAlignSignApk(
        originalApkStream = null,
        patchedDexByEntryName = mapOf("classes.dex" to buildMinimalDexBytes("Lcom/example/SignedDemo;", "039")),
        outputStream = out,
        privateKeyDer = first.privateKeyPkcs8Der,
        certificateDer = first.certificateX509Der,
      )
    assertEquals(1, signResult.entryCount)
    assertTrue(out.toByteArray().isNotEmpty())
  }

  private fun buildMinimalDexBytes(classDescriptor: String, dexVersion: String): ByteArray {
    return buildMinimalDexBytesAligned(listOf(classDescriptor, "Ljava/lang/Object;"), dexVersion)
  }

  private fun buildMinimalDexBytesAligned(strings: List<String>, dexVersion: String): ByteArray {
    val strDataStream = ByteArrayOutputStream()
    val strDataOffsets = mutableListOf<Int>()
    val stringDataBase = 0xA8
    strings.forEach { s ->
      strDataOffsets += stringDataBase + strDataStream.size()
      val utf8 = s.toByteArray(Charsets.UTF_8)
      strDataStream.write(utf8.size)
      strDataStream.write(utf8)
      strDataStream.write(0)
    }
    val totalSize = stringDataBase + strDataStream.size()
    val buf = ByteBuffer.allocate(totalSize).order(ByteOrder.LITTLE_ENDIAN)
    buf.put("dex\n$dexVersion\u0000".toByteArray(Charsets.US_ASCII))
    buf.putInt(0x20, totalSize)
    buf.putInt(0x24, 0x70)
    buf.putInt(0x28, 0x12345678)
    buf.putInt(0x38, strings.size)
    buf.putInt(0x3C, 0x70)
    buf.putInt(0x40, strings.size)
    buf.putInt(0x44, 0x78)
    buf.putInt(0x60, 1)
    buf.putInt(0x64, 0x80)

    strDataOffsets.forEachIndexed { i, off -> buf.putInt(0x70 + i * 4, off) }
    buf.putInt(0x78, 0)
    buf.putInt(0x7C, 1)
    buf.putInt(0x80, 0) // classIdx
    buf.putInt(0x84, 1) // accessFlags
    buf.putInt(0x88, 1) // superclassIdx
    buf.putInt(0x8C, 0)
    buf.putInt(0x90, -1)
    buf.putInt(0x94, 0)
    buf.putInt(0x98, 0)
    buf.putInt(0x9C, 0)

    buf.position(stringDataBase)
    buf.put(strDataStream.toByteArray())
    return buf.array()
  }

  private fun relocateMinimalDexOffsets(dex: ByteArray, containerOffset: Int) {
    val buf = ByteBuffer.wrap(dex).order(ByteOrder.LITTLE_ENDIAN)
    val stringIdsSize = buf.getInt(0x38)
    val stringIdsOff = buf.getInt(0x3C)
    for (i in 0 until stringIdsSize) {
      val pos = stringIdsOff + i * 4
      buf.putInt(pos, buf.getInt(pos) + containerOffset)
    }
    buf.putInt(0x3C, stringIdsOff + containerOffset)
    buf.putInt(0x44, buf.getInt(0x44) + containerOffset)
    buf.putInt(0x64, buf.getInt(0x64) + containerOffset)
  }
}
