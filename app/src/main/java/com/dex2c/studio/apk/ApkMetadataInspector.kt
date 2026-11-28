package com.dex2c.studio.apk

import android.content.Context
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import com.dex2c.studio.dex.ApkDexEntry
import com.dex2c.studio.dex.DexParser
import com.dex2c.studio.dex.inferDominantDexPackageName
import com.dex2c.studio.nativeengine.DexNativeEngine
import java.io.BufferedInputStream
import java.io.ByteArrayInputStream
import java.io.File
import java.io.FileInputStream
import java.io.InputStream
import java.io.RandomAccessFile
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.zip.ZipFile
import java.util.zip.ZipInputStream

object ApkMetadataInspector {

  fun inspectFromUri(context: Context, uri: Uri, displayName: String): ApkStagingPreview {
    val totalSize = queryUriByteSize(context, uri)
    val stream =
      context.contentResolver.openInputStream(uri)
        ?: throw IllegalArgumentException("Unable to read \"$displayName\". Permission may have expired.")
    return stream.use { rawStream ->
      inspectStream(
        context = context,
        inputStream = rawStream,
        knownTotalBytes = totalSize,
        sourceLabel = displayName,
        sourceRef = uri.toString(),
        sourceType = BinarySourceType.SAF_URI,
        knownApp = null,
      )
    }
  }

  fun inspectMultipleUris(context: Context, items: List<Pair<Uri, String>>): ApkStagingPreview {
    if (items.isEmpty()) {
      throw IllegalArgumentException("No files selected.")
    }
    if (items.size == 1) {
      val (uri, name) = items.first()
      return inspectFromUri(context, uri, name)
    }

    val entries = mutableListOf<ApkDexEntry>()
    val dexMap = linkedMapOf<String, ByteArray>()
    val abis = linkedSetOf<String>()
    var manifestBytes: ByteArray? = null
    var arscBytes: ByteArray? = null
    var hasDex041 = false
    var totalBytes = 0L

    fun registerEntry(desiredName: String, dexBytes: ByteArray, isSplit041: Boolean = false) {
      var candidate = desiredName
      var suffix = 2
      while (candidate in dexMap) {
        val dot = desiredName.lastIndexOf('.')
        candidate =
          if (dot > 0) "${desiredName.substring(0, dot)} ($suffix)${desiredName.substring(dot)}"
          else "$desiredName ($suffix)"
        suffix++
      }
      entries += ApkDexEntry(candidate, dexBytes.size, isSplitFromDex041 = isSplit041)
      dexMap[candidate] = dexBytes
    }

    items.forEach { (uri, displayName) ->
      val uriSize = queryUriByteSize(context, uri)
      val stream =
        context.contentResolver.openInputStream(uri)
          ?: throw IllegalArgumentException("Unable to read \"$displayName\".")
      stream.use { rawInput ->
        val buffered = BufferedInputStream(rawInput, 32 * 1024)
        buffered.mark(16)
        val header = ByteArray(8)
        val headerRead = buffered.read(header)
        buffered.reset()

        if (
          headerRead >= 4 &&
            header[0] == 'd'.code.toByte() &&
            header[1] == 'e'.code.toByte() &&
            header[2] == 'x'.code.toByte() &&
            header[3] == '\n'.code.toByte()
        ) {
          val bytes = buffered.readBytes()
          totalBytes += if (uriSize > 0L) uriSize else bytes.size.toLong()
          val entryName = if (displayName.endsWith(".dex", ignoreCase = true)) displayName else "$displayName.dex"
          val split = DexParser.splitDex041ContainerIfNeeded(entryName, bytes)
          val isSplit = split.size > 1
          if (isSplit) hasDex041 = true
          split.forEach { (n, b) -> registerEntry(n, b, isSplit) }
        } else {
          var foundInsideZip = false
          var extractedBytesSum = 0L
          ZipInputStream(buffered).use { zis ->
            while (true) {
              val entry = zis.nextEntry ?: break
              val name = entry.name
              if (!entry.isDirectory) {
                if (name.endsWith(".dex", ignoreCase = true)) {
                  foundInsideZip = true
                  val dexBytes = zis.readBytes()
                  extractedBytesSum += dexBytes.size.toLong()
                  val prefix = "${displayName.substringBeforeLast('.')}/$name"
                  val split = DexParser.splitDex041ContainerIfNeeded(prefix, dexBytes)
                  val isSplit = split.size > 1
                  if (isSplit) hasDex041 = true
                  split.forEach { (n, b) -> registerEntry(n, b, isSplit) }
                } else if (name.equals("AndroidManifest.xml", ignoreCase = true) && manifestBytes == null) {
                  val mb = zis.readBytes()
                  extractedBytesSum += mb.size.toLong()
                  manifestBytes = mb
                } else if (name.equals("resources.arsc", ignoreCase = true) && arscBytes == null) {
                  val ab = zis.readBytes()
                  extractedBytesSum += ab.size.toLong()
                  arscBytes = ab
                } else if (name.startsWith("lib/") && name.endsWith(".so")) {
                  val parts = name.split('/')
                  if (parts.size >= 3) abis += parts[1]
                }
              }
              zis.closeEntry()
            }
          }
          totalBytes += if (uriSize > 0L) uriSize else extractedBytesSum
          if (!foundInsideZip) {
            throw IllegalArgumentException("\"$displayName\" is not a valid DEX or APK archive.")
          }
        }
      }
    }

    if (entries.isEmpty()) {
      throw IllegalArgumentException("No valid DEX entries found in the selected files.")
    }

    val manifestSummary = manifestBytes?.let { extractManifestSummary(it, arscBytes) }
    var detectedPkgName = manifestSummary?.packageName
    if (detectedPkgName.isNullOrBlank()) {
      detectedPkgName =
        dexMap.entries.firstNotNullOfOrNull { (entryName, dexBytes) ->
          inferPackageNameFromDexBytes(dexBytes, entryName)
        }
    }

    return ApkStagingPreview(
      sourceLabel = "${items.size} DEX files",
      sourceRef = items.joinToString("|") { it.first.toString() },
      sourceType = BinarySourceType.SAF_URI,
      packageName = detectedPkgName,
      appLabel = manifestSummary?.appLabel ?: "${entries.size} Selected DEX Binaries",
      versionName = manifestSummary?.versionName ?: "${entries.size} DEX files",
      versionCode = manifestSummary?.versionCode,
      minSdk = manifestSummary?.minSdk,
      targetSdk = manifestSummary?.targetSdk,
      totalByteSize = totalBytes,
      nativeAbis = abis.sorted(),
      dexEntries = entries,
      dexByteMap = dexMap,
      isSingleDex = false,
      iconBitmap = null,
      applicationName = manifestSummary?.applicationName,
      permissionsCount = manifestSummary?.permissions?.size ?: 0,
      hasDex041Container = hasDex041,
      arscBytes = arscBytes,
    )
  }

  fun inspectFromInstalledApp(context: Context, app: InstalledAppItem): ApkStagingPreview {
    val file = File(app.apkPath)
    if (!file.exists() || !file.canRead()) {
      throw IllegalArgumentException("APK for ${app.packageName} is no longer accessible.")
    }
    return inspectLocalFile(
      context = context,
      file = file,
      sourceLabel = "${app.appLabel}.apk",
      sourceRef = app.apkPath,
      sourceType = BinarySourceType.INSTALLED_APK,
      knownApp = app,
    )
  }

  fun inspectFromFilePath(context: Context, path: String, fallbackLabel: String): ApkStagingPreview {
    val file = File(path)
    if (!file.exists() || !file.canRead()) {
      throw IllegalArgumentException("File \"$fallbackLabel\" is not accessible.")
    }
    return inspectLocalFile(
      context = context,
      file = file,
      sourceLabel = fallbackLabel,
      sourceRef = path,
      sourceType = BinarySourceType.INSTALLED_APK,
      knownApp = null,
    )
  }

  private fun queryUriByteSize(context: Context, uri: Uri): Long {
    return runCatching {
      context.contentResolver.openAssetFileDescriptor(uri, "r")?.use { afd ->
        afd.length.takeIf { it > 0L } ?: 0L
      } ?: 0L
    }.getOrDefault(0L)
  }

  /**
   * Memory-optimized local file inspector: uses random-access [ZipFile] when the file is an APK
   * so only `classes*.dex` and `AndroidManifest.xml` entries are read into memory, avoiding
   * allocating a full-APK `ByteArray` on the heap.
   */
  private fun inspectLocalFile(
    context: Context,
    file: File,
    sourceLabel: String,
    sourceRef: String,
    sourceType: BinarySourceType,
    knownApp: InstalledAppItem?,
  ): ApkStagingPreview {
    val fileLen = file.length()
    if (fileLen < 8L) {
      throw IllegalArgumentException("File \"$sourceLabel\" is too small.")
    }
    val magicHeader = ByteArray(8)
    FileInputStream(file).use { fis -> fis.read(magicHeader) }
    if (
      magicHeader[0] == 'd'.code.toByte() &&
        magicHeader[1] == 'e'.code.toByte() &&
        magicHeader[2] == 'x'.code.toByte() &&
        magicHeader[3] == '\n'.code.toByte()
    ) {
      val bytes = file.readBytes()
      val entryName = if (sourceLabel.endsWith(".dex", ignoreCase = true)) sourceLabel else "classes.dex"
      val split = DexParser.splitDex041ContainerIfNeeded(entryName, bytes)
      val hasDex041 = split.size > 1
      val splitEntries = split.map { (n, b) -> ApkDexEntry(n, b.size, isSplitFromDex041 = hasDex041) }
      val splitMap = split.toMap(linkedMapOf())
      val primaryBytes = split.first().second
      val inferredDexPkg = inferPackageNameFromDexBytes(primaryBytes, sourceLabel)
      return ApkStagingPreview(
        sourceLabel = sourceLabel,
        sourceRef = sourceRef,
        sourceType = sourceType,
        packageName = inferredDexPkg,
        appLabel = sourceLabel,
        versionName = "DEX v" + String(bytes, 4, 3, Charsets.US_ASCII),
        versionCode = null,
        minSdk = null,
        targetSdk = null,
        totalByteSize = fileLen,
        nativeAbis = emptyList(),
        dexEntries = splitEntries,
        dexByteMap = splitMap,
        isSingleDex = !hasDex041,
        iconBitmap = null,
        hasDex041Container = hasDex041,
      )
    }

    val entries = mutableListOf<ApkDexEntry>()
    val dexMap = linkedMapOf<String, ByteArray>()
    val abis = linkedSetOf<String>()
    var manifestBytes: ByteArray? = null
    var arscBytes: ByteArray? = null
    var hasV1Sig = false
    var hasDex041 = false
    var isApkmBundle = false
    val sigSchemes = linkedSetOf<String>()
    val nestedApkNames = mutableListOf<String>()

    ZipFile(file).use { zip ->
      val enumeration = zip.entries()
      while (enumeration.hasMoreElements()) {
        val entry = enumeration.nextElement()
        if (entry.isDirectory) continue
        val name = entry.name
        if (isRootDexName(name)) {
          val dexBytes = zip.getInputStream(entry).use { it.readBytes() }
          val split = DexParser.splitDex041ContainerIfNeeded(name, dexBytes)
          val isSplit = split.size > 1
          if (isSplit) hasDex041 = true
          split.forEach { (logicalName, logicalBytes) ->
            entries += ApkDexEntry(logicalName, logicalBytes.size, isSplitFromDex041 = isSplit)
            dexMap[logicalName] = logicalBytes
          }
        } else if (name.equals("AndroidManifest.xml", ignoreCase = true)) {
          manifestBytes = zip.getInputStream(entry).use { it.readBytes() }
        } else if (name.equals("resources.arsc", ignoreCase = true)) {
          arscBytes = zip.getInputStream(entry).use { it.readBytes() }
        } else if (name.startsWith("lib/") && name.endsWith(".so")) {
          val parts = name.split('/')
          if (parts.size >= 3) abis += parts[1]
        } else if (isV1SignatureEntry(name)) {
          hasV1Sig = true
        } else if (name.endsWith(".apk", ignoreCase = true)) {
          nestedApkNames += name
        }
      }

      if (entries.isEmpty() && manifestBytes == null && nestedApkNames.isNotEmpty()) {
        isApkmBundle = true
        val baseEntryName = pickApkmBaseName(nestedApkNames)
        nestedApkNames.forEach { apkEntryName ->
          val entry = zip.getEntry(apkEntryName) ?: return@forEach
          val isBase = apkEntryName == baseEntryName
          zip.getInputStream(entry).use { inner ->
            val innerResult = collectFromApkZipStream(inner)
            abis += innerResult.abis
            if (isBase) {
              manifestBytes = innerResult.manifestBytes
              arscBytes = innerResult.arscBytes
              if (innerResult.hasV1Sig) hasV1Sig = true
              if (innerResult.hasDex041) hasDex041 = true
              entries += innerResult.entries
              dexMap.putAll(innerResult.dexMap)
            } else {
              if (innerResult.hasDex041) hasDex041 = true
              innerResult.dexMap.forEach { (dexName, dexBytes) ->
                val scoped = "${apkEntryName.substringAfterLast('/')}/$dexName"
                if (scoped !in dexMap) {
                  entries += ApkDexEntry(scoped, dexBytes.size, isSplitFromDex041 = dexName.contains("!classes"))
                  dexMap[scoped] = dexBytes
                }
              }
            }
          }
        }
      }
    }

    if (hasV1Sig) sigSchemes += "v1"
    if (!isApkmBundle) {
      sigSchemes += detectV2V3SignatureSchemes(file)
    }

    return buildApkStagingPreview(
      context = context,
      sourceLabel = sourceLabel,
      sourceRef = sourceRef,
      sourceType = sourceType,
      totalByteSize = fileLen,
      entries = entries,
      dexMap = dexMap,
      abis = abis,
      manifestBytes = manifestBytes,
      arscBytes = arscBytes,
      signatureSchemes = sigSchemes.toList(),
      isApkmBundle = isApkmBundle,
      hasDex041Container = hasDex041,
      knownApp = knownApp,
    )
  }

  private fun inspectStream(
    context: Context,
    inputStream: InputStream,
    knownTotalBytes: Long,
    sourceLabel: String,
    sourceRef: String,
    sourceType: BinarySourceType,
    knownApp: InstalledAppItem?,
  ): ApkStagingPreview {
    val buffered = BufferedInputStream(inputStream, 32 * 1024)
    buffered.mark(16)
    val magic = ByteArray(8)
    val readCount = buffered.read(magic)
    buffered.reset()

    if (
      readCount >= 8 &&
        magic[0] == 'd'.code.toByte() &&
        magic[1] == 'e'.code.toByte() &&
        magic[2] == 'x'.code.toByte() &&
        magic[3] == '\n'.code.toByte()
    ) {
      val bytes = buffered.readBytes()
      val entryName = if (sourceLabel.endsWith(".dex", ignoreCase = true)) sourceLabel else "classes.dex"
      val split = DexParser.splitDex041ContainerIfNeeded(entryName, bytes)
      val hasDex041 = split.size > 1
      val splitEntries = split.map { (n, b) -> ApkDexEntry(n, b.size, isSplitFromDex041 = hasDex041) }
      val splitMap = split.toMap(linkedMapOf())
      val inferredDexPkg = inferPackageNameFromDexBytes(split.first().second, sourceLabel)
      return ApkStagingPreview(
        sourceLabel = sourceLabel,
        sourceRef = sourceRef,
        sourceType = sourceType,
        packageName = inferredDexPkg,
        appLabel = sourceLabel,
        versionName = "DEX v" + String(bytes, 4, 3, Charsets.US_ASCII),
        versionCode = null,
        minSdk = null,
        targetSdk = null,
        totalByteSize = if (knownTotalBytes > 0L) knownTotalBytes else bytes.size.toLong(),
        nativeAbis = emptyList(),
        dexEntries = splitEntries,
        dexByteMap = splitMap,
        isSingleDex = !hasDex041,
        iconBitmap = null,
        hasDex041Container = hasDex041,
      )
    }

    val entries = mutableListOf<ApkDexEntry>()
    val dexMap = linkedMapOf<String, ByteArray>()
    val abis = linkedSetOf<String>()
    var manifestBytes: ByteArray? = null
    var arscBytes: ByteArray? = null
    var hasV1Sig = false
    var hasDex041 = false
    var isApkmBundle = false
    val nestedApks = linkedMapOf<String, ByteArray>()
    var extractedTotal = 0L

    ZipInputStream(buffered).use { zis ->
      while (true) {
        val entry = zis.nextEntry ?: break
        val name = entry.name
        if (!entry.isDirectory) {
          if (isRootDexName(name)) {
            val dexBytes = zis.readBytes()
            extractedTotal += dexBytes.size.toLong()
            val split = DexParser.splitDex041ContainerIfNeeded(name, dexBytes)
            val isSplit = split.size > 1
            if (isSplit) hasDex041 = true
            split.forEach { (logicalName, logicalBytes) ->
              entries += ApkDexEntry(logicalName, logicalBytes.size, isSplitFromDex041 = isSplit)
              dexMap[logicalName] = logicalBytes
            }
          } else if (name.equals("AndroidManifest.xml", ignoreCase = true)) {
            val mb = zis.readBytes()
            extractedTotal += mb.size.toLong()
            manifestBytes = mb
          } else if (name.equals("resources.arsc", ignoreCase = true)) {
            val ab = zis.readBytes()
            extractedTotal += ab.size.toLong()
            arscBytes = ab
          } else if (name.startsWith("lib/") && name.endsWith(".so")) {
            val parts = name.split('/')
            if (parts.size >= 3) abis += parts[1]
          } else if (isV1SignatureEntry(name)) {
            hasV1Sig = true
          } else if (name.endsWith(".apk", ignoreCase = true)) {
            val apkBytes = zis.readBytes()
            extractedTotal += apkBytes.size.toLong()
            nestedApks[name] = apkBytes
          }
        }
        zis.closeEntry()
      }
    }

    val sigSchemes = linkedSetOf<String>()
    if (hasV1Sig) sigSchemes += "v1"

    if (entries.isEmpty() && manifestBytes == null && nestedApks.isNotEmpty()) {
      isApkmBundle = true
      val baseName = pickApkmBaseName(nestedApks.keys.toList())
      nestedApks.forEach { (apkEntryName, apkBytes) ->
        val isBase = apkEntryName == baseName
        val innerResult = collectFromApkZipStream(ByteArrayInputStream(apkBytes))
        abis += innerResult.abis
        if (isBase) {
          manifestBytes = innerResult.manifestBytes
          arscBytes = innerResult.arscBytes
          if (innerResult.hasV1Sig) sigSchemes += "v1"
          if (innerResult.hasDex041) hasDex041 = true
          entries += innerResult.entries
          dexMap.putAll(innerResult.dexMap)
          DexNativeEngine.inspectApkArchiveFast(apkBytes)?.signature?.let { sig ->
            if (sig.isSignedV1) sigSchemes += "v1"
            if (sig.isSignedV2) sigSchemes += "v2"
            if (sig.isSignedV3) sigSchemes += "v3"
          }
        } else {
          if (innerResult.hasDex041) hasDex041 = true
          innerResult.dexMap.forEach { (dexName, dexBytes) ->
            val scoped = "${apkEntryName.substringAfterLast('/')}/$dexName"
            if (scoped !in dexMap) {
              entries += ApkDexEntry(scoped, dexBytes.size, isSplitFromDex041 = dexName.contains("!classes"))
              dexMap[scoped] = dexBytes
            }
          }
        }
      }
    }

    return buildApkStagingPreview(
      context = context,
      sourceLabel = sourceLabel,
      sourceRef = sourceRef,
      sourceType = sourceType,
      totalByteSize = if (knownTotalBytes > 0L) knownTotalBytes else extractedTotal,
      entries = entries,
      dexMap = dexMap,
      abis = abis,
      manifestBytes = manifestBytes,
      arscBytes = arscBytes,
      signatureSchemes = sigSchemes.toList(),
      isApkmBundle = isApkmBundle,
      hasDex041Container = hasDex041,
      knownApp = knownApp,
    )
  }

  private fun buildApkStagingPreview(
    context: Context,
    sourceLabel: String,
    sourceRef: String,
    sourceType: BinarySourceType,
    totalByteSize: Long,
    entries: List<ApkDexEntry>,
    dexMap: Map<String, ByteArray>,
    abis: Set<String>,
    manifestBytes: ByteArray?,
    arscBytes: ByteArray?,
    signatureSchemes: List<String>,
    isApkmBundle: Boolean,
    hasDex041Container: Boolean,
    knownApp: InstalledAppItem?,
  ): ApkStagingPreview {
    if (entries.isEmpty()) {
      throw IllegalArgumentException("No DEX binary or classes*.dex entries found inside \"$sourceLabel\".")
    }

    val sortedEntries = entries.sortedWith(compareBy({ it.entryName.length }, { it.entryName }))

    var pkgName = knownApp?.packageName
    var appLabel = knownApp?.appLabel
    var verName = knownApp?.versionName
    var verCode = knownApp?.versionCode
    var minSdk = knownApp?.minSdk
    var targetSdk = knownApp?.targetSdk
    var iconBitmap = knownApp?.iconBitmap

    // Tier 1: Native Rust AXML + ARSC inspector (handles SAF APKs/APKMs & quirk manifests)
    val manifestSummary = manifestBytes?.let { extractManifestSummary(it, arscBytes) }
    if (manifestSummary != null) {
      if (pkgName.isNullOrBlank()) pkgName = manifestSummary.packageName
      if (appLabel.isNullOrBlank()) appLabel = manifestSummary.appLabel
      if (verName.isNullOrBlank()) verName = manifestSummary.versionName
      if (verCode == null) verCode = manifestSummary.versionCode
      if (minSdk == null) minSdk = manifestSummary.minSdk
      if (targetSdk == null) targetSdk = manifestSummary.targetSdk
    }

    // Tier 2: Platform PackageManager archive fallback for local file paths (icon + fallback meta)
    if (sourceType == BinarySourceType.INSTALLED_APK && !isApkmBundle && File(sourceRef).exists()) {
      val archiveMeta = extractArchiveInfoFromFile(context, sourceRef)
      if (archiveMeta != null) {
        if (pkgName.isNullOrBlank()) pkgName = archiveMeta.packageName
        if (appLabel.isNullOrBlank()) appLabel = archiveMeta.appLabel
        if (verName.isNullOrBlank()) verName = archiveMeta.versionName
        if (verCode == null) verCode = archiveMeta.versionCode
        if (minSdk == null) minSdk = archiveMeta.minSdk
        if (targetSdk == null) targetSdk = archiveMeta.targetSdk
        if (iconBitmap == null) iconBitmap = archiveMeta.iconBitmap
      }
    }

    // Tier 3: Infer dominant non-framework package from primary DEX entries
    if (pkgName.isNullOrBlank()) {
      val primaryDexEntry = sortedEntries.first()
      val primaryBytes = dexMap[primaryDexEntry.entryName]
      if (primaryBytes != null) {
        pkgName = inferPackageNameFromDexBytes(primaryBytes, sourceLabel)
      }
    }

    return ApkStagingPreview(
      sourceLabel = sourceLabel,
      sourceRef = sourceRef,
      sourceType = sourceType,
      packageName = pkgName,
      appLabel = appLabel ?: sourceLabel,
      versionName = verName,
      versionCode = verCode,
      minSdk = minSdk,
      targetSdk = targetSdk,
      totalByteSize = totalByteSize,
      nativeAbis = abis.sorted(),
      dexEntries = sortedEntries,
      dexByteMap = dexMap,
      isSingleDex = false,
      iconBitmap = iconBitmap,
      applicationName = manifestSummary?.applicationName,
      permissionsCount = manifestSummary?.permissions?.size ?: 0,
      signatureSchemes = signatureSchemes,
      isApkmBundle = isApkmBundle,
      hasDex041Container = hasDex041Container,
      arscBytes = arscBytes,
    )
  }

  private data class InnerZipCollectResult(
    val entries: List<ApkDexEntry>,
    val dexMap: Map<String, ByteArray>,
    val abis: Set<String>,
    val manifestBytes: ByteArray?,
    val arscBytes: ByteArray?,
    val hasV1Sig: Boolean,
    val hasDex041: Boolean,
  )

  private fun collectFromApkZipStream(stream: InputStream): InnerZipCollectResult {
    val entries = mutableListOf<ApkDexEntry>()
    val dexMap = linkedMapOf<String, ByteArray>()
    val abis = linkedSetOf<String>()
    var manifestBytes: ByteArray? = null
    var arscBytes: ByteArray? = null
    var hasV1Sig = false
    var hasDex041 = false

    ZipInputStream(BufferedInputStream(stream, 32 * 1024)).use { zis ->
      while (true) {
        val entry = zis.nextEntry ?: break
        if (!entry.isDirectory) {
          val name = entry.name
          if (isRootDexName(name)) {
            val dexBytes = zis.readBytes()
            val split = DexParser.splitDex041ContainerIfNeeded(name, dexBytes)
            val isSplit = split.size > 1
            if (isSplit) hasDex041 = true
            split.forEach { (logicalName, logicalBytes) ->
              entries += ApkDexEntry(logicalName, logicalBytes.size, isSplitFromDex041 = isSplit)
              dexMap[logicalName] = logicalBytes
            }
          } else if (name.equals("AndroidManifest.xml", ignoreCase = true) && manifestBytes == null) {
            manifestBytes = zis.readBytes()
          } else if (name.equals("resources.arsc", ignoreCase = true) && arscBytes == null) {
            arscBytes = zis.readBytes()
          } else if (name.startsWith("lib/") && name.endsWith(".so")) {
            val parts = name.split('/')
            if (parts.size >= 3) abis += parts[1]
          } else if (isV1SignatureEntry(name)) {
            hasV1Sig = true
          }
        }
        zis.closeEntry()
      }
    }

    return InnerZipCollectResult(entries, dexMap, abis, manifestBytes, arscBytes, hasV1Sig, hasDex041)
  }

  private fun isRootDexName(name: String): Boolean {
    return !name.contains('/') && name.endsWith(".dex", ignoreCase = true)
  }

  private fun isV1SignatureEntry(name: String): Boolean {
    val upper = name.uppercase()
    return upper.startsWith("META-INF/") &&
      (upper.endsWith(".RSA") || upper.endsWith(".DSA") || upper.endsWith(".EC"))
  }

  private fun pickApkmBaseName(apkNames: List<String>): String {
    return apkNames.firstOrNull { it.equals("base.apk", ignoreCase = true) }
      ?: apkNames.firstOrNull { it.substringAfterLast('/').equals("base.apk", ignoreCase = true) }
      ?: apkNames.first()
  }

  /**
   * Detects APK Signature Scheme v2 (`0x7109871A`) and v3 (`0xF05368C0`) block IDs
   * in O(EOCD + SigBlock) without loading the entire APK into memory.
   */
  private fun detectV2V3SignatureSchemes(apkFile: File): List<String> {
    return runCatching {
      val fileLen = apkFile.length()
      if (fileLen < 64L) return@runCatching emptyList()
      RandomAccessFile(apkFile, "r").use { raf ->
        val tailLen = minOf(fileLen, 65_557L).toInt()
        val tailStart = fileLen - tailLen
        val tail = ByteArray(tailLen)
        raf.seek(tailStart)
        raf.readFully(tail)

        var eocdRel = -1
        for (i in tailLen - 22 downTo 0) {
          if (tail[i] == 0x50.toByte() && tail[i + 1] == 0x4B.toByte() && tail[i + 2] == 0x05.toByte() && tail[i + 3] == 0x06.toByte()) {
            val commentLen = (tail[i + 20].toInt() and 0xFF) or ((tail[i + 21].toInt() and 0xFF) shl 8)
            if (i + 22 + commentLen == tailLen) {
              eocdRel = i
              break
            }
          }
        }
        if (eocdRel < 0) return@runCatching emptyList()

        val cdOffset = ByteBuffer.wrap(tail, eocdRel + 16, 4).order(ByteOrder.LITTLE_ENDIAN).int.toLong() and 0xFFFFFFFFL
        if (cdOffset < 24L || cdOffset > fileLen) return@runCatching emptyList()

        val footer = ByteArray(24)
        raf.seek(cdOffset - 24L)
        raf.readFully(footer)
        val fBuf = ByteBuffer.wrap(footer).order(ByteOrder.LITTLE_ENDIAN)
        val sizeOfBlock = fBuf.getLong(0)
        val magicLo = fBuf.getLong(8)
        val magicHi = fBuf.getLong(16)
        // "APK Sig Block 42" in little-endian 64-bit chunks
        if (magicLo != 0x20676953204B5041L || magicHi != 0x3234206B636F6C42L) {
          return@runCatching emptyList()
        }
        if (sizeOfBlock < 24L || sizeOfBlock > 16L * 1024L * 1024L || sizeOfBlock + 8L > cdOffset) {
          return@runCatching emptyList()
        }
        val blockStart = cdOffset - sizeOfBlock - 8L
        val pairsLen = (sizeOfBlock - 24L).toInt().coerceAtLeast(0)
        val pairs = ByteArray(pairsLen)
        raf.seek(blockStart + 8L)
        raf.readFully(pairs)

        val pBuf = ByteBuffer.wrap(pairs).order(ByteOrder.LITTLE_ENDIAN)
        val found = mutableListOf<String>()
        var off = 0
        while (off + 12 <= pairsLen) {
          val pairLen = pBuf.getLong(off)
          if (pairLen < 4L || off + 8L + pairLen > pairsLen) break
          val id = pBuf.getInt(off + 8)
          if (id == 0x7109871A && "v2" !in found) found += "v2"
          if (id == 0xF05368C0.toInt() && "v3" !in found) found += "v3"
          off += 8 + pairLen.toInt()
        }
        found
      }
    }.getOrDefault(emptyList())
  }

  /**
   * Extracts structured manifest metadata (`packageName`, `appLabel`, `applicationName`,
   * `versionName`, `versionCode`, `minSdk`, `targetSdk`, `permissions`) via Rust `axml-parser`
   * when available, falling back to pure Kotlin parsing on host JVM tests.
   */
  internal fun extractManifestSummary(
    manifestBytes: ByteArray,
    arscBytes: ByteArray? = null,
  ): DexNativeEngine.NativeManifestSummary? {
    if (manifestBytes.size < 8) return null
    DexNativeEngine.inspectManifestAndResourcesFast(manifestBytes, arscBytes)?.let { return it }
    return parseManifestSummaryFallback(manifestBytes)
  }

  /**
   * Extracts the Android `package="..."` attribute from either a compiled binary XML (`AXML`)
   * `AndroidManifest.xml` resource or a plain-text XML manifest.
   */
  internal fun extractPackageNameFromManifestBytes(manifestBytes: ByteArray): String? {
    val pkg = extractManifestSummary(manifestBytes, null)?.packageName ?: return null
    return pkg.takeIf { isValidAndroidPackageName(it) }
  }

  private fun parseManifestSummaryFallback(manifestBytes: ByteArray): DexNativeEngine.NativeManifestSummary? {
    return runCatching {
      val buf = ByteBuffer.wrap(manifestBytes).order(ByteOrder.LITTLE_ENDIAN)
      val fileType = buf.getShort(0).toInt() and 0xFFFF
      if (fileType == 0x0003) {
        parseBinaryAxmlSummary(buf, manifestBytes)
      } else {
        parsePlainTextXmlSummary(manifestBytes)
      }
    }.getOrNull()
  }

  private fun parsePlainTextXmlSummary(bytes: ByteArray): DexNativeEngine.NativeManifestSummary? {
    val text = String(bytes, Charsets.UTF_8)
    if (!text.contains("<manifest")) return null

    fun extractAttrInTag(tagName: String, attrRegex: String): String? {
      val tagMatch = Regex("""<$tagName\b([\s\S]*?)>""").find(text)?.groupValues?.getOrNull(1) ?: return null
      return Regex("""(?:android:|\b)$attrRegex\s*=\s*["']([^"']+)["']""").find(tagMatch)?.groupValues?.getOrNull(1)?.trim()
    }

    val pkg =
      Regex("""<manifest\b[\s\S]*?\bpackage\s*=\s*["']([A-Za-z0-9_.$]+)["']""")
        .find(text)
        ?.groupValues
        ?.getOrNull(1)
        ?.trim()
        ?.takeIf { isValidAndroidPackageName(it) }

    val verCode = extractAttrInTag("manifest", "versionCode")?.let {
      if (it.startsWith("0x", ignoreCase = true)) it.substring(2).toLongOrNull(16) else it.toLongOrNull()
    }
    val verName = extractAttrInTag("manifest", "versionName")?.takeIf { !it.startsWith("@") }
    val minSdk = extractAttrInTag("uses-sdk", "minSdkVersion")?.toIntOrNull()
    val targetSdk = extractAttrInTag("uses-sdk", "targetSdkVersion")?.toIntOrNull()
    val rawLabel = extractAttrInTag("application", "label")?.takeIf { !it.startsWith("@") }
    val rawAppName = extractAttrInTag("application", "name")?.let { normalizeAppName(it, pkg) }
    val perms =
      Regex("""<uses-permission(?:-sdk-23)?\b[^>]*?\b(?:android:)?name\s*=\s*["']([^"']+)["']""")
        .findAll(text)
        .map { it.groupValues[1].trim() }
        .filter { it.isNotEmpty() }
        .distinct()
        .toList()

    return DexNativeEngine.NativeManifestSummary(
      packageName = pkg,
      appLabel = rawLabel,
      applicationName = rawAppName,
      versionName = verName,
      versionCode = verCode,
      minSdk = minSdk,
      targetSdk = targetSdk,
      permissions = perms,
    )
  }

  private fun parseBinaryAxmlSummary(
    buf: ByteBuffer,
    rawBytes: ByteArray,
  ): DexNativeEngine.NativeManifestSummary? {
    val fileLen = rawBytes.size
    val xmlHeaderSize = (buf.getShort(2).toInt() and 0xFFFF).coerceAtLeast(8)
    var pos = xmlHeaderSize
    var strings: List<String> = emptyList()
    var resourceIds: List<Int> = emptyList()

    var pkgName: String? = null
    var verName: String? = null
    var verCode: Long? = null
    var minSdk: Int? = null
    var targetSdk: Int? = null
    var appLabel: String? = null
    var appName: String? = null
    val perms = linkedSetOf<String>()
    var depth = 0

    while (pos + 8 <= fileLen) {
      val chunkType = buf.getShort(pos).toInt() and 0xFFFF
      val chunkHeaderSize = buf.getShort(pos + 2).toInt() and 0xFFFF
      val chunkSize = buf.getInt(pos + 4)
      if (chunkSize <= 0 || pos + chunkSize > fileLen) break

      when (chunkType) {
        0x0001 -> {
          if (chunkHeaderSize >= 28 && pos + 28 <= fileLen) {
            val stringCount = buf.getInt(pos + 8).coerceIn(0, 65536)
            val flags = buf.getInt(pos + 16)
            val stringsStart = buf.getInt(pos + 20)
            val isUtf8 = (flags and 0x0100) != 0
            val offsetsBase = pos + chunkHeaderSize
            val poolDataBase = pos + stringsStart
            val pool = ArrayList<String>(stringCount)
            for (i in 0 until stringCount) {
              val offPos = offsetsBase + i * 4
              if (offPos + 4 > fileLen) break
              val strOff = poolDataBase + buf.getInt(offPos)
              pool +=
                if (strOff < 0 || strOff >= fileLen) ""
                else if (isUtf8) readAxmlUtf8String(rawBytes, strOff)
                else readAxmlUtf16String(buf, rawBytes, strOff)
            }
            strings = pool
          }
        }
        0x0180 -> {
          val count = (chunkSize - chunkHeaderSize) / 4
          val ids = ArrayList<Int>(count.coerceAtLeast(0))
          for (i in 0 until count) {
            val off = pos + chunkHeaderSize + i * 4
            if (off + 4 > fileLen) break
            ids += buf.getInt(off)
          }
          resourceIds = ids
        }
        0x0102 -> {
          val nodeExtBase = pos + chunkHeaderSize
          depth++
          if (nodeExtBase + 20 <= fileLen) {
            val nameIdx = buf.getInt(nodeExtBase + 4)
            val attrStart = buf.getShort(nodeExtBase + 8).toInt() and 0xFFFF
            val attrSize = (buf.getShort(nodeExtBase + 10).toInt() and 0xFFFF).coerceAtLeast(20)
            val attrCount = (buf.getShort(nodeExtBase + 12).toInt() and 0xFFFF).coerceIn(0, 256)
            val elemName = strings.getOrNull(nameIdx)?.substringAfterLast(':')?.lowercase()
            var attrPos = nodeExtBase + attrStart
            for (a in 0 until attrCount) {
              if (attrPos + 20 > fileLen) break
              val attrNameIdx = buf.getInt(attrPos + 4)
              val attrRawValIdx = buf.getInt(attrPos + 8)
              val dataType = rawBytes[attrPos + 15].toInt() and 0xFF
              val dataVal = buf.getInt(attrPos + 16)
              val rawName = strings.getOrNull(attrNameIdx)?.substringAfterLast(':')
              val attrName =
                when (resourceIds.getOrNull(attrNameIdx)) {
                  16842753 -> "label"
                  16842755 -> "name"
                  16843276 -> "minSdkVersion"
                  16843291 -> "versionCode"
                  16843292 -> "versionName"
                  16843376 -> "targetSdkVersion"
                  else -> rawName
                }
              val strVal =
                if (dataType == 0x03) {
                  strings.getOrNull(attrRawValIdx)?.takeIf { it.isNotBlank() }
                    ?: strings.getOrNull(dataVal)?.takeIf { it.isNotBlank() }
                } else {
                  null
                }
              val intVal =
                if (dataType == 0x10 || dataType == 0x11) dataVal.toLong() and 0xFFFFFFFFL else null

              when {
                elemName == "manifest" && depth == 1 ->
                  when (attrName) {
                    "package" -> strVal?.trim()?.takeIf { isValidAndroidPackageName(it) }?.let { pkgName = it }
                    "versionCode" -> if (intVal != null) verCode = intVal else strVal?.toLongOrNull()?.let { verCode = it }
                    "versionName" -> strVal?.trim()?.takeIf { !it.startsWith("@") }?.let { verName = it }
                  }
                elemName == "uses-sdk" && depth == 2 ->
                  when (attrName) {
                    "minSdkVersion" -> if (intVal != null) minSdk = intVal.toInt() else strVal?.toIntOrNull()?.let { minSdk = it }
                    "targetSdkVersion" -> if (intVal != null) targetSdk = intVal.toInt() else strVal?.toIntOrNull()?.let { targetSdk = it }
                  }
                elemName == "application" && depth == 2 ->
                  when (attrName) {
                    "label" -> strVal?.trim()?.takeIf { !it.startsWith("@") }?.let { appLabel = it }
                    "name" -> strVal?.trim()?.let { appName = normalizeAppName(it, pkgName) }
                  }
                (elemName == "uses-permission" || elemName == "uses-permission-sdk-23") && depth == 2 ->
                  if (attrName == "name") strVal?.trim()?.takeIf { it.isNotEmpty() }?.let { perms += it }
              }
              attrPos += attrSize
            }
          }
        }
        0x0103 -> {
          if (depth > 0) depth--
        }
      }
      pos += chunkSize
    }

    return if (pkgName != null || verCode != null || verName != null || perms.isNotEmpty()) {
      DexNativeEngine.NativeManifestSummary(
        packageName = pkgName,
        appLabel = appLabel,
        applicationName = appName?.let { normalizeAppName(it, pkgName) },
        versionName = verName,
        versionCode = verCode,
        minSdk = minSdk,
        targetSdk = targetSdk,
        permissions = perms.toList(),
      )
    } else {
      null
    }
  }

  private fun normalizeAppName(raw: String, pkg: String?): String {
    val t = raw.trim()
    return when {
      pkg != null && t.startsWith(".") -> "$pkg$t"
      pkg != null && !t.contains('.') -> "$pkg.$t"
      else -> t
    }
  }

  private fun readAxmlUtf8String(bytes: ByteArray, offset: Int): String {
    var idx = offset
    if (idx >= bytes.size) return ""
    val u16LenFirst = bytes[idx++].toInt() and 0xFF
    if ((u16LenFirst and 0x80) != 0) {
      if (idx >= bytes.size) return ""
      idx++
    }
    if (idx >= bytes.size) return ""
    var utf8ByteLen = bytes[idx++].toInt() and 0xFF
    if ((utf8ByteLen and 0x80) != 0) {
      if (idx >= bytes.size) return ""
      utf8ByteLen = ((utf8ByteLen and 0x7F) shl 8) or (bytes[idx++].toInt() and 0xFF)
    }
    val safeLen = utf8ByteLen.coerceIn(0, (bytes.size - idx).coerceAtLeast(0))
    return String(bytes, idx, safeLen, Charsets.UTF_8)
  }

  private fun readAxmlUtf16String(buf: ByteBuffer, bytes: ByteArray, offset: Int): String {
    var idx = offset
    if (idx + 2 > bytes.size) return ""
    var charLen = buf.getShort(idx).toInt() and 0xFFFF
    idx += 2
    if ((charLen and 0x8000) != 0) {
      if (idx + 2 > bytes.size) return ""
      charLen = ((charLen and 0x7FFF) shl 16) or (buf.getShort(idx).toInt() and 0xFFFF)
      idx += 2
    }
    val byteLen = (charLen * 2).coerceIn(0, (bytes.size - idx).coerceAtLeast(0))
    return String(bytes, idx, byteLen, Charsets.UTF_16LE)
  }

  private fun isValidAndroidPackageName(candidate: String): Boolean {
    val trimmed = candidate.trim()
    if (trimmed.isEmpty() || !trimmed.contains('.')) return false
    val parts = trimmed.split('.')
    return parts.size >= 2 && parts.all { part -> part.isNotEmpty() && part.all { ch -> ch.isLetterOrDigit() || ch == '_' || ch == '$' } }
  }

  private fun inferPackageNameFromDexBytes(dexBytes: ByteArray, sourceLabel: String): String? {
    return runCatching {
      val parsed = DexParser.parseDex(rawBytes = dexBytes, sourceLabel = sourceLabel, entryName = "classes.dex")
      inferDominantDexPackageName(parsed.classes)
    }.getOrNull()
  }

  private data class ArchiveMeta(
    val packageName: String,
    val appLabel: String?,
    val versionName: String?,
    val versionCode: Long?,
    val minSdk: Int?,
    val targetSdk: Int?,
    val iconBitmap: android.graphics.Bitmap?,
  )

  private fun extractArchiveInfoFromFile(
    context: Context,
    apkPath: String,
  ): ArchiveMeta? {
    val pm = context.packageManager
    return try {
      val pkgInfo =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
          pm.getPackageArchiveInfo(apkPath, PackageManager.PackageInfoFlags.of(0L))
        } else {
          @Suppress("DEPRECATION")
          pm.getPackageArchiveInfo(apkPath, 0)
        } ?: return null

      val appInfo = pkgInfo.applicationInfo
      if (appInfo != null) {
        appInfo.sourceDir = apkPath
        appInfo.publicSourceDir = apkPath
      }

      val label = appInfo?.loadLabel(pm)?.toString()
      val icon = runCatching { appInfo?.loadIcon(pm)?.let { InstalledAppRepository.drawableToBitmap(it) } }.getOrNull()
      val verCode =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
          pkgInfo.longVersionCode
        } else {
          @Suppress("DEPRECATION")
          pkgInfo.versionCode.toLong()
        }
      val minSdk =
        if (appInfo != null && Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) appInfo.minSdkVersion else null

      ArchiveMeta(
        packageName = pkgInfo.packageName,
        appLabel = label,
        versionName = pkgInfo.versionName,
        versionCode = verCode,
        minSdk = minSdk,
        targetSdk = appInfo?.targetSdkVersion,
        iconBitmap = icon,
      )
    } catch (_: Throwable) {
      null
    }
  }
}
