package com.dex2c.studio.data.repository

import com.dex2c.studio.dex.DexClassInfo
import com.dex2c.studio.nativeengine.DexNativeEngine
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * High-performance repository interfacing between ViewModel state machines and
 * the Rust native backend engine (`librust_dex2c.so`).
 * Guarantees zero main-thread blocking by dispatching all compute-heavy operations onto Dispatchers.IO.
 */
class Dex2cNativeRepository {

  val isAvailable: Boolean
    get() = DexNativeEngine.isAvailable

  val version: String?
    get() = DexNativeEngine.nativeEngineVersion

  suspend fun parseClasses(
    dexBytes: ByteArray,
    sourceEntryName: String = "classes.dex",
  ): List<DexClassInfo>? = withContext(Dispatchers.IO) {
    DexNativeEngine.parseClassesFast(dexBytes, sourceEntryName)
  }

  suspend fun evaluateFilterRules(
    dexBytes: ByteArray,
    rules: List<String>,
    allowInit: Boolean = false,
    skipSynthetic: Boolean = true,
  ): DexNativeEngine.NativeFilterResult? = withContext(Dispatchers.IO) {
    DexNativeEngine.evaluateFilterRulesFast(dexBytes, rules, allowInit, skipSynthetic)
  }

  suspend fun disassembleSmali(
    dexBytes: ByteArray,
    classDefIdx: Int,
  ): String? = withContext(Dispatchers.IO) {
    DexNativeEngine.disassembleSmaliFast(dexBytes, classDefIdx)
  }

  suspend fun disassembleMethod(
    dexBytes: ByteArray,
    classDefIdx: Int,
    methodIdx: Int,
  ): DexNativeEngine.NativeMethodDisassembly? = withContext(Dispatchers.IO) {
    DexNativeEngine.disassembleMethodFast(dexBytes, classDefIdx, methodIdx)
  }

  suspend fun transpileMethod(
    dexBytes: ByteArray,
    classDefIdx: Int,
    methodIdx: Int,
  ): String? = withContext(Dispatchers.IO) {
    DexNativeEngine.transpileMethodFast(dexBytes, classDefIdx, methodIdx)
  }

  suspend fun patchDex(
    dexBytes: ByteArray,
    methodIndices: Set<Int>,
  ): ByteArray? = withContext(Dispatchers.IO) {
    DexNativeEngine.patchDexMethodsFast(dexBytes, methodIndices)
  }

  suspend fun inspectManifestAndResources(
    manifestBytes: ByteArray,
    arscBytes: ByteArray? = null,
  ): DexNativeEngine.NativeManifestSummary? = withContext(Dispatchers.IO) {
    DexNativeEngine.inspectManifestAndResourcesFast(manifestBytes, arscBytes)
  }

  suspend fun inspectApkArchive(
    apkBytes: ByteArray,
  ): DexNativeEngine.NativeApkArchiveSummary? = withContext(Dispatchers.IO) {
    DexNativeEngine.inspectApkArchiveFast(apkBytes)
  }

  suspend fun splitDex041Container(
    entryName: String,
    dexBytes: ByteArray,
  ): List<Pair<String, ByteArray>>? = withContext(Dispatchers.IO) {
    DexNativeEngine.splitDex041ContainerFast(entryName, dexBytes)
  }

  suspend fun verifyDexMethod(
    dexBytes: ByteArray,
    classDefIdx: Int,
    methodIdx: Int,
  ): DexNativeEngine.NativeMethodVerificationReport? = withContext(Dispatchers.IO) {
    DexNativeEngine.verifyDexMethodFast(dexBytes, classDefIdx, methodIdx)
  }

  suspend fun verifyDexClass(
    dexBytes: ByteArray,
    classDefIdx: Int,
  ): List<DexNativeEngine.NativeMethodVerificationReport>? = withContext(Dispatchers.IO) {
    DexNativeEngine.verifyDexClassFast(dexBytes, classDefIdx)
  }

  suspend fun alignAndSignApk(
    apkBytes: ByteArray,
    privateKeyDer: ByteArray? = null,
    certDer: ByteArray? = null,
    enableV1: Boolean = false,
    enableV2: Boolean = true,
    enableV3: Boolean = true,
    pageAlignment: Int = 16384,
  ): ByteArray? = withContext(Dispatchers.IO) {
    DexNativeEngine.alignAndSignApkFast(
      apkBytes = apkBytes,
      privateKeyDer = privateKeyDer,
      certDer = certDer,
      enableV1 = enableV1,
      enableV2 = enableV2,
      enableV3 = enableV3,
      pageAlignment = pageAlignment,
    )
  }

  suspend fun decompileMethodJava(
    dexBytes: ByteArray,
    classDefIdx: Int,
    methodIdx: Int,
    arscBytes: ByteArray? = null,
  ): String? = withContext(Dispatchers.IO) {
    DexNativeEngine.decompileMethodJavaFast(dexBytes, classDefIdx, methodIdx, arscBytes)
  }

  suspend fun decompileClassJava(
    dexBytes: ByteArray,
    classDefIdx: Int,
    arscBytes: ByteArray? = null,
  ): String? = withContext(Dispatchers.IO) {
    DexNativeEngine.decompileClassJavaFast(dexBytes, classDefIdx, arscBytes)
  }
}
