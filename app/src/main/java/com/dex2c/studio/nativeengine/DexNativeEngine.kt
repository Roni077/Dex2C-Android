package com.dex2c.studio.nativeengine

import android.util.Log
import com.dex2c.studio.cloud.JsonMini
import com.dex2c.studio.dex.BasicBlockInfo
import com.dex2c.studio.dex.BlockTerminatorKind
import com.dex2c.studio.dex.CfgEdge
import com.dex2c.studio.dex.CfgEdgeKind
import com.dex2c.studio.dex.DalvikInstruction
import com.dex2c.studio.dex.DalvikPayload
import com.dex2c.studio.dex.DexCatchHandler
import com.dex2c.studio.dex.DexFieldRef
import com.dex2c.studio.dex.DexMethodRef
import com.dex2c.studio.dex.DexProto
import com.dex2c.studio.dex.DexTryBlock
import com.dex2c.studio.dex.MethodControlFlowGraph
import com.dex2c.studio.dex.OpCategory

/**
 * JNI bridge facade to the high-performance Rust native engine (`librust_dex2c.so`).
 * Provides transparent, zero-friction fallback to Kotlin implementations when the native
 * shared library is not compiled or loaded on the host platform.
 */
object DexNativeEngine {

  private const val TAG = "DexNativeEngine"
  private const val LIB_NAME = "rust_dex2c"

  val isAvailable: Boolean =
    try {
      System.loadLibrary(LIB_NAME)
      true
    } catch (e: Throwable) {
      safeLog(TAG, "Native Rust engine ($LIB_NAME) not loaded; utilizing Kotlin fallback: ${e.message}")
      false
    }

  val nativeEngineVersion: String? by lazy {
    if (isAvailable) {
      runCatching { nativeGetVersion() }.getOrNull()
    } else {
      null
    }
  }

  // --- External JNI Declarations ---

  @JvmStatic
  external fun nativeOpenDex(bytes: ByteArray, size: Int): Long

  @JvmStatic
  external fun nativeCloseDex(handle: Long)

  @JvmStatic
  external fun nativeGetClassCount(handle: Long): Int

  @JvmStatic
  external fun nativeGetStringCount(handle: Long): Int

  data class NativeFilterResult(
    val matchedClassIndices: Set<Int>,
    val matchedMethodIndices: Set<Int>,
  )

  @JvmStatic
  external fun nativeFilterMethods(
    handle: Long,
    rules: Array<String>,
    allowInit: Boolean,
    skipSynthetic: Boolean,
  ): IntArray?

  @JvmStatic
  external fun nativeFilterClassesAndMethods(
    handle: Long,
    rules: Array<String>,
    allowInit: Boolean,
    skipSynthetic: Boolean,
  ): IntArray?

  @JvmStatic
  external fun nativeParseDex(handle: Long): java.nio.ByteBuffer?

  data class NativeMethodDisassembly(
    val instructions: List<DalvikInstruction>,
    val tryBlocks: List<DexTryBlock>,
    val cfg: MethodControlFlowGraph,
  )

  data class NativeManifestSummary(
    val packageName: String?,
    val appLabel: String?,
    val applicationName: String?,
    val versionName: String?,
    val versionCode: Long?,
    val minSdk: Int?,
    val targetSdk: Int?,
    val permissions: List<String>,
    val isPacked: Boolean = false,
  )

  data class NativeApkDexSummary(
    val entryName: String,
    val byteSize: Int,
    val dexVersion: String,
    val isDex041Container: Boolean,
    val logicalDexCount: Int,
  )

  data class NativeApkSignatureSummary(
    val isSigned: Boolean,
    val isSignedV1: Boolean,
    val isSignedV2: Boolean,
    val isSignedV3: Boolean,
    val v1SignatureNames: List<String>,
    val v2SignerCount: Int,
    val v3SignerCount: Int,
  )

  data class NativeApkArchiveSummary(
    val isApkm: Boolean,
    val baseApkName: String?,
    val apkmSplits: List<String>,
    val manifest: NativeManifestSummary?,
    val nativeAbis: List<String>,
    val dexEntries: List<NativeApkDexSummary>,
    val signature: NativeApkSignatureSummary?,
  )

  data class NativeVerificationIssue(
    val pcWord: Int,
    val mnemonic: String,
    val severity: String,
    val code: String,
    val message: String,
  )

  data class NativeMethodVerificationReport(
    val passed: Boolean,
    val classDescriptor: String,
    val methodIdx: Int,
    val methodName: String,
    val registersSize: Int,
    val insSize: Int,
    val instructionCount: Int,
    val issues: List<NativeVerificationIssue>,
  )

  @JvmStatic
  external fun nativeVerifyDexMethod(
    handle: Long,
    classDefIdx: Int,
    methodIdx: Int,
  ): String?

  @JvmStatic
  external fun nativeVerifyDexClass(
    handle: Long,
    classDefIdx: Int,
  ): String?

  @JvmStatic
  external fun nativeDecompileMethodJava(
    handle: Long,
    classDefIdx: Int,
    methodIdx: Int,
    arscBytes: ByteArray?,
  ): String?

  @JvmStatic
  external fun nativeDecompileClassJava(
    handle: Long,
    classDefIdx: Int,
    arscBytes: ByteArray?,
  ): String?

  @JvmStatic
  external fun nativeAlignAndSignApk(
    apkBytes: ByteArray,
    privateKeyDer: ByteArray?,
    certDer: ByteArray?,
    v1: Boolean,
    v2: Boolean,
    v3: Boolean,
    pageAlignment: Int,
  ): ByteArray?

  @JvmStatic
  external fun nativeInspectManifestAndResources(
    manifestBytes: ByteArray,
    arscBytes: ByteArray?,
  ): String?

  @JvmStatic
  external fun nativeInspectApkArchive(apkBytes: ByteArray): String?

  @JvmStatic
  external fun nativeSplitDex041Container(
    entryName: String,
    dexBytes: ByteArray,
  ): Array<ByteArray>?

  @JvmStatic
  external fun nativeDisassembleClassSmali(
    handle: Long,
    classDefIdx: Int,
  ): String?

  @JvmStatic
  external fun nativeDisassembleMethodJson(
    handle: Long,
    classDefIdx: Int,
    methodIdx: Int,
  ): String?

  @JvmStatic
  external fun nativeTranspileMethod(
    handle: Long,
    classDefIdx: Int,
    methodIdx: Int,
  ): String?

  @JvmStatic
  external fun nativePatchDexMethods(
    handle: Long,
    methodIndices: IntArray,
  ): Int

  @JvmStatic
  external fun nativeGenerateBuildFiles(
    moduleName: String,
    sourceFiles: Array<String>,
  ): String?

  @JvmStatic
  external fun nativeGetVersion(): String?

  // --- Safe Kotlin Helper APIs ---

  /**
   * Fast DEX class indexing via the Rust native engine with direct ByteBuffer decoding.
   * Returns a list of [com.dex2c.studio.dex.DexClassInfo] instances, or null if the native engine is unavailable,
   * encounters corrupted structures, or is running on a platform without native libraries.
   */
  fun parseClassesFast(
    dexBytes: ByteArray,
    sourceEntryName: String = "classes.dex",
  ): List<com.dex2c.studio.dex.DexClassInfo>? {
    if (!isAvailable || dexBytes.isEmpty()) return null

    val handle = runCatching { nativeOpenDex(dexBytes, dexBytes.size) }.getOrDefault(0L)
    if (handle == 0L) return null

    return try {
      val byteBuffer = nativeParseDex(handle) ?: return null
      com.dex2c.studio.dex.D2cnBinaryDecoder.decodeClasses(byteBuffer, sourceEntryName)
    } catch (e: Throwable) {
      safeLog(TAG, "Native D2CN direct buffer decoding failed, falling back to Kotlin", e)
      null
    } finally {
      runCatching { nativeCloseDex(handle) }
    }
  }

  /**
   * Evaluates filter rules over a raw DEX binary using the Rust SIMD RegexSet engine.
   * Returns a set of matching method indices, or null if the native engine is unavailable.
   */
  fun evaluateFilterRules(
    dexBytes: ByteArray,
    rules: List<String>,
    allowInit: Boolean = false,
    skipSynthetic: Boolean = true,
  ): Set<Int>? {
    val res = evaluateFilterRulesFast(dexBytes, rules, allowInit, skipSynthetic)
    return res?.matchedMethodIndices
  }

  /**
   * Evaluates filter rules returning both matched class indices and method indices in a single fast JNI pass.
   */
  fun evaluateFilterRulesFast(
    dexBytes: ByteArray,
    rules: List<String>,
    allowInit: Boolean = false,
    skipSynthetic: Boolean = true,
  ): NativeFilterResult? {
    if (!isAvailable || dexBytes.isEmpty()) return null

    val handle = runCatching { nativeOpenDex(dexBytes, dexBytes.size) }.getOrDefault(0L)
    if (handle == 0L) return null

    return try {
      val packed =
        nativeFilterClassesAndMethods(
          handle = handle,
          rules = rules.toTypedArray(),
          allowInit = allowInit,
          skipSynthetic = skipSynthetic,
        ) ?: return null

      if (packed.size < 2) return null
      val classCount = packed[0]
      val methodCount = packed[1]
      val classes = HashSet<Int>(classCount)
      val methods = HashSet<Int>(methodCount)

      val classEnd = 2 + classCount
      for (i in 2 until classEnd) {
        classes.add(packed[i])
      }
      val methodEnd = classEnd + methodCount
      for (i in classEnd until methodEnd) {
        methods.add(packed[i])
      }

      NativeFilterResult(classes, methods)
    } catch (e: Throwable) {
      safeLog(TAG, "Native filter evaluation failed, falling back to Kotlin", e)
      null
    } finally {
      runCatching { nativeCloseDex(handle) }
    }
  }

  /**
   * Disassembles a class to Smali text using the Rust engine.
   */
  fun disassembleSmaliFast(
    dexBytes: ByteArray,
    classDefIdx: Int,
  ): String? {
    if (!isAvailable || dexBytes.isEmpty() || classDefIdx < 0) return null
    val handle = runCatching { nativeOpenDex(dexBytes, dexBytes.size) }.getOrDefault(0L)
    if (handle == 0L) return null
    return try {
      nativeDisassembleClassSmali(handle, classDefIdx)
    } catch (e: Throwable) {
      safeLog(TAG, "Native Smali disassembly failed", e)
      null
    } finally {
      runCatching { nativeCloseDex(handle) }
    }
  }

  /**
   * Transpiles a single method to C++17 JNI code using the Rust engine.
   */
  fun transpileMethodFast(
    dexBytes: ByteArray,
    classDefIdx: Int,
    methodIdx: Int,
  ): String? {
    if (!isAvailable || dexBytes.isEmpty() || classDefIdx < 0 || methodIdx < 0) return null
    val handle = runCatching { nativeOpenDex(dexBytes, dexBytes.size) }.getOrDefault(0L)
    if (handle == 0L) return null
    return try {
      nativeTranspileMethod(handle, classDefIdx, methodIdx)
    } catch (e: Throwable) {
      safeLog(TAG, "Native C++ transpilation failed", e)
      null
    } finally {
      runCatching { nativeCloseDex(handle) }
    }
  }

  /**
   * In-place patches methods in a DEX binary to native stubs and recomputes signatures.
   */
  fun patchDexMethodsFast(
    dexBytes: ByteArray,
    methodIndices: Set<Int>,
  ): ByteArray? {
    if (!isAvailable || dexBytes.isEmpty() || methodIndices.isEmpty()) return null
    val copy = dexBytes.copyOf()
    val handle = runCatching { nativeOpenDex(copy, copy.size) }.getOrDefault(0L)
    if (handle == 0L) return null
    return try {
      val count = nativePatchDexMethods(handle, methodIndices.toIntArray())
      if (count >= 0) copy else null
    } catch (e: Throwable) {
      safeLog(TAG, "Native DEX method patching failed", e)
      null
    } finally {
      runCatching { nativeCloseDex(handle) }
    }
  }

  /**
   * Disassembles a single method's Dalvik bytecode, try/catch blocks, and CFG via Rust `dex-bytecode`.
   */
  fun disassembleMethodFast(
    dexBytes: ByteArray,
    classDefIdx: Int,
    methodIdx: Int,
  ): NativeMethodDisassembly? {
    if (!isAvailable || dexBytes.isEmpty() || classDefIdx < 0 || methodIdx < 0) return null
    val handle = runCatching { nativeOpenDex(dexBytes, dexBytes.size) }.getOrDefault(0L)
    if (handle == 0L) return null
    return try {
      val json = nativeDisassembleMethodJson(handle, classDefIdx, methodIdx) ?: return null
      parseMethodDisassemblyJson(json)
    } catch (e: Throwable) {
      safeLog(TAG, "Native method disassembly failed, falling back to Kotlin", e)
      null
    } finally {
      runCatching { nativeCloseDex(handle) }
    }
  }

  internal fun parseMethodDisassemblyJson(rawJson: String): NativeMethodDisassembly? {
    if (rawJson.isBlank()) return null
    return runCatching {
      val root = JsonMini.parseObject(rawJson)
      val rawInsns = root["instructions"] as? List<*> ?: return@runCatching null
      val instructions = ArrayList<DalvikInstruction>(rawInsns.size)

      for (item in rawInsns) {
        val m = item as? Map<*, *> ?: return@runCatching null
        val offsetWords = m.intOr("offsetWords") ?: return@runCatching null
        val categoryName = m.strOr("category") ?: "UNKNOWN"
        val category = OpCategory.entries.firstOrNull { it.name == categoryName } ?: OpCategory.UNKNOWN

        val fieldRef =
          (m["fieldRef"] as? Map<*, *>)?.let { fm ->
            val cls = fm.strOr("definingClass")
            val typ = fm.strOr("type")
            val name = fm.strOr("name")
            if (cls != null && typ != null && name != null) DexFieldRef(cls, typ, name) else null
          }

        val methodRef =
          (m["methodRef"] as? Map<*, *>)?.let { mm ->
            val cls = mm.strOr("definingClass")
            val name = mm.strOr("name")
            val pm = mm["proto"] as? Map<*, *>
            val shorty = pm?.strOr("shorty")
            val ret = pm?.strOr("returnType")
            val params =
              (pm?.get("parameterTypes") as? List<*>)?.mapNotNull { it as? String } ?: emptyList()
            if (cls != null && name != null && shorty != null && ret != null) {
              DexMethodRef(cls, DexProto(shorty, ret, params), name)
            } else {
              null
            }
          }

        val payload = (m["payload"] as? Map<*, *>)?.let { parsePayloadJson(it) }

        instructions +=
          DalvikInstruction(
            offsetWords = offsetWords,
            widthWords = m.intOr("widthWords") ?: 1,
            opcode = m.intOr("opcode") ?: 0,
            mnemonic = m.strOr("mnemonic") ?: "unknown",
            format = m.strOr("format") ?: "10x",
            operandsText = m.strOr("operandsText") ?: "",
            rawWords = (m["rawWords"] as? List<*>)?.mapNotNull { (it as? Number)?.toInt() } ?: emptyList(),
            category = category,
            regA = m.intOr("regA"),
            regB = m.intOr("regB"),
            regC = m.intOr("regC"),
            regList = (m["regList"] as? List<*>)?.mapNotNull { (it as? Number)?.toInt() } ?: emptyList(),
            isRangeInvoke = m["isRangeInvoke"] as? Boolean ?: false,
            literal = (m["literal"] as? Number)?.toLong(),
            targetOffset = m.intOr("targetOffset"),
            stringRef = m.strOr("stringRef"),
            typeRef = m.strOr("typeRef"),
            fieldRef = fieldRef,
            methodRef = methodRef,
            payload = payload,
          )
      }

      val rawTries = root["tryBlocks"] as? List<*> ?: emptyList<Any?>()
      val tryBlocks = ArrayList<DexTryBlock>(rawTries.size)
      for (tb in rawTries) {
        val tm = tb as? Map<*, *> ?: continue
        val handlers =
          (tm["handlers"] as? List<*>)?.mapNotNull { h ->
            val hm = h as? Map<*, *> ?: return@mapNotNull null
            val off = hm.intOr("handlerOffsetWord") ?: return@mapNotNull null
            DexCatchHandler(typeDescriptor = hm.strOr("typeDescriptor"), handlerOffsetWord = off)
          } ?: emptyList()
        tryBlocks +=
          DexTryBlock(
            startOffsetWord = tm.intOr("startOffsetWord") ?: 0,
            insnCount = tm.intOr("insnCount") ?: 0,
            handlers = handlers,
          )
      }

      val cfgMap = root["cfg"] as? Map<*, *> ?: return@runCatching null
      val rawBlocks = cfgMap["blocks"] as? List<*> ?: emptyList<Any?>()
      val blocks = ArrayList<BasicBlockInfo>(rawBlocks.size)
      for (b in rawBlocks) {
        val bm = b as? Map<*, *> ?: continue
        val id = bm.strOr("id") ?: return@runCatching null
        val termName = bm.strOr("terminatorKind") ?: "FALLTHROUGH"
        val termKind =
          BlockTerminatorKind.entries.firstOrNull { it.name == termName }
            ?: BlockTerminatorKind.FALLTHROUGH
        val blockInsns =
          (bm["instructionIndices"] as? List<*>)?.mapNotNull { idx ->
            (idx as? Number)?.toInt()?.let { instructions.getOrNull(it) }
          } ?: emptyList()
        val preds = (bm["predecessors"] as? List<*>)?.mapNotNull { it as? String } ?: emptyList()
        val edges =
          (bm["outgoingEdges"] as? List<*>)?.mapNotNull { e ->
            val em = e as? Map<*, *> ?: return@mapNotNull null
            val toBlock = em.strOr("toBlockId") ?: return@mapNotNull null
            val kindName = em.strOr("kind") ?: "FALLTHROUGH"
            val kind = CfgEdgeKind.entries.firstOrNull { it.name == kindName } ?: CfgEdgeKind.FALLTHROUGH
            CfgEdge(
              fromBlockId = em.strOr("fromBlockId") ?: id,
              toBlockId = toBlock,
              toOffsetWords = em.intOr("toOffsetWords") ?: 0,
              kind = kind,
              label = em.strOr("label") ?: kind.shortLabel,
            )
          } ?: emptyList()

        blocks +=
          BasicBlockInfo(
            id = id,
            index = bm.intOr("index") ?: 0,
            startOffsetWords = bm.intOr("startOffsetWords") ?: 0,
            endOffsetWords = bm.intOr("endOffsetWords") ?: 0,
            instructions = blockInsns,
            terminatorKind = termKind,
            isEntry = bm["isEntry"] as? Boolean ?: false,
            isExceptionHandler = bm["isExceptionHandler"] as? Boolean ?: false,
            predecessors = preds,
            outgoingEdges = edges,
          )
      }

      val cfg =
        MethodControlFlowGraph(
          blocks = blocks,
          payloads = instructions.mapNotNull { it.payload },
          edgeCount = cfgMap.intOr("edgeCount") ?: blocks.sumOf { it.outgoingEdges.size },
          branchCount = cfgMap.intOr("branchCount") ?: 0,
          exceptionEdgeCount = cfgMap.intOr("exceptionEdgeCount") ?: 0,
          engineLabel = cfgMap.strOr("engineLabel") ?: "Rust Native (dex-bytecode CFG)",
        )

      NativeMethodDisassembly(instructions = instructions, tryBlocks = tryBlocks, cfg = cfg)
    }.getOrNull()
  }

  private fun parsePayloadJson(pm: Map<*, *>): DalvikPayload? {
    val kind = pm.strOr("kind") ?: return null
    val offsetWords = pm.intOr("offsetWords") ?: return null
    val wordCount = pm.intOr("wordCount") ?: return null
    return when (kind) {
      "packed_switch" ->
        DalvikPayload.PackedSwitch(
          offsetWords = offsetWords,
          wordCount = wordCount,
          firstKey = pm.intOr("firstKey") ?: 0,
          targetOffsets =
            (pm["targetOffsets"] as? List<*>)?.mapNotNull { (it as? Number)?.toInt() } ?: emptyList(),
        )
      "sparse_switch" -> {
        val keys = (pm["keys"] as? List<*>)?.mapNotNull { (it as? Number)?.toInt() } ?: emptyList()
        val targets =
          (pm["targetOffsets"] as? List<*>)?.mapNotNull { (it as? Number)?.toInt() } ?: emptyList()
        DalvikPayload.SparseSwitch(
          offsetWords = offsetWords,
          wordCount = wordCount,
          cases = keys.zip(targets),
        )
      }
      "fill_array_data" ->
        DalvikPayload.FillArrayData(
          offsetWords = offsetWords,
          wordCount = wordCount,
          elementWidthBytes = pm.intOr("elementWidthBytes") ?: 1,
          elementCount = pm.intOr("elementCount") ?: 0,
          previewElements =
            (pm["previewElements"] as? List<*>)?.mapNotNull { it as? String } ?: emptyList(),
          hexPreview = pm.strOr("hexPreview") ?: "",
        )
      else -> null
    }
  }

  /**
   * Inspects binary AXML (or plaintext XML) `AndroidManifest.xml` and optional `resources.arsc`
   * via Rust `axml-parser` (`AXMLPrinter` + `ARSCParser`).
   */
  fun inspectManifestAndResourcesFast(
    manifestBytes: ByteArray,
    arscBytes: ByteArray? = null,
  ): NativeManifestSummary? {
    if (!isAvailable || manifestBytes.size < 8) return null
    return try {
      val json = nativeInspectManifestAndResources(manifestBytes, arscBytes) ?: return null
      parseManifestSummaryJson(json)
    } catch (e: Throwable) {
      safeLog(TAG, "Native manifest/ARSC inspection failed, falling back to Kotlin", e)
      null
    }
  }

  /**
   * Inspects a complete APK or APKM container via Rust `apkparser` + `axml-parser`.
   */
  fun inspectApkArchiveFast(apkBytes: ByteArray): NativeApkArchiveSummary? {
    if (!isAvailable || apkBytes.size < 22) return null
    return try {
      val json = nativeInspectApkArchive(apkBytes) ?: return null
      parseApkArchiveSummaryJson(json)
    } catch (e: Throwable) {
      safeLog(TAG, "Native APK archive inspection failed, falling back to Kotlin", e)
      null
    }
  }

  /**
   * Splits a DEX `041` multi-section container using `apkparser::iter_logical_dexes`.
   * Returns `null` when the buffer does not contain multiple DEX `041` sections or native is unavailable.
   */
  fun splitDex041ContainerFast(
    entryName: String,
    dexBytes: ByteArray,
  ): List<Pair<String, ByteArray>>? {
    if (!isAvailable || dexBytes.size < 0x70) return null
    if (
      dexBytes[0] != 'd'.code.toByte() ||
        dexBytes[1] != 'e'.code.toByte() ||
        dexBytes[2] != 'x'.code.toByte() ||
        dexBytes[3] != '\n'.code.toByte() ||
        dexBytes[4] != '0'.code.toByte() ||
        dexBytes[5] != '4'.code.toByte() ||
        dexBytes[6] != '1'.code.toByte() ||
        dexBytes[7] != 0.toByte()
    ) {
      return null
    }
    return try {
      val packed = nativeSplitDex041Container(entryName, dexBytes) ?: return null
      if (packed.size < 2 || packed.size % 2 != 0) return null
      val out = ArrayList<Pair<String, ByteArray>>(packed.size / 2)
      var i = 0
      while (i + 1 < packed.size) {
        val label = String(packed[i], Charsets.UTF_8)
        out += label to packed[i + 1]
        i += 2
      }
      out.takeIf { it.isNotEmpty() }
    } catch (e: Throwable) {
      safeLog(TAG, "Native DEX 041 splitting failed, falling back to Kotlin", e)
      null
    }
  }

  internal fun parseManifestSummaryJson(rawJson: String): NativeManifestSummary? {
    if (rawJson.isBlank()) return null
    return runCatching {
      val root = JsonMini.parseObject(rawJson)
      parseManifestSummaryMap(root)
    }.getOrNull()
  }

  internal fun parseApkArchiveSummaryJson(rawJson: String): NativeApkArchiveSummary? {
    if (rawJson.isBlank()) return null
    return runCatching {
      val root = JsonMini.parseObject(rawJson)
      val manifest = (root["manifest"] as? Map<*, *>)?.let { parseManifestSummaryMap(it) }
      val splits = (root["apkmSplits"] as? List<*>)?.mapNotNull { it as? String } ?: emptyList()
      val abis = (root["nativeAbis"] as? List<*>)?.mapNotNull { it as? String } ?: emptyList()
      val dexEntries =
        (root["dexEntries"] as? List<*>)?.mapNotNull { item ->
          val dm = item as? Map<*, *> ?: return@mapNotNull null
          val name = dm.strOr("entryName") ?: return@mapNotNull null
          NativeApkDexSummary(
            entryName = name,
            byteSize = dm.intOr("byteSize") ?: 0,
            dexVersion = dm.strOr("dexVersion") ?: "",
            isDex041Container = dm["isDex041Container"] as? Boolean ?: false,
            logicalDexCount = dm.intOr("logicalDexCount") ?: 1,
          )
        } ?: emptyList()
      val sig =
        (root["signature"] as? Map<*, *>)?.let { sm ->
          NativeApkSignatureSummary(
            isSigned = sm["isSigned"] as? Boolean ?: false,
            isSignedV1 = sm["isSignedV1"] as? Boolean ?: false,
            isSignedV2 = sm["isSignedV2"] as? Boolean ?: false,
            isSignedV3 = sm["isSignedV3"] as? Boolean ?: false,
            v1SignatureNames =
              (sm["v1SignatureNames"] as? List<*>)?.mapNotNull { it as? String } ?: emptyList(),
            v2SignerCount = sm.intOr("v2SignerCount") ?: 0,
            v3SignerCount = sm.intOr("v3SignerCount") ?: 0,
          )
        }

      NativeApkArchiveSummary(
        isApkm = root["isApkm"] as? Boolean ?: false,
        baseApkName = root.strOr("baseApkName"),
        apkmSplits = splits,
        manifest = manifest,
        nativeAbis = abis,
        dexEntries = dexEntries,
        signature = sig,
      )
    }.getOrNull()
  }

  /**
   * Runs Dalvik structural & `RegType` pre-flight verification on a single method.
   */
  fun verifyDexMethodFast(
    dexBytes: ByteArray,
    classDefIdx: Int,
    methodIdx: Int,
  ): NativeMethodVerificationReport? {
    if (!isAvailable || dexBytes.isEmpty() || classDefIdx < 0 || methodIdx < 0) return null
    val handle = runCatching { nativeOpenDex(dexBytes, dexBytes.size) }.getOrDefault(0L)
    if (handle == 0L) return null
    return try {
      val json = nativeVerifyDexMethod(handle, classDefIdx, methodIdx) ?: return null
      parseMethodVerificationReportJson(json)
    } catch (e: Throwable) {
      safeLog(TAG, "Native method bytecode verification failed", e)
      null
    } finally {
      runCatching { nativeCloseDex(handle) }
    }
  }

  /**
   * Runs Dalvik structural & `RegType` pre-flight verification on all methods of [classDefIdx].
   */
  fun verifyDexClassFast(
    dexBytes: ByteArray,
    classDefIdx: Int,
  ): List<NativeMethodVerificationReport>? {
    if (!isAvailable || dexBytes.isEmpty() || classDefIdx < 0) return null
    val handle = runCatching { nativeOpenDex(dexBytes, dexBytes.size) }.getOrDefault(0L)
    if (handle == 0L) return null
    return try {
      val json = nativeVerifyDexClass(handle, classDefIdx) ?: return null
      parseClassVerificationReportsJson(json)
    } catch (e: Throwable) {
      safeLog(TAG, "Native class bytecode verification failed", e)
      null
    } finally {
      runCatching { nativeCloseDex(handle) }
    }
  }

  /**
   * Aligns (`.so` to [pageAlignment] bytes, default 16384; other stored entries to 4 bytes)
   * and signs [apkBytes] via pure-Rust `apkparser::sign` (v2+v3 enabled, v1 optional).
   */
  fun alignAndSignApkFast(
    apkBytes: ByteArray,
    privateKeyDer: ByteArray? = null,
    certDer: ByteArray? = null,
    enableV1: Boolean = false,
    enableV2: Boolean = true,
    enableV3: Boolean = true,
    pageAlignment: Int = 16384,
  ): ByteArray? {
    if (!isAvailable || apkBytes.size < 22) return null
    return try {
      nativeAlignAndSignApk(
        apkBytes = apkBytes,
        privateKeyDer = privateKeyDer,
        certDer = certDer,
        v1 = enableV1,
        v2 = enableV2,
        v3 = enableV3,
        pageAlignment = pageAlignment,
      )
    } catch (e: Throwable) {
      safeLog(TAG, "Native APK alignment/signing failed", e)
      null
    }
  }

  private inline fun <T> withOpenedDex(dexBytes: ByteArray, block: (Long) -> T?): T? {
    if (!isAvailable || dexBytes.isEmpty()) return null
    val handle = runCatching { nativeOpenDex(dexBytes, dexBytes.size) }.getOrDefault(0L)
    if (handle == 0L) return null
    return try {
      block(handle)
    } finally {
      runCatching { nativeCloseDex(handle) }
    }
  }

  /**
   * Decompiles a single Dalvik method into restructured Java source via `dex-decompiler`,
   * resolving `R.type.name` resource IDs when [arscBytes] is provided.
   */
  fun decompileMethodJavaFast(
    dexBytes: ByteArray,
    classDefIdx: Int,
    methodIdx: Int,
    arscBytes: ByteArray? = null,
  ): String? {
    if (classDefIdx < 0 || methodIdx < 0) return null
    return try {
      withOpenedDex(dexBytes) { handle ->
        nativeDecompileMethodJava(handle, classDefIdx, methodIdx, arscBytes)
      }
    } catch (e: Throwable) {
      safeLog(TAG, "Native method Java decompilation failed", e)
      null
    }
  }

  /**
   * Decompiles an entire DEX class into restructured Java source via `dex-decompiler`.
   */
  fun decompileClassJavaFast(
    dexBytes: ByteArray,
    classDefIdx: Int,
    arscBytes: ByteArray? = null,
  ): String? {
    if (classDefIdx < 0) return null
    return try {
      withOpenedDex(dexBytes) { handle ->
        nativeDecompileClassJava(handle, classDefIdx, arscBytes)
      }
    } catch (e: Throwable) {
      safeLog(TAG, "Native class Java decompilation failed", e)
      null
    }
  }

  internal fun parseMethodVerificationReportJson(rawJson: String): NativeMethodVerificationReport? {
    if (rawJson.isBlank()) return null
    return runCatching {
      parseVerificationReportMap(JsonMini.parseObject(rawJson))
    }.getOrNull()
  }

  internal fun parseClassVerificationReportsJson(rawJson: String): List<NativeMethodVerificationReport>? {
    val trimmed = rawJson.trim()
    if (!trimmed.startsWith("[")) return null
    return runCatching {
      val wrapped = JsonMini.parseObject("{\"reports\":$trimmed}")
      val list = wrapped["reports"] as? List<*> ?: return@runCatching null
      list.mapNotNull { item -> (item as? Map<*, *>)?.let { parseVerificationReportMap(it) } }
    }.getOrNull()
  }

  private fun parseVerificationReportMap(m: Map<*, *>): NativeMethodVerificationReport {
    val rawIssues = m["issues"] as? List<*> ?: emptyList<Any?>()
    val issues =
      rawIssues.mapNotNull { item ->
        val im = item as? Map<*, *> ?: return@mapNotNull null
        NativeVerificationIssue(
          pcWord = im.intOr("pcWord") ?: 0,
          mnemonic = im.strOr("mnemonic") ?: "<unknown>",
          severity = im.strOr("severity") ?: "error",
          code = im.strOr("code") ?: "VERIFY_ERROR",
          message = im.strOr("message") ?: "Bytecode verification error",
        )
      }
    return NativeMethodVerificationReport(
      passed = m["passed"] as? Boolean ?: issues.none { it.severity == "error" },
      classDescriptor = m.strOr("classDescriptor") ?: "",
      methodIdx = m.intOr("methodIdx") ?: 0,
      methodName = m.strOr("methodName") ?: "",
      registersSize = m.intOr("registersSize") ?: 0,
      insSize = m.intOr("insSize") ?: 0,
      instructionCount = m.intOr("instructionCount") ?: 0,
      issues = issues,
    )
  }

  private fun parseManifestSummaryMap(m: Map<*, *>): NativeManifestSummary {
    return NativeManifestSummary(
      packageName = m.strOr("packageName"),
      appLabel = m.strOr("appLabel"),
      applicationName = m.strOr("applicationName"),
      versionName = m.strOr("versionName"),
      versionCode = (m["versionCode"] as? Number)?.toLong(),
      minSdk = m.intOr("minSdk"),
      targetSdk = m.intOr("targetSdk"),
      permissions = (m["permissions"] as? List<*>)?.mapNotNull { it as? String } ?: emptyList(),
      isPacked = m["isPacked"] as? Boolean ?: false,
    )
  }

  private fun Map<*, *>.strOr(key: String): String? = this[key] as? String

  private fun Map<*, *>.intOr(key: String): Int? = (this[key] as? Number)?.toInt()

  private fun safeLog(tag: String, msg: String, tr: Throwable? = null) {
    runCatching {
      if (tr != null) Log.w(tag, msg, tr) else Log.d(tag, msg)
    }
  }
}
