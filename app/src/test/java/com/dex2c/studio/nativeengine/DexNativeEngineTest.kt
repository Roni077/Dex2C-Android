package com.dex2c.studio.nativeengine

import com.dex2c.studio.dex.BlockTerminatorKind
import com.dex2c.studio.dex.CfgEdgeKind
import com.dex2c.studio.dex.D2cnBinaryDecoder
import com.dex2c.studio.dex.D2cnHeader
import com.dex2c.studio.dex.DalvikPayload
import com.dex2c.studio.dex.DexParser
import com.dex2c.studio.dex.OpCategory
import com.dex2c.studio.transpiler.FilterRuleEngine
import com.dex2c.studio.transpiler.TranspilerConfig
import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class DexNativeEngineTest {

  @Test
  fun testEngineFallbackGraceful() {
    // If native library is not on the test host path, isAvailable is false and calling
    // evaluateFilterRules returns null without throwing unhandled exceptions.
    if (!DexNativeEngine.isAvailable) {
      val result = DexNativeEngine.evaluateFilterRules(ByteArray(0), listOf(".*"))
      assertEquals(null, result)
    } else {
      assertNotNull(DexNativeEngine.nativeEngineVersion)
    }
  }

  @Test
  fun testFilterRuleEngineParityWithFallback() {
    val dexBytes = buildMinimalTestDex()
    val parsed = DexParser.parseDex(dexBytes, "test.dex", "classes.dex")

    // 1. Match everything
    val matchAllConfig = TranspilerConfig(filterRulesText = ".*")
    val summaryAll = FilterRuleEngine.evaluateAll(listOf(parsed), matchAllConfig)
    assertEquals(1, summaryAll.matchedMethodIds.size)
    assertEquals(1, summaryAll.matchedClassCount)

    // 2. Exclude the SecretCalc class
    val excludeConfig = TranspilerConfig(filterRulesText = "!^Lcom/example/SecretCalc;.*")
    val summaryExclude = FilterRuleEngine.evaluateAll(listOf(parsed), excludeConfig)
    assertEquals(0, summaryExclude.matchedMethodIds.size)
    assertEquals(0, summaryExclude.matchedClassCount)

    // 3. Match specifically compute method
    val specificConfig = TranspilerConfig(filterRulesText = ".*->compute\\(.*")
    val summarySpecific = FilterRuleEngine.evaluateAll(listOf(parsed), specificConfig)
    assertEquals(1, summarySpecific.matchedMethodIds.size)
    assertEquals(1, summarySpecific.matchedClassCount)
  }

  @Test
  fun testCorruptedDexBufferSafety() {
    // Ensure that malformed or truncated DEX buffers do not crash the engine
    val emptyBytes = ByteArray(0)
    val invalidBytes = byteArrayOf(0x64, 0x65, 0x78, 0x0a, 0x00, 0x00) // truncated header

    val res1 = DexNativeEngine.evaluateFilterRules(emptyBytes, listOf(".*"))
    val res2 = DexNativeEngine.evaluateFilterRules(invalidBytes, listOf(".*"))
    val res3 = DexNativeEngine.disassembleSmaliFast(emptyBytes, 0)
    val res4 = DexNativeEngine.transpileMethodFast(emptyBytes, 0, 0)
    val res5 = DexNativeEngine.patchDexMethodsFast(emptyBytes, setOf(0))
    val res6 = DexNativeEngine.disassembleMethodFast(emptyBytes, 0, 0)
    val res7 = DexNativeEngine.disassembleMethodFast(invalidBytes, -1, 0)

    assertEquals(null, res1)
    assertEquals(null, res2)
    assertEquals(null, res3)
    assertEquals(null, res4)
    assertEquals(null, res5)
    assertEquals(null, res6)
    assertEquals(null, res7)
  }

  @Test
  fun testSmaliDisassemblerFallbackSafety() {
    val dexBytes = buildMinimalTestDex()
    val parsed = DexParser.parseDex(dexBytes, "test.dex", "classes.dex")
    assertTrue("At least one class should be parsed", parsed.classes.isNotEmpty())
    val cls = parsed.classes.first()

    val result = com.dex2c.studio.dex.SmaliClassDisassembler.disassembleClass(parsed, cls)
    assertNotNull(result)
    assertTrue("Disassembly should produce lines", result.lines.isNotEmpty())
    assertTrue("Engine label should be present", result.engineLabel.isNotBlank())

    if (cls.allMethods.isNotEmpty()) {
      val methodSmali = com.dex2c.studio.dex.SmaliClassDisassembler.disassembleMethod(parsed, cls, cls.allMethods.first())
      assertNotNull(methodSmali)
      assertTrue("Method smali should start with .method", methodSmali.trim().startsWith(".method"))
    }
  }

  @Test
  fun testFullAppRustEngineDefaults() {
    val settings = com.dex2c.studio.data.AppSettings()
    assertEquals(
      "Default editor engine must be RUST_HYBRID",
      com.dex2c.studio.data.EditorEngineType.RUST_HYBRID,
      settings.editorEngine,
    )

    // Test filter editor session defaults
    val filterSession = EditorNativeEngine.createSession("# Filter\n!com/example/Test", EditorNativeEngine.GRAMMAR_FILTER_TXT)
    try {
      assertEquals(2, filterSession.lineCount)
      val tokens = filterSession.getLineTokens(0, 2)
      assertEquals(2, tokens.size)
      assertEquals(NativeTokenSpan.KIND_COMMENT, tokens[0][0].kind)
      assertEquals(NativeTokenSpan.KIND_FILTER_EXCLUSION, tokens[1][0].kind)
    } finally {
      filterSession.close()
    }
  }

  @Test
  fun testDex2cNativeRepositorySafety() {
    val repo = com.dex2c.studio.data.repository.Dex2cNativeRepository()
    kotlinx.coroutines.runBlocking {
      val parsed = repo.parseClasses(ByteArray(0))
      assertEquals(null, parsed)
      val filtered = repo.evaluateFilterRules(ByteArray(0), listOf(".*"))
      assertEquals(null, filtered)
      val smali = repo.disassembleSmali(ByteArray(0), 0)
      assertEquals(null, smali)
      val cpp = repo.transpileMethod(ByteArray(0), 0, 0)
      assertEquals(null, cpp)
      val patched = repo.patchDex(ByteArray(0), setOf(0))
      assertEquals(null, patched)
      val disasm = repo.disassembleMethod(ByteArray(0), 0, 0)
      assertEquals(null, disasm)
      val manifest = repo.inspectManifestAndResources(ByteArray(0), null)
      assertEquals(null, manifest)
      val apk = repo.inspectApkArchive(ByteArray(0))
      assertEquals(null, apk)
      val split041 = repo.splitDex041Container("classes.dex", ByteArray(0))
      assertEquals(null, split041)
      val verifyMethod = repo.verifyDexMethod(ByteArray(0), 0, 0)
      assertEquals(null, verifyMethod)
      val verifyClass = repo.verifyDexClass(ByteArray(0), 0)
      assertEquals(null, verifyClass)
      val signedApk = repo.alignAndSignApk(ByteArray(0))
      assertEquals(null, signedApk)
      val decompMethod = repo.decompileMethodJava(ByteArray(0), 0, 0)
      assertEquals(null, decompMethod)
      val decompClass = repo.decompileClassJava(ByteArray(0), 0)
      assertEquals(null, decompClass)
    }
  }

  @Test
  fun testParseMethodAndClassVerificationReportJson() {
    assertNull(DexNativeEngine.parseMethodVerificationReportJson(""))
    assertNull(DexNativeEngine.parseClassVerificationReportsJson("{not-an-array}"))

    val methodJson =
      """
      {
        "passed": false,
        "classDescriptor": "Lcom/example/Edited;",
        "methodIdx": 7,
        "methodName": "brokenMethod",
        "registersSize": 2,
        "insSize": 1,
        "instructionCount": 3,
        "issues": [
          {
            "pcWord": 2,
            "mnemonic": "return-object",
            "severity": "error",
            "code": "TYPE_MISMATCH_REF",
            "message": "Expected initialized reference/null in v0, found Primitive32"
          }
        ]
      }
      """.trimIndent()
    val single = DexNativeEngine.parseMethodVerificationReportJson(methodJson)
    assertNotNull(single)
    assertFalse(single!!.passed)
    assertEquals("brokenMethod", single.methodName)
    assertEquals(1, single.issues.size)
    assertEquals("TYPE_MISMATCH_REF", single.issues.first().code)
    assertEquals(2, single.issues.first().pcWord)

    val classReports = DexNativeEngine.parseClassVerificationReportsJson("[$methodJson]")
    assertNotNull(classReports)
    assertEquals(1, classReports!!.size)
    assertFalse(classReports.first().passed)
  }

  @Test
  fun testParseManifestAndApkArchiveJsonDecodesAxmlArscDex041AndSignature() {
    assertNull(DexNativeEngine.parseManifestSummaryJson(""))
    assertNull(DexNativeEngine.parseApkArchiveSummaryJson("{invalid"))

    val manifestJson =
      """
      {
        "packageName": "com.example.shop",
        "appLabel": "Shop Demo",
        "applicationName": "com.example.shop.ShopApp",
        "versionName": "3.1.4",
        "versionCode": 314,
        "minSdk": 24,
        "targetSdk": 36,
        "permissions": ["android.permission.INTERNET"],
        "isPacked": false
      }
      """.trimIndent()
    val parsedManifest = DexNativeEngine.parseManifestSummaryJson(manifestJson)
    assertNotNull(parsedManifest)
    assertEquals("com.example.shop", parsedManifest?.packageName)
    assertEquals("Shop Demo", parsedManifest?.appLabel)
    assertEquals("com.example.shop.ShopApp", parsedManifest?.applicationName)
    assertEquals(314L, parsedManifest?.versionCode)
    assertEquals(24, parsedManifest?.minSdk)
    assertEquals(36, parsedManifest?.targetSdk)
    assertEquals(listOf("android.permission.INTERNET"), parsedManifest?.permissions)

    val archiveJson =
      """
      {
        "isApkm": true,
        "baseApkName": "base.apk",
        "apkmSplits": ["split_config.arm64_v8a.apk"],
        "manifest": $manifestJson,
        "nativeAbis": ["arm64-v8a", "armeabi-v7a"],
        "dexEntries": [
          {
            "entryName": "classes.dex",
            "byteSize": 65536,
            "dexVersion": "041",
            "isDex041Container": true,
            "logicalDexCount": 3
          }
        ],
        "signature": {
          "isSigned": true,
          "isSignedV1": false,
          "isSignedV2": true,
          "isSignedV3": true,
          "v1SignatureNames": [],
          "v2SignerCount": 1,
          "v3SignerCount": 1
        }
      }
      """.trimIndent()
    val parsedArchive = DexNativeEngine.parseApkArchiveSummaryJson(archiveJson)
    assertNotNull(parsedArchive)
    assertTrue(parsedArchive?.isApkm == true)
    assertEquals("base.apk", parsedArchive?.baseApkName)
    assertEquals(listOf("split_config.arm64_v8a.apk"), parsedArchive?.apkmSplits)
    assertEquals(listOf("arm64-v8a", "armeabi-v7a"), parsedArchive?.nativeAbis)
    assertEquals(1, parsedArchive?.dexEntries?.size)
    assertTrue(parsedArchive?.dexEntries?.first()?.isDex041Container == true)
    assertEquals(3, parsedArchive?.dexEntries?.first()?.logicalDexCount)
    assertTrue(parsedArchive?.signature?.isSignedV2 == true)
    assertTrue(parsedArchive?.signature?.isSignedV3 == true)
  }

  @Test
  fun testParseMethodDisassemblyJsonDecodesInstructionsPayloadsTryBlocksAndCfg() {
    assertNull(DexNativeEngine.parseMethodDisassemblyJson(""))
    assertNull(DexNativeEngine.parseMethodDisassemblyJson("{not-valid"))

    val sampleJson =
      """
      {
        "instructions": [
          {
            "offsetWords": 0,
            "widthWords": 2,
            "opcode": 56,
            "mnemonic": "if-eqz",
            "format": "21t",
            "operandsText": "v1, +0x0004",
            "rawWords": [312, 4],
            "category": "BRANCH",
            "regA": 1,
            "regB": null,
            "regC": null,
            "regList": [],
            "isRangeInvoke": false,
            "literal": null,
            "targetOffset": 4,
            "stringRef": null,
            "typeRef": null,
            "fieldRef": null,
            "methodRef": null,
            "payload": null
          },
          {
            "offsetWords": 2,
            "widthWords": 1,
            "opcode": 129,
            "mnemonic": "int-to-long",
            "format": "12x",
            "operandsText": "v0, v1",
            "rawWords": [4225],
            "category": "CONVERT",
            "regA": 0,
            "regB": 1,
            "regC": null,
            "regList": [],
            "isRangeInvoke": false,
            "literal": null,
            "targetOffset": null,
            "stringRef": null,
            "typeRef": null,
            "fieldRef": null,
            "methodRef": null,
            "payload": null
          },
          {
            "offsetWords": 3,
            "widthWords": 3,
            "opcode": 110,
            "mnemonic": "invoke-virtual",
            "format": "35c",
            "operandsText": "{v0, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;",
            "rawWords": [8302, 1, 16],
            "category": "INVOKE",
            "regA": null,
            "regB": null,
            "regC": null,
            "regList": [0, 1],
            "isRangeInvoke": false,
            "literal": null,
            "targetOffset": null,
            "stringRef": null,
            "typeRef": null,
            "fieldRef": {
              "definingClass": "Lcom/example/Box;",
              "type": "I",
              "name": "value"
            },
            "methodRef": {
              "definingClass": "Ljava/lang/StringBuilder;",
              "proto": {
                "shorty": "LI",
                "returnType": "Ljava/lang/StringBuilder;",
                "parameterTypes": ["I"]
              },
              "name": "append"
            },
            "payload": {
              "kind": "packed_switch",
              "offsetWords": 10,
              "wordCount": 6,
              "firstKey": 100,
              "targetOffsets": [16, 20]
            }
          }
        ],
        "tryBlocks": [
          {
            "startOffsetWord": 0,
            "insnCount": 4,
            "handlers": [
              {
                "typeDescriptor": "Ljava/lang/Exception;",
                "handlerOffsetWord": 4
              },
              {
                "typeDescriptor": null,
                "handlerOffsetWord": 8
              }
            ]
          }
        ],
        "cfg": {
          "blocks": [
            {
              "id": "BB0",
              "index": 0,
              "startOffsetWords": 0,
              "endOffsetWords": 2,
              "instructionIndices": [0],
              "terminatorKind": "CONDITIONAL_BRANCH",
              "isEntry": true,
              "isExceptionHandler": false,
              "predecessors": [],
              "outgoingEdges": [
                {
                  "fromBlockId": "BB0",
                  "toBlockId": "BB1",
                  "toOffsetWords": 2,
                  "kind": "FALLTHROUGH",
                  "label": "false"
                },
                {
                  "fromBlockId": "BB0",
                  "toBlockId": "BB2",
                  "toOffsetWords": 4,
                  "kind": "EXCEPTION_HANDLER",
                  "label": "catch Exception"
                }
              ]
            },
            {
              "id": "BB1",
              "index": 1,
              "startOffsetWords": 2,
              "endOffsetWords": 6,
              "instructionIndices": [1, 2],
              "terminatorKind": "RETURN",
              "isEntry": false,
              "isExceptionHandler": false,
              "predecessors": ["BB0"],
              "outgoingEdges": []
            }
          ],
          "edgeCount": 2,
          "branchCount": 1,
          "exceptionEdgeCount": 1,
          "engineLabel": "Rust Native (dex-bytecode CFG)"
        }
      }
      """.trimIndent()

    val decoded = DexNativeEngine.parseMethodDisassemblyJson(sampleJson)
    assertNotNull(decoded)
    val result = decoded!!

    assertEquals(3, result.instructions.size)
    assertEquals(OpCategory.BRANCH, result.instructions[0].category)
    assertEquals(4, result.instructions[0].targetOffset)
    assertEquals(OpCategory.CONVERT, result.instructions[1].category)
    assertEquals("int-to-long", result.instructions[1].mnemonic)
    assertEquals(listOf(0, 1), result.instructions[2].regList)
    assertEquals("com/example/Box;", result.instructions[2].fieldRef?.definingClass?.removePrefix("L"))
    assertEquals("append", result.instructions[2].methodRef?.name)
    assertEquals(listOf("I"), result.instructions[2].methodRef?.proto?.parameterTypes)
    val switchPayload = result.instructions[2].payload as? DalvikPayload.PackedSwitch
    assertNotNull(switchPayload)
    assertEquals(100, switchPayload?.firstKey)
    assertEquals(listOf(16, 20), switchPayload?.targetOffsets)

    assertEquals(1, result.tryBlocks.size)
    assertEquals(2, result.tryBlocks[0].handlers.size)
    assertEquals("Ljava/lang/Exception;", result.tryBlocks[0].handlers[0].typeDescriptor)
    assertNull(result.tryBlocks[0].handlers[1].typeDescriptor)

    assertEquals(2, result.cfg.blocks.size)
    assertEquals(1, result.cfg.payloads.size)
    assertEquals(2, result.cfg.edgeCount)
    assertEquals(1, result.cfg.branchCount)
    assertEquals(1, result.cfg.exceptionEdgeCount)
    assertEquals("Rust Native (dex-bytecode CFG)", result.cfg.engineLabel)
    assertEquals(BlockTerminatorKind.CONDITIONAL_BRANCH, result.cfg.blocks[0].terminatorKind)
    assertEquals(CfgEdgeKind.EXCEPTION_HANDLER, result.cfg.blocks[0].outgoingEdges[1].kind)
  }

  @Test
  fun testD2cnBinaryDecoderSynthesizedBuffer() {
    val stringPool = listOf(
      "Lcom/example/TestClass;",
      "com.example.TestClass",
      "com.example",
      "TestClass",
      "Ljava/lang/Object;",
      "TestClass.java",
      "Ljava/lang/Runnable;",
      "myField",
      "I",
      "testMethod",
      "V"
    )

    val out = ByteArrayOutputStream()
    // 1. Header (32 bytes placeholder)
    val headerBytes = ByteArray(32)
    out.write(headerBytes)

    val stringPoolOff = out.size()
    stringPool.forEach { s ->
      val bytes = s.toByteArray(Charsets.UTF_8)
      out.write(bytes.size and 0xFF)
      out.write((bytes.size ushr 8) and 0xFF)
      out.write(bytes)
    }

    val classesOff = out.size()
    val buf = ByteBuffer.allocate(1024).order(ByteOrder.LITTLE_ENDIAN)
    // Class record:
    buf.putInt(0) // class_def_idx
    buf.putInt(1) // access_flags (public)
    buf.putInt(0) // descriptor_idx -> "Lcom/example/TestClass;"
    buf.putInt(1) // full_name_idx -> "com.example.TestClass"
    buf.putInt(2) // pkg_name_idx -> "com.example"
    buf.putInt(3) // simple_name_idx -> "TestClass"
    buf.putInt(4) // superclass_idx -> "Ljava/lang/Object;"
    buf.putInt(5) // source_file_idx -> "TestClass.java"
    buf.putInt(0x100) // annotations_off
    buf.putInt(0x200) // static_values_off
    buf.putInt(0x300) // class_data_off

    // Interfaces: 1
    buf.putShort(1)
    buf.putInt(6) // "Ljava/lang/Runnable;"

    // Static fields: 0
    buf.putShort(0)

    // Instance fields: 1
    buf.putShort(1)
    buf.putInt(10) // field_idx
    buf.putInt(2)  // access_flags (private)
    buf.putInt(7)  // name_idx -> "myField"
    buf.putInt(8)  // type_idx -> "I"

    // Direct methods: 1
    buf.putShort(1)
    buf.putInt(20) // method_idx
    buf.putInt(1)  // access_flags (public)
    buf.putInt(9)  // name_idx -> "testMethod"
    buf.putInt(10) // shorty_idx -> "V"
    buf.putInt(10) // ret_idx -> "V"
    buf.putShort(0) // param_count: 0
    buf.put(1.toByte()) // has_code = 1
    buf.putShort(4) // regs
    buf.putShort(1) // ins
    buf.putShort(2) // outs
    buf.putShort(0) // tries
    buf.putInt(3)   // insns_count
    buf.putInt(0x400) // insns_offset_bytes
    buf.putInt(0x380) // code_item_offset
    buf.putInt(0x500) // debug_info_offset

    // Virtual methods: 0
    buf.putShort(0)

    out.write(buf.array(), 0, buf.position())

    val totalBytes = out.toByteArray()
    // Patch header at offset 0
    val headerBuf = ByteBuffer.wrap(totalBytes).order(ByteOrder.LITTLE_ENDIAN)
    headerBuf.putInt(0, D2cnHeader.MAGIC)
    headerBuf.putShort(4, 1.toShort()) // version
    headerBuf.putShort(6, 0.toShort()) // flags
    headerBuf.putInt(8, 32) // header_size
    headerBuf.putInt(12, stringPool.size)
    headerBuf.putInt(16, 1) // class_count
    headerBuf.putInt(20, 1) // method_count
    headerBuf.putInt(24, stringPoolOff)
    headerBuf.putInt(28, classesOff)

    val classes = D2cnBinaryDecoder.decodeClasses(ByteBuffer.wrap(totalBytes))
    assertEquals(1, classes.size)
    val cls = classes.first()
    assertEquals("Lcom/example/TestClass;", cls.descriptor)
    assertEquals("com.example.TestClass", cls.fullName)
    assertEquals("com.example", cls.packageName)
    assertEquals("TestClass", cls.simpleName)
    assertEquals("Ljava/lang/Object;", cls.superclass)
    assertEquals("TestClass.java", cls.sourceFile)
    assertEquals(listOf("Ljava/lang/Runnable;"), cls.interfaces)
    assertEquals(1, cls.instanceFields.size)
    assertEquals("myField", cls.instanceFields[0].fieldRef.name)
    assertEquals("I", cls.instanceFields[0].fieldRef.type)
    assertEquals(1, cls.directMethods.size)
    val m = cls.directMethods.first()
    assertEquals("testMethod", m.methodRef.name)
    assertNotNull(m.codeMeta)
    assertEquals(4, m.codeMeta?.registersSize)
    assertEquals(3, m.codeMeta?.insnsCount)
  }

  private fun buildMinimalTestDex(): ByteArray {
    val strings = listOf("I", "III", "Lcom/example/SecretCalc;", "Ljava/lang/Object;", "compute")
    val strDataStream = ByteArrayOutputStream()
    val strDataOffsets = mutableListOf<Int>()

    val stringDataBase = 0x100
    strings.forEach { s ->
      strDataOffsets += stringDataBase + strDataStream.size()
      val utf8 = s.toByteArray(Charsets.UTF_8)
      strDataStream.write(utf8.size)
      strDataStream.write(utf8)
      strDataStream.write(0)
    }

    val totalSize = stringDataBase + strDataStream.size()
    val buf = ByteBuffer.allocate(totalSize).order(ByteOrder.LITTLE_ENDIAN)

    buf.position(0)
    buf.put("dex\n035\u0000".toByteArray(Charsets.US_ASCII))
    buf.putInt(0x20, totalSize)
    buf.putInt(0x24, 0x70)
    buf.putInt(0x28, 0x12345678)
    buf.putInt(0x38, strings.size)
    buf.putInt(0x3C, 0x70)
    buf.putInt(0x40, 2)
    buf.putInt(0x44, 0x84)
    buf.putInt(0x48, 1)
    buf.putInt(0x4C, 0x8C)
    buf.putInt(0x50, 0)
    buf.putInt(0x54, 0)
    buf.putInt(0x58, 1)
    buf.putInt(0x5C, 0x98)
    buf.putInt(0x60, 1)
    buf.putInt(0x64, 0xA0)

    strDataOffsets.forEachIndexed { idx, off -> buf.putInt(0x70 + idx * 4, off) }
    buf.putInt(0x84, 0)
    buf.putInt(0x88, 2)
    buf.putInt(0x8C, 1)
    buf.putInt(0x90, 0)
    buf.putInt(0x94, 0xC0)
    buf.putShort(0x98, 1)
    buf.putShort(0x9A, 0)
    buf.putInt(0x9C, 4)
    buf.putInt(0xA0, 1)
    buf.putInt(0xA4, 1)
    buf.putInt(0xA8, -1)
    buf.putInt(0xAC, 0)
    buf.putInt(0xB0, -1)
    buf.putInt(0xB4, 0)
    buf.putInt(0xB8, 0xE0)
    buf.putInt(0xBC, 0)
    buf.putInt(0xC0, 2)
    buf.putShort(0xC4, 0)
    buf.putShort(0xC6, 0)

    buf.putShort(0xC8, 3)
    buf.putShort(0xCA, 2)
    buf.putShort(0xCC, 0)
    buf.putShort(0xCE, 0)
    buf.putInt(0xD0, 0)
    buf.putInt(0xD4, 4)
    buf.putShort(0xD8, 0x5012.toShort())
    buf.putShort(0xDA, 0x0090.toShort())
    buf.putShort(0xDC, 0x0201.toShort())
    buf.putShort(0xDE, 0x000F.toShort())

    var p = 0xE0
    fun putUleb(v: Int) {
      var x = v
      do {
        var b = x and 0x7F
        x = x ushr 7
        if (x != 0) b = b or 0x80
        buf.put(p++, b.toByte())
      } while (x != 0)
    }
    putUleb(0)
    putUleb(0)
    putUleb(1)
    putUleb(0)
    putUleb(0)
    putUleb(9)
    putUleb(0xC8)

    val strBytes = strDataStream.toByteArray()
    buf.position(stringDataBase)
    buf.put(strBytes)

    return buf.array()
  }
}
