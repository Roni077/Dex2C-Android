package com.dex2c.studio.dex

import com.dex2c.studio.nativeengine.DexNativeEngine

/**
 * Pure post-condition verification gates to ensure DEX modifications meet invariants
 * before in-memory state is replaced.
 */
object DexEditVerifier {

  /**
   * Asserts that [descriptor] is present in [parsed].
   * Returns an error description if missing, or null if verification passed.
   */
  fun verifyClassPresent(parsed: DexParsedFile, descriptor: String): String? {
    val found = parsed.classes.any { it.descriptor == descriptor }
    return if (!found) {
      "Target class $descriptor was not found in assembled DEX output."
    } else null
  }

  /**
   * Asserts that all [deletedDescriptors] are completely absent from [parsed].
   * Returns an error description if any deleted class is still present, or null if passed.
   */
  fun verifyClassesDeleted(parsed: DexParsedFile, deletedDescriptors: Set<String>): String? {
    val remaining = parsed.classes.filter { it.descriptor in deletedDescriptors }
    return if (remaining.isNotEmpty()) {
      "Failed to remove ${remaining.size} class(es); still present in DEX output."
    } else null
  }

  /**
   * Asserts that [count] of replacements is greater than zero.
   * Returns an error description if 0 or negative, or null if passed.
   */
  fun verifyReplacementCount(count: Int, query: String): String? {
    return if (count <= 0) {
      "No string literals matching '$query' found in active DEX."
    } else null
  }

  /**
   * Pre-flight structural and Dalvik `RegType` verification of a recompiled class
   * using native `dex2c-dex::verifier` (`nativeVerifyDexClass`) when available.
   */
  fun verifyCompiledClassBytecode(
    dexBytes: ByteArray,
    parsed: DexParsedFile,
    targetDescriptor: String,
  ): String? {
    if (dexBytes.size < 0x70 || !String(dexBytes, 0, 4, Charsets.US_ASCII).startsWith("dex\n")) {
      return "Recompiled output does not start with a valid DEX header."
    }
    val classDefIdx = parsed.classes.indexOfFirst { it.descriptor == targetDescriptor }
    if (classDefIdx < 0) {
      return "Target class $targetDescriptor missing from assembled DEX class_defs."
    }
    if (!DexNativeEngine.isAvailable) {
      return null
    }
    val reports = DexNativeEngine.verifyDexClassFast(dexBytes, classDefIdx) ?: return null
    val failing = reports.firstOrNull { !it.passed } ?: return null
    val firstIssue = failing.issues.firstOrNull { it.severity == "error" } ?: failing.issues.firstOrNull()
    val detail =
      if (firstIssue != null) {
        "${firstIssue.code} at pc=0x%04X (${firstIssue.mnemonic}): ${firstIssue.message}".format(firstIssue.pcWord)
      } else {
        "Verification failed with unspecified bytecode error"
      }
    return "${failing.methodName}: $detail"
  }
}
