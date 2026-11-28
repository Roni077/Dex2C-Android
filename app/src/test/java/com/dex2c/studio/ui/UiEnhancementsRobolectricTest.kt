package com.dex2c.studio.ui

import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import com.dex2c.studio.cloud.GitHubApiClient
import com.dex2c.studio.cloud.GitHubWorkflowStep
import com.dex2c.studio.dex.DexClassInfo
import com.dex2c.studio.dex.DexCodeMeta
import com.dex2c.studio.dex.DexEncodedMethod
import com.dex2c.studio.dex.DexMethodRef
import com.dex2c.studio.dex.DexMethodStructuralMeta
import com.dex2c.studio.dex.DexProto
import com.dex2c.studio.transpiler.TranspilerConfig
import com.dex2c.studio.ui.MethodInspectionState
import com.dex2c.studio.ui.components.BatchActionBar
import com.dex2c.studio.ui.components.FilterRustEditor
import com.dex2c.studio.ui.components.InteractiveFilterRuleBuilderPanel
import com.dex2c.studio.ui.components.formatDisplaySteps
import com.dex2c.studio.ui.screens.MethodDetailScreen
import com.dex2c.studio.ui.theme.Dex2cTheme
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [36], qualifiers = "w412dp-h892dp")
class UiEnhancementsRobolectricTest {

  @get:Rule val composeTestRule = createComposeRule()

  @Test
  fun testFormatDisplayStepsHidesLogStepOnSuccessAndMovesToEndOnFailure() {
    val steps = listOf(
      GitHubWorkflowStep("Set up job", "completed", "success"),
      GitHubWorkflowStep("Checkout Private Workspace", "completed", "success"),
      GitHubWorkflowStep("Compile codehasan/dex2c", "completed", "success"),
      GitHubWorkflowStep("Align & Auto-Sign Output APK", "completed", "success"),
      GitHubWorkflowStep("Upload Signed Dex2C APK Artifact", "completed", "success"),
      GitHubWorkflowStep("Upload Dex2C Build Log", "completed", "skipped"),
      GitHubWorkflowStep("Post Setup", "completed", "success"),
      GitHubWorkflowStep("Complete job", "completed", "success"),
    )

    // Build succeeded: Upload Dex2C Build Log must be hidden
    val successDisplay = formatDisplaySteps(steps, isSuccess = true)
    assertEquals(7, successDisplay.size)
    assertFalse(successDisplay.any { it.name.contains("upload dex2c build log", ignoreCase = true) })

    // Build failed: Upload Dex2C Build Log must be at the very end
    val failureSteps = listOf(
      GitHubWorkflowStep("Set up job", "completed", "success"),
      GitHubWorkflowStep("Run codehasan/dex2c Compilation", "completed", "failure"),
      GitHubWorkflowStep("Upload Dex2C Build Log", "completed", "success"),
      GitHubWorkflowStep("Post Setup", "completed", "success"),
      GitHubWorkflowStep("Complete job", "completed", "success"),
    )
    val failureDisplay = formatDisplaySteps(failureSteps, isSuccess = false)
    assertEquals(5, failureDisplay.size)
    assertEquals("Upload Dex2C Build Log", failureDisplay.last().name)
  }

  @Test
  fun testAwsS3XmlErrorDetection() {
    val client = GitHubApiClient()
    val s3ErrorXml = """
      <?xml version="1.0" encoding="utf-8"?>
      <Error><Code>InvalidArgument</Code><Message>Only one auth mechanism allowed; only the X-Amz-Algorithm query parameter, Signature query string parameter or the Authorization header should be specified</Message></Error>
    """.trimIndent()
    assertTrue(client.isAwsS3XmlError(s3ErrorXml))

    val normalLog = "Starting Dex2C build...\nCompiled 45 classes cleanly.\nDone."
    assertFalse(client.isAwsS3XmlError(normalLog))
  }

  @Test
  fun testBatchActionBarOnlyShowsCountAndFilterButtons() {
    composeTestRule.setContent {
      Dex2cTheme {
        BatchActionBar(
          selectedCount = 3,
          onFilterSelected = {},
          onClearSelection = {},
        )
      }
    }

    composeTestRule.onNodeWithText("3 sel").assertIsDisplayed()
    composeTestRule.onNodeWithTag("batch_add_to_filter_btn").assertIsDisplayed()
    composeTestRule.onNodeWithTag("batch_clear_btn").assertIsDisplayed()

    // Select All, Deselect, Invert must not exist
    composeTestRule.onNodeWithTag("batch_select_all_btn").assertDoesNotExist()
    composeTestRule.onNodeWithTag("batch_deselect_all_btn").assertDoesNotExist()
    composeTestRule.onNodeWithTag("batch_invert_selection_btn").assertDoesNotExist()
  }

  @Test
  fun testFilterRustEditorOnlyShowsEditButton() {
    composeTestRule.setContent {
      Dex2cTheme {
        FilterRustEditor(
          filterText = "com/example/MyClass",
          onFilterTextChanged = {},
          wordWrap = true,
        )
      }
    }

    composeTestRule.onNodeWithTag("filter_bulk_edit_button").assertIsDisplayed()
    composeTestRule.onNodeWithTag("filter_search_toggle").assertDoesNotExist()
    composeTestRule.onNodeWithTag("filter_undo_button").assertDoesNotExist()
    composeTestRule.onNodeWithTag("filter_redo_button").assertDoesNotExist()
  }

  @Test
  fun testInteractiveFilterRuleBuilderPanelShowsDynamicTargetPackage() {
    composeTestRule.setContent {
      Dex2cTheme {
        InteractiveFilterRuleBuilderPanel(
          config = TranspilerConfig(),
          hasLoadedDex = true,
          filterMatchSummary = null,
          selectedMethodCount = 0,
          onUpdateConfig = {},
          onApplyFilterRules = {},
          targetPackageName = "com.sample.dynamictarget",
        )
      }
    }

    composeTestRule.onNodeWithText("Target: com.sample.dynamictarget.*").assertIsDisplayed()
    composeTestRule.onNodeWithTag("preset_target_package").assertIsDisplayed()
  }

  private fun buildJavaMethodInspection(
    classDescriptor: String,
    simpleName: String,
    fullName: String,
    methodName: String,
    proto: DexProto,
    paramNames: List<String>,
    decompiledJava: String,
  ): MethodInspectionState {
    val method =
      DexEncodedMethod(
        id = "classes.dex::$classDescriptor#0",
        methodIndex = 0,
        methodRef = DexMethodRef(definingClass = classDescriptor, proto = proto, name = methodName),
        accessFlags = 0x0001,
        isDirect = false,
        codeMeta = DexCodeMeta(2, 1 + proto.parameterTypes.size, 0, 0, 4, 0),
        sourceEntryName = "classes.dex",
      )
    val dexClass =
      DexClassInfo(
        classIndex = 0,
        descriptor = classDescriptor,
        fullName = fullName,
        simpleName = simpleName,
        packageName = "com.example",
        superclass = "Ljava/lang/Object;",
        interfaces = emptyList(),
        sourceFile = "$simpleName.java",
        accessFlags = 0x0001,
        staticFields = emptyList(),
        instanceFields = emptyList(),
        directMethods = emptyList(),
        virtualMethods = listOf(method),
      )
    return MethodInspectionState(
      method = method,
      dexClass = dexClass,
      instructions = emptyList(),
      tryBlocks = emptyList(),
      transpiledC = "void Java_stub(JNIEnv* env, jobject thiz) {}",
      structuralMeta =
        DexMethodStructuralMeta(
          methodIndex = 0,
          codeItemOffset = 0,
          debugInfoOffset = 0,
          classAnnotationsOffset = 0,
          staticValuesOffset = 0,
          parameterNames = paramNames,
          debugLines = emptyList(),
          classAnnotations = emptyList(),
          methodAnnotations = emptyList(),
          staticValuesPreview = emptyList(),
          sourceFile = "$simpleName.java",
        ),
      decompiledJava = decompiledJava,
    )
  }

  @Test
  fun testMethodDetailScreenJavaTabDisplaysAndCopiesDecompiledJava() {
    val sampleJava =
      """
      public boolean checkAccess(int code) {
          if (code == 42) {
              return true;
          }
          return false;
      }
      """.trimIndent()
    val inspection =
      buildJavaMethodInspection(
        classDescriptor = "Lcom/example/Guard;",
        simpleName = "Guard",
        fullName = "com.example.Guard",
        methodName = "checkAccess",
        proto = DexProto(shorty = "ZI", returnType = "Z", parameterTypes = listOf("I")),
        paramNames = listOf("code"),
        decompiledJava = sampleJava,
      )

    var copied = ""
    composeTestRule.setContent {
      Dex2cTheme {
        MethodDetailScreen(
          inspection = inspection,
          isSelected = false,
          onToggleSelect = {},
          onCopyCCode = { copied = it },
          onBack = {},
        )
      }
    }

    composeTestRule.onNodeWithTag("tab_method_java").assertIsDisplayed().performClick()
    composeTestRule.waitForIdle()
    composeTestRule.onNodeWithTag("java_code_viewer").assertIsDisplayed()
    composeTestRule.onNodeWithText("public boolean checkAccess(int code) {", substring = true).assertIsDisplayed()
    composeTestRule.onNodeWithTag("method_copy_c_btn").performClick()
    assertEquals(sampleJava, copied)
  }

  @Test
  @Config(sdk = [36], qualifiers = "w840dp-h900dp")
  fun testMethodDetailScreenWideLayoutDisplaysJavaSegmentedTab() {
    val sampleJava = "public void ping() {\n    System.out.println(\"pong\");\n}"
    val inspection =
      buildJavaMethodInspection(
        classDescriptor = "Lcom/example/WideHost;",
        simpleName = "WideHost",
        fullName = "com.example.WideHost",
        methodName = "ping",
        proto = DexProto(shorty = "V", returnType = "V", parameterTypes = emptyList()),
        paramNames = emptyList(),
        decompiledJava = sampleJava,
      )

    composeTestRule.setContent {
      Dex2cTheme {
        MethodDetailScreen(
          inspection = inspection,
          isSelected = false,
          onToggleSelect = {},
          onCopyCCode = {},
          onBack = {},
        )
      }
    }

    composeTestRule.onNodeWithTag("tab_method_java_wide").assertIsDisplayed().performClick()
    composeTestRule.waitForIdle()
    composeTestRule.onNodeWithTag("java_code_viewer").assertIsDisplayed()
    composeTestRule.onNodeWithText("public void ping() {", substring = true).assertIsDisplayed()
  }
}
