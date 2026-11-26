package com.dex2c.studio.ui

import android.content.Context
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.test.core.app.ApplicationProvider
import com.dex2c.studio.data.AppPreferences
import com.dex2c.studio.ui.components.TelegramPromoDialog
import com.dex2c.studio.ui.theme.Dex2cTheme
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [36], qualifiers = "w412dp-h892dp")
class TelegramPromoDialogRobolectricTest {

  @get:Rule val composeTestRule = createComposeRule()

  @Test
  fun testTelegramPromoDialogElementsDisplayedAndDismissOptionsRemoved() {
    composeTestRule.setContent {
      Dex2cTheme {
        TelegramPromoDialog(
          onJoin = {},
        )
      }
    }

    // Must be displayed
    composeTestRule.onNodeWithTag("telegram_promo_dialog").assertIsDisplayed()
    composeTestRule.onNodeWithText("Join Dex2C on Telegram").assertIsDisplayed()
    composeTestRule.onNodeWithTag("telegram_promo_join_btn").assertIsDisplayed()

    // Must NOT exist (all removed per specification)
    composeTestRule.onNodeWithTag("telegram_promo_later_btn").assertDoesNotExist()
    composeTestRule.onNodeWithTag("telegram_promo_close_btn").assertDoesNotExist()
    composeTestRule.onNodeWithTag("telegram_promo_dont_show_checkbox").assertDoesNotExist()
    composeTestRule.onNodeWithTag("telegram_promo_dont_show_again_row").assertDoesNotExist()
    composeTestRule.onNodeWithText("Community Channel").assertDoesNotExist()
    composeTestRule.onNodeWithText("Maybe Later").assertDoesNotExist()
    composeTestRule.onNodeWithText("Don't show again").assertDoesNotExist()
  }

  @Test
  fun testJoinActionTriggersCallback() {
    var joined = false
    composeTestRule.setContent {
      Dex2cTheme {
        TelegramPromoDialog(
          onJoin = { joined = true },
        )
      }
    }

    composeTestRule.onNodeWithTag("telegram_promo_join_btn").performClick()
    assertTrue("Join callback should be invoked", joined)
  }

  @Test
  fun testAppPreferencesTelegramPromoDismissedPersistence() = runBlocking {
    val context: Context = ApplicationProvider.getApplicationContext()
    val prefs = AppPreferences(context)

    // Initial state: not dismissed
    val initialSettings = prefs.settingsFlow.first()
    assertFalse(initialSettings.telegramPromoDismissed)

    // Update settings: mark promo as dismissed
    prefs.updateSettings { it.copy(telegramPromoDismissed = true) }
    val updatedSettings = prefs.settingsFlow.first()
    assertTrue(updatedSettings.telegramPromoDismissed)
  }
}
