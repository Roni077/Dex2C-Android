package com.dex2c.studio.ui.components

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.AutoAwesome
import androidx.compose.material.icons.rounded.Build
import androidx.compose.material.icons.rounded.Info
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import com.dex2c.studio.R

val TelegramBrandColor = Color(0xFF24A1DE)

@Composable
fun TelegramPromoDialog(
  onJoin: () -> Unit,
  modifier: Modifier = Modifier,
) {
  Dialog(
    onDismissRequest = {},
    properties =
      DialogProperties(
        dismissOnBackPress = false,
        dismissOnClickOutside = false,
        usePlatformDefaultWidth = false,
      ),
  ) {
    Surface(
      modifier =
        modifier
          .fillMaxWidth()
          .padding(horizontal = 20.dp, vertical = 24.dp)
          .widthIn(max = 440.dp)
          .testTag("telegram_promo_dialog"),
      shape = RoundedCornerShape(28.dp),
      color = MaterialTheme.colorScheme.surfaceContainerHigh,
      tonalElevation = 6.dp,
      border =
        BorderStroke(
          width = 1.dp,
          color = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.55f),
        ),
    ) {
      Column(
        modifier = Modifier.padding(horizontal = 24.dp, vertical = 28.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
      ) {
        // Telegram Branding Squircle Icon
        Surface(
          modifier = Modifier.size(68.dp),
          shape = RoundedCornerShape(24.dp),
          color = TelegramBrandColor,
          shadowElevation = 8.dp,
        ) {
          Box(contentAlignment = Alignment.Center) {
            Icon(
              painter = painterResource(R.drawable.ic_telegram),
              contentDescription = "Telegram Logo",
              tint = Color.White,
              modifier = Modifier.size(36.dp),
            )
          }
        }

        Spacer(modifier = Modifier.height(18.dp))

        // Title & Description
        Text(
          text = stringResource(R.string.telegram_promo_title),
          style = MaterialTheme.typography.titleLarge,
          fontWeight = FontWeight.Bold,
          color = MaterialTheme.colorScheme.onSurface,
          textAlign = TextAlign.Center,
        )

        Spacer(modifier = Modifier.height(8.dp))

        Text(
          text = stringResource(R.string.telegram_promo_subtitle),
          style = MaterialTheme.typography.bodyMedium,
          color = MaterialTheme.colorScheme.onSurfaceVariant,
          textAlign = TextAlign.Center,
          lineHeight = 20.sp,
        )

        Spacer(modifier = Modifier.height(20.dp))

        // Value Proposition Highlight Rows
        Surface(
          modifier = Modifier.fillMaxWidth(),
          shape = RoundedCornerShape(18.dp),
          color = MaterialTheme.colorScheme.surfaceContainerLow,
          border =
            BorderStroke(
              width = 1.dp,
              color = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.4f),
            ),
        ) {
          Column(
            modifier = Modifier.padding(horizontal = 14.dp, vertical = 14.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
          ) {
            PromoBenefitRow(
              icon = Icons.Rounded.AutoAwesome,
              text = stringResource(R.string.telegram_promo_benefit_releases),
            )
            PromoBenefitRow(
              icon = Icons.Rounded.Build,
              text = stringResource(R.string.telegram_promo_benefit_ci),
            )
            PromoBenefitRow(
              icon = Icons.Rounded.Info,
              text = stringResource(R.string.telegram_promo_benefit_community),
            )
          }
        }

        Spacer(modifier = Modifier.height(24.dp))

        // Single Full-Width Action Button: Join Channel
        Button(
          onClick = onJoin,
          modifier =
            Modifier
              .fillMaxWidth()
              .height(50.dp)
              .testTag("telegram_promo_join_btn"),
          shape = RoundedCornerShape(16.dp),
          colors =
            ButtonDefaults.buttonColors(
              containerColor = TelegramBrandColor,
              contentColor = Color.White,
            ),
        ) {
          Icon(
            painter = painterResource(R.drawable.ic_telegram),
            contentDescription = null,
            modifier = Modifier.size(20.dp),
          )
          Spacer(modifier = Modifier.width(10.dp))
          Text(
            text = stringResource(R.string.telegram_promo_action_join),
            style = MaterialTheme.typography.titleMedium,
            fontWeight = FontWeight.Bold,
          )
        }
      }
    }
  }
}

@Composable
private fun PromoBenefitRow(
  icon: ImageVector,
  text: String,
) {
  Row(
    verticalAlignment = Alignment.CenterVertically,
    horizontalArrangement = Arrangement.spacedBy(10.dp),
    modifier = Modifier.fillMaxWidth(),
  ) {
    Surface(
      shape = CircleShape,
      color = TelegramBrandColor.copy(alpha = 0.12f),
      modifier = Modifier.size(24.dp),
    ) {
      Box(contentAlignment = Alignment.Center) {
        Icon(
          imageVector = icon,
          contentDescription = null,
          tint = TelegramBrandColor,
          modifier = Modifier.size(14.dp),
        )
      }
    }
    Text(
      text = text,
      style = MaterialTheme.typography.bodySmall,
      color = MaterialTheme.colorScheme.onSurface,
      modifier = Modifier.weight(1f),
      lineHeight = 16.sp,
    )
  }
}
