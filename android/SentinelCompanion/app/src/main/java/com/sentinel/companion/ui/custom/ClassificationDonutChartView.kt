package com.sentinel.companion.ui.custom

import android.content.Context
import android.graphics.Canvas
import android.graphics.Paint
import android.graphics.RectF
import android.graphics.Typeface
import android.util.AttributeSet
import android.view.View
import androidx.core.content.ContextCompat
import com.sentinel.companion.R

/**
 * Custom Donut Chart for Message Classification statistics matching Sentinel AI reference design Screen 7.
 */
class ClassificationDonutChartView @JvmOverloads constructor(
    context: Context,
    attrs: AttributeSet? = null,
    defStyleAttr: Int = 0
) : View(context, attrs, defStyleAttr) {

    private var legitimateCount = 92
    private var spamCount = 18
    private var suspiciousCount = 10
    private var phishingCount = 3
    private var needsReviewCount = 5

    private val arcPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        style = Paint.Style.STROKE
    }

    private val textTotalPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        color = ContextCompat.getColor(context, R.color.text_primary)
        textAlign = Paint.Align.CENTER
        typeface = Typeface.create(Typeface.DEFAULT, Typeface.BOLD)
    }

    private val textLabelPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        color = ContextCompat.getColor(context, R.color.text_secondary)
        textAlign = Paint.Align.CENTER
        typeface = Typeface.DEFAULT
    }

    private val arcBounds = RectF()

    fun setData(legitimate: Int, spam: Int, suspicious: Int, phishing: Int, needsReview: Int) {
        this.legitimateCount = legitimate.coerceAtLeast(0)
        this.spamCount = spam.coerceAtLeast(0)
        this.suspiciousCount = suspicious.coerceAtLeast(0)
        this.phishingCount = phishing.coerceAtLeast(0)
        this.needsReviewCount = needsReview.coerceAtLeast(0)
        invalidate()
    }

    override fun onDraw(canvas: Canvas) {
        super.onDraw(canvas)

        val size = width.coerceAtMost(height).toFloat()
        if (size <= 0f) return

        val strokeWidth = size * 0.16f
        arcPaint.strokeWidth = strokeWidth

        val padding = strokeWidth / 2f + 4f
        val centerX = width / 2f
        val centerY = height / 2f
        val radius = (size / 2f) - padding

        arcBounds.set(
            centerX - radius,
            centerY - radius,
            centerX + radius,
            centerY + radius
        )

        val total = legitimateCount + spamCount + suspiciousCount + phishingCount + needsReviewCount

        if (total == 0) {
            // Draw placeholder ring
            arcPaint.color = ContextCompat.getColor(context, R.color.border_subtle)
            canvas.drawArc(arcBounds, 0f, 360f, false, arcPaint)
        } else {
            var startAngle = -90f

            val segments = listOf(
                Pair(legitimateCount, ContextCompat.getColor(context, R.color.status_green)),
                Pair(spamCount, ContextCompat.getColor(context, R.color.status_amber)),
                Pair(suspiciousCount, ContextCompat.getColor(context, R.color.warning_orange)),
                Pair(phishingCount, ContextCompat.getColor(context, R.color.status_red)),
                Pair(needsReviewCount, ContextCompat.getColor(context, R.color.status_gray))
            )

            for ((count, color) in segments) {
                if (count > 0) {
                    val sweepAngle = (count.toFloat() / total.toFloat()) * 360f
                    arcPaint.color = color
                    // Small gap between segments if multiple
                    canvas.drawArc(arcBounds, startAngle, sweepAngle, false, arcPaint)
                    startAngle += sweepAngle
                }
            }
        }

        // Center typography: Total number and "Total" subtitle
        textTotalPaint.textSize = size * 0.18f
        textLabelPaint.textSize = size * 0.09f

        val totalText = if (total > 0) total.toString() else "0"
        val totalY = centerY - (textTotalPaint.descent() + textTotalPaint.ascent()) / 2f - (size * 0.04f)
        canvas.drawText(totalText, centerX, totalY, textTotalPaint)

        val labelY = totalY + (size * 0.12f)
        canvas.drawText("Total", centerX, labelY, textLabelPaint)
    }
}
