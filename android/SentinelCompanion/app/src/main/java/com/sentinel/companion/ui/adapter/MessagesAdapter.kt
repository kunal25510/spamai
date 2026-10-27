package com.sentinel.companion.ui.adapter

import android.view.LayoutInflater
import android.view.ViewGroup
import androidx.core.content.ContextCompat
import androidx.recyclerview.widget.DiffUtil
import androidx.recyclerview.widget.ListAdapter
import androidx.recyclerview.widget.RecyclerView
import com.sentinel.companion.R
import com.sentinel.companion.data.model.UiSmsMessage
import com.sentinel.companion.databinding.ItemMessageCardBinding
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

class MessagesAdapter(
    private val onItemClick: (UiSmsMessage) -> Unit
) : ListAdapter<UiSmsMessage, MessagesAdapter.MessageViewHolder>(DiffCallback) {

    private val timeFormatter = SimpleDateFormat("hh:mm a", Locale.getDefault())

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): MessageViewHolder {
        val binding = ItemMessageCardBinding.inflate(
            LayoutInflater.from(parent.context),
            parent,
            false
        )
        return MessageViewHolder(binding)
    }

    override fun onBindViewHolder(holder: MessageViewHolder, position: Int) {
        holder.bind(getItem(position))
    }

    inner class MessageViewHolder(
        private val binding: ItemMessageCardBinding
    ) : RecyclerView.ViewHolder(binding.root) {

        fun bind(item: UiSmsMessage) {
            val context = binding.root.context

            binding.tvMessageSender.text = item.sender.ifBlank { "Unknown" }
            binding.tvMessageBody.text = item.body.trim().replace("\n", " ")
            binding.tvMessageTime.text = if (item.timestamp > 0) {
                timeFormatter.format(Date(item.timestamp))
            } else {
                "Recent"
            }

            // Determine badge appearance and category avatar based on classification
            val normCategory = item.category.uppercase(Locale.US)
            when {
                normCategory == "PHISHING" || item.riskScore >= 70 -> {
                    binding.ivCategoryAvatar.setImageResource(R.drawable.ic_category_phishing)
                    binding.tvMessageBadge.setBackgroundResource(R.drawable.bg_badge_red)
                    binding.tvMessageBadge.setTextColor(ContextCompat.getColor(context, R.color.status_red_text))
                    binding.tvMessageBadge.text = "Phishing"
                }
                normCategory == "SPAM" || normCategory == "SUSPICIOUS" -> {
                    binding.ivCategoryAvatar.setImageResource(R.drawable.ic_category_spam)
                    binding.tvMessageBadge.setBackgroundResource(R.drawable.bg_badge_amber)
                    binding.tvMessageBadge.setTextColor(ContextCompat.getColor(context, R.color.status_amber_text))
                    binding.tvMessageBadge.text = if (normCategory == "SUSPICIOUS") "Suspicious" else "Spam"
                }
                normCategory == "LEGITIMATE" || normCategory == "SAFE" -> {
                    binding.ivCategoryAvatar.setImageResource(R.drawable.ic_category_legit)
                    binding.tvMessageBadge.setBackgroundResource(R.drawable.bg_badge_green)
                    binding.tvMessageBadge.setTextColor(ContextCompat.getColor(context, R.color.status_green_text))
                    binding.tvMessageBadge.text = "Legitimate"
                }
                normCategory == "BLOCKED" -> {
                    binding.ivCategoryAvatar.setImageResource(R.drawable.ic_category_phishing)
                    binding.tvMessageBadge.setBackgroundResource(R.drawable.bg_badge_red)
                    binding.tvMessageBadge.setTextColor(ContextCompat.getColor(context, R.color.status_red_text))
                    binding.tvMessageBadge.text = "Blocked"
                }
                else -> {
                    // Default: Forwarded / Synced / Analyzed
                    binding.ivCategoryAvatar.setImageResource(R.drawable.ic_category_forwarded)
                    binding.tvMessageBadge.setBackgroundResource(R.drawable.bg_badge_blue)
                    binding.tvMessageBadge.setTextColor(ContextCompat.getColor(context, R.color.status_blue_text))
                    binding.tvMessageBadge.text = "Forwarded"
                }
            }

            binding.root.setOnClickListener {
                onItemClick(item)
            }
        }
    }

    companion object DiffCallback : DiffUtil.ItemCallback<UiSmsMessage>() {
        override fun areItemsTheSame(oldItem: UiSmsMessage, newItem: UiSmsMessage): Boolean =
            oldItem.id == newItem.id

        override fun areContentsTheSame(oldItem: UiSmsMessage, newItem: UiSmsMessage): Boolean =
            oldItem == newItem
    }
}
