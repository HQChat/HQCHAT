import SwiftUI

/// A message bubble's fill and stroke, in one place.
enum HQBubble {
    static func fill(outgoing: Bool) -> AnyShapeStyle {
        outgoing
        ? AnyShapeStyle(HQColor.green.opacity(0.10))
        : AnyShapeStyle(Color.white.opacity(0.035))
    }

    static func stroke(outgoing: Bool) -> Color {
        outgoing ? HQColor.green.opacity(0.22) : Color.white.opacity(0.08)
    }
}

struct MessageBubble: View {
    let message: ChatMessage
    /// Called when the user taps a failed message. Nil where retry doesn't
    /// apply (previews, read-only contexts).
    var onRetry: (() -> Void)?
    /// Reports this message; nil on outgoing messages and in previews.
    var onReport: (() -> Void)?
    
    /// The delivery glyph's VoiceOver label.
    private var deliveryDescription: String {
        switch message.deliveryStatus {
        case .sending:   return "sending"
        case .sent:      return "sent"
        case .delivered: return "delivered"
        case .queued:    return "queued — they are offline"
        case .failed:    return "not sent"
        }
    }

    /// Delivery state glyph shown after the timestamp on outgoing messages.
    @ViewBuilder
    private var deliveryIcon: some View {
        switch message.deliveryStatus {
        case .sending:
            Image(systemName: "clock").font(.caption2).foregroundColor(HQColor.textDim)
        case .sent:
            Image(systemName: "checkmark").font(.caption2).foregroundColor(HQColor.textSecond)
        case .delivered:
            Image(systemName: "checkmark.circle.fill").font(.caption2).foregroundColor(HQColor.green)
        case .queued:
            Image(systemName: "clock.badge.questionmark")
                .font(.caption2)
                .foregroundColor(HQColor.warning)
        case .failed:
            Image(systemName: "exclamationmark.circle.fill")
                .font(.caption2)
                .foregroundColor(HQColor.danger)
        }
    }
    
    /// The bubble, with its pressable area grown to at least 44pt and aligned
    /// to its own side, so short messages can be long-pressed.
    private var bubble: some View {
        Text(message.content)
            .font(HQFont.ui(14.5))
            .foregroundColor(message.isOutgoing ? HQColor.inkOnGreenBubble : HQColor.inkOnGreyBubble)
            .padding(.horizontal, 13)
            .padding(.vertical, 10)
            .background(HQBubble.fill(outgoing: message.isOutgoing))
            .clipShape(Rectangle())
            .overlay(
                Rectangle()
                    .stroke(HQBubble.stroke(outgoing: message.isOutgoing), lineWidth: 1)
            )
            .frame(minWidth: 44, minHeight: 44,
                   alignment: message.isOutgoing ? .trailing : .leading)
            .contentShape(Rectangle())
    }

    var body: some View {
        HStack {
            if message.isOutgoing {
                Spacer()
            }

            VStack(alignment: message.isOutgoing ? .trailing : .leading, spacing: 4) {
                // Only incoming bubbles get the menu; an empty `.contextMenu` still
                // captures the long press.
                if let onReport {
                    bubble.contextMenu {
                        Button(role: .destructive, action: onReport) {
                            Label("report", systemImage: "flag")
                        }
                    }
                } else {
                    bubble
                }

                HStack(spacing: 4) {
                    Text(message.timestamp, style: .time)
                        .font(HQFont.mono(10))
                        .foregroundColor(HQColor.textDim)
                    if message.isOutgoing {
                        deliveryIcon
                    }
                }
                .accessibilityElement(children: .combine)
                .accessibilityLabel(message.isOutgoing
                    ? "\(message.timestamp.formatted(date: .omitted, time: .shortened)), \(deliveryDescription)"
                    : message.timestamp.formatted(date: .omitted, time: .shortened))

                if message.isOutgoing, message.deliveryStatus == .failed, let onRetry {
                    Button(action: onRetry) {
                        HStack(spacing: 4) {
                            Image(systemName: "arrow.clockwise")
                            Text("not sent · tap to retry")
                        }
                        .font(HQFont.mono(10, weight: .medium))
                        .foregroundColor(HQColor.danger)
                    }
                    .buttonStyle(.plain)
                    .accessibilityLabel("retry sending this message")
                }
            }
            .frame(maxWidth: 300, alignment: message.isOutgoing ? .trailing : .leading)
            
            if !message.isOutgoing {
                Spacer()
            }
        }
    }
}
