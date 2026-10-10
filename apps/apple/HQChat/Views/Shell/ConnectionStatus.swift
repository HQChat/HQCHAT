import SwiftUI

/// The header every tab root wears: its name, the connection chip, and the
/// server-info button with its sheet.
struct HQScreenHeader: View {
    let path: String
    @ObservedObject var appState: AppState
    var profileManager: ProfileManager?

    @State private var showingServerInfo = false

    var body: some View {
        HQPromptHeader(path: path) {
            HStack(spacing: 10) {
                ConnectionStatusChip(appState: appState)
                ServerInfoButton(appState: appState) { showingServerInfo = true }
            }
        }
        .sheet(isPresented: $showingServerInfo) {
            ServerInfoView(
                appState: appState,
                serverURL: ServerConfig.apiBaseURL
            )
        }
    }
}

/// The connection state as a terminal readout: a lit dot and a short uppercase
/// code, for the right-hand side of `HQPromptHeader`. Tapping retries when a
/// retry can help.
struct ConnectionStatusChip: View {
    @ObservedObject var appState: AppState

    var body: some View {
        let status = appState.connectionStatus
        Button {
            if status.canReconnect { Task { await appState.connectToServer(force: true) } }
        } label: {
            HStack(spacing: 5) {
                Circle()
                    .fill(status.indicatorColor)
                    .frame(width: 6, height: 6)
                    .shadow(color: status.indicatorColor.opacity(0.9), radius: 4)
                Text(status.terminalCode)
                    .font(HQFont.mono(10.5, weight: .bold))
                    .tracking(1)
                    .lineLimit(1)
                    .fixedSize()
                    .foregroundColor(status.indicatorColor)
            }
            .padding(.horizontal, 8)
            .padding(.vertical, 4)
            .overlay(Rectangle().stroke(status.indicatorColor.opacity(0.35), lineWidth: 1))
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .disabled(!status.canReconnect)
        .help(status.label)
        .hqGlitch(on: status)
    }
}

extension AppState.ConnectionStatus {
    /// Short machine code for the prompt header.
    var terminalCode: String {
        switch self {
        case .authenticated:   return "SECURE"
        case .connecting:      return "LINK.."
        case .connected:       return "AUTH.."
        case .disconnected:    return "DOWN"
        case .offline:         return "NO NET"
        case .error:           return "ERROR"
        }
    }

    /// Shared status colour for the toolbar dot and the info sheet.
    var indicatorColor: Color {
        switch self {
        case .authenticated:          return HQColor.green
        case .connecting, .connected: return HQColor.warning
        case .disconnected:           return HQColor.textMuted
        case .offline:                return HQColor.textSecond
        case .error:                  return HQColor.danger
        }
    }

    /// Human-readable connection state for the info sheet.
    var label: String {
        switch self {
        case .authenticated:   return "Connected · end-to-end encrypted"
        case .connecting:      return "Connecting…"
        case .connected:       return "Authenticating…"
        case .disconnected:    return "Disconnected"
        case .offline:         return "No network"
        case .error:           return "Connection error"
        }
    }

    /// Whether a manual reconnect makes sense from this state.
    var canReconnect: Bool {
        switch self {
        case .disconnected, .error: return true
        default:                    return false
        }
    }
}

/// A server glyph, green when connected and grey otherwise; opens `ServerInfoView`.
struct ServerInfoButton: View {
    @ObservedObject var appState: AppState
    let action: () -> Void

    private var isConnected: Bool {
        if case .authenticated = appState.connectionStatus { return true }
        return false
    }

    var body: some View {
        Button(action: action) {
            Image(systemName: "server.rack")
                .font(.system(size: 16, weight: .semibold))
                .foregroundColor(isConnected ? HQColor.green : HQColor.textMuted)
        }
        .buttonStyle(.plain)
        .help("Server info")
        .animation(.easeInOut(duration: 0.2), value: isConnected)
    }
}

/// Read-only summary of the server this profile is attached to: host, address,
/// live connection status, and the transport/encryption guarantee. Offers a
/// manual reconnect when the socket is down.
struct ServerInfoView: View {
    @ObservedObject var appState: AppState
    let serverURL: URL
    @Environment(\.dismiss) private var dismiss

    private var host: String { serverURL.host ?? serverURL.absoluteString }
    /// wss/https → secure transport.
    private var isSecure: Bool { (serverURL.scheme ?? "").hasSuffix("s") }

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    infoRow("Host", host)
                    infoRow("Address", serverURL.absoluteString)
                    HStack {
                        Text("Status").foregroundColor(HQColor.textSecond)
                        Spacer()
                        HStack(spacing: 6) {
                            Circle()
                                .fill(appState.connectionStatus.indicatorColor)
                                .frame(width: 8, height: 8)
                            Text(appState.connectionStatus.label)
                                .foregroundColor(HQColor.textPrimary)
                        }
                    }
                } header: {
                    Text("Server")
                } footer: {
                    Text(isSecure
                         ? "Transport is TLS-encrypted; messages are end-to-end encrypted with post-quantum HQC keys."
                         : "⚠︎ This server uses an unencrypted transport.")
                }

                if appState.connectionStatus.canReconnect {
                    Section {
                        Button {
                            Task { await appState.connectToServer(force: true) }
                            dismiss()
                        } label: {
                            Label("Reconnect", systemImage: "arrow.clockwise")
                        }
                    }
                }
            }
            .formStyle(.grouped)
            .navigationTitle("Server Info")
            .inlineNavTitle()
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button("Done") { dismiss() }
                }
            }
        }
        .sheetSizing()
    }

    @ViewBuilder
    private func infoRow(_ label: String, _ value: String) -> some View {
        HStack {
            Text(label).foregroundColor(HQColor.textSecond)
            Spacer()
            Text(value)
                .font(HQFont.mono(13))
                .foregroundColor(HQColor.textPrimary)
                .lineLimit(1)
                .truncationMode(.middle)
        }
    }
}

/// The macOS toolbar's connection indicator: a spinner while connecting, a
/// glyph otherwise, tappable when a retry can help.
struct ConnectionStatusButton: View {
    @ObservedObject var appState: AppState

    private var symbol: (name: String, spinning: Bool) {
        switch appState.connectionStatus {
        case .authenticated: return ("lock.fill", false)
        case .connecting, .connected: return ("", true)
        case .disconnected: return ("wifi.slash", false)
        case .offline: return ("airplane", false)
        case .error: return ("exclamationmark.triangle.fill", false)
        }
    }

    var body: some View {
        let status = appState.connectionStatus
        Button {
            if status.canReconnect { Task { await appState.connectToServer(force: true) } }
        } label: {
            ZStack {
                if symbol.spinning {
                    ProgressView().controlSize(.small)
                } else {
                    Image(systemName: symbol.name)
                        .font(.system(size: 15, weight: .semibold))
                        .foregroundColor(status.indicatorColor)
                }
            }
            .frame(width: 30, height: 30)
            .background(status.indicatorColor.opacity(0.12))
            .clipShape(Circle())
            .overlay(Circle().stroke(status.indicatorColor.opacity(0.4), lineWidth: 1))
        }
        .buttonStyle(.plain)
        .disabled(!status.canReconnect)
        .help(status.canReconnect ? "\(status.label) — click to reconnect" : status.label)
    }
}
