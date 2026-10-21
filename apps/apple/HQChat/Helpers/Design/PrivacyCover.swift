// The window's cover while the app is not in front, or while the screen is
// recorded, mirrored or shared.
//
// iOS keeps a snapshot of the window for the app switcher, taken once the
// scene has resigned; whatever is on screen then (an open conversation, the
// list's previews) is saved to disk. Covering on `.inactive` means the
// snapshot is of the cover. A screen being captured sends every frame
// elsewhere, so conversations are hidden for as long as it lasts.

import SwiftUI
#if os(iOS)
import UIKit
#endif

private struct PrivacyCover: ViewModifier {
    @Environment(\.scenePhase) private var scenePhase
    @State private var captured = false

    private var covered: Bool { scenePhase != .active || captured }

    func body(content: Content) -> some View {
        content
            .accessibilityHidden(covered)
            .overlay {
                if covered { cover }
            }
            #if os(iOS)
            .background(CaptureProbe(captured: $captured))
            #endif
    }

    private var cover: some View {
        VStack(spacing: 14) {
            HQLogoMark(size: 44)
            if captured {
                Text("your screen is being recorded or shared")
                    .font(HQFont.ui(15, weight: .semibold))
                    .foregroundColor(HQColor.textPrimary)
                Text("conversations stay hidden until it stops.")
                    .font(HQFont.mono(11))
                    .foregroundColor(HQColor.textSecond)
            }
        }
        .multilineTextAlignment(.center)
        .padding()
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        // Opaque and still: the snapshot is taken of whatever this shows.
        .background(HQScreenBackground(animated: false))
        .accessibilityElement(children: .combine)
    }
}

extension View {
    /// Covers the window while the scene is not active or the screen is captured.
    func hqPrivacyCover() -> some View {
        modifier(PrivacyCover())
    }
}

#if os(iOS)
/// Reports whether the window's scene is being captured (recorded, mirrored,
/// AirPlayed), from the trait UIKit keeps for it.
private struct CaptureProbe: UIViewRepresentable {
    @Binding var captured: Bool

    func makeUIView(context: Context) -> ProbeView {
        let view = ProbeView()
        view.isUserInteractionEnabled = false
        view.onChange = { value in
            // Out of UIKit's trait pass, never during a SwiftUI update.
            DispatchQueue.main.async {
                if captured != value { captured = value }
            }
        }
        return view
    }

    func updateUIView(_ uiView: ProbeView, context: Context) {}

    final class ProbeView: UIView {
        var onChange: ((Bool) -> Void)?

        override init(frame: CGRect) {
            super.init(frame: frame)
            registerForTraitChanges([UITraitSceneCaptureState.self]) { (view: ProbeView, _) in
                view.report()
            }
        }

        required init?(coder: NSCoder) { nil }

        override func didMoveToWindow() {
            super.didMoveToWindow()
            report()
        }

        private func report() {
            let state = window?.windowScene?.traitCollection.sceneCaptureState ?? traitCollection.sceneCaptureState
            onChange?(state == .active)
        }
    }
}
#endif
