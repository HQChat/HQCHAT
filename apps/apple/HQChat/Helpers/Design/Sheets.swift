import SwiftUI

extension View {
    /// Inline navigation-bar title on iOS; no-op on macOS.
    @ViewBuilder func inlineNavTitle() -> some View {
        #if os(iOS)
        self.navigationBarTitleDisplayMode(.inline)
        #else
        self
        #endif
    }

    /// A minimum sheet size on macOS; iOS uses the system sheet.
    @ViewBuilder func sheetSizing(minWidth: CGFloat = 380, minHeight: CGFloat = 240) -> some View {
        #if os(macOS)
        self.frame(minWidth: minWidth, minHeight: minHeight)
        #else
        self
        #endif
    }
}
