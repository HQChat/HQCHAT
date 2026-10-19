// swift-tools-version: 6.0
// The Apple shell around the Rust core: carries out the Engine's effects
// (HTTP, the broker connection, one timer, the unlock prompt) and reports the
// rest to the app. Its I/O sits behind protocols, so `swift test` drives the
// real engine with fakes; the app passes URLSession and Network.framework
// implementations configured with its TLS pinning.
import PackageDescription

let package = Package(
    name: "CoreShell",
    platforms: [.iOS("18.5"), .macOS("15.5")],
    products: [.library(name: "CoreShell", targets: ["CoreShell"])],
    dependencies: [.package(path: "../../../core/swift/HQChatCore")],
    targets: [
        .target(
            name: "CoreShell",
            dependencies: [.product(name: "HQChatCore", package: "HQChatCore")],
            // The generated bindings' types carry no Sendable annotations.
            swiftSettings: [.swiftLanguageMode(.v5)]
        ),
        .testTarget(
            name: "CoreShellTests",
            dependencies: ["CoreShell", .product(name: "HQChatCore", package: "HQChatCore")],
            swiftSettings: [.swiftLanguageMode(.v5)]
        ),
    ]
)
