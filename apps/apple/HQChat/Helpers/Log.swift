import os

/// The app's unified-log channels, subsystem `app.hqchat`. Interpolated values
/// are private unless marked otherwise, so Release logs carry no user data.
///
///     log stream --predicate 'subsystem == "app.hqchat"' --level debug
enum Log {
    static let app = Logger(subsystem: "app.hqchat", category: "app")
    static let keys = Logger(subsystem: "app.hqchat", category: "keys")
    static let storage = Logger(subsystem: "app.hqchat", category: "storage")
    static let network = Logger(subsystem: "app.hqchat", category: "network")
    static let push = Logger(subsystem: "app.hqchat", category: "push")
}
