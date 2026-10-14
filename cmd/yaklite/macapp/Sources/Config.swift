import Foundation

// Settings written by `yaklite menubar install`:
//   ~/.config/yaklite/app.json   {"port": 9842, "bin": "/path/to/yaklite"}
//   ~/.config/yaklite/app-token  the secret the dashboard expects
// The app only reads them; it never creates them.
enum YakliteConfig {
    struct File: Decodable {
        var port: Int?
        var bin: String?
    }

    static var configDir: URL {
        if let x = ProcessInfo.processInfo.environment["XDG_CONFIG_HOME"], !x.isEmpty {
            return URL(fileURLWithPath: x).appendingPathComponent("yaklite")
        }
        return FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent(".config")
            .appendingPathComponent("yaklite")
    }

    static func load() -> File {
        let url = configDir.appendingPathComponent("app.json")
        guard let data = try? Data(contentsOf: url),
              let f = try? JSONDecoder().decode(File.self, from: data) else {
            return File(port: nil, bin: nil)
        }
        return f
    }

    static var port: Int {
        let p = load().port ?? 9842
        return (1...65535).contains(p) ? p : 9842
    }

    static var token: String? {
        let url = configDir.appendingPathComponent("app-token")
        guard let s = try? String(contentsOf: url, encoding: .utf8) else { return nil }
        let t = s.trimmingCharacters(in: .whitespacesAndNewlines)
        return t.isEmpty ? nil : t
    }

    /// The yaklite program: the one in app.json, else the usual places.
    static var binaryPath: String? {
        var candidates: [String] = []
        if let b = load().bin, !b.isEmpty { candidates.append(b) }
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        candidates += [
            home + "/Library/Application Support/yaklite/yaklite",
            home + "/.local/bin/yaklite",
            "/opt/homebrew/bin/yaklite",
            "/usr/local/bin/yaklite",
        ]
        return candidates.first { FileManager.default.isExecutableFile(atPath: $0) }
    }

    static var dashboardURL: URL {
        URL(string: "http://127.0.0.1:\(port)/")!
    }
}
