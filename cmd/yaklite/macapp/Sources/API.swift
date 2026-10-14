import Foundation

struct Problem: Decodable, Hashable {
    let id: String
    let title: String
    let fix: String?
    let severity: String
    let ackKey: String
    let time: String?
}

struct Summary: Decodable {
    let status: String
    let openHigh: Int
    let openMedium: Int
    let score: Int
    let grade: String
    let lastCheck: String?
    let topProblems: [Problem]?
    let recentAlerts: [Problem]?
}

enum APIError: Error {
    case notSetUp
    case http(Int)
}

private struct AckBody: Encodable {
    let key: String
    let `for`: String
}

private struct EventBody: Encodable {
    let kind: String
    let app: String
    let on: Bool
}

/// Talks to the local yaklite dashboard on 127.0.0.1.
enum YakliteAPI {
    static func call(_ path: String, method: String = "GET", body: Data? = nil) async throws -> Data {
        guard let token = YakliteConfig.token else { throw APIError.notSetUp }
        guard let url = URL(string: "http://127.0.0.1:\(YakliteConfig.port)\(path)") else { throw APIError.http(0) }
        var req = URLRequest(url: url)
        req.httpMethod = method
        req.timeoutInterval = 15
        req.cachePolicy = .reloadIgnoringLocalCacheData
        req.setValue(token, forHTTPHeaderField: "X-Yaklite-App-Token")
        if let body = body {
            req.httpBody = body
            req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        }
        let (data, resp) = try await URLSession.shared.data(for: req)
        let code = (resp as? HTTPURLResponse)?.statusCode ?? 0
        guard (200..<300).contains(code) else { throw APIError.http(code) }
        return data
    }

    static func summary() async throws -> Summary {
        let data = try await call("/api/app/summary")
        let dec = JSONDecoder()
        dec.keyDecodingStrategy = .convertFromSnakeCase
        return try dec.decode(Summary.self, from: data)
    }

    /// forever: "Done" (I know about this); otherwise snooze for one day.
    static func ack(key: String, forever: Bool) async throws {
        let body = try JSONEncoder().encode(AckBody(key: key, for: forever ? "forever" : "1d"))
        _ = try await call("/api/app/ack", method: "POST", body: body)
    }

    static func checkNow() async throws {
        _ = try await call("/api/app/check", method: "POST", body: Data("{}".utf8))
    }

    static func event(kind: String, app: String, on: Bool) async throws {
        let body = try JSONEncoder().encode(EventBody(kind: kind, app: String(app.prefix(100)), on: on))
        _ = try await call("/api/app/event", method: "POST", body: body)
    }
}
