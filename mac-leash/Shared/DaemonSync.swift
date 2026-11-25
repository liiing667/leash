import Foundation
import os.log

/// DaemonSync maintains a websocket connection to the Go leash daemon and
/// publishes macOS-specific state (tracked PIDs, rules, telemetry).
final class DaemonSync: NSObject {
    static let shared = DaemonSync()

    let log = OSLog(subsystem: LeashIdentifiers.bundle, category: "daemon-sync")
    let queue = DispatchQueue(label: LeashIdentifiers.namespaced("daemon-sync"), qos: .utility)
    lazy var session: URLSession = {
        let configuration = URLSessionConfiguration.default
        configuration.requestCachePolicy = .reloadIgnoringLocalCacheData
        return URLSession(configuration: configuration, delegate: nil, delegateQueue: nil)
    }()

    var task: URLSessionWebSocketTask?
    var isConnected = false
    var reconnectWorkItem: DispatchWorkItem?

    /// Stable identifier of this client process. It survives websocket
    /// reconnects so the daemon can recognise the same client across
    /// different connection-scoped ids.
    let clientID = UUID().uuidString
    /// Logical sync session shared with the daemon's message envelopes. It
    /// identifies this sync pipeline; the per-connection boundary is carried
    /// by `shimID` (rotated on every reconnect) and the connection-scoped id
    /// the daemon assigns to each websocket.
    let sessionID = UUID().uuidString
    var shimID = UUID().uuidString

    /// Monotonic per-connection rule transaction counter. It restarts at zero
    /// on every (re)connect so the first snapshot over a new connection is
    /// generation 1 and can never be confused with state the dead connection
    /// published. Combined with the connection-scoped daemon id this prevents
    /// old client rules from being applied to the new connection.
    var ruleGeneration: UInt64 = 0
    /// Highest generation acknowledged as committed by the daemon. Used to
    /// realign after a rejected (stale) transaction.
    var acknowledgedRuleGeneration: UInt64 = 0

    var capabilities: [String] = ["pid-sync", "rule-sync", "event", "policy", "network-rules"]
    var connectAttempts = 0

    var pendingRequests: [String: (Result<[String: Any], Error>) -> Void] = [:]

    typealias MessageHandler = ([String: Any]) -> Void
    var messageHandlers: [String: [MessageHandler]] = [:]
    var endpointURL: URL {
        if let override = ProcessInfo.processInfo.environment["LEASH_WS_URL"], let url = URL(string: override) {
            return url
        }
        return URL(string: "ws://127.0.0.1:18080/api")!
    }

    struct IncomingEnvelope: Decodable {
        let type: String
        let version: Int
        let sessionID: String?
        let shimID: String?
        let requestID: String?
        let payload: [String: AnyCodable]

        enum CodingKeys: String, CodingKey {
            case type
            case version
            case sessionID = "session_id"
            case shimID = "shim_id"
            case requestID = "request_id"
            case payload
        }
    }

    @preconcurrency struct AnyCodable: Codable {
        let value: Any

        init(_ value: Any) {
            self.value = value
        }

        init(from decoder: Decoder) throws {
            let container = try decoder.singleValueContainer()
            if let bool = try? container.decode(Bool.self) {
                value = bool
            } else if let int = try? container.decode(Int.self) {
                value = int
            } else if let double = try? container.decode(Double.self) {
                value = double
            } else if let string = try? container.decode(String.self) {
                value = string
            } else if let array = try? container.decode([AnyCodable].self) {
                value = array.map { $0.value }
            } else if let dict = try? container.decode([String: AnyCodable].self) {
                value = dict.mapValues { $0.value }
            } else {
                value = NSNull()
            }
        }

        func encode(to encoder: Encoder) throws {
            var container = encoder.singleValueContainer()
            switch value {
            case let bool as Bool:
                try container.encode(bool)
            case let int as Int:
                try container.encode(int)
            case let double as Double:
                try container.encode(double)
            case let string as String:
                try container.encode(string)
            case let array as [Any]:
                try container.encode(array.map { AnyCodable($0) })
            case let dict as [String: Any]:
                try container.encode(dict.mapValues { AnyCodable($0) })
            default:
                try container.encodeNil()
            }
        }
    }

    struct PIDEntry: Encodable, Sendable {
        let pid: Int32
        let leashPID: Int32
        let executable: String
        let ttyPath: String?
        let cwd: String?
        let description: String?

        enum CodingKeys: String, CodingKey {
            case pid
            case leashPID = "leash_pid"
            case executable
            case ttyPath = "tty_path"
            case cwd
            case description
        }
    }

    struct RuleSet: Encodable, Sendable {
        struct FileRule: Encodable, Sendable {
            let id: String
            let action: String
            let executable: String
            let directory: String?
            let file: String?
            let kind: String?
        }

        struct ExecRule: Encodable, Sendable {
            let id: String
            let action: String
            let executable: String
            let argsHash: String?

            enum CodingKeys: String, CodingKey {
                case id
                case action
                case executable
                case argsHash = "args_hash"
            }
        }

        struct NetworkRule: Encodable, Sendable {
            let id: String
            let name: String?
            let targetType: String
            let targetValue: String
            let action: String
            let cwd: String?
            let enabled: Bool

            enum CodingKeys: String, CodingKey {
                case id
                case name
                case targetType = "target_type"
                case targetValue = "target_value"
                case action
                case cwd
                case enabled
            }
        }

        let fileRules: [FileRule]
        let execRules: [ExecRule]
        let networkRules: [NetworkRule]
        let version: String
        /// Logical session this snapshot belongs to.
        let sessionID: String
        /// Monotonic generation within the current session.
        let generation: UInt64

        enum CodingKeys: String, CodingKey {
            case fileRules = "file_rules"
            case execRules = "exec_rules"
            case networkRules = "network_rules"
            case version
            case sessionID = "session_id"
            case generation
        }
    }

    override private init() {
        super.init()
    }
}
