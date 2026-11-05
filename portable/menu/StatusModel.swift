import Foundation
import CoreFoundation

enum HealthTone: Equatable {
    case good, warning, bad, unknown
}

struct StatusPresentation: Equatable {
    let kind: String
    var mode: String? = nil
    var modeText: String {
        mode == "home" ? "家宽模式" : mode == "original" ? "原网络模式" : "未确认"
    }
    var availabilityText: String {
        switch kind {
        case "healthy": return "可用（家宽验证通过）"
        case "verifying": return "暂时禁用（正在验证家宽）"
        case "original": return "禁用（原网络模式）"
        case "fault": return "禁用（检查异常）"
        default: return "未确认，请暂停使用"
        }
    }
    var title: String {
        mode == "home" ? "Home" : mode == "original" ? "Origin" : "—"
    }

    let headline: String
    let detail: String
    let guidance: String
    let tone: HealthTone
    let updatedAt: Date?
    let identity: String
    let routeText: String
    let historyLabel: String
}

/// Only the public, credential-free status document is decoded here.
struct StatusSnapshot: Decodable {
    let version: Int
    let mode: String
    let phase: String
    let policy: String
    let reason: String
    let successes: Int
    let eventID: Int
    let updatedAt: Double
    let requestID: String
    let coreRunning: Bool
    let route: String
    let notice: String?

    enum CodingKeys: String, CodingKey {
        case version, mode, phase, policy, reason, successes, route, notice
        case eventID = "event_id"
        case updatedAt = "updated_at"
        case requestID = "request_id"
        case coreRunning = "core_running"
    }

    var identity: String {
        "\(requestID)|\(eventID)|\(phase)|\(reason)"
    }

    static func parse(_ data: Data, now: Date = Date()) -> StatusPresentation {
        StatusInterpreter.parse(data, now: now)
    }

    static func unavailable(_ message: String) -> StatusPresentation {
        StatusInterpreter.unavailable(message)
    }
}

enum StatusInterpreter {
    static let staleSeconds: Double = 120
    static let futureTolerance: Double = 5

    static func unavailable(_ message: String) -> StatusPresentation {
        StatusPresentation(
            kind: "unknown", headline: "Claude 请暂停使用",
            detail: message, guidance: "等状态重新确认；持续异常时重新启用家宽。",
            tone: .unknown, updatedAt: nil, identity: "unavailable|\(message)",
            routeText: "连接线路未确认", historyLabel: "状态未确认，Claude 请暂停使用"
        )
    }

    static func parse(_ data: Data, now: Date = Date()) -> StatusPresentation {
        guard !data.isEmpty, data.count <= 65_536,
              let object = try? JSONSerialization.jsonObject(with: data),
              let fields = object as? [String: Any],
              strictNumbers(fields)
        else {
            return unavailable("保护状态无法读取，或状态数据不完整。")
        }

        // Startup can fail before the supervisor has an intent or route. This
        // literal error document must never look healthy, but its one known
        // fact is still useful to the user.
        if startupFailureWithoutIntent(fields, now: now) {
            return unavailable("保护服务报告启动失败；状态数据尚不完整。")
        }
        guard let state = try? JSONDecoder().decode(StatusSnapshot.self, from: data) else {
            return unavailable("保护状态无法读取，或状态数据不完整。")
        }

        guard state.version == 1, ["home", "original"].contains(state.mode),
              ["healthy", "blocked"].contains(state.phase),
              ["direct", "relay", "original"].contains(state.route),
              state.eventID >= 1, (0...2).contains(state.successes),
              !state.requestID.isEmpty, state.requestID.utf8.count <= 128,
              state.requestID.unicodeScalars.allSatisfy({
                  CharacterSet.alphanumerics.contains($0) || "-_".unicodeScalars.contains($0)
              }),
              !state.reason.isEmpty, state.reason.utf8.count <= 128,
              state.updatedAt.isFinite, now.timeIntervalSince1970.isFinite
        else {
            return unavailable("保护状态数据不一致，暂时不能确认连接。")
        }

        let age = now.timeIntervalSince1970 - state.updatedAt
        guard age <= staleSeconds, age >= -futureTolerance else {
            return unknown(
                state,
                detail: age > staleSeconds
                    ? "保护状态已超过 2 分钟未更新。"
                    : "保护状态的时间异常，暂时不能确认连接。",
                identitySuffix: age > staleSeconds ? "stale" : "future"
            )
        }

        if state.phase == "healthy" {
            guard state.mode == "home", state.policy == "home_open",
                  state.reason == "verified", state.successes == 2,
                  state.coreRunning, ["direct", "relay"].contains(state.route),
                  state.notice == nil || state.notice == "recovery" else {
                return unknown(state, detail: "保护状态数据不一致，不能确认 Claude 可用。")
            }
            return presentation(
                state, kind: "healthy", headline: "Claude 可以使用",
                detail: "已连续两轮核对到指定家宽出口，代理与保护检查通过。",
                guidance: "可以继续使用；检测到异常时会自动禁用并提醒。",
                tone: .good, historyLabel: "家宽验证通过，Claude 可用"
            )
        }

        guard state.policy == state.mode + "_blocked",
              state.notice == nil || state.notice == "fault",
              state.successes <= 1,
              state.mode != "home" || state.route != "original" else {
            return unknown(state, detail: "保护状态数据不一致，暂时不能确认连接。")
        }

        if state.mode == "original" {
            guard state.successes == 0 else {
                return unknown(state, detail: "原网络模式的状态数据不一致。")
            }
            if state.reason == "original_mode" {
                guard state.coreRunning else {
                    return unknown(state, detail: "原网络模式已记录，但保护服务尚未就绪。")
                }
                return presentation(
                    state, kind: "original", headline: "Claude 已禁用（原网络模式）",
                    detail: "当前使用原网络；手动恢复或家宽启用失败回退都会进入此模式。",
                    guidance: "需要 Claude 时，点击“启用家宽”并等验证通过。",
                    tone: .warning, historyLabel: "已恢复原网络，Claude 保持禁用"
                )
            }
            let serviceReasons = ["core_not_ready", "network_not_ready", "firewall_error",
                                  "startup_error", "monitor_error", "core_restart", "supervisor_stopped"]
            guard serviceReasons.contains(state.reason) else {
                return unknown(state, detail: "原网络模式的保护状态暂时无法确认。")
            }
            return serviceFault(state)
        }

        if state.reason == "starting" || state.reason == "verifying" {
            let expectedSuccesses = state.reason == "verifying" ? 1 : 0
            guard state.successes == expectedSuccesses else {
                return unknown(state, detail: "家宽验证进度与保护状态不一致。")
            }
            return presentation(
                state, kind: "verifying", headline: "Claude 暂时禁用，正在验证家宽",
                detail: state.reason == "verifying" ? "已通过第 1 轮，正在等待第 2 轮验证。" : "正在准备家宽连接，尚未完成出口验证。",
                guidance: "先等待；顶部 Home 图标变绿后再使用。",
                tone: .warning, historyLabel: "正在验证家宽，Claude 暂时禁用"
            )
        }

        guard state.successes == 0 else {
            return unknown(state, detail: "保护状态的验证次数不一致。")
        }
        if state.reason == "wrong_exit" {
            return presentation(
                state, kind: "fault", headline: "Claude 已禁用：家宽出口不符",
                detail: "出口校验返回的地址与指定家宽出口不一致。",
                guidance: "先暂停使用 Claude，等待家宽重新验证通过。",
                tone: .bad, historyLabel: "家宽出口不符，Claude 已禁用"
            )
        }
        if state.reason == "unreachable" {
            return presentation(
                state, kind: "fault", headline: "Claude 已禁用：家宽出口校验失败",
                detail: "本轮未能验证家宽出口，暂时不能确定具体原因。",
                guidance: "正在自动重试；等顶部 Home 图标变绿后再使用。",
                tone: .bad, historyLabel: "家宽出口校验失败，Claude 已禁用"
            )
        }
        return serviceFault(state)
    }

    /// Reject booleans masquerading as numbers and non-integer counter values
    /// before Decodable is allowed to perform numeric conversions.
    private static func strictNumbers(_ fields: [String: Any]) -> Bool {
        for key in ["version", "successes", "event_id"] {
            guard let value = fields[key] as? NSNumber,
                  CFGetTypeID(value) != CFBooleanGetTypeID(),
                  !CFNumberIsFloatType(unsafeBitCast(value, to: CFNumber.self)) else {
                return false
            }
        }
        guard let updated = fields["updated_at"] as? NSNumber,
              CFGetTypeID(updated) != CFBooleanGetTypeID() else {
            return false
        }
        return true
    }

    private static func startupFailureWithoutIntent(_ fields: [String: Any], now: Date) -> Bool {
        guard fields["request_id"] == nil, fields["route"] == nil,
              (fields["version"] as? NSNumber)?.intValue == 1,
              fields["mode"] as? String == "home",
              fields["phase"] as? String == "blocked",
              fields["policy"] as? String == "home_blocked",
              fields["reason"] as? String == "startup_error",
              (fields["successes"] as? NSNumber)?.intValue == 0,
              (fields["event_id"] as? NSNumber)?.intValue == 1,
              fields["notice"] as? String == "fault",
              let running = fields["core_running"] as? NSNumber,
              CFGetTypeID(running) == CFBooleanGetTypeID(), !running.boolValue,
              let timestamp = (fields["updated_at"] as? NSNumber)?.doubleValue,
              timestamp.isFinite, now.timeIntervalSince1970.isFinite else {
            return false
        }
        let age = now.timeIntervalSince1970 - timestamp
        return age >= -futureTolerance && age <= staleSeconds
    }

    private static func routeText(_ state: StatusSnapshot) -> String {
        if state.mode == "original" { return "原网络（Claude禁用）" }
        switch state.route {
        case "direct": return "家宽直连"
        case "relay": return "经备用线路连接家宽"
        default: return "连接线路未确认"
        }
    }

    private static func presentation(
        _ state: StatusSnapshot, kind: String, headline: String,
        detail: String, guidance: String, tone: HealthTone, historyLabel: String
    ) -> StatusPresentation {
        StatusPresentation(
            kind: kind, mode: state.mode, headline: headline, detail: detail, guidance: guidance,
            tone: tone, updatedAt: Date(timeIntervalSince1970: state.updatedAt),
            identity: state.identity, routeText: routeText(state), historyLabel: historyLabel
        )
    }

    private static func unknown(
        _ state: StatusSnapshot, detail: String, identitySuffix: String = "invalid"
    ) -> StatusPresentation {
        StatusPresentation(
            kind: "unknown", headline: "Claude 请暂停使用",
            detail: detail, guidance: "等状态重新确认；持续异常时重新启用家宽。",
            tone: .unknown, updatedAt: Date(timeIntervalSince1970: state.updatedAt),
            identity: "\(state.identity)|\(identitySuffix)", routeText: "连接线路未确认",
            historyLabel: "状态未确认，Claude 请暂停使用"
        )
    }

    private static func serviceFault(_ state: StatusSnapshot) -> StatusPresentation {
        let detail: String
        switch state.reason {
        case "core_not_ready":
            detail = "代理核心尚未就绪，暂时无法确认连接可用。"
        case "network_not_ready":
            detail = "代理监听或受保护网络路由未就绪，后台正在重建连接。"
        case "firewall_error":
            detail = "防火墙保护检查未通过，后台正在尝试修复。"
        case "startup_error":
            detail = "保护服务启动失败，暂时无法建立受保护连接。"
        case "monitor_error":
            detail = "保护后台检查出错，暂时无法确认家宽连接。"
        case "core_restart":
            detail = "代理核心刚刚重启，连接需要重新确认。"
        case "supervisor_stopped":
            detail = "家宽保护后台已停止，暂时无法确认连接。"
        default:
            return unknown(state, detail: "保护后台返回了暂时无法识别的状态。")
        }
        let original = state.mode == "original"
        return presentation(
            state, kind: "fault", headline: "Claude 请暂停使用：保护服务异常",
            detail: detail,
            guidance: original
                ? "原网络模式仍要求禁用 Claude；持续异常时重新启用家宽。"
                : "等待后台恢复；持续异常时重新启用家宽。",
            tone: .bad, historyLabel: "保护服务异常，Claude 请暂停使用"
        )
    }
}
