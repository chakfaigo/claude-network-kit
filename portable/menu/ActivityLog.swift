import Foundation
import Darwin
import CryptoKit

/// Bounded, credential-free observations and explicit menu actions. No probes.
final class ActivityLog {
    let directory: URL
    let maximumBytes: Int64
    private(set) var available = true

    init(directory: URL, maximumBytes: Int64 = 1_048_576) {
        self.directory = directory
        self.maximumBytes = maximumBytes
    }

    @discardableResult
    func append(category: String, message: String, status: StatusPresentation) -> Bool {
        let timestamp = ISO8601DateFormatter()
        timestamp.timeZone = .autoupdatingCurrent
        var record: [String: Any] = [
            "time": timestamp.string(from: Date()), "category": category,
            "message": message, "kind": status.kind, "identity": status.identity,
            "mode": status.modeText, "claude": status.availabilityText, "headline": status.headline, "detail": status.detail, "route": status.routeText
        ]
        if let date = status.updatedAt, date.timeIntervalSince1970.isFinite,
           (0...4_102_444_800).contains(date.timeIntervalSince1970) {
            record["backend_updated_at"] = timestamp.string(from: date)
        }
        do {
            var line = try JSONSerialization.data(withJSONObject: record, options: [.sortedKeys])
            guard line.count < 16_384 else { available = false; return false }
            line.append(10)
            let path = directory.appendingPathComponent("events.jsonl").path
            var fd = Darwin.open(path, O_WRONLY | O_APPEND | O_CREAT | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC, 0o600)
            guard fd >= 0 else { available = false; return false }
            defer { if fd >= 0 { Darwin.close(fd) } }
            var info = stat()
            guard fstat(fd, &info) == 0, info.st_mode & S_IFMT == S_IFREG,
                  info.st_uid == getuid() else { available = false; return false }
            if info.st_size + Int64(line.count) > maximumBytes {
                Darwin.close(fd); fd = -1
                let previous = directory.appendingPathComponent("events.previous.jsonl").path
                guard Darwin.rename(path, previous) == 0 else { available = false; return false }
                fd = Darwin.open(path, O_WRONLY | O_APPEND | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
                guard fd >= 0 else { available = false; return false }
            }
            guard fchmod(fd, 0o600) == 0 else { available = false; return false }
            var offset = 0
            while offset < line.count {
                let written = line.withUnsafeBytes { raw in
                    Darwin.write(fd, raw.baseAddress!.advanced(by: offset), raw.count - offset)
                }
                if written < 0 && errno == EINTR { continue }
                guard written > 0 else { available = false; return false }
                offset += written
            }
            available = true
            return true
        } catch { available = false; return false }
    }
}

enum MenuCommand: String, CaseIterable {
    case enable, restore
    static let packageDirectory = URL(fileURLWithPath:
        "/Library/Application Support/ClaudeResidential", isDirectory: true)
    var title: String { self == .enable ? "切换到 Home…" : "切换到 Origin（通道锁定）…" }
    var shortTitle: String { self == .enable ? "Home" : "Origin" }
    var file: URL { Self.packageDirectory.appendingPathComponent(self == .enable ? "Home.command" : "Origin.command") }
}


