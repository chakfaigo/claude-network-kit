import AppKit
import Foundation
import Darwin

private let statusPath = "/Library/Application Support/ClaudeResidential/public/status.json"
private let appID = "local.claude.residential.status"

// Apply to every visible description, including history saved by older versions.
private func displayCopy(_ text: String) -> String {
    text.replacingOccurrences(of: "启用家宽", with: "切换到 Home")
        .replacingOccurrences(of: "Claude", with: "通道")
        .replacingOccurrences(of: "家宽", with: "Home")
        .replacingOccurrences(of: "原网络", with: "Origin")
}


enum PublicStatusReader {
    static func read() -> StatusPresentation {
        let fd = Darwin.open(statusPath, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
        guard fd >= 0 else {
            return StatusInterpreter.unavailable("暂时读不到保护状态，后台可能尚未启动。")
        }
        defer { Darwin.close(fd) }
        var info = stat()
        guard fstat(fd, &info) == 0, info.st_mode & S_IFMT == S_IFREG,
              info.st_uid == 0, info.st_mode & 0o022 == 0,
              info.st_size > 0, info.st_size <= 65_536 else {
            return StatusInterpreter.unavailable("保护状态文件无法确认，暂时不要使用 Claude。")
        }
        var buffer = [UInt8](repeating: 0, count: 65_537)
        var count = 0
        while count < buffer.count {
            let received = buffer.withUnsafeMutableBytes { raw in
                Darwin.read(fd, raw.baseAddress!.advanced(by: count), raw.count - count)
            }
            if received == 0 { break }
            if received < 0 {
                if errno == EINTR { continue }
                return StatusInterpreter.unavailable("读取保护状态失败，请等待下一次更新。")
            }
            count += received
        }
        return StatusInterpreter.parse(Data(buffer.prefix(count)))
    }
}

struct HistoryEntry: Codable {
    let observedAt: Date
    let label: String
}

struct HistoryState: Codable {
    var version = 1
    var lastIdentity: String?
    var lastKind: String?
    var entries: [HistoryEntry] = []
}

final class LocalHistory {
    let directory = FileManager.default.homeDirectoryForCurrentUser
        .appendingPathComponent("Library/Application Support/ClaudeResidentialStatus", isDirectory: true)
    private var state = HistoryState()
    private var lockFD: Int32 = -1
    lazy var activity = ActivityLog(directory: directory)
    private(set) var available = true
    var entries: [HistoryEntry] { state.entries }

    func acquire() -> Bool {
        do {
            if FileManager.default.fileExists(atPath: directory.path) {
                let attrs = try FileManager.default.attributesOfItem(atPath: directory.path)
                guard attrs[.type] as? FileAttributeType == .typeDirectory,
                      (attrs[.ownerAccountID] as? NSNumber)?.uint32Value == getuid() else { return false }
            } else {
                try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true,
                    attributes: [.posixPermissions: 0o700])
            }
            try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: directory.path)
            lockFD = Darwin.open(directory.appendingPathComponent("app.lock").path,
                                 O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK, 0o600)
            var info = stat()
            guard lockFD >= 0, fstat(lockFD, &info) == 0,
                  info.st_mode & S_IFMT == S_IFREG, info.st_uid == getuid(),
                  flock(lockFD, LOCK_EX | LOCK_NB) == 0 else { return false }
            fchmod(lockFD, 0o600)
            let file = directory.appendingPathComponent("history.json")
            if let attrs = try? FileManager.default.attributesOfItem(atPath: file.path),
               attrs[.type] as? FileAttributeType == .typeRegular,
               (attrs[.ownerAccountID] as? NSNumber)?.uint32Value == getuid(),
               let size = attrs[.size] as? NSNumber, size.intValue <= 131_072,
               let data = try? Data(contentsOf: file),
               let saved = try? JSONDecoder().decode(HistoryState.self, from: data), saved.version == 1,
               saved.entries.count <= 20,
               saved.entries.allSatisfy({ $0.label.count <= 200 &&
                   (0...(Date().timeIntervalSince1970 + 300)).contains($0.observedAt.timeIntervalSince1970) }) {
                state = saved
            }
            return true
        } catch { return false }
    }

    func observe(_ presentation: StatusPresentation) {
        guard state.lastIdentity != presentation.identity else { return }
        var label = presentation.historyLabel
        if state.lastIdentity == nil {
            label = "启动时：" + label
        } else if presentation.kind == "healthy", state.lastKind == "healthy",
                  let old = state.lastIdentity?.split(separator: "|"), old.count >= 2 {
            let new = presentation.identity.split(separator: "|")
            if new.count >= 2, old[0] == new[0], let before = Int(old[1]),
               let after = Int(new[1]), before >= 1, after > before, after - before >= 2 {
                label = "期间曾异常，现已恢复（原因未捕获）"
            }
        }
        state.entries.insert(HistoryEntry(observedAt: Date(), label: label), at: 0)
        state.entries = Array(state.entries.prefix(20))
        state.lastIdentity = presentation.identity
        state.lastKind = presentation.kind
        activity.append(category: "state", message: label, status: presentation)
        do {
            let data = try JSONEncoder().encode(state)
            try data.write(to: directory.appendingPathComponent("history.json"), options: .atomic)
            try FileManager.default.setAttributes([.posixPermissions: 0o600],
                ofItemAtPath: directory.appendingPathComponent("history.json").path)
            available = true
        } catch { available = false }
    }

    deinit { if lockFD >= 0 { Darwin.close(lockFD) } }
}

final class AppDelegate: NSObject, NSApplicationDelegate, NSMenuDelegate {
    let history = LocalHistory()
    private var statusItem: NSStatusItem!
    private let menu = NSMenu()
    private var timer: Timer?
    private var current = StatusInterpreter.unavailable("正在读取家宽保护状态。")
    private let headline = NSTextField(wrappingLabelWithString: "")
    private let detail = NSTextField(wrappingLabelWithString: "")
    private let guidance = NSTextField(wrappingLabelWithString: "")
    private let routeItem = NSMenuItem()
    private let updatedItem = NSMenuItem()
    private let operationItem = NSMenuItem()
    private var commandItems: [NSMenuItem] = []
    private var commandCooldownUntil = Date.distantPast
    private let modeItem = NSMenuItem()
    private let availabilityItem = NSMenuItem()
    private let historyTitle = NSMenuItem()
    private var historyItems: [NSMenuItem] = []
    private let clockFormatter: DateFormatter = {
        let f = DateFormatter(); f.locale = Locale(identifier: "zh_CN"); f.timeZone = .autoupdatingCurrent
        f.dateFormat = "HH:mm:ss"; return f
    }()
    private let historyFormatter: DateFormatter = {
        let f = DateFormatter(); f.locale = Locale(identifier: "zh_CN"); f.timeZone = .autoupdatingCurrent
        f.dateFormat = "MM/dd HH:mm:ss"; return f
    }()

    func applicationDidFinishLaunching(_ notification: Notification) {
        guard history.acquire() else { NSApp.terminate(nil); return }
        NSApp.setActivationPolicy(.accessory)
        statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        statusItem.autosaveName = appID
        menu.autoenablesItems = false
        menu.delegate = self
        buildMenu()
        statusItem.menu = menu
        refresh()
        history.activity.append(category: "application", message: "状态栏已启动", status: current)
        let t = Timer(timeInterval: 1, repeats: true) { [weak self] _ in self?.refresh() }
        t.tolerance = 0.15
        RunLoop.main.add(t, forMode: .common)
        timer = t
        NSWorkspace.shared.notificationCenter.addObserver(self, selector: #selector(refresh),
            name: NSWorkspace.didWakeNotification, object: nil)
    }

    func buildMenu() {
        let top = NSView(frame: NSRect(x: 0, y: 0, width: 390, height: 166))
        headline.frame = NSRect(x: 18, y: 116, width: 354, height: 40)
        headline.font = .systemFont(ofSize: 15, weight: .semibold)
        detail.frame = NSRect(x: 18, y: 70, width: 354, height: 42)
        detail.font = .systemFont(ofSize: 12)
        detail.textColor = .secondaryLabelColor
        guidance.frame = NSRect(x: 18, y: 12, width: 354, height: 50)
        guidance.font = .systemFont(ofSize: 12)
        guidance.textColor = .labelColor
        for field in [headline, detail, guidance] {
            field.isSelectable = false
            field.maximumNumberOfLines = 3
            top.addSubview(field)
        }
        let summary = NSMenuItem(); summary.view = top; menu.addItem(summary)
        menu.addItem(.separator())
        for item in [modeItem, availabilityItem, routeItem, updatedItem] { item.isEnabled = false; menu.addItem(item) }
        let meaning = NSMenuItem(title: "绿色 = 就绪 · 橙色 = 等待 / 锁定 · 红色 = 异常", action: nil, keyEquivalent: "")
        meaning.isEnabled = false; menu.addItem(meaning)
        menu.addItem(.separator())
        commandItems = [addAction(MenuCommand.enable.title, #selector(enableHome)),
                        addAction(MenuCommand.restore.title, #selector(restoreNetwork))]
        operationItem.title = "点击操作后按窗口提示完成；不会自动切换"
        operationItem.isEnabled = false; menu.addItem(operationItem)
        menu.addItem(.separator())
        historyTitle.title = "最近变化（本机观察时间）"
        historyTitle.isEnabled = false
        menu.addItem(historyTitle)
        for _ in 0..<6 {
            let item = NSMenuItem(); item.isEnabled = false
            item.isHidden = true; menu.addItem(item); historyItems.append(item)
        }
        menu.addItem(.separator())
        addAction("复制当前状态", #selector(copyStatus))
        let logs = NSMenuItem(title: "查看日志", action: nil, keyEquivalent: "")
        let logMenu = NSMenu()
        logMenu.autoenablesItems = false
        for (name, selector) in [("状态变化与操作记录", #selector(openStatusLogs)),
                                 ("启用与恢复执行日志", #selector(openControllerLogs))] {
            let item = NSMenuItem(title: name, action: selector, keyEquivalent: "")
            item.target = self; logMenu.addItem(item)
        }
        logs.submenu = logMenu; menu.addItem(logs)
        let login = NSMenuItem(title: "已设为登录 Mac 后自动显示", action: nil, keyEquivalent: "")
        login.isEnabled = false; menu.addItem(login)
        addAction("使用说明", #selector(openHelp))
        menu.addItem(.separator())
        addAction("关闭状态栏（保护继续运行）", #selector(quit))
    }

    @discardableResult
    private func addAction(_ title: String, _ action: Selector) -> NSMenuItem {
        let item = NSMenuItem(title: title, action: action, keyEquivalent: "")
        item.target = self; menu.addItem(item)
        return item
    }

    @objc func refresh() {
        current = PublicStatusReader.read()
        history.observe(current)
        for item in commandItems { item.isEnabled = Date() >= commandCooldownUntil }
        modeItem.title = "模式：" + displayCopy(current.modeText)
        availabilityItem.title = "通道：" + displayCopy(current.availabilityText)
        let color: NSColor
        let symbol: String
        switch current.tone {
        case .good: color = .systemGreen; symbol = "circle.fill"
        case .warning: color = .systemOrange; symbol = current.kind == "original" ? "minus.circle.fill" : "clock.fill"
        case .bad: color = .systemRed; symbol = "exclamationmark.circle.fill"
        case .unknown: color = .secondaryLabelColor; symbol = "questionmark.circle.fill"
        }
        if let button = statusItem.button {
            button.title = " " + current.title
            button.font = .systemFont(ofSize: 12, weight: .medium)
            button.image = NSImage(systemSymbolName: symbol, accessibilityDescription: current.title)?
                .withSymbolConfiguration(.init(pointSize: 15, weight: .regular))?
                .withSymbolConfiguration(.init(paletteColors: [color]))
            button.image?.isTemplate = false
            button.imagePosition = .imageLeading
            button.toolTip = displayCopy(current.modeText + " · " + current.availabilityText + "\n" + current.detail)
            button.setAccessibilityLabel(displayCopy(current.modeText + " · " + current.headline))
        }
        headline.stringValue = displayCopy(current.headline)
        headline.textColor = current.tone == .good ? .labelColor : color
        detail.stringValue = displayCopy(current.detail)
        guidance.stringValue = displayCopy(current.guidance)
        routeItem.title = "线路：" + displayCopy(current.routeText)
        if let date = current.updatedAt {
            let elapsed = Date().timeIntervalSince(date)
            if elapsed.isFinite && (-5...31_536_000).contains(elapsed) {
                let age = max(0, Int(elapsed))
                updatedItem.title = "后台更新：\(clockFormatter.string(from: date))（\(age) 秒前）"
            } else { updatedItem.title = "后台更新：时间异常或已过期" }
        } else { updatedItem.title = "后台更新：暂时无法确认" }
        historyTitle.title = history.available && history.activity.available
            ? "最近变化（本机观察时间）" : "记录保存异常，请查看日志目录权限"
        for (index, item) in historyItems.enumerated() {
            if index < history.entries.count {
                let entry = history.entries[index]
                item.title = "\(historyFormatter.string(from: entry.observedAt))  \(displayCopy(entry.label))"
                item.isHidden = false
            } else { item.isHidden = true }
        }
    }

    func menuWillOpen(_ menu: NSMenu) { refresh() }

    @objc func enableHome() { openCommand(.enable) }
    @objc func restoreNetwork() { openCommand(.restore) }

    private func confirmOrigin() -> Bool {
        let alert = NSAlert()
        alert.messageText = "切换到 Origin"
        alert.informativeText = "普通流量恢复为这台电脑原来的网络，受保护通道继续锁定。"
        alert.addButton(withTitle: "继续")
        alert.addButton(withTitle: "取消")
        NSApp.activate(ignoringOtherApps: true)
        return alert.runModal() == .alertFirstButtonReturn
    }

    private func openCommand(_ command: MenuCommand) {
        guard Date() >= commandCooldownUntil else { return }
        refresh()
        history.activity.append(category: "action_requested", message: "用户点击：" + command.shortTitle, status: current)
        if command == .restore && !confirmOrigin() { return }
        commandCooldownUntil = Date().addingTimeInterval(5)
        operationItem.title = "正在打开" + command.shortTitle + "窗口…"
        for item in commandItems { item.isEnabled = false }
        let terminal = URL(fileURLWithPath: "/System/Applications/Utilities/Terminal.app")
        NSWorkspace.shared.open([command.file], withApplicationAt: terminal,
            configuration: NSWorkspace.OpenConfiguration()) { [weak self] _, error in
            DispatchQueue.main.async {
                guard let self = self else { return }
                if error != nil {
                    self.operationItem.title = "未能打开操作窗口，请使用原来的桌面按钮"
                    self.history.activity.append(category: "action_error", message: command.shortTitle + "：终端窗口未能打开", status: self.current)
                } else {
                    self.operationItem.title = "已打开操作窗口；按提示输入 Mac 密码并查看结果"
                    self.history.activity.append(category: "action_window_opened", message: command.shortTitle + "：已打开终端入口，尚不代表操作成功", status: self.current)
                }
            }
        }
    }

    @objc func openStatusLogs() { NSWorkspace.shared.open(history.directory) }
    @objc func openControllerLogs() {
        NSWorkspace.shared.open(FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Library/Application Support/HomeGuard/logs", isDirectory: true))
    }

    @objc func copyStatus() {
        refresh()
        var lines = ["家宽状态 · " + historyFormatter.string(from: Date()), current.headline,
                     modeItem.title, availabilityItem.title, current.detail, current.guidance, routeItem.title, updatedItem.title, "", "最近变化："]
        lines += history.entries.prefix(6).map { historyFormatter.string(from: $0.observedAt) + " " + $0.label }
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(displayCopy(lines.joined(separator: "\n")), forType: .string)
    }

    @objc func openHelp() {
        if let file = Bundle.main.url(forResource: "使用说明", withExtension: "html") {
            NSWorkspace.shared.open(file)
        }
    }

    @objc func quit() {
        history.activity.append(category: "application", message: "用户关闭状态栏；保护后台继续运行", status: current)
        NSApp.terminate(nil)
    }
}

@main
enum StatusApp {
static func main() {
if CommandLine.arguments.contains("--snapshot") {
    let p = PublicStatusReader.read()
    let object: [String: Any] = ["kind": p.kind, "title": p.title, "headline": displayCopy(p.headline),
        "mode": displayCopy(p.modeText), "channel": displayCopy(p.availabilityText),
        "detail": displayCopy(p.detail), "guidance": displayCopy(p.guidance),
        "route": displayCopy(p.routeText), "identity": p.identity]

    if let data = try? JSONSerialization.data(withJSONObject: object, options: [.prettyPrinted, .sortedKeys]),
       let text = String(data: data, encoding: .utf8) { print(text) }
} else {
    let app = NSApplication.shared
    let delegate = AppDelegate()
    app.delegate = delegate
    app.run()
    withExtendedLifetime(delegate) {}
}
}
}
