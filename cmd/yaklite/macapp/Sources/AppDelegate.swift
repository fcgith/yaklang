import AppKit
import UserNotifications

enum Prefs {
    static let deviceAlerts = "deviceAlerts"   // Bool, alert when camera or mic turns on
    static let allowedApps = "allowedApps"     // [String], apps that may use them quietly
    static let seenAlertIDs = "seenAlertIDs"   // [String], alerts already shown
}

final class AppDelegate: NSObject, NSApplicationDelegate {
    static var shared: AppDelegate?

    private enum Level { case ok, medium, high, unknown }

    private var statusItem: NSStatusItem?
    private var summary: Summary?
    private var problem: String?          // why there is no summary
    private var notSetUp = false
    private var checking = false
    private var pollTimer: Timer?
    private let notifier = Notifier()
    private let devices = DeviceWatcher()
    private var setupWindow: SetupWindowController?

    func applicationDidFinishLaunching(_ notification: Notification) {
        AppDelegate.shared = self
        UserDefaults.standard.register(defaults: [Prefs.deviceAlerts: true])
        statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        setIcon(.unknown)
        notifier.start()
        devices.onTurnedOn = { [weak self] kind, app in
            self?.deviceTurnedOn(kind: kind, app: app)
        }
        devices.start()
        rebuildMenu()
        refresh()
        pollTimer = Timer.scheduledTimer(timeInterval: 60, target: self, selector: #selector(timerFired),
                                         userInfo: nil, repeats: true)
    }

    // MARK: - status

    @objc private func timerFired() {
        refresh()
    }

    func refresh() {
        guard YakliteConfig.token != nil else {
            notSetUp = true
            summary = nil
            problem = nil
            setIcon(.unknown)
            rebuildMenu()
            return
        }
        notSetUp = false
        Task { @MainActor in
            do {
                let s = try await YakliteAPI.summary()
                self.summary = s
                self.problem = nil
                self.notifier.showNew(alerts: s.recentAlerts ?? [])
            } catch APIError.http(let code) where code == 403 {
                self.summary = nil
                self.problem = "yaklite did not accept this app. Open Setup and click Apply."
            } catch {
                self.summary = nil
                self.problem = "Can't reach yaklite. Is the dashboard on?"
            }
            self.updateIcon()
            self.rebuildMenu()
        }
    }

    private func updateIcon() {
        guard let s = summary else {
            setIcon(.unknown)
            return
        }
        if s.status == "alert" || s.openHigh > 0 {
            setIcon(.high)
        } else if s.status == "warn" || s.openMedium > 0 {
            setIcon(.medium)
        } else {
            setIcon(.ok)
        }
    }

    private func setIcon(_ level: Level) {
        guard let button = statusItem?.button else { return }
        let name: String
        let tip: String
        switch level {
        case .ok:
            name = "checkmark.shield"
            tip = "yaklite: all good"
        case .medium:
            name = "exclamationmark.shield"
            tip = "yaklite: some things need a look"
        case .high:
            name = "xmark.shield"
            tip = "yaklite: something needs attention now"
        case .unknown:
            name = "shield"
            tip = "yaklite"
        }
        var image = NSImage(systemSymbolName: name, accessibilityDescription: tip)
        if level == .high,
           let red = image?.withSymbolConfiguration(NSImage.SymbolConfiguration(paletteColors: [.systemRed])) {
            red.isTemplate = false
            image = red
        } else {
            image?.isTemplate = true
        }
        button.image = image
        button.toolTip = tip
    }

    // MARK: - menu

    private func rebuildMenu() {
        let menu = NSMenu()
        menu.autoenablesItems = false

        if notSetUp {
            menu.addItem(disabled("yaklite is not set up yet"))
            menu.addItem(item("Open setup", #selector(openSetup)))
        } else if let s = summary {
            menu.addItem(disabled(statusLine(s)))
            menu.addItem(disabled("Safety score: \(s.score)/100 (\(s.grade))"))
            if checking {
                menu.addItem(disabled("Checking now…"))
            } else if let last = s.lastCheck, !last.isEmpty {
                menu.addItem(disabled("Last check: \(last)"))
            }
            let top = Array((s.topProblems ?? []).prefix(5))
            if !top.isEmpty {
                menu.addItem(.separator())
                menu.addItem(disabled("Fix these first:"))
                for p in top {
                    menu.addItem(problemItem(p))
                }
            }
        } else {
            menu.addItem(disabled(problem ?? "Checking…"))
        }

        menu.addItem(.separator())
        let check = item("Check now", #selector(checkNow))
        check.isEnabled = !notSetUp && !checking
        menu.addItem(check)
        let dash = item("Open dashboard", #selector(openDashboard))
        dash.isEnabled = !notSetUp
        menu.addItem(dash)

        menu.addItem(.separator())
        let toggle = item("Alert when camera or mic turns on", #selector(toggleDeviceAlerts))
        toggle.state = UserDefaults.standard.bool(forKey: Prefs.deviceAlerts) ? .on : .off
        menu.addItem(toggle)
        menu.addItem(allowedAppsItem())

        menu.addItem(.separator())
        menu.addItem(item("Setup…", #selector(openSetup)))
        menu.addItem(item("Quit", #selector(quit), key: "q"))
        statusItem?.menu = menu
    }

    private func statusLine(_ s: Summary) -> String {
        if s.status == "alert" || s.openHigh > 0 { return "Something needs attention now" }
        if s.status == "warn" || s.openMedium > 0 { return "Some things need a look" }
        return "All good"
    }

    private func item(_ title: String, _ action: Selector, key: String = "") -> NSMenuItem {
        let i = NSMenuItem(title: title, action: action, keyEquivalent: key)
        i.target = self
        return i
    }

    private func disabled(_ title: String) -> NSMenuItem {
        let i = NSMenuItem(title: title, action: nil, keyEquivalent: "")
        i.isEnabled = false
        return i
    }

    private func short(_ s: String, _ n: Int = 60) -> String {
        s.count > n ? String(s.prefix(n - 1)) + "…" : s
    }

    private func problemItem(_ p: Problem) -> NSMenuItem {
        let label = (p.severity == "high" ? "Urgent: " : "") + short(p.title)
        let top = NSMenuItem(title: label, action: nil, keyEquivalent: "")
        top.toolTip = p.title
        let sub = NSMenu()
        sub.autoenablesItems = false
        for (title, action) in [("What to do", #selector(menuWhatToDo(_:))),
                                ("Done", #selector(menuDone(_:))),
                                ("Snooze 1 day", #selector(menuSnooze(_:)))] {
            let i = item(title, action)
            i.representedObject = p
            sub.addItem(i)
        }
        top.submenu = sub
        return top
    }

    private func allowedAppsItem() -> NSMenuItem {
        let top = NSMenuItem(title: "Apps allowed to use camera or mic", action: nil, keyEquivalent: "")
        let sub = NSMenu()
        sub.autoenablesItems = false
        let apps = allowedApps
        if apps.isEmpty {
            sub.addItem(disabled("None yet"))
        } else {
            sub.addItem(disabled("Click an app to remove it"))
            for a in apps {
                let i = item(a, #selector(removeAllowed(_:)))
                i.representedObject = a
                sub.addItem(i)
            }
        }
        top.submenu = sub
        return top
    }

    // MARK: - actions

    @objc private func menuWhatToDo(_ sender: NSMenuItem) {
        guard let p = sender.representedObject as? Problem else { return }
        showFix(title: p.title, fix: p.fix ?? "")
    }

    @objc private func menuDone(_ sender: NSMenuItem) {
        guard let p = sender.representedObject as? Problem else { return }
        ack(p.ackKey, forever: true)
    }

    @objc private func menuSnooze(_ sender: NSMenuItem) {
        guard let p = sender.representedObject as? Problem else { return }
        ack(p.ackKey, forever: false)
    }

    func ack(_ key: String, forever: Bool) {
        guard !key.isEmpty else { return }
        Task { @MainActor in
            do {
                try await YakliteAPI.ack(key: key, forever: forever)
            } catch {
                self.showMessage("Could not save that", "yaklite did not answer. Try again in a minute.")
            }
            self.refresh()
        }
    }

    func showFix(title: String, fix: String) {
        NSApp.activate(ignoringOtherApps: true)
        let alert = NSAlert()
        alert.messageText = title
        alert.informativeText = fix.isEmpty ? "No steps are known for this one. Open the dashboard to see more." : fix
        alert.addButton(withTitle: "OK")
        alert.runModal()
    }

    private func showMessage(_ title: String, _ text: String) {
        NSApp.activate(ignoringOtherApps: true)
        let alert = NSAlert()
        alert.messageText = title
        alert.informativeText = text
        alert.addButton(withTitle: "OK")
        alert.runModal()
    }

    @objc private func checkNow() {
        checking = true
        rebuildMenu()
        Task { @MainActor in
            do {
                try await YakliteAPI.checkNow()
            } catch {
                self.problem = "Could not start a check."
            }
            // a check takes a little while; look again after it
            Timer.scheduledTimer(timeInterval: 45, target: self, selector: #selector(self.checkDone),
                                 userInfo: nil, repeats: false)
        }
    }

    @objc private func checkDone() {
        checking = false
        refresh()
    }

    @objc private func openDashboard() {
        NSWorkspace.shared.open(YakliteConfig.dashboardURL)
    }

    @objc func openSetup() {
        if setupWindow == nil {
            setupWindow = SetupWindowController()
        }
        setupWindow?.show()
    }

    @objc private func quit() {
        NSApp.terminate(nil)
    }

    // MARK: - camera and microphone

    var allowedApps: [String] {
        UserDefaults.standard.stringArray(forKey: Prefs.allowedApps) ?? []
    }

    func allow(app: String) {
        guard !app.isEmpty, !allowedApps.contains(app) else { return }
        UserDefaults.standard.set((allowedApps + [app]).sorted(), forKey: Prefs.allowedApps)
        rebuildMenu()
    }

    @objc private func removeAllowed(_ sender: NSMenuItem) {
        guard let a = sender.representedObject as? String else { return }
        UserDefaults.standard.set(allowedApps.filter { $0 != a }, forKey: Prefs.allowedApps)
        rebuildMenu()
    }

    @objc private func toggleDeviceAlerts() {
        let d = UserDefaults.standard
        d.set(!d.bool(forKey: Prefs.deviceAlerts), forKey: Prefs.deviceAlerts)
        rebuildMenu()
    }

    private func deviceTurnedOn(kind: DeviceKind, app: String?) {
        let name = app ?? ""
        // keep a record in yaklite's history (best effort)
        if YakliteConfig.token != nil {
            Task {
                try? await YakliteAPI.event(kind: kind.rawValue, app: name, on: true)
            }
        }
        guard UserDefaults.standard.bool(forKey: Prefs.deviceAlerts) else { return }
        if !name.isEmpty && allowedApps.contains(name) { return }
        notifier.showDevice(kind: kind, app: name)
    }

    // MARK: - notification buttons

    func handleNotification(action: String, key: String, title: String, fix: String, app: String) {
        switch action {
        case NotificationIDs.done:
            ack(key, forever: true)
        case NotificationIDs.snooze:
            ack(key, forever: false)
        case NotificationIDs.whatToDo, UNNotificationDefaultActionIdentifier:
            if !key.isEmpty {
                showFix(title: title, fix: fix)
            }
        case NotificationIDs.allow:
            allow(app: app)
        default:
            break
        }
    }
}
