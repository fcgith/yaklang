import AppKit
import UserNotifications

enum NotificationIDs {
    static let alertCategory = "yaklite.alert"
    static let done = "yaklite.done"
    static let snooze = "yaklite.snooze"
    static let whatToDo = "yaklite.whattodo"
    static let allow = "yaklite.allow"
}

/// Receives taps on notification buttons and hands them to the app.
final class NotificationHandler: NSObject, UNUserNotificationCenterDelegate {
    func userNotificationCenter(_ center: UNUserNotificationCenter,
                                willPresent notification: UNNotification,
                                withCompletionHandler completionHandler: @escaping (UNNotificationPresentationOptions) -> Void) {
        completionHandler([.banner, .list, .sound])
    }

    func userNotificationCenter(_ center: UNUserNotificationCenter,
                                didReceive response: UNNotificationResponse,
                                withCompletionHandler completionHandler: @escaping () -> Void) {
        let content = response.notification.request.content
        let info = content.userInfo
        let action = response.actionIdentifier
        let key = info["ackKey"] as? String ?? ""
        let title = info["title"] as? String ?? content.title
        let fix = info["fix"] as? String ?? ""
        let app = info["app"] as? String ?? ""
        completionHandler()
        Task { @MainActor in
            AppDelegate.shared?.handleNotification(action: action, key: key, title: title, fix: fix, app: app)
        }
    }
}

final class Notifier {
    private let handler = NotificationHandler()
    private var deviceCategories: [String: UNNotificationCategory] = [:]

    private var center: UNUserNotificationCenter { UNUserNotificationCenter.current() }

    func start() {
        center.delegate = handler
        center.requestAuthorization(options: [.alert, .sound]) { _, _ in }
        applyCategories()
    }

    private var alertCategory: UNNotificationCategory {
        UNNotificationCategory(
            identifier: NotificationIDs.alertCategory,
            actions: [
                UNNotificationAction(identifier: NotificationIDs.done, title: "Done", options: []),
                UNNotificationAction(identifier: NotificationIDs.snooze, title: "Snooze 1 day", options: []),
                UNNotificationAction(identifier: NotificationIDs.whatToDo, title: "What to do", options: [.foreground]),
            ],
            intentIdentifiers: [],
            options: [])
    }

    private func applyCategories() {
        var all: Set<UNNotificationCategory> = [alertCategory]
        for c in deviceCategories.values {
            all.insert(c)
        }
        center.setNotificationCategories(all)
    }

    /// Shows alerts that were not shown before. On the very first run it only
    /// remembers them, so a fresh install does not flood the screen.
    func showNew(alerts: [Problem]) {
        let d = UserDefaults.standard
        let firstRun = d.object(forKey: Prefs.seenAlertIDs) == nil
        var seen = d.stringArray(forKey: Prefs.seenAlertIDs) ?? []
        let known = Set(seen)
        var fresh: [Problem] = []
        for a in alerts.reversed() where !known.contains(a.id) { // oldest first
            seen.append(a.id)
            fresh.append(a)
        }
        if seen.count > 500 {
            seen.removeFirst(seen.count - 500)
        }
        d.set(seen, forKey: Prefs.seenAlertIDs)
        if firstRun { return }

        for a in fresh.suffix(5) {
            let c = UNMutableNotificationContent()
            c.title = a.severity == "high" ? "yaklite: needs attention now" : "yaklite: worth a look"
            c.body = a.title
            c.sound = .default
            c.categoryIdentifier = NotificationIDs.alertCategory
            c.userInfo = ["ackKey": a.ackKey, "title": a.title, "fix": a.fix ?? ""]
            center.add(UNNotificationRequest(identifier: "alert-" + a.id, content: c, trigger: nil),
                       withCompletionHandler: nil)
        }
        if fresh.count > 5 {
            let c = UNMutableNotificationContent()
            c.title = "yaklite"
            c.body = "\(fresh.count - 5) more alerts. Open the dashboard to see them."
            center.add(UNNotificationRequest(identifier: "alert-more-" + UUID().uuidString, content: c, trigger: nil),
                       withCompletionHandler: nil)
        }
    }

    func showDevice(kind: DeviceKind, app: String) {
        let c = UNMutableNotificationContent()
        c.title = kind == .camera ? "Camera turned on" : "Microphone turned on"
        c.body = app.isEmpty ? "An app started using it." : "Probably \(app)."
        c.sound = .default
        c.userInfo = ["app": app]
        if !app.isEmpty {
            let id = "yaklite.device." + app
            if deviceCategories[id] == nil {
                deviceCategories[id] = UNNotificationCategory(
                    identifier: id,
                    actions: [UNNotificationAction(identifier: NotificationIDs.allow, title: "Always allow \(app)", options: [])],
                    intentIdentifiers: [],
                    options: [])
                applyCategories()
            }
            c.categoryIdentifier = id
        }
        let request = UNNotificationRequest(identifier: "device-" + UUID().uuidString, content: c, trigger: nil)
        // wait until the button set is registered, then show it
        let center = self.center
        center.getNotificationCategories { _ in
            center.add(request, withCompletionHandler: nil)
        }
    }
}
