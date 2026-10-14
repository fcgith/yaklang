import AppKit
import ServiceManagement
import SwiftUI

/// The choices map to `yaklite install` flags (see cmd/yaklite/install.go).
final class SetupModel: ObservableObject {
    @Published var dashboard = true        // off: --no-dashboard
    @Published var connections = true      // off: --no-connwatch
    @Published var weeklySummary = true    // off: --no-summary
    @Published var routerLog = false       // on: --router-log
    @Published var tripwire = false        // on: --tripwire
    @Published var output = ""
    @Published var running = false
    @Published var startAtLogin = false
    @Published var loginMessage = ""
    @Published var binaryPath: String?

    init() {
        refresh()
    }

    func refresh() {
        binaryPath = YakliteConfig.binaryPath
        startAtLogin = SMAppService.mainApp.status == .enabled
    }

    var installArgs: [String] {
        var a = ["install", "-y"] // -y: no questions; trust a network later with `yaklite trust`
        if !dashboard { a.append("--no-dashboard") }
        if !connections { a.append("--no-connwatch") }
        if !weeklySummary { a.append("--no-summary") }
        if routerLog { a.append("--router-log") }
        if tripwire { a.append("--tripwire") }
        return a
    }

    func apply() {
        refresh()
        guard let bin = binaryPath else {
            output = "yaklite is not installed yet. Download it, then run it once in Terminal with: yaklite install\n"
            return
        }
        running = true
        output = ""
        run(bin, installArgs) { [weak self] ok in
            guard let self = self else { return }
            if ok && YakliteConfig.token == nil {
                // link this app to yaklite (writes the app secret)
                self.run(bin, ["menubar", "connect"]) { [weak self] _ in self?.finish() }
            } else {
                self.finish()
            }
        }
    }

    private func finish() {
        running = false
        Task { @MainActor in
            AppDelegate.shared?.refresh()
        }
    }

    /// Runs yaklite, shows what it prints, and calls done on the main thread.
    private func run(_ bin: String, _ args: [String], done: @escaping (Bool) -> Void) {
        output += "$ yaklite " + args.joined(separator: " ") + "\n"
        let p = Process()
        p.executableURL = URL(fileURLWithPath: bin)
        p.arguments = args
        let pipe = Pipe()
        p.standardOutput = pipe
        p.standardError = pipe
        p.standardInput = FileHandle.nullDevice
        let reader = pipe.fileHandleForReading
        reader.readabilityHandler = { [weak self] h in
            let data = h.availableData
            guard !data.isEmpty else { return }
            let text = String(decoding: data, as: UTF8.self)
            DispatchQueue.main.async { self?.output += text }
        }
        p.terminationHandler = { [weak self] proc in
            reader.readabilityHandler = nil
            let rest = String(decoding: reader.readDataToEndOfFile(), as: UTF8.self)
            let ok = proc.terminationStatus == 0
            DispatchQueue.main.async {
                self?.output += rest
                self?.output += ok ? "Done.\n\n" : "It did not finish (code \(proc.terminationStatus)).\n\n"
                done(ok)
            }
        }
        do {
            try p.run()
        } catch {
            output += "Could not start yaklite: \(error.localizedDescription)\n"
            done(false)
        }
    }

    func openFullDiskAccess() {
        if let url = URL(string: "x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles") {
            NSWorkspace.shared.open(url)
        }
    }

    func copyPath() {
        guard let p = binaryPath else { return }
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(p, forType: .string)
    }

    func setStartAtLogin(_ on: Bool) {
        do {
            if on {
                try SMAppService.mainApp.register()
            } else {
                try SMAppService.mainApp.unregister()
            }
            loginMessage = ""
        } catch {
            loginMessage = "Could not change this: \(error.localizedDescription)"
        }
        let status = SMAppService.mainApp.status
        startAtLogin = status == .enabled
        if status == .requiresApproval {
            loginMessage = "Allow it in System Settings > General > Login Items."
            SMAppService.openSystemSettingsLoginItems()
        }
    }
}

struct SetupView: View {
    @ObservedObject var model: SetupModel

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("Set up yaklite").font(.title2).bold()
            Text("Choose what yaklite does in the background, then click Apply.")
                .foregroundColor(.secondary)

            Toggle("Dashboard on this Mac (this app needs it)", isOn: $model.dashboard)
            Toggle("Watch this Mac's internet connections", isOn: $model.connections)
            Toggle("Weekly summary on Monday morning", isOn: $model.weeklySummary)
            Toggle("Read the router's log (the router must send it here)", isOn: $model.routerLog)
            Toggle("Tripwire: fake services that catch snooping devices", isOn: $model.tripwire)

            HStack {
                Button("Apply") { model.apply() }
                    .disabled(model.running)
                if model.running {
                    ProgressView().controlSize(.small)
                }
            }
            ScrollView {
                Text(model.output.isEmpty ? "What yaklite says shows here." : model.output)
                    .font(.system(.caption, design: .monospaced))
                    .foregroundColor(model.output.isEmpty ? .secondary : .primary)
                    .textSelection(.enabled)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(6)
            }
            .frame(height: 150)
            .overlay(RoundedRectangle(cornerRadius: 4).stroke(Color.secondary.opacity(0.3)))

            Divider()
            Text("Full Disk Access").font(.headline)
            Text("Some checks need it. Click the button, click +, press Command-Shift-G, paste this path and add it:")
                .foregroundColor(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            HStack {
                Text(model.binaryPath ?? "yaklite is not installed yet")
                    .font(.system(.caption, design: .monospaced))
                    .textSelection(.enabled)
                    .lineLimit(2)
                Spacer()
                Button("Copy") { model.copyPath() }
                    .disabled(model.binaryPath == nil)
            }
            Button("Give Full Disk Access") { model.openFullDiskAccess() }

            Divider()
            Toggle("Start this app at login", isOn: Binding(
                get: { model.startAtLogin },
                set: { model.setStartAtLogin($0) }))
            if !model.loginMessage.isEmpty {
                Text(model.loginMessage).font(.caption).foregroundColor(.secondary)
            }
        }
        .padding(20)
        .frame(width: 500)
    }
}

final class SetupWindowController {
    private var window: NSWindow?
    private let model: SetupModel

    init() {
        model = SetupModel()
    }

    func show() {
        model.refresh()
        if window == nil {
            let w = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 500, height: 640),
                             styleMask: [.titled, .closable],
                             backing: .buffered,
                             defer: false)
            w.title = "yaklite setup"
            w.isReleasedWhenClosed = false
            w.contentView = NSHostingView(rootView: SetupView(model: model))
            w.center()
            window = w
        }
        NSApp.activate(ignoringOtherApps: true)
        window?.makeKeyAndOrderFront(nil)
    }
}
