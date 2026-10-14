// YakliteBar: the menu bar companion for yaklite.
// Built with plain swiftc (see build.sh); this file is the entry point.

import AppKit

let app = NSApplication.shared
let delegate = AppDelegate()
app.delegate = delegate
app.setActivationPolicy(.accessory)
app.run()
