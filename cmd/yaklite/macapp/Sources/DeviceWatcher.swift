import AppKit
import CoreAudio
import CoreMediaIO

enum DeviceKind: String {
    case camera
    case mic
}

/// Notices when any camera or microphone starts being used. It only asks the
/// system whether a device is in use; it never opens the camera or mic.
final class DeviceWatcher: NSObject {
    var onTurnedOn: ((DeviceKind, String?) -> Void)?
    private var timer: Timer?
    private var cameraOn: Bool?
    private var micOn: Bool?

    func start() {
        poll()
        timer = Timer.scheduledTimer(timeInterval: 3, target: self, selector: #selector(poll),
                                     userInfo: nil, repeats: true)
    }

    @objc private func poll() {
        let cam = DeviceWatcher.anyCameraRunning()
        let mic = DeviceWatcher.anyMicRunning()
        let app = NSWorkspace.shared.frontmostApplication?.localizedName
        if cameraOn == false && cam {
            onTurnedOn?(.camera, app)
        }
        if micOn == false && mic {
            onTurnedOn?(.mic, app)
        }
        cameraOn = cam
        micOn = mic
    }

    // MARK: - cameras (CoreMediaIO)

    private static func cmioAddress(_ selector: Int) -> CMIOObjectPropertyAddress {
        CMIOObjectPropertyAddress(
            mSelector: CMIOObjectPropertySelector(selector),
            mScope: CMIOObjectPropertyScope(kCMIOObjectPropertyScopeGlobal),
            mElement: CMIOObjectPropertyElement(kCMIOObjectPropertyElementMain))
    }

    static func anyCameraRunning() -> Bool {
        let system = CMIOObjectID(kCMIOObjectSystemObject)
        var addr = cmioAddress(Int(kCMIOHardwarePropertyDevices))
        var size: UInt32 = 0
        guard CMIOObjectGetPropertyDataSize(system, &addr, 0, nil, &size) == noErr, size > 0 else {
            return false
        }
        let stride = MemoryLayout<CMIOObjectID>.size
        var devices = [CMIOObjectID](repeating: 0, count: Int(size) / stride)
        var used: UInt32 = 0
        guard CMIOObjectGetPropertyData(system, &addr, 0, nil, size, &used, &devices) == noErr else {
            return false
        }
        for dev in devices.prefix(Int(used) / stride) {
            var runAddr = cmioAddress(Int(kCMIODevicePropertyDeviceIsRunningSomewhere))
            var running: UInt32 = 0
            var got: UInt32 = 0
            let status = CMIOObjectGetPropertyData(dev, &runAddr, 0, nil,
                                                   UInt32(MemoryLayout<UInt32>.size), &got, &running)
            if status == noErr && running != 0 {
                return true
            }
        }
        return false
    }

    // MARK: - microphones (CoreAudio)

    private static func audioAddress(_ selector: AudioObjectPropertySelector,
                                     _ scope: AudioObjectPropertyScope = AudioObjectPropertyScope(kAudioObjectPropertyScopeGlobal))
        -> AudioObjectPropertyAddress {
        AudioObjectPropertyAddress(
            mSelector: selector,
            mScope: scope,
            mElement: AudioObjectPropertyElement(kAudioObjectPropertyElementMain))
    }

    static func anyMicRunning() -> Bool {
        let system = AudioObjectID(kAudioObjectSystemObject)
        var addr = audioAddress(AudioObjectPropertySelector(kAudioHardwarePropertyDevices))
        var size: UInt32 = 0
        guard AudioObjectGetPropertyDataSize(system, &addr, 0, nil, &size) == noErr, size > 0 else {
            return false
        }
        let stride = MemoryLayout<AudioObjectID>.size
        var devices = [AudioObjectID](repeating: 0, count: Int(size) / stride)
        guard AudioObjectGetPropertyData(system, &addr, 0, nil, &size, &devices) == noErr else {
            return false
        }
        for dev in devices.prefix(Int(size) / stride) {
            // only devices with input streams are microphones
            var streams = audioAddress(AudioObjectPropertySelector(kAudioDevicePropertyStreams),
                                       AudioObjectPropertyScope(kAudioObjectPropertyScopeInput))
            var streamSize: UInt32 = 0
            guard AudioObjectGetPropertyDataSize(dev, &streams, 0, nil, &streamSize) == noErr, streamSize > 0 else {
                continue
            }
            var runAddr = audioAddress(AudioObjectPropertySelector(kAudioDevicePropertyDeviceIsRunningSomewhere))
            var running: UInt32 = 0
            var runSize = UInt32(MemoryLayout<UInt32>.size)
            if AudioObjectGetPropertyData(dev, &runAddr, 0, nil, &runSize, &running) == noErr && running != 0 {
                return true
            }
        }
        return false
    }
}
