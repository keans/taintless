import Foundation

class Runner {
    var cmd: String

    init(cmd: String) {
        self.cmd = cmd
    }

    func run() -> Int32 {
        return system(cmd)
    }
}

func direct() {
    let name = readLine()!
    system("ls " + name)
}

func fromArguments() {
    let path = CommandLine.arguments[1]
    let data = FileManager.default.contents(atPath: path)
    print(data as Any)
}

func safe() {
    let name = readLine()!
    system("ls " + String(Int(name) ?? 0))
}

func stored() {
    let r = Runner(cmd: readLine()!)
    r.run()
}

func bindings() {
    let raw = readLine()
    if let name = raw, name.count > 0 {
        system(name)
    }
    guard let other = readLine() else { return }
    popen(other, "r")
}

func branches(_ flag: Bool) {
    let x = readLine()!
    var y = "fixed"
    if flag {
        y = x
    }
    system(y)
}

func rescued() {
    do {
        let d = readLine()!
        let obj = NSKeyedUnarchiver.unarchiveObject(with: Data(d.utf8))
        print(obj as Any)
    } catch {
        print(error)
    }
}
