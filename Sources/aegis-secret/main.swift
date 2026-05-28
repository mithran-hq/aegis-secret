import AegisSecretCore
import Foundation
#if os(Linux)
import Glibc
#else
import Darwin
#endif

@main
struct AegisSecretCLIEntryPoint {
    static func main() async {
        let app = CLIApplication()
        await app.run(
            arguments: Array(CommandLine.arguments.dropFirst()),
            stdinIsTTY: isatty(FileHandle.standardInput.fileDescriptor) != 0
        )
    }
}
