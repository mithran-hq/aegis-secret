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
        let arguments = Array(CommandLine.arguments.dropFirst())
        if arguments.first == "--mcp-server" {
            let server = StdioMCPServer()
            await server.run()
            Foundation.exit(ExitCode.success.rawValue)
        }

        let app = CLIApplication()
        await app.run(
            arguments: arguments,
            stdinIsTTY: isatty(FileHandle.standardInput.fileDescriptor) != 0
        )
    }
}
