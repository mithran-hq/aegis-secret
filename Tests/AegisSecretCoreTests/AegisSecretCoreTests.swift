import AegisSecretCore
import Foundation
import XCTest

struct InMemorySecretStore: SecretStore {
    var secrets: [String: Data]

    init(secrets: [String: Data] = [:]) {
        self.secrets = secrets
    }

    func setSecret(_ secretData: Data, for key: String) throws {}

    func readSecret(for key: String) throws -> Data {
        guard let secret = secrets[key] else {
            throw AegisSecretError.runtime("missing secret")
        }
        return secret
    }

    func deleteSecret(for key: String) throws -> Bool {
        secrets[key] != nil
    }

    func listSecrets() throws -> [SecretListItem] {
        secrets.keys.sorted().map(SecretListItem.init(key:))
    }

    func secretExists(for key: String) throws -> Bool {
        secrets[key] != nil
    }
}

actor AuthRecorder: DeviceAuthenticator {
    private(set) var reasons: [String] = []

    func authenticate(reason: String) async throws {
        reasons.append(reason)
    }

    func snapshot() -> [String] {
        reasons
    }
}

struct MockCommandExecutor: CommandExecutor {
    let handler: @Sendable (CommandExecutionRequest) async throws -> RawCommandExecutionResult

    func execute(_ request: CommandExecutionRequest) async throws -> RawCommandExecutionResult {
        try await handler(request)
    }
}

final class AegisSecretCoreTests: XCTestCase {
    func testHelpWhenNoArguments() throws {
        XCTAssertEqual(try CommandParser().parse([], stdinIsTTY: true), .help)
    }

    func testSetDefaultsToPromptWhenTTY() throws {
        XCTAssertEqual(
            try CommandParser().parse(["set", "OPENAI_API_KEY"], stdinIsTTY: true),
            .set(key: "OPENAI_API_KEY", inputMode: .prompt)
        )
    }

    func testSetDefaultsToStdinWhenPiped() throws {
        XCTAssertEqual(
            try CommandParser().parse(["set", "OPENAI_API_KEY"], stdinIsTTY: false),
            .set(key: "OPENAI_API_KEY", inputMode: .stdin)
        )
    }

    func testGetRequiresAgentName() {
        XCTAssertThrowsError(try CommandParser().parse(["get", "OPENAI_API_KEY"], stdinIsTTY: true)) { error in
            XCTAssertEqual(
                error as? AegisSecretError,
                .usage("`get` requires `--agent <name>` so the approval prompt identifies the caller.")
            )
        }
    }

    func testDeleteParses() throws {
        XCTAssertEqual(
            try CommandParser().parse(["delete", "OPENAI_API_KEY"], stdinIsTTY: true),
            .delete(key: "OPENAI_API_KEY")
        )
    }

    func testInstallUserParses() throws {
        XCTAssertEqual(
            try CommandParser().parse(["install-user"], stdinIsTTY: true),
            .installUser
        )
    }

    func testCommandValidateFileParses() throws {
        XCTAssertEqual(
            try CommandParser().parse(["command", "validate", "--file", "/tmp/commands.json"], stdinIsTTY: true),
            .command(.validateFile(path: "/tmp/commands.json"))
        )
    }

    func testApprovalStatusParses() throws {
        XCTAssertEqual(
            try CommandParser().parse(["approval", "status", "gh", "--agent", "Codex"], stdinIsTTY: true),
            .approval(.status(command: "gh", agent: "Codex"))
        )
    }

    func testGuardShellParsesCommand() throws {
        XCTAssertEqual(
            try CommandParser().parse(["guard", "shell", "--command", "gh issue list"], stdinIsTTY: true),
            .guardCommand(.shell(command: "gh issue list"))
        )
    }

    func testGuardShellParsesStdinMode() throws {
        XCTAssertEqual(
            try CommandParser().parse(["guard", "shell"], stdinIsTTY: false),
            .guardCommand(.shell(command: nil))
        )
    }

    func testRunParsesArgsAfterDoubleDash() throws {
        XCTAssertEqual(
            try CommandParser().parse(["run", "gh", "--", "api", "/user"], stdinIsTTY: true),
            .run(name: "gh", args: ["api", "/user"])
        )
    }

    func testWrappedCommandConfigResolvesDefaults() throws {
        let command = try WrappedCommandConfig(
            name: "gh",
            command: "gh"
        ).resolved()

        XCTAssertEqual(command.approvalWindowSeconds, 300)
        XCTAssertEqual(command.timeoutSeconds, 30)
        XCTAssertEqual(command.maxOutputBytes, 256 * 1024)
    }

    func testWrappedCommandRejectsAllowAndDenyPrefixesTogether() {
        XCTAssertThrowsError(
            try WrappedCommandConfig(
                name: "gh",
                command: "gh",
                denyPrefixes: [["auth"]],
                allowPrefixes: [["api"]]
            ).resolved()
        ) { error in
            XCTAssertTrue((error as? AegisSecretError)?.description.contains("cannot define both") == true)
        }
    }

    func testCommandStoreUsesDefaultTemplateWhenMissing() throws {
        let tempDirectory = try temporaryDirectory()
        let store = CommandStore(
            fileURL: tempDirectory.appendingPathComponent("commands.json"),
            environment: [systemCommandsFileEnvironmentKey: tempDirectory.appendingPathComponent("system-commands.json").path]
        )

        let names = try store.listCommands().map(\.name)
        XCTAssertEqual(names, ["aws", "az", "gcloud", "gh", "kubectl", "terraform"])
    }

    func testCommandStoreMergesSystemAndUserOverrides() throws {
        let tempDirectory = try temporaryDirectory()
        let systemFile = tempDirectory.appendingPathComponent("system-commands.json")
        let userFile = tempDirectory.appendingPathComponent("commands.json")

        try prettyJSON(
            CommandFile(commands: [
                WrappedCommandConfig(name: "gh", command: "gh", approvalWindowSeconds: 300),
                WrappedCommandConfig(name: "aws", command: "aws", approvalWindowSeconds: 300)
            ])
        ).write(to: systemFile)

        try prettyJSON(
            CommandFile(commands: [
                WrappedCommandConfig(name: "gh", approvalWindowSeconds: 0),
                WrappedCommandConfig(name: "aws", enabled: false),
                WrappedCommandConfig(name: "kubectl", command: "kubectl", approvalWindowSeconds: 120)
            ])
        ).write(to: userFile)

        let store = CommandStore(
            fileURL: userFile,
            environment: [systemCommandsFileEnvironmentKey: systemFile.path]
        )

        let commands = try store.resolvedCommands()
        XCTAssertEqual(commands.map(\.name), ["gh", "kubectl"])
        XCTAssertEqual(commands.first(where: { $0.name == "gh" })?.approvalWindowSeconds, 0)
        XCTAssertEqual(commands.first(where: { $0.name == "kubectl" })?.command, "kubectl")
    }

    func testCommandStoreValidateFileRejectsDuplicateNames() throws {
        let tempDirectory = try temporaryDirectory()
        let commandFile = tempDirectory.appendingPathComponent("commands.json")
        try prettyJSON(
            CommandFile(commands: [
                WrappedCommandConfig(name: "gh", command: "gh"),
                WrappedCommandConfig(name: "gh", command: "gh")
            ])
        ).write(to: commandFile)

        let store = CommandStore(fileURL: commandFile)
        XCTAssertThrowsError(try store.validateCurrentConfiguration()) { error in
            XCTAssertTrue((error as? AegisSecretError)?.description.contains("duplicate") == true)
        }
    }

    func testRunnerRejectsUnknownWrappedCommand() async throws {
        let tempDirectory = try temporaryDirectory()
        let systemFile = tempDirectory.appendingPathComponent("system-commands.json")
        let commandFile = tempDirectory.appendingPathComponent("commands.json")
        try prettyJSON(CommandFile(commands: [])).write(to: systemFile)
        try prettyJSON(CommandFile(commands: [])).write(to: commandFile)

        let runner = WrappedCommandRunner(
            commandStore: CommandStore(
                fileURL: commandFile,
                environment: [systemCommandsFileEnvironmentKey: systemFile.path]
            ),
            authenticator: AuthRecorder(),
            executor: MockCommandExecutor { _ in
                XCTFail("executor should not run")
                return RawCommandExecutionResult(stdout: Data(), stderr: Data(), exitCode: 0)
            }
        )

        do {
            _ = try await runner.run(name: "gh", args: ["api", "/user"], requester: "Test")
            XCTFail("expected wrapped command to fail")
        } catch let error as AegisSecretError {
            XCTAssertTrue(error.description.contains("was not found"))
        }
    }

    func testRunnerRejectsDeniedPrefix() async throws {
        let tempDirectory = try temporaryDirectory()
        let executablePath = try makeExecutable(named: "gh", in: tempDirectory, contents: "#!/bin/zsh\nexit 0\n")
        let commandFile = tempDirectory.appendingPathComponent("commands.json")
        try prettyJSON(
            CommandFile(commands: [
                WrappedCommandConfig(name: "gh", command: executablePath.path, denyPrefixes: [["auth"]])
            ])
        ).write(to: commandFile)

        let runner = WrappedCommandRunner(
            commandStore: CommandStore(fileURL: commandFile),
            authenticator: AuthRecorder(),
            executor: MockCommandExecutor { _ in
                XCTFail("executor should not run")
                return RawCommandExecutionResult(stdout: Data(), stderr: Data(), exitCode: 0)
            }
        )

        do {
            _ = try await runner.run(name: "gh", args: ["auth", "token"], requester: "Test")
            XCTFail("expected wrapped command to fail")
        } catch let error as AegisSecretError {
            XCTAssertTrue(error.description.contains("not allowed"))
            XCTAssertTrue(error.description.contains("gh api /user"))
        }
    }

    func testRunnerRejectsDeniedFlagWithEqualsSyntax() async throws {
        let tempDirectory = try temporaryDirectory()
        let executablePath = try makeExecutable(named: "gh", in: tempDirectory, contents: "#!/bin/zsh\nexit 0\n")
        let commandFile = tempDirectory.appendingPathComponent("commands.json")
        try prettyJSON(
            CommandFile(commands: [
                WrappedCommandConfig(name: "gh", command: executablePath.path, denyFlags: ["--hostname"])
            ])
        ).write(to: commandFile)

        let runner = WrappedCommandRunner(
            commandStore: CommandStore(fileURL: commandFile),
            authenticator: AuthRecorder(),
            executor: MockCommandExecutor { _ in
                XCTFail("executor should not run")
                return RawCommandExecutionResult(stdout: Data(), stderr: Data(), exitCode: 0)
            }
        )

        do {
            _ = try await runner.run(name: "gh", args: ["repo", "view", "--hostname=example.com"], requester: "Test")
            XCTFail("expected wrapped command to fail")
        } catch let error as AegisSecretError {
            XCTAssertTrue(error.description.contains("Flag"))
        }
    }

    func testRunnerAllowsGcloudAccountFlag() async throws {
        let tempDirectory = try temporaryDirectory()
        let executablePath = try makeExecutable(named: "gcloud", in: tempDirectory, contents: "#!/bin/zsh\nexit 0\n")
        let commandFile = tempDirectory.appendingPathComponent("commands.json")
        try prettyJSON(
            CommandFile(commands: [
                WrappedCommandConfig(
                    name: "gcloud",
                    command: executablePath.path,
                    denyPrefixes: [["auth"], ["config", "config-helper"]],
                    denyFlags: ["--access-token-file"]
                )
            ])
        ).write(to: commandFile)

        let runner = WrappedCommandRunner(
            commandStore: CommandStore(fileURL: commandFile),
            authenticator: AuthRecorder(),
            approvalCache: ApprovalCache(leaseFileURL: nil),
            executor: MockCommandExecutor { request in
                XCTAssertEqual(
                    request.arguments,
                    ["compute", "ssh", "vm-name", "--account=user@example.com"]
                )
                return RawCommandExecutionResult(
                    stdout: Data("ok\n".utf8),
                    stderr: Data(),
                    exitCode: 0
                )
            }
        )

        let result = try await runner.run(
            name: "gcloud",
            args: ["compute", "ssh", "vm-name", "--account=user@example.com"],
            requester: "Claude"
        )
        XCTAssertEqual(result.exitCode, 0)
        XCTAssertEqual(result.stdout, "ok\n")
    }

    func testRunnerRequiresApprovalOncePerWindow() async throws {
        let tempDirectory = try temporaryDirectory()
        let executablePath = try makeExecutable(named: "gh", in: tempDirectory, contents: "#!/bin/zsh\nexit 0\n")
        let commandFile = tempDirectory.appendingPathComponent("commands.json")
        try prettyJSON(
            CommandFile(commands: [
                WrappedCommandConfig(name: "gh", command: executablePath.path)
            ])
        ).write(to: commandFile)

        let authenticator = AuthRecorder()
        let runner = WrappedCommandRunner(
            commandStore: CommandStore(fileURL: commandFile),
            authenticator: authenticator,
            approvalCache: ApprovalCache(leaseFileURL: nil),
            executor: MockCommandExecutor { request in
                XCTAssertEqual(request.arguments, ["api", "/user"])
                return RawCommandExecutionResult(
                    stdout: Data(#"{"login":"olympum"}"#.utf8),
                    stderr: Data(),
                    exitCode: 0
                )
            }
        )

        let first = try await runner.run(name: "gh", args: ["api", "/user"], requester: "Claude")
        XCTAssertEqual(first.stdoutJSON, JSONValue.object(["login": JSONValue.string("olympum")]))

        _ = try await runner.run(name: "gh", args: ["api", "/user"], requester: "Claude")
        let reasons = await authenticator.snapshot()
        XCTAssertEqual(reasons.count, 1)
        XCTAssertTrue(reasons[0].contains("wrapped command 'gh'"))
    }

    func testRunnerReusesPersistedApprovalAcrossCachesForSameAgent() async throws {
        let tempDirectory = try temporaryDirectory()
        let executablePath = try makeExecutable(named: "gh", in: tempDirectory, contents: "#!/bin/zsh\nexit 0\n")
        let commandFile = tempDirectory.appendingPathComponent("commands.json")
        let leaseFile = tempDirectory.appendingPathComponent("approval-leases.json")
        try prettyJSON(
            CommandFile(commands: [
                WrappedCommandConfig(name: "gh", command: executablePath.path, approvalWindowSeconds: 300)
            ])
        ).write(to: commandFile)

        let authenticator = AuthRecorder()
        let start = Date(timeIntervalSince1970: 1_000_000)
        let runner1 = WrappedCommandRunner(
            commandStore: CommandStore(fileURL: commandFile),
            authenticator: authenticator,
            approvalCache: ApprovalCache(leaseFileURL: leaseFile, now: { start }),
            executor: MockCommandExecutor { _ in
                RawCommandExecutionResult(stdout: Data("one\n".utf8), stderr: Data(), exitCode: 0)
            }
        )
        let runner2 = WrappedCommandRunner(
            commandStore: CommandStore(fileURL: commandFile),
            authenticator: authenticator,
            approvalCache: ApprovalCache(leaseFileURL: leaseFile, now: { start.addingTimeInterval(10) }),
            executor: MockCommandExecutor { _ in
                RawCommandExecutionResult(stdout: Data("two\n".utf8), stderr: Data(), exitCode: 0)
            }
        )

        _ = try await runner1.run(name: "gh", args: ["api", "/user"], requester: "Claude")
        _ = try await runner2.run(name: "gh", args: ["api", "/user"], requester: "Claude")

        let reasons = await authenticator.snapshot()
        XCTAssertEqual(reasons.count, 1)
        XCTAssertTrue(FileManager.default.fileExists(atPath: leaseFile.path))
    }

    func testPersistedApprovalDoesNotCrossAgents() async throws {
        let tempDirectory = try temporaryDirectory()
        let executablePath = try makeExecutable(named: "gh", in: tempDirectory, contents: "#!/bin/zsh\nexit 0\n")
        let commandFile = tempDirectory.appendingPathComponent("commands.json")
        let leaseFile = tempDirectory.appendingPathComponent("approval-leases.json")
        try prettyJSON(
            CommandFile(commands: [
                WrappedCommandConfig(name: "gh", command: executablePath.path, approvalWindowSeconds: 300)
            ])
        ).write(to: commandFile)

        let authenticator = AuthRecorder()
        let start = Date(timeIntervalSince1970: 1_000_000)
        let makeRunner: (String) -> WrappedCommandRunner = { output in
            WrappedCommandRunner(
                commandStore: CommandStore(fileURL: commandFile),
                authenticator: authenticator,
                approvalCache: ApprovalCache(leaseFileURL: leaseFile, now: { start }),
                executor: MockCommandExecutor { _ in
                    RawCommandExecutionResult(stdout: Data("\(output)\n".utf8), stderr: Data(), exitCode: 0)
                }
            )
        }

        _ = try await makeRunner("one").run(name: "gh", args: ["api", "/user"], requester: "Claude")
        _ = try await makeRunner("two").run(name: "gh", args: ["api", "/user"], requester: "Codex")

        let reasons = await authenticator.snapshot()
        XCTAssertEqual(reasons.count, 2)
    }

    func testPersistedApprovalExpires() async throws {
        let tempDirectory = try temporaryDirectory()
        let executablePath = try makeExecutable(named: "gh", in: tempDirectory, contents: "#!/bin/zsh\nexit 0\n")
        let commandFile = tempDirectory.appendingPathComponent("commands.json")
        let leaseFile = tempDirectory.appendingPathComponent("approval-leases.json")
        try prettyJSON(
            CommandFile(commands: [
                WrappedCommandConfig(name: "gh", command: executablePath.path, approvalWindowSeconds: 30)
            ])
        ).write(to: commandFile)

        let authenticator = AuthRecorder()
        let start = Date(timeIntervalSince1970: 1_000_000)
        let executor = MockCommandExecutor { _ in
            RawCommandExecutionResult(stdout: Data("ok\n".utf8), stderr: Data(), exitCode: 0)
        }

        _ = try await WrappedCommandRunner(
            commandStore: CommandStore(fileURL: commandFile),
            authenticator: authenticator,
            approvalCache: ApprovalCache(leaseFileURL: leaseFile, now: { start }),
            executor: executor
        ).run(name: "gh", args: ["api", "/user"], requester: "Claude")

        _ = try await WrappedCommandRunner(
            commandStore: CommandStore(fileURL: commandFile),
            authenticator: authenticator,
            approvalCache: ApprovalCache(leaseFileURL: leaseFile, now: { start.addingTimeInterval(31) }),
            executor: executor
        ).run(name: "gh", args: ["api", "/user"], requester: "Claude")

        let reasons = await authenticator.snapshot()
        XCTAssertEqual(reasons.count, 2)
    }

    func testPersistedApprovalInvalidatesWhenPolicyChanges() async throws {
        let tempDirectory = try temporaryDirectory()
        let executablePath = try makeExecutable(named: "gh", in: tempDirectory, contents: "#!/bin/zsh\nexit 0\n")
        let commandFile = tempDirectory.appendingPathComponent("commands.json")
        let leaseFile = tempDirectory.appendingPathComponent("approval-leases.json")
        try prettyJSON(
            CommandFile(commands: [
                WrappedCommandConfig(name: "gh", command: executablePath.path, approvalWindowSeconds: 300)
            ])
        ).write(to: commandFile)

        let authenticator = AuthRecorder()
        let start = Date(timeIntervalSince1970: 1_000_000)
        let executor = MockCommandExecutor { _ in
            RawCommandExecutionResult(stdout: Data("ok\n".utf8), stderr: Data(), exitCode: 0)
        }

        _ = try await WrappedCommandRunner(
            commandStore: CommandStore(fileURL: commandFile),
            authenticator: authenticator,
            approvalCache: ApprovalCache(leaseFileURL: leaseFile, now: { start }),
            executor: executor
        ).run(name: "gh", args: ["api", "/user"], requester: "Claude")

        try prettyJSON(
            CommandFile(commands: [
                WrappedCommandConfig(
                    name: "gh",
                    command: executablePath.path,
                    approvalWindowSeconds: 300,
                    denyFlags: ["--other-host"]
                )
            ])
        ).write(to: commandFile)

        _ = try await WrappedCommandRunner(
            commandStore: CommandStore(fileURL: commandFile),
            authenticator: authenticator,
            approvalCache: ApprovalCache(leaseFileURL: leaseFile, now: { start.addingTimeInterval(10) }),
            executor: executor
        ).run(name: "gh", args: ["api", "/user"], requester: "Claude")

        let reasons = await authenticator.snapshot()
        XCTAssertEqual(reasons.count, 2)
    }

    func testPersistedApprovalInvalidatesWhenExecutablePathChanges() async throws {
        let tempDirectory = try temporaryDirectory()
        let firstExecutable = try makeExecutable(named: "gh-one", in: tempDirectory, contents: "#!/bin/zsh\nexit 0\n")
        let secondExecutable = try makeExecutable(named: "gh-two", in: tempDirectory, contents: "#!/bin/zsh\nexit 0\n")
        let commandFile = tempDirectory.appendingPathComponent("commands.json")
        let leaseFile = tempDirectory.appendingPathComponent("approval-leases.json")
        try prettyJSON(
            CommandFile(commands: [
                WrappedCommandConfig(name: "gh", command: firstExecutable.path, approvalWindowSeconds: 300)
            ])
        ).write(to: commandFile)

        let authenticator = AuthRecorder()
        let start = Date(timeIntervalSince1970: 1_000_000)
        let executor = MockCommandExecutor { _ in
            RawCommandExecutionResult(stdout: Data("ok\n".utf8), stderr: Data(), exitCode: 0)
        }

        _ = try await WrappedCommandRunner(
            commandStore: CommandStore(fileURL: commandFile),
            authenticator: authenticator,
            approvalCache: ApprovalCache(leaseFileURL: leaseFile, now: { start }),
            executor: executor
        ).run(name: "gh", args: ["api", "/user"], requester: "Claude")

        try prettyJSON(
            CommandFile(commands: [
                WrappedCommandConfig(name: "gh", command: secondExecutable.path, approvalWindowSeconds: 300)
            ])
        ).write(to: commandFile)

        _ = try await WrappedCommandRunner(
            commandStore: CommandStore(fileURL: commandFile),
            authenticator: authenticator,
            approvalCache: ApprovalCache(leaseFileURL: leaseFile, now: { start.addingTimeInterval(10) }),
            executor: executor
        ).run(name: "gh", args: ["api", "/user"], requester: "Claude")

        let reasons = await authenticator.snapshot()
        XCTAssertEqual(reasons.count, 2)
    }

    func testZeroApprovalWindowDoesNotPersistLease() async throws {
        let tempDirectory = try temporaryDirectory()
        let executablePath = try makeExecutable(named: "gh", in: tempDirectory, contents: "#!/bin/zsh\nexit 0\n")
        let commandFile = tempDirectory.appendingPathComponent("commands.json")
        let leaseFile = tempDirectory.appendingPathComponent("approval-leases.json")
        try prettyJSON(
            CommandFile(commands: [
                WrappedCommandConfig(name: "gh", command: executablePath.path, approvalWindowSeconds: 0)
            ])
        ).write(to: commandFile)

        let authenticator = AuthRecorder()
        let start = Date(timeIntervalSince1970: 1_000_000)
        let makeRunner: () -> WrappedCommandRunner = {
            WrappedCommandRunner(
                commandStore: CommandStore(fileURL: commandFile),
                authenticator: authenticator,
                approvalCache: ApprovalCache(leaseFileURL: leaseFile, now: { start }),
                executor: MockCommandExecutor { _ in
                    RawCommandExecutionResult(stdout: Data("ok\n".utf8), stderr: Data(), exitCode: 0)
                }
            )
        }

        _ = try await makeRunner().run(name: "gh", args: ["api", "/user"], requester: "Claude")
        _ = try await makeRunner().run(name: "gh", args: ["api", "/user"], requester: "Claude")

        let reasons = await authenticator.snapshot()
        XCTAssertEqual(reasons.count, 2)
        XCTAssertFalse(FileManager.default.fileExists(atPath: leaseFile.path))
    }

    func testApprovalInspectorClassifiesLeaseStatus() throws {
        let tempDirectory = try temporaryDirectory()
        let executablePath = try makeExecutable(named: "gh", in: tempDirectory, contents: "#!/bin/zsh\nexit 0\n")
        let commandFile = tempDirectory.appendingPathComponent("commands.json")
        let leaseFile = tempDirectory.appendingPathComponent("approval-leases.json")
        try prettyJSON(
            CommandFile(commands: [
                WrappedCommandConfig(name: "gh", command: executablePath.path, approvalWindowSeconds: 300)
            ])
        ).write(to: commandFile)

        let commandStore = CommandStore(fileURL: commandFile)
        let resolvedCommand = try commandStore.resolvedCommand(named: "gh")
        let fingerprint = try approvalPolicyFingerprint(for: resolvedCommand, executableURL: executablePath)
        let now = Date(timeIntervalSince1970: 1_000_000)
        try writeLeaseFile(
            ApprovalLeaseFile(leases: [
                ApprovalLeaseRecord(
                    agent: "Claude",
                    command: "gh",
                    executablePath: executablePath.path,
                    policyFingerprint: fingerprint,
                    approvedAt: now,
                    expiresAt: now.addingTimeInterval(300)
                ),
                ApprovalLeaseRecord(
                    agent: "Claude",
                    command: "aws",
                    executablePath: "/tmp/aws",
                    policyFingerprint: "old",
                    approvedAt: now.addingTimeInterval(-400),
                    expiresAt: now.addingTimeInterval(-100)
                )
            ]),
            to: leaseFile
        )

        let inspector = ApprovalLeaseInspector(leaseFileURL: leaseFile, commandStore: commandStore, now: now)
        XCTAssertEqual(try inspector.statuses(command: "gh", agent: "Claude").map(\.reason), [.hit])
        XCTAssertEqual(try inspector.statuses(command: "gh", agent: "Codex").map(\.reason), [.agentMismatch])
        XCTAssertEqual(try inspector.statuses(command: "aws", agent: "Claude").map(\.reason), [.expired])
        XCTAssertEqual(try inspector.statuses(command: "kubectl", agent: "Claude").map(\.reason), [.missingLease])
    }

    func testRunnerReturnsNonZeroExitCodeWithoutThrowing() async throws {
        let tempDirectory = try temporaryDirectory()
        let executablePath = try makeExecutable(named: "aws", in: tempDirectory, contents: "#!/bin/zsh\nexit 3\n")
        let commandFile = tempDirectory.appendingPathComponent("commands.json")
        try prettyJSON(
            CommandFile(commands: [
                WrappedCommandConfig(name: "aws", command: executablePath.path)
            ])
        ).write(to: commandFile)

        let runner = WrappedCommandRunner(
            commandStore: CommandStore(fileURL: commandFile),
            authenticator: AuthRecorder(),
            approvalCache: ApprovalCache(leaseFileURL: nil),
            executor: MockCommandExecutor { _ in
                RawCommandExecutionResult(
                    stdout: Data("ok\n".utf8),
                    stderr: Data("warn\n".utf8),
                    exitCode: 3
                )
            }
        )

        let result = try await runner.run(name: "aws", args: ["sts", "get-caller-identity"], requester: "Claude")
        XCTAssertEqual(result.exitCode, 3)
        XCTAssertEqual(result.stdout, "ok\n")
        XCTAssertEqual(result.stderr, "warn\n")
    }

    func testRunnerRejectsRelativeWorkingDirectory() async throws {
        let tempDirectory = try temporaryDirectory()
        let executablePath = try makeExecutable(named: "gh", in: tempDirectory, contents: "#!/bin/zsh\nexit 0\n")
        let commandFile = tempDirectory.appendingPathComponent("commands.json")
        try prettyJSON(
            CommandFile(commands: [
                WrappedCommandConfig(name: "gh", command: executablePath.path)
            ])
        ).write(to: commandFile)

        let runner = WrappedCommandRunner(
            commandStore: CommandStore(fileURL: commandFile),
            authenticator: AuthRecorder(),
            executor: MockCommandExecutor { _ in
                XCTFail("executor should not run")
                return RawCommandExecutionResult(stdout: Data(), stderr: Data(), exitCode: 0)
            }
        )

        do {
            _ = try await runner.run(name: "gh", args: [], cwd: "relative/path", requester: "Claude")
            XCTFail("expected wrapped command to fail")
        } catch let error as AegisSecretError {
            XCTAssertTrue(error.description.contains("absolute path"))
        }
    }

    func testShellGuardBlocksDirectWrappedCommand() {
        let result = ShellBypassGuard(wrappedCommandNames: ["gh"]).evaluate(command: "gh issue list")

        XCTAssertFalse(result.allowed)
        XCTAssertTrue(result.message.contains("wrapped command `gh`"))
    }

    func testShellGuardBlocksPathToWrappedCommand() {
        let result = ShellBypassGuard(wrappedCommandNames: ["gh"]).evaluate(command: "/opt/homebrew/bin/gh auth status")

        XCTAssertFalse(result.allowed)
        XCTAssertTrue(result.message.contains("wrapped command `gh`"))
    }

    func testShellGuardBlocksEnvironmentPrefixedWrappedCommand() {
        let result = ShellBypassGuard(wrappedCommandNames: ["gh"]).evaluate(command: "env GH_HOST=github.com gh issue list")

        XCTAssertFalse(result.allowed)
        XCTAssertTrue(result.message.contains("wrapped command `gh`"))
    }

    func testShellGuardBlocksAssignmentPrefixedWrappedCommand() {
        let result = ShellBypassGuard(wrappedCommandNames: ["gh"]).evaluate(command: "FOO=1 gh api /user")

        XCTAssertFalse(result.allowed)
        XCTAssertTrue(result.message.contains("wrapped command `gh`"))
    }

    func testShellGuardBlocksEnvOptionPrefixedWrappedCommand() {
        let result = ShellBypassGuard(wrappedCommandNames: ["gh"]).evaluate(command: "env -i GH_HOST=github.com gh issue list")

        XCTAssertFalse(result.allowed)
        XCTAssertTrue(result.message.contains("wrapped command `gh`"))
    }

    func testShellGuardBlocksCompoundWrappedCommand() {
        let result = ShellBypassGuard(wrappedCommandNames: ["gh"]).evaluate(command: "git status && gh issue list")

        XCTAssertFalse(result.allowed)
        XCTAssertTrue(result.message.contains("wrapped command `gh`"))
    }

    func testShellGuardBlocksAegisRunWrappedCommand() {
        let result = ShellBypassGuard(wrappedCommandNames: ["gh"]).evaluate(command: "aegis-secret run gh -- issue list")

        XCTAssertFalse(result.allowed)
        XCTAssertTrue(result.message.contains("wrapped command `gh`"))
    }

    func testShellGuardAllowsUnrelatedCommand() {
        let result = ShellBypassGuard(wrappedCommandNames: ["gh"]).evaluate(command: "git status --short")

        XCTAssertTrue(result.allowed)
    }

    func testShellGuardAllowsQuotedMentionOfWrappedCommand() {
        let result = ShellBypassGuard(wrappedCommandNames: ["gh"]).evaluate(command: "printf 'gh issue list'")

        XCTAssertTrue(result.allowed)
    }

    func testShellHookExtractorReadsTopLevelCommand() throws {
        let data = #"{"command":"gh issue list"}"#.data(using: .utf8)!

        XCTAssertEqual(try ShellHookCommandExtractor().extract(from: data), "gh issue list")
    }

    func testShellHookExtractorReadsNestedToolInputCommand() throws {
        let data = #"{"tool_input":{"command":"gh issue list"}}"#.data(using: .utf8)!

        XCTAssertEqual(try ShellHookCommandExtractor().extract(from: data), "gh issue list")
    }

    func testShellHookExtractorReadsNestedToolInputCamelCaseCommand() throws {
        let data = #"{"toolInput":{"cmd":"gh issue list"}}"#.data(using: .utf8)!

        XCTAssertEqual(try ShellHookCommandExtractor().extract(from: data), "gh issue list")
    }

    func testClaudeHookUpdaterPreservesExistingHooksAndIsIdempotent() throws {
        let existing = """
        {
          "permissions": { "allow": ["Bash(*)"] },
          "hooks": {
            "PreToolUse": [
              {
                "matcher": "Edit",
                "hooks": [
                  { "type": "command", "command": "/tmp/edit-check" }
                ]
              }
            ]
          }
        }
        """.data(using: .utf8)!
        let executableURL = URL(fileURLWithPath: "/Applications/Aegis Secret.app/Contents/MacOS/aegis-secret")
        let updater = AgentHookConfigUpdater()

        let once = try updater.upsertClaudeSettings(data: existing, executableURL: executableURL)
        let twice = try updater.upsertClaudeSettings(data: once, executableURL: executableURL)

        XCTAssertEqual(String(data: once, encoding: .utf8), String(data: twice, encoding: .utf8))
        let root = try jsonDictionary(from: twice)
        let hooks = try XCTUnwrap(root["hooks"] as? [String: Any])
        let preToolUse = try XCTUnwrap(hooks["PreToolUse"] as? [[String: Any]])
        XCTAssertEqual(preToolUse.count, 2)
        XCTAssertTrue(preToolUse.contains { $0["matcher"] as? String == "Edit" })
        let managed = try XCTUnwrap(preToolUse.first { $0["matcher"] as? String == "Bash" })
        let managedHooks = try XCTUnwrap(managed["hooks"] as? [[String: Any]])
        XCTAssertEqual(managedHooks.first?["command"] as? String, executableURL.path)
        XCTAssertEqual(managedHooks.first?["args"] as? [String], ["guard", "shell"])
    }

    func testCodexHookUpdaterPreservesExistingHooksAndIsIdempotent() throws {
        let existing = """
        {
          "hooks": {
            "PreToolUse": [
              {
                "matcher": "Edit",
                "hooks": [
                  { "type": "command", "command": "/tmp/edit-check" }
                ]
              }
            ],
            "PostToolUse": [
              {
                "matcher": "Bash",
                "hooks": [
                  { "type": "command", "command": "/tmp/audit" }
                ]
              }
            ]
          }
        }
        """.data(using: .utf8)!
        let executableURL = URL(fileURLWithPath: "/Applications/Aegis Secret.app/Contents/MacOS/aegis-secret")
        let updater = AgentHookConfigUpdater()

        let once = try updater.upsertCodexHooks(data: existing, executableURL: executableURL)
        let twice = try updater.upsertCodexHooks(data: once, executableURL: executableURL)

        XCTAssertEqual(String(data: once, encoding: .utf8), String(data: twice, encoding: .utf8))
        let root = try jsonDictionary(from: twice)
        let hooks = try XCTUnwrap(root["hooks"] as? [String: Any])
        let preToolUse = try XCTUnwrap(hooks["PreToolUse"] as? [[String: Any]])
        let postToolUse = try XCTUnwrap(hooks["PostToolUse"] as? [[String: Any]])
        XCTAssertEqual(preToolUse.count, 2)
        XCTAssertEqual(postToolUse.count, 1)
        XCTAssertTrue(preToolUse.contains { $0["matcher"] as? String == "Edit" })
        let managed = try XCTUnwrap(preToolUse.first {
            ($0["matcher"] as? String)?.contains("Bash") == true
        })
        let managedHooks = try XCTUnwrap(managed["hooks"] as? [[String: Any]])
        XCTAssertEqual(
            managedHooks.first?["command"] as? String,
            "'/Applications/Aegis Secret.app/Contents/MacOS/aegis-secret' guard shell"
        )
    }

    func testCodexConfigUpdaterAddsFeatureFlagWhenMissing() {
        let updated = AgentHookConfigUpdater().upsertCodexConfig("model = \"gpt-5.5\"\n")

        XCTAssertTrue(updated.contains("[features]\nhooks = true\n"))
    }

    func testCodexConfigUpdaterRefreshesExistingFeatureFlagIdempotently() {
        let existing = """
        model = "gpt-5.5"

        [features]
        hooks = false
        plugins = true

        [tui]
        theme = "dark"
        """
        let updater = AgentHookConfigUpdater()

        let once = updater.upsertCodexConfig(existing)
        let twice = updater.upsertCodexConfig(once)

        XCTAssertEqual(once, twice)
        XCTAssertTrue(once.contains("[features]\nhooks = true\nplugins = true"))
        XCTAssertTrue(once.contains("[tui]\ntheme = \"dark\""))
    }

    private func temporaryDirectory() throws -> URL {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
        return url
    }

    private func makeExecutable(named name: String, in directory: URL, contents: String) throws -> URL {
        let url = directory.appendingPathComponent(name)
        try contents.write(to: url, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: url.path)
        return url
    }

    private func writeLeaseFile(_ file: ApprovalLeaseFile, to url: URL) throws {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        try encoder.encode(file).write(to: url)
    }

    private func jsonDictionary(from data: Data) throws -> [String: Any] {
        try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
    }
}
