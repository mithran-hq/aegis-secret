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

final class LinuxMAPGCPCommandRecorder: @unchecked Sendable {
    struct Invocation: Equatable {
        let executable: String
        let arguments: [String]
    }

    private(set) var invocations: [Invocation] = []

    func append(executable: String, arguments: [String]) {
        invocations.append(Invocation(executable: executable, arguments: arguments))
    }
}

struct MockLinuxMAPGCPCommandExecutor: LinuxMAPGCPCommandExecuting {
    let handler: @Sendable (String, [String], [String: String]) throws -> LinuxMAPGCPCommandResult

    func execute(executable: String, arguments: [String], environment: [String: String]) throws -> LinuxMAPGCPCommandResult {
        try handler(executable, arguments, environment)
    }
}

struct StubBrunoGuardEvaluator: BrunoGuardEvaluating {
    let handler: @Sendable (JSONValue) async throws -> BrunoGuardDecision

    func evaluate(event: JSONValue) async throws -> BrunoGuardDecision {
        try await handler(event)
    }
}

struct StubRemoteAuthorityLeaseProvider: RemoteAuthorityLeaseProviding {
    let handler: @Sendable (RemoteAuthorityActionRequest, RemoteAuthorityActionDescriptor) async throws -> RemoteAuthorityLease

    func lease(for request: RemoteAuthorityActionRequest, descriptor: RemoteAuthorityActionDescriptor) async throws -> RemoteAuthorityLease {
        try await handler(request, descriptor)
    }
}

struct StubGitHubRemoteAuthorityClient: GitHubRemoteAuthorityClient {
    let handler: @Sendable (GitHubRemoteAuthorityOperation, String) async throws -> RemoteAuthorityActionOutput

    func execute(operation: GitHubRemoteAuthorityOperation, token: String) async throws -> RemoteAuthorityActionOutput {
        try await handler(operation, token)
    }
}

struct StubGitAuthorIdentityProvider: GitAuthorIdentityProviding {
    let handler: @Sendable (String) throws -> GitAuthorIdentity

    func identity(cwd: String) throws -> GitAuthorIdentity {
        try handler(cwd)
    }
}

struct StubCLIProfileLeaseProvider: RemoteAuthorityCLIProfileLeaseProviding {
    let handler: @Sendable (RemoteAuthorityCLIProfileRequest, RemoteAuthorityCLIProfileDescriptor) async throws -> RemoteAuthorityLease

    func lease(for request: RemoteAuthorityCLIProfileRequest, profile: RemoteAuthorityCLIProfileDescriptor) async throws -> RemoteAuthorityLease {
        try await handler(request, profile)
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

    func testSecretListItemMergedDedupeAndSorts() {
        let merged = SecretListItem.merged(
            [SecretListItem(key: "ZED"), SecretListItem(key: "GITHUB_TOKEN")],
            [SecretListItem(key: "AWS_TOKEN"), SecretListItem(key: "GITHUB_TOKEN")]
        )

        XCTAssertEqual(merged.map(\.key), ["AWS_TOKEN", "GITHUB_TOKEN", "ZED"])
    }

    func testLinuxMAPGCPStoreResolvesSecretThroughActiveMAPAccount() throws {
        let recorder = LinuxMAPGCPCommandRecorder()
        let store = LinuxMAPGCPSecretStore(
            projectID: "mithran-sandbox",
            secretPrefix: "aegis-",
            gcloudExecutable: "/usr/bin/gcloud",
            environment: ["PATH": "/usr/bin"],
            executor: MockLinuxMAPGCPCommandExecutor { executable, arguments, _ in
                recorder.append(executable: executable, arguments: arguments)
                if arguments == ["auth", "list", "--filter=status:ACTIVE", "--format=value(account)"] {
                    return LinuxMAPGCPCommandResult(
                        stdout: Data("developer@mithran.ai\n".utf8),
                        stderr: Data(),
                        exitCode: 0
                    )
                }
                if arguments == [
                    "secrets", "versions", "access", "latest",
                    "--project", "mithran-sandbox",
                    "--secret", "aegis-github-token",
                ] {
                    return LinuxMAPGCPCommandResult(
                        stdout: Data("secret-token-123".utf8),
                        stderr: Data(),
                        exitCode: 0
                    )
                }
                XCTFail("unexpected gcloud invocation: \(arguments)")
                return LinuxMAPGCPCommandResult(stdout: Data(), stderr: Data(), exitCode: 1)
            }
        )

        let token = try store.readSecret(for: "github-token", reason: "test")

        XCTAssertEqual(String(decoding: token, as: UTF8.self), "secret-token-123")
        XCTAssertEqual(recorder.invocations.map(\.executable), ["/usr/bin/gcloud", "/usr/bin/gcloud"])
    }

    func testDefaultSecretStoreCanSelectLinuxMAPGCPAuthority() throws {
        let store = defaultSecretStore(environment: [
            "AEGIS_SECRET_AUTHORITY": "map-gcp",
            "AEGIS_SECRET_GCP_PROJECT": "mithran-sandbox",
        ])

        XCTAssertTrue(store is LinuxMAPGCPSecretStore)
    }

    func testLinuxMAPGCPStoreFailsClosedWithoutProjectOrMAPAccount() throws {
        let store = LinuxMAPGCPSecretStore(
            environment: [:],
            executor: MockLinuxMAPGCPCommandExecutor { _, _, _ in
                XCTFail("gcloud should not run without project configuration")
                return LinuxMAPGCPCommandResult(stdout: Data(), stderr: Data(), exitCode: 1)
            }
        )

        XCTAssertThrowsError(try store.readSecret(for: "github-token", reason: "test")) { error in
            XCTAssertTrue(String(describing: error).contains("broker_auth_lease_denied"))
            XCTAssertTrue(String(describing: error).contains("AEGIS_SECRET_GCP_PROJECT"))
        }

        let missingMAPStore = LinuxMAPGCPSecretStore(
            projectID: "mithran-sandbox",
            executor: MockLinuxMAPGCPCommandExecutor { _, arguments, _ in
                XCTAssertEqual(arguments, ["auth", "list", "--filter=status:ACTIVE", "--format=value(account)"])
                return LinuxMAPGCPCommandResult(stdout: Data(), stderr: Data("not logged in".utf8), exitCode: 1)
            }
        )

        XCTAssertThrowsError(try missingMAPStore.readSecret(for: "github-token", reason: "test")) { error in
            XCTAssertTrue(String(describing: error).contains("broker_auth_lease_denied"))
            XCTAssertTrue(String(describing: error).contains("MAP sign-in"))
        }
    }

    func testLinuxMAPGCPStoreMapsDeniedAndUnsafeRefsWithoutLeakingProviderDetails() throws {
        let store = LinuxMAPGCPSecretStore(
            projectID: "mithran-sandbox",
            mapAccount: "developer@mithran.ai",
            executor: MockLinuxMAPGCPCommandExecutor { _, _, _ in
                LinuxMAPGCPCommandResult(
                    stdout: Data(),
                    stderr: Data("PERMISSION_DENIED secret projects/mithran-sandbox/secrets/private-token".utf8),
                    exitCode: 1
                )
            }
        )

        XCTAssertThrowsError(try store.readSecret(for: "private-token", reason: "test")) { error in
            let message = String(describing: error)
            XCTAssertTrue(message.contains("broker_credential_materialization_failed"))
            XCTAssertTrue(message.contains("IAM denied"))
            XCTAssertFalse(message.contains("private-token"))
            XCTAssertFalse(message.contains("mithran-sandbox/secrets"))
        }

        XCTAssertThrowsError(try store.readSecret(for: "../private-token", reason: "test")) { error in
            XCTAssertTrue(String(describing: error).contains("broker_auth_lease_denied"))
        }
    }

    func testLinuxMAPGCPStoreRawSecretCRUDIsUnavailable() throws {
        let store = LinuxMAPGCPSecretStore(
            projectID: "mithran-sandbox",
            mapAccount: "developer@mithran.ai",
            executor: MockLinuxMAPGCPCommandExecutor { _, _, _ in
                XCTFail("raw CRUD should not call gcloud")
                return LinuxMAPGCPCommandResult(stdout: Data(), stderr: Data(), exitCode: 0)
            }
        )

        XCTAssertThrowsError(try store.setSecret(Data("value".utf8), for: "github-token")) { error in
            XCTAssertTrue(String(describing: error).contains("raw_secret_crud_unavailable"))
        }
        XCTAssertThrowsError(try store.listSecrets()) { error in
            XCTAssertTrue(String(describing: error).contains("raw_secret_crud_unavailable"))
        }
        XCTAssertThrowsError(try store.deleteSecret(for: "github-token")) { error in
            XCTAssertTrue(String(describing: error).contains("raw_secret_crud_unavailable"))
        }
    }

    func testLinuxMAPGCPStoreFeedsBrokerCLIProfileWithoutLeakingCredential() async throws {
        let tempDirectory = try temporaryDirectory()
        let executableURL = try makeExecutable(named: "gcloud", in: tempDirectory, contents: "#!/bin/zsh\nexit 0\n")
        let profile = RemoteAuthorityCLIProfileDescriptor(
            profileID: "gcloud.run.deploy.sandbox",
            tool: "gcloud",
            argvTemplate: [
                "run", "deploy", "{{service}}",
                "--image", "{{image}}",
                "--region", "{{region}}",
                "--project", "{{project}}",
                "--quiet",
            ],
            allowedCWDPrefixes: [tempDirectory.path],
            grantClass: "cloud_deploy_mutation",
            credentialClass: "gcp_access_token",
            credentialEnvironmentVariable: "CLOUDSDK_AUTH_ACCESS_TOKEN",
            networkPolicyRef: "network-policy://d79/gcloud-run-deploy"
        )
        let store = LinuxMAPGCPSecretStore(
            projectID: "mithran-sandbox",
            mapAccount: "developer@mithran.ai",
            executor: MockLinuxMAPGCPCommandExecutor { _, arguments, _ in
                XCTAssertEqual(arguments, [
                    "secrets", "versions", "access", "latest",
                    "--project", "mithran-sandbox",
                    "--secret", "gcp-run-token",
                ])
                return LinuxMAPGCPCommandResult(
                    stdout: Data("secret-token-123".utf8),
                    stderr: Data(),
                    exitCode: 0
                )
            }
        )
        let runner = RemoteAuthorityCLIProfileRunner(
            catalog: RemoteAuthorityCLIProfileCatalog(profiles: [profile]),
            leaseProvider: SecretStoreCLIProfileLeaseProvider(secretStore: store),
            commandStore: CommandStore(
                fileURL: tempDirectory.appendingPathComponent("commands.json"),
                environment: ["PATH": tempDirectory.path]
            ),
            executor: MockCommandExecutor { request in
                XCTAssertEqual(request.executableURL.path, executableURL.path)
                XCTAssertEqual(request.environment["CLOUDSDK_AUTH_ACCESS_TOKEN"], "secret-token-123")
                return RawCommandExecutionResult(
                    stdout: Data("deployed\n".utf8),
                    stderr: Data(),
                    exitCode: 0
                )
            },
            environment: ["PATH": tempDirectory.path],
            brunoEvaluator: nil,
            now: { Date(timeIntervalSince1970: 1_000_000) }
        )

        let result = try await runner.run(RemoteAuthorityCLIProfileRequest(
            profileID: "gcloud.run.deploy.sandbox",
            parameters: [
                "service": "aegis-smoke",
                "image": "us-docker.pkg.dev/mithran/aegis/smoke:1",
                "region": "us-central1",
                "project": "mithran-sandbox",
            ],
            cwd: tempDirectory.path,
            authLeaseRef: "auth-lease://gcp/run/deploy",
            grantRef: "auth-grant://cloud_deploy_mutation/sandbox",
            credentialRef: "\(secretEnvironmentReferencePrefix)gcp-run-token",
            requester: "Codex"
        ))
        let encoded = String(decoding: try JSONEncoder().encode(result), as: UTF8.self)

        XCTAssertEqual(result.status, "ok")
        XCTAssertEqual(result.evidence.result, "allowed")
        XCTAssertEqual(result.evidence.redactionState, "metadata_only_sha256")
        XCTAssertFalse(result.evidence.rawCredentialMaterialPrinted)
        XCTAssertFalse(encoded.contains("secret-token-123"))
        XCTAssertFalse(encoded.contains("gcp-run-token"))
        XCTAssertEqual(RemoteAuthorityCLIProfileCatalog().profiles.map(\.profileID), ["gcloud.run.deploy.sandbox"])
        XCTAssertTrue(try CommandStore(fileURL: tempDirectory.appendingPathComponent("commands.json")).listCommands().contains { $0.name == "gcloud" })
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

    func testRecoveryDiagnoseParsesSourceApp() throws {
        XCTAssertEqual(
            try CommandParser().parse([
                "recovery", "diagnose",
                "--source-app", "/tmp/Aegis Secret.app/Contents/MacOS/aegis-secret"
            ], stdinIsTTY: true),
            .recovery(.diagnose(sourceApp: "/tmp/Aegis Secret.app/Contents/MacOS/aegis-secret"))
        )
    }

    func testRecoveryMigrateParsesAllAndOverwrite() throws {
        XCTAssertEqual(
            try CommandParser().parse([
                "recovery", "migrate",
                "--source-app", "/tmp/aegis-secret",
                "--all",
                "--overwrite"
            ], stdinIsTTY: true),
            .recovery(.migrate(sourceApp: "/tmp/aegis-secret", selection: .allMissing, overwrite: true))
        )
    }

    func testRecoveryMigrateParsesSingleKey() throws {
        XCTAssertEqual(
            try CommandParser().parse([
                "recovery", "migrate",
                "--source-app", "/tmp/aegis-secret",
                "--key", "OPENAI_API_KEY"
            ], stdinIsTTY: true),
            .recovery(.migrate(sourceApp: "/tmp/aegis-secret", selection: .key("OPENAI_API_KEY"), overwrite: false))
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

        let terraform = try store.resolvedCommand(named: "terraform")
        XCTAssertTrue(terraform.brokerRequiredPrefixes.contains(["apply"]))
        XCTAssertTrue(terraform.brokerRequiredPrefixes.contains(["destroy"]))
        XCTAssertFalse(terraform.denyPrefixes.contains(["apply"]))

        let gcloud = try store.resolvedCommand(named: "gcloud")
        XCTAssertTrue(gcloud.brokerRequiredPrefixes.contains(["run", "deploy"]))
        XCTAssertTrue(gcloud.denyPrefixes.contains(["auth"]))
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

    func testRunnerAllowsBrokerRequiredTerraformMutationThroughMCP() async throws {
        let tempDirectory = try temporaryDirectory()
        let executablePath = try makeExecutable(named: "terraform", in: tempDirectory, contents: "#!/bin/zsh\nexit 0\n")
        let systemFile = tempDirectory.appendingPathComponent("system-commands.json")
        let commandFile = tempDirectory.appendingPathComponent("commands.json")
        try prettyJSON(CommandFile(commands: [])).write(to: systemFile)
        try prettyJSON(
            CommandFile(commands: [
                WrappedCommandConfig(
                    name: "terraform",
                    command: executablePath.path,
                    brokerRequiredPrefixes: [["apply"]]
                )
            ])
        ).write(to: commandFile)

        let runner = WrappedCommandRunner(
            commandStore: CommandStore(
                fileURL: commandFile,
                environment: [systemCommandsFileEnvironmentKey: systemFile.path]
            ),
            authenticator: AuthRecorder(),
            approvalCache: ApprovalCache(leaseFileURL: nil),
            executor: MockCommandExecutor { request in
                XCTAssertEqual(request.arguments, ["apply", "-auto-approve"])
                return RawCommandExecutionResult(
                    stdout: Data("apply complete\n".utf8),
                    stderr: Data(),
                    exitCode: 0
                )
            }
        )

        let result = try await runner.run(
            name: "terraform",
            args: ["apply", "-auto-approve"],
            requester: "Codex",
            surface: "mcp"
        )

        XCTAssertEqual(result.exitCode, 0)
        XCTAssertEqual(result.stdout, "apply complete\n")
        XCTAssertEqual(result.receipt.decision, "allow")
        XCTAssertEqual(result.receipt.matchedPolicy?.brokerRequiredPrefixes, [["apply"]])
        XCTAssertEqual(result.receipt.redaction.rawSecretMCPCRUDAvailable, false)
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
        XCTAssertEqual(first.receipt.approvalState, .prompted)

        let second = try await runner.run(name: "gh", args: ["api", "/user"], requester: "Claude")
        XCTAssertEqual(second.receipt.approvalState, .cacheHitMemory)
        let reasons = await authenticator.snapshot()
        XCTAssertEqual(reasons.count, 1)
        XCTAssertTrue(reasons[0].contains("wrapped command 'gh'"))
    }

    func testRunnerIncludesToolDecisionReceipt() async throws {
        let tempDirectory = try temporaryDirectory()
        let executablePath = try makeExecutable(named: "gh", in: tempDirectory, contents: "#!/bin/zsh\nexit 0\n")
        let commandFile = tempDirectory.appendingPathComponent("commands.json")
        try prettyJSON(
            CommandFile(commands: [
                WrappedCommandConfig(name: "gh", command: executablePath.path, approvalWindowSeconds: 300)
            ])
        ).write(to: commandFile)

        let runner = WrappedCommandRunner(
            commandStore: CommandStore(fileURL: commandFile),
            authenticator: AuthRecorder(),
            approvalCache: ApprovalCache(leaseFileURL: nil),
            executor: MockCommandExecutor { request in
                XCTAssertEqual(request.arguments, ["api", "/user"])
                return RawCommandExecutionResult(
                    stdout: Data(#"{"login":"olympum"}"#.utf8),
                    stderr: Data("notice\n".utf8),
                    exitCode: 0
                )
            }
        )

        let result = try await runner.run(
            name: "gh",
            args: ["api", "/user"],
            requester: "Codex",
            surface: "mcp"
        )

        XCTAssertEqual(result.receipt.schemaVersion, "aegis.tool_decision_receipt.v1")
        XCTAssertEqual(result.receipt.surface, "mcp")
        XCTAssertEqual(result.receipt.toolName, "run_command")
        XCTAssertEqual(result.receipt.commandName, "gh")
        XCTAssertEqual(result.receipt.argv, [executablePath.path, "api", "/user"])
        XCTAssertEqual(result.receipt.requester, "Codex")
        XCTAssertEqual(result.receipt.decision, "allow")
        XCTAssertEqual(result.receipt.approvalState, .prompted)
        XCTAssertEqual(result.receipt.exitCode, 0)
        XCTAssertEqual(result.receipt.stdoutTruncated, false)
        XCTAssertEqual(result.receipt.stderrTruncated, false)
        XCTAssertEqual(result.receipt.output?.stdoutBytes, 19)
        XCTAssertEqual(result.receipt.output?.stderrBytes, 7)
        XCTAssertTrue(result.receipt.output?.stdoutSHA256.hasPrefix("sha256:") == true)
        XCTAssertEqual(result.receipt.redaction.rawSecretMCPCRUDAvailable, false)
        XCTAssertEqual(result.receipt.matchedPolicy?.commandName, "gh")
        XCTAssertEqual(result.receipt.matchedPolicy?.executablePath, executablePath.path)
        XCTAssertNotNil(result.receipt.matchedPolicy?.policyFingerprint)
    }

    func testReceiptRecorderWritesJSONL() throws {
        let tempDirectory = try temporaryDirectory()
        let receiptURL = tempDirectory.appendingPathComponent("tool-decisions.jsonl")
        let recorder = ToolDecisionReceiptRecorder(fileURL: receiptURL)
        let receipt = ToolDecisionReceipt(
            receiptID: "receipt-1",
            surface: "mcp",
            toolName: "list_commands",
            commandName: nil,
            argv: [],
            cwd: nil,
            requester: "Codex",
            matchedPolicy: nil,
            decision: "allow",
            approvalState: .notRequired,
            startedAt: "2026-05-25T12:00:00Z",
            completedAt: "2026-05-25T12:00:00Z",
            exitCode: nil,
            stdoutTruncated: false,
            stderrTruncated: false,
            output: nil,
            error: nil
        )

        try recorder.record(receipt)
        try recorder.record(receipt)

        let lines = try String(contentsOf: receiptURL, encoding: .utf8)
            .split(separator: "\n")
        XCTAssertEqual(lines.count, 2)
        let decoded = try JSONDecoder().decode(ToolDecisionReceipt.self, from: Data(lines[0].utf8))
        XCTAssertEqual(decoded, receipt)
    }

    func testDeniedRunReceiptCarriesPolicyContext() throws {
        let tempDirectory = try temporaryDirectory()
        let executablePath = try makeExecutable(named: "gh", in: tempDirectory, contents: "#!/bin/zsh\nexit 0\n")
        let commandFile = tempDirectory.appendingPathComponent("commands.json")
        try prettyJSON(
            CommandFile(commands: [
                WrappedCommandConfig(name: "gh", command: executablePath.path, denyPrefixes: [["auth"]])
            ])
        ).write(to: commandFile)

        let runner = WrappedCommandRunner(commandStore: CommandStore(fileURL: commandFile))
        let receipt = runner.deniedReceipt(
            name: "gh",
            args: ["auth", "token"],
            cwd: tempDirectory.path,
            requester: "Codex",
            surface: "mcp",
            error: "The `auth` subcommand is not allowed."
        )

        XCTAssertEqual(receipt.decision, "deny")
        XCTAssertEqual(receipt.approvalState, .deniedByPolicy)
        XCTAssertEqual(receipt.argv, [executablePath.path, "auth", "token"])
        XCTAssertEqual(receipt.cwd, tempDirectory.path)
        XCTAssertEqual(receipt.error, "The `auth` subcommand is not allowed.")
        XCTAssertEqual(receipt.matchedPolicy?.denyPrefixes, [["auth"]])
        XCTAssertNil(receipt.output)
    }

    func testRunnerInjectsReferencedSecretWithoutReceiptLeakage() async throws {
        let tempDirectory = try temporaryDirectory()
        let executablePath = try makeExecutable(named: "gh", in: tempDirectory, contents: "#!/bin/zsh\nexit 0\n")
        let commandFile = tempDirectory.appendingPathComponent("commands.json")
        try prettyJSON(
            CommandFile(commands: [
                WrappedCommandConfig(
                    name: "gh",
                    command: executablePath.path,
                    environment: ["GH_TOKEN": "\(secretEnvironmentReferencePrefix)github-app-token"]
                )
            ])
        ).write(to: commandFile)

        let runner = WrappedCommandRunner(
            commandStore: CommandStore(fileURL: commandFile),
            authenticator: AuthRecorder(),
            approvalCache: ApprovalCache(leaseFileURL: nil),
            executor: MockCommandExecutor { request in
                XCTAssertEqual(request.environment["GH_TOKEN"], "secret-token-123")
                return RawCommandExecutionResult(
                    stdout: Data("token absent\n".utf8),
                    stderr: Data(),
                    exitCode: 0
                )
            },
            secretStore: InMemorySecretStore(secrets: [
                "github-app-token": Data("secret-token-123".utf8)
            ])
        )

        let result = try await runner.run(name: "gh", args: ["api", "/user"], requester: "Codex", surface: "mcp")
        let encodedReceipt = String(decoding: try JSONEncoder().encode(result.receipt), as: UTF8.self)

        XCTAssertEqual(result.stdout, "token absent\n")
        XCTAssertFalse(encodedReceipt.contains("secret-token-123"))
        XCTAssertFalse(encodedReceipt.contains("github-app-token"))
        XCTAssertEqual(result.receipt.redaction.rawSecretMCPCRUDAvailable, false)
    }

    func testRemoteAuthorityGitHubIssueCommentSucceedsWithScopedLeaseAndEvidence() async throws {
        let runner = RemoteAuthorityActionRunner(
            leaseProvider: StubRemoteAuthorityLeaseProvider { request, descriptor in
                XCTAssertEqual(request.actionID, "github.issue.comment")
                XCTAssertEqual(descriptor.grantClass, "github_issue_pr_mutation")
                return RemoteAuthorityLease(
                    authLeaseRef: "auth-lease://github-app/aegis-secret/issues",
                    grantRef: "auth-grant://github_issue_pr_mutation/aegis-secret",
                    token: "secret-token-123"
                )
            },
            githubClient: StubGitHubRemoteAuthorityClient { operation, token in
                XCTAssertEqual(token, "secret-token-123")
                XCTAssertEqual(operation.method, "POST")
                XCTAssertEqual(operation.path, "/repos/mithran-hq/aegis-secret/issues/23/comments")
                XCTAssertEqual(operation.body, .object(["body": .string("Evidence evidence://d79/smoke")]))
                return RemoteAuthorityActionOutput(
                    statusCode: 201,
                    resourceRef: "github://mithran-hq/aegis-secret/issues/23#issuecomment-1",
                    responseSHA256: "sha256:abc123"
                )
            },
            brunoEvaluator: StubBrunoGuardEvaluator { _ in
                XCTFail("issue comments do not require Bruno in the initial catalog")
                return BrunoGuardDecision(decision: "deny")
            },
            now: { Date(timeIntervalSince1970: 1_000_000) }
        )

        let result = try await runner.run(RemoteAuthorityActionRequest(
            actionID: "github.issue.comment",
            payload: remoteIssuePayload(body: "Evidence evidence://d79/smoke"),
            requester: "Codex"
        ))
        let encoded = String(decoding: try JSONEncoder().encode(result), as: UTF8.self)

        XCTAssertEqual(result.status, "ok")
        XCTAssertEqual(result.evidence.schemaVersion, "aegis.broker.remote_authority_evidence.v1")
        XCTAssertEqual(result.evidence.actionID, "github.issue.comment")
        XCTAssertEqual(result.evidence.repoRef, "github://mithran-hq/aegis-secret")
        XCTAssertEqual(result.evidence.resourceScopeRef, "github://mithran-hq/aegis-secret/issues/23")
        XCTAssertEqual(result.evidence.authLeaseRef, "auth-lease://github-app/aegis-secret/issues")
        XCTAssertEqual(result.evidence.result, "allowed")
        XCTAssertEqual(result.evidence.cleanupStatus, "credentials_dropped")
        XCTAssertFalse(result.evidence.rawCredentialMaterialPrinted)
        XCTAssertFalse(encoded.contains("secret-token-123"))
        XCTAssertFalse(encoded.contains("\(secretEnvironmentReferencePrefix)github-app-token"))
    }

    func testRemoteAuthorityGitHubIssueCloseFailsClosedWhenBrunoDenies() async throws {
        let runner = RemoteAuthorityActionRunner(
            leaseProvider: StubRemoteAuthorityLeaseProvider { _, _ in
                XCTFail("lease should not be requested after Bruno denial")
                return RemoteAuthorityLease(authLeaseRef: "auth-lease://unexpected", grantRef: "auth-grant://unexpected", token: "secret-token-123")
            },
            githubClient: StubGitHubRemoteAuthorityClient { _, _ in
                XCTFail("GitHub should not be called after Bruno denial")
                return RemoteAuthorityActionOutput(statusCode: 200, resourceRef: nil, responseSHA256: "sha256:unused")
            },
            brunoEvaluator: StubBrunoGuardEvaluator { event in
                guard case .object(let root) = event,
                      case .object(let action)? = root["action"] else {
                    XCTFail("expected Bruno event")
                    return BrunoGuardDecision(decision: "deny")
                }
                XCTAssertEqual(root["schema_version"], .string("aegis.broker.remote_authority_bruno_event.v1"))
                XCTAssertEqual(action["action_id"], .string("github.issue.close"))
                return BrunoGuardDecision(decision: "deny", recommendedNextPrompt: "Add closure evidence.")
            }
        )

        do {
            _ = try await runner.run(RemoteAuthorityActionRequest(
                actionID: "github.issue.close",
                payload: remoteIssuePayload(body: nil),
                requester: "Codex"
            ))
            XCTFail("expected Bruno denial")
        } catch let error as AegisSecretError {
            XCTAssertTrue(error.description.contains("broker_bruno_denied"))
            XCTAssertTrue(error.description.contains("Add closure evidence."))
        }
    }

    func testRemoteAuthorityActionCatalogDescribesPRMergeEvidenceContract() throws {
        let descriptor = try RemoteAuthorityActionCatalog().descriptor(actionID: "github.pr.merge")

        XCTAssertEqual(descriptor.payloadContract.requiredFields, [
            "repo",
            "auth_lease_ref",
            "grant_ref",
            "credential_ref",
            "pr_number",
            "cwd",
        ])
        XCTAssertTrue(descriptor.payloadContract.optionalFields.contains("expected_head_oid"))
        XCTAssertTrue(descriptor.payloadContract.optionalFields.contains("intended_mutation_summary"))
        XCTAssertEqual(descriptor.payloadContract.retryFields, [
            "evidence_refs",
            "local_verification",
            "adversarial_review",
            "expected_head_oid",
            "intended_mutation_summary",
        ])
        XCTAssertTrue(descriptor.payloadContract.retryGuidance.contains("Do not inspect Bruno"))
    }

    func testRemoteAuthorityGitHubPRMergeDenialExplainsRetryPayload() async throws {
        let runner = RemoteAuthorityActionRunner(
            leaseProvider: StubRemoteAuthorityLeaseProvider { _, _ in
                XCTFail("lease should not be requested after Bruno denial")
                return RemoteAuthorityLease(authLeaseRef: "auth-lease://unexpected", grantRef: "auth-grant://unexpected", token: "secret-token-123")
            },
            githubClient: StubGitHubRemoteAuthorityClient { _, _ in
                XCTFail("GitHub should not be called after Bruno denial")
                return RemoteAuthorityActionOutput(statusCode: 200, resourceRef: nil, responseSHA256: "sha256:unused")
            },
            gitIdentityProvider: StubGitAuthorIdentityProvider { _ in
                GitAuthorIdentity(
                    email: "b@mithran.ai",
                    emailOrigin: "file:/Users/brunofr/.gitconfig-mithran\tb@mithran.ai",
                    remoteOriginURL: "git@github.com:mithran-hq/aegis-secret.git"
                )
            },
            brunoEvaluator: StubBrunoGuardEvaluator { event in
                guard case .object(let root) = event,
                      case .object(let action)? = root["action"],
                      case .array(let evidenceRefs)? = root["evidence_refs"] else {
                    XCTFail("expected Bruno event")
                    return BrunoGuardDecision(decision: "deny")
                }
                XCTAssertEqual(action["action_id"], .string("github.pr.merge"))
                XCTAssertTrue(evidenceRefs.isEmpty)
                return BrunoGuardDecision(
                    decision: "deny",
                    recommendedNextPrompt: "Stop this action, gather the required evidence, and re-run the guard before finalizing or mutating external state."
                )
            }
        )

        do {
            _ = try await runner.run(RemoteAuthorityActionRequest(
                actionID: "github.pr.merge",
                payload: remotePRMergePayload(cwd: "/tmp/aegis-secret", includeEvidence: false),
                requester: "Codex"
            ))
            XCTFail("expected Bruno denial")
        } catch let error as AegisSecretError {
            XCTAssertTrue(error.description.contains("broker_bruno_denied"))
            XCTAssertTrue(error.description.contains("Retry Aegis Broker MCP `run_remote_action`"))
            XCTAssertTrue(error.description.contains("evidence_refs"))
            XCTAssertTrue(error.description.contains("local_verification"))
            XCTAssertTrue(error.description.contains("adversarial_review"))
            XCTAssertTrue(error.description.contains("expected_head_oid"))
            XCTAssertTrue(error.description.contains("intended_mutation_summary"))
            XCTAssertTrue(error.description.contains("Do not inspect Bruno"))
        }
    }

    func testRemoteAuthorityGitHubPRMergeUsesGitConfigAuthorEmailForGraphQL() async throws {
        let runner = RemoteAuthorityActionRunner(
            leaseProvider: StubRemoteAuthorityLeaseProvider { request, descriptor in
                XCTAssertEqual(request.actionID, "github.pr.merge")
                XCTAssertEqual(descriptor.brunoGateRef, "bruno://github.pr.merge.v1")
                return RemoteAuthorityLease(
                    authLeaseRef: "auth-lease://github-app/aegis-secret/prs",
                    grantRef: "auth-grant://github_issue_pr_mutation/aegis-secret",
                    token: "secret-token-123"
                )
            },
            githubClient: StubGitHubRemoteAuthorityClient { operation, token in
                XCTAssertEqual(token, "secret-token-123")
                XCTAssertEqual(operation.method, "POST")
                XCTAssertEqual(operation.path, "/graphql")
                guard case .graphQLPullRequestMerge(let merge) = operation.kind else {
                    XCTFail("expected GraphQL PR merge")
                    return RemoteAuthorityActionOutput(statusCode: 500, resourceRef: nil, responseSHA256: "sha256:unused")
                }
                XCTAssertEqual(merge.repo, "mithran-hq/aegis-secret")
                XCTAssertEqual(merge.pullRequestNumber, 42)
                XCTAssertEqual(merge.mergeMethod, "merge")
                XCTAssertEqual(merge.authorEmail, "b@mithran.ai")
                XCTAssertEqual(merge.expectedHeadOid, "abc123")
                return RemoteAuthorityActionOutput(
                    statusCode: 200,
                    resourceRef: "github://mithran-hq/aegis-secret/pull/42",
                    responseSHA256: "sha256:abc123"
                )
            },
            gitIdentityProvider: StubGitAuthorIdentityProvider { cwd in
                XCTAssertEqual(cwd, "/tmp/aegis-secret")
                return GitAuthorIdentity(
                    email: "b@mithran.ai",
                    emailOrigin: "file:/Users/brunofr/.gitconfig-mithran\tb@mithran.ai",
                    remoteOriginURL: "git@github.com:mithran-hq/aegis-secret.git"
                )
            },
            brunoEvaluator: StubBrunoGuardEvaluator { event in
                guard case .object(let root) = event,
                      case .object(let action)? = root["action"],
                      case .object(let caller)? = root["caller"],
                      case .object(let subjectRefs)? = root["subject_refs"] else {
                    XCTFail("expected Bruno event")
                    return BrunoGuardDecision(decision: "deny")
                }
                XCTAssertEqual(root["schema_version"], .string("aegis.broker.remote_authority_bruno_event.v1"))
                XCTAssertEqual(action["action_id"], .string("github.pr.merge"))
                XCTAssertEqual(action["kind"], .string("github.pr.merge"))
                XCTAssertEqual(action["command"], .string("gh"))
                XCTAssertEqual(action["argv"], .array([
                    .string("gh"),
                    .string("pr"),
                    .string("merge"),
                    .string("42"),
                    .string("--repo"),
                    .string("mithran-hq/aegis-secret"),
                    .string("--merge"),
                ]))
                XCTAssertEqual(action["input_schema_ref"], .string("schema://aegis-broker/github.pr.merge.v1"))
                XCTAssertEqual(action["grant_class"], .string("github_issue_pr_mutation"))
                XCTAssertEqual(action["credential_class"], .string("github_app_installation_token"))
                XCTAssertEqual(caller["agent"], .string("Codex"))
                XCTAssertEqual(caller["session_ref"], .string("agent-session://local/test"))
                XCTAssertEqual(subjectRefs["project"], .string("project://d79"))
                XCTAssertEqual(subjectRefs["repo"], .string("github://mithran-hq/aegis-secret"))
                XCTAssertEqual(subjectRefs["resource"], .string("github://mithran-hq/aegis-secret/pull/42"))
                XCTAssertEqual(root["intended_mutation_summary"], .string("Run github.pr.merge for github://mithran-hq/aegis-secret/pull/42 through Aegis Broker using supplied evidence refs."))
                return BrunoGuardDecision(decision: "allow")
            },
            now: { Date(timeIntervalSince1970: 1_000_000) }
        )

        let result = try await runner.run(RemoteAuthorityActionRequest(
            actionID: "github.pr.merge",
            payload: remotePRMergePayload(cwd: "/tmp/aegis-secret"),
            requester: "Codex"
        ))
        let encoded = String(decoding: try JSONEncoder().encode(result), as: UTF8.self)

        XCTAssertEqual(result.status, "ok")
        XCTAssertEqual(result.evidence.authorIdentity?.emailDomain, "mithran.ai")
        XCTAssertEqual(result.evidence.authorIdentity?.emailOriginKind, "include")
        XCTAssertFalse(encoded.contains("b@mithran.ai"))
        XCTAssertFalse(encoded.contains("secret-token-123"))
    }

    func testRemoteAuthorityGitHubPRMergeRealBrunoEvaluatorReceivesRemoteAuthoritySchema() async throws {
        let tempDirectory = try temporaryDirectory()
        _ = try makeExecutable(named: "bruno", in: tempDirectory, contents: "#!/bin/sh\nexit 0\n")
        let evaluator = ProcessBrunoGuardEvaluator(
            commandStore: CommandStore(
                fileURL: tempDirectory.appendingPathComponent("commands.json"),
                environment: ["PATH": tempDirectory.path]
            ),
            executor: MockCommandExecutor { request in
                XCTAssertEqual(request.arguments.first, "guard")
                guard let fileIndex = request.arguments.firstIndex(of: "--file"),
                      request.arguments.indices.contains(fileIndex + 1) else {
                    XCTFail("expected --file argument")
                    return RawCommandExecutionResult(stdout: Data(), stderr: Data(), exitCode: 2)
                }
                let eventData = try Data(contentsOf: URL(fileURLWithPath: request.arguments[fileIndex + 1]))
                let event = try JSONDecoder().decode(JSONValue.self, from: eventData)
                guard case .object(let root) = event,
                      case .object(let action)? = root["action"] else {
                    XCTFail("expected Bruno event object")
                    return RawCommandExecutionResult(stdout: Data(), stderr: Data(), exitCode: 2)
                }
                XCTAssertEqual(root["schema_version"], .string("aegis.broker.remote_authority_bruno_event.v1"))
                XCTAssertEqual(action["action_id"], .string("github.pr.merge"))
                XCTAssertNotEqual(root["schema_version"], .string("aegis.broker.bruno_event.v1"))
                return RawCommandExecutionResult(
                    stdout: Data("""
                    {"decision":"allow","reasons":[],"required_evidence":[]}
                    """.utf8),
                    stderr: Data(),
                    exitCode: 0
                )
            }
        )
        let runner = RemoteAuthorityActionRunner(
            leaseProvider: StubRemoteAuthorityLeaseProvider { _, _ in
                RemoteAuthorityLease(
                    authLeaseRef: "auth-lease://github-app/aegis-secret/prs",
                    grantRef: "auth-grant://github_issue_pr_mutation/aegis-secret",
                    token: "secret-token-123"
                )
            },
            githubClient: StubGitHubRemoteAuthorityClient { _, _ in
                RemoteAuthorityActionOutput(
                    statusCode: 200,
                    resourceRef: "github://mithran-hq/aegis-secret/pull/42",
                    responseSHA256: "sha256:abc123"
                )
            },
            gitIdentityProvider: StubGitAuthorIdentityProvider { _ in
                GitAuthorIdentity(
                    email: "b@mithran.ai",
                    emailOrigin: "file:/Users/brunofr/.gitconfig-mithran\tb@mithran.ai",
                    remoteOriginURL: "git@github.com:mithran-hq/aegis-secret.git"
                )
            },
            brunoEvaluator: evaluator
        )

        let result = try await runner.run(RemoteAuthorityActionRequest(
            actionID: "github.pr.merge",
            payload: remotePRMergePayload(cwd: "/tmp/aegis-secret"),
            requester: "Codex"
        ))

        XCTAssertEqual(result.status, "ok")
    }

    func testProcessBrunoGuardEvaluatorSurfacesStructuredBrunoError() async throws {
        let tempDirectory = try temporaryDirectory()
        _ = try makeExecutable(named: "bruno", in: tempDirectory, contents: "#!/bin/sh\nexit 0\n")
        let evaluator = ProcessBrunoGuardEvaluator(
            commandStore: CommandStore(
                fileURL: tempDirectory.appendingPathComponent("commands.json"),
                environment: ["PATH": tempDirectory.path]
            ),
            executor: MockCommandExecutor { _ in
                RawCommandExecutionResult(
                    stdout: Data("""
                    {"schema_version":"bruno.error.v1","error_type":"input","target":"guard","message":"broker Bruno event command must be gh","ok":false}
                    """.utf8),
                    stderr: Data(),
                    exitCode: 2
                )
            }
        )

        do {
            _ = try await evaluator.evaluate(event: .object(["schema_version": .string("aegis.broker.bruno_event.v1")]))
            XCTFail("expected structured Bruno error")
        } catch let error as AegisSecretError {
            XCTAssertTrue(error.description.contains("Bruno guard failed"))
            XCTAssertTrue(error.description.contains("broker Bruno event command must be gh"))
            XCTAssertFalse(error.description.contains("malformed output"))
        }
    }

    func testRemoteAuthorityGitHubPRMergeFailsClosedWhenGitEmailMissing() async throws {
        let runner = RemoteAuthorityActionRunner(
            leaseProvider: StubRemoteAuthorityLeaseProvider { _, _ in
                XCTFail("lease should not be requested without git author identity")
                return RemoteAuthorityLease(authLeaseRef: "auth-lease://unexpected", grantRef: "auth-grant://unexpected", token: "secret-token-123")
            },
            githubClient: StubGitHubRemoteAuthorityClient { _, _ in
                XCTFail("GitHub should not be called without git author identity")
                return RemoteAuthorityActionOutput(statusCode: 200, resourceRef: nil, responseSHA256: "sha256:unused")
            },
            gitIdentityProvider: StubGitAuthorIdentityProvider { _ in
                throw AegisSecretError.blocked("broker_policy_denied: PR merge requires `git config user.email` in the checkout.")
            },
            brunoEvaluator: StubBrunoGuardEvaluator { _ in
                XCTFail("Bruno should not be called without git author identity")
                return BrunoGuardDecision(decision: "deny")
            }
        )

        do {
            _ = try await runner.run(RemoteAuthorityActionRequest(
                actionID: "github.pr.merge",
                payload: remotePRMergePayload(cwd: "/tmp/aegis-secret"),
                requester: "Codex"
            ))
            XCTFail("expected missing git email failure")
        } catch let error as AegisSecretError {
            XCTAssertTrue(error.description.contains("git config user.email"))
        }
    }

    func testRemoteAuthorityGitHubPRMergeRejectsWrongEmailDomain() async throws {
        let runner = RemoteAuthorityActionRunner(
            leaseProvider: StubRemoteAuthorityLeaseProvider { _, _ in
                XCTFail("lease should not be requested with wrong author domain")
                return RemoteAuthorityLease(authLeaseRef: "auth-lease://unexpected", grantRef: "auth-grant://unexpected", token: "secret-token-123")
            },
            githubClient: StubGitHubRemoteAuthorityClient { _, _ in
                XCTFail("GitHub should not be called with wrong author domain")
                return RemoteAuthorityActionOutput(statusCode: 200, resourceRef: nil, responseSHA256: "sha256:unused")
            },
            gitIdentityProvider: StubGitAuthorIdentityProvider { _ in
                GitAuthorIdentity(
                    email: "b@getnexar.com",
                    emailOrigin: "file:.git/config\tb@getnexar.com",
                    remoteOriginURL: "git@github.com:mithran-hq/aegis-secret.git"
                )
            },
            brunoEvaluator: nil
        )

        do {
            _ = try await runner.run(RemoteAuthorityActionRequest(
                actionID: "github.pr.merge",
                payload: remotePRMergePayload(cwd: "/tmp/aegis-secret"),
                requester: "Codex"
            ))
            XCTFail("expected author domain failure")
        } catch let error as AegisSecretError {
            XCTAssertTrue(error.description.contains("not allowed"))
        }
    }

    func testRemoteAuthorityFailsClosedWhenLeaseIsDenied() async throws {
        let runner = RemoteAuthorityActionRunner(
            leaseProvider: StubRemoteAuthorityLeaseProvider { _, _ in
                throw AegisSecretError.blocked("broker_auth_lease_denied: grant refused")
            },
            githubClient: StubGitHubRemoteAuthorityClient { _, _ in
                XCTFail("GitHub should not be called without a lease")
                return RemoteAuthorityActionOutput(statusCode: 200, resourceRef: nil, responseSHA256: "sha256:unused")
            },
            brunoEvaluator: nil
        )

        do {
            _ = try await runner.run(RemoteAuthorityActionRequest(
                actionID: "github.issue.comment",
                payload: remoteIssuePayload(body: "hello"),
                requester: "Codex"
            ))
            XCTFail("expected lease failure")
        } catch let error as AegisSecretError {
            XCTAssertTrue(error.description.contains("broker_auth_lease_denied"))
        }
    }

    func testRemoteAuthorityUnsupportedTypedActionFailsClosed() async throws {
        let runner = RemoteAuthorityActionRunner(
            leaseProvider: StubRemoteAuthorityLeaseProvider { _, _ in
                XCTFail("lease should not be requested for unsupported actions")
                return RemoteAuthorityLease(authLeaseRef: "auth-lease://unexpected", grantRef: "auth-grant://unexpected", token: "secret-token-123")
            },
            githubClient: StubGitHubRemoteAuthorityClient { _, _ in
                XCTFail("GitHub should not be called for unsupported actions")
                return RemoteAuthorityActionOutput(statusCode: 200, resourceRef: nil, responseSHA256: "sha256:unused")
            },
            brunoEvaluator: nil
        )

        do {
            _ = try await runner.run(RemoteAuthorityActionRequest(
                actionID: "github.repo.delete",
                payload: remoteIssuePayload(body: nil),
                requester: "Codex"
            ))
            XCTFail("expected unsupported action failure")
        } catch let error as AegisSecretError {
            XCTAssertTrue(error.description.contains("broker_action_unsupported"))
        }
    }

    func testCLIProfileGCloudRunDeploySucceedsWithScopedLeaseAndEvidence() async throws {
        let tempDirectory = try temporaryDirectory()
        let executableURL = try makeExecutable(named: "gcloud", in: tempDirectory, contents: "#!/bin/zsh\nexit 0\n")
        let profile = RemoteAuthorityCLIProfileDescriptor(
            profileID: "gcloud.run.deploy.sandbox",
            tool: "gcloud",
            argvTemplate: [
                "run", "deploy", "{{service}}",
                "--image", "{{image}}",
                "--region", "{{region}}",
                "--project", "{{project}}",
                "--quiet",
            ],
            allowedCWDPrefixes: [tempDirectory.path],
            grantClass: "cloud_deploy_mutation",
            credentialClass: "gcp_access_token",
            credentialEnvironmentVariable: "CLOUDSDK_AUTH_ACCESS_TOKEN",
            networkPolicyRef: "network-policy://d79/gcloud-run-deploy",
            brunoGateRef: "bruno://gcloud.run.deploy.v1"
        )
        let runner = RemoteAuthorityCLIProfileRunner(
            catalog: RemoteAuthorityCLIProfileCatalog(profiles: [profile]),
            leaseProvider: StubCLIProfileLeaseProvider { request, descriptor in
                XCTAssertEqual(request.profileID, "gcloud.run.deploy.sandbox")
                XCTAssertEqual(request.credentialRef, "\(secretEnvironmentReferencePrefix)gcp-run-token")
                XCTAssertEqual(descriptor.grantClass, "cloud_deploy_mutation")
                return RemoteAuthorityLease(
                    authLeaseRef: "auth-lease://gcp/run/deploy",
                    grantRef: "auth-grant://cloud_deploy_mutation/sandbox",
                    token: "secret-token-123"
                )
            },
            commandStore: CommandStore(
                fileURL: tempDirectory.appendingPathComponent("commands.json"),
                environment: ["PATH": tempDirectory.path]
            ),
            executor: MockCommandExecutor { request in
                XCTAssertEqual(request.executableURL.path, executableURL.path)
                XCTAssertEqual(request.currentDirectoryURL?.path, tempDirectory.path)
                XCTAssertEqual(request.environment["CLOUDSDK_AUTH_ACCESS_TOKEN"], "secret-token-123")
                XCTAssertNil(request.environment["UNRELATED_SECRET"])
                XCTAssertTrue(request.environment["HOME"]?.contains("aegis-cli-profile-") == true)
                XCTAssertTrue(request.environment["CLOUDSDK_CONFIG"]?.contains("aegis-cli-profile-") == true)
                XCTAssertEqual(request.arguments, [
                    "run", "deploy", "aegis-smoke",
                    "--image", "us-docker.pkg.dev/mithran/aegis/smoke:1",
                    "--region", "us-central1",
                    "--project", "mithran-sandbox",
                    "--quiet",
                ])
                return RawCommandExecutionResult(
                    stdout: Data("deployed revision\n".utf8),
                    stderr: Data("notice\n".utf8),
                    exitCode: 0
                )
            },
            environment: ["PATH": tempDirectory.path, "UNRELATED_SECRET": "do-not-pass-through"],
            brunoEvaluator: StubBrunoGuardEvaluator { event in
                guard case .object(let root) = event,
                      case .object(let action)? = root["action"] else {
                    XCTFail("expected Bruno CLI profile event")
                    return BrunoGuardDecision(decision: "deny")
                }
                XCTAssertEqual(action["kind"], .string("broker.cli_profile.run"))
                XCTAssertEqual(action["profile_id"], .string("gcloud.run.deploy.sandbox"))
                return BrunoGuardDecision(decision: "allow")
            },
            now: { Date(timeIntervalSince1970: 1_000_000) }
        )

        let result = try await runner.run(RemoteAuthorityCLIProfileRequest(
            profileID: "gcloud.run.deploy.sandbox",
            parameters: [
                "service": "aegis-smoke",
                "image": "us-docker.pkg.dev/mithran/aegis/smoke:1",
                "region": "us-central1",
                "project": "mithran-sandbox",
            ],
            cwd: tempDirectory.path,
            authLeaseRef: "auth-lease://gcp/run/deploy",
            grantRef: "auth-grant://cloud_deploy_mutation/sandbox",
            credentialRef: "\(secretEnvironmentReferencePrefix)gcp-run-token",
            requester: "Codex",
            projectRef: "project://d79",
            resourceScopeRef: "gcp-run://mithran-sandbox/us-central1/aegis-smoke",
            sessionRef: "agent-session://local/test"
        ))
        let encoded = String(decoding: try JSONEncoder().encode(result), as: UTF8.self)

        XCTAssertEqual(result.status, "ok")
        XCTAssertEqual(result.exitCode, 0)
        XCTAssertEqual(result.evidence.schemaVersion, "aegis.broker.remote_authority_evidence.v1")
        XCTAssertEqual(result.evidence.profileID, "gcloud.run.deploy.sandbox")
        XCTAssertEqual(result.evidence.authLeaseRef, "auth-lease://gcp/run/deploy")
        XCTAssertEqual(result.evidence.grantClass, "cloud_deploy_mutation")
        XCTAssertEqual(result.evidence.credentialClass, "gcp_access_token")
        XCTAssertEqual(result.evidence.argvTemplate, ["run", "deploy", "[PARAM]", "--image", "[PARAM]", "--region", "[PARAM]", "--project", "[PARAM]", "--quiet"])
        XCTAssertTrue(result.evidence.argvTemplateDigest.hasPrefix("sha256:"))
        XCTAssertTrue(result.evidence.commandDigest.hasPrefix("sha256:"))
        XCTAssertTrue(result.evidence.brunoDecisionRef.hasPrefix("bruno-decision://gcloud.run.deploy.sandbox/"))
        XCTAssertEqual(result.evidence.executionMode, "broker_job")
        XCTAssertEqual(result.evidence.result, "allowed")
        XCTAssertEqual(result.evidence.cleanupStatus, "credentials_dropped")
        XCTAssertEqual(result.evidence.redactionState, "metadata_only_sha256")
        XCTAssertFalse(result.evidence.rawCredentialMaterialPrinted)
        XCTAssertEqual(result.evidence.output.stdoutBytes, 18)
        XCTAssertFalse(encoded.contains("secret-token-123"))
        XCTAssertFalse(encoded.contains("\(secretEnvironmentReferencePrefix)gcp-run-token"))
        XCTAssertFalse(encoded.contains("CLOUDSDK_AUTH_ACCESS_TOKEN"))
    }

    func testCLIProfileEquivalentWorkerInvocationFailsWithoutCredential() async throws {
        let tempDirectory = try temporaryDirectory()
        let executableURL = try makeExecutable(named: "gcloud", in: tempDirectory, contents: "#!/bin/zsh\nexit 1\n")
        let commandFile = tempDirectory.appendingPathComponent("commands.json")
        try prettyJSON(
            CommandFile(commands: [
                WrappedCommandConfig(name: "gcloud", command: executableURL.path)
            ])
        ).write(to: commandFile)

        let runner = WrappedCommandRunner(
            commandStore: CommandStore(fileURL: commandFile),
            authenticator: AuthRecorder(),
            approvalCache: ApprovalCache(leaseFileURL: nil),
            executor: MockCommandExecutor { request in
                XCTAssertNil(request.environment["CLOUDSDK_AUTH_ACCESS_TOKEN"])
                XCTAssertEqual(request.arguments, [
                    "run", "deploy", "aegis-smoke",
                    "--image", "us-docker.pkg.dev/mithran/aegis/smoke:1",
                    "--region", "us-central1",
                    "--project", "mithran-sandbox",
                    "--quiet",
                ])
                return RawCommandExecutionResult(
                    stdout: Data(),
                    stderr: Data("missing credentials\n".utf8),
                    exitCode: 1
                )
            },
            environment: ["PATH": tempDirectory.path]
        )

        let result = try await runner.run(
            name: "gcloud",
            args: [
                "run", "deploy", "aegis-smoke",
                "--image", "us-docker.pkg.dev/mithran/aegis/smoke:1",
                "--region", "us-central1",
                "--project", "mithran-sandbox",
                "--quiet",
            ],
            requester: "Codex"
        )

        XCTAssertEqual(result.exitCode, 1)
        XCTAssertEqual(result.stderr, "missing credentials\n")
        XCTAssertFalse(String(decoding: try JSONEncoder().encode(result.receipt), as: UTF8.self).contains("secret-token-123"))
    }

    func testCLIProfileUnsupportedProfileFailsClosedBeforeLeaseAndExec() async throws {
        let runner = RemoteAuthorityCLIProfileRunner(
            catalog: RemoteAuthorityCLIProfileCatalog(profiles: []),
            leaseProvider: StubCLIProfileLeaseProvider { _, _ in
                XCTFail("lease should not be requested for unsupported profiles")
                return RemoteAuthorityLease(authLeaseRef: "auth-lease://unexpected", grantRef: "auth-grant://unexpected", token: "secret-token-123")
            },
            executor: MockCommandExecutor { _ in
                XCTFail("executor should not run for unsupported profiles")
                return RawCommandExecutionResult(stdout: Data(), stderr: Data(), exitCode: 0)
            },
            brunoEvaluator: nil
        )

        do {
            _ = try await runner.run(cliProfileRequest(parameters: [:], cwd: nil))
            XCTFail("expected unsupported profile failure")
        } catch let error as AegisSecretError {
            XCTAssertTrue(error.description.contains("broker_cli_profile_unsupported"))
        }
    }

    func testCLIProfileRejectsUnsafeParametersBeforeLeaseAndExec() async throws {
        let tempDirectory = try temporaryDirectory()
        _ = try makeExecutable(named: "gcloud", in: tempDirectory, contents: "#!/bin/zsh\nexit 0\n")
        let runner = RemoteAuthorityCLIProfileRunner(
            leaseProvider: StubCLIProfileLeaseProvider { _, _ in
                XCTFail("lease should not be requested when parameters are unsafe")
                return RemoteAuthorityLease(authLeaseRef: "auth-lease://unexpected", grantRef: "auth-grant://unexpected", token: "secret-token-123")
            },
            commandStore: CommandStore(
                fileURL: tempDirectory.appendingPathComponent("commands.json"),
                environment: ["PATH": tempDirectory.path]
            ),
            executor: MockCommandExecutor { _ in
                XCTFail("executor should not run when parameters are unsafe")
                return RawCommandExecutionResult(stdout: Data(), stderr: Data(), exitCode: 0)
            },
            brunoEvaluator: nil
        )

        do {
            _ = try await runner.run(cliProfileRequest(
                parameters: [
                    "service": "aegis-smoke;rm",
                    "image": "us-docker.pkg.dev/mithran/aegis/smoke:1",
                    "region": "us-central1",
                    "project": "mithran-sandbox",
                ],
                cwd: "/workspace"
            ))
            XCTFail("expected unsafe parameter failure")
        } catch let error as AegisSecretError {
            XCTAssertTrue(error.description.contains("broker_policy_denied"))
            XCTAssertTrue(error.description.contains("unsafe CLI profile parameter"))
        }
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

        let first = try await runner1.run(name: "gh", args: ["api", "/user"], requester: "Claude")
        let second = try await runner2.run(name: "gh", args: ["api", "/user"], requester: "Claude")

        let reasons = await authenticator.snapshot()
        XCTAssertEqual(reasons.count, 1)
        XCTAssertTrue(FileManager.default.fileExists(atPath: leaseFile.path))
        XCTAssertEqual(first.receipt.approvalState, .prompted)
        XCTAssertEqual(second.receipt.approvalState, .cacheHitFile)
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

    func testShellGuardAllowsNonMutatingGhIssueList() async {
        let guarder = ShellBypassGuard(wrappedCommands: [
            ShellGuardWrappedCommand(name: "gh", denyPrefixes: [["auth"]])
        ], brunoEvaluator: StubBrunoGuardEvaluator { _ in
            XCTFail("Bruno should not run for non-mutating gh reads")
            return BrunoGuardDecision(decision: "deny")
        })

        let result = await guarder.evaluate(command: "gh issue list")

        XCTAssertTrue(result.allowed)
    }

    func testShellGuardAllowsProtectedGhHelpInvocations() async {
        let guarder = ShellBypassGuard(wrappedCommands: [
            ShellGuardWrappedCommand(name: "gh", denyPrefixes: [["auth"]])
        ], brunoEvaluator: StubBrunoGuardEvaluator { _ in
            XCTFail("Bruno should not run for help output")
            return BrunoGuardDecision(decision: "deny")
        })

        let issueLongHelp = await guarder.evaluate(command: "gh issue edit --help")
        let issueShortHelp = await guarder.evaluate(command: "gh issue edit -h")
        let prHelp = await guarder.evaluate(command: "gh pr merge --help")
        let apiHelp = await guarder.evaluate(command: "gh api --help")

        XCTAssertTrue(issueLongHelp.allowed)
        XCTAssertTrue(issueShortHelp.allowed)
        XCTAssertTrue(prHelp.allowed)
        XCTAssertTrue(apiHelp.allowed)
    }

    func testShellGuardAllowsAegisRunProtectedGhHelpInvocation() async {
        let guarder = ShellBypassGuard(wrappedCommands: [
            ShellGuardWrappedCommand(name: "gh", denyPrefixes: [["auth"]])
        ], brunoEvaluator: StubBrunoGuardEvaluator { _ in
            XCTFail("Bruno should not run for help output")
            return BrunoGuardDecision(decision: "deny")
        })

        let result = await guarder.evaluate(command: "aegis-secret run gh -- issue edit --help")

        XCTAssertTrue(result.allowed)
    }

    func testShellGuardBlocksBrokerRequiredWrappedCommand() async {
        let result = await ShellBypassGuard(wrappedCommands: [
            ShellGuardWrappedCommand(name: "terraform", brokerRequiredPrefixes: [["apply"]])
        ]).evaluate(command: "/opt/homebrew/bin/terraform apply")

        XCTAssertFalse(result.allowed)
        XCTAssertTrue(result.message.contains("privileged command `terraform`"))
        XCTAssertTrue(result.message.contains("list_commands"))
        XCTAssertTrue(result.message.contains("run_command"))
    }

    func testShellGuardBrokerRequiredMessageDoesNotEchoSecretLikeArguments() async {
        let result = await ShellBypassGuard(wrappedCommands: [
            ShellGuardWrappedCommand(name: "terraform", brokerRequiredPrefixes: [["apply"]])
        ]).evaluate(command: "terraform apply -var password=super-secret-token")

        XCTAssertFalse(result.allowed)
        XCTAssertTrue(result.message.contains("Aegis Broker MCP"))
        XCTAssertFalse(result.message.contains("super-secret-token"))
        XCTAssertFalse(result.message.contains("password="))
    }

    func testShellGuardDeniesNeverAllowedWrappedCommandWithoutBrokerReroute() async {
        let result = await ShellBypassGuard(wrappedCommands: [
            ShellGuardWrappedCommand(name: "gh", denyPrefixes: [["auth"]])
        ]).evaluate(command: "gh auth token")

        XCTAssertFalse(result.allowed)
        XCTAssertTrue(result.message.contains("denied command `gh`"))
        XCTAssertFalse(result.message.contains("then `run_command` for `gh`"))
    }

    func testCodexPreToolUseDenyHookOutputUsesSupportedShape() throws {
        let output = try codexPreToolUseDenyHookOutput(
            reason: "Use Aegis Broker MCP `list_commands`, then `run_command`."
        )
        let root = try jsonDictionary(from: Data(output.utf8))
        let hookSpecificOutput = try XCTUnwrap(root["hookSpecificOutput"] as? [String: Any])

        XCTAssertEqual(hookSpecificOutput["hookEventName"] as? String, "PreToolUse")
        XCTAssertEqual(hookSpecificOutput["permissionDecision"] as? String, "deny")
        XCTAssertEqual(
            hookSpecificOutput["permissionDecisionReason"] as? String,
            "Use Aegis Broker MCP `list_commands`, then `run_command`."
        )
    }

    func testShellGuardAllowsEnvironmentPrefixedGhRead() async {
        let result = await ShellBypassGuard(wrappedCommands: [
            ShellGuardWrappedCommand(name: "gh", denyPrefixes: [["auth"]])
        ]).evaluate(command: "env GH_HOST=github.com gh issue list")

        XCTAssertTrue(result.allowed)
    }

    func testShellGuardAllowsAssignmentPrefixedGhRead() async {
        let result = await ShellBypassGuard(wrappedCommands: [
            ShellGuardWrappedCommand(name: "gh", denyPrefixes: [["auth"]])
        ]).evaluate(command: "FOO=1 gh api /user")

        XCTAssertTrue(result.allowed)
    }

    func testShellGuardAllowsCompoundGhRead() async {
        let result = await ShellBypassGuard(wrappedCommands: [
            ShellGuardWrappedCommand(name: "gh", denyPrefixes: [["auth"]])
        ]).evaluate(command: "git status && gh issue list")

        XCTAssertTrue(result.allowed)
    }

    func testShellGuardAllowsAegisRunGhRead() async {
        let result = await ShellBypassGuard(wrappedCommands: [
            ShellGuardWrappedCommand(name: "gh", denyPrefixes: [["auth"]])
        ]).evaluate(command: "aegis-secret run gh -- issue list")

        XCTAssertTrue(result.allowed)
    }

    func testShellGuardDeniesProtectedGhMutationWhenBrunoDenies() async {
        let guarder = ShellBypassGuard(wrappedCommands: [
            ShellGuardWrappedCommand(name: "gh", denyPrefixes: [["auth"]])
        ], brunoEvaluator: StubBrunoGuardEvaluator { event in
            guard case .object(let root) = event,
                  case .object(let action)? = root["action"],
                  action["kind"] == .string("github.issue.close") else {
                XCTFail("expected protected issue close event")
                return BrunoGuardDecision(decision: "deny")
            }
            return BrunoGuardDecision(
                decision: "deny",
                recommendedNextPrompt: "Stop and add closure evidence."
            )
        })

        let result = await guarder.evaluate(command: "gh issue close 17 --repo mithran-hq/aegis-secret")

        XCTAssertFalse(result.allowed)
        XCTAssertTrue(result.message.contains("Stop and add closure evidence."))
    }

    func testShellGuardExplainsMissingMachineReadableEvidenceRef() async {
        let guarder = ShellBypassGuard(wrappedCommands: [
            ShellGuardWrappedCommand(name: "gh", denyPrefixes: [["auth"]])
        ], brunoEvaluator: StubBrunoGuardEvaluator { _ in
            BrunoGuardDecision(
                decision: "deny",
                recommendedNextPrompt: "Stop and add closure evidence."
            )
        })

        let result = await guarder.evaluate(command: "gh issue close 17 --repo mithran-hq/aegis-secret --comment 'Evidence verified: state valid errors none'")

        XCTAssertFalse(result.allowed)
        XCTAssertTrue(result.message.contains("No machine-readable evidence reference"))
        XCTAssertTrue(result.message.contains("artifact://"))
        XCTAssertTrue(result.message.contains("evidence://"))
    }

    func testShellGuardDoesNotAddEvidenceRefHintWhenRefIsPresent() async {
        let guarder = ShellBypassGuard(wrappedCommands: [
            ShellGuardWrappedCommand(name: "gh", denyPrefixes: [["auth"]])
        ], brunoEvaluator: StubBrunoGuardEvaluator { _ in
            BrunoGuardDecision(
                decision: "deny",
                recommendedNextPrompt: "Stop and add closure evidence."
            )
        })

        let result = await guarder.evaluate(command: "gh issue close 17 --repo mithran-hq/aegis-secret --comment 'Evidence: evidence://local/aegis/evidence-verify'")

        XCTAssertFalse(result.allowed)
        XCTAssertFalse(result.message.contains("No machine-readable evidence reference"))
    }

    func testShellGuardAllowsProtectedGhMutationWhenBrunoAllows() async {
        let guarder = ShellBypassGuard(wrappedCommands: [
            ShellGuardWrappedCommand(name: "gh", denyPrefixes: [["auth"]])
        ], brunoEvaluator: StubBrunoGuardEvaluator { event in
            guard case .object(let root) = event,
                  case .array(let evidenceRefs)? = root["evidence_refs"],
                  case .object(let action)? = root["action"],
                  case .array(let argv)? = action["argv"] else {
                XCTFail("expected Bruno event with action argv and evidence refs")
                return BrunoGuardDecision(decision: "deny")
            }
            XCTAssertFalse(evidenceRefs.isEmpty)
            XCTAssertTrue(argv.contains(.string("[REDACTED]")))
            return BrunoGuardDecision(decision: "allow")
        })

        let result = await guarder.evaluate(command: "gh issue close 17 --repo mithran-hq/aegis-secret --comment 'Evidence artifact://local/smoke'")

        XCTAssertTrue(result.allowed)
    }

    func testShellGuardRoutesMutatingGhAPIThroughBruno() async {
        let guarder = ShellBypassGuard(wrappedCommands: [
            ShellGuardWrappedCommand(name: "gh", denyPrefixes: [["auth"]])
        ], brunoEvaluator: StubBrunoGuardEvaluator { event in
            guard case .object(let root) = event,
                  case .object(let action)? = root["action"],
                  case .object(let subjectRefs)? = root["subject_refs"] else {
                XCTFail("expected protected gh api event")
                return BrunoGuardDecision(decision: "deny")
            }
            XCTAssertEqual(action["kind"], .string("github.issue.edit"))
            XCTAssertEqual(subjectRefs["repo"], .string("github://mithran-hq/aegis-secret"))
            XCTAssertEqual(subjectRefs["issue"], .string("github://mithran-hq/aegis-secret/issues/123"))
            return BrunoGuardDecision(decision: "deny", recommendedNextPrompt: "Use typed Broker action.")
        })

        let result = await guarder.evaluate(command: "gh api -X PATCH repos/mithran-hq/aegis-secret/issues/123 -f title=x")

        XCTAssertFalse(result.allowed)
        XCTAssertTrue(result.message.contains("Use typed Broker action."))
    }

    func testShellGuardRoutesImplicitPostGhAPIThroughBruno() async {
        let guarder = ShellBypassGuard(wrappedCommands: [
            ShellGuardWrappedCommand(name: "gh", denyPrefixes: [["auth"]])
        ], brunoEvaluator: StubBrunoGuardEvaluator { event in
            guard case .object(let root) = event,
                  case .object(let action)? = root["action"] else {
                XCTFail("expected protected gh api event")
                return BrunoGuardDecision(decision: "deny")
            }
            XCTAssertEqual(action["kind"], .string("github.issue.edit"))
            return BrunoGuardDecision(decision: "deny", recommendedNextPrompt: "Use typed Broker action.")
        })

        let result = await guarder.evaluate(command: "gh api repos/mithran-hq/aegis-secret/issues/123/comments -f body=x")

        XCTAssertFalse(result.allowed)
        XCTAssertTrue(result.message.contains("Use typed Broker action."))
    }

    func testShellGuardAllowsExplicitGetGhAPIWithFields() async {
        let guarder = ShellBypassGuard(wrappedCommands: [
            ShellGuardWrappedCommand(name: "gh", denyPrefixes: [["auth"]])
        ], brunoEvaluator: StubBrunoGuardEvaluator { _ in
            XCTFail("Bruno should not run for explicit GET")
            return BrunoGuardDecision(decision: "deny")
        })

        let result = await guarder.evaluate(command: "gh api -X GET repos/mithran-hq/aegis-secret/issues/123 -f per_page=1")

        XCTAssertTrue(result.allowed)
    }

    func testShellGuardBlocksGenericMutatingGhAPIWithoutRouteAround() async {
        let guarder = ShellBypassGuard(wrappedCommands: [
            ShellGuardWrappedCommand(name: "gh", denyPrefixes: [["auth"]])
        ], brunoEvaluator: StubBrunoGuardEvaluator { _ in
            XCTFail("generic gh api mutations should block before Bruno")
            return BrunoGuardDecision(decision: "allow")
        })

        let result = await guarder.evaluate(command: "gh api -X DELETE repos/mithran-hq/aegis-secret/git/refs/heads/tmp")

        XCTAssertFalse(result.allowed)
        XCTAssertTrue(result.message.contains("Blocked mutating GitHub API call"))
    }

    func testShellGuardBlocksDirectGhPRMergeThroughBrokerRemoteAction() async {
        let result = await ShellBypassGuard(wrappedCommands: [
            ShellGuardWrappedCommand(name: "gh", denyPrefixes: [["auth"]])
        ], brunoEvaluator: StubBrunoGuardEvaluator { _ in
            XCTFail("direct PR merge should reroute before Bruno")
            return BrunoGuardDecision(decision: "allow")
        }).evaluate(command: "gh pr merge 42 --repo mithran-hq/aegis-secret")

        XCTAssertFalse(result.allowed)
        XCTAssertTrue(result.message.contains("run_remote_action"))
        XCTAssertTrue(result.message.contains("git config user.email"))
    }

    func testShellGuardFailsClosedWhenBrunoTimesOut() async {
        let guarder = ShellBypassGuard(wrappedCommands: [
            ShellGuardWrappedCommand(name: "gh")
        ], brunoEvaluator: StubBrunoGuardEvaluator { _ in
            throw AegisSecretError.runtime("Bruno guard timed out after 5 seconds.")
        })

        let result = await guarder.evaluate(command: "gh issue close 17 --repo mithran-hq/aegis-secret")

        XCTAssertFalse(result.allowed)
        XCTAssertTrue(result.message.contains("failed closed"))
        XCTAssertTrue(result.message.contains("timed out"))
    }

    func testShellGuardFailsClosedWhenBrunoOutputIsMalformed() async {
        let guarder = ShellBypassGuard(wrappedCommands: [
            ShellGuardWrappedCommand(name: "gh")
        ], brunoEvaluator: StubBrunoGuardEvaluator { _ in
            throw AegisSecretError.runtime("Bruno guard returned malformed output.")
        })

        let result = await guarder.evaluate(command: "gh issue close 17 --repo mithran-hq/aegis-secret")

        XCTAssertFalse(result.allowed)
        XCTAssertTrue(result.message.contains("malformed output"))
    }

    func testShellGuardBlocksTerraformApplyThroughBrokerMCP() async {
        let result = await ShellBypassGuard(wrappedCommands: [
            ShellGuardWrappedCommand(name: "terraform", brokerRequiredPrefixes: [["apply"]])
        ]).evaluate(command: "terraform apply")

        XCTAssertFalse(result.allowed)
        XCTAssertTrue(result.message.contains("Aegis Broker MCP"))
    }

    func testShellGuardAllowsUnrelatedCommand() async {
        let result = await ShellBypassGuard(wrappedCommandNames: ["gh"]).evaluate(command: "git status --short")

        XCTAssertTrue(result.allowed)
    }

    func testShellGuardAllowsQuotedMentionOfWrappedCommand() async {
        let result = await ShellBypassGuard(wrappedCommandNames: ["gh"]).evaluate(command: "printf 'gh issue list'")

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

    func testRecoveryPlannerMigratesOnlyMissingByDefault() throws {
        let plan = try KeychainRecoveryPlanner().plan(
            sourceKeys: ["GITHUB_TOKEN", "OPENAI_API_KEY", "VOYAGE_API_KEY"],
            targetKeys: ["GITHUB_TOKEN"],
            selection: .allMissing,
            overwrite: false
        )

        XCTAssertEqual(plan.keysToMigrate, ["OPENAI_API_KEY", "VOYAGE_API_KEY"])
        XCTAssertEqual(plan.skippedAlreadyPresent, ["GITHUB_TOKEN"])
    }

    func testRecoveryPlannerOverwriteMigratesAllSourceKeys() throws {
        let plan = try KeychainRecoveryPlanner().plan(
            sourceKeys: ["GITHUB_TOKEN", "OPENAI_API_KEY"],
            targetKeys: ["GITHUB_TOKEN"],
            selection: .allMissing,
            overwrite: true
        )

        XCTAssertEqual(plan.keysToMigrate, ["GITHUB_TOKEN", "OPENAI_API_KEY"])
        XCTAssertEqual(plan.skippedAlreadyPresent, [])
    }

    func testRecoveryPlannerSkipsExistingSelectedKeyUnlessOverwrite() throws {
        let plan = try KeychainRecoveryPlanner().plan(
            sourceKeys: ["OPENAI_API_KEY"],
            targetKeys: ["OPENAI_API_KEY"],
            selection: .key("OPENAI_API_KEY"),
            overwrite: false
        )

        XCTAssertEqual(plan.keysToMigrate, [])
        XCTAssertEqual(plan.skippedAlreadyPresent, ["OPENAI_API_KEY"])
    }

    func testRecoveryRendererDoesNotIncludeSecretValues() {
        let source = KeychainRecoveryAppSnapshot(
            identity: SignedAegisAppIdentity(
                executablePath: "/old/aegis-secret",
                teamIdentifier: "TEAM123456",
                applicationIdentifier: "OLDPREFIX.com.olympum.aegis-secret",
                keychainAccessGroups: ["OLDPREFIX.com.olympum.aegis-secret"]
            ),
            keys: ["GITHUB_TOKEN", "OPENAI_API_KEY"]
        )
        let target = KeychainRecoveryAppSnapshot(
            identity: SignedAegisAppIdentity(
                executablePath: "/new/aegis-secret",
                teamIdentifier: "TEAM123456",
                applicationIdentifier: "TEAM123456.com.olympum.aegis-secret",
                keychainAccessGroups: ["TEAM123456.com.olympum.aegis-secret"]
            ),
            keys: ["GITHUB_TOKEN"]
        )

        let rendered = KeychainRecoveryRenderer().render(
            diagnosis: KeychainRecoveryDiagnosis(source: source, target: target)
        )

        XCTAssertTrue(rendered.contains("Missing from target: 1"))
        XCTAssertTrue(rendered.contains("OPENAI_API_KEY"))
        XCTAssertTrue(rendered.contains("No secret values were read"))
        XCTAssertFalse(rendered.contains("sk-proj"))
        XCTAssertFalse(rendered.contains("ghp_"))
    }

    func testUserInstallerOverwritesExistingLocalBinaryWithShim() throws {
        let tempDirectory = try temporaryDirectory()
        let homeDirectory = tempDirectory.appendingPathComponent("home", isDirectory: true)
        let appDirectory = tempDirectory.appendingPathComponent("Aegis Secret.app", isDirectory: true)
        let macOSDirectory = appDirectory
            .appendingPathComponent("Contents", isDirectory: true)
            .appendingPathComponent("MacOS", isDirectory: true)
        try FileManager.default.createDirectory(at: macOSDirectory, withIntermediateDirectories: true)
        let executableURL = try makeExecutable(
            named: "aegis-secret",
            in: macOSDirectory,
            contents: "#!/bin/zsh\nexit 0\n"
        )

        let binDirectory = homeDirectory.appendingPathComponent(".local/bin", isDirectory: true)
        try FileManager.default.createDirectory(at: binDirectory, withIntermediateDirectories: true)
        let existingBinaryURL = binDirectory.appendingPathComponent("aegis-secret", isDirectory: false)
        try Data([0xCA, 0xFE, 0xBA, 0xBE]).write(to: existingBinaryURL)

        let commandStore = CommandStore(
            fileURL: homeDirectory
                .appendingPathComponent(".config", isDirectory: true)
                .appendingPathComponent("aegis-secret", isDirectory: true)
                .appendingPathComponent("commands.local.json", isDirectory: false),
            environment: ["HOME": homeDirectory.path, "PATH": ""]
        )
        let summary = try UserInstaller(
            currentExecutablePath: executableURL.path,
            environment: ["HOME": homeDirectory.path, "PATH": ""],
            commandStore: commandStore,
            homeDirectory: homeDirectory
        ).install()

        let installedShim = try String(contentsOf: existingBinaryURL, encoding: .utf8)
        XCTAssertEqual(summary.appBundleURL.path, appDirectory.path)
        XCTAssertTrue(installedShim.hasPrefix("#!/bin/zsh\n"))
        XCTAssertTrue(installedShim.contains("exec '\(executableURL.path)' \"$@\""))
        XCTAssertEqual(
            try String(contentsOf: binDirectory.appendingPathComponent("aegis-broker"), encoding: .utf8),
            installedShim
        )
        XCTAssertTrue(FileManager.default.isExecutableFile(atPath: existingBinaryURL.path))
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

    private func remoteIssuePayload(body: String?) -> JSONValue {
        var payload: [String: JSONValue] = [
            "repo": .string("mithran-hq/aegis-secret"),
            "issue_number": .integer(23),
            "project_ref": .string("project://d79"),
            "session_ref": .string("agent-session://local/test"),
            "auth_lease_ref": .string("auth-lease://github-app/aegis-secret/issues"),
            "grant_ref": .string("auth-grant://github_issue_pr_mutation/aegis-secret"),
            "credential_ref": .string("\(secretEnvironmentReferencePrefix)github-app-token"),
            "evidence_refs": .array([
                .object([
                    "ref": .string("evidence://d79/smoke"),
                    "redaction_state": .string("metadata_only"),
                ])
            ]),
        ]
        if let body {
            payload["body"] = .string(body)
        }
        return .object(payload)
    }

    private func remotePRMergePayload(cwd: String, includeEvidence: Bool = true) -> JSONValue {
        var payload: [String: JSONValue] = [
            "repo": .string("mithran-hq/aegis-secret"),
            "pr_number": .integer(42),
            "merge_method": .string("merge"),
            "expected_head_oid": .string("abc123"),
            "cwd": .string(cwd),
            "project_ref": .string("project://d79"),
            "session_ref": .string("agent-session://local/test"),
            "auth_lease_ref": .string("auth-lease://github-app/aegis-secret/prs"),
            "grant_ref": .string("auth-grant://github_issue_pr_mutation/aegis-secret"),
            "credential_ref": .string("\(secretEnvironmentReferencePrefix)github-app-token"),
        ]
        if includeEvidence {
            payload["evidence_refs"] = .array([
                .object([
                    "ref": .string("evidence://d79/pr-merge"),
                    "redaction_state": .string("metadata_only"),
                ])
            ])
        }
        return .object(payload)
    }

    private func cliProfileRequest(parameters: [String: String], cwd: String?) -> RemoteAuthorityCLIProfileRequest {
        RemoteAuthorityCLIProfileRequest(
            profileID: "gcloud.run.deploy.sandbox",
            parameters: parameters,
            cwd: cwd,
            authLeaseRef: "auth-lease://gcp/run/deploy",
            grantRef: "auth-grant://cloud_deploy_mutation/sandbox",
            credentialRef: "\(secretEnvironmentReferencePrefix)gcp-run-token",
            requester: "Codex",
            projectRef: "project://d79",
            resourceScopeRef: "gcp-run://mithran-sandbox/us-central1/aegis-smoke",
            sessionRef: "agent-session://local/test"
        )
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
