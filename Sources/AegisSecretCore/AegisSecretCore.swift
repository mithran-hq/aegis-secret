import Foundation
import CryptoKit
import LocalAuthentication
import Security

public let aegisSecretServiceName = "Aegis Secrets"
public let aegisSecretMetadataServiceName = "Aegis Secrets Metadata"
public let commandsFileEnvironmentKey = "AEGIS_SECRET_COMMANDS_FILE"
public let systemCommandsFileEnvironmentKey = "AEGIS_SECRET_SYSTEM_COMMANDS_FILE"
public let receiptsFileEnvironmentKey = "AEGIS_SECRET_RECEIPTS_FILE"
public let bundledCommandsResourceName = "commands.default"
public let bundledClaudeGuidanceResourceName = "claude.guidance"
public let bundledCodexGuidanceResourceName = "codex.guidance"
public let secretEnvironmentReferencePrefix = "aegis-secret://"

public enum ExitCode: Int32 {
    case success = 0
    case blocked = 2
    case usage = 64
    case failure = 1
}

public enum AegisSecretError: Error, CustomStringConvertible, Equatable {
    case usage(String)
    case runtime(String)
    case blocked(String)

    public var description: String {
        switch self {
        case .usage(let message), .runtime(let message), .blocked(let message):
            return message
        }
    }
}

public protocol DeviceAuthenticator: Sendable {
    func authenticate(reason: String) async throws
}

public final class LocalDeviceAuthenticator: DeviceAuthenticator, @unchecked Sendable {
    public init() {}

    public func authenticate(reason: String) async throws {
        let context = LAContext()
        context.localizedFallbackTitle = ""
        var evaluationError: NSError?

        guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &evaluationError) else {
            let details = evaluationError?.localizedDescription ?? "Unknown authentication error"
            throw AegisSecretError.runtime("Biometric authentication is unavailable: \(details).")
        }

        try await withCheckedThrowingContinuation { continuation in
            context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: reason) { success, error in
                if success {
                    continuation.resume()
                    return
                }

                if let error {
                    continuation.resume(throwing: AegisSecretError.runtime("Authentication failed: \(error.localizedDescription)."))
                } else {
                    continuation.resume(throwing: AegisSecretError.runtime("Authentication was cancelled."))
                }
            }
        }
    }
}

public struct SecretListItem: Equatable, Codable, Sendable {
    public let key: String

    public init(key: String) {
        self.key = key
    }

    public static func merged(_ groups: [SecretListItem]...) -> [SecretListItem] {
        Set(groups.flatMap { $0.map(\.key) })
            .sorted()
            .map(SecretListItem.init(key:))
    }
}

public protocol SecretStore: Sendable {
    func setSecret(_ secretData: Data, for key: String) throws
    func readSecret(for key: String) throws -> Data
    func readSecret(for key: String, reason: String) throws -> Data
    func deleteSecret(for key: String) throws -> Bool
    func listSecrets() throws -> [SecretListItem]
    func secretExists(for key: String) throws -> Bool
}

public extension SecretStore {
    func readSecret(for key: String, reason: String) throws -> Data {
        try readSecret(for: key)
    }
}

public struct KeychainSecretStore: SecretStore {
    public let serviceName: String
    public let metadataServiceName: String

    private enum SecretCopyResult {
        case success(Data)
        case failure(OSStatus)
    }

    public init(
        serviceName: String = aegisSecretServiceName,
        metadataServiceName: String = aegisSecretMetadataServiceName
    ) {
        self.serviceName = serviceName
        self.metadataServiceName = metadataServiceName
    }

    public func setSecret(_ secretData: Data, for key: String) throws {
        for query in [baseQuery(for: key), legacyBaseQuery(for: key)] {
            let deleteStatus = SecItemDelete(query as CFDictionary)
            guard deleteStatus == errSecSuccess || deleteStatus == errSecItemNotFound else {
                throw AegisSecretError.runtime("Unable to replace existing secret `\(key)`: \(message(for: deleteStatus)).")
            }
        }

        var accessControlError: Unmanaged<CFError>?
        guard let accessControl = SecAccessControlCreateWithFlags(
            nil,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            .biometryCurrentSet,
            &accessControlError
        ) else {
            let details = accessControlError?.takeRetainedValue().localizedDescription ?? "Unknown access control error"
            throw AegisSecretError.runtime("Unable to create access control for secret `\(key)`: \(details).")
        }

        var addQuery = baseQuery(for: key)
        addQuery[kSecValueData as String] = secretData
        addQuery[kSecAttrLabel as String] = "Aegis secret: \(key)"
        addQuery[kSecAttrAccessControl as String] = accessControl

        let addStatus = SecItemAdd(addQuery as CFDictionary, nil)
        guard addStatus == errSecSuccess else {
            throw AegisSecretError.runtime(storageErrorMessage(for: key, status: addStatus))
        }

        try upsertMetadata(for: key)
    }

    public func readSecret(for key: String) throws -> Data {
        try readSecret(for: key, reason: "Access the secret named '\(key)'.")
    }

    public func readSecret(for key: String, reason: String) throws -> Data {
        let context = LAContext()
        context.localizedReason = reason
        context.localizedFallbackTitle = ""

        let currentResult = copySecretData(query: baseQuery(for: key), context: context)
        switch currentResult {
        case .success(let data):
            return data
        case .failure(let status) where status == errSecItemNotFound:
            let legacyResult = copySecretData(query: legacyBaseQuery(for: key), context: context)
            switch legacyResult {
            case .success(let data):
                _ = try? upsertMetadata(for: key)
                return data
            case .failure(let legacyStatus) where legacyStatus == errSecItemNotFound:
                throw AegisSecretError.runtime(readErrorMessage(for: key, status: status))
            case .failure(let legacyStatus):
                throw AegisSecretError.runtime(readErrorMessage(for: key, status: legacyStatus))
            }
        case .failure(let status):
            throw AegisSecretError.runtime(readErrorMessage(for: key, status: status))
        }
    }

    private func copySecretData(query: [String: Any], context: LAContext) -> SecretCopyResult {
        var query = query
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        query[kSecUseAuthenticationContext as String] = context

        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        guard status == errSecSuccess else {
            return .failure(status)
        }

        guard let data = item as? Data else {
            return .failure(errSecDecode)
        }

        return .success(data)
    }

    public func deleteSecret(for key: String) throws -> Bool {
        let status = SecItemDelete(baseQuery(for: key) as CFDictionary)
        let legacyStatus = SecItemDelete(legacyBaseQuery(for: key) as CFDictionary)
        let metadataStatus = SecItemDelete(metadataQuery(for: key) as CFDictionary)
        guard metadataStatus == errSecSuccess || metadataStatus == errSecItemNotFound else {
            throw AegisSecretError.runtime("Unable to update secret index for `\(key)`: \(message(for: metadataStatus)).")
        }
        guard legacyStatus == errSecSuccess || legacyStatus == errSecItemNotFound else {
            throw AegisSecretError.runtime("Unable to delete legacy secret `\(key)`: \(message(for: legacyStatus)).")
        }

        switch status {
        case errSecSuccess:
            return true
        case errSecItemNotFound:
            return legacyStatus == errSecSuccess
        default:
            throw AegisSecretError.runtime("Unable to delete secret `\(key)`: \(message(for: status)).")
        }
    }

    public func listSecrets() throws -> [SecretListItem] {
        try SecretListItem.merged(
            listMetadataKeys(),
            listStoredSecretKeys(useDataProtectionKeychain: true),
            listStoredSecretKeys(useDataProtectionKeychain: false)
        )
    }

    public func secretExists(for key: String) throws -> Bool {
        let context = LAContext()
        context.interactionNotAllowed = true

        let currentStatus = copySecretAttributesStatus(query: baseQuery(for: key), context: context)
        switch currentStatus {
        case errSecSuccess, errSecInteractionNotAllowed:
            return true
        case errSecItemNotFound:
            break
        default:
            throw AegisSecretError.runtime("Unable to check secret `\(key)`: \(message(for: currentStatus)).")
        }

        let legacyStatus = copySecretAttributesStatus(query: legacyBaseQuery(for: key), context: context)
        switch legacyStatus {
        case errSecSuccess, errSecInteractionNotAllowed:
            return true
        case errSecItemNotFound:
            return false
        default:
            throw AegisSecretError.runtime("Unable to check legacy secret `\(key)`: \(message(for: legacyStatus)).")
        }
    }

    private func copySecretAttributesStatus(query: [String: Any], context: LAContext) -> OSStatus {
        var query = query
        query[kSecReturnAttributes as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        query[kSecUseAuthenticationContext as String] = context

        var item: CFTypeRef?
        return SecItemCopyMatching(query as CFDictionary, &item)
    }

    private func baseQuery(for key: String) -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: serviceName,
            kSecAttrAccount as String: key,
            kSecUseDataProtectionKeychain as String: true
        ]
    }

    private func legacyBaseQuery(for key: String) -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: serviceName,
            kSecAttrAccount as String: key
        ]
    }

    private func metadataQuery(for key: String) -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: metadataServiceName,
            kSecAttrAccount as String: key,
            kSecUseDataProtectionKeychain as String: true
        ]
    }

    private func upsertMetadata(for key: String) throws {
        let deleteStatus = SecItemDelete(metadataQuery(for: key) as CFDictionary)
        guard deleteStatus == errSecSuccess || deleteStatus == errSecItemNotFound else {
            throw AegisSecretError.runtime("Unable to update secret index for `\(key)`: \(message(for: deleteStatus)).")
        }

        var addQuery = metadataQuery(for: key)
        addQuery[kSecValueData as String] = Data()
        addQuery[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        addQuery[kSecAttrLabel as String] = "Aegis secret metadata: \(key)"

        let status = SecItemAdd(addQuery as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw AegisSecretError.runtime("Unable to update secret index for `\(key)`: \(message(for: status)).")
        }
    }

    private func listMetadataKeys() throws -> [SecretListItem] {
        let context = LAContext()
        context.interactionNotAllowed = true

        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: metadataServiceName,
            kSecReturnAttributes as String: true,
            kSecMatchLimit as String: kSecMatchLimitAll,
            kSecUseAuthenticationContext as String: context,
            kSecUseDataProtectionKeychain as String: true,
        ]

        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        switch status {
        case errSecSuccess:
            guard let dictionaries = item as? [[String: Any]] else {
                throw AegisSecretError.runtime("Keychain returned an unexpected response while listing secrets.")
            }
            return dictionaries.compactMap { dictionary in
                (dictionary[kSecAttrAccount as String] as? String).map(SecretListItem.init(key:))
            }
        case errSecItemNotFound, errSecInteractionNotAllowed:
            return []
        default:
            throw AegisSecretError.runtime("Unable to list secrets: \(message(for: status)).")
        }
    }

    private func listStoredSecretKeys(useDataProtectionKeychain: Bool) throws -> [SecretListItem] {
        let context = LAContext()
        context.interactionNotAllowed = true

        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: serviceName,
            kSecReturnAttributes as String: true,
            kSecMatchLimit as String: kSecMatchLimitAll,
            kSecUseAuthenticationContext as String: context,
        ]
        if useDataProtectionKeychain {
            query[kSecUseDataProtectionKeychain as String] = true
        }

        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        switch status {
        case errSecSuccess:
            guard let dictionaries = item as? [[String: Any]] else {
                throw AegisSecretError.runtime("Keychain returned an unexpected response while listing stored secrets.")
            }
            return dictionaries.compactMap { dictionary in
                (dictionary[kSecAttrAccount as String] as? String).map(SecretListItem.init(key:))
            }
        case errSecItemNotFound, errSecInteractionNotAllowed:
            return []
        default:
            throw AegisSecretError.runtime("Unable to list stored secrets: \(message(for: status)).")
        }
    }

    private func storageErrorMessage(for key: String, status: OSStatus) -> String {
        if status == errSecMissingEntitlement {
            return """
            Unable to store secret `\(key)`: the signed Aegis app/helper is missing the entitlement required for the Data Protection keychain. Build and sign the app bundle with a valid Apple code-signing identity before using biometric-only secrets.
            """
        }
        return "Unable to store secret `\(key)`: \(message(for: status))."
    }

    private func readErrorMessage(for key: String, status: OSStatus) -> String {
        if status == errSecMissingEntitlement {
            return """
            Unable to retrieve secret `\(key)`: the signed Aegis app/helper is missing the entitlement required for the Data Protection keychain. Build and sign the app bundle with a valid Apple code-signing identity before using biometric-only secrets.
            """
        }
        return "Unable to retrieve secret `\(key)`: \(message(for: status))."
    }
}

public struct WrappedCommandConfig: Codable, Equatable, Sendable {
    public let name: String
    public let enabled: Bool?
    public let command: String?
    public let description: String?
    public let approvalWindowSeconds: Int?
    public let timeoutSeconds: Int?
    public let maxOutputBytes: Int?
    public let denyPrefixes: [[String]]?
    public let brokerRequiredPrefixes: [[String]]?
    public let allowPrefixes: [[String]]?
    public let denyFlags: [String]?
    public let environment: [String: String]?

    public init(
        name: String,
        enabled: Bool? = nil,
        command: String? = nil,
        description: String? = nil,
        approvalWindowSeconds: Int? = nil,
        timeoutSeconds: Int? = nil,
        maxOutputBytes: Int? = nil,
        brokerRequiredPrefixes: [[String]]? = nil,
        denyPrefixes: [[String]]? = nil,
        allowPrefixes: [[String]]? = nil,
        denyFlags: [String]? = nil,
        environment: [String: String]? = nil
    ) {
        self.name = name
        self.enabled = enabled
        self.command = command
        self.description = description
        self.approvalWindowSeconds = approvalWindowSeconds
        self.timeoutSeconds = timeoutSeconds
        self.maxOutputBytes = maxOutputBytes
        self.denyPrefixes = denyPrefixes
        self.brokerRequiredPrefixes = brokerRequiredPrefixes
        self.allowPrefixes = allowPrefixes
        self.denyFlags = denyFlags
        self.environment = environment
    }

    private enum CodingKeys: String, CodingKey {
        case name
        case enabled
        case command
        case description
        case approvalWindowSeconds = "approval_window_seconds"
        case timeoutSeconds = "timeout_seconds"
        case maxOutputBytes = "max_output_bytes"
        case denyPrefixes = "deny_prefixes"
        case brokerRequiredPrefixes = "broker_required_prefixes"
        case allowPrefixes = "allow_prefixes"
        case denyFlags = "deny_flags"
        case environment
    }

    public func merged(over base: WrappedCommandConfig?) -> WrappedCommandConfig {
        let mergedEnabled = enabled ?? base?.enabled
        let mergedCommand = command ?? base?.command
        let mergedDescription = description ?? base?.description
        let mergedApprovalWindowSeconds = approvalWindowSeconds ?? base?.approvalWindowSeconds
        let mergedTimeoutSeconds = timeoutSeconds ?? base?.timeoutSeconds
        let mergedMaxOutputBytes = maxOutputBytes ?? base?.maxOutputBytes
        let mergedBrokerRequiredPrefixes = brokerRequiredPrefixes ?? base?.brokerRequiredPrefixes
        let mergedDenyPrefixes = denyPrefixes ?? base?.denyPrefixes
        let mergedAllowPrefixes = allowPrefixes ?? base?.allowPrefixes
        let mergedDenyFlags = denyFlags ?? base?.denyFlags
        let mergedEnvironment = environment ?? base?.environment
        return WrappedCommandConfig(
            name: name,
            enabled: mergedEnabled,
            command: mergedCommand,
            description: mergedDescription,
            approvalWindowSeconds: mergedApprovalWindowSeconds,
            timeoutSeconds: mergedTimeoutSeconds,
            maxOutputBytes: mergedMaxOutputBytes,
            brokerRequiredPrefixes: mergedBrokerRequiredPrefixes,
            denyPrefixes: mergedDenyPrefixes,
            allowPrefixes: mergedAllowPrefixes,
            denyFlags: mergedDenyFlags,
            environment: mergedEnvironment
        )
    }

    public func resolved() throws -> ResolvedWrappedCommand {
        let trimmedName = name.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmedName.isEmpty else {
            throw AegisSecretError.runtime("Wrapped command names cannot be empty.")
        }

        let trimmedCommand = command?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        guard !trimmedCommand.isEmpty else {
            throw AegisSecretError.runtime("Wrapped command `\(trimmedName)` is missing `command`.")
        }

        guard !(denyPrefixes?.isEmpty == false && allowPrefixes?.isEmpty == false) else {
            throw AegisSecretError.runtime("Wrapped command `\(trimmedName)` cannot define both `deny_prefixes` and `allow_prefixes`.")
        }

        let resolvedApprovalWindow = approvalWindowSeconds ?? 300
        guard resolvedApprovalWindow >= 0 else {
            throw AegisSecretError.runtime("Wrapped command `\(trimmedName)` has an invalid `approval_window_seconds`.")
        }

        let resolvedTimeout = timeoutSeconds ?? 30
        guard resolvedTimeout > 0 else {
            throw AegisSecretError.runtime("Wrapped command `\(trimmedName)` has an invalid `timeout_seconds`.")
        }

        let resolvedMaxOutputBytes = maxOutputBytes ?? 256 * 1024
        guard resolvedMaxOutputBytes > 0 else {
            throw AegisSecretError.runtime("Wrapped command `\(trimmedName)` has an invalid `max_output_bytes`.")
        }

        let normalizedDenyPrefixes = try normalizePrefixes(denyPrefixes, name: trimmedName, field: "deny_prefixes")
        let normalizedBrokerRequiredPrefixes = try normalizePrefixes(
            brokerRequiredPrefixes,
            name: trimmedName,
            field: "broker_required_prefixes"
        )
        let normalizedAllowPrefixes = try normalizePrefixes(allowPrefixes, name: trimmedName, field: "allow_prefixes")
        let normalizedFlags = try normalizeFlags(denyFlags, name: trimmedName)
        let normalizedEnvironment = try normalizeEnvironment(environment, name: trimmedName)

        return ResolvedWrappedCommand(
            name: trimmedName,
            command: trimmedCommand,
            description: description?.trimmedNonEmpty,
            approvalWindowSeconds: resolvedApprovalWindow,
            timeoutSeconds: resolvedTimeout,
            maxOutputBytes: resolvedMaxOutputBytes,
            denyPrefixes: normalizedDenyPrefixes,
            brokerRequiredPrefixes: normalizedBrokerRequiredPrefixes,
            allowPrefixes: normalizedAllowPrefixes,
            denyFlags: normalizedFlags,
            environment: normalizedEnvironment
        )
    }

    private func normalizePrefixes(
        _ prefixes: [[String]]?,
        name: String,
        field: String
    ) throws -> [[String]] {
        guard let prefixes else {
            return []
        }

        return try prefixes.map { prefix in
            let normalized = prefix.compactMap { value in
                value.trimmingCharacters(in: .whitespacesAndNewlines).nilIfEmpty
            }
            guard !normalized.isEmpty else {
                throw AegisSecretError.runtime("Wrapped command `\(name)` contains an empty prefix in `\(field)`.")
            }
            return normalized
        }
    }

    private func normalizeFlags(_ flags: [String]?, name: String) throws -> Set<String> {
        let normalized = Set((flags ?? []).compactMap {
            $0.trimmingCharacters(in: .whitespacesAndNewlines).nilIfEmpty
        })
        if normalized.contains(where: { !$0.hasPrefix("-") }) {
            throw AegisSecretError.runtime("Wrapped command `\(name)` has an invalid `deny_flags` entry.")
        }
        return normalized
    }

    private func normalizeEnvironment(_ environment: [String: String]?, name: String) throws -> [String: String] {
        let environment = environment ?? [:]
        for key in environment.keys {
            if key.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                throw AegisSecretError.runtime("Wrapped command `\(name)` has an empty environment variable name.")
            }
        }
        return environment
    }
}

public struct CommandFile: Codable, Equatable, Sendable {
    public let version: Int
    public let commands: [WrappedCommandConfig]

    public init(version: Int = 1, commands: [WrappedCommandConfig]) {
        self.version = version
        self.commands = commands
    }

    public static func defaultTemplate() -> CommandFile {
        CommandFile(
            version: 1,
            commands: [
                WrappedCommandConfig(
                    name: "gh",
                    command: "gh",
                    description: "GitHub CLI",
                    denyPrefixes: [["auth"], ["alias"], ["extension"]],
                    denyFlags: ["--hostname"]
                ),
                WrappedCommandConfig(
                    name: "aws",
                    command: "aws",
                    description: "AWS CLI",
                    brokerRequiredPrefixes: [
                        ["cloudformation", "deploy"],
                        ["cloudformation", "create-stack"],
                        ["cloudformation", "update-stack"],
                        ["cloudformation", "delete-stack"],
                        ["ecs", "update-service"],
                        ["lambda", "update-function-code"],
                        ["s3", "rm"]
                    ],
                    denyPrefixes: [
                        ["configure"],
                        ["sts", "assume-role"],
                        ["sts", "assume-role-with-saml"],
                        ["sts", "assume-role-with-web-identity"],
                        ["sts", "get-session-token"],
                        ["sts", "get-federation-token"],
                        ["ecr", "get-login-password"],
                        ["rds", "generate-db-auth-token"],
                        ["codeartifact", "get-authorization-token"],
                        ["eks", "get-token"]
                    ],
                    denyFlags: ["--debug"]
                ),
                WrappedCommandConfig(
                    name: "gcloud",
                    command: "gcloud",
                    description: "Google Cloud CLI",
                    brokerRequiredPrefixes: [
                        ["run", "deploy"],
                        ["functions", "deploy"],
                        ["app", "deploy"],
                        ["container", "clusters", "create"],
                        ["container", "clusters", "delete"],
                        ["deployment-manager", "deployments", "create"],
                        ["deployment-manager", "deployments", "update"],
                        ["deployment-manager", "deployments", "delete"]
                    ],
                    denyPrefixes: [["auth"], ["config", "config-helper"]],
                    denyFlags: ["--access-token-file"]
                ),
                WrappedCommandConfig(
                    name: "kubectl",
                    command: "kubectl",
                    description: "Kubernetes CLI",
                    brokerRequiredPrefixes: [
                        ["apply"],
                        ["create"],
                        ["delete"],
                        ["patch"],
                        ["replace"],
                        ["edit"],
                        ["exec"],
                        ["cp"],
                        ["port-forward"]
                    ]
                ),
                WrappedCommandConfig(
                    name: "terraform",
                    command: "terraform",
                    description: "Terraform CLI",
                    brokerRequiredPrefixes: [
                        ["apply"],
                        ["destroy"],
                        ["import"],
                        ["login"],
                        ["force-unlock"],
                        ["state"]
                    ]
                ),
                WrappedCommandConfig(
                    name: "az",
                    command: "az",
                    description: "Azure CLI",
                    brokerRequiredPrefixes: [
                        ["deployment", "group", "create"],
                        ["deployment", "sub", "create"],
                        ["deployment", "mg", "create"],
                        ["deployment", "tenant", "create"]
                    ],
                    denyPrefixes: [
                        ["login"],
                        ["account", "set"],
                        ["configure"]
                    ],
                    denyFlags: ["--debug"]
                ),
            ]
        )
    }
}

public struct WrappedCommandSummary: Codable, Equatable, Sendable {
    public let name: String
    public let description: String?
    public let command: String
    public let approvalWindowSeconds: Int
    public let executableResolves: Bool

    public init(name: String, description: String?, command: String, approvalWindowSeconds: Int, executableResolves: Bool) {
        self.name = name
        self.description = description
        self.command = command
        self.approvalWindowSeconds = approvalWindowSeconds
        self.executableResolves = executableResolves
    }
}

public struct ResolvedWrappedCommand: Equatable, Sendable {
    public let name: String
    public let command: String
    public let description: String?
    public let approvalWindowSeconds: Int
    public let timeoutSeconds: Int
    public let maxOutputBytes: Int
    public let denyPrefixes: [[String]]
    public let brokerRequiredPrefixes: [[String]]
    public let allowPrefixes: [[String]]
    public let denyFlags: Set<String>
    public let environment: [String: String]
}

public final class CommandStore: @unchecked Sendable {
    public let fileURL: URL
    public let environment: [String: String]
    public let fileManager: FileManager

    public init(
        fileURL: URL = CommandStore.defaultURL(),
        environment: [String: String] = ProcessInfo.processInfo.environment,
        fileManager: FileManager = .default
    ) {
        self.fileURL = fileURL
        self.environment = environment
        self.fileManager = fileManager
    }

    public static func defaultURL(environment: [String: String] = ProcessInfo.processInfo.environment) -> URL {
        if let override = environment[commandsFileEnvironmentKey]?.trimmedNonEmpty {
            return URL(fileURLWithPath: expandUserPath(override))
        }

        return defaultConfigDirectory()
            .appendingPathComponent("commands.local.json", isDirectory: false)
    }

    public static func defaultSystemURL(environment: [String: String] = ProcessInfo.processInfo.environment) -> URL {
        if let override = environment[systemCommandsFileEnvironmentKey]?.trimmedNonEmpty {
            return URL(fileURLWithPath: expandUserPath(override))
        }

        return defaultConfigDirectory()
            .appendingPathComponent("commands.base.json", isDirectory: false)
    }

    public static func defaultConfigDirectory(environment: [String: String] = ProcessInfo.processInfo.environment) -> URL {
        let homeDirectory: URL
        if let home = environment["HOME"]?.trimmedNonEmpty {
            homeDirectory = URL(fileURLWithPath: expandUserPath(home))
        } else {
            homeDirectory = FileManager.default.homeDirectoryForCurrentUser
        }
        return homeDirectory
            .appendingPathComponent(".config", isDirectory: true)
            .appendingPathComponent("aegis-secret", isDirectory: true)
    }

    public func rawFile(optionalIfMissing: Bool = true) throws -> CommandFile {
        let systemFile = try rawSystemFile()
        let userFile = try rawUserFile(optionalIfMissing: optionalIfMissing)
        return try mergedFile(system: systemFile, user: userFile)
    }

    public func resolvedCommands(optionalIfMissing: Bool = true) throws -> [ResolvedWrappedCommand] {
        let file = try rawFile(optionalIfMissing: optionalIfMissing)
        guard file.version == 1 else {
            throw AegisSecretError.runtime("Unsupported commands file version `\(file.version)`.")
        }

        let resolved = try file.commands.map { try $0.resolved() }
        let names = resolved.map(\.name)
        guard Set(names).count == names.count else {
            throw AegisSecretError.runtime("Commands file contains duplicate wrapped command names.")
        }

        return resolved.sorted { $0.name < $1.name }
    }

    public func listCommands() throws -> [WrappedCommandSummary] {
        try resolvedCommands().map { command in
            WrappedCommandSummary(
                name: command.name,
                description: command.description,
                command: command.command,
                approvalWindowSeconds: command.approvalWindowSeconds,
                executableResolves: resolveExecutable(named: command.command) != nil
            )
        }
    }

    public func rawCommand(named name: String) throws -> WrappedCommandConfig {
        let file = try rawFile(optionalIfMissing: false)
        guard let command = file.commands.first(where: { $0.name == name }) else {
            throw AegisSecretError.runtime("Wrapped command `\(name)` was not found.")
        }
        return command
    }

    public func resolvedCommand(named name: String) throws -> ResolvedWrappedCommand {
        guard let command = try resolvedCommands(optionalIfMissing: false).first(where: { $0.name == name }) else {
            throw AegisSecretError.runtime("Wrapped command `\(name)` was not found.")
        }
        return command
    }

    @discardableResult
    public func importFile(from sourcePath: String) throws -> Int {
        let sourceURL = URL(fileURLWithPath: expandUserPath(sourcePath))
        let data = try Data(contentsOf: sourceURL)
        let file = try JSONDecoder().decode(CommandFile.self, from: data)
        _ = try mergedFile(system: rawSystemFile(), user: file)

        try fileManager.createDirectory(at: fileURL.deletingLastPathComponent(), withIntermediateDirectories: true)
        try data.write(to: fileURL, options: .atomic)
        return file.commands.count
    }

    public func validateCurrentConfiguration() throws -> Int {
        try resolvedCommands(optionalIfMissing: false).count
    }

    public func validateCurrentCommand(named name: String) throws {
        _ = try resolvedCommand(named: name)
    }

    public func validateFile(at path: String) throws -> Int {
        let url = URL(fileURLWithPath: expandUserPath(path))
        let data = try Data(contentsOf: url)
        let file = try JSONDecoder().decode(CommandFile.self, from: data)
        let merged = try mergedFile(system: rawSystemFile(), user: file)
        return merged.commands.count
    }

    public func writeUserOverrideFileIfMissing() throws {
        guard !fileManager.fileExists(atPath: fileURL.path) else {
            return
        }

        try fileManager.createDirectory(at: fileURL.deletingLastPathComponent(), withIntermediateDirectories: true)
        try prettyJSON(CommandFile(version: 1, commands: [])).write(to: fileURL, options: .atomic)
    }

    public func writeManagedSystemFile() throws {
        let systemURL = CommandStore.defaultSystemURL(environment: environment)
        try fileManager.createDirectory(at: systemURL.deletingLastPathComponent(), withIntermediateDirectories: true)

        if let bundledURL = bundledSystemFileURL() {
            let data = try Data(contentsOf: bundledURL)
            _ = try JSONDecoder().decode(CommandFile.self, from: data)
            try data.write(to: systemURL, options: .atomic)
            return
        }

        try prettyJSON(CommandFile.defaultTemplate()).write(to: systemURL, options: .atomic)
    }

    public func resolveExecutable(named executableName: String) -> URL? {
        if executableName.contains("/") {
            let url = URL(fileURLWithPath: expandUserPath(executableName))
            return fileManager.isExecutableFile(atPath: url.path) ? url : nil
        }

        guard let path = environment["PATH"] else {
            return nil
        }

        for component in path.split(separator: ":") {
            let candidate = URL(fileURLWithPath: String(component), isDirectory: true)
                .appendingPathComponent(executableName)
            if fileManager.isExecutableFile(atPath: candidate.path) {
                return candidate
            }
        }
        return nil
    }

    private func rawSystemFile() throws -> CommandFile {
        let systemURL = CommandStore.defaultSystemURL(environment: environment)
        if fileManager.fileExists(atPath: systemURL.path) {
            let data = try Data(contentsOf: systemURL)
            return try JSONDecoder().decode(CommandFile.self, from: data)
        }

        if let bundledURL = bundledSystemFileURL() {
            let data = try Data(contentsOf: bundledURL)
            return try JSONDecoder().decode(CommandFile.self, from: data)
        }

        return CommandFile.defaultTemplate()
    }

    private func rawUserFile(optionalIfMissing: Bool) throws -> CommandFile {
        guard fileManager.fileExists(atPath: fileURL.path) else {
            if optionalIfMissing {
                return CommandFile(version: 1, commands: [])
            }
            return CommandFile(version: 1, commands: [])
        }

        let data = try Data(contentsOf: fileURL)
        return try JSONDecoder().decode(CommandFile.self, from: data)
    }

    private func bundledSystemFileURL() -> URL? {
        Bundle.main.url(forResource: bundledCommandsResourceName, withExtension: "json")
    }

    private func mergedFile(system: CommandFile, user: CommandFile) throws -> CommandFile {
        guard system.version == 1 else {
            throw AegisSecretError.runtime("Unsupported commands file version `\(system.version)`.")
        }
        guard user.version == 1 else {
            throw AegisSecretError.runtime("Unsupported commands file version `\(user.version)`.")
        }

        try validateUniqueNames(system.commands, label: "system commands")
        try validateUniqueNames(user.commands, label: "user commands")

        var mergedByName: [String: WrappedCommandConfig] = [:]
        var orderedNames: [String] = []

        for command in system.commands {
            mergedByName[command.name] = command
            orderedNames.append(command.name)
        }

        for command in user.commands {
            let merged = command.merged(over: mergedByName[command.name])
            if merged.enabled == false {
                mergedByName.removeValue(forKey: command.name)
                orderedNames.removeAll { $0 == command.name }
                continue
            }

            if mergedByName[command.name] == nil {
                orderedNames.append(command.name)
            }
            mergedByName[command.name] = merged
        }

        let mergedCommands = orderedNames.compactMap { mergedByName[$0] }
        _ = try mergedCommands.map { try $0.resolved() }
        return CommandFile(version: 1, commands: mergedCommands)
    }

    private func validateUniqueNames(_ commands: [WrappedCommandConfig], label: String) throws {
        let names = commands.map(\.name)
        if Set(names).count != names.count {
            throw AegisSecretError.runtime("The \(label) contain duplicate wrapped command names.")
        }
    }
}

public struct ApprovalLeaseRecord: Codable, Equatable, Sendable {
    public let agent: String
    public let command: String
    public let executablePath: String
    public let policyFingerprint: String
    public let approvedAt: Date
    public let expiresAt: Date

    public init(
        agent: String,
        command: String,
        executablePath: String,
        policyFingerprint: String,
        approvedAt: Date,
        expiresAt: Date
    ) {
        self.agent = agent
        self.command = command
        self.executablePath = executablePath
        self.policyFingerprint = policyFingerprint
        self.approvedAt = approvedAt
        self.expiresAt = expiresAt
    }

    public var cacheKey: String {
        [agent, command, executablePath, policyFingerprint].joined(separator: "\u{1F}")
    }
}

public struct ApprovalLeaseFile: Codable, Equatable, Sendable {
    public let version: Int
    public var leases: [ApprovalLeaseRecord]

    public init(version: Int = 1, leases: [ApprovalLeaseRecord]) {
        self.version = version
        self.leases = leases
    }
}

public enum ApprovalLeaseMatchReason: String, Sendable {
    case hit
    case missingLease = "missing_lease"
    case expired
    case agentMismatch = "agent_mismatch"
    case policyMismatch = "policy_mismatch"
}

public struct ApprovalLeaseStatus: Equatable, Sendable {
    public let reason: ApprovalLeaseMatchReason
    public let lease: ApprovalLeaseRecord?
    public let command: String?
    public let agent: String?
    public let currentExecutablePath: String?

    public init(
        reason: ApprovalLeaseMatchReason,
        lease: ApprovalLeaseRecord?,
        command: String?,
        agent: String?,
        currentExecutablePath: String?
    ) {
        self.reason = reason
        self.lease = lease
        self.command = command
        self.agent = agent
        self.currentExecutablePath = currentExecutablePath
    }
}

public enum ApprovalAuthorizationOutcome: String, Codable, Equatable, Sendable {
    case cacheHitMemory = "cache_hit_memory"
    case cacheHitFile = "cache_hit_file"
    case prompted
    case notRequired = "not_required"
    case notEvaluated = "not_evaluated"
    case deniedByPolicy = "denied_by_policy"
}

private struct ApprovalLeaseMatch {
    let lease: ApprovalLeaseRecord?
    let reason: ApprovalLeaseMatchReason
    let source: ApprovalAuthorizationOutcome?

    init(
        lease: ApprovalLeaseRecord?,
        reason: ApprovalLeaseMatchReason,
        source: ApprovalAuthorizationOutcome? = nil
    ) {
        self.lease = lease
        self.reason = reason
        self.source = source
    }
}

private struct FingerprintEnvironmentValue: Codable, Comparable {
    let key: String
    let value: String

    static func < (lhs: FingerprintEnvironmentValue, rhs: FingerprintEnvironmentValue) -> Bool {
        lhs.key < rhs.key
    }
}

private struct FingerprintPolicy: Codable {
    let name: String
    let command: String
    let executablePath: String
    let approvalWindowSeconds: Int
    let timeoutSeconds: Int
    let maxOutputBytes: Int
    let denyPrefixes: [[String]]
    let brokerRequiredPrefixes: [[String]]
    let allowPrefixes: [[String]]
    let denyFlags: [String]
    let environment: [FingerprintEnvironmentValue]
}

public func approvalPolicyFingerprint(for command: ResolvedWrappedCommand, executableURL: URL) throws -> String {
    let policy = FingerprintPolicy(
        name: command.name,
        command: command.command,
        executablePath: executableURL.path,
        approvalWindowSeconds: command.approvalWindowSeconds,
        timeoutSeconds: command.timeoutSeconds,
        maxOutputBytes: command.maxOutputBytes,
        denyPrefixes: command.denyPrefixes,
        brokerRequiredPrefixes: command.brokerRequiredPrefixes,
        allowPrefixes: command.allowPrefixes,
        denyFlags: command.denyFlags.sorted(),
        environment: command.environment.map { FingerprintEnvironmentValue(key: $0.key, value: $0.value) }.sorted()
    )
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.sortedKeys]
    let data = try encoder.encode(policy)
    return SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
}

private func sha256Hex(_ data: Data) -> String {
    SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
}

func iso8601String(_ date: Date) -> String {
    ISO8601DateFormatter().string(from: date)
}

public struct ApprovalLeaseInspector {
    public let leaseFileURL: URL
    public let commandStore: CommandStore
    public let fileManager: FileManager
    public let now: Date

    public init(
        leaseFileURL: URL = ApprovalCache.defaultLeaseFileURL(),
        commandStore: CommandStore = CommandStore(),
        fileManager: FileManager = .default,
        now: Date = Date()
    ) {
        self.leaseFileURL = leaseFileURL
        self.commandStore = commandStore
        self.fileManager = fileManager
        self.now = now
    }

    public func statuses(command commandFilter: String?, agent agentFilter: String?) throws -> [ApprovalLeaseStatus] {
        let file = try readLeaseFile()
        var statuses: [ApprovalLeaseStatus] = []
        var sawCommandCandidate = false

        for lease in file.leases {
            if let commandFilter, lease.command != commandFilter {
                continue
            }

            sawCommandCandidate = true

            if let agentFilter, lease.agent != agentFilter {
                statuses.append(ApprovalLeaseStatus(
                    reason: .agentMismatch,
                    lease: lease,
                    command: commandFilter,
                    agent: agentFilter,
                    currentExecutablePath: nil
                ))
                continue
            }

            statuses.append(try status(for: lease, commandFilter: commandFilter, agentFilter: agentFilter))
        }

        if statuses.isEmpty {
            statuses.append(ApprovalLeaseStatus(
                reason: sawCommandCandidate ? .agentMismatch : .missingLease,
                lease: nil,
                command: commandFilter,
                agent: agentFilter,
                currentExecutablePath: nil
            ))
        }

        return statuses
    }

    private func status(
        for lease: ApprovalLeaseRecord,
        commandFilter: String?,
        agentFilter: String?
    ) throws -> ApprovalLeaseStatus {
        if lease.expiresAt <= now {
            return ApprovalLeaseStatus(
                reason: .expired,
                lease: lease,
                command: commandFilter,
                agent: agentFilter,
                currentExecutablePath: nil
            )
        }

        guard let resolvedCommand = try? commandStore.resolvedCommand(named: lease.command),
              let executableURL = commandStore.resolveExecutable(named: resolvedCommand.command) else {
            return ApprovalLeaseStatus(
                reason: .policyMismatch,
                lease: lease,
                command: commandFilter,
                agent: agentFilter,
                currentExecutablePath: nil
            )
        }

        let fingerprint = try approvalPolicyFingerprint(for: resolvedCommand, executableURL: executableURL)
        let reason: ApprovalLeaseMatchReason = (
            lease.executablePath == executableURL.path &&
            lease.policyFingerprint == fingerprint
        ) ? .hit : .policyMismatch

        return ApprovalLeaseStatus(
            reason: reason,
            lease: lease,
            command: commandFilter,
            agent: agentFilter,
            currentExecutablePath: executableURL.path
        )
    }

    private func readLeaseFile() throws -> ApprovalLeaseFile {
        guard fileManager.fileExists(atPath: leaseFileURL.path) else {
            return ApprovalLeaseFile(leases: [])
        }

        let data = try Data(contentsOf: leaseFileURL)
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        let file = try decoder.decode(ApprovalLeaseFile.self, from: data)
        guard file.version == 1 else {
            throw AegisSecretError.runtime("Unsupported approval lease file version `\(file.version)`.")
        }
        return file
    }
}

public actor ApprovalCache {
    private var expirations: [String: Date] = [:]
    private let leaseFileURL: URL?
    private let fileManager: FileManager
    private let now: @Sendable () -> Date

    public init(
        leaseFileURL: URL? = ApprovalCache.defaultLeaseFileURL(),
        fileManager: FileManager = .default,
        now: @escaping @Sendable () -> Date = Date.init
    ) {
        self.leaseFileURL = leaseFileURL
        self.fileManager = fileManager
        self.now = now
    }

    public static func defaultLeaseFileURL(environment: [String: String] = ProcessInfo.processInfo.environment) -> URL {
        CommandStore.defaultConfigDirectory(environment: environment)
            .appendingPathComponent("approval-leases.json", isDirectory: false)
    }

    @discardableResult
    public func authorize(
        agent: String,
        command: ResolvedWrappedCommand,
        executableURL: URL,
        policyFingerprint: String,
        reason: String,
        authenticator: DeviceAuthenticator
    ) async throws -> ApprovalAuthorizationOutcome {
        let currentDate = now()
        let key = ApprovalLeaseRecord(
            agent: agent,
            command: command.name,
            executablePath: executableURL.path,
            policyFingerprint: policyFingerprint,
            approvedAt: currentDate,
            expiresAt: currentDate
        ).cacheKey

        if let expiration = expirations[key], expiration > currentDate {
            debug("approval_cache_hit source=memory command=\(command.name) agent=\(agent)")
            return .cacheHitMemory
        }

        let match = try command.approvalWindowSeconds > 0 ? loadMatchingLease(
            agent: agent,
            command: command,
            executableURL: executableURL,
            policyFingerprint: policyFingerprint,
            now: currentDate
        ) : ApprovalLeaseMatch(lease: nil, reason: .missingLease)
        if let lease = match.lease {
            expirations[key] = lease.expiresAt
            debug("approval_cache_hit source=file command=\(command.name) agent=\(agent)")
            return match.source ?? .cacheHitFile
        }

        debug("approval_cache_miss reason=\(match.reason.rawValue) command=\(command.name) agent=\(agent)")
        try await authenticator.authenticate(reason: reason)

        if command.approvalWindowSeconds > 0 {
            let expiration = currentDate.addingTimeInterval(TimeInterval(command.approvalWindowSeconds))
            expirations[key] = expiration
            try storeLease(ApprovalLeaseRecord(
                agent: agent,
                command: command.name,
                executablePath: executableURL.path,
                policyFingerprint: policyFingerprint,
                approvedAt: currentDate,
                expiresAt: expiration
            ), now: currentDate)
        } else {
            expirations.removeValue(forKey: key)
        }
        return .prompted
    }

    private func loadMatchingLease(
        agent: String,
        command: ResolvedWrappedCommand,
        executableURL: URL,
        policyFingerprint: String,
        now currentDate: Date
    ) throws -> ApprovalLeaseMatch {
        guard let leaseFileURL else {
            return ApprovalLeaseMatch(lease: nil, reason: .missingLease)
        }

        var file = try readLeaseFile(from: leaseFileURL)
        let beforeCount = file.leases.count
        let hadExpiredRelevantLease = file.leases.contains {
            $0.command == command.name &&
            $0.agent == agent &&
            $0.executablePath == executableURL.path &&
            $0.policyFingerprint == policyFingerprint &&
            $0.expiresAt <= currentDate
        }
        file.leases.removeAll { $0.expiresAt <= currentDate }
        if beforeCount != file.leases.count {
            try writeLeaseFile(file, to: leaseFileURL)
        }

        if let lease = file.leases.first(where: {
            $0.agent == agent &&
            $0.command == command.name &&
            $0.executablePath == executableURL.path &&
            $0.policyFingerprint == policyFingerprint &&
            $0.expiresAt > currentDate
        }) {
            return ApprovalLeaseMatch(lease: lease, reason: .hit, source: .cacheHitFile)
        }

        if file.leases.contains(where: { $0.command == command.name && $0.executablePath == executableURL.path && $0.policyFingerprint == policyFingerprint }) {
            return ApprovalLeaseMatch(lease: nil, reason: .agentMismatch)
        }

        if hadExpiredRelevantLease {
            return ApprovalLeaseMatch(lease: nil, reason: .expired)
        }

        if file.leases.contains(where: { $0.agent == agent && $0.command == command.name }) {
            return ApprovalLeaseMatch(lease: nil, reason: .policyMismatch)
        }

        return ApprovalLeaseMatch(lease: nil, reason: .missingLease)
    }

    private func storeLease(_ lease: ApprovalLeaseRecord, now currentDate: Date) throws {
        guard let leaseFileURL else {
            return
        }

        var file = try readLeaseFile(from: leaseFileURL)
        file.leases.removeAll {
            $0.expiresAt <= currentDate || $0.cacheKey == lease.cacheKey
        }
        file.leases.append(lease)
        try writeLeaseFile(file, to: leaseFileURL)
    }

    private func readLeaseFile(from url: URL) throws -> ApprovalLeaseFile {
        guard fileManager.fileExists(atPath: url.path) else {
            return ApprovalLeaseFile(leases: [])
        }

        let data = try Data(contentsOf: url)
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        let file = try decoder.decode(ApprovalLeaseFile.self, from: data)
        guard file.version == 1 else {
            throw AegisSecretError.runtime("Unsupported approval lease file version `\(file.version)`.")
        }
        return file
    }

    private func writeLeaseFile(_ file: ApprovalLeaseFile, to url: URL) throws {
        try fileManager.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        let data = try encoder.encode(file)
        try data.write(to: url, options: .atomic)
    }

    private func debug(_ message: String) {
        guard ProcessInfo.processInfo.environment["AEGIS_SECRET_DEBUG"] == "1" else {
            return
        }
        fputs("[aegis-secret] \(message)\n", stderr)
    }
}

public struct CommandExecutionRequest: Sendable {
    public let executableURL: URL
    public let arguments: [String]
    public let environment: [String: String]
    public let currentDirectoryURL: URL?
    public let timeoutSeconds: Int
    public let maxOutputBytes: Int

    public init(
        executableURL: URL,
        arguments: [String],
        environment: [String: String],
        currentDirectoryURL: URL?,
        timeoutSeconds: Int,
        maxOutputBytes: Int
    ) {
        self.executableURL = executableURL
        self.arguments = arguments
        self.environment = environment
        self.currentDirectoryURL = currentDirectoryURL
        self.timeoutSeconds = timeoutSeconds
        self.maxOutputBytes = maxOutputBytes
    }
}

public struct RawCommandExecutionResult: Sendable {
    public let stdout: Data
    public let stderr: Data
    public let exitCode: Int32

    public init(stdout: Data, stderr: Data, exitCode: Int32) {
        self.stdout = stdout
        self.stderr = stderr
        self.exitCode = exitCode
    }
}

public protocol CommandExecutor: Sendable {
    func execute(_ request: CommandExecutionRequest) async throws -> RawCommandExecutionResult
}

public final class ProcessCommandExecutor: CommandExecutor, @unchecked Sendable {
    public init() {}

    public func execute(_ request: CommandExecutionRequest) async throws -> RawCommandExecutionResult {
        let process = Process()
        process.executableURL = request.executableURL
        process.arguments = request.arguments
        process.environment = request.environment
        process.currentDirectoryURL = request.currentDirectoryURL
        process.standardInput = FileHandle.nullDevice

        let stdoutPipe = Pipe()
        let stderrPipe = Pipe()
        process.standardOutput = stdoutPipe
        process.standardError = stderrPipe

        try process.run()

        let stdoutTask = Task {
            try await readStream(
                from: stdoutPipe.fileHandleForReading,
                maxBytes: request.maxOutputBytes,
                process: process,
                label: "stdout",
                commandName: request.executableURL.lastPathComponent
            )
        }
        let stderrTask = Task {
            try await readStream(
                from: stderrPipe.fileHandleForReading,
                maxBytes: request.maxOutputBytes,
                process: process,
                label: "stderr",
                commandName: request.executableURL.lastPathComponent
            )
        }
        let terminationTask = Task {
            await waitForTermination(process)
        }
        let timeoutTask = Task {
            try await Task.sleep(for: .seconds(request.timeoutSeconds))
            if process.isRunning {
                process.terminate()
            }
            throw AegisSecretError.runtime("Command `\(request.executableURL.lastPathComponent)` timed out after \(request.timeoutSeconds) seconds.")
        }

        let exitCode = await terminationTask.value
        timeoutTask.cancel()

        let stdout = try await stdoutTask.value
        let stderr = try await stderrTask.value
        _ = try? await timeoutTask.value

        return RawCommandExecutionResult(stdout: stdout, stderr: stderr, exitCode: exitCode)
    }

    private func readStream(
        from handle: FileHandle,
        maxBytes: Int,
        process: Process,
        label: String,
        commandName: String
    ) async throws -> Data {
        var data = Data()
        for try await byte in handle.bytes {
            if data.count >= maxBytes {
                if process.isRunning {
                    process.terminate()
                }
                throw AegisSecretError.runtime("Command `\(commandName)` exceeded the \(maxBytes)-byte \(label) limit.")
            }
            data.append(byte)
        }
        return data
    }

    private func waitForTermination(_ process: Process) async -> Int32 {
        while process.isRunning {
            try? await Task.sleep(for: .milliseconds(25))
        }
        return process.terminationStatus
    }
}

public struct ToolDecisionMatchedPolicy: Codable, Equatable, Sendable {
    public let commandName: String
    public let command: String
    public let executablePath: String?
    public let policyFingerprint: String?
    public let approvalWindowSeconds: Int
    public let timeoutSeconds: Int
    public let maxOutputBytes: Int
    public let denyPrefixes: [[String]]
    public let brokerRequiredPrefixes: [[String]]
    public let allowPrefixes: [[String]]
    public let denyFlags: [String]

    public init(
        commandName: String,
        command: String,
        executablePath: String?,
        policyFingerprint: String?,
        approvalWindowSeconds: Int,
        timeoutSeconds: Int,
        maxOutputBytes: Int,
        denyPrefixes: [[String]],
        brokerRequiredPrefixes: [[String]],
        allowPrefixes: [[String]],
        denyFlags: [String]
    ) {
        self.commandName = commandName
        self.command = command
        self.executablePath = executablePath
        self.policyFingerprint = policyFingerprint
        self.approvalWindowSeconds = approvalWindowSeconds
        self.timeoutSeconds = timeoutSeconds
        self.maxOutputBytes = maxOutputBytes
        self.denyPrefixes = denyPrefixes
        self.brokerRequiredPrefixes = brokerRequiredPrefixes
        self.allowPrefixes = allowPrefixes
        self.denyFlags = denyFlags
    }

    private enum CodingKeys: String, CodingKey {
        case commandName = "command_name"
        case command
        case executablePath = "executable_path"
        case policyFingerprint = "policy_fingerprint"
        case approvalWindowSeconds = "approval_window_seconds"
        case timeoutSeconds = "timeout_seconds"
        case maxOutputBytes = "max_output_bytes"
        case denyPrefixes = "deny_prefixes"
        case brokerRequiredPrefixes = "broker_required_prefixes"
        case allowPrefixes = "allow_prefixes"
        case denyFlags = "deny_flags"
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        commandName = try container.decode(String.self, forKey: .commandName)
        command = try container.decode(String.self, forKey: .command)
        executablePath = try container.decodeIfPresent(String.self, forKey: .executablePath)
        policyFingerprint = try container.decodeIfPresent(String.self, forKey: .policyFingerprint)
        approvalWindowSeconds = try container.decode(Int.self, forKey: .approvalWindowSeconds)
        timeoutSeconds = try container.decode(Int.self, forKey: .timeoutSeconds)
        maxOutputBytes = try container.decode(Int.self, forKey: .maxOutputBytes)
        denyPrefixes = try container.decode([[String]].self, forKey: .denyPrefixes)
        brokerRequiredPrefixes = try container.decodeIfPresent([[String]].self, forKey: .brokerRequiredPrefixes) ?? []
        allowPrefixes = try container.decode([[String]].self, forKey: .allowPrefixes)
        denyFlags = try container.decode([String].self, forKey: .denyFlags)
    }
}

public struct ToolDecisionOutputMetadata: Codable, Equatable, Sendable {
    public let stdoutBytes: Int
    public let stderrBytes: Int
    public let stdoutSHA256: String
    public let stderrSHA256: String

    public init(stdout: Data, stderr: Data) {
        self.stdoutBytes = stdout.count
        self.stderrBytes = stderr.count
        self.stdoutSHA256 = "sha256:\(sha256Hex(stdout))"
        self.stderrSHA256 = "sha256:\(sha256Hex(stderr))"
    }

    private enum CodingKeys: String, CodingKey {
        case stdoutBytes = "stdout_bytes"
        case stderrBytes = "stderr_bytes"
        case stdoutSHA256 = "stdout_sha256"
        case stderrSHA256 = "stderr_sha256"
    }
}

public struct ToolDecisionRedactionMetadata: Codable, Equatable, Sendable {
    public let stdout: String
    public let stderr: String
    public let rawSecretMCPCRUDAvailable: Bool

    public init(
        stdout: String = "not_redacted_broker_response",
        stderr: String = "not_redacted_broker_response",
        rawSecretMCPCRUDAvailable: Bool = false
    ) {
        self.stdout = stdout
        self.stderr = stderr
        self.rawSecretMCPCRUDAvailable = rawSecretMCPCRUDAvailable
    }

    private enum CodingKeys: String, CodingKey {
        case stdout
        case stderr
        case rawSecretMCPCRUDAvailable = "raw_secret_mcp_crud_available"
    }
}

public struct ToolDecisionReceipt: Codable, Equatable, Sendable {
    public let schemaVersion: String
    public let receiptID: String
    public let surface: String
    public let toolName: String
    public let commandName: String?
    public let argv: [String]
    public let cwd: String?
    public let requester: String?
    public let matchedPolicy: ToolDecisionMatchedPolicy?
    public let decision: String
    public let approvalState: ApprovalAuthorizationOutcome
    public let startedAt: String
    public let completedAt: String
    public let exitCode: Int32?
    public let stdoutTruncated: Bool
    public let stderrTruncated: Bool
    public let output: ToolDecisionOutputMetadata?
    public let redaction: ToolDecisionRedactionMetadata
    public let error: String?

    public init(
        schemaVersion: String = "aegis.tool_decision_receipt.v1",
        receiptID: String = UUID().uuidString,
        surface: String,
        toolName: String,
        commandName: String?,
        argv: [String],
        cwd: String?,
        requester: String?,
        matchedPolicy: ToolDecisionMatchedPolicy?,
        decision: String,
        approvalState: ApprovalAuthorizationOutcome,
        startedAt: String,
        completedAt: String,
        exitCode: Int32?,
        stdoutTruncated: Bool,
        stderrTruncated: Bool,
        output: ToolDecisionOutputMetadata?,
        redaction: ToolDecisionRedactionMetadata = ToolDecisionRedactionMetadata(),
        error: String?
    ) {
        self.schemaVersion = schemaVersion
        self.receiptID = receiptID
        self.surface = surface
        self.toolName = toolName
        self.commandName = commandName
        self.argv = argv
        self.cwd = cwd
        self.requester = requester
        self.matchedPolicy = matchedPolicy
        self.decision = decision
        self.approvalState = approvalState
        self.startedAt = startedAt
        self.completedAt = completedAt
        self.exitCode = exitCode
        self.stdoutTruncated = stdoutTruncated
        self.stderrTruncated = stderrTruncated
        self.output = output
        self.redaction = redaction
        self.error = error
    }

    private enum CodingKeys: String, CodingKey {
        case schemaVersion = "schema_version"
        case receiptID = "receipt_id"
        case surface
        case toolName = "tool_name"
        case commandName = "command_name"
        case argv
        case cwd
        case requester
        case matchedPolicy = "matched_policy"
        case decision
        case approvalState = "approval_state"
        case startedAt = "started_at"
        case completedAt = "completed_at"
        case exitCode = "exit_code"
        case stdoutTruncated = "stdout_truncated"
        case stderrTruncated = "stderr_truncated"
        case output
        case redaction
        case error
    }
}

public struct ToolDecisionReceiptRecorder: @unchecked Sendable {
    public let fileURL: URL?
    public let fileManager: FileManager

    public init(
        fileURL: URL? = ToolDecisionReceiptRecorder.defaultURL(),
        fileManager: FileManager = .default
    ) {
        self.fileURL = fileURL
        self.fileManager = fileManager
    }

    public static func defaultURL(environment: [String: String] = ProcessInfo.processInfo.environment) -> URL? {
        if let override = environment[receiptsFileEnvironmentKey]?.trimmedNonEmpty {
            if ["0", "false", "off", "none"].contains(override.lowercased()) {
                return nil
            }
            return URL(fileURLWithPath: expandUserPath(override))
        }

        return CommandStore.defaultConfigDirectory(environment: environment)
            .appendingPathComponent("tool-decisions.jsonl", isDirectory: false)
    }

    public func record(_ receipt: ToolDecisionReceipt) throws {
        guard let fileURL else {
            return
        }

        try fileManager.createDirectory(at: fileURL.deletingLastPathComponent(), withIntermediateDirectories: true)
        if !fileManager.fileExists(atPath: fileURL.path) {
            fileManager.createFile(atPath: fileURL.path, contents: nil)
        }

        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        let data = try encoder.encode(receipt)
        let handle = try FileHandle(forWritingTo: fileURL)
        defer { try? handle.close() }
        try handle.seekToEnd()
        try handle.write(contentsOf: data)
        try handle.write(contentsOf: Data([0x0A]))
    }
}

public struct WrappedCommandInvocationResult: Codable, Equatable, Sendable {
    public let exitCode: Int32
    public let stdout: String
    public let stderr: String
    public let stdoutJSON: JSONValue?
    public let stdoutTruncated: Bool
    public let stderrTruncated: Bool
    public let receipt: ToolDecisionReceipt

    public init(
        exitCode: Int32,
        stdout: String,
        stderr: String,
        stdoutJSON: JSONValue?,
        stdoutTruncated: Bool,
        stderrTruncated: Bool,
        receipt: ToolDecisionReceipt
    ) {
        self.exitCode = exitCode
        self.stdout = stdout
        self.stderr = stderr
        self.stdoutJSON = stdoutJSON
        self.stdoutTruncated = stdoutTruncated
        self.stderrTruncated = stderrTruncated
        self.receipt = receipt
    }

    private enum CodingKeys: String, CodingKey {
        case exitCode = "exit_code"
        case stdout
        case stderr
        case stdoutJSON = "stdout_json"
        case stdoutTruncated = "stdout_truncated"
        case stderrTruncated = "stderr_truncated"
        case receipt
    }
}

public struct RemoteAuthorityActionDescriptor: Codable, Equatable, Sendable {
    public let schemaVersion: String
    public let actionID: String
    public let inputSchemaRef: String
    public let grantClass: String
    public let credentialClass: String
    public let policyRef: String
    public let policyHash: String
    public let brunoGateRef: String
    public let approvalRequirement: String
    public let authLeaseRef: String
    public let executionMode: String
    public let cleanup: String

    public init(
        schemaVersion: String = "aegis.broker.remote_authority_action.v1",
        actionID: String,
        inputSchemaRef: String,
        grantClass: String = "github_issue_pr_mutation",
        credentialClass: String = "github_app_installation_token",
        policyRef: String = "aegis-broker-policy://d79/github-typed-actions",
        policyHash: String,
        brunoGateRef: String,
        approvalRequirement: String = "none",
        authLeaseRef: String = "auth-lease://payload",
        executionMode: String = "broker_api_call",
        cleanup: String = "drop_credentials_after_call"
    ) {
        self.schemaVersion = schemaVersion
        self.actionID = actionID
        self.inputSchemaRef = inputSchemaRef
        self.grantClass = grantClass
        self.credentialClass = credentialClass
        self.policyRef = policyRef
        self.policyHash = policyHash
        self.brunoGateRef = brunoGateRef
        self.approvalRequirement = approvalRequirement
        self.authLeaseRef = authLeaseRef
        self.executionMode = executionMode
        self.cleanup = cleanup
    }

    private enum CodingKeys: String, CodingKey {
        case schemaVersion = "schema_version"
        case actionID = "action_id"
        case inputSchemaRef = "input_schema_ref"
        case grantClass = "grant_class"
        case credentialClass = "credential_class"
        case policyRef = "policy_ref"
        case policyHash = "policy_hash"
        case brunoGateRef = "bruno_gate_ref"
        case approvalRequirement = "approval_requirement"
        case authLeaseRef = "auth_lease_ref"
        case executionMode = "execution_mode"
        case cleanup
    }
}

public struct RemoteAuthorityActionCatalog: Sendable {
    public let actions: [RemoteAuthorityActionDescriptor]

    public init(actions: [RemoteAuthorityActionDescriptor] = RemoteAuthorityActionCatalog.defaultActions()) {
        self.actions = actions.sorted { $0.actionID < $1.actionID }
    }

    public func descriptor(actionID: String) throws -> RemoteAuthorityActionDescriptor {
        guard let descriptor = actions.first(where: { $0.actionID == actionID }) else {
            throw AegisSecretError.blocked("broker_action_unsupported: typed action `\(actionID)` is not supported.")
        }
        return descriptor
    }

    public static func defaultActions() -> [RemoteAuthorityActionDescriptor] {
        [
            descriptor("github.issue.comment", schema: "schema://aegis-broker/github.issue.comment.v1", bruno: "none"),
            descriptor("github.issue.close", schema: "schema://aegis-broker/github.issue.state.v1", bruno: "bruno://github.issue.close.v1"),
            descriptor("github.issue.reopen", schema: "schema://aegis-broker/github.issue.state.v1", bruno: "bruno://github.issue.reopen.v1"),
            descriptor("github.pr.comment", schema: "schema://aegis-broker/github.pr.comment.v1", bruno: "none"),
            descriptor("github.pr.merge", schema: "schema://aegis-broker/github.pr.merge.v1", bruno: "bruno://github.pr.merge.v1"),
            descriptor("github.pr.label", schema: "schema://aegis-broker/github.pr.label.v1", bruno: "bruno://github.pr.label.v1"),
        ]
    }

    private static func descriptor(_ actionID: String, schema: String, bruno: String) -> RemoteAuthorityActionDescriptor {
        let policyHash = "sha256:\(sha256Hex(Data("d79:\(actionID):\(schema):\(bruno)".utf8)))"
        return RemoteAuthorityActionDescriptor(
            actionID: actionID,
            inputSchemaRef: schema,
            policyHash: policyHash,
            brunoGateRef: bruno
        )
    }
}

public struct RemoteAuthorityActionRequest: Codable, Equatable, Sendable {
    public let actionID: String
    public let payload: JSONValue
    public let requester: String?

    public init(actionID: String, payload: JSONValue, requester: String? = nil) {
        self.actionID = actionID
        self.payload = payload
        self.requester = requester
    }

    private enum CodingKeys: String, CodingKey {
        case actionID = "action_id"
        case payload
        case requester
    }
}

public struct RemoteAuthorityLease: Equatable, Sendable {
    public let authLeaseRef: String
    public let grantRef: String
    public let token: String

    public init(authLeaseRef: String, grantRef: String, token: String) {
        self.authLeaseRef = authLeaseRef
        self.grantRef = grantRef
        self.token = token
    }
}

public protocol RemoteAuthorityLeaseProviding: Sendable {
    func lease(for request: RemoteAuthorityActionRequest, descriptor: RemoteAuthorityActionDescriptor) async throws -> RemoteAuthorityLease
}

public struct SecretStoreRemoteAuthorityLeaseProvider: RemoteAuthorityLeaseProviding {
    public let secretStore: any SecretStore

    public init(secretStore: any SecretStore) {
        self.secretStore = secretStore
    }

    public func lease(for request: RemoteAuthorityActionRequest, descriptor: RemoteAuthorityActionDescriptor) async throws -> RemoteAuthorityLease {
        let payload = try objectPayload(request.payload)
        let authLeaseRef = try requiredString(payload, "auth_lease_ref")
        let grantRef = try requiredString(payload, "grant_ref")
        let credentialRef = try requiredString(payload, "credential_ref")
        guard safeAuthorityRef(authLeaseRef, prefixes: ["auth-lease://"]) else {
            throw AegisSecretError.blocked("broker_auth_lease_denied: auth lease ref is unsafe.")
        }
        guard safeAuthorityRef(grantRef, prefixes: ["auth-grant://", "grant://"]) else {
            throw AegisSecretError.blocked("broker_auth_lease_denied: grant ref is unsafe.")
        }
        guard let secretKey = secretReferenceKey(from: credentialRef) else {
            throw AegisSecretError.blocked("broker_auth_lease_denied: credential ref must be broker-local.")
        }

        let reason = "Allow Aegis Broker to materialize \(descriptor.credentialClass) for typed action '\(descriptor.actionID)'."
        let tokenData: Data
        do {
            tokenData = try secretStore.readSecret(for: secretKey, reason: reason)
        } catch {
            throw AegisSecretError.blocked("broker_credential_materialization_failed: credential material was unavailable.")
        }
        guard let token = String(data: tokenData, encoding: .utf8)?.trimmedNonEmpty else {
            throw AegisSecretError.blocked("broker_credential_materialization_failed: credential material was unavailable.")
        }
        return RemoteAuthorityLease(authLeaseRef: authLeaseRef, grantRef: grantRef, token: token)
    }
}

public struct GitHubPullRequestMergeGraphQLOperation: Equatable, Sendable {
    public let repo: String
    public let pullRequestNumber: Int
    public let mergeMethod: String
    public let authorEmail: String
    public let expectedHeadOid: String?
    public let commitHeadline: String?
    public let commitBody: String?

    public init(
        repo: String,
        pullRequestNumber: Int,
        mergeMethod: String,
        authorEmail: String,
        expectedHeadOid: String? = nil,
        commitHeadline: String? = nil,
        commitBody: String? = nil
    ) {
        self.repo = repo
        self.pullRequestNumber = pullRequestNumber
        self.mergeMethod = mergeMethod
        self.authorEmail = authorEmail
        self.expectedHeadOid = expectedHeadOid
        self.commitHeadline = commitHeadline
        self.commitBody = commitBody
    }
}

public enum GitHubRemoteAuthorityOperationKind: Equatable, Sendable {
    case rest
    case graphQLPullRequestMerge(GitHubPullRequestMergeGraphQLOperation)
}

public struct GitHubRemoteAuthorityOperation: Equatable, Sendable {
    public let method: String
    public let path: String
    public let body: JSONValue?
    public let kind: GitHubRemoteAuthorityOperationKind

    public init(
        method: String,
        path: String,
        body: JSONValue?,
        kind: GitHubRemoteAuthorityOperationKind = .rest
    ) {
        self.method = method
        self.path = path
        self.body = body
        self.kind = kind
    }
}

public struct RemoteAuthorityActionOutput: Codable, Equatable, Sendable {
    public let statusCode: Int
    public let resourceRef: String?
    public let responseSHA256: String

    public init(statusCode: Int, resourceRef: String?, responseSHA256: String) {
        self.statusCode = statusCode
        self.resourceRef = resourceRef
        self.responseSHA256 = responseSHA256
    }

    private enum CodingKeys: String, CodingKey {
        case statusCode = "status_code"
        case resourceRef = "resource_ref"
        case responseSHA256 = "response_sha256"
    }
}

public protocol GitHubRemoteAuthorityClient: Sendable {
    func execute(operation: GitHubRemoteAuthorityOperation, token: String) async throws -> RemoteAuthorityActionOutput
}

public struct URLSessionGitHubRemoteAuthorityClient: GitHubRemoteAuthorityClient {
    public let apiBaseURL: URL

    public init(apiBaseURL: URL = URL(string: "https://api.github.com")!) {
        self.apiBaseURL = apiBaseURL
    }

    public func execute(operation: GitHubRemoteAuthorityOperation, token: String) async throws -> RemoteAuthorityActionOutput {
        if case .graphQLPullRequestMerge(let merge) = operation.kind {
            return try await executePullRequestMerge(merge, token: token)
        }

        let base = apiBaseURL.absoluteString.trimmingCharacters(in: CharacterSet(charactersIn: "/"))
        guard let url = URL(string: "\(base)/\(operation.path.trimmingCharacters(in: CharacterSet(charactersIn: "/")))") else {
            throw AegisSecretError.blocked("broker_remote_action_failed: GitHub API URL was invalid.")
        }
        var request = URLRequest(url: url)
        request.httpMethod = operation.method
        request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        request.setValue("application/vnd.github+json", forHTTPHeaderField: "Accept")
        request.setValue("2022-11-28", forHTTPHeaderField: "X-GitHub-Api-Version")
        if let body = operation.body {
            request.httpBody = try JSONEncoder().encode(body)
            request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        }
        let (data, response) = try await URLSession.shared.data(for: request)
        let status = (response as? HTTPURLResponse)?.statusCode ?? 0
        guard (200...299).contains(status) else {
            throw AegisSecretError.blocked("broker_remote_action_failed: GitHub returned HTTP \(status).")
        }
        return RemoteAuthorityActionOutput(
            statusCode: status,
            resourceRef: nil,
            responseSHA256: "sha256:\(sha256Hex(data))"
        )
    }

    private func executePullRequestMerge(
        _ merge: GitHubPullRequestMergeGraphQLOperation,
        token: String
    ) async throws -> RemoteAuthorityActionOutput {
        let parts = merge.repo.split(separator: "/")
        guard parts.count == 2 else {
            throw AegisSecretError.blocked("broker_remote_action_failed: GitHub repo scope was invalid.")
        }
        let owner = String(parts[0])
        let name = String(parts[1])

        let lookup = try await executeGraphQL(
            query: """
            query($owner: String!, $name: String!, $number: Int!) {
              repository(owner: $owner, name: $name) {
                pullRequest(number: $number) {
                  id
                  headRefOid
                }
              }
            }
            """,
            variables: [
                "owner": owner,
                "name": name,
                "number": merge.pullRequestNumber,
            ],
            token: token
        )
        guard let repository = lookup["repository"] as? [String: Any],
              let pullRequest = repository["pullRequest"] as? [String: Any],
              let pullRequestID = pullRequest["id"] as? String else {
            throw AegisSecretError.blocked("broker_remote_action_failed: GitHub pull request lookup failed.")
        }

        var input: [String: Any] = [
            "pullRequestId": pullRequestID,
            "mergeMethod": merge.mergeMethod.uppercased(),
            "authorEmail": merge.authorEmail,
        ]
        if let expectedHeadOid = merge.expectedHeadOid ?? pullRequest["headRefOid"] as? String {
            input["expectedHeadOid"] = expectedHeadOid
        }
        if let commitHeadline = merge.commitHeadline {
            input["commitHeadline"] = commitHeadline
        }
        if let commitBody = merge.commitBody {
            input["commitBody"] = commitBody
        }

        let mutation = try await executeGraphQL(
            query: """
            mutation($input: MergePullRequestInput!) {
              mergePullRequest(input: $input) {
                pullRequest {
                  id
                  number
                  merged
                }
              }
            }
            """,
            variables: ["input": input],
            token: token
        )
        let responseData = try JSONSerialization.data(withJSONObject: mutation, options: [.sortedKeys])
        return RemoteAuthorityActionOutput(
            statusCode: 200,
            resourceRef: "github://\(merge.repo)/pull/\(merge.pullRequestNumber)",
            responseSHA256: "sha256:\(sha256Hex(responseData))"
        )
    }

    private func executeGraphQL(
        query: String,
        variables: [String: Any],
        token: String
    ) async throws -> [String: Any] {
        let base = apiBaseURL.absoluteString.trimmingCharacters(in: CharacterSet(charactersIn: "/"))
        guard let url = URL(string: "\(base)/graphql") else {
            throw AegisSecretError.blocked("broker_remote_action_failed: GitHub GraphQL URL was invalid.")
        }
        let body: [String: Any] = [
            "query": query,
            "variables": variables,
        ]
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        request.setValue("application/vnd.github+json", forHTTPHeaderField: "Accept")
        request.setValue("2022-11-28", forHTTPHeaderField: "X-GitHub-Api-Version")
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = try JSONSerialization.data(withJSONObject: body, options: [])

        let (data, response) = try await URLSession.shared.data(for: request)
        let status = (response as? HTTPURLResponse)?.statusCode ?? 0
        guard (200...299).contains(status) else {
            throw AegisSecretError.blocked("broker_remote_action_failed: GitHub GraphQL returned HTTP \(status).")
        }
        guard let root = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw AegisSecretError.blocked("broker_remote_action_failed: GitHub GraphQL response was invalid.")
        }
        if let errors = root["errors"] as? [[String: Any]], !errors.isEmpty {
            throw AegisSecretError.blocked("broker_remote_action_failed: GitHub GraphQL returned errors.")
        }
        guard let data = root["data"] as? [String: Any] else {
            throw AegisSecretError.blocked("broker_remote_action_failed: GitHub GraphQL response omitted data.")
        }
        return data
    }
}

public struct GitAuthorIdentity: Equatable, Sendable {
    public let email: String
    public let emailOrigin: String?
    public let remoteOriginURL: String?

    public init(email: String, emailOrigin: String?, remoteOriginURL: String?) {
        self.email = email
        self.emailOrigin = emailOrigin
        self.remoteOriginURL = remoteOriginURL
    }
}

public protocol GitAuthorIdentityProviding: Sendable {
    func identity(cwd: String) throws -> GitAuthorIdentity
}

public struct ProcessGitAuthorIdentityProvider: GitAuthorIdentityProviding {
    public init() {}

    public func identity(cwd: String) throws -> GitAuthorIdentity {
        var isDirectory = ObjCBool(false)
        guard FileManager.default.fileExists(atPath: cwd, isDirectory: &isDirectory), isDirectory.boolValue else {
            throw AegisSecretError.blocked("broker_policy_denied: PR merge requires a valid checkout cwd.")
        }
        let emailOutput: String
        do {
            emailOutput = try runGit(["config", "--get", "user.email"], cwd: cwd)
        } catch {
            throw AegisSecretError.blocked("broker_policy_denied: PR merge requires `git config user.email` in the checkout. Set the checkout Git identity before retrying.")
        }
        let email = emailOutput.trimmedNonEmpty
        guard let email else {
            throw AegisSecretError.blocked("broker_policy_denied: PR merge requires `git config user.email` in the checkout. Set the checkout Git identity before retrying.")
        }
        let origin = try? runGit(["config", "--show-origin", "--get", "user.email"], cwd: cwd).trimmedNonEmpty
        let remote = try? runGit(["remote", "get-url", "origin"], cwd: cwd).trimmedNonEmpty
        return GitAuthorIdentity(email: email, emailOrigin: origin, remoteOriginURL: remote)
    }

    private func runGit(_ args: [String], cwd: String) throws -> String {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/git")
        process.arguments = ["-C", cwd] + args
        let output = Pipe()
        let error = Pipe()
        process.standardOutput = output
        process.standardError = error
        try process.run()
        process.waitUntilExit()
        guard process.terminationStatus == 0 else {
            throw AegisSecretError.blocked("broker_policy_denied: PR merge requires readable Git identity in the checkout.")
        }
        return String(decoding: output.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
    }
}

public struct RemoteAuthorityAuthorIdentityEvidence: Codable, Equatable, Sendable {
    public let emailDomain: String
    public let emailSHA256: String
    public let emailOriginKind: String

    private enum CodingKeys: String, CodingKey {
        case emailDomain = "email_domain"
        case emailSHA256 = "email_sha256"
        case emailOriginKind = "email_origin_kind"
    }
}

public struct RemoteAuthorityActionEvidence: Codable, Equatable, Sendable {
    public let schemaVersion: String
    public let evidenceID: String
    public let actionID: String
    public let caller: [String: String]
    public let projectRef: String
    public let repoRef: String
    public let resourceScopeRef: String
    public let grantClass: String
    public let credentialClass: String
    public let authLeaseRef: String
    public let grantRef: String
    public let policyRef: String
    public let policyHash: String
    public let brunoDecisionRef: String
    public let approvalRef: String
    public let executionMode: String
    public let startedAt: String
    public let completedAt: String
    public let result: String
    public let cleanupStatus: String
    public let redactionState: String
    public let rawCredentialMaterialPrinted: Bool
    public let output: RemoteAuthorityActionOutput?
    public let authorIdentity: RemoteAuthorityAuthorIdentityEvidence?

    private enum CodingKeys: String, CodingKey {
        case schemaVersion = "schema_version"
        case evidenceID = "evidence_id"
        case actionID = "action_id"
        case caller
        case projectRef = "project_ref"
        case repoRef = "repo_ref"
        case resourceScopeRef = "resource_scope_ref"
        case grantClass = "grant_class"
        case credentialClass = "credential_class"
        case authLeaseRef = "auth_lease_ref"
        case grantRef = "grant_ref"
        case policyRef = "policy_ref"
        case policyHash = "policy_hash"
        case brunoDecisionRef = "bruno_decision_ref"
        case approvalRef = "approval_ref"
        case executionMode = "execution_mode"
        case startedAt = "started_at"
        case completedAt = "completed_at"
        case result
        case cleanupStatus = "cleanup_status"
        case redactionState = "redaction_state"
        case rawCredentialMaterialPrinted = "raw_credential_material_printed"
        case output
        case authorIdentity = "author_identity"
    }
}

public struct RemoteAuthorityActionInvocationResult: Codable, Equatable, Sendable {
    public let status: String
    public let actionID: String
    public let evidence: RemoteAuthorityActionEvidence

    public init(status: String, actionID: String, evidence: RemoteAuthorityActionEvidence) {
        self.status = status
        self.actionID = actionID
        self.evidence = evidence
    }

    private enum CodingKeys: String, CodingKey {
        case status
        case actionID = "action_id"
        case evidence
    }
}

public struct RemoteAuthorityActionRunner: Sendable {
    public let catalog: RemoteAuthorityActionCatalog
    public let leaseProvider: any RemoteAuthorityLeaseProviding
    public let githubClient: any GitHubRemoteAuthorityClient
    public let gitIdentityProvider: any GitAuthorIdentityProviding
    public let brunoEvaluator: (any BrunoGuardEvaluating)?
    public let now: @Sendable () -> Date

    public init(
        catalog: RemoteAuthorityActionCatalog = RemoteAuthorityActionCatalog(),
        leaseProvider: any RemoteAuthorityLeaseProviding,
        githubClient: any GitHubRemoteAuthorityClient = URLSessionGitHubRemoteAuthorityClient(),
        gitIdentityProvider: any GitAuthorIdentityProviding = ProcessGitAuthorIdentityProvider(),
        brunoEvaluator: (any BrunoGuardEvaluating)? = ProcessBrunoGuardEvaluator(),
        now: @escaping @Sendable () -> Date = Date.init
    ) {
        self.catalog = catalog
        self.leaseProvider = leaseProvider
        self.githubClient = githubClient
        self.gitIdentityProvider = gitIdentityProvider
        self.brunoEvaluator = brunoEvaluator
        self.now = now
    }

    public func listActions() -> [RemoteAuthorityActionDescriptor] {
        catalog.actions
    }

    public func run(_ request: RemoteAuthorityActionRequest) async throws -> RemoteAuthorityActionInvocationResult {
        let descriptor = try catalog.descriptor(actionID: request.actionID)
        let startedAt = now()
        let payload = try objectPayload(request.payload)
        let repo = try requiredString(payload, "repo")
        guard safeGitHubRepo(repo) else {
            throw AegisSecretError.blocked("broker_policy_denied: repo scope is unsafe.")
        }
        let authorIdentity = try authorIdentityEvidenceIfNeeded(actionID: request.actionID, repo: repo, payload: payload)
        let resourceScopeRef = try resourceScopeRef(actionID: request.actionID, repo: repo, payload: payload)
        let projectRef = stringValue(payload["project_ref"]) ?? "project://local"

        let brunoDecisionRef = try await evaluateBrunoIfNeeded(
            descriptor: descriptor,
            request: request,
            repo: repo,
            resourceScopeRef: resourceScopeRef
        )
        let lease = try await leaseProvider.lease(for: request, descriptor: descriptor)
        let operation = try githubOperation(actionID: request.actionID, repo: repo, payload: payload, authorEmail: authorIdentity?.email)
        let output = try await githubClient.execute(operation: operation, token: lease.token)
        let evidence = RemoteAuthorityActionEvidence(
            schemaVersion: "aegis.broker.remote_authority_evidence.v1",
            evidenceID: "broker-evidence://\(request.actionID)/\(sha256Hex(Data("\(repo):\(resourceScopeRef):\(startedAt.timeIntervalSince1970)".utf8)))",
            actionID: request.actionID,
            caller: [
                "agent": request.requester?.trimmedNonEmpty ?? "local-agent",
                "session_ref": stringValue(payload["session_ref"]) ?? "agent-session://local",
            ],
            projectRef: projectRef,
            repoRef: "github://\(repo)",
            resourceScopeRef: resourceScopeRef,
            grantClass: descriptor.grantClass,
            credentialClass: descriptor.credentialClass,
            authLeaseRef: lease.authLeaseRef,
            grantRef: lease.grantRef,
            policyRef: descriptor.policyRef,
            policyHash: descriptor.policyHash,
            brunoDecisionRef: brunoDecisionRef,
            approvalRef: "none",
            executionMode: descriptor.executionMode,
            startedAt: iso8601String(startedAt),
            completedAt: iso8601String(now()),
            result: "allowed",
            cleanupStatus: "credentials_dropped",
            redactionState: "metadata_only",
            rawCredentialMaterialPrinted: false,
            output: output,
            authorIdentity: authorIdentity?.evidence
        )
        return RemoteAuthorityActionInvocationResult(status: "ok", actionID: request.actionID, evidence: evidence)
    }

    private func authorIdentityEvidenceIfNeeded(
        actionID: String,
        repo: String,
        payload: [String: JSONValue]
    ) throws -> (email: String, evidence: RemoteAuthorityAuthorIdentityEvidence)? {
        guard actionID == "github.pr.merge" else {
            return nil
        }
        let cwd = try requiredString(payload, "cwd")
        let identity = try gitIdentityProvider.identity(cwd: cwd)
        try validateAuthorEmail(identity.email, repo: repo)
        if let remoteOriginURL = identity.remoteOriginURL,
           let originRepo = gitHubRepo(fromRemoteURL: remoteOriginURL),
           originRepo != repo {
            throw AegisSecretError.blocked("broker_policy_denied: checkout origin does not match PR merge repo.")
        }
        return (
            identity.email,
            RemoteAuthorityAuthorIdentityEvidence(
                emailDomain: emailDomain(identity.email),
                emailSHA256: "sha256:\(sha256Hex(Data(identity.email.utf8)))",
                emailOriginKind: gitConfigOriginKind(identity.emailOrigin)
            )
        )
    }

    private func evaluateBrunoIfNeeded(
        descriptor: RemoteAuthorityActionDescriptor,
        request: RemoteAuthorityActionRequest,
        repo: String,
        resourceScopeRef: String
    ) async throws -> String {
        guard descriptor.brunoGateRef != "none" else {
            return "none"
        }
        guard let brunoEvaluator else {
            throw AegisSecretError.blocked("broker_bruno_denied: Bruno guard is required but unavailable.")
        }
        let decision = try await brunoEvaluator.evaluate(event: brunoEvent(
            descriptor: descriptor,
            request: request,
            repo: repo,
            resourceScopeRef: resourceScopeRef
        ))
        guard decision.decision == "allow" else {
            throw AegisSecretError.blocked("broker_bruno_denied: \(decision.recommendedNextPrompt ?? decision.reasons.first?.message ?? "Bruno denied the action.").")
        }
        return "bruno-decision://\(descriptor.actionID)/\(sha256Hex(Data("\(repo):\(resourceScopeRef)".utf8)))"
    }

    private func brunoEvent(
        descriptor: RemoteAuthorityActionDescriptor,
        request: RemoteAuthorityActionRequest,
        repo: String,
        resourceScopeRef: String
    ) -> JSONValue {
        let payload = (try? objectPayload(request.payload)) ?? [:]
        let action: [String: JSONValue] = [
            "kind": .string(request.actionID),
            "broker_action_ref": .string("broker-action://\(request.actionID)"),
            "bruno_gate_ref": .string(descriptor.brunoGateRef),
        ]
        let subjectRefs: [String: JSONValue] = [
            "repo": .string("github://\(repo)"),
            "resource": .string(resourceScopeRef),
        ]
        let actor: [String: JSONValue] = [
            "agent": .string(request.requester?.trimmedNonEmpty ?? "local-agent"),
            "session_ref": .string(stringValue(payload["session_ref"]) ?? "agent-session://local"),
        ]
        let context: [String: JSONValue] = [
            "tool_kind": .string("broker_remote_action"),
            "cwd": .string("[REDACTED_PATH]"),
        ]
        return .object([
            "schema_version": .string("aegis.broker.bruno_event.v1"),
            "action": .object(action),
            "subject_refs": .object(subjectRefs),
            "actor": .object(actor),
            "context": .object(context),
            "redaction_state": .string("metadata_only"),
            "evidence_refs": .array(arrayValue(payload["evidence_refs"]) ?? []),
        ])
    }
}

private func objectPayload(_ value: JSONValue) throws -> [String: JSONValue] {
    guard let payload = value.objectValue else {
        throw AegisSecretError.blocked("broker_policy_denied: typed action payload must be an object.")
    }
    return payload
}

private func stringValue(_ value: JSONValue?) -> String? {
    value?.stringValue?.trimmedNonEmpty
}

private func arrayValue(_ value: JSONValue?) -> [JSONValue]? {
    value?.arrayValue
}

private func integerValue(_ value: JSONValue?) -> Int? {
    value?.integerValue
}

private func requiredString(_ payload: [String: JSONValue], _ key: String) throws -> String {
    guard let value = stringValue(payload[key]) else {
        throw AegisSecretError.blocked("broker_policy_denied: missing required field `\(key)`.")
    }
    return value
}

private func requiredInteger(_ payload: [String: JSONValue], _ key: String) throws -> Int {
    guard let value = integerValue(payload[key]) else {
        throw AegisSecretError.blocked("broker_policy_denied: missing required field `\(key)`.")
    }
    return value
}

private func safeAuthorityRef(_ value: String, prefixes: [String]) -> Bool {
    value.count <= 512 &&
    prefixes.contains(where: { value.hasPrefix($0) }) &&
    !value.contains(where: \.isWhitespace) &&
    redactionSafe(value)
}

private func redactionSafe(_ value: String) -> Bool {
    let lower = value.lowercased()
    return !value.isEmpty &&
    !value.contains("@") &&
    !lower.contains("access_token") &&
    !lower.contains("github_pat_") &&
    !lower.contains("ghp_") &&
    !lower.contains("bearer ") &&
    !lower.contains("password") &&
    !lower.contains("private_key") &&
    !lower.contains("/users/") &&
    !lower.contains("/home/")
}

private func safeGitHubRepo(_ value: String) -> Bool {
    let parts = value.split(separator: "/")
    return parts.count == 2 &&
    value.count <= 160 &&
    parts.allSatisfy { !$0.isEmpty && $0 != "." && $0 != ".." } &&
    value.allSatisfy { character in
        character.isASCII && (character.isLetter || character.isNumber || character == "-" || character == "_" || character == "." || character == "/")
    } &&
    redactionSafe(value)
}

private func resourceScopeRef(actionID: String, repo: String, payload: [String: JSONValue]) throws -> String {
    if actionID.hasPrefix("github.issue.") {
        return "github://\(repo)/issues/\(try requiredInteger(payload, "issue_number"))"
    }
    if actionID.hasPrefix("github.pr.") {
        return "github://\(repo)/pull/\(try requiredInteger(payload, "pr_number"))"
    }
    throw AegisSecretError.blocked("broker_action_unsupported: typed action `\(actionID)` is not supported.")
}

private func githubOperation(
    actionID: String,
    repo: String,
    payload: [String: JSONValue],
    authorEmail: String? = nil
) throws -> GitHubRemoteAuthorityOperation {
    switch actionID {
    case "github.issue.comment":
        let issue = try requiredInteger(payload, "issue_number")
        let body = try requiredString(payload, "body")
        return GitHubRemoteAuthorityOperation(
            method: "POST",
            path: "/repos/\(repo)/issues/\(issue)/comments",
            body: .object(["body": .string(body)])
        )
    case "github.issue.close":
        let issue = try requiredInteger(payload, "issue_number")
        return GitHubRemoteAuthorityOperation(
            method: "PATCH",
            path: "/repos/\(repo)/issues/\(issue)",
            body: .object(["state": .string("closed")])
        )
    case "github.issue.reopen":
        let issue = try requiredInteger(payload, "issue_number")
        return GitHubRemoteAuthorityOperation(
            method: "PATCH",
            path: "/repos/\(repo)/issues/\(issue)",
            body: .object(["state": .string("open")])
        )
    case "github.pr.comment":
        let pullRequest = try requiredInteger(payload, "pr_number")
        let body = try requiredString(payload, "body")
        return GitHubRemoteAuthorityOperation(
            method: "POST",
            path: "/repos/\(repo)/issues/\(pullRequest)/comments",
            body: .object(["body": .string(body)])
        )
    case "github.pr.merge":
        let pullRequest = try requiredInteger(payload, "pr_number")
        let mergeMethod = stringValue(payload["merge_method"]) ?? "merge"
        guard ["merge", "squash", "rebase"].contains(mergeMethod) else {
            throw AegisSecretError.blocked("broker_policy_denied: unsupported PR merge method.")
        }
        guard let authorEmail else {
            throw AegisSecretError.blocked("broker_policy_denied: PR merge requires Broker-derived git author email.")
        }
        return GitHubRemoteAuthorityOperation(
            method: "POST",
            path: "/graphql",
            body: nil,
            kind: .graphQLPullRequestMerge(GitHubPullRequestMergeGraphQLOperation(
                repo: repo,
                pullRequestNumber: pullRequest,
                mergeMethod: mergeMethod,
                authorEmail: authorEmail,
                expectedHeadOid: stringValue(payload["expected_head_oid"]),
                commitHeadline: stringValue(payload["commit_headline"]),
                commitBody: stringValue(payload["commit_body"])
            ))
        )
    case "github.pr.label":
        let pullRequest = try requiredInteger(payload, "pr_number")
        let labels = arrayValue(payload["labels"])?.compactMap(\.stringValue) ?? []
        guard !labels.isEmpty, labels.allSatisfy({ !$0.isEmpty && $0.count <= 64 && redactionSafe($0) }) else {
            throw AegisSecretError.blocked("broker_policy_denied: labels are unsafe.")
        }
        return GitHubRemoteAuthorityOperation(
            method: "POST",
            path: "/repos/\(repo)/issues/\(pullRequest)/labels",
            body: .object(["labels": .array(labels.map { .string($0) })])
        )
    default:
        throw AegisSecretError.blocked("broker_action_unsupported: typed action `\(actionID)` is not supported.")
    }
}

private func validateAuthorEmail(_ value: String, repo: String) throws {
    guard isSafeEmail(value) else {
        throw AegisSecretError.blocked("broker_policy_denied: git author email is invalid or unsafe.")
    }
    let owner = repo.split(separator: "/").first.map(String.init) ?? ""
    let domain = emailDomain(value)
    let allowedDomains = allowedAuthorEmailDomains(forOwner: owner)
    guard allowedDomains.isEmpty || allowedDomains.contains(domain) || isGitHubNoReplyEmail(value) else {
        throw AegisSecretError.blocked("broker_policy_denied: git author email is not allowed for this repository owner.")
    }
}

private func allowedAuthorEmailDomains(forOwner owner: String) -> Set<String> {
    switch owner {
    case "mithran-hq":
        return ["mithran.ai"]
    case "getnexar":
        return ["getnexar.com"]
    case "olympum":
        return ["olympum.com"]
    default:
        return []
    }
}

private func isSafeEmail(_ value: String) -> Bool {
    let parts = value.split(separator: "@", omittingEmptySubsequences: false)
    guard parts.count == 2 else { return false }
    guard !parts[0].isEmpty, !parts[1].isEmpty, value.count <= 254 else { return false }
    return value.allSatisfy { character in
        character.isASCII &&
        !character.isWhitespace &&
        character != "/" &&
        character != "\\" &&
        character != "\"" &&
        character != "'"
    }
}

private func emailDomain(_ value: String) -> String {
    value.split(separator: "@").last.map { String($0).lowercased() } ?? "unknown"
}

private func isGitHubNoReplyEmail(_ value: String) -> Bool {
    value.lowercased().hasSuffix("@users.noreply.github.com")
}

private func gitConfigOriginKind(_ value: String?) -> String {
    guard let value = value?.lowercased() else {
        return "unknown"
    }
    if value.contains(".git/config") {
        return "local"
    }
    if value.contains(".gitconfig-") {
        return "include"
    }
    if value.contains(".gitconfig") {
        return "global"
    }
    if value.hasPrefix("file:") {
        return "file"
    }
    return "unknown"
}

private func gitHubRepo(fromRemoteURL value: String) -> String? {
    let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
    if trimmed.hasPrefix("git@github.com:") {
        return normalizeGitHubRepo(String(trimmed.dropFirst("git@github.com:".count)))
    }
    if let url = URL(string: trimmed),
       url.host?.lowercased() == "github.com" {
        return normalizeGitHubRepo(url.path.trimmingCharacters(in: CharacterSet(charactersIn: "/")))
    }
    return nil
}

private func normalizeGitHubRepo(_ value: String) -> String? {
    var repo = value
    if repo.hasSuffix(".git") {
        repo.removeLast(4)
    }
    return safeGitHubRepo(repo) ? repo : nil
}

public struct RemoteAuthorityCLIProfileDescriptor: Codable, Equatable, Sendable {
    public let schemaVersion: String
    public let profileID: String
    public let tool: String
    public let argvTemplate: [String]
    public let argvTemplateDigest: String
    public let allowedCWDPrefixes: [String]
    public let grantClass: String
    public let credentialClass: String
    public let credentialEnvironmentVariable: String
    public let networkPolicyRef: String
    public let approvalRequirement: String
    public let timeoutSeconds: Int
    public let maxOutputBytes: Int
    public let outputRedaction: String
    public let cleanup: String
    public let brunoGateRef: String

    public init(
        schemaVersion: String = "aegis.broker.cli_profile.v1",
        profileID: String,
        tool: String,
        argvTemplate: [String],
        allowedCWDPrefixes: [String],
        grantClass: String,
        credentialClass: String,
        credentialEnvironmentVariable: String,
        networkPolicyRef: String,
        approvalRequirement: String = "none",
        timeoutSeconds: Int = 120,
        maxOutputBytes: Int = 64 * 1024,
        outputRedaction: String = "metadata_only_sha256",
        cleanup: String = "drop_env_credentials_after_process_exit",
        brunoGateRef: String = "none"
    ) {
        self.schemaVersion = schemaVersion
        self.profileID = profileID
        self.tool = tool
        self.argvTemplate = argvTemplate
        self.argvTemplateDigest = "sha256:\(sha256Hex(Data(argvTemplate.joined(separator: "\u{1F}").utf8)))"
        self.allowedCWDPrefixes = allowedCWDPrefixes
        self.grantClass = grantClass
        self.credentialClass = credentialClass
        self.credentialEnvironmentVariable = credentialEnvironmentVariable
        self.networkPolicyRef = networkPolicyRef
        self.approvalRequirement = approvalRequirement
        self.timeoutSeconds = timeoutSeconds
        self.maxOutputBytes = maxOutputBytes
        self.outputRedaction = outputRedaction
        self.cleanup = cleanup
        self.brunoGateRef = brunoGateRef
    }

    private enum CodingKeys: String, CodingKey {
        case schemaVersion = "schema_version"
        case profileID = "profile_id"
        case tool
        case argvTemplate = "argv_template"
        case argvTemplateDigest = "argv_template_digest"
        case allowedCWDPrefixes = "allowed_cwd_prefixes"
        case grantClass = "grant_class"
        case credentialClass = "credential_class"
        case credentialEnvironmentVariable = "credential_environment_variable"
        case networkPolicyRef = "network_policy_ref"
        case approvalRequirement = "approval_requirement"
        case timeoutSeconds = "timeout_seconds"
        case maxOutputBytes = "max_output_bytes"
        case outputRedaction = "output_redaction"
        case cleanup
        case brunoGateRef = "bruno_gate_ref"
    }
}

public struct RemoteAuthorityCLIProfileCatalog: Sendable {
    public let profiles: [RemoteAuthorityCLIProfileDescriptor]

    public init(profiles: [RemoteAuthorityCLIProfileDescriptor] = RemoteAuthorityCLIProfileCatalog.defaultProfiles()) {
        self.profiles = profiles.sorted { $0.profileID < $1.profileID }
    }

    public func descriptor(profileID: String) throws -> RemoteAuthorityCLIProfileDescriptor {
        guard let descriptor = profiles.first(where: { $0.profileID == profileID }) else {
            throw AegisSecretError.blocked("broker_cli_profile_unsupported: CLI profile `\(profileID)` is not supported.")
        }
        return descriptor
    }

    public static func defaultProfiles() -> [RemoteAuthorityCLIProfileDescriptor] {
        [
            RemoteAuthorityCLIProfileDescriptor(
                profileID: "gcloud.run.deploy.sandbox",
                tool: "gcloud",
                argvTemplate: [
                    "run", "deploy", "{{service}}",
                    "--image", "{{image}}",
                    "--region", "{{region}}",
                    "--project", "{{project}}",
                    "--quiet",
                ],
                allowedCWDPrefixes: ["/workspace"],
                grantClass: "cloud_deploy_mutation",
                credentialClass: "gcp_access_token",
                credentialEnvironmentVariable: "CLOUDSDK_AUTH_ACCESS_TOKEN",
                networkPolicyRef: "network-policy://d79/gcloud-run-deploy",
                brunoGateRef: "bruno://gcloud.run.deploy.v1"
            )
        ]
    }
}

public struct RemoteAuthorityCLIProfileRequest: Codable, Equatable, Sendable {
    public let profileID: String
    public let parameters: [String: String]
    public let cwd: String?
    public let authLeaseRef: String
    public let grantRef: String
    public let credentialRef: String
    public let requester: String?
    public let projectRef: String?
    public let resourceScopeRef: String?
    public let sessionRef: String?

    public init(
        profileID: String,
        parameters: [String: String],
        cwd: String?,
        authLeaseRef: String,
        grantRef: String,
        credentialRef: String,
        requester: String? = nil,
        projectRef: String? = nil,
        resourceScopeRef: String? = nil,
        sessionRef: String? = nil
    ) {
        self.profileID = profileID
        self.parameters = parameters
        self.cwd = cwd
        self.authLeaseRef = authLeaseRef
        self.grantRef = grantRef
        self.credentialRef = credentialRef
        self.requester = requester
        self.projectRef = projectRef
        self.resourceScopeRef = resourceScopeRef
        self.sessionRef = sessionRef
    }

    private enum CodingKeys: String, CodingKey {
        case profileID = "profile_id"
        case parameters
        case cwd
        case authLeaseRef = "auth_lease_ref"
        case grantRef = "grant_ref"
        case credentialRef = "credential_ref"
        case requester
        case projectRef = "project_ref"
        case resourceScopeRef = "resource_scope_ref"
        case sessionRef = "session_ref"
    }
}

public protocol RemoteAuthorityCLIProfileLeaseProviding: Sendable {
    func lease(for request: RemoteAuthorityCLIProfileRequest, profile: RemoteAuthorityCLIProfileDescriptor) async throws -> RemoteAuthorityLease
}

public struct SecretStoreCLIProfileLeaseProvider: RemoteAuthorityCLIProfileLeaseProviding {
    public let secretStore: any SecretStore

    public init(secretStore: any SecretStore) {
        self.secretStore = secretStore
    }

    public func lease(for request: RemoteAuthorityCLIProfileRequest, profile: RemoteAuthorityCLIProfileDescriptor) async throws -> RemoteAuthorityLease {
        guard safeAuthorityRef(request.authLeaseRef, prefixes: ["auth-lease://"]) else {
            throw AegisSecretError.blocked("broker_auth_lease_denied: auth lease ref is unsafe.")
        }
        guard safeAuthorityRef(request.grantRef, prefixes: ["auth-grant://", "grant://"]) else {
            throw AegisSecretError.blocked("broker_auth_lease_denied: grant ref is unsafe.")
        }
        guard let secretKey = secretReferenceKey(from: request.credentialRef) else {
            throw AegisSecretError.blocked("broker_auth_lease_denied: credential ref must be broker-local.")
        }
        let reason = "Allow Aegis Broker to materialize \(profile.credentialClass) for CLI profile '\(profile.profileID)'."
        let tokenData: Data
        do {
            tokenData = try secretStore.readSecret(for: secretKey, reason: reason)
        } catch {
            throw AegisSecretError.blocked("broker_credential_materialization_failed: credential material was unavailable.")
        }
        guard let token = String(data: tokenData, encoding: .utf8)?.trimmedNonEmpty else {
            throw AegisSecretError.blocked("broker_credential_materialization_failed: credential material was unavailable.")
        }
        return RemoteAuthorityLease(authLeaseRef: request.authLeaseRef, grantRef: request.grantRef, token: token)
    }
}

public struct RemoteAuthorityCLIProfileEvidence: Codable, Equatable, Sendable {
    public let schemaVersion: String
    public let evidenceID: String
    public let profileID: String
    public let caller: [String: String]
    public let projectRef: String
    public let resourceScopeRef: String
    public let grantClass: String
    public let credentialClass: String
    public let authLeaseRef: String
    public let grantRef: String
    public let argvTemplate: [String]
    public let argvTemplateDigest: String
    public let commandDigest: String
    public let brunoDecisionRef: String
    public let approvalRef: String
    public let executionMode: String
    public let startedAt: String
    public let completedAt: String
    public let result: String
    public let cleanupStatus: String
    public let redactionState: String
    public let rawCredentialMaterialPrinted: Bool
    public let output: ToolDecisionOutputMetadata

    private enum CodingKeys: String, CodingKey {
        case schemaVersion = "schema_version"
        case evidenceID = "evidence_id"
        case profileID = "profile_id"
        case caller
        case projectRef = "project_ref"
        case resourceScopeRef = "resource_scope_ref"
        case grantClass = "grant_class"
        case credentialClass = "credential_class"
        case authLeaseRef = "auth_lease_ref"
        case grantRef = "grant_ref"
        case argvTemplate = "argv_template"
        case argvTemplateDigest = "argv_template_digest"
        case commandDigest = "command_digest"
        case brunoDecisionRef = "bruno_decision_ref"
        case approvalRef = "approval_ref"
        case executionMode = "execution_mode"
        case startedAt = "started_at"
        case completedAt = "completed_at"
        case result
        case cleanupStatus = "cleanup_status"
        case redactionState = "redaction_state"
        case rawCredentialMaterialPrinted = "raw_credential_material_printed"
        case output
    }
}

public struct RemoteAuthorityCLIProfileInvocationResult: Codable, Equatable, Sendable {
    public let status: String
    public let profileID: String
    public let exitCode: Int32
    public let evidence: RemoteAuthorityCLIProfileEvidence

    private enum CodingKeys: String, CodingKey {
        case status
        case profileID = "profile_id"
        case exitCode = "exit_code"
        case evidence
    }
}

public struct RemoteAuthorityCLIProfileRunner: Sendable {
    public let catalog: RemoteAuthorityCLIProfileCatalog
    public let leaseProvider: any RemoteAuthorityCLIProfileLeaseProviding
    public let commandStore: CommandStore
    public let executor: CommandExecutor
    public let environment: [String: String]
    public let brunoEvaluator: (any BrunoGuardEvaluating)?
    public let now: @Sendable () -> Date

    public init(
        catalog: RemoteAuthorityCLIProfileCatalog = RemoteAuthorityCLIProfileCatalog(),
        leaseProvider: any RemoteAuthorityCLIProfileLeaseProviding,
        commandStore: CommandStore = CommandStore(),
        executor: CommandExecutor = ProcessCommandExecutor(),
        environment: [String: String] = ProcessInfo.processInfo.environment,
        brunoEvaluator: (any BrunoGuardEvaluating)? = ProcessBrunoGuardEvaluator(),
        now: @escaping @Sendable () -> Date = Date.init
    ) {
        self.catalog = catalog
        self.leaseProvider = leaseProvider
        self.commandStore = commandStore
        self.executor = executor
        self.environment = environment
        self.brunoEvaluator = brunoEvaluator
        self.now = now
    }

    public func listProfiles() -> [RemoteAuthorityCLIProfileDescriptor] {
        catalog.profiles
    }

    public func run(_ request: RemoteAuthorityCLIProfileRequest) async throws -> RemoteAuthorityCLIProfileInvocationResult {
        let profile = try catalog.descriptor(profileID: request.profileID)
        let startedAt = now()
        let argv = try renderArgvTemplate(profile.argvTemplate, parameters: request.parameters)
        let cwd = try resolveProfileCWD(request.cwd, allowedPrefixes: profile.allowedCWDPrefixes)
        let brunoDecisionRef = try await evaluateCLIProfileBrunoIfNeeded(profile: profile, request: request, argv: argv)
        let lease = try await leaseProvider.lease(for: request, profile: profile)
        guard let executableURL = commandStore.resolveExecutable(named: profile.tool) else {
            throw AegisSecretError.blocked("broker_cli_profile_unsupported: tool `\(profile.tool)` is not executable on PATH.")
        }
        let tempRoot = FileManager.default.temporaryDirectory
            .appendingPathComponent("aegis-cli-profile-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: tempRoot, withIntermediateDirectories: true)
        var executionEnvironment = isolatedCLIProfileEnvironment(from: environment, tempRoot: tempRoot)
        executionEnvironment[profile.credentialEnvironmentVariable] = lease.token
        let rawResult: RawCommandExecutionResult
        do {
            rawResult = try await executor.execute(CommandExecutionRequest(
                executableURL: executableURL,
                arguments: argv,
                environment: executionEnvironment,
                currentDirectoryURL: cwd,
                timeoutSeconds: profile.timeoutSeconds,
                maxOutputBytes: profile.maxOutputBytes
            ))
        } catch {
            _ = cleanupCLIProfileTempRoot(tempRoot)
            throw error
        }
        let credentialMaterialPrinted = containsCredentialMaterial(rawResult, token: lease.token)
        let cleanupStatus = cleanupCLIProfileTempRoot(tempRoot)
        let evidence = RemoteAuthorityCLIProfileEvidence(
            schemaVersion: "aegis.broker.remote_authority_evidence.v1",
            evidenceID: "broker-evidence://\(request.profileID)/\(sha256Hex(Data("\(argv.joined(separator: "\u{1F}")):\(startedAt.timeIntervalSince1970)".utf8)))",
            profileID: request.profileID,
            caller: [
                "agent": request.requester?.trimmedNonEmpty ?? "local-agent",
                "session_ref": request.sessionRef?.trimmedNonEmpty ?? "agent-session://local",
            ],
            projectRef: request.projectRef?.trimmedNonEmpty ?? "project://local",
            resourceScopeRef: request.resourceScopeRef?.trimmedNonEmpty ?? "resource://local/cli-profile",
            grantClass: profile.grantClass,
            credentialClass: profile.credentialClass,
            authLeaseRef: lease.authLeaseRef,
            grantRef: lease.grantRef,
            argvTemplate: redactedArgvTemplate(profile.argvTemplate),
            argvTemplateDigest: profile.argvTemplateDigest,
            commandDigest: "sha256:\(sha256Hex(Data(([executableURL.path] + argv).joined(separator: "\u{1F}").utf8)))",
            brunoDecisionRef: brunoDecisionRef,
            approvalRef: profile.approvalRequirement == "none" ? "none" : "approval://local/required",
            executionMode: "broker_job",
            startedAt: iso8601String(startedAt),
            completedAt: iso8601String(now()),
            result: rawResult.exitCode == 0 ? "allowed" : "failed",
            cleanupStatus: cleanupStatus,
            redactionState: credentialMaterialPrinted ? "credential_material_observed_metadata_only" : profile.outputRedaction,
            rawCredentialMaterialPrinted: credentialMaterialPrinted,
            output: ToolDecisionOutputMetadata(stdout: rawResult.stdout, stderr: rawResult.stderr)
        )
        return RemoteAuthorityCLIProfileInvocationResult(
            status: rawResult.exitCode == 0 ? "ok" : "failed",
            profileID: request.profileID,
            exitCode: rawResult.exitCode,
            evidence: evidence
        )
    }

    private func evaluateCLIProfileBrunoIfNeeded(
        profile: RemoteAuthorityCLIProfileDescriptor,
        request: RemoteAuthorityCLIProfileRequest,
        argv: [String]
    ) async throws -> String {
        guard profile.brunoGateRef != "none" else {
            return "none"
        }
        guard let brunoEvaluator else {
            throw AegisSecretError.blocked("broker_bruno_denied: Bruno guard is required but unavailable.")
        }
        let decision = try await brunoEvaluator.evaluate(event: .object([
            "schema_version": .string("aegis.broker.bruno_event.v1"),
            "action": .object([
                "kind": .string("broker.cli_profile.run"),
                "profile_id": .string(profile.profileID),
                "tool": .string(profile.tool),
                "argv_template": .array(redactedArgvTemplate(profile.argvTemplate).map { .string($0) }),
                "argv": .array(argv.map { .string(redactSensitiveCLIArgument($0)) }),
                "bruno_gate_ref": .string(profile.brunoGateRef),
            ]),
            "actor": .object([
                "agent": .string(request.requester?.trimmedNonEmpty ?? "local-agent"),
                "session_ref": .string(request.sessionRef?.trimmedNonEmpty ?? "agent-session://local"),
            ]),
            "context": .object([
                "tool_kind": .string("broker_cli_profile"),
                "cwd": .string("[REDACTED_PATH]"),
            ]),
            "redaction_state": .string("metadata_only"),
        ]))
        guard decision.decision == "allow" else {
            throw AegisSecretError.blocked("broker_bruno_denied: \(decision.recommendedNextPrompt ?? decision.reasons.first?.message ?? "Bruno denied the CLI profile.").")
        }
        return "bruno-decision://\(profile.profileID)/\(sha256Hex(Data(argv.joined(separator: "\u{1F}").utf8)))"
    }
}

private func renderArgvTemplate(_ template: [String], parameters: [String: String]) throws -> [String] {
    let expectedKeys = Set(template.compactMap(templateParameterKey))
    let unexpectedKeys = Set(parameters.keys).subtracting(expectedKeys)
    guard unexpectedKeys.isEmpty else {
        throw AegisSecretError.blocked("broker_policy_denied: unsupported CLI profile parameter `\(unexpectedKeys.sorted()[0])`.")
    }

    return try template.map { item in
        guard let key = templateParameterKey(item) else {
            return item
        }
        guard let value = parameters[key]?.trimmedNonEmpty else {
            throw AegisSecretError.blocked("broker_policy_denied: missing CLI profile parameter `\(key)`.")
        }
        guard safeCLIParameter(value) else {
            throw AegisSecretError.blocked("broker_policy_denied: unsafe CLI profile parameter `\(key)`.")
        }
        return value
    }
}

private func templateParameterKey(_ item: String) -> String? {
    guard item.hasPrefix("{{"), item.hasSuffix("}}") else {
        return nil
    }
    return String(item.dropFirst(2).dropLast(2))
}

private func safeCLIParameter(_ value: String) -> Bool {
    value.count <= 512 &&
    !value.contains(where: \.isNewline) &&
    !value.contains("\u{0}") &&
    value.unicodeScalars.allSatisfy(isSafeCLIParameterScalar) &&
    redactionSafe(value)
}

private func isSafeCLIParameterScalar(_ scalar: UnicodeScalar) -> Bool {
    switch scalar.value {
    case 48...57, 65...90, 97...122:
        return true
    default:
        return "._:/+=,-".unicodeScalars.contains(scalar)
    }
}

private func resolveProfileCWD(_ cwd: String?, allowedPrefixes: [String]) throws -> URL? {
    guard let cwd = cwd?.trimmedNonEmpty else {
        throw AegisSecretError.blocked("broker_policy_denied: CLI profile cwd is required.")
    }
    guard cwd.hasPrefix("/") else {
        throw AegisSecretError.blocked("broker_policy_denied: CLI profile cwd must be absolute.")
    }
    guard !cwd.contains("\u{0}"), !cwd.contains(where: \.isNewline) else {
        throw AegisSecretError.blocked("broker_policy_denied: CLI profile cwd is unsafe.")
    }
    let resolvedCWD = URL(fileURLWithPath: cwd, isDirectory: true).standardizedFileURL.path
    let resolvedPrefixes = allowedPrefixes.map { URL(fileURLWithPath: $0, isDirectory: true).standardizedFileURL.path }
    guard resolvedPrefixes.contains(where: { resolvedCWD == $0 || resolvedCWD.hasPrefix($0 + "/") }) else {
        throw AegisSecretError.blocked("broker_policy_denied: CLI profile cwd is outside allowed workspace roots.")
    }
    var isDirectory: ObjCBool = false
    guard FileManager.default.fileExists(atPath: resolvedCWD, isDirectory: &isDirectory), isDirectory.boolValue else {
        throw AegisSecretError.blocked("broker_policy_denied: CLI profile cwd does not exist.")
    }
    return URL(fileURLWithPath: resolvedCWD, isDirectory: true)
}

private func redactedArgvTemplate(_ template: [String]) -> [String] {
    template.map { item in
        if item.hasPrefix("{{"), item.hasSuffix("}}") {
            return "[PARAM]"
        }
        return item
    }
}

private func redactSensitiveCLIArgument(_ value: String) -> String {
    redactionSafe(value) ? value : "[REDACTED]"
}

private func isolatedCLIProfileEnvironment(from environment: [String: String], tempRoot: URL) -> [String: String] {
    var isolated: [String: String] = [:]
    for key in ["PATH", "TMPDIR", "LANG", "LC_ALL", "SSL_CERT_FILE", "SSL_CERT_DIR", "REQUESTS_CA_BUNDLE", "NO_COLOR"] {
        if let value = environment[key]?.trimmedNonEmpty {
            isolated[key] = value
        }
    }
    isolated["HOME"] = tempRoot.path
    isolated["XDG_CONFIG_HOME"] = tempRoot.appendingPathComponent("xdg-config", isDirectory: true).path
    isolated["CLOUDSDK_CONFIG"] = tempRoot.appendingPathComponent("gcloud", isDirectory: true).path
    return isolated
}

private func cleanupCLIProfileTempRoot(_ tempRoot: URL) -> String {
    do {
        try FileManager.default.removeItem(at: tempRoot)
        return "credentials_dropped"
    } catch {
        return "credential_env_dropped_temp_cleanup_failed"
    }
}

private func containsCredentialMaterial(_ result: RawCommandExecutionResult, token: String) -> Bool {
    guard let tokenData = token.data(using: .utf8), !tokenData.isEmpty else {
        return false
    }
    return result.stdout.range(of: tokenData) != nil || result.stderr.range(of: tokenData) != nil
}

public struct WrappedCommandRunner: Sendable {
    public let commandStore: CommandStore
    public let authenticator: DeviceAuthenticator
    public let approvalCache: ApprovalCache
    public let executor: CommandExecutor
    public let environment: [String: String]
    public let secretStore: (any SecretStore)?

    public init(
        commandStore: CommandStore = CommandStore(),
        authenticator: DeviceAuthenticator = LocalDeviceAuthenticator(),
        approvalCache: ApprovalCache = ApprovalCache(),
        executor: CommandExecutor = ProcessCommandExecutor(),
        environment: [String: String] = ProcessInfo.processInfo.environment,
        secretStore: (any SecretStore)? = nil
    ) {
        self.commandStore = commandStore
        self.authenticator = authenticator
        self.approvalCache = approvalCache
        self.executor = executor
        self.environment = environment
        self.secretStore = secretStore
    }

    public func run(
        name: String,
        args: [String],
        cwd: String? = nil,
        requester: String? = nil,
        surface: String = "cli"
    ) async throws -> WrappedCommandInvocationResult {
        let startedAt = Date()
        let wrappedCommand = try commandStore.resolvedCommand(named: name)
        try validate(args: args, for: wrappedCommand)

        guard let executableURL = commandStore.resolveExecutable(named: wrappedCommand.command) else {
            throw AegisSecretError.runtime("Wrapped command `\(wrappedCommand.name)` points to `\(wrappedCommand.command)`, which is not executable on PATH.")
        }

        let workingDirectoryURL = try resolveWorkingDirectory(cwd)
        let requesterLabel = requester?.trimmedNonEmpty ?? "the local agent"
        let reason = "Allow \(requesterLabel) to run wrapped command '\(wrappedCommand.name)'."
        let policyFingerprint = try approvalPolicyFingerprint(for: wrappedCommand, executableURL: executableURL)
        let approvalState = try await approvalCache.authorize(
            agent: requesterLabel,
            command: wrappedCommand,
            executableURL: executableURL,
            policyFingerprint: policyFingerprint,
            reason: reason,
            authenticator: authenticator
        )

        var executionEnvironment = environment
        for (key, value) in wrappedCommand.environment {
            executionEnvironment[key] = try resolvedEnvironmentValue(
                value,
                environmentKey: key,
                commandName: wrappedCommand.name,
                requester: requesterLabel
            )
        }

        let rawResult = try await executor.execute(
            CommandExecutionRequest(
                executableURL: executableURL,
                arguments: args,
                environment: executionEnvironment,
                currentDirectoryURL: workingDirectoryURL,
                timeoutSeconds: wrappedCommand.timeoutSeconds,
                maxOutputBytes: wrappedCommand.maxOutputBytes
            )
        )

        let stdout = String(decoding: rawResult.stdout, as: UTF8.self)
        let stderr = String(decoding: rawResult.stderr, as: UTF8.self)
        let stdoutJSON = try decodeJSONIfPresent(rawResult.stdout)
        let receipt = ToolDecisionReceipt(
            surface: surface,
            toolName: "run_command",
            commandName: wrappedCommand.name,
            argv: [executableURL.path] + args,
            cwd: workingDirectoryURL?.path,
            requester: requesterLabel,
            matchedPolicy: matchedPolicy(
                for: wrappedCommand,
                executableURL: executableURL,
                policyFingerprint: policyFingerprint
            ),
            decision: "allow",
            approvalState: approvalState,
            startedAt: iso8601String(startedAt),
            completedAt: iso8601String(Date()),
            exitCode: rawResult.exitCode,
            stdoutTruncated: false,
            stderrTruncated: false,
            output: ToolDecisionOutputMetadata(stdout: rawResult.stdout, stderr: rawResult.stderr),
            error: nil
        )

        return WrappedCommandInvocationResult(
            exitCode: rawResult.exitCode,
            stdout: stdout,
            stderr: stderr,
            stdoutJSON: stdoutJSON,
            stdoutTruncated: false,
            stderrTruncated: false,
            receipt: receipt
        )
    }

    public func deniedReceipt(
        name: String,
        args: [String],
        cwd: String?,
        requester: String?,
        surface: String,
        error: String,
        startedAt: Date = Date()
    ) -> ToolDecisionReceipt {
        let requesterLabel = requester?.trimmedNonEmpty ?? "the local agent"
        var matchedPolicy: ToolDecisionMatchedPolicy?
        var argv = [name] + args

        if let wrappedCommand = try? commandStore.resolvedCommand(named: name) {
            let executableURL = commandStore.resolveExecutable(named: wrappedCommand.command)
            let policyFingerprint = executableURL.flatMap { try? approvalPolicyFingerprint(for: wrappedCommand, executableURL: $0) }
            matchedPolicy = self.matchedPolicy(
                for: wrappedCommand,
                executableURL: executableURL,
                policyFingerprint: policyFingerprint
            )
            if let executableURL {
                argv = [executableURL.path] + args
            }
        }

        return ToolDecisionReceipt(
            surface: surface,
            toolName: "run_command",
            commandName: name,
            argv: argv,
            cwd: cwd,
            requester: requesterLabel,
            matchedPolicy: matchedPolicy,
            decision: "deny",
            approvalState: matchedPolicy == nil ? .notEvaluated : .deniedByPolicy,
            startedAt: iso8601String(startedAt),
            completedAt: iso8601String(Date()),
            exitCode: nil,
            stdoutTruncated: false,
            stderrTruncated: false,
            output: nil,
            error: error
        )
    }

    private func matchedPolicy(
        for command: ResolvedWrappedCommand,
        executableURL: URL?,
        policyFingerprint: String?
    ) -> ToolDecisionMatchedPolicy {
        ToolDecisionMatchedPolicy(
            commandName: command.name,
            command: command.command,
            executablePath: executableURL?.path,
            policyFingerprint: policyFingerprint,
            approvalWindowSeconds: command.approvalWindowSeconds,
            timeoutSeconds: command.timeoutSeconds,
            maxOutputBytes: command.maxOutputBytes,
            denyPrefixes: command.denyPrefixes,
            brokerRequiredPrefixes: command.brokerRequiredPrefixes,
            allowPrefixes: command.allowPrefixes,
            denyFlags: command.denyFlags.sorted()
        )
    }

    private func resolvedEnvironmentValue(
        _ value: String,
        environmentKey: String,
        commandName: String,
        requester: String
    ) throws -> String {
        guard let secretKey = secretReferenceKey(from: value) else {
            return value
        }

        guard let secretStore else {
            throw AegisSecretError.runtime("Wrapped command `\(commandName)` requires secret `\(secretKey)` for environment variable `\(environmentKey)`, but no secret store is configured.")
        }

        let reason = "Allow \(requester) to inject secret '\(secretKey)' into wrapped command '\(commandName)'."
        let secretData = try secretStore.readSecret(for: secretKey, reason: reason)
        guard let secret = String(data: secretData, encoding: .utf8) else {
            throw AegisSecretError.runtime("Secret `\(secretKey)` for wrapped command `\(commandName)` is not valid UTF-8.")
        }
        return secret
    }

    private func validate(args: [String], for command: ResolvedWrappedCommand) throws {
        for argument in args {
            if command.denyFlags.contains(argument) || command.denyFlags.contains(where: { argument.hasPrefix("\($0)=") }) {
                throw AegisSecretError.runtime("Flag `\(argument)` is not allowed for wrapped command `\(command.name)`.")
            }
        }

        if !command.allowPrefixes.isEmpty && !command.allowPrefixes.contains(where: { matchesPrefix(args, prefix: $0) }) {
            throw AegisSecretError.runtime("Arguments are not allowed for wrapped command `\(command.name)`.")
        }

        if let matchedPrefix = command.denyPrefixes.first(where: { matchesPrefix(args, prefix: $0) }) {
            let renderedPrefix = matchedPrefix.joined(separator: " ")
            let suggestion = deniedPrefixSuggestion(for: command, matchedPrefix: matchedPrefix)
            throw AegisSecretError.runtime("The `\(renderedPrefix)` subcommand is not allowed for wrapped command `\(command.name)`. \(suggestion)")
        }
    }

    private func deniedPrefixSuggestion(for command: ResolvedWrappedCommand, matchedPrefix: [String]) -> String {
        if command.name == "gh", matchedPrefix == ["auth"] {
            return "Try a non-auth GitHub command such as `gh api /user` instead."
        }

        if !command.allowPrefixes.isEmpty {
            return "Try one of the allowed subcommands for `\(command.name)` instead."
        }

        return "Try a different non-sensitive subcommand for `\(command.name)` instead."
    }

    private func resolveWorkingDirectory(_ cwd: String?) throws -> URL? {
        guard let cwd = cwd?.trimmedNonEmpty else {
            return nil
        }

        let expanded = expandUserPath(cwd)
        guard expanded.hasPrefix("/") else {
            throw AegisSecretError.runtime("Working directory must be an absolute path.")
        }

        var isDirectory: ObjCBool = false
        guard FileManager.default.fileExists(atPath: expanded, isDirectory: &isDirectory), isDirectory.boolValue else {
            throw AegisSecretError.runtime("Working directory `\(expanded)` does not exist.")
        }

        return URL(fileURLWithPath: expanded, isDirectory: true)
    }

    private func decodeJSONIfPresent(_ data: Data) throws -> JSONValue? {
        guard let text = String(data: data, encoding: .utf8)?.trimmedNonEmpty else {
            return nil
        }

        let trimmedData = Data(text.utf8)
        do {
            return try JSONDecoder().decode(JSONValue.self, from: trimmedData)
        } catch {
            return nil
        }
    }
}

private func matchesPrefix(_ args: [String], prefix: [String]) -> Bool {
    guard !prefix.isEmpty, args.count >= prefix.count else {
        return false
    }
    return Array(args.prefix(prefix.count)) == prefix
}

private func secretReferenceKey(from value: String) -> String? {
    guard value.hasPrefix(secretEnvironmentReferencePrefix) else {
        return nil
    }

    return String(value.dropFirst(secretEnvironmentReferencePrefix.count)).trimmedNonEmpty
}

public struct ShellGuardResult: Equatable, Sendable {
    public let allowed: Bool
    public let message: String

    public init(allowed: Bool, message: String = "") {
        self.allowed = allowed
        self.message = message
    }
}

public func codexPreToolUseDenyHookOutput(reason: String) throws -> String {
    let payload: [String: Any] = [
        "hookSpecificOutput": [
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason
        ]
    ]
    let data = try JSONSerialization.data(withJSONObject: payload, options: [.sortedKeys])
    guard let output = String(data: data, encoding: .utf8) else {
        throw AegisSecretError.runtime("Failed to encode Codex PreToolUse deny output.")
    }
    return output
}

public struct ShellGuardWrappedCommand: Equatable, Sendable {
    public let name: String
    public let denyPrefixes: [[String]]
    public let brokerRequiredPrefixes: [[String]]

    public init(
        name: String,
        denyPrefixes: [[String]] = [],
        brokerRequiredPrefixes: [[String]] = []
    ) {
        self.name = name
        self.denyPrefixes = denyPrefixes
        self.brokerRequiredPrefixes = brokerRequiredPrefixes
    }
}

public struct BrunoGuardReason: Decodable, Equatable, Sendable {
    public let code: String
    public let severity: String
    public let message: String
}

public struct BrunoGuardDecision: Decodable, Equatable, Sendable {
    public let decision: String
    public let reasons: [BrunoGuardReason]
    public let requiredEvidence: [String]
    public let recommendedNextPrompt: String?

    private enum CodingKeys: String, CodingKey {
        case decision
        case reasons
        case requiredEvidence = "required_evidence"
        case recommendedNextPrompt = "recommended_next_prompt"
    }

    public init(
        decision: String,
        reasons: [BrunoGuardReason] = [],
        requiredEvidence: [String] = [],
        recommendedNextPrompt: String? = nil
    ) {
        self.decision = decision
        self.reasons = reasons
        self.requiredEvidence = requiredEvidence
        self.recommendedNextPrompt = recommendedNextPrompt
    }
}

public protocol BrunoGuardEvaluating: Sendable {
    func evaluate(event: JSONValue) async throws -> BrunoGuardDecision
}

public struct ProcessBrunoGuardEvaluator: BrunoGuardEvaluating {
    public let commandStore: CommandStore
    public let executor: CommandExecutor
    public let environment: [String: String]
    public let timeoutSeconds: Int
    public let maxOutputBytes: Int

    public init(
        commandStore: CommandStore = CommandStore(),
        executor: CommandExecutor = ProcessCommandExecutor(),
        environment: [String: String] = ProcessInfo.processInfo.environment,
        timeoutSeconds: Int = 5,
        maxOutputBytes: Int = 64 * 1024
    ) {
        self.commandStore = commandStore
        self.executor = executor
        self.environment = environment
        self.timeoutSeconds = timeoutSeconds
        self.maxOutputBytes = maxOutputBytes
    }

    public func evaluate(event: JSONValue) async throws -> BrunoGuardDecision {
        guard let brunoURL = commandStore.resolveExecutable(named: "bruno") else {
            throw AegisSecretError.runtime("Bruno guard binary `bruno` was not found on PATH.")
        }

        let fileManager = FileManager.default
        let eventURL = fileManager.temporaryDirectory
            .appendingPathComponent("aegis-broker-bruno-\(UUID().uuidString).json")
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        try encoder.encode(event).write(to: eventURL, options: .atomic)
        defer { try? fileManager.removeItem(at: eventURL) }

        let result = try await executor.execute(
            CommandExecutionRequest(
                executableURL: brunoURL,
                arguments: ["guard", "--file", eventURL.path, "--json"],
                environment: environment,
                currentDirectoryURL: nil,
                timeoutSeconds: timeoutSeconds,
                maxOutputBytes: maxOutputBytes
            )
        )

        guard let decision = try? JSONDecoder().decode(BrunoGuardDecision.self, from: result.stdout) else {
            throw AegisSecretError.runtime("Bruno guard returned malformed output.")
        }

        if result.exitCode != 0 && result.exitCode != 1 {
            throw AegisSecretError.runtime("Bruno guard failed with exit code \(result.exitCode).")
        }

        return decision
    }
}

public struct ShellBypassGuard: Sendable {
    public let wrappedCommands: [String: ShellGuardWrappedCommand]
    public let brunoEvaluator: (any BrunoGuardEvaluating)?

    public init(
        wrappedCommands: [ShellGuardWrappedCommand],
        brunoEvaluator: (any BrunoGuardEvaluating)? = ProcessBrunoGuardEvaluator()
    ) {
        self.wrappedCommands = Dictionary(uniqueKeysWithValues: wrappedCommands.map { ($0.name, $0) })
        self.brunoEvaluator = brunoEvaluator
    }

    public init(
        resolvedCommands: [ResolvedWrappedCommand],
        brunoEvaluator: (any BrunoGuardEvaluating)? = ProcessBrunoGuardEvaluator()
    ) {
        self.init(
            wrappedCommands: resolvedCommands.map {
                ShellGuardWrappedCommand(
                    name: $0.name,
                    denyPrefixes: $0.denyPrefixes,
                    brokerRequiredPrefixes: $0.brokerRequiredPrefixes
                )
            },
            brunoEvaluator: brunoEvaluator
        )
    }

    public init(
        wrappedCommandNames: Set<String>,
        brunoEvaluator: (any BrunoGuardEvaluating)? = nil
    ) {
        self.init(
            wrappedCommands: wrappedCommandNames.map { ShellGuardWrappedCommand(name: $0) },
            brunoEvaluator: brunoEvaluator
        )
    }

    public func evaluate(command: String) async -> ShellGuardResult {
        for segment in shellSegments(command) {
            let tokens = shellTokens(segment)
            guard let executableIndex = executableTokenIndex(in: tokens) else {
                continue
            }

            let executableName = lastPathComponent(tokens[executableIndex])
            let args = Array(tokens.dropFirst(executableIndex + 1))
            if executableName == "gh", let protected = protectedGitHubMutation(args: args) {
                return await evaluateProtectedGitHubMutation(protected, commandName: executableName, args: args)
            }

            if directDenied(commandName: executableName, args: args) {
                return directDeniedBlocked(commandName: executableName)
            }

            if brokerRequired(commandName: executableName, args: args) {
                return brokerRequiredBlocked(commandName: executableName)
            }

            if executableName == "aegis-secret",
               tokens.count > executableIndex + 2,
               tokens[executableIndex + 1] == "run",
               wrappedCommands[tokens[executableIndex + 2]] != nil {
                let commandName = tokens[executableIndex + 2]
                let passthroughArgs = passthroughRunArguments(tokens: tokens, start: executableIndex + 3)
                if commandName == "gh", let protected = protectedGitHubMutation(args: passthroughArgs) {
                    return await evaluateProtectedGitHubMutation(protected, commandName: commandName, args: passthroughArgs)
                }
                if directDenied(commandName: commandName, args: passthroughArgs) {
                    return directDeniedBlocked(commandName: commandName)
                }
                if brokerRequired(commandName: commandName, args: passthroughArgs) {
                    return brokerRequiredBlocked(commandName: commandName)
                }
            }
        }

        return ShellGuardResult(allowed: true)
    }

    private func evaluateProtectedGitHubMutation(
        _ mutation: ProtectedGitHubMutation,
        commandName: String,
        args: [String]
    ) async -> ShellGuardResult {
        if mutation.kind == "github.pr.merge" {
            return ShellGuardResult(
                allowed: false,
                message: "Blocked direct PR merge `\(commandName) \(redactedArguments(args).joined(separator: " "))`: use Aegis Broker MCP `run_remote_action` with `github.pr.merge` so Broker can derive and enforce `git config user.email`."
            )
        }

        guard let brunoEvaluator else {
            return ShellGuardResult(allowed: true)
        }

        do {
            let decision = try await brunoEvaluator.evaluate(event: brunoEvent(for: mutation, commandName: commandName, args: args))
            if decision.decision != "allow" {
                return ShellGuardResult(
                    allowed: false,
                    message: "Blocked protected GitHub mutation `\(commandName) \(redactedArguments(args).joined(separator: " "))`: \(brunoMessage(from: decision))"
                )
            }
            return ShellGuardResult(allowed: true)
        } catch {
            return ShellGuardResult(
                allowed: false,
                message: "Blocked protected GitHub mutation `\(commandName) \(redactedArguments(args).joined(separator: " "))`: Bruno guard failed closed: \(errorDescription(error))"
            )
        }
    }

    private func brunoMessage(from decision: BrunoGuardDecision) -> String {
        if let prompt = decision.recommendedNextPrompt?.trimmedNonEmpty {
            return prompt
        }
        if let reason = decision.reasons.first?.message.trimmedNonEmpty {
            return reason
        }
        if let evidence = decision.requiredEvidence.first {
            return "Required evidence: \(evidence)."
        }
        return "Bruno denied the protected mutation."
    }

    private func errorDescription(_ error: Error) -> String {
        if let aegisError = error as? AegisSecretError {
            return aegisError.description
        }
        return error.localizedDescription
    }

    private func brokerRequired(commandName: String, args: [String]) -> Bool {
        guard let command = wrappedCommands[commandName] else {
            return false
        }
        return command.brokerRequiredPrefixes.contains { matchesPrefix(args, prefix: $0) }
    }

    private func directDenied(commandName: String, args: [String]) -> Bool {
        guard let command = wrappedCommands[commandName] else {
            return false
        }
        return command.denyPrefixes.contains { matchesPrefix(args, prefix: $0) }
    }

    private func directDeniedBlocked(commandName: String) -> ShellGuardResult {
        ShellGuardResult(
            allowed: false,
            message: "Blocked direct shell use of denied command `\(commandName)`. Try a safer non-sensitive subcommand, or use Aegis Broker MCP only for configured privileged actions."
        )
    }

    private func brokerRequiredBlocked(commandName: String) -> ShellGuardResult {
        ShellGuardResult(
            allowed: false,
            message: "Blocked direct shell use of privileged command `\(commandName)`. Use the Aegis Broker MCP `list_commands` tool, then `run_command` for `\(commandName)`."
        )
    }

    private func passthroughRunArguments(tokens: [String], start: Int) -> [String] {
        var args = Array(tokens.dropFirst(start))
        if args.first == "--" {
            args.removeFirst()
        }
        return args
    }

    private struct ProtectedGitHubMutation {
        let kind: String
        let target: String?
        let repo: String?
        let evidenceRefs: [JSONValue]
    }

    private func protectedGitHubMutation(args: [String]) -> ProtectedGitHubMutation? {
        guard args.count >= 2 else {
            return nil
        }

        let normalizedArgs = args.first == "gh" ? Array(args.dropFirst()) : args
        guard normalizedArgs.count >= 2 else {
            return nil
        }

        let scope = normalizedArgs[0]
        let action = normalizedArgs[1]
        guard let kind = protectedGitHubKind(scope: scope, action: action) else {
            return nil
        }

        return ProtectedGitHubMutation(
            kind: kind,
            target: firstPositionalTarget(in: Array(normalizedArgs.dropFirst(2))),
            repo: optionValue(in: normalizedArgs, names: ["--repo", "-R"]),
            evidenceRefs: evidenceRefs(in: normalizedArgs)
        )
    }

    private func protectedGitHubKind(scope: String, action: String) -> String? {
        switch (scope, action) {
        case ("issue", "close"), ("issue", "edit"), ("issue", "reopen"), ("issue", "lock"), ("issue", "unlock"), ("issue", "transfer"):
            return "github.issue.\(action)"
        case ("pr", "merge"), ("pr", "close"), ("pr", "edit"), ("pr", "ready"), ("pr", "lock"), ("pr", "unlock"):
            return "github.pr.\(action)"
        case ("release", "create"), ("release", "edit"), ("release", "delete"):
            return "github.release.\(action)"
        default:
            return nil
        }
    }

    private func brunoEvent(for mutation: ProtectedGitHubMutation, commandName: String, args: [String]) -> JSONValue {
        var subjectRefs: [String: JSONValue] = [:]
        if let repo = mutation.repo?.trimmedNonEmpty {
            subjectRefs["repo"] = .string("github://\(repo)")
            if let target = mutation.target?.trimmedNonEmpty {
                if mutation.kind.hasPrefix("github.issue.") {
                    subjectRefs["issue"] = .string("github://\(repo)/issues/\(target)")
                } else if mutation.kind.hasPrefix("github.pr.") {
                    subjectRefs["pr"] = .string("github://\(repo)/pull/\(target)")
                } else if mutation.kind.hasPrefix("github.release.") {
                    subjectRefs["release"] = .string("github://\(repo)/releases/tag/\(target)")
                }
            }
        }

        return .object([
            "schema_version": .string("aegis.broker.bruno_event.v1"),
            "action": .object([
                "kind": .string(mutation.kind),
                "command": .string(commandName),
                "argv": .array(redactedArguments(args).map { .string($0) }),
            ]),
            "subject_refs": .object(subjectRefs),
            "actor": .object([
                "agent": .string("local-agent"),
                "session_ref": .string("agent-session://local"),
            ]),
            "context": .object([
                "tool_kind": .string("shell"),
                "cwd": .string("[REDACTED_PATH]"),
            ]),
            "redaction_state": .string("metadata_only"),
            "evidence_refs": .array(mutation.evidenceRefs),
        ])
    }

    private func redactedArguments(_ args: [String]) -> [String] {
        var redacted: [String] = []
        var redactNext = false
        for arg in args {
            if redactNext {
                redacted.append("[REDACTED]")
                redactNext = false
                continue
            }
            redacted.append(arg)
            if ["--comment", "--body", "--notes", "--message", "-m"].contains(arg) {
                redactNext = true
            } else if ["--comment=", "--body=", "--notes=", "--message="].contains(where: { arg.hasPrefix($0) }) {
                let prefix = arg.prefix { $0 != "=" }
                redacted[redacted.count - 1] = "\(prefix)=[REDACTED]"
            }
        }
        return redacted
    }

    private func firstPositionalTarget(in args: [String]) -> String? {
        var skipNext = false
        for arg in args {
            if skipNext {
                skipNext = false
                continue
            }
            if arg.hasPrefix("--") {
                if !arg.contains("=") {
                    skipNext = true
                }
                continue
            }
            if arg.hasPrefix("-") {
                skipNext = true
                continue
            }
            return arg
        }
        return nil
    }

    private func optionValue(in args: [String], names: Set<String>) -> String? {
        for (index, arg) in args.enumerated() {
            for name in names {
                if arg == name, args.indices.contains(index + 1) {
                    return args[index + 1]
                }
                if arg.hasPrefix("\(name)=") {
                    return String(arg.dropFirst(name.count + 1))
                }
            }
        }
        return nil
    }

    private func evidenceRefs(in args: [String]) -> [JSONValue] {
        var refs: [JSONValue] = []
        for value in messageValues(in: args) {
            refs.append(contentsOf: artifactRefs(in: value).map { ref in
                .object([
                    "ref": .string(ref),
                    "kind": .string("local_evidence"),
                    "redaction_state": .string("metadata_only"),
                ])
            })
        }
        return refs
    }

    private func messageValues(in args: [String]) -> [String] {
        var values: [String] = []
        var captureNext = false
        for arg in args {
            if captureNext {
                values.append(arg)
                captureNext = false
                continue
            }
            if ["--comment", "--body", "--notes", "--message", "-m"].contains(arg) {
                captureNext = true
                continue
            }
            for prefix in ["--comment=", "--body=", "--notes=", "--message="] where arg.hasPrefix(prefix) {
                values.append(String(arg.dropFirst(prefix.count)))
            }
        }
        return values
    }

    private func artifactRefs(in value: String) -> [String] {
        value
            .split(whereSeparator: { $0.isWhitespace || $0 == "," || $0 == ")" || $0 == "]" })
            .map(String.init)
            .filter { $0.hasPrefix("artifact://") || $0.hasPrefix("evidence://") }
    }

    private func executableTokenIndex(in tokens: [String]) -> Int? {
        var index = 0
        if tokens.first == "env" {
            index = 1
            while index < tokens.count {
                if isEnvironmentAssignment(tokens[index]) {
                    index += 1
                } else if tokens[index] == "--" {
                    index += 1
                    break
                } else if tokens[index] == "-u" || tokens[index] == "--unset" || tokens[index] == "-C" || tokens[index] == "--chdir" {
                    index += 2
                } else if tokens[index].hasPrefix("-") {
                    index += 1
                } else {
                    break
                }
            }
        }

        while index < tokens.count, isEnvironmentAssignment(tokens[index]) {
            index += 1
        }

        return index < tokens.count ? index : nil
    }

    private func isEnvironmentAssignment(_ token: String) -> Bool {
        guard let equals = token.firstIndex(of: "="), equals != token.startIndex else {
            return false
        }
        return token[..<equals].allSatisfy { character in
            character == "_" || character.isLetter || character.isNumber
        }
    }

    private func lastPathComponent(_ token: String) -> String {
        URL(fileURLWithPath: token).lastPathComponent
    }

    private func shellSegments(_ command: String) -> [String] {
        var segments: [String] = []
        var current = ""
        var quote: Character?
        var escaped = false

        for character in command {
            if escaped {
                current.append(character)
                escaped = false
                continue
            }

            if character == "\\" {
                current.append(character)
                escaped = true
                continue
            }

            if let activeQuote = quote {
                current.append(character)
                if character == activeQuote {
                    quote = nil
                }
                continue
            }

            if character == "'" || character == "\"" {
                quote = character
                current.append(character)
                continue
            }

            if character == ";" || character == "|" || character == "&" || character == "(" || character == ")" {
                appendSegment(current, to: &segments)
                current = ""
                continue
            }

            current.append(character)
        }

        appendSegment(current, to: &segments)
        return segments
    }

    private func appendSegment(_ segment: String, to segments: inout [String]) {
        let trimmed = segment.trimmingCharacters(in: .whitespacesAndNewlines)
        if !trimmed.isEmpty {
            segments.append(trimmed)
        }
    }

    private func shellTokens(_ segment: String) -> [String] {
        var tokens: [String] = []
        var current = ""
        var quote: Character?
        var escaped = false

        for character in segment {
            if escaped {
                current.append(character)
                escaped = false
                continue
            }

            if character == "\\" {
                escaped = true
                continue
            }

            if let activeQuote = quote {
                if character == activeQuote {
                    quote = nil
                } else {
                    current.append(character)
                }
                continue
            }

            if character == "'" || character == "\"" {
                quote = character
                continue
            }

            if character.isWhitespace {
                if !current.isEmpty {
                    tokens.append(current)
                    current = ""
                }
                continue
            }

            current.append(character)
        }

        if !current.isEmpty {
            tokens.append(current)
        }
        return tokens
    }
}

public struct ShellHookCommandExtractor {
    public init() {}

    public func extract(from data: Data) throws -> String {
        guard !data.isEmpty else {
            throw AegisSecretError.runtime("No hook input was provided.")
        }

        guard let json = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw AegisSecretError.runtime("Hook input was not a JSON object.")
        }

        if let command = stringValue(named: "command", in: json) ?? stringValue(named: "cmd", in: json) {
            return command
        }

        if let toolInput = json["tool_input"] as? [String: Any],
           let command = stringValue(named: "command", in: toolInput) ?? stringValue(named: "cmd", in: toolInput) {
            return command
        }

        if let toolInput = json["toolInput"] as? [String: Any],
           let command = stringValue(named: "command", in: toolInput) ?? stringValue(named: "cmd", in: toolInput) {
            return command
        }

        throw AegisSecretError.runtime("Hook input did not include a shell command.")
    }

    private func stringValue(named name: String, in object: [String: Any]) -> String? {
        object[name] as? String
    }
}

public enum SecretInputMode: Equatable {
    case prompt
    case stdin
}

public enum WrappedCommandManagementCommand: Equatable {
    case list
    case show(name: String)
    case validateCurrent(name: String?)
    case validateFile(path: String)
    case importFile(path: String)
}

public enum ApprovalManagementCommand: Equatable {
    case status(command: String?, agent: String?)
}

public enum GuardCommand: Equatable {
    case shell(command: String?)
}

public enum KeychainRecoveryCommand: Equatable {
    case diagnose(sourceApp: String)
    case migrate(sourceApp: String, selection: KeychainRecoverySelection, overwrite: Bool)
}

public enum KeychainRecoverySelection: Equatable {
    case allMissing
    case key(String)
}

public enum CLICommand: Equatable {
    case set(key: String, inputMode: SecretInputMode)
    case get(key: String, agentName: String)
    case delete(key: String)
    case list
    case installUser
    case command(WrappedCommandManagementCommand)
    case approval(ApprovalManagementCommand)
    case guardCommand(GuardCommand)
    case recovery(KeychainRecoveryCommand)
    case run(name: String, args: [String])
    case help
}

public struct CommandParser {
    public init() {}

    public func parse(_ arguments: [String], stdinIsTTY: Bool) throws -> CLICommand {
        guard let command = arguments.first else {
            return .help
        }

        switch command {
        case "set":
            return try parseSet(Array(arguments.dropFirst()), stdinIsTTY: stdinIsTTY)
        case "get":
            return try parseGet(Array(arguments.dropFirst()))
        case "delete":
            return try parseDelete(Array(arguments.dropFirst()))
        case "list":
            guard arguments.count == 1 else {
                throw AegisSecretError.usage("`list` does not accept additional arguments.")
            }
            return .list
        case "install-user":
            guard arguments.count == 1 else {
                throw AegisSecretError.usage("`install-user` does not accept additional arguments.")
            }
            return .installUser
        case "command":
            return try parseCommand(Array(arguments.dropFirst()))
        case "approval":
            return try parseApproval(Array(arguments.dropFirst()))
        case "guard":
            return try parseGuard(Array(arguments.dropFirst()))
        case "recovery":
            return try parseRecovery(Array(arguments.dropFirst()))
        case "run":
            return try parseRun(Array(arguments.dropFirst()))
        case "help", "--help", "-h":
            return .help
        default:
            throw AegisSecretError.usage("Unknown command `\(command)`.")
        }
    }

    private func parseSet(_ arguments: [String], stdinIsTTY: Bool) throws -> CLICommand {
        guard let key = arguments.first, !key.hasPrefix("-") else {
            throw AegisSecretError.usage("`set` requires a secret key.")
        }

        var useStdin = !stdinIsTTY
        var index = 1
        while index < arguments.count {
            let argument = arguments[index]
            switch argument {
            case "--stdin":
                useStdin = true
            default:
                throw AegisSecretError.usage("Unknown argument for `set`: `\(argument)`.")
            }
            index += 1
        }

        return .set(key: key, inputMode: useStdin ? .stdin : .prompt)
    }

    private func parseGet(_ arguments: [String]) throws -> CLICommand {
        guard let key = arguments.first, !key.hasPrefix("-") else {
            throw AegisSecretError.usage("`get` requires a secret key.")
        }

        var agentName: String?
        var index = 1
        while index < arguments.count {
            switch arguments[index] {
            case "--agent":
                let nextIndex = index + 1
                guard nextIndex < arguments.count else {
                    throw AegisSecretError.usage("`get` requires a value after `--agent`.")
                }
                agentName = arguments[nextIndex]
                index += 2
            default:
                throw AegisSecretError.usage("Unknown argument for `get`: `\(arguments[index])`.")
            }
        }

        guard let agentName, !agentName.isEmpty else {
            throw AegisSecretError.usage("`get` requires `--agent <name>` so the approval prompt identifies the caller.")
        }

        return .get(key: key, agentName: agentName)
    }

    private func parseDelete(_ arguments: [String]) throws -> CLICommand {
        guard arguments.count == 1, let key = arguments.first, !key.hasPrefix("-") else {
            throw AegisSecretError.usage("`delete` requires exactly one secret key.")
        }
        return .delete(key: key)
    }

    private func parseCommand(_ arguments: [String]) throws -> CLICommand {
        guard let subcommand = arguments.first else {
            throw AegisSecretError.usage("`command` requires a subcommand.")
        }

        let remaining = Array(arguments.dropFirst())
        switch subcommand {
        case "list":
            guard remaining.isEmpty else {
                throw AegisSecretError.usage("`command list` does not accept additional arguments.")
            }
            return .command(.list)
        case "show":
            guard remaining.count == 1 else {
                throw AegisSecretError.usage("`command show` requires a wrapped command name.")
            }
            return .command(.show(name: remaining[0]))
        case "validate":
            if remaining.isEmpty {
                return .command(.validateCurrent(name: nil))
            }
            if remaining.count == 2 && remaining[0] == "--file" {
                return .command(.validateFile(path: remaining[1]))
            }
            if remaining.count == 1, !remaining[0].hasPrefix("-") {
                return .command(.validateCurrent(name: remaining[0]))
            }
            throw AegisSecretError.usage("Usage: `aegis-secret command validate [<name> | --file <path>]`.")
        case "import":
            guard remaining.count == 1 else {
                throw AegisSecretError.usage("`command import` requires a JSON file path.")
            }
            return .command(.importFile(path: remaining[0]))
        default:
            throw AegisSecretError.usage("Unknown command subcommand `\(subcommand)`.")
        }
    }

    private func parseApproval(_ arguments: [String]) throws -> CLICommand {
        guard arguments.first == "status" else {
            throw AegisSecretError.usage("`approval` requires the `status` subcommand.")
        }

        var commandName: String?
        var agentName: String?
        var index = 1
        while index < arguments.count {
            let argument = arguments[index]
            switch argument {
            case "--agent":
                let nextIndex = index + 1
                guard nextIndex < arguments.count else {
                    throw AegisSecretError.usage("`approval status --agent` requires a value.")
                }
                agentName = arguments[nextIndex]
                index += 2
            default:
                guard !argument.hasPrefix("-"), commandName == nil else {
                    throw AegisSecretError.usage("Usage: `aegis-secret approval status [<command>] [--agent <agent>]`.")
                }
                commandName = argument
                index += 1
            }
        }

        return .approval(.status(command: commandName, agent: agentName))
    }

    private func parseGuard(_ arguments: [String]) throws -> CLICommand {
        guard arguments.first == "shell" else {
            throw AegisSecretError.usage("`guard` requires the `shell` subcommand.")
        }

        let remaining = Array(arguments.dropFirst())
        if remaining.isEmpty {
            return .guardCommand(.shell(command: nil))
        }

        guard remaining.count == 2, remaining[0] == "--command" else {
            throw AegisSecretError.usage("Usage: `aegis-secret guard shell [--command <shell-command>]`.")
        }

        return .guardCommand(.shell(command: remaining[1]))
    }

    private func parseRecovery(_ arguments: [String]) throws -> CLICommand {
        guard let subcommand = arguments.first else {
            throw AegisSecretError.usage("`recovery` requires a subcommand.")
        }

        var sourceApp: String?
        var selection: KeychainRecoverySelection?
        var overwrite = false
        var index = 1
        while index < arguments.count {
            let argument = arguments[index]
            switch argument {
            case "--source-app":
                let nextIndex = index + 1
                guard nextIndex < arguments.count else {
                    throw AegisSecretError.usage("`recovery \(subcommand) --source-app` requires a path.")
                }
                sourceApp = arguments[nextIndex]
                index += 2
            case "--all":
                guard subcommand == "migrate" else {
                    throw AegisSecretError.usage("`recovery diagnose` does not accept `--all`.")
                }
                guard selection == nil else {
                    throw AegisSecretError.usage("Choose either `--all` or `--key`, not both.")
                }
                selection = .allMissing
                index += 1
            case "--key":
                guard subcommand == "migrate" else {
                    throw AegisSecretError.usage("`recovery diagnose` does not accept `--key`.")
                }
                let nextIndex = index + 1
                guard nextIndex < arguments.count else {
                    throw AegisSecretError.usage("`recovery migrate --key` requires a key name.")
                }
                guard selection == nil else {
                    throw AegisSecretError.usage("Choose either `--all` or `--key`, not both.")
                }
                selection = .key(arguments[nextIndex])
                index += 2
            case "--overwrite":
                guard subcommand == "migrate" else {
                    throw AegisSecretError.usage("`recovery diagnose` does not accept `--overwrite`.")
                }
                overwrite = true
                index += 1
            default:
                throw AegisSecretError.usage("Unknown argument for `recovery \(subcommand)`: `\(argument)`.")
            }
        }

        guard let sourceApp, !sourceApp.isEmpty else {
            throw AegisSecretError.usage("`recovery \(subcommand)` requires `--source-app <path-to-aegis-secret-binary>`.")
        }

        switch subcommand {
        case "diagnose":
            return .recovery(.diagnose(sourceApp: sourceApp))
        case "migrate":
            guard let selection else {
                throw AegisSecretError.usage("`recovery migrate` requires `--all` or `--key <name>`.")
            }
            return .recovery(.migrate(sourceApp: sourceApp, selection: selection, overwrite: overwrite))
        default:
            throw AegisSecretError.usage("Unknown recovery subcommand `\(subcommand)`.")
        }
    }

    private func parseRun(_ arguments: [String]) throws -> CLICommand {
        guard let name = arguments.first, !name.hasPrefix("-") else {
            throw AegisSecretError.usage("`run` requires a wrapped command name.")
        }

        let remaining = Array(arguments.dropFirst())
        guard remaining.isEmpty || remaining.first == "--" else {
            throw AegisSecretError.usage("Usage: `aegis-secret run <name> -- <args...>`.")
        }
        let args = remaining.isEmpty ? [] : Array(remaining.dropFirst())
        return .run(name: name, args: args)
    }
}

public struct SignedAegisAppIdentity: Equatable, Sendable {
    public let executablePath: String
    public let teamIdentifier: String
    public let applicationIdentifier: String
    public let keychainAccessGroups: [String]

    public init(
        executablePath: String,
        teamIdentifier: String,
        applicationIdentifier: String,
        keychainAccessGroups: [String]
    ) {
        self.executablePath = executablePath
        self.teamIdentifier = teamIdentifier
        self.applicationIdentifier = applicationIdentifier
        self.keychainAccessGroups = keychainAccessGroups
    }

    public var primaryKeychainAccessGroup: String {
        keychainAccessGroups.first ?? ""
    }
}

public struct KeychainRecoveryAppSnapshot: Equatable, Sendable {
    public let identity: SignedAegisAppIdentity
    public let keys: [String]

    public init(identity: SignedAegisAppIdentity, keys: [String]) {
        self.identity = identity
        self.keys = keys
    }
}

public struct KeychainRecoveryDiagnosis: Equatable, Sendable {
    public let source: KeychainRecoveryAppSnapshot
    public let target: KeychainRecoveryAppSnapshot
    public let missingFromTarget: [String]
    public let alreadyPresent: [String]

    public init(source: KeychainRecoveryAppSnapshot, target: KeychainRecoveryAppSnapshot) {
        self.source = source
        self.target = target
        let sourceKeys = Set(source.keys)
        let targetKeys = Set(target.keys)
        self.missingFromTarget = sourceKeys.subtracting(targetKeys).sorted()
        self.alreadyPresent = sourceKeys.intersection(targetKeys).sorted()
    }
}

public struct KeychainRecoveryMigrationPlan: Equatable, Sendable {
    public let keysToMigrate: [String]
    public let skippedAlreadyPresent: [String]

    public init(keysToMigrate: [String], skippedAlreadyPresent: [String]) {
        self.keysToMigrate = keysToMigrate
        self.skippedAlreadyPresent = skippedAlreadyPresent
    }
}

public struct KeychainRecoveryMigrationResult: Equatable, Sendable {
    public let source: SignedAegisAppIdentity
    public let target: SignedAegisAppIdentity
    public let migratedKeys: [String]
    public let skippedAlreadyPresent: [String]

    public init(
        source: SignedAegisAppIdentity,
        target: SignedAegisAppIdentity,
        migratedKeys: [String],
        skippedAlreadyPresent: [String]
    ) {
        self.source = source
        self.target = target
        self.migratedKeys = migratedKeys
        self.skippedAlreadyPresent = skippedAlreadyPresent
    }
}

public struct KeychainRecoveryPlanner {
    public init() {}

    public func plan(
        sourceKeys: [String],
        targetKeys: [String],
        selection: KeychainRecoverySelection,
        overwrite: Bool
    ) throws -> KeychainRecoveryMigrationPlan {
        let sourceSet = Set(sourceKeys)
        let targetSet = Set(targetKeys)

        switch selection {
        case .allMissing:
            if overwrite {
                return KeychainRecoveryMigrationPlan(keysToMigrate: sourceSet.sorted(), skippedAlreadyPresent: [])
            }
            return KeychainRecoveryMigrationPlan(
                keysToMigrate: sourceSet.subtracting(targetSet).sorted(),
                skippedAlreadyPresent: sourceSet.intersection(targetSet).sorted()
            )
        case .key(let key):
            guard sourceSet.contains(key) else {
                throw AegisSecretError.runtime("Source app cannot see secret `\(key)`.")
            }
            if targetSet.contains(key) && !overwrite {
                return KeychainRecoveryMigrationPlan(keysToMigrate: [], skippedAlreadyPresent: [key])
            }
            return KeychainRecoveryMigrationPlan(keysToMigrate: [key], skippedAlreadyPresent: [])
        }
    }
}

public protocol SignedAegisAppInspecting: Sendable {
    func inspect(executablePath: String) throws -> SignedAegisAppIdentity
}

public protocol KeychainRecoverySourceClient: Sendable {
    func listKeys(sourceExecutablePath: String) throws -> [String]
    func readSecret(sourceExecutablePath: String, key: String, agent: String) throws -> Data
}

public struct CodesignAegisAppInspector: SignedAegisAppInspecting {
    public init() {}

    public func inspect(executablePath: String) throws -> SignedAegisAppIdentity {
        let resolvedPath = URL(fileURLWithPath: expandUserPath(executablePath)).resolvingSymlinksInPath().path
        guard FileManager.default.isExecutableFile(atPath: resolvedPath) else {
            throw AegisSecretError.runtime("Aegis app binary is not executable at `\(resolvedPath)`.")
        }

        let result = try runCodesign(arguments: ["-d", "--entitlements", ":-", resolvedPath])
        guard result.exitCode == 0 else {
            throw AegisSecretError.runtime("Unable to inspect code signature for `\(resolvedPath)`.")
        }
        guard !result.stdout.isEmpty else {
            throw AegisSecretError.runtime("Code signature for `\(resolvedPath)` did not include entitlements.")
        }
        guard let plist = try PropertyListSerialization.propertyList(
            from: result.stdout,
            options: [],
            format: nil
        ) as? [String: Any] else {
            throw AegisSecretError.runtime("Code signature entitlements for `\(resolvedPath)` were not a plist dictionary.")
        }

        guard let teamIdentifier = (plist["com.apple.developer.team-identifier"] as? String)?.trimmedNonEmpty else {
            throw AegisSecretError.runtime("Code signature for `\(resolvedPath)` does not prove an Apple team identifier.")
        }
        guard let applicationIdentifier = (plist["com.apple.application-identifier"] as? String)?.trimmedNonEmpty else {
            throw AegisSecretError.runtime("Code signature for `\(resolvedPath)` does not prove an application identifier.")
        }
        guard let keychainAccessGroups = plist["keychain-access-groups"] as? [String],
              !keychainAccessGroups.isEmpty else {
            throw AegisSecretError.runtime("Code signature for `\(resolvedPath)` does not prove a keychain access group.")
        }

        let identity = SignedAegisAppIdentity(
            executablePath: resolvedPath,
            teamIdentifier: teamIdentifier,
            applicationIdentifier: applicationIdentifier,
            keychainAccessGroups: keychainAccessGroups
        )
        try validateAegisIdentity(identity)
        return identity
    }

    private func validateAegisIdentity(_ identity: SignedAegisAppIdentity) throws {
        let expectedBundleIdentifier = "com.olympum.aegis-secret"
        guard identity.applicationIdentifier.hasSuffix(".\(expectedBundleIdentifier)") else {
            throw AegisSecretError.runtime("Signed app `\(identity.executablePath)` is not an Aegis Secret app identifier.")
        }
        guard identity.keychainAccessGroups.contains(where: { $0.hasSuffix(".\(expectedBundleIdentifier)") }) else {
            throw AegisSecretError.runtime("Signed app `\(identity.executablePath)` is not entitled for the Aegis Secret keychain group.")
        }
    }

    private func runCodesign(arguments: [String]) throws -> RecoveryProcessResult {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/codesign")
        process.arguments = arguments

        let stdoutPipe = Pipe()
        let stderrPipe = Pipe()
        process.standardOutput = stdoutPipe
        process.standardError = stderrPipe

        try process.run()
        process.waitUntilExit()

        return RecoveryProcessResult(
            stdout: stdoutPipe.fileHandleForReading.readDataToEndOfFile(),
            stderr: stderrPipe.fileHandleForReading.readDataToEndOfFile(),
            exitCode: process.terminationStatus
        )
    }
}

public struct ProcessKeychainRecoverySourceClient: KeychainRecoverySourceClient {
    public init() {}

    public func listKeys(sourceExecutablePath: String) throws -> [String] {
        let result = try runSource(executablePath: sourceExecutablePath, arguments: ["list"])
        guard result.exitCode == 0 else {
            throw AegisSecretError.runtime("Source app failed to list key names.")
        }
        let output = String(decoding: result.stdout, as: UTF8.self)
        return output
            .split(whereSeparator: \.isNewline)
            .map(String.init)
            .filter { !$0.isEmpty }
            .sorted()
    }

    public func readSecret(sourceExecutablePath: String, key: String, agent: String) throws -> Data {
        let result = try runSource(
            executablePath: sourceExecutablePath,
            arguments: ["get", key, "--agent", agent]
        )
        guard result.exitCode == 0 else {
            throw AegisSecretError.runtime("Source app failed to read secret `\(key)` for migration.")
        }
        guard !result.stdout.isEmpty else {
            throw AegisSecretError.runtime("Source app returned an empty secret for `\(key)`; refusing to migrate it.")
        }
        return result.stdout
    }

    private func runSource(executablePath: String, arguments: [String]) throws -> RecoveryProcessResult {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: executablePath)
        process.arguments = arguments

        let stdoutPipe = Pipe()
        let stderrPipe = Pipe()
        process.standardOutput = stdoutPipe
        process.standardError = stderrPipe

        try process.run()
        process.waitUntilExit()

        return RecoveryProcessResult(
            stdout: stdoutPipe.fileHandleForReading.readDataToEndOfFile(),
            stderr: stderrPipe.fileHandleForReading.readDataToEndOfFile(),
            exitCode: process.terminationStatus
        )
    }
}

public struct KeychainRecoveryTool {
    public let targetExecutablePath: String
    public let secretStore: SecretStore
    public let inspector: SignedAegisAppInspecting
    public let sourceClient: KeychainRecoverySourceClient
    public let planner: KeychainRecoveryPlanner

    public init(
        targetExecutablePath: String,
        secretStore: SecretStore,
        inspector: SignedAegisAppInspecting = CodesignAegisAppInspector(),
        sourceClient: KeychainRecoverySourceClient = ProcessKeychainRecoverySourceClient(),
        planner: KeychainRecoveryPlanner = KeychainRecoveryPlanner()
    ) {
        self.targetExecutablePath = targetExecutablePath
        self.secretStore = secretStore
        self.inspector = inspector
        self.sourceClient = sourceClient
        self.planner = planner
    }

    public func diagnose(sourceApp: String) throws -> KeychainRecoveryDiagnosis {
        let sourceIdentity = try inspector.inspect(executablePath: sourceApp)
        let targetIdentity = try inspector.inspect(executablePath: targetExecutablePath)
        try validateRecoveryPair(source: sourceIdentity, target: targetIdentity)

        let sourceKeys = try sourceClient.listKeys(sourceExecutablePath: sourceIdentity.executablePath)
        let targetKeys = try secretStore.listSecrets().map(\.key).sorted()
        return KeychainRecoveryDiagnosis(
            source: KeychainRecoveryAppSnapshot(identity: sourceIdentity, keys: sourceKeys),
            target: KeychainRecoveryAppSnapshot(identity: targetIdentity, keys: targetKeys)
        )
    }

    public func migrate(
        sourceApp: String,
        selection: KeychainRecoverySelection,
        overwrite: Bool
    ) throws -> KeychainRecoveryMigrationResult {
        let diagnosis = try diagnose(sourceApp: sourceApp)
        let plan = try planner.plan(
            sourceKeys: diagnosis.source.keys,
            targetKeys: diagnosis.target.keys,
            selection: selection,
            overwrite: overwrite
        )

        var migratedKeys: [String] = []
        for key in plan.keysToMigrate {
            let secretData = try sourceClient.readSecret(
                sourceExecutablePath: diagnosis.source.identity.executablePath,
                key: key,
                agent: "Aegis Keychain Recovery"
            )
            try secretStore.setSecret(secretData, for: key)
            migratedKeys.append(key)
        }

        return KeychainRecoveryMigrationResult(
            source: diagnosis.source.identity,
            target: diagnosis.target.identity,
            migratedKeys: migratedKeys,
            skippedAlreadyPresent: plan.skippedAlreadyPresent
        )
    }

    private func validateRecoveryPair(source: SignedAegisAppIdentity, target: SignedAegisAppIdentity) throws {
        guard source.teamIdentifier == target.teamIdentifier else {
            throw AegisSecretError.runtime("Source and target apps are signed by different Apple teams; refusing recovery.")
        }
        guard source.applicationIdentifier.hasSuffix(".com.olympum.aegis-secret"),
              target.applicationIdentifier.hasSuffix(".com.olympum.aegis-secret") else {
            throw AegisSecretError.runtime("Source and target apps are not both Aegis Secret apps; refusing recovery.")
        }
        guard !source.primaryKeychainAccessGroup.isEmpty, !target.primaryKeychainAccessGroup.isEmpty else {
            throw AegisSecretError.runtime("Source and target apps must both prove keychain access groups.")
        }
    }
}

public struct KeychainRecoveryRenderer {
    public init() {}

    public func render(diagnosis: KeychainRecoveryDiagnosis) -> String {
        var lines: [String] = []
        lines.append("Keychain recovery diagnosis")
        lines.append("")
        append(snapshot: diagnosis.source, label: "Source app", to: &lines)
        lines.append("")
        append(snapshot: diagnosis.target, label: "Target app", to: &lines)
        lines.append("")
        lines.append("Missing from target: \(diagnosis.missingFromTarget.count)")
        append(keys: diagnosis.missingFromTarget, to: &lines)
        lines.append("")
        lines.append("Already present: \(diagnosis.alreadyPresent.count)")
        append(keys: diagnosis.alreadyPresent, to: &lines)
        lines.append("")
        lines.append("No secret values were read by this diagnostic.")
        return lines.joined(separator: "\n")
    }

    public func render(result: KeychainRecoveryMigrationResult) -> String {
        var lines: [String] = []
        lines.append("Keychain recovery migration")
        lines.append("source_group: \(result.source.primaryKeychainAccessGroup)")
        lines.append("target_group: \(result.target.primaryKeychainAccessGroup)")
        lines.append("migrated: \(result.migratedKeys.count)")
        append(keys: result.migratedKeys, to: &lines)
        lines.append("skipped_already_present: \(result.skippedAlreadyPresent.count)")
        append(keys: result.skippedAlreadyPresent, to: &lines)
        lines.append("No secret values were printed.")
        return lines.joined(separator: "\n")
    }

    private func append(snapshot: KeychainRecoveryAppSnapshot, label: String, to lines: inout [String]) {
        lines.append("\(label):")
        lines.append("  executable: \(snapshot.identity.executablePath)")
        lines.append("  team_id: \(snapshot.identity.teamIdentifier)")
        lines.append("  application_id: \(snapshot.identity.applicationIdentifier)")
        lines.append("  keychain_group: \(snapshot.identity.primaryKeychainAccessGroup)")
        lines.append("  key_count: \(snapshot.keys.count)")
        append(keys: snapshot.keys, to: &lines)
    }

    private func append(keys: [String], to lines: inout [String]) {
        guard !keys.isEmpty else {
            lines.append("  (none)")
            return
        }
        for key in keys {
            lines.append("  \(key)")
        }
    }
}

private struct RecoveryProcessResult {
    let stdout: Data
    let stderr: Data
    let exitCode: Int32
}

public struct CLIApplication {
    public let parser: CommandParser
    public let secretStore: SecretStore
    public let authenticator: DeviceAuthenticator
    public let commandStore: CommandStore
    public let wrappedCommandRunner: WrappedCommandRunner
    public let currentExecutablePath: String

    public init(
        parser: CommandParser = CommandParser(),
        secretStore: SecretStore = KeychainSecretStore(),
        authenticator: DeviceAuthenticator = LocalDeviceAuthenticator(),
        commandStore: CommandStore = CommandStore(),
        wrappedCommandRunner: WrappedCommandRunner? = nil,
        currentExecutablePath: String = CommandLine.arguments.first ?? ""
    ) {
        self.parser = parser
        self.secretStore = secretStore
        self.authenticator = authenticator
        self.commandStore = commandStore
        self.currentExecutablePath = currentExecutablePath
        self.wrappedCommandRunner = wrappedCommandRunner ?? WrappedCommandRunner(
            commandStore: commandStore,
            authenticator: authenticator,
            secretStore: secretStore
        )
    }

    public func run(arguments: [String], stdinIsTTY: Bool) async -> Never {
        do {
            let command = try parser.parse(arguments, stdinIsTTY: stdinIsTTY)
            if command == .help {
                print(usageText)
                exit(ExitCode.success.rawValue)
            }

            try await run(command)
            exit(ExitCode.success.rawValue)
        } catch let error as AegisSecretError {
            emit(error: error)
        } catch {
            emit(error: .runtime(error.localizedDescription))
        }
    }

    private func run(_ command: CLICommand) async throws {
        switch command {
        case .set(let key, let inputMode):
            let secret = try readSecret(using: inputMode)
            guard !secret.isEmpty else {
                throw AegisSecretError.runtime("Refusing to store an empty secret for `\(key)`.")
            }

            try secretStore.setSecret(secret, for: key)
            print("Stored `\(key)` in Keychain.")
        case .get(let key, let agentName):
            let reason = "Allow \(agentName) to access the secret named '\(key)'."
            let secret = try secretStore.readSecret(for: key, reason: reason)
            FileHandle.standardOutput.write(secret)
            if isatty(FileHandle.standardOutput.fileDescriptor) != 0 {
                FileHandle.standardOutput.write(Data([0x0A]))
            }
        case .delete(let key):
            let reason = "Allow aegis-secret to delete the secret named '\(key)'."
            try await authenticator.authenticate(reason: reason)
            if try secretStore.deleteSecret(for: key) {
                print("Deleted `\(key)` from Keychain.")
            } else {
                print("No secret named `\(key)` was found.")
            }
        case .list:
            for item in try secretStore.listSecrets() {
                print(item.key)
            }
        case .installUser:
            let installation = try UserInstaller(
                currentExecutablePath: currentExecutablePath,
                commandStore: commandStore
            ).install()
            print("Installed user shims for `\(installation.appBundleURL.path)`.")
            if installation.registeredCodex {
                print("Registered the Codex MCP server.")
            }
            if installation.registeredClaude {
                print("Registered the Claude MCP server.")
            }
            if installation.registeredCodexBroker {
                print("Registered the Codex Aegis Broker MCP alias.")
            }
            if installation.registeredClaudeBroker {
                print("Registered the Claude Aegis Broker MCP alias.")
            }
            if installation.installedCodexHook {
                print("Installed the managed Codex shell-bypass guard hook.")
            }
            if installation.installedClaudeHook {
                print("Installed the managed Claude shell-bypass guard hook.")
            }
            if !installation.registeredCodex
                && !installation.registeredClaude
                && !installation.registeredCodexBroker
                && !installation.registeredClaudeBroker {
                print("No supported MCP client CLI was found, so only PATH shims were created.")
            }
            if installation.updatedCodexGuidance {
                print("Updated ~/.codex/AGENTS.md with the managed Aegis guidance block.")
            }
            if installation.updatedClaudeGuidance {
                print("Updated ~/.claude/CLAUDE.md with the managed Aegis guidance block.")
            }
        case .command(let wrappedCommandCommand):
            try handleWrappedCommandManagement(wrappedCommandCommand)
        case .approval(let approvalCommand):
            try handleApprovalManagement(approvalCommand)
        case .guardCommand(let guardCommand):
            try await handleGuard(guardCommand)
        case .recovery(let recoveryCommand):
            try handleRecovery(recoveryCommand)
        case .run(let name, let args):
            let result = try await wrappedCommandRunner.run(
                name: name,
                args: args,
                requester: "aegis-secret"
            )
            if !result.stdout.isEmpty {
                FileHandle.standardOutput.write(Data(result.stdout.utf8))
            }
            if !result.stderr.isEmpty {
                FileHandle.standardError.write(Data(result.stderr.utf8))
            }
            if result.exitCode != 0 {
                throw AegisSecretError.runtime("Wrapped command `\(name)` exited with status \(result.exitCode).")
            }
        case .help:
            print(usageText)
        }
    }

    private func handleRecovery(_ command: KeychainRecoveryCommand) throws {
        let recovery = KeychainRecoveryTool(
            targetExecutablePath: currentExecutablePath,
            secretStore: secretStore
        )
        let renderer = KeychainRecoveryRenderer()

        switch command {
        case .diagnose(let sourceApp):
            print(renderer.render(diagnosis: try recovery.diagnose(sourceApp: sourceApp)))
        case .migrate(let sourceApp, let selection, let overwrite):
            print(renderer.render(result: try recovery.migrate(
                sourceApp: sourceApp,
                selection: selection,
                overwrite: overwrite
            )))
        }
    }

    private func handleWrappedCommandManagement(_ command: WrappedCommandManagementCommand) throws {
        switch command {
        case .list:
            for summary in try commandStore.listCommands() {
                print(summary.name)
            }
        case .show(let name):
            let data = try prettyJSON(commandStore.rawCommand(named: name))
            print(String(decoding: data, as: UTF8.self))
        case .validateCurrent(let name):
            if let name {
                try commandStore.validateCurrentCommand(named: name)
                print("Wrapped command `\(name)` is valid.")
            } else {
                let count = try commandStore.validateCurrentConfiguration()
                print("Validated \(count) wrapped commands from `\(commandStore.fileURL.path)`.")
            }
        case .validateFile(let path):
            let count = try commandStore.validateFile(at: path)
            print("Validated \(count) wrapped commands from `\(expandUserPath(path))`.")
        case .importFile(let path):
            let count = try commandStore.importFile(from: path)
            print("Imported \(count) wrapped commands into `\(commandStore.fileURL.path)`.")
        }
    }

    private func handleApprovalManagement(_ command: ApprovalManagementCommand) throws {
        switch command {
        case .status(let commandName, let agentName):
            let inspector = ApprovalLeaseInspector(commandStore: commandStore)
            for status in try inspector.statuses(command: commandName, agent: agentName) {
                print(render(status: status))
            }
        }
    }

    private func handleGuard(_ command: GuardCommand) async throws {
        switch command {
        case .shell(let explicitCommand):
            let hookMode = explicitCommand == nil
            let commandText: String
            do {
                commandText = try explicitCommand ?? extractShellCommand(from: FileHandle.standardInput.readDataToEndOfFile())
            } catch {
                print(try codexPreToolUseDenyHookOutput(reason: codexBrokerRetryReason(
                    "Aegis Secret could not parse the shell command from Codex hook input."
                )))
                return
            }
            let resolvedCommands: [ResolvedWrappedCommand]
            do {
                resolvedCommands = try commandStore.resolvedCommands()
            } catch {
                if hookMode {
                    print(try codexPreToolUseDenyHookOutput(reason: codexBrokerRetryReason(
                        "Aegis Secret could not load the wrapped-command policy."
                    )))
                    return
                }
                throw error
            }
            let guardResult = await ShellBypassGuard(resolvedCommands: resolvedCommands).evaluate(command: commandText)
            if guardResult.allowed {
                return
            }

            if hookMode {
                print(try codexPreToolUseDenyHookOutput(reason: guardResult.message))
                return
            }
            throw AegisSecretError.blocked(guardResult.message)
        }
    }

    private func codexBrokerRetryReason(_ prefix: String) -> String {
        "\(prefix) Retry through Aegis Broker MCP `list_commands` and `run_command` if this was a privileged action."
    }

    private func extractShellCommand(from data: Data) throws -> String {
        try ShellHookCommandExtractor().extract(from: data)
    }

    private func render(status: ApprovalLeaseStatus) -> String {
        var parts = ["status=\(status.reason.rawValue)"]
        if let lease = status.lease {
            parts.append("command=\(lease.command)")
            parts.append("agent=\(lease.agent)")
            parts.append("expires_at=\(iso8601String(lease.expiresAt))")
            parts.append("executable=\(lease.executablePath)")
        } else {
            if let command = status.command {
                parts.append("command=\(command)")
            }
            if let agent = status.agent {
                parts.append("agent=\(agent)")
            }
        }
        if let currentExecutablePath = status.currentExecutablePath, status.lease?.executablePath != currentExecutablePath {
            parts.append("current_executable=\(currentExecutablePath)")
        }
        return parts.joined(separator: " ")
    }

    private func readSecret(using inputMode: SecretInputMode) throws -> Data {
        switch inputMode {
        case .stdin:
            return FileHandle.standardInput.readDataToEndOfFile()
        case .prompt:
            print("Enter secret: ", terminator: "")
            fflush(stdout)

            guard let secret = readPassword() else {
                print("")
                throw AegisSecretError.runtime("Failed to read secret from terminal.")
            }

            print("")
            guard let data = secret.data(using: .utf8) else {
                throw AegisSecretError.runtime("Secret could not be encoded as UTF-8.")
            }
            return data
        }
    }

    private func emit(error: AegisSecretError) -> Never {
        switch error {
        case .usage:
            fputs("Error: \(error.description)\n\n\(usageText)\n", stderr)
            exit(ExitCode.usage.rawValue)
        case .blocked:
            fputs("\(error.description)\n", stderr)
            exit(ExitCode.blocked.rawValue)
        case .runtime:
            fputs("Error: \(error.description)\n", stderr)
            exit(ExitCode.failure.rawValue)
        }
    }
}

public let usageText = """
Usage:
  aegis-secret set <key> [--stdin]
  aegis-secret get <key> --agent <agent-name>
  aegis-secret delete <key>
  aegis-secret list
  aegis-secret install-user
  aegis-secret command list
  aegis-secret command show <name>
  aegis-secret command validate [<name> | --file <path>]
  aegis-secret command import <json-file>
  aegis-secret approval status [<command>] [--agent <agent>]
  aegis-secret guard shell [--command <shell-command>]
  aegis-secret recovery diagnose --source-app <path-to-old-aegis-secret-binary>
  aegis-secret recovery migrate --source-app <path-to-old-aegis-secret-binary> (--all | --key <key>) [--overwrite]
  aegis-secret run <name> -- <args...>

Notes:
  `set` reads from the terminal by default, or from stdin when piped / passed `--stdin`.
  `get` is for explicit human use and reveals the raw secret on stdout after device-owner authentication.
  `install-user` creates PATH shims in `~/.local/bin` and registers user-scoped MCP integrations for installed Codex / Claude CLIs.
  `recovery diagnose` reports signed app namespaces and key names only; it does not read secret values.
  `recovery migrate` copies secrets from an older signed Aegis app into the current signed app without printing values.
  Aegis reads a managed base file from `~/.config/aegis-secret/commands.base.json` and overlays user changes from `~/.config/aegis-secret/commands.local.json`.
"""

public struct UserInstallationSummary {
    public let appBundleURL: URL
    public let registeredCodex: Bool
    public let registeredClaude: Bool
    public let registeredCodexBroker: Bool
    public let registeredClaudeBroker: Bool
    public let installedCodexHook: Bool
    public let installedClaudeHook: Bool
    public let updatedCodexGuidance: Bool
    public let updatedClaudeGuidance: Bool
}

public struct AgentHookConfigUpdater {
    public static let managedStatusMessage = "Aegis Broker: checking protected tool route"

    public init() {}

    public func upsertClaudeSettings(data: Data, executableURL: URL) throws -> Data {
        var root = try mutableJSONObject(from: data, fallback: [:], label: "Claude settings")
        var hooks = try dictionaryValue(root["hooks"], label: "Claude hooks")
        var preToolUse = try arrayOfDictionariesValue(hooks["PreToolUse"], label: "Claude PreToolUse hooks")
        preToolUse.removeAll(where: isManagedHookGroup)
        preToolUse.append([
            "matcher": "Bash",
            "hooks": [[
                "type": "command",
                "command": executableURL.path,
                "args": ["guard", "shell"],
                "timeout": 10,
                "statusMessage": Self.managedStatusMessage
            ]]
        ])
        hooks["PreToolUse"] = preToolUse
        root["hooks"] = hooks
        return try encodeJSONObject(root)
    }

    public func upsertCodexHooks(data: Data?, executableURL: URL) throws -> Data {
        var root = try mutableJSONObject(from: data, fallback: ["hooks": [:]], label: "Codex hooks")
        var hooks = try dictionaryValue(root["hooks"], label: "Codex hooks root")
        var preToolUse = try arrayOfDictionariesValue(hooks["PreToolUse"], label: "Codex PreToolUse hooks")
        preToolUse.removeAll(where: isManagedHookGroup)
        preToolUse.append([
            "matcher": "^(Bash|shell|exec_command|unified_exec)$",
            "hooks": [[
                "type": "command",
                "command": "\(shellQuote(executableURL.path)) guard shell",
                "timeout": 10,
                "statusMessage": Self.managedStatusMessage
            ]]
        ])
        hooks["PreToolUse"] = preToolUse
        root["hooks"] = hooks
        return try encodeJSONObject(root)
    }

    public func upsertCodexConfig(_ existing: String) -> String {
        var lines = existing.split(separator: "\n", omittingEmptySubsequences: false).map(String.init)
        var featuresStart: Int?
        var featuresEnd = lines.count

        for (index, line) in lines.enumerated() {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            if trimmed == "[features]" {
                featuresStart = index
                featuresEnd = lines.count
                continue
            }

            if featuresStart != nil,
               index > featuresStart!,
               trimmed.hasPrefix("["),
               trimmed.hasSuffix("]") {
                featuresEnd = index
                break
            }
        }

        if let featuresStart {
            for index in (featuresStart + 1)..<featuresEnd {
                let trimmed = lines[index].trimmingCharacters(in: .whitespaces)
                if trimmed.hasPrefix("hooks") && trimmed.dropFirst("hooks".count).trimmingCharacters(in: .whitespaces).hasPrefix("=") {
                    lines[index] = "hooks = true"
                    return lines.joined(separator: "\n").ensureTrailingNewline()
                }
            }

            lines.insert("hooks = true", at: featuresStart + 1)
            return lines.joined(separator: "\n").ensureTrailingNewline()
        }

        let prefix = existing.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ? "" : existing.ensureTrailingNewline() + "\n"
        return prefix + """
        [features]
        hooks = true
        """
        .ensureTrailingNewline()
    }

    private func mutableJSONObject(from data: Data?, fallback: [String: Any], label: String) throws -> [String: Any] {
        guard let data, !data.isEmpty else {
            return fallback
        }

        guard let json = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw AegisSecretError.runtime("\(label) must be a JSON object.")
        }
        return json
    }

    private func dictionaryValue(_ value: Any?, label: String) throws -> [String: Any] {
        guard let value else {
            return [:]
        }
        guard let dictionary = value as? [String: Any] else {
            throw AegisSecretError.runtime("\(label) must be a JSON object.")
        }
        return dictionary
    }

    private func arrayOfDictionariesValue(_ value: Any?, label: String) throws -> [[String: Any]] {
        guard let value else {
            return []
        }
        guard let array = value as? [[String: Any]] else {
            throw AegisSecretError.runtime("\(label) must be an array of objects.")
        }
        return array
    }

    private func isManagedHookGroup(_ group: [String: Any]) -> Bool {
        guard let hooks = group["hooks"] as? [[String: Any]] else {
            return false
        }

        return hooks.contains { hook in
            hook["statusMessage"] as? String == Self.managedStatusMessage
                || ((hook["command"] as? String)?.contains("aegis-secret") == true
                    && (hook["command"] as? String)?.contains("guard shell") == true)
        }
    }

    private func encodeJSONObject(_ object: [String: Any]) throws -> Data {
        let data = try JSONSerialization.data(withJSONObject: object, options: [.prettyPrinted, .sortedKeys])
        return data + Data([0x0A])
    }
}

public struct UserInstaller {
    public let currentExecutablePath: String
    public let environment: [String: String]
    public let fileManager: FileManager
    public let commandStore: CommandStore
    public let homeDirectory: URL?

    public init(
        currentExecutablePath: String,
        environment: [String: String] = ProcessInfo.processInfo.environment,
        fileManager: FileManager = .default,
        commandStore: CommandStore = CommandStore(),
        homeDirectory: URL? = nil
    ) {
        self.currentExecutablePath = currentExecutablePath
        self.environment = environment
        self.fileManager = fileManager
        self.commandStore = commandStore
        self.homeDirectory = homeDirectory
    }

    public func install() throws -> UserInstallationSummary {
        let appBundleURL = try resolveAppBundleURL()
        guard !appBundleURL.path.hasPrefix("/Volumes/") else {
            throw AegisSecretError.runtime("Run `install-user` after copying Aegis Secret.app to /Applications or ~/Applications.")
        }

        try commandStore.writeManagedSystemFile()
        try commandStore.writeUserOverrideFileIfMissing()

        let executableURL = appBundleURL.appendingPathComponent("Contents/MacOS/aegis-secret")
        let binDirectory = resolvedHomeDirectory()
            .appendingPathComponent(".local/bin", isDirectory: true)
        try fileManager.createDirectory(at: binDirectory, withIntermediateDirectories: true)

        try writeShim(
            named: "aegis-secret",
            targetExecutable: executableURL,
            arguments: [],
            in: binDirectory
        )
        try writeShim(
            named: "aegis-secret-mcp",
            targetExecutable: executableURL,
            arguments: ["--mcp-server"],
            in: binDirectory
        )
        try writeShim(
            named: "aegis-broker",
            targetExecutable: executableURL,
            arguments: [],
            in: binDirectory
        )
        try writeShim(
            named: "aegis-broker-mcp",
            targetExecutable: executableURL,
            arguments: ["--mcp-server"],
            in: binDirectory
        )

        let registeredCodex = try registerCodex(serverName: "aegis-secret", executableURL: executableURL)
        let registeredClaude = try registerClaude(serverName: "aegis-secret", executableURL: executableURL)
        let registeredCodexBroker = try registerCodex(serverName: "aegis-broker", executableURL: executableURL)
        let registeredClaudeBroker = try registerClaude(serverName: "aegis-broker", executableURL: executableURL)
        let installedCodexHook = registeredCodex ? try installCodexHook(executableURL: executableURL) : false
        let installedClaudeHook = registeredClaude ? try installClaudeHook(executableURL: executableURL) : false
        let updatedCodexGuidance = try updateCodexGuidance()
        let updatedClaudeGuidance = try updateClaudeGuidance()

        return UserInstallationSummary(
            appBundleURL: appBundleURL,
            registeredCodex: registeredCodex,
            registeredClaude: registeredClaude,
            registeredCodexBroker: registeredCodexBroker,
            registeredClaudeBroker: registeredClaudeBroker,
            installedCodexHook: installedCodexHook,
            installedClaudeHook: installedClaudeHook,
            updatedCodexGuidance: updatedCodexGuidance,
            updatedClaudeGuidance: updatedClaudeGuidance
        )
    }

    private func resolveAppBundleURL() throws -> URL {
        let bundleURL = Bundle.main.bundleURL.standardizedFileURL
        if bundleURL.pathExtension == "app" {
            return bundleURL
        }

        let executableURL = URL(fileURLWithPath: currentExecutablePath).resolvingSymlinksInPath()
        let candidate = executableURL
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        if candidate.pathExtension == "app" {
            return candidate.standardizedFileURL
        }

        throw AegisSecretError.runtime("`install-user` must be run from the signed Aegis Secret app bundle.")
    }

    private func resolvedHomeDirectory() -> URL {
        homeDirectory ?? fileManager.homeDirectoryForCurrentUser
    }

    private func writeShim(
        named shimName: String,
        targetExecutable: URL,
        arguments: [String],
        in directory: URL
    ) throws {
        let shimURL = directory.appendingPathComponent(shimName)
        let renderedArguments = arguments.map { shellQuote($0) }.joined(separator: " ")
        let argumentSuffix = renderedArguments.isEmpty ? "" : " \(renderedArguments)"
        let contents = """
        #!/bin/zsh
        exec \(shellQuote(targetExecutable.path))\(argumentSuffix) "$@"
        """

        try contents.write(to: shimURL, atomically: true, encoding: .utf8)
        try fileManager.setAttributes([.posixPermissions: 0o755], ofItemAtPath: shimURL.path)
    }

    private func registerCodex(serverName: String, executableURL: URL) throws -> Bool {
        guard let codexExecutable = findExecutable(named: "codex") else {
            return false
        }

        _ = try runProcess(
            executableURL: codexExecutable,
            arguments: ["mcp", "remove", serverName],
            allowFailure: true
        )
        _ = try runProcess(
            executableURL: codexExecutable,
            arguments: [
                "mcp", "add", serverName,
                "--env", "AEGIS_SECRET_AGENT_NAME=Codex",
                "--",
                executableURL.path,
                "--mcp-server"
            ]
        )
        return true
    }

    private func registerClaude(serverName: String, executableURL: URL) throws -> Bool {
        guard let claudeExecutable = findExecutable(named: "claude") else {
            return false
        }

        _ = try runProcess(
            executableURL: claudeExecutable,
            arguments: ["mcp", "remove", serverName, "-s", "user"],
            allowFailure: true
        )
        _ = try runProcess(
            executableURL: claudeExecutable,
            arguments: ["mcp", "remove", serverName, "-s", "local"],
            allowFailure: true
        )

        let payloadData = try JSONSerialization.data(
            withJSONObject: [
                "type": "stdio",
                "command": executableURL.path,
                "args": ["--mcp-server"],
                "env": ["AEGIS_SECRET_AGENT_NAME": "Claude"]
            ],
            options: []
        )
        guard let payload = String(data: payloadData, encoding: .utf8) else {
            throw AegisSecretError.runtime("Failed to encode the Claude MCP registration payload.")
        }

        _ = try runProcess(
            executableURL: claudeExecutable,
            arguments: ["mcp", "add-json", "-s", "user", serverName, payload]
        )
        return true
    }

    private func installCodexHook(executableURL: URL) throws -> Bool {
        let codexDirectory = resolvedHomeDirectory().appendingPathComponent(".codex", isDirectory: true)
        let configURL = codexDirectory.appendingPathComponent("config.toml", isDirectory: false)
        guard fileManager.fileExists(atPath: configURL.path) else {
            return false
        }

        let updater = AgentHookConfigUpdater()
        let existingConfig = (try? String(contentsOf: configURL, encoding: .utf8)) ?? ""
        let updatedConfig = updater.upsertCodexConfig(existingConfig)
        if updatedConfig != existingConfig {
            try updatedConfig.write(to: configURL, atomically: true, encoding: .utf8)
        }

        let hooksURL = codexDirectory.appendingPathComponent("hooks.json", isDirectory: false)
        let existingHooks = try? Data(contentsOf: hooksURL)
        let updatedHooks = try updater.upsertCodexHooks(data: existingHooks, executableURL: executableURL)
        if updatedHooks != existingHooks {
            try updatedHooks.write(to: hooksURL, options: .atomic)
        }

        return true
    }

    private func installClaudeHook(executableURL: URL) throws -> Bool {
        let settingsURL = resolvedHomeDirectory()
            .appendingPathComponent(".claude", isDirectory: true)
            .appendingPathComponent("settings.json", isDirectory: false)
        guard fileManager.fileExists(atPath: settingsURL.path) else {
            return false
        }

        let existingSettings = try Data(contentsOf: settingsURL)
        let updatedSettings = try AgentHookConfigUpdater().upsertClaudeSettings(
            data: existingSettings,
            executableURL: executableURL
        )
        if updatedSettings != existingSettings {
            try updatedSettings.write(to: settingsURL, options: .atomic)
        }

        return true
    }

    private func updateCodexGuidance() throws -> Bool {
        let guidanceURL = resolvedHomeDirectory()
            .appendingPathComponent(".codex", isDirectory: true)
            .appendingPathComponent("AGENTS.md", isDirectory: false)
        let guidance = bundledGuidance(
            resourceName: bundledCodexGuidanceResourceName,
            fallback: defaultCodexGuidance
        )
        try upsertManagedGuidance(guidance, into: guidanceURL)
        return true
    }

    private func updateClaudeGuidance() throws -> Bool {
        let guidanceURL = resolvedHomeDirectory()
            .appendingPathComponent(".claude", isDirectory: true)
            .appendingPathComponent("CLAUDE.md", isDirectory: false)
        let guidance = bundledGuidance(
            resourceName: bundledClaudeGuidanceResourceName,
            fallback: defaultClaudeGuidance
        )
        try upsertManagedGuidance(guidance, into: guidanceURL)
        return true
    }

    private func bundledGuidance(resourceName: String, fallback: String) -> String {
        if let url = Bundle.main.url(forResource: resourceName, withExtension: "md"),
           let contents = try? String(contentsOf: url, encoding: .utf8).trimmingCharacters(in: .whitespacesAndNewlines),
           !contents.isEmpty {
            return contents
        }

        return fallback
    }

    private func upsertManagedGuidance(_ guidance: String, into fileURL: URL) throws {
        let startMarker = "<!-- aegis-secret:begin -->"
        let endMarker = "<!-- aegis-secret:end -->"
        let managedSection = """
        \(startMarker)
        \(guidance)
        \(endMarker)
        """

        try fileManager.createDirectory(at: fileURL.deletingLastPathComponent(), withIntermediateDirectories: true)

        let existing = (try? String(contentsOf: fileURL, encoding: .utf8)) ?? ""
        let updated: String

        if let startRange = existing.range(of: startMarker),
           let endRange = existing.range(of: endMarker),
           startRange.lowerBound <= endRange.lowerBound {
            let replacementRange = startRange.lowerBound..<endRange.upperBound
            updated = existing.replacingCharacters(in: replacementRange, with: managedSection)
        } else if existing.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            updated = managedSection + "\n"
        } else {
            let separator = existing.hasSuffix("\n") ? "\n" : "\n\n"
            updated = existing + separator + managedSection + "\n"
        }

        try updated.write(to: fileURL, atomically: true, encoding: .utf8)
    }

    private func findExecutable(named executableName: String) -> URL? {
        commandStore.resolveExecutable(named: executableName)
    }

    @discardableResult
    private func runProcess(
        executableURL: URL,
        arguments: [String],
        allowFailure: Bool = false
    ) throws -> String {
        let process = Process()
        process.executableURL = executableURL
        process.arguments = arguments
        process.environment = environment

        let outputPipe = Pipe()
        process.standardOutput = outputPipe
        process.standardError = outputPipe

        try process.run()
        process.waitUntilExit()

        let outputData = outputPipe.fileHandleForReading.readDataToEndOfFile()
        let output = String(decoding: outputData, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)

        if process.terminationStatus != 0 && !allowFailure {
            let renderedCommand = ([executableURL.path] + arguments).joined(separator: " ")
            let detail = output.isEmpty ? "exit status \(process.terminationStatus)" : output
            throw AegisSecretError.runtime("Command failed: \(renderedCommand)\n\(detail)")
        }

        return output
    }
}

private let defaultClaudeGuidance = """
## Aegis Secret / Aegis Broker

Use ordinary shell calls for ordinary commands. Use Aegis Broker only for protected or privileged actions.

- Protected GitHub method mutations such as issue close, PR merge, or release edits are checked by the Aegis PreTool hook and Bruno before the original command runs.
- Protected GitHub/source-control mutations can use typed Broker MCP actions: call `list_remote_actions`, then `run_remote_action`.
- Approved cloud/deploy/package mutations can use fixed Broker CLI profiles: call `list_cli_profiles`, then `run_cli_profile`.
- Privileged credentialed actions such as `terraform apply` must use the Aegis Broker MCP server: call `list_commands`, then `run_command`.
- Ordinary commands such as `gh issue list`, `terraform plan`, and `git status` are not brokered by default.
- Use `aegis-secret command list` and `aegis-secret command show <NAME>` only as a local fallback when MCP is unavailable.
- If a `Bash` call is blocked by `aegis-secret guard shell`, follow the block message. It may ask for evidence, or it may ask you to retry through Aegis Broker MCP.
- Aegis approval leases are per agent and wrapped command. The persisted lease identity includes the agent name, command name, resolved executable path, and policy fingerprint.
- Use `aegis-secret approval status <NAME> --agent Claude` to diagnose repeated approval prompts.
- Use `aegis-secret get <KEY> --agent Claude` only for explicit human-approved debugging or when the user specifically asks for the raw value.
"""

private let defaultCodexGuidance = """
## Aegis Secret / Aegis Broker

Use ordinary shell calls for ordinary commands. Use Aegis Broker only for protected or privileged actions.

- Protected GitHub method mutations such as issue close, PR merge, or release edits are checked by the Aegis PreTool hook and Bruno before the original command runs.
- Protected GitHub/source-control mutations can use typed Broker MCP actions: call `list_remote_actions`, then `run_remote_action`.
- Approved cloud/deploy/package mutations can use fixed Broker CLI profiles: call `list_cli_profiles`, then `run_cli_profile`.
- Privileged credentialed actions such as `terraform apply` must use the Aegis Broker MCP server: call `list_commands`, then `run_command`.
- Ordinary commands such as `gh issue list`, `terraform plan`, and `git status` are not brokered by default.
- Use `aegis-secret command list` and `aegis-secret command show <NAME>` only as a local fallback when MCP is unavailable.
- If a shell tool call is blocked by `aegis-secret guard shell`, follow the block message. It may ask for evidence, or it may ask you to retry through Aegis Broker MCP.
- Aegis approval leases are per agent and wrapped command. The persisted lease identity includes the agent name, command name, resolved executable path, and policy fingerprint.
- Use `aegis-secret approval status <NAME> --agent Codex` to diagnose repeated approval prompts.
- Use `aegis-secret get <KEY> --agent Codex` only for explicit human-approved debugging or when the user specifically asks for the raw value.
"""

public func readPassword() -> String? {
    let stdinFD = FileHandle.standardInput.fileDescriptor
    var term = termios()
    tcgetattr(stdinFD, &term)

    let originalTerm = term
    term.c_lflag &= ~tcflag_t(ECHO)
    tcsetattr(stdinFD, TCSANOW, &term)

    defer {
        var restored = originalTerm
        tcsetattr(stdinFD, TCSANOW, &restored)
    }

    return readLine()
}

public func message(for status: OSStatus) -> String {
    if let text = SecCopyErrorMessageString(status, nil) as String? {
        return text
    }
    return "OSStatus \(status)"
}

public func prettyJSON<T: Encodable>(_ value: T) throws -> Data {
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
    return try encoder.encode(value)
}

public func expandUserPath(_ path: String) -> String {
    NSString(string: path).expandingTildeInPath
}

public func shellQuote(_ value: String) -> String {
    "'\(value.replacingOccurrences(of: "'", with: "'\\''"))'"
}

private extension String {
    var trimmedNonEmpty: String? {
        let trimmed = trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed.isEmpty ? nil : trimmed
    }

    var nilIfEmpty: String? {
        isEmpty ? nil : self
    }

    func ensureTrailingNewline() -> String {
        hasSuffix("\n") ? self : self + "\n"
    }
}
