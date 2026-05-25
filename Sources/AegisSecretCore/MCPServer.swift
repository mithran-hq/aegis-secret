import Foundation

private struct ToolErrorPayload: Codable {
    let error: String
    let receipt: ToolDecisionReceipt?
}

public enum JSONValue: Codable, Equatable, Sendable {
    case string(String)
    case number(Double)
    case integer(Int)
    case bool(Bool)
    case object([String: JSONValue])
    case array([JSONValue])
    case null

    public init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        if container.decodeNil() {
            self = .null
        } else if let value = try? container.decode(Bool.self) {
            self = .bool(value)
        } else if let value = try? container.decode(Int.self) {
            self = .integer(value)
        } else if let value = try? container.decode(Double.self) {
            self = .number(value)
        } else if let value = try? container.decode(String.self) {
            self = .string(value)
        } else if let value = try? container.decode([String: JSONValue].self) {
            self = .object(value)
        } else if let value = try? container.decode([JSONValue].self) {
            self = .array(value)
        } else {
            throw DecodingError.dataCorruptedError(in: container, debugDescription: "Unsupported JSON value.")
        }
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        switch self {
        case .string(let value):
            try container.encode(value)
        case .number(let value):
            try container.encode(value)
        case .integer(let value):
            try container.encode(value)
        case .bool(let value):
            try container.encode(value)
        case .object(let value):
            try container.encode(value)
        case .array(let value):
            try container.encode(value)
        case .null:
            try container.encodeNil()
        }
    }

    public var stringValue: String? {
        if case .string(let value) = self { return value }
        return nil
    }

    public var integerValue: Int? {
        if case .integer(let value) = self { return value }
        return nil
    }

    public var objectValue: [String: JSONValue]? {
        if case .object(let value) = self { return value }
        return nil
    }

    public var arrayValue: [JSONValue]? {
        if case .array(let value) = self { return value }
        return nil
    }
}

private struct RPCRequest: Decodable {
    let jsonrpc: String?
    let id: JSONValue?
    let method: String
    let params: JSONValue?
}

private struct RPCResponse<Payload: Encodable>: Encodable {
    let jsonrpc = "2.0"
    let id: JSONValue?
    let result: Payload?
    let error: RPCError?
}

private struct RPCError: Encodable {
    let code: Int
    let message: String
}

private struct ServerInfo: Codable {
    let name: String
    let version: String
}

private struct InitializeResult: Codable {
    let protocolVersion: String
    let capabilities: [String: JSONValue]
    let serverInfo: ServerInfo
}

private struct ToolDescriptor: Codable {
    let name: String
    let title: String
    let description: String
    let inputSchema: [String: JSONValue]
    let outputSchema: [String: JSONValue]
}

private struct ToolsListResult: Codable {
    let tools: [ToolDescriptor]
}

private struct ToolContent: Codable {
    let type: String
    let text: String
}

private struct ToolCallResult<Payload: Encodable>: Encodable {
    let content: [ToolContent]
    let structuredContent: Payload
    let isError: Bool
}

private struct ListCommandsToolResponse: Encodable {
    let commands: [WrappedCommandSummary]
    let receipt: ToolDecisionReceipt
}

public final class StdioMCPServer {
    private let commandStore: CommandStore
    private let runner: WrappedCommandRunner
    private let agentName: String?
    private let receiptRecorder: ToolDecisionReceiptRecorder

    public init(
        commandStore: CommandStore = CommandStore(),
        runner: WrappedCommandRunner? = nil,
        agentName: String? = ProcessInfo.processInfo.environment["AEGIS_SECRET_AGENT_NAME"],
        receiptRecorder: ToolDecisionReceiptRecorder = ToolDecisionReceiptRecorder()
    ) {
        self.commandStore = commandStore
        self.runner = runner ?? WrappedCommandRunner(commandStore: commandStore, secretStore: KeychainSecretStore())
        self.agentName = agentName
        self.receiptRecorder = receiptRecorder
    }

    public func run() async {
        while let line = readLine() {
            let trimmed = line.trimmingCharacters(in: .whitespacesAndNewlines)
            if trimmed.isEmpty {
                continue
            }

            do {
                let request = try JSONDecoder().decode(RPCRequest.self, from: Data(trimmed.utf8))
                try await handle(request)
            } catch {
                try? emit(RPCResponse<JSONValue>(
                    id: nil,
                    result: nil,
                    error: RPCError(code: -32700, message: "Invalid JSON-RPC request: \(error.localizedDescription)")
                ))
            }
        }
    }

    private func handle(_ request: RPCRequest) async throws {
        switch request.method {
        case "initialize":
            let result = InitializeResult(
                protocolVersion: "2024-11-05",
                capabilities: [
                    "tools": .object([
                        "listChanged": .bool(false),
                    ]),
                ],
                serverInfo: ServerInfo(name: "aegis-secret", version: "0.2.0")
            )
            try emit(RPCResponse(id: request.id, result: result, error: nil))
        case "notifications/initialized":
            return
        case "tools/list":
            try emit(RPCResponse(id: request.id, result: ToolsListResult(tools: toolDescriptors()), error: nil))
        case "tools/call":
            guard let params = request.params?.objectValue else {
                try emitError(id: request.id, message: "Missing tool call params.")
                return
            }
            try await handleToolCall(id: request.id, params: params)
        default:
            if request.id != nil {
                try emitError(id: request.id, message: "Unknown method `\(request.method)`.")
            }
        }
    }

    private func handleToolCall(id: JSONValue?, params: [String: JSONValue]) async throws {
        guard let name = params["name"]?.stringValue else {
            try emitError(id: id, message: "Missing tool name.")
            return
        }

        let arguments = params["arguments"]?.objectValue ?? [:]

        do {
            switch name {
            case "list_commands":
                let startedAt = Date()
                let commands = try commandStore.listCommands()
                let receipt = ToolDecisionReceipt(
                    surface: "mcp",
                    toolName: "list_commands",
                    commandName: nil,
                    argv: [],
                    cwd: nil,
                    requester: agentName,
                    matchedPolicy: nil,
                    decision: "allow",
                    approvalState: .notRequired,
                    startedAt: iso8601String(startedAt),
                    completedAt: iso8601String(Date()),
                    exitCode: nil,
                    stdoutTruncated: false,
                    stderrTruncated: false,
                    output: nil,
                    error: nil
                )
                try? receiptRecorder.record(receipt)
                try emitToolResult(id: id, payload: ListCommandsToolResponse(commands: commands, receipt: receipt))
            case "run_command":
                guard let commandName = arguments["name"]?.stringValue else {
                    try emitToolError(id: id, message: "Missing `name`.")
                    return
                }
                let args = try decodeArgs(arguments["args"])
                let cwd = arguments["cwd"]?.stringValue
                let requester = arguments["requester"]?.stringValue ?? agentName ?? "MCP client"
                let result = try await runner.run(
                    name: commandName,
                    args: args,
                    cwd: cwd,
                    requester: requester,
                    surface: "mcp"
                )
                try? receiptRecorder.record(result.receipt)
                try emitToolResult(id: id, payload: result)
            default:
                try emitToolError(id: id, message: "Unknown tool `\(name)`.")
            }
        } catch let error as AegisSecretError {
            let receipt = deniedRunReceiptIfPossible(toolName: name, arguments: arguments, message: error.description)
            if let receipt {
                try? receiptRecorder.record(receipt)
            }
            try emitToolError(id: id, message: error.description, receipt: receipt)
        } catch {
            let receipt = deniedRunReceiptIfPossible(toolName: name, arguments: arguments, message: error.localizedDescription)
            if let receipt {
                try? receiptRecorder.record(receipt)
            }
            try emitToolError(id: id, message: error.localizedDescription, receipt: receipt)
        }
    }

    private func deniedRunReceiptIfPossible(
        toolName: String,
        arguments: [String: JSONValue],
        message: String
    ) -> ToolDecisionReceipt? {
        guard toolName == "run_command", let commandName = arguments["name"]?.stringValue else {
            return nil
        }

        let args = (try? decodeArgs(arguments["args"])) ?? []
        let cwd = arguments["cwd"]?.stringValue
        let requester = arguments["requester"]?.stringValue ?? agentName ?? "MCP client"
        return runner.deniedReceipt(
            name: commandName,
            args: args,
            cwd: cwd,
            requester: requester,
            surface: "mcp",
            error: message
        )
    }

    private func toolDescriptors() -> [ToolDescriptor] {
        [
            ToolDescriptor(
                name: "list_commands",
                title: "List brokered privileged commands",
                description: "List the local CLIs that Aegis Broker can run through MCP when a protected or privileged action requires brokered execution. Ordinary commands are not brokered by default.",
                inputSchema: [
                    "type": .string("object"),
                    "properties": .object([:]),
                ],
                outputSchema: [
                    "type": .string("object"),
                    "properties": .object([
                        "commands": .object([
                            "type": .string("array")
                        ]),
                        "receipt": .object([
                            "description": .string("D37-compatible decision receipt written to the local JSONL handoff file.")
                        ])
                    ]),
                ]
            ),
            ToolDescriptor(
                name: "run_command",
                title: "Run brokered command",
                description: "Run a configured command through Aegis Broker with Touch ID approval and redacted output. Use this for privileged credentialed actions when the PreTool hook requires brokered execution; ordinary commands should use the normal tool path.",
                inputSchema: [
                    "type": .string("object"),
                    "properties": .object([
                        "name": .object([
                            "type": .string("string"),
                            "description": .string("Wrapped command name to run, such as gh, aws, or gcloud.")
                        ]),
                        "args": .object([
                            "type": .string("array"),
                            "description": .string("Argument vector to pass to the wrapped command.")
                        ]),
                        "cwd": .object([
                            "type": .string("string"),
                            "description": .string("Optional absolute working directory for the command.")
                        ]),
                        "requester": .object([
                            "type": .string("string"),
                            "description": .string("Optional caller label shown in the approval prompt.")
                        ]),
                    ]),
                    "required": .array([
                        .string("name"),
                        .string("args"),
                    ]),
                ],
                outputSchema: [
                    "type": .string("object"),
                    "properties": .object([
                        "exit_code": .object(["type": .string("integer")]),
                        "stdout": .object(["type": .string("string")]),
                        "stderr": .object(["type": .string("string")]),
                        "stdout_json": .object(["description": .string("Parsed stdout when stdout is valid JSON.")]),
                        "stdout_truncated": .object(["type": .string("boolean")]),
                        "stderr_truncated": .object(["type": .string("boolean")]),
                        "receipt": .object(["description": .string("D37-compatible decision receipt written to the local JSONL handoff file.")]),
                    ]),
                ]
            ),
        ]
    }

    private func decodeArgs(_ value: JSONValue?) throws -> [String] {
        guard let array = value?.arrayValue else {
            throw AegisSecretError.runtime("`args` must be an array of strings.")
        }

        return try array.enumerated().map { index, item in
            guard let value = item.stringValue else {
                throw AegisSecretError.runtime("`args[\(index)]` must be a string.")
            }
            return value
        }
    }

    private func emit<Payload: Encodable>(_ response: RPCResponse<Payload>) throws {
        let data = try JSONEncoder().encode(response)
        FileHandle.standardOutput.write(data)
        FileHandle.standardOutput.write(Data([0x0A]))
    }

    private func emitError(id: JSONValue?, message: String) throws {
        try emit(RPCResponse<JSONValue>(
            id: id,
            result: nil,
            error: RPCError(code: -32602, message: message)
        ))
    }

    private func emitToolError(id: JSONValue?, message: String, receipt: ToolDecisionReceipt? = nil) throws {
        try emit(RPCResponse(
            id: id,
            result: ToolCallResult(
                content: [ToolContent(type: "text", text: "Error: \(message)")],
                structuredContent: ToolErrorPayload(error: message, receipt: receipt),
                isError: true
            ),
            error: nil
        ))
    }

    private func emitToolResult<Payload: Encodable>(id: JSONValue?, payload: Payload) throws {
        let payloadData = try JSONEncoder().encode(payload)
        let payloadText = String(decoding: payloadData, as: UTF8.self)

        try emit(RPCResponse(
            id: id,
            result: ToolCallResult(
                content: [ToolContent(type: "text", text: payloadText)],
                structuredContent: payload,
                isError: false
            ),
            error: nil
        ))
    }
}
