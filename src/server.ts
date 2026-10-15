import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import type { Bridge } from "./bridge.js";

/**
 * The MCP surface. This is the only module coupled to the MCP SDK — every tool handler is a thin
 * shim over a Bridge method, so the security pipeline stays fully testable without the SDK. Each
 * result is returned as JSON text; `isError` is set whenever the bridge reports `ok: false`.
 */

const ACTOR = { host: "mcp" };

function toResult(r: Record<string, unknown>) {
  return {
    content: [{ type: "text" as const, text: JSON.stringify(r, null, 2) }],
    isError: r["ok"] === false,
  };
}

export function buildMcpServer(bridge: Bridge): McpServer {
  const server = new McpServer({ name: "tether", version: "0.1.0" });

  server.registerTool(
    "list_devices",
    {
      description:
        "List the microcontrollers Tether can reach, with each device's enabled tools and risk tiers.",
      inputSchema: {},
    },
    async () => toResult(bridge.listDevices()),
  );

  server.registerTool(
    "describe_device",
    {
      description:
        "Describe a device's sensors and actuators (names, types, units, ranges), filtered to what policy allows.",
      inputSchema: { deviceId: z.string() },
    },
    async ({ deviceId }) => toResult(await bridge.describeDevice(ACTOR, deviceId)),
  );

  server.registerTool(
    "read_sensor",
    {
      description: "Read a sensor value from a device. Read-only.",
      inputSchema: { deviceId: z.string(), sensor: z.string() },
    },
    async ({ deviceId, sensor }) =>
      toResult(await bridge.runDeviceTool(ACTOR, deviceId, "read_sensor", { sensor })),
  );

  server.registerTool(
    "set_actuator",
    {
      description:
        "Set an actuator state (e.g. relay on/off). May be high-risk and require operator confirmation before it executes.",
      inputSchema: { deviceId: z.string(), actuator: z.string(), state: z.string() },
    },
    async ({ deviceId, actuator, state }) =>
      toResult(await bridge.runDeviceTool(ACTOR, deviceId, "set_actuator", { actuator, state })),
  );

  server.registerTool(
    "send_raw_command",
    {
      description:
        "Send a raw command string to a device. High-risk; disabled unless explicitly allowed in policy.",
      inputSchema: { deviceId: z.string(), command: z.string() },
    },
    async ({ deviceId, command }) =>
      toResult(await bridge.runDeviceTool(ACTOR, deviceId, "send_raw_command", { command })),
  );

  server.registerTool(
    "check_action",
    {
      description:
        "Check a queued high-risk action; once an operator has approved it, this executes it and returns the result.",
      inputSchema: { actionId: z.string() },
    },
    async ({ actionId }) => toResult(await bridge.checkAction(ACTOR, actionId)),
  );

  server.registerTool(
    "query_audit_log",
    {
      description: "Query Tether's audit log of recent tool calls (forensic trail).",
      inputSchema: {
        deviceId: z.string().optional(),
        tool: z.string().optional(),
        decision: z.string().optional(),
        limit: z.number().int().positive().optional(),
      },
    },
    async ({ deviceId, tool, decision, limit }) =>
      toResult(bridge.queryAudit({ deviceId, tool, decision, limit })),
  );

  return server;
}

export async function runStdio(bridge: Bridge): Promise<void> {
  const server = buildMcpServer(bridge);
  const transport = new StdioServerTransport();
  await server.connect(transport);
  // stdout is the MCP channel — all diagnostics must go to stderr.
  console.error("[tether] MCP server ready on stdio");
}
