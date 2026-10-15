#!/usr/bin/env node
import { Bridge } from "./bridge.js";
import { loadPolicy } from "./config.js";
import { PendingStore } from "./pending.js";
import { runStdio } from "./server.js";

/**
 * Tether CLI.
 *
 *   tether serve   [--config p] [--audit p] [--pending p]   run the MCP server (stdio)
 *   tether approve <actionId> [--pending p]                 operator: approve a queued high-risk action
 *   tether deny    <actionId> [--pending p]                 operator: reject one
 *   tether pending [--pending p]                            operator: list the queue
 *   tether call <tool> [--device d] [--sensor s] ...        invoke a tool directly (no MCP client, for testing)
 */

interface ParsedArgs {
  _: string[];
  flags: Record<string, string | boolean>;
}

function parseArgs(argv: string[]): ParsedArgs {
  const _: string[] = [];
  const flags: Record<string, string | boolean> = {};
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]!;
    if (a.startsWith("--")) {
      const key = a.slice(2);
      const next = argv[i + 1];
      if (next !== undefined && !next.startsWith("--")) {
        flags[key] = next;
        i++;
      } else {
        flags[key] = true;
      }
    } else {
      _.push(a);
    }
  }
  return { _, flags };
}

const USAGE = `tether — a security-first MCP bridge for microcontrollers

  tether serve   [--config <path>] [--audit <path>] [--pending <path>]
  tether approve <actionId> [--pending <path>]
  tether deny    <actionId> [--pending <path>]
  tether pending [--pending <path>]
  tether call <tool> --device <id> [--sensor <s>] [--actuator <a>] [--state <st>] [--command <c>] [--config <path>]
`;

async function main(): Promise<void> {
  const { _, flags } = parseArgs(process.argv.slice(2));
  const cmd = _[0];
  const pendingPath = String(flags["pending"] ?? "pending_actions.json");
  const configPath = String(flags["config"] ?? "config/policy.example.yaml");

  switch (cmd) {
    case "serve": {
      const policy = loadPolicy(configPath);
      const bridge = new Bridge(policy, {
        auditPath: String(flags["audit"] ?? "tether.audit.jsonl"),
        pendingPath,
      });
      console.error(`[tether] loaded ${Object.keys(policy.devices).length} device(s) from ${configPath}`);
      await runStdio(bridge);
      return; // stdio transport keeps the process alive
    }

    case "approve":
    case "deny": {
      const id = _[1];
      if (!id) fail(`${cmd} needs an <actionId>`);
      const store = new PendingStore(pendingPath);
      const a = cmd === "approve" ? store.approve(id!) : store.deny(id!);
      if (!a) fail(`no such action '${id}'`);
      if (cmd === "approve") {
        console.log(
          `approved ${a!.actionId} — ${a!.tool} ${JSON.stringify(a!.args)} on ${a!.deviceId}. ` +
            `The client's next check_action will execute it.`,
        );
      } else {
        console.log(`denied ${a!.actionId} — ${a!.tool} on ${a!.deviceId}`);
      }
      return;
    }

    case "pending": {
      const store = new PendingStore(pendingPath);
      const list = store.list();
      if (list.length === 0) {
        console.log("no actions in the queue");
        return;
      }
      for (const a of list) {
        console.log(
          `${a.actionId}  ${a.status.padEnd(9)} ${a.tool} ${JSON.stringify(a.args)} on ${a.deviceId}  (expires ${a.expiresAt})`,
        );
      }
      return;
    }

    case "call": {
      const tool = _[1];
      if (!tool) fail("call needs a <tool> name");
      const bridge = new Bridge(loadPolicy(configPath), { auditPath: null, pendingPath });
      const actor = { host: "cli" };
      const device = String(flags["device"] ?? "");
      let result: Record<string, unknown>;
      switch (tool) {
        case "list_devices":
          result = bridge.listDevices();
          break;
        case "describe_device":
          result = await bridge.describeDevice(actor, device);
          break;
        case "read_sensor":
          result = await bridge.runDeviceTool(actor, device, "read_sensor", {
            sensor: String(flags["sensor"] ?? ""),
          });
          break;
        case "set_actuator":
          result = await bridge.runDeviceTool(actor, device, "set_actuator", {
            actuator: String(flags["actuator"] ?? ""),
            state: String(flags["state"] ?? ""),
          });
          break;
        case "send_raw_command":
          result = await bridge.runDeviceTool(actor, device, "send_raw_command", {
            command: String(flags["command"] ?? ""),
          });
          break;
        case "check_action":
          result = await bridge.checkAction(actor, String(flags["action"] ?? _[2] ?? ""));
          break;
        case "query_audit_log":
          result = bridge.queryAudit({
            deviceId: flags["device"] ? device : undefined,
            tool: flags["tool"] ? String(flags["tool"]) : undefined,
            decision: flags["decision"] ? String(flags["decision"]) : undefined,
            limit: flags["limit"] ? Number(flags["limit"]) : undefined,
          });
          break;
        default:
          await bridge.close();
          fail(`unknown tool '${tool}'`);
          return;
      }
      console.log(JSON.stringify(result, null, 2));
      await bridge.close();
      return;
    }

    default:
      process.stdout.write(USAGE);
      process.exit(cmd ? 1 : 0);
  }
}

function fail(msg: string): never {
  console.error(`error: ${msg}`);
  process.exit(1);
}

main().catch((e) => {
  console.error(e instanceof Error ? e.message : String(e));
  process.exit(1);
});
