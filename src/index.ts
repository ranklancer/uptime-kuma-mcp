#!/usr/bin/env node
import http from 'node:http';
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { CallToolRequestSchema, ListToolsRequestSchema } from '@modelcontextprotocol/sdk/types.js';
import { z } from 'zod';
import { toolDefs } from './tools.js';
import { invalidDenyEntries, invalidAllowEntries, invalidNotificationHostEntries } from './policy.js';
import { disconnectAll } from './instances.js';

const PORT = parseInt(process.env.PORT ?? '3000', 10);
const HOST = process.env.HOST ?? '0.0.0.0';

/** Zod v4 native JSON Schema for MCP tool registration (input side: defaults/optionals as the caller sees them). */
function zodToJsonSchema(schema: z.ZodType<any>): Record<string, any> {
  const js = z.toJSONSchema(schema, { target: 'draft-7', io: 'input', unrepresentable: 'any' }) as Record<string, any>;
  delete js.$schema;
  if (!js.required) js.required = [];
  return js;
}

// ── Per-session MCP server factory ──────────────────────────────────

function createMcpServer(): Server {
  const server = new Server(
    { name: 'uptime-kuma-mcp', version: '0.1.0' },
    { capabilities: { tools: {} } },
  );

  server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: toolDefs.map(t => ({
      name: t.name,
      description: t.description,
      inputSchema: zodToJsonSchema(t.schema),
    })),
  }));

  server.setRequestHandler(CallToolRequestSchema, async (req) => {
    const tool = toolDefs.find(t => t.name === req.params.name);
    if (!tool) throw new Error(`Unknown tool: ${req.params.name}`);

    const args = tool.schema.parse(req.params.arguments ?? {});
    try {
      const result = await tool.handler(args);
      return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
    } catch (err: any) {
      return { isError: true, content: [{ type: 'text', text: String(err?.message ?? err) }] };
    }
  });

  return server;
}

// ── Session management ──────────────────────────────────────────────

interface McpSession {
  transport: StreamableHTTPServerTransport;
  server: Server;
}

const sessions = new Map<string, McpSession>();
const closingSessions = new Set<string>();

function cleanupSession(sessionId: string): void {
  if (!sessionId || closingSessions.has(sessionId)) return;
  closingSessions.add(sessionId);
  sessions.delete(sessionId);
  // Don't call server.close() here — it triggers transport.onclose
  // which would recurse back into this function.
  closingSessions.delete(sessionId);
}

// ── HTTP server ─────────────────────────────────────────────────────

const httpServer = http.createServer(async (req, res) => {
  // Health check
  if (req.url === '/health') {
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({
      ok: true,
      service: 'uptime-kuma-mcp',
      version: '0.1.0',
      activeSessions: sessions.size,
    }));
    return;
  }

  if (!req.url?.startsWith('/mcp')) {
    res.writeHead(404).end('not found');
    return;
  }

  // Check for existing session
  const sessionId = req.headers['mcp-session-id'] as string | undefined;

  if (sessionId && sessions.has(sessionId)) {
    // Route to existing session
    const session = sessions.get(sessionId)!;
    await session.transport.handleRequest(req, res);
    return;
  }

  if (sessionId && !sessions.has(sessionId)) {
    // Unknown session ID — client must re-initialize
    res.writeHead(404, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ jsonrpc: '2.0', error: { code: -32000, message: 'Session not found' }, id: null }));
    return;
  }

  // No session ID — new connection. Only POST (initialize) is valid here.
  if (req.method !== 'POST') {
    res.writeHead(405).end('Method not allowed — initialize with POST first');
    return;
  }

  // Create a fresh server + transport for this session
  const transport = new StreamableHTTPServerTransport({
    sessionIdGenerator: () => crypto.randomUUID(),
  });
  const server = createMcpServer();
  await server.connect(transport);

  // Clean up when the session closes (just remove from map, no recursive close)
  transport.onclose = () => {
    const sid = (transport as any).sessionId ?? (transport as any)._sessionId;
    if (sid) cleanupSession(sid);
  };

  // Handle the initialize request
  await transport.handleRequest(req, res);

  // Store the session (sessionId is set after handling the first request)
  const newSessionId = (transport as any).sessionId ?? (transport as any)._sessionId;
  if (newSessionId) {
    sessions.set(newSessionId, { transport, server });
  }
});

{
  const bad = invalidDenyEntries();
  if (bad.length > 0) {
    console.error(`WARNING: KUMA_MCP_DENY_HOSTS has invalid entries (monitor add/edit will fail until fixed): ${bad.join(', ')}`);
  }
  const badNotif = invalidNotificationHostEntries();
  if (badNotif.length > 0) {
    console.error(`WARNING: KUMA_MCP_NOTIFICATION_HOSTS has invalid entries (ignored, so those destinations are refused): ${badNotif.join(', ')}`);
  }
  const badAllow = invalidAllowEntries();
  if (badAllow.length > 0) {
    console.error(`WARNING: KUMA_MCP_ALLOW_HOSTS has invalid entries (ignored, so those hosts stay unverified and are refused): ${badAllow.join(', ')}`);
  }
}

httpServer.listen(PORT, HOST, () => {
  console.log(`uptime-kuma-mcp listening on http://${HOST}:${PORT}`);
  console.log(`Sessions: per-connection (multi-client safe)`);
});

async function shutdown() {
  // Close all active sessions gracefully
  for (const [sid, session] of sessions) {
    closingSessions.add(sid);
    await session.server.close().catch(() => {});
  }
  sessions.clear();
  closingSessions.clear();
  await disconnectAll();
  httpServer.close();
  process.exit(0);
}
process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);
