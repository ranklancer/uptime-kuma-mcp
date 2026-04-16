#!/usr/bin/env node
import http from 'node:http';
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { CallToolRequestSchema, ListToolsRequestSchema } from '@modelcontextprotocol/sdk/types.js';
import { z } from 'zod';
import { toolDefs } from './tools.js';
import { disconnectAll } from './instances.js';

const PORT = parseInt(process.env.PORT ?? '3000', 10);
const HOST = process.env.HOST ?? '0.0.0.0';

/** Minimal Zod-to-JSON-Schema converter for MCP tool registration. */
function zodToJsonSchema(schema: z.ZodType<any>): Record<string, any> {
  if (!(schema instanceof z.ZodObject)) return { type: 'object' };
  const shape = (schema as z.ZodObject<any>).shape;
  const properties: Record<string, any> = {};
  const required: string[] = [];

  for (const [key, val] of Object.entries(shape)) {
    let v = val as z.ZodType<any>;
    let optional = false;

    if (v instanceof z.ZodOptional) { v = (v as any)._def.innerType; optional = true; }
    if (v instanceof z.ZodDefault)  { v = (v as any)._def.innerType; optional = true; }

    let prop: Record<string, any> = { type: 'string' };
    if      (v instanceof z.ZodString)  prop = { type: 'string' };
    else if (v instanceof z.ZodNumber)  prop = { type: 'number' };
    else if (v instanceof z.ZodBoolean) prop = { type: 'boolean' };
    else if (v instanceof z.ZodEnum)    prop = { type: 'string', enum: (v as any)._def.values };

    if ((val as any)?._def?.description) prop.description = (val as any)._def.description;

    properties[key] = prop;
    if (!optional) required.push(key);
  }
  return { type: 'object', properties, required };
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

// ── HTTP server ─────────────────────────────────────────────────────

const httpServer = http.createServer(async (req, res) => {
  // Health check
  if (req.url === '/health') {
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ ok: true, service: 'uptime-kuma-mcp', version: '0.1.0' }));
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

  // Clean up when the session closes
  transport.onclose = () => {
    const sid = (transport as any).sessionId ?? (transport as any)._sessionId;
    if (sid) sessions.delete(sid);
    server.close().catch(() => {});
  };

  // Handle the initialize request
  await transport.handleRequest(req, res);

  // Store the session (sessionId is set after handling the first request)
  const newSessionId = (transport as any).sessionId ?? (transport as any)._sessionId;
  if (newSessionId) {
    sessions.set(newSessionId, { transport, server });
  }
});

httpServer.listen(PORT, HOST, () => {
  console.log(`uptime-kuma-mcp listening on http://${HOST}:${PORT}`);
  console.log(`Sessions: per-connection (multi-client safe)`);
});

async function shutdown() {
  // Close all active sessions
  for (const [, session] of sessions) {
    await session.server.close().catch(() => {});
  }
  sessions.clear();
  await disconnectAll();
  httpServer.close();
  process.exit(0);
}
process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);
