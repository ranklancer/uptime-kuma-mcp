import { test } from 'node:test';
import assert from 'node:assert/strict';
import { z } from 'zod';
process.env.KUMA_INSTANCES ??= 'kuma';
process.env.KUMA_BASE_URL ??= 'http://kuma.test:3001';
process.env.KUMA_USERNAME ??= 'u';
process.env.KUMA_PASSWORD ??= 'p';
const { toolDefs } = await import('../src/tools.js');

test('zod v4 JSON schema keeps every tool field, required set, and bounds', () => {
  for (const t of toolDefs) {
    const js: any = z.toJSONSchema(t.schema, { target: 'draft-7', io: 'input', unrepresentable: 'any' });
    const keys = Object.keys((t.schema as any).shape).sort();
    assert.deepEqual(Object.keys(js.properties ?? {}).sort(), keys, t.name);
  }
  const add: any = z.toJSONSchema(toolDefs.find((t) => t.name === 'uptimekuma_add_monitor')!.schema, { target: 'draft-7', io: 'input' });
  assert.equal(add.properties.port.maximum, 65535);
  assert.ok(add.required.includes('name'));
});
