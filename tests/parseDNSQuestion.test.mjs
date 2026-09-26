import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import vm from 'node:vm';
import path from 'node:path';

const workerPath = path.resolve(fileURLToPath(new URL('../Worker.js', import.meta.url)));
const workerSource = await readFile(workerPath, 'utf8');
const runnableSource = workerSource.replace(
  /^export default \{/m,
  'const __workerExport = {'
);

const context = vm.createContext({
  AbortController,
  Map,
  Promise,
  Uint8Array,
  ArrayBuffer,
  Number,
  Math,
  String,
  Date,
  setTimeout,
  clearTimeout,
  console
});
vm.runInContext(runnableSource, context, { filename: workerPath });
const parseDNSQuestion = vm.runInContext('parseDNSQuestion', context);
const readResourceRecord = vm.runInContext('readResourceRecord', context);

function u16(value) {
  return [(value >>> 8) & 0xff, value & 0xff];
}

function u32(value) {
  return [
    (value >>> 24) & 0xff,
    (value >>> 16) & 0xff,
    (value >>> 8) & 0xff,
    value & 0xff
  ];
}

function encodeName(labels) {
  const out = [];
  for (const label of labels) {
    const bytes = Array.from(Buffer.from(label, 'ascii'));
    assert.ok(bytes.length <= 63);
    out.push(bytes.length, ...bytes);
  }
  out.push(0);
  return out;
}

function makeQuery({
  id = 0x1234,
  flags = 0x0100,
  labels = ['example', 'com'],
  qtype = 1,
  qclass = 1,
  ancount = 0,
  nscount = 0,
  additional = []
} = {}) {
  const header = [
    ...u16(id),
    ...u16(flags),
    ...u16(1),
    ...u16(ancount),
    ...u16(nscount),
    ...u16(additional.length)
  ];

  return new Uint8Array([
    ...header,
    ...encodeName(labels),
    ...u16(qtype),
    ...u16(qclass),
    ...additional.flat()
  ]);
}

function makeOPTRecord({ udpPayloadSize = 1232, ttl = 0, rdata = [] } = {}) {
  return [
    0,
    ...u16(41),
    ...u16(udpPayloadSize),
    ...u32(ttl),
    ...u16(rdata.length),
    ...rdata
  ];
}

function parse(packet) {
  return parseDNSQuestion(packet);
}

test('accepts a valid standard A query and preserves the transaction ID', () => {
  const result = parse(makeQuery({ id: 0xbeef }));
  assert.equal(result.ok, true);
  assert.equal(result.id, 0xbeef);
});

test('accepts a valid AAAA query', () => {
  const result = parse(makeQuery({ qtype: 28 }));
  assert.equal(result.ok, true);
  assert.equal(result.id, 0x1234);
});

test('accepts a valid root-name query', () => {
  const result = parse(makeQuery({ labels: [] }));
  assert.equal(result.ok, true);
  assert.equal(result.id, 0x1234);
});

test('rejects DNS response packets', () => {
  const result = parse(makeQuery({ flags: 0x8100 }));
  assert.equal(result.ok, false);
  assert.match(result.error, /response/i);
});

test('rejects queries with QDCOUNT other than one', () => {
  const packet = makeQuery();
  packet[4] = 0;
  packet[5] = 0;
  const result = parse(packet);
  assert.equal(result.ok, false);
  assert.match(result.error, /section counts/i);
});

test('rejects queries containing answer records', () => {
  const packet = makeQuery({ ancount: 1 });
  const result = parse(packet);
  assert.equal(result.ok, false);
  assert.match(result.error, /section counts/i);
});

test('rejects queries containing authority records', () => {
  const packet = makeQuery({ nscount: 1 });
  const result = parse(packet);
  assert.equal(result.ok, false);
  assert.match(result.error, /section counts/i);
});

test('accepts a valid EDNS(0) OPT additional record', () => {
  const packet = makeQuery({ additional: [makeOPTRecord()] });
  const result = parse(packet);
  assert.equal(result.ok, true);
  assert.equal(result.id, 0x1234);
});

test('rejects a truncated question name', () => {
  let packet = makeQuery();
  packet[12] = 10;
  packet = packet.slice(0, 22);
  const result = parse(packet);
  assert.equal(result.ok, false);
  assert.match(result.error, /invalid DNS question name|incomplete DNS question/i);
});

test('rejects a question name missing its terminating zero octet', () => {
  const packet = makeQuery();
  const withoutTerminator = packet.slice(0, 12 + 1 + 7 + 1 + 3);
  const result = parse(withoutTerminator);
  assert.equal(result.ok, false);
  assert.match(result.error, /incomplete DNS question|invalid DNS question name/i);
});

test('rejects a compressed question name', () => {
  const packet = makeQuery();
  packet[12] = 0xc0;
  packet[13] = 0x0c;
  const result = parse(packet);
  assert.equal(result.ok, false);
  assert.match(result.error, /label encoding/i);
});

test('rejects reserved DNS label encodings', () => {
  const packet = makeQuery();
  packet[12] = 0x80;
  const result = parse(packet);
  assert.equal(result.ok, false);
  assert.match(result.error, /label encoding/i);
});

test('rejects a label longer than 63 octets', () => {
  const packet = makeQuery({ labels: ['a'.repeat(63), 'com'] });
  packet[12] = 64;
  const result = parse(packet);
  assert.equal(result.ok, false);
  assert.match(result.error, /label encoding/i);
});

test('accepts the maximum legal 255-octet wire-format DNS name', () => {
  const labels = ['a'.repeat(63), 'b'.repeat(63), 'c'.repeat(63), 'd'.repeat(61)];
  const packet = makeQuery({ labels });
  const result = parse(packet);
  assert.equal(result.ok, true);
  assert.equal(result.id, 0x1234);
});

test('rejects a DNS name exceeding 255 wire octets', () => {
  const labels = ['a'.repeat(63), 'b'.repeat(63), 'c'.repeat(63), 'd'.repeat(62)];
  const packet = makeQuery({ labels });
  const result = parse(packet);
  assert.equal(result.ok, false);
  assert.match(result.error, /name too long/i);
});

test('rejects a truncated QTYPE/QCLASS', () => {
  const packet = makeQuery().slice(0, -1);
  const result = parse(packet);
  assert.equal(result.ok, false);
  assert.match(result.error, /incomplete DNS question/i);
});


test('rejects the reserved DNS Z bit', () => {
  const packet = makeQuery({ flags: 0x0140 });
  const result = parse(packet);
  assert.equal(result.ok, false);
  assert.match(result.error, /reserved/i);
});

test('rejects compressed Additional-section names with out-of-range pointers', () => {
  const badOpt = [0xc0, 0xff, ...u16(41), ...u16(1232), ...u32(0), ...u16(0)];
  const packet = makeQuery({ additional: [badOpt] });
  const result = parse(packet);
  assert.equal(result.ok, false);
  assert.match(result.error, /additional section/i);
});

test('rejects unsupported non-standard DNS opcodes', () => {
  const packet = makeQuery({ flags: 0x0900 });
  const result = parse(packet);
  assert.equal(result.ok, false);
  assert.match(result.error, /standard DNS queries/i);
});

test('rejects malformed additional records', () => {
  const packet = makeQuery({ additional: [makeOPTRecord().slice(0, -1)] });
  const result = parse(packet);
  assert.equal(result.ok, false);
  assert.match(result.error, /additional section/i);
});

test('rejects trailing bytes after the declared DNS message', () => {
  const packet = new Uint8Array([...makeQuery(), 0xde, 0xad, 0xbe, 0xef]);
  const result = parse(packet);
  assert.equal(result.ok, false);
  assert.match(result.error, /trailing data/i);
});

test('rejects truncated packet shorter than the DNS header', () => {
  const result = parse(new Uint8Array(11));
  assert.equal(result.ok, false);
  assert.match(result.error, /too short/i);
});

test('validates additional-section record framing with the same RR parser used for responses', () => {
  const opt = makeOPTRecord({ rdata: [0, 12, 0, 4, 0x00, 0x01, 0x00, 0x00] });
  const packet = makeQuery({ additional: [opt] });
  const additionalOffset = packet.length - opt.length;
  const rr = readResourceRecord(packet, additionalOffset);
  assert.ok(rr);
  assert.equal(rr.type, 41);
  assert.equal(rr.end, packet.length);
});
