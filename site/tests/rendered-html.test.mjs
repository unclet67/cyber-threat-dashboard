import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const root = new URL("../", import.meta.url);

test("ships the operational intelligence workflows", async () => {
  const page = await readFile(new URL("app/page.tsx", root), "utf8");
  for (const capability of [
    "Priority scores combine recency",
    "CISA KEV + FIRST EPSS",
    "Download Navigator layer",
    "Saved watchlists",
    "Evidence and source traceability",
    "Export STIX 2.1 bundle",
    "Copy structured brief",
    "Newest first",
  ]) assert.match(page, new RegExp(capability.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
});

test("configures durable analyst storage and its migration", async () => {
  const [hosting, schema, route, migration] = await Promise.all([
    readFile(new URL(".openai/hosting.json", root), "utf8"),
    readFile(new URL("db/schema.ts", root), "utf8"),
    readFile(new URL("app/api/workbench/route.ts", root), "utf8"),
    readFile(new URL("drizzle/0000_mute_lorna_dane.sql", root), "utf8"),
  ]);
  assert.match(hosting, /"d1": "DB"/);
  assert.match(schema, /analystState/);
  assert.match(route, /pins.*watchlists.*diamonds/);
  assert.match(migration, /CREATE TABLE `analyst_state`/);
});

test("keeps live-source fallback behavior", async () => {
  const page = await readFile(new URL("app/page.tsx", root), "utf8");
  assert.match(page, /raw\.githubusercontent\.com/);
  assert.match(page, /Snapshot fallback/);
  assert.match(page, /setInterval\(loadData, 15 \* 60 \* 1000\)/);
});

test("risk scoring exposes the field consumed by the interface", async () => {
  const page = await readFile(new URL("app/page.tsx", root), "utf8");
  assert.match(page, /return \{ score: Math\.min\(100, score\), riskReasons:/);
});
