import { eq } from "drizzle-orm";
import { getDb } from "../../../db";
import { analystState } from "../../../db/schema";

const allowedKeys = new Set(["pins", "watchlists", "diamonds"]);

function errorMessage(error: unknown) {
  const message = error instanceof Error ? error.message : "Unexpected storage error";
  if (message.includes("no such table")) return "Workbench storage is being initialized. Please retry shortly.";
  return message;
}

export async function GET() {
  try {
    const rows = await getDb().select().from(analystState);
    const state = Object.fromEntries(rows.map((row) => {
      try { return [row.key, JSON.parse(row.value)]; }
      catch { return [row.key, []]; }
    }));
    return Response.json({ state, durable: true });
  } catch (error) {
    return Response.json({ error: errorMessage(error) }, { status: 503 });
  }
}

export async function PUT(request: Request) {
  try {
    const payload = await request.json() as { key?: string; value?: unknown };
    if (!payload.key || !allowedKeys.has(payload.key)) {
      return Response.json({ error: "Unsupported workbench key" }, { status: 400 });
    }
    const value = JSON.stringify(payload.value ?? []);
    if (value.length > 250_000) return Response.json({ error: "Workbench item is too large" }, { status: 413 });
    const db = getDb();
    await db.insert(analystState).values({ key: payload.key, value })
      .onConflictDoUpdate({ target: analystState.key, set: { value, updatedAt: new Date().toISOString() } });
    const [saved] = await db.select().from(analystState).where(eq(analystState.key, payload.key));
    return Response.json({ saved: { key: saved.key, updatedAt: saved.updatedAt }, durable: true });
  } catch (error) {
    return Response.json({ error: errorMessage(error) }, { status: 503 });
  }
}
