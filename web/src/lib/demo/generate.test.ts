import { describe, expect, it } from "vitest";
import { evaluate, parse } from "@/lib/kql";
import { coverage, TECHNIQUES } from "@/lib/attack";
import { generate } from "./generate";

const now = Date.UTC(2026, 10, 9, 12, 0, 0);
const d = generate(now);

describe("demo dataset", () => {
  it("is deterministic", () => {
    const again = generate(now);
    expect(again.events.length).toBe(d.events.length);
    expect(again.events[0]!.id).toBe(d.events[0]!.id);
    expect(again.alerts.map((a) => a.id)).toEqual(d.alerts.map((a) => a.id));
  });
  it("keeps events inside the last 24 hours, newest first", () => {
    for (const e of d.events) {
      const t = Date.parse(e["@timestamp"]);
      expect(t).toBeLessThanOrEqual(now);
      expect(t).toBeGreaterThan(now - 25 * 3_600_000);
    }
    expect(d.events[0]!["@timestamp"] >= d.events[d.events.length - 1]!["@timestamp"]).toBe(true);
  });
  it("contains the brute-force then lateral-movement scenario", () => {
    const sc = d.events.filter((e) => e["argus.scenario"] === "bruteforce-lateral");
    const failures = sc.filter((e) => evaluate(parse("event.code:4625 and event.outcome:failure"), e));
    expect(failures.length).toBe(18);
    const hosts = new Set(sc.filter((e) => e["event.code"] === "5140").map((e) => e["host.name"]));
    expect(hosts.size).toBe(3);
    const inc = d.incidents.find((i) => i.id === "INC-1042")!;
    expect(inc.alertIds.length).toBe(5);
    expect(inc.alertIds.every((id) => d.alerts.find((a) => a.id === id)?.incidentId === "INC-1042")).toBe(true);
    expect(inc.timeline.length).toBeGreaterThan(10);
  });
  it("references only known rules and techniques", () => {
    const ruleIds = new Set(d.rules.map((r) => r.id));
    for (const a of d.alerts) expect(ruleIds.has(a.ruleId)).toBe(true);
    const known = new Set(TECHNIQUES.map((t) => t.id));
    const cov = coverage(d.rules);
    expect(cov.size).toBeGreaterThan(20);
    for (const t of cov.keys()) expect(known.has(t)).toBe(true);
  });
  it("chains audit entries by hash", () => {
    for (let i = 1; i < d.audit.length; i++) expect(d.audit[i]!.prevHash).toBe(d.audit[i - 1]!.hash);
  });
});
