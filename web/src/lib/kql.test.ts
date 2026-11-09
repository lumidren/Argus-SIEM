import { describe, expect, it } from "vitest";
import { costWarnings, evaluate, fieldsOf, KQLError, parse, quote } from "./kql";

const doc = {
  "event.action": "logon-failed",
  "event.outcome": "failure",
  "user.name": "alice",
  "source.ip": "198.51.100.7",
  "source.port": 51234,
  "host.name": "ws01.corp.local",
  "event.category": ["authentication"],
  message: "An account failed to log on",
};

const q = (s: string) => evaluate(parse(s), doc);

describe("kql", () => {
  it("matches fields, case-insensitively", () => {
    expect(q("user.name:alice")).toBe(true);
    expect(q("user.name:ALICE")).toBe(true);
    expect(q("user.name:bob")).toBe(false);
    expect(q("event.category:authentication")).toBe(true);
  });
  it("supports boolean logic and grouping", () => {
    expect(q("user.name:alice and event.outcome:failure")).toBe(true);
    expect(q("user.name:bob or event.outcome:failure")).toBe(true);
    expect(q("not user.name:alice")).toBe(false);
    expect(q("(user.name:bob or user.name:alice) and not host.name:dc01")).toBe(true);
    expect(q("user.name:alice event.outcome:failure")).toBe(true); // implicit AND
    expect(q("user.name:(bob or alice)")).toBe(true);
  });
  it("supports wildcards, phrases, existence and ranges", () => {
    expect(q("host.name:ws*")).toBe(true);
    expect(q("host.name:*.corp.local")).toBe(true);
    expect(q('message:"An account failed to log on"')).toBe(true);
    expect(q('"failed to log"')).toBe(true);
    expect(q("source.ip:*")).toBe(true);
    expect(q("destination.ip:*")).toBe(false);
    expect(q("source.port >= 50000")).toBe(true);
    expect(q("source.port < 1024")).toBe(false);
    expect(q("alice")).toBe(true);
  });
  it("matches everything for an empty query", () => {
    expect(q("")).toBe(true);
    expect(q("   ")).toBe(true);
  });
  it("reports syntax errors with positions", () => {
    expect(() => parse("user.name:")).toThrow(KQLError);
    expect(() => parse("(user.name:alice")).toThrow(/parenthesis/);
    expect(() => parse('message:"open')).toThrow(/unterminated/);
    try {
      parse("user.name:alice )");
    } catch (e) {
      expect((e as KQLError).position).toBe(16);
    }
  });
  it("lists referenced fields and warns about expensive patterns", () => {
    expect(fieldsOf(parse("a:1 and (b:2 or not c:*) and d > 3")).sort()).toEqual(["a", "b", "c", "d"]);
    expect(costWarnings(parse("process.command_line:*encoded*"))[0]).toMatch(/Leading wildcard/);
    expect(costWarnings(parse("alice"))[0]).toMatch(/Free-text/);
    expect(costWarnings(parse("user.name:alice"))).toEqual([]);
  });
  it("quotes values for pivots", () => {
    expect(quote("alice")).toBe("alice");
    expect(quote("C:\\Windows\\cmd.exe")).toBe('"C:\\\\Windows\\\\cmd.exe"');
    expect(quote('say "hi"')).toBe('"say \\"hi\\""');
    expect(evaluate(parse(`user.name:${quote("alice")}`), doc)).toBe(true);
  });
});
