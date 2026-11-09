// A KQL subset: field:value, field:"phrase", field:wild*card, bare terms,
// comparisons (field >= 10), existence (field:*), AND / OR / NOT and
// parentheses. Used to evaluate searches in demo mode and to validate and
// explain queries in the search bar. The server-side planner in argus-api
// compiles the same grammar to OpenSearch DSL.

export type Node =
  | { op: "and" | "or"; left: Node; right: Node }
  | { op: "not"; node: Node }
  | { op: "match"; field: string | null; value: string; wildcard: boolean; phrase: boolean }
  | { op: "exists"; field: string }
  | { op: "range"; field: string; cmp: ">" | ">=" | "<" | "<="; value: number | string }
  | { op: "all" };

export class KQLError extends Error {
  constructor(
    message: string,
    public readonly position: number,
  ) {
    super(message);
  }
}

type Tok =
  | { t: "word"; v: string; pos: number }
  | { t: "string"; v: string; pos: number }
  | { t: "colon" | "lparen" | "rparen"; pos: number }
  | { t: "cmp"; v: ">" | ">=" | "<" | "<="; pos: number };

function tokenize(src: string): Tok[] {
  const out: Tok[] = [];
  let i = 0;
  while (i < src.length) {
    const c = src[i]!;
    if (/\s/.test(c)) {
      i++;
      continue;
    }
    if (c === "(") {
      out.push({ t: "lparen", pos: i++ });
      continue;
    }
    if (c === ")") {
      out.push({ t: "rparen", pos: i++ });
      continue;
    }
    if (c === ":") {
      out.push({ t: "colon", pos: i++ });
      continue;
    }
    if (c === ">" || c === "<") {
      const eq = src[i + 1] === "=";
      out.push({ t: "cmp", v: (eq ? c + "=" : c) as ">" | ">=" | "<" | "<=", pos: i });
      i += eq ? 2 : 1;
      continue;
    }
    if (c === '"') {
      const start = i++;
      let v = "";
      while (i < src.length && src[i] !== '"') {
        if (src[i] === "\\" && i + 1 < src.length) i++;
        v += src[i++];
      }
      if (i >= src.length) throw new KQLError("unterminated quoted string", start);
      i++;
      out.push({ t: "string", v, pos: start });
      continue;
    }
    const start = i;
    let v = "";
    while (i < src.length && !/[\s():<>"]/.test(src[i]!)) {
      if (src[i] === "\\" && i + 1 < src.length) i++;
      v += src[i++];
    }
    out.push({ t: "word", v, pos: start });
  }
  return out;
}

/** Parses a query. An empty query matches everything. */
export function parse(src: string): Node {
  const toks = tokenize(src);
  let p = 0;
  const peek = () => toks[p];
  const isKw = (tok: Tok | undefined, kw: string) => tok?.t === "word" && tok.v.toUpperCase() === kw;

  function parseOr(): Node {
    let left = parseAnd();
    while (isKw(peek(), "OR")) {
      p++;
      left = { op: "or", left, right: parseAnd() };
    }
    return left;
  }
  function parseAnd(): Node {
    let left = parseNot();
    for (;;) {
      const tok = peek();
      if (!tok || tok.t === "rparen" || isKw(tok, "OR")) return left;
      if (isKw(tok, "AND")) p++;
      left = { op: "and", left, right: parseNot() };
    }
  }
  function parseNot(): Node {
    if (isKw(peek(), "NOT")) {
      p++;
      return { op: "not", node: parseNot() };
    }
    return parsePrimary();
  }
  function parsePrimary(): Node {
    const tok = peek();
    if (!tok) throw new KQLError("unexpected end of query", src.length);
    if (tok.t === "lparen") {
      p++;
      const n = parseOr();
      const close = peek();
      if (close?.t !== "rparen") throw new KQLError("missing closing parenthesis", close?.pos ?? src.length);
      p++;
      return n;
    }
    if (tok.t === "string") {
      p++;
      return { op: "match", field: null, value: tok.v, wildcard: false, phrase: true };
    }
    if (tok.t !== "word") throw new KQLError(`unexpected '${tok.t === "cmp" ? tok.v : tok.t}'`, tok.pos);
    p++;
    const next = peek();
    if (next?.t === "colon") {
      p++;
      const val = peek();
      if (!val) throw new KQLError(`missing value for field '${tok.v}'`, next.pos);
      if (val.t === "lparen") {
        // field:(a or b)
        p++;
        const inner = parseValueList(tok.v);
        const close = peek();
        if (close?.t !== "rparen") throw new KQLError("missing closing parenthesis", close?.pos ?? src.length);
        p++;
        return inner;
      }
      if (val.t === "string") {
        p++;
        return { op: "match", field: tok.v, value: val.v, wildcard: false, phrase: true };
      }
      if (val.t === "word") {
        p++;
        if (val.v === "*") return { op: "exists", field: tok.v };
        return { op: "match", field: tok.v, value: val.v, wildcard: val.v.includes("*") || val.v.includes("?"), phrase: false };
      }
      throw new KQLError(`invalid value for field '${tok.v}'`, val.pos);
    }
    if (next?.t === "cmp") {
      p++;
      const val = peek();
      if (!val || (val.t !== "word" && val.t !== "string")) throw new KQLError("comparison needs a value", next.pos);
      p++;
      const num = Number(val.v);
      return { op: "range", field: tok.v, cmp: next.v, value: Number.isFinite(num) && val.t === "word" ? num : val.v };
    }
    return { op: "match", field: null, value: tok.v, wildcard: tok.v.includes("*"), phrase: false };
  }
  function parseValueList(field: string): Node {
    let left = parseValue(field);
    for (;;) {
      const tok = peek();
      if (isKw(tok, "OR")) {
        p++;
        left = { op: "or", left, right: parseValue(field) };
      } else if (isKw(tok, "AND")) {
        p++;
        left = { op: "and", left, right: parseValue(field) };
      } else return left;
    }
  }
  function parseValue(field: string): Node {
    const tok = peek();
    if (isKw(tok, "NOT")) {
      p++;
      return { op: "not", node: parseValue(field) };
    }
    if (tok?.t === "word" || tok?.t === "string") {
      p++;
      return { op: "match", field, value: tok.v, wildcard: tok.t === "word" && tok.v.includes("*"), phrase: tok.t === "string" };
    }
    throw new KQLError("expected a value", tok?.pos ?? src.length);
  }

  if (toks.length === 0) return { op: "all" };
  const n = parseOr();
  const rest = peek();
  if (rest) throw new KQLError(`unexpected '${rest.t === "word" || rest.t === "string" || rest.t === "cmp" ? rest.v : ")"}'`, rest.pos);
  return n;
}

function wildcardToRegExp(pattern: string): RegExp {
  const esc = pattern.replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*").replace(/\?/g, ".");
  return new RegExp("^" + esc + "$", "i");
}

type Doc = Record<string, unknown>;

function values(doc: Doc, field: string): string[] {
  const v = doc[field];
  if (v === undefined || v === null) return [];
  if (Array.isArray(v)) return v.map(String);
  return [String(v)];
}

function matchValue(candidate: string, n: Extract<Node, { op: "match" }>): boolean {
  if (n.wildcard) return wildcardToRegExp(n.value).test(candidate);
  if (n.phrase && n.field === null) return candidate.toLowerCase().includes(n.value.toLowerCase());
  return candidate.toLowerCase() === n.value.toLowerCase();
}

/** Evaluates a parsed query against a flat document. */
export function evaluate(n: Node, doc: Doc): boolean {
  switch (n.op) {
    case "all":
      return true;
    case "and":
      return evaluate(n.left, doc) && evaluate(n.right, doc);
    case "or":
      return evaluate(n.left, doc) || evaluate(n.right, doc);
    case "not":
      return !evaluate(n.node, doc);
    case "exists":
      return values(doc, n.field).length > 0;
    case "match": {
      if (n.field) return values(doc, n.field).some((v) => matchValue(v, n));
      // Free text: any field's value, substring match.
      const needle = n.value.toLowerCase().replace(/\*/g, "");
      return Object.values(doc).some((v) =>
        (Array.isArray(v) ? v : [v]).some((x) => x !== undefined && x !== null && String(x).toLowerCase().includes(needle)),
      );
    }
    case "range": {
      return values(doc, n.field).some((raw) => {
        const a: number | string = typeof n.value === "number" ? Number(raw) : raw;
        if (typeof n.value === "number" && Number.isNaN(a as number)) return false;
        switch (n.cmp) {
          case ">":
            return a > n.value;
          case ">=":
            return a >= n.value;
          case "<":
            return a < n.value;
          case "<=":
            return a <= n.value;
        }
      });
    }
  }
}

/** Lists the fields a query references (for the field explorer). */
export function fieldsOf(n: Node): string[] {
  const out = new Set<string>();
  const walk = (x: Node) => {
    if (x.op === "and" || x.op === "or") {
      walk(x.left);
      walk(x.right);
    } else if (x.op === "not") walk(x.node);
    else if (x.op === "match" && x.field) out.add(x.field);
    else if (x.op === "exists" || x.op === "range") out.add(x.field);
  };
  walk(n);
  return [...out];
}

/** Flags patterns the server planner rewrites or rejects as expensive. */
export function costWarnings(n: Node): string[] {
  const w: string[] = [];
  const walk = (x: Node) => {
    if (x.op === "and" || x.op === "or") {
      walk(x.left);
      walk(x.right);
    } else if (x.op === "not") walk(x.node);
    else if (x.op === "match" && x.wildcard && x.value.startsWith("*")) {
      w.push(`Leading wildcard on ${x.field ?? "free text"} is rewritten to a wildcard-field query and may be slow.`);
    } else if (x.op === "match" && x.field === null && !x.phrase) {
      w.push(`Free-text term "${x.value}" scans every field; prefer field:value.`);
    }
  };
  walk(n);
  return [...new Set(w)];
}

/** Quotes a value for insertion into a query (used by pivots). */
export function quote(v: string): string {
  return /^[A-Za-z0-9_.\-@/]+$/.test(v) ? v : `"${v.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`;
}
