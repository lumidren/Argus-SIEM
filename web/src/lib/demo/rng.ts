// Deterministic PRNG (mulberry32) so demo data is stable across reloads.
export function rng(seed: number) {
  let a = seed >>> 0;
  const next = () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
  return {
    next,
    int: (min: number, max: number) => min + Math.floor(next() * (max - min + 1)),
    pick: <T,>(xs: readonly T[]): T => xs[Math.floor(next() * xs.length)]!,
    chance: (p: number) => next() < p,
    weighted: <T,>(xs: readonly [T, number][]): T => {
      const total = xs.reduce((s, [, w]) => s + w, 0);
      let r = next() * total;
      for (const [x, w] of xs) {
        r -= w;
        if (r <= 0) return x;
      }
      return xs[xs.length - 1]![0];
    },
  };
}

export type Rng = ReturnType<typeof rng>;

/** Short stable hex id. */
export function hexId(r: Rng, len = 16): string {
  let s = "";
  while (s.length < len) s += Math.floor(r.next() * 0xffffffff).toString(16).padStart(8, "0");
  return s.slice(0, len);
}
