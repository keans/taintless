async function j(xs) {
  for await (const x of xs) { if (x) break; }
  try { await go(); } finally { done(); }
  return xs?.length ?? 0;
}
