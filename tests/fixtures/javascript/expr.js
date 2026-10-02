const f = (a, b) => (a ? b?.x : (b ?? 0));
function g(a, b) { const v = a && b(); return a || b; }
function h(o) { return o?.p?.q(1); }
function t() { try { work(); } finally { done(); } }
