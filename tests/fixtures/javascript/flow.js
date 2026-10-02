function scan(items, mode) {
  let total = 0;
  outer: for (let i = 0; i < items.length; i++) {
    for (const x of items[i]) {
      if (x < 0) continue outer;
      if (x > 100) break outer;
      total += x;
    }
  }
  while (total > 10) total -= 10;
  do { total++; } while (total < 5);
  switch (mode) {
    case "a":
      total += 1;
    case "b":
      total += 2;
      break;
    default:
      return -1;
  }
  try {
    risky(total);
  } catch (e) {
    throw e;
  } finally {
    cleanup();
  }
  return total;
}

const arrow = (a) => (a ? 1 : 2);
const block = (a) => { if (a) { return 1; } return 2; };

class K {
  method(x) { return x ? 1 : 0; }
}
