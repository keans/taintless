interface Shape { area(): number }

function pick(kind: string, n: number): number {
  if (kind === "a") {
    return 1;
  } else if (kind === "b") {
    for (let i = 0; i < n; i++) {
      if (i === 3) break;
    }
  } else {
    throw new Error("bad");
  }
  return n;
}

export class Box<T> {
  constructor(private v: T) {}
  get(): T { return this.v; }
}
