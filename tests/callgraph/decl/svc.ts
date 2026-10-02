class Runner {
  run(): void {}
}

class Other {
  run(): void {}
}

class Svc {
  r: Runner;

  go(): void {
    this.r.run();
  }

  local(): void {
    const x: Runner = this.make();
    x.run();
  }

  make(): any {
    return null;
  }
}
