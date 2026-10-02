class A { run(c) {} }
class B { run(c) { exec(c); } }

function sibling() {
  { const x = new A(); x.run(1); }
  { const x = new B(); x.run(2); }
}

function outer_resumes() {
  let x = new A();
  {
    let x = new B();
    x.run(3);
  }
  x.run(process.argv[2]);
}

function inner_gets_the_tainted_call() {
  let x = new A();
  {
    let x = new B();
    x.run(process.argv[2]);
  }
}

function reassigned() {
  let x = new B();
  x = new A();
  x.run(process.argv[2]);
}
