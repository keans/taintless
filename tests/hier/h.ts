class A {
  go() { this.hook(); }
  hook() {}
}
class B extends A {
  hook() {}
}
