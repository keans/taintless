class A {
    void run(String c) throws Exception { Runtime.getRuntime().exec(c); }
}

class B {
    void run(String c) {}
}

class S {
    void f() throws Exception {
        {
            B x = new B();
            x.run(System.getenv("P"));
        }
        A x = new A();
        x.run(System.getenv("Q"));
    }
}
