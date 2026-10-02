interface Shape {
    void draw();
}

class Circle implements Shape {
    public void draw() {}
}

class Square implements Shape {
    public void draw() {}
}

class Canvas {
    void paint(Shape s) {
        s.draw();
    }
}
