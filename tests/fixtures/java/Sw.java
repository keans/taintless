class Sw {
    int a(int k) {
        switch (k) {
            case 1 -> { return 1; }
            case 2 -> System.out.println("two");
            default -> throw new RuntimeException();
        }
        return 0;
    }
    boolean b(boolean x, boolean y) {
        if (!x || y) { return true; }
        return false;
    }
}
