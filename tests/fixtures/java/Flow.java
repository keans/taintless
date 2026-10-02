class Flow {
    int run(int[] xs, String mode) {
        int total = 0;
        outer:
        for (int i = 0; i < xs.length; i++) {
            for (int x : xs) {
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
        } catch (IllegalStateException e) {
            throw e;
        } catch (RuntimeException e) {
            total = 0;
        } finally {
            cleanup();
        }
        return total;
    }

    Flow() { init(); }

    String arrow(int k) {
        return switch (k) {
            case 1 -> "one";
            default -> "other";
        };
    }
}
