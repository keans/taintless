#include <vector>
#include <stdexcept>

namespace ns {
class W {
public:
    int run(const std::vector<int>& xs) {
        int total = 0;
        for (auto x : xs) {
            if (x < 0) continue;
            total += x;
        }
        try {
            check(total);
        } catch (const std::exception& e) {
            throw;
        } catch (...) {
            return -1;
        }
        return total;
    }
};
}

int W_free(int a) { return a ? 1 : 2; }
