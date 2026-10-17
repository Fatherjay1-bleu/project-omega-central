#include <algorithm>
#include <cmath>
#include <iostream>
#include <string>

int main() {
    double severity, failures, suspicious;
    std::string extra;
    if (!(std::cin >> severity >> failures >> suspicious) ||
        (std::cin >> extra) || !std::isfinite(severity) ||
        !std::isfinite(failures) || !std::isfinite(suspicious) ||
        severity < 0 || severity > 10 || std::floor(severity) != severity ||
        failures < 0 || failures > 1000000 || std::floor(failures) != failures ||
        (suspicious != 0 && suspicious != 1)) {
        std::cerr << "Invalid event\n";
        return 1;
    }
    const int score = static_cast<int>(std::min(100.0,
        severity * 6 + std::min(failures, 10.0) * 2 + suspicious * 20));
    const char* risk = score >= 80 ? "CRITICAL" : score >= 50 ? "HIGH" :
                       score >= 25 ? "MEDIUM" : "LOW";
    std::cout << score << ' ' << risk << '\n';
}
