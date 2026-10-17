#include <stdio.h>
#include <math.h>

/* severity [0,10], failed logins [0,1000000], suspicious flag [0,1]. */
int main(void) {
    double severity, failures, suspicious;
    char extra;
    if (scanf("%lf %lf %lf", &severity, &failures, &suspicious) != 3 ||
        scanf(" %c", &extra) == 1 ||
        !isfinite(severity) || !isfinite(failures) || !isfinite(suspicious) ||
        severity < 0 || severity > 10 || floor(severity) != severity ||
        failures < 0 || failures > 1000000 || floor(failures) != failures ||
        (suspicious != 0 && suspicious != 1)) {
        fputs("INVALID\n", stdout);
        return 1;
    }
    puts("VALID");
    return 0;
}
