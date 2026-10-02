#include "svc.h"

void Runner::run() {}

void Other::run() {}

void Svc::viaField() {
    r->run();
}

void Svc::viaAlias() {
    r2.run();
}

void Svc::viaTypedef() {
    r3.run();
}

void viaAliasParam(R a) {
    a.run();
}
