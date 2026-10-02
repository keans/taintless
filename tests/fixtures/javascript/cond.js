function f(a, b, c) {
  if (a && (b || !c)) {
    return 1;
  }
  while (a || b) {
    a = next();
  }
  return 0;
}
