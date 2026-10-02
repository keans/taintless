function cleanDot() {
  const d = { a: 'ls', b: prompt() };
  child_process.exec(d.a);
}
function cleanBracket() {
  const d = { a: 'ls', b: prompt() };
  child_process.exec(d['a']);
}
function taintedDot() {
  const d = { a: 'ls', b: prompt() };
  child_process.exec(d.b);
}
function taintedBracket() {
  const d = { a: 'ls', b: prompt() };
  child_process.exec(d['b']);
}
