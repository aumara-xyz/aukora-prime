// Which targets the production gate entry allowlists, and how it stores them. Empty until a reviewed,
// declarative target registry is wired in: the gate then refuses every proposal (fail closed).
export function gateTargets() { return {} }
export function gateStore() {
  const refuse = () => { throw new Error('no target store configured (fail closed)') }
  return { read: refuse, write: refuse }
}
