// Internal persistent AVL map. Every copy shares immutable nodes; updating one
// prefix cannot change an earlier prefix or allocate a full historical Map.
const height = node => node?.height ?? 0;
const node = (key, value, left = null, right = null) => ({ key, value, left, right, height: 1 + Math.max(height(left), height(right)) });
const right = n => node(n.left.key, n.left.value, n.left.left, node(n.key, n.value, n.left.right, n.right));
const left = n => node(n.right.key, n.right.value, node(n.key, n.value, n.left, n.right.left), n.right.right);
function put(n, key, value) {
  if (!n) return node(key, value);
  if (key === n.key) return node(key, value, n.left, n.right);
  let result = key < n.key ? node(n.key, n.value, put(n.left, key, value), n.right) : node(n.key, n.value, n.left, put(n.right, key, value));
  if (height(result.left) - height(result.right) > 1) {
    if (height(result.left.left) < height(result.left.right)) result = node(result.key, result.value, left(result.left), result.right);
    return right(result);
  }
  if (height(result.right) - height(result.left) > 1) {
    if (height(result.right.right) < height(result.right.left)) result = node(result.key, result.value, result.left, right(result.right));
    return left(result);
  }
  return result;
}
export class PrefixMap {
  constructor(previous) { this.root = previous?.root ?? null; this.size = previous?.size ?? 0; }
  get(key) { let n = this.root; while (n) { if (key === n.key) return n.value; n = key < n.key ? n.left : n.right; } }
  has(key) { let n = this.root; while (n) { if (key === n.key) return true; n = key < n.key ? n.left : n.right; } return false; }
  set(key, value) { if (!this.has(key)) this.size++; this.root = put(this.root, key, value); return this; }
  *entries() { const stack = []; let n = this.root; while (n || stack.length) { while (n) { stack.push(n); n = n.left; } n = stack.pop(); yield [n.key, n.value]; n = n.right; } }
  *keys() { for (const [key] of this.entries()) yield key; }
  *values() { for (const [, value] of this.entries()) yield value; }
  [Symbol.iterator]() { return this.entries(); }
}
