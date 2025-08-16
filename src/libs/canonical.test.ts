import { describe, expect, it } from 'vitest';
import { canonicalize } from './canonical';

describe('canonicalize', () => {
  it('sorts keys and removes spaces', () => {
    const obj = { b: 2, a: 1 };
    expect(canonicalize(obj)).toBe('{"a":1,"b":2}');
  });
});

