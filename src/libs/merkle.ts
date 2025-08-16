import { createHash } from 'crypto';

export function sha256HexBuf(data: Buffer | string): string {
  return createHash('sha256').update(data).digest('hex');
}

export function hashLeafHex(hexDigest: string): Buffer {
  // Leaf hash as sha256 of hex digest string bytes
  return createHash('sha256').update(Buffer.from(hexDigest, 'utf8')).digest();
}

export function hashPair(a: Buffer, b: Buffer): Buffer {
  const [left, right] = Buffer.compare(a, b) <= 0 ? [a, b] : [b, a];
  return createHash('sha256').update(Buffer.concat([left, right])).digest();
}

export type MerkleProof = { leaf: string; path: Array<{ position: 'left' | 'right'; hash: string }>; root: string };

export class MerkleTree {
  private leaves: Buffer[] = [];

  addLeafFromHexDigest(hexDigest: string): number {
    this.leaves.push(hashLeafHex(hexDigest));
    return this.leaves.length - 1;
  }

  getRootHex(): string {
    if (this.leaves.length === 0) return '';
    let level = this.leaves.slice();
    while (level.length > 1) {
      const next: Buffer[] = [];
      for (let i = 0; i < level.length; i += 2) {
        const left = level[i];
        const right = level[i + 1];
        if (left && right) next.push(hashPair(left, right));
        else if (left) next.push(left);
      }
      level = next;
    }
    return level[0]?.toString('hex') || '';
  }

  getProof(index: number): MerkleProof | null {
    if (index < 0 || index >= this.leaves.length) return null;
    const path: Array<{ position: 'left' | 'right'; hash: string }> = [];
    let level = this.leaves.slice();
    let idx = index;
    while (level.length > 1) {
      const isRight = idx % 2 === 1;
      const pairIdx = isRight ? idx - 1 : idx + 1;
      if (pairIdx < level.length && level[pairIdx]) {
        path.push({ position: isRight ? 'left' : 'right', hash: level[pairIdx].toString('hex') });
      }
      // build next level
      const next: Buffer[] = [];
      for (let i = 0; i < level.length; i += 2) {
        const left = level[i];
        const right = level[i + 1];
        if (left && right) next.push(hashPair(left, right));
        else if (left) next.push(left);
      }
      idx = Math.floor(idx / 2);
      level = next;
    }
    return { leaf: this.leaves[index]?.toString('hex') || '', path, root: level[0]?.toString('hex') || '' };
  }

  static verifyProof(hexDigest: string, proof: MerkleProof): boolean {
    let computed = hashLeafHex(hexDigest);
    for (const step of proof.path) {
      const sibling = Buffer.from(step.hash, 'hex');
      if (step.position === 'left') computed = hashPair(sibling, computed);
      else computed = hashPair(computed, sibling);
    }
    return computed.toString('hex') === proof.root;
  }
}

