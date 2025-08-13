import { createPrivateKey, createPublicKey, sign, verify, privateDecrypt, createHmac } from "crypto";

export function signEd25519Base64(canonicalJson: string, privateKeyPem: string): string {
  const key = createPrivateKey({ key: privateKeyPem });
  const signature = sign(null, Buffer.from(canonicalJson, "utf8"), key);
  return signature.toString("base64");
}

export function verifyEd25519Base64(canonicalJson: string, signatureB64: string, publicKeyPem: string): boolean {
  const key = createPublicKey({ key: publicKeyPem });
  return verify(null, Buffer.from(canonicalJson, "utf8"), key, Buffer.from(signatureB64, "base64"));
}

export function hmacSha256Hex(secret: string, data: string): string {
  return createHmac("sha256", Buffer.from(secret, "utf8")).update(Buffer.from(data, "utf8")).digest("hex");
}

export function decryptRsaOaepBase64(ciphertextB64: string, privateKeyPem: string): Buffer {
  const key = createPrivateKey({ key: privateKeyPem });
  const buf = Buffer.from(ciphertextB64, "base64");
  // Node uses OAEP with SHA1 by default; specify OAEP with SHA-256 if needed
  try {
    return privateDecrypt({ key, oaepHash: "sha256" }, buf);
  } catch {
    // Fallback to default OAEP (SHA-1) if client used default
    return privateDecrypt(key, buf);
  }
}

export function decryptRsaOaepJson<T = any>(ciphertextB64: string, privateKeyPem: string): T {
  const plain = decryptRsaOaepBase64(ciphertextB64, privateKeyPem);
  return JSON.parse(plain.toString("utf8")) as T;
}

