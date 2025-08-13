import { describe, expect, it } from "vitest";
import { signEd25519Base64, verifyEd25519Base64 } from "./crypto";
import { generateKeyPairSync } from "crypto";

describe("ed25519", () => {
  it("signs and verifies", () => {
    const { privateKey, publicKey } = generateKeyPairSync("ed25519");
    const priv = privateKey.export({ format: "pem", type: "pkcs8" }).toString();
    const pub = publicKey.export({ format: "pem", type: "spki" }).toString();
    const msg = "{\"a\":1}";
    const sig = signEd25519Base64(msg, priv);
    expect(verifyEd25519Base64(msg, sig, pub)).toBe(true);
  });
});

