import { createHash } from "crypto";

type JsonPrimitive = string | number | boolean | null;
type JsonValue = JsonPrimitive | JsonObject | JsonArray;
type JsonObject = { [key: string]: JsonValue };
type JsonArray = JsonValue[];

function isObject(value: unknown): value is JsonObject {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function stableNumber(value: number): string {
  if (!Number.isFinite(value)) return "null";
  // Use minimal decimal representation without trailing zeros
  const asString = value.toString();
  if (/e/i.test(asString)) {
    // Expand exponent to decimal to keep stability across engines
    const [coeff, expStr] = asString.split(/e/i);
    const exp = Number(expStr);
    const [intPart, fracPart = ""] = coeff.split(".");
    const digits = intPart.replace("-", "") + fracPart;
    const sign = value < 0 ? "-" : "";
    if (exp >= 0) {
      const zeros = exp - fracPart.length;
      return sign + (zeros >= 0 ? digits + "0".repeat(zeros) : digits.slice(0, digits.length + zeros) + "." + digits.slice(digits.length + zeros));
    } else {
      const pos = intPart.replace("-", "").length + exp;
      if (pos <= 0) return sign + "0." + "0".repeat(-pos) + digits;
      return sign + digits.slice(0, pos) + "." + digits.slice(pos);
    }
  }
  return asString;
}

export function canonicalize(value: JsonValue): string {
  return serialize(value);
}

function serialize(value: JsonValue): string {
  if (value === null) return "null";
  if (typeof value === "string") return JSON.stringify(value);
  if (typeof value === "number") return stableNumber(value);
  if (typeof value === "boolean") return value ? "true" : "false";
  if (Array.isArray(value)) return "[" + value.map(serialize).join(",") + "]";
  if (isObject(value)) {
    const keys = Object.keys(value).sort();
    const parts: string[] = [];
    for (const key of keys) {
      const v = (value as JsonObject)[key];
      parts.push(JSON.stringify(key) + ":" + serialize(v as JsonValue));
    }
    return "{" + parts.join(",") + "}";
  }
  // Fallback
  return JSON.stringify(value as unknown as JsonPrimitive);
}

export function sha256Hex(input: string): string {
  return createHash("sha256").update(input, "utf8").digest("hex");
}

