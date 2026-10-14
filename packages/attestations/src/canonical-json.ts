export type JsonValue = null | boolean | number | string | JsonValue[] | { [key: string]: JsonValue };

export function canonicalJson(value: unknown): string {
  return serialize(assertJsonValue(value, "$"));
}

function assertJsonValue(value: unknown, path: string): JsonValue {
  if (value === null) {
    return value;
  }

  const valueType = typeof value;
  if (valueType === "string" || valueType === "boolean") {
    return value as JsonValue;
  }

  if (valueType === "number") {
    if (!Number.isFinite(value)) {
      throw new TypeError(`${path} must not be NaN or infinite`);
    }
    if (Object.is(value, -0)) {
      throw new TypeError(`${path} must not be negative zero`);
    }
    return value;
  }

  if (Array.isArray(value)) {
    return value.map((item, index) => assertJsonValue(item, `${path}[${index}]`));
  }

  if (valueType === "object") {
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) {
      throw new TypeError(`${path} must be a plain JSON object`);
    }

    const output: { [key: string]: JsonValue } = {};
    for (const [key, item] of Object.entries(value as Record<string, unknown>)) {
      if (item === undefined) {
        throw new TypeError(`${path}.${key} must not be undefined`);
      }
      output[key] = assertJsonValue(item, `${path}.${key}`);
    }
    return output;
  }

  throw new TypeError(`${path} has unsupported JSON value type: ${valueType}`);
}

function serialize(value: JsonValue): string {
  if (value === null || typeof value !== "object") {
    return JSON.stringify(value);
  }

  if (Array.isArray(value)) {
    return `[${value.map((item) => serialize(item)).join(",")}]`;
  }

  const fields = Object.keys(value)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${serialize(value[key])}`);
  return `{${fields.join(",")}}`;
}
