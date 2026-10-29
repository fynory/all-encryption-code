// ALL 2.0 contracts, TypeScript reference verifier (the contract).
//
// The same checks as contracts/e2e_contracts.py and tunnel/contracts_verify_test.go, written independently: all three must give the same verdict
// AND the same error word on every golden vector of contracts/vectors/ (the Worker contract test runs this one). Spec and
// fixtures only: the control plane (WP02, WP03, WP04) writes its own handlers and tests them with these functions.
//
// It runs in Node (the test) and in a Worker: WebCrypto only (crypto.subtle), no node: imports, and it receives the policy, the schemas and
// the wire grammar as data (createContracts), so nothing here is typed twice. Erasable syntax only (no enums, no parameter properties), so
// Node runs the file as it is.

type Json = any;
type Dict = Record<string, Json>;

export type Verdict = { ok: boolean; error?: string; claims?: Dict; jti?: string };
export type Parsed = Dict & { verb: string };
export type ContractInput = { policy: Dict; schemas: Record<string, Json>; grammar: Dict };

export class ProtocolError extends Error {
  code: string;
  constructor(code: string) {
    super(code);
    this.code = code;
  }
}

class Reject extends Error {
  code: string;
  constructor(code: string) {
    super(code);
    this.code = code;
  }
}

const encoder = new TextEncoder();

/** Own keys only: `in` also finds what Object.prototype carries (constructor, toString, __proto__...), and the other verifiers have no such keys. */
const has = (value: object, key: string): boolean => Object.prototype.hasOwnProperty.call(value, key);

// ---------------------------------------------------------------------------------------------------------------------------- JSON

/** One JSON value: a repeated object key, a stray character after the value or an invalid escape is an error (JSON.parse accepts a repeated key). */
export function parseJson(text: string): Json {
  let i = 0;
  const fail = (): never => {
    throw new Error("json");
  };
  const ws = () => {
    while (i < text.length && " \t\n\r".includes(text[i])) i++;
  };
  const string = (): string => {
    i++; // opening quote
    let out = "";
    for (;;) {
      if (i >= text.length) fail();
      const ch = text[i++];
      if (ch === '"') return out;
      if (ch.charCodeAt(0) < 0x20) fail();
      if (ch !== "\\") {
        out += ch;
        continue;
      }
      const esc = text[i++];
      const simple: Dict = { '"': '"', "\\": "\\", "/": "/", b: "\b", f: "\f", n: "\n", r: "\r", t: "\t" };
      if (esc in simple) out += simple[esc];
      else if (esc === "u") {
        const hex = text.slice(i, i + 4);
        if (!/^[0-9a-fA-F]{4}$/.test(hex)) fail();
        out += String.fromCharCode(parseInt(hex, 16));
        i += 4;
      } else fail();
    }
  };
  const value = (): Json => {
    ws();
    const ch = text[i];
    if (ch === "{") {
      i++;
      const out: Dict = {};
      ws();
      if (text[i] === "}") {
        i++;
        return out;
      }
      for (;;) {
        ws();
        if (text[i] !== '"') fail();
        const key = string();
        if (Object.prototype.hasOwnProperty.call(out, key)) fail();
        ws();
        if (text[i++] !== ":") fail();
        Object.defineProperty(out, key, { value: value(), enumerable: true, writable: true, configurable: true });
        ws();
        const next = text[i++];
        if (next === "}") return out;
        if (next !== ",") fail();
      }
    }
    if (ch === "[") {
      i++;
      const out: Json[] = [];
      ws();
      if (text[i] === "]") {
        i++;
        return out;
      }
      for (;;) {
        out.push(value());
        ws();
        const next = text[i++];
        if (next === "]") return out;
        if (next !== ",") fail();
      }
    }
    if (ch === '"') return string();
    for (const [word, literal] of [["true", true], ["false", false], ["null", null]] as const) {
      if (text.startsWith(word, i)) {
        i += word.length;
        return literal;
      }
    }
    const number = /^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/.exec(text.slice(i));
    if (!number) return fail();
    i += number[0].length;
    return Number(number[0]);
  };
  const result = value();
  ws();
  if (i !== text.length) fail();
  return result;
}

function noFloats(value: Json): boolean {
  if (typeof value === "number") return Number.isInteger(value);
  if (Array.isArray(value)) return value.every(noFloats);
  if (value !== null && typeof value === "object") return Object.values(value).every(noFloats);
  return true;
}

function isObject(value: Json): value is Dict {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

/** The form of a JSON body on a wire line: keys sorted, no whitespace, ASCII only. */
export function canonicalJson(value: Json): string {
  if (value === null) return "null";
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number") return String(value);
  if (typeof value === "string") {
    let out = '"';
    for (let k = 0; k < value.length; k++) {
      const code = value.charCodeAt(k);
      const ch = value[k];
      if (ch === '"') out += '\\"';
      else if (ch === "\\") out += "\\\\";
      else if (ch === "\n") out += "\\n";
      else if (ch === "\r") out += "\\r";
      else if (ch === "\t") out += "\\t";
      else if (ch === "\b") out += "\\b";
      else if (ch === "\f") out += "\\f";
      else if (code < 0x20 || code > 0x7e) out += "\\u" + code.toString(16).padStart(4, "0");
      else out += ch;
    }
    return out + '"';
  }
  if (Array.isArray(value)) return "[" + value.map(canonicalJson).join(",") + "]";
  return "{" + Object.keys(value).sort().map((key) => canonicalJson(key) + ":" + canonicalJson(value[key])).join(",") + "}";
}

function equal(a: Json, b: Json): boolean {
  if (a === null || b === null) return a === b;
  if (typeof a !== typeof b) return false;
  if (Array.isArray(a)) return Array.isArray(b) && a.length === b.length && a.every((item, k) => equal(item, b[k]));
  if (typeof a === "object") {
    const keys = Object.keys(a);
    return !Array.isArray(b) && keys.length === Object.keys(b).length && keys.every((key) => key in b && equal(a[key], b[key]));
  }
  return a === b;
}

// ---------------------------------------------------------------------------------------------------------------------------- bytes, hashes

function b64uDecode(text: string): Uint8Array {
  if (typeof text !== "string" || !/^[A-Za-z0-9_-]+$/.test(text)) throw new Error("base64url");
  const raw = atob(text.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (text.length % 4)) % 4));
  const bytes = Uint8Array.from(raw, (c) => c.charCodeAt(0));
  if (b64uEncode(bytes) !== text) throw new Error("base64url");
  return bytes;
}

function b64uEncode(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

async function sha256B64(data: Uint8Array | string): Promise<string> {
  return b64uEncode(new Uint8Array(await crypto.subtle.digest("SHA-256", typeof data === "string" ? encoder.encode(data) : data)));
}

async function hmacB64(key: Uint8Array, message: string): Promise<string> {
  const imported = await crypto.subtle.importKey("raw", key, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return b64uEncode(new Uint8Array(await crypto.subtle.sign("HMAC", imported, encoder.encode(message))));
}

function sameText(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let k = 0; k < a.length; k++) diff |= a.charCodeAt(k) ^ b.charCodeAt(k);
  return diff === 0;
}

async function ed25519Ok(x: string, signature: Uint8Array, input: string): Promise<boolean> {
  if (signature.length !== 64) return false;
  try {
    const key = await crypto.subtle.importKey("jwk", { kty: "OKP", crv: "Ed25519", x }, "Ed25519", false, ["verify"]);
    return await crypto.subtle.verify("Ed25519", key, signature, encoder.encode(input));
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------------------------------------------------------- addresses

const V4 = /^(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])(?:\.(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])){3}$/;

/** `format: ip`: a textual IPv4 or IPv6 address, lower case, no zone, no brackets, no spaces (RFC 4291 text forms, dotted-quad tail allowed). */
export function validIp(value: Json): boolean {
  if (typeof value !== "string" || value === "" || value !== value.toLowerCase() || /[%[\] \t\r\n/]/.test(value)) return false;
  if (!value.includes(":")) return V4.test(value);
  const halves = value.split("::");
  if (halves.length > 2) return false;
  const groups = (part: string): string[] => (part === "" ? [] : part.split(":"));
  const all = halves.length === 2 ? [...groups(halves[0]), ...groups(halves[1])] : groups(halves[0]);
  let count = 0;
  for (let k = 0; k < all.length; k++) {
    const group = all[k];
    // a dotted-quad tail must end the whole address: "1.2.3.4::" is not an address
    if (k === all.length - 1 && group.includes(".") && (halves.length === 1 || halves[1] !== "")) {
      if (!V4.test(group)) return false;
      count += 2;
    } else {
      if (!/^[0-9a-f]{1,4}$/.test(group)) return false;
      count += 1;
    }
  }
  return halves.length === 2 ? count <= 7 : count === 8;
}

// ---------------------------------------------------------------------------------------------------------------------------- the contracts

export function createContracts(input: ContractInput) {
  const { policy, schemas, grammar } = input;
  const pol = (dotted: string): Json => dotted.split(".").reduce((node: Json, part) => node[part], policy);
  const anchored = (pattern: string): RegExp => {
    if (!pattern.startsWith("^") || !pattern.endsWith("$")) throw new Error("contract patterns are anchored: " + pattern);
    return new RegExp(pattern);
  };
  const labelRe = anchored(pol("identity.label_regex"));
  const fqdnRe = anchored(pol("identity.fqdn_regex"));
  const nonceRe = anchored(pol("identity.nonce_regex"));
  const kidRe = anchored(pol("identity.kid_regex"));
  const patterns = new Map<string, RegExp>();
  const pattern = (text: string): RegExp => {
    if (!patterns.has(text)) patterns.set(text, anchored(text));
    return patterns.get(text) as RegExp;
  };

  const labelOk = (value: Json): boolean => typeof value === "string" && labelRe.test(value);
  const fqdnOk = (value: Json, zones?: string[]): boolean => {
    if (typeof value !== "string" || value.length > pol("identity.fqdn_max_length") || !fqdnRe.test(value)) return false;
    return zones === undefined || zones.includes(value.slice(value.indexOf(".") + 1));
  };
  /** The detector a node or a device builds for its own address in a zone: the policy's label pattern, one dot, the zone. */
  const hostPattern = (zone: string): RegExp => {
    const label: string = pol("identity.label_regex");
    return new RegExp("^" + label.slice(1, -1) + "\\." + zone.replace(/[.*+?^${}()|[\]\\]/g, "\\$&") + "$");
  };

  // ---- JSON Schema subset (the keywords the schemas use; the same list in the Python and Go validators)
  const typeOk = (kind: string, value: Json): boolean => {
    switch (kind) {
      case "string": return typeof value === "string";
      case "boolean": return typeof value === "boolean";
      case "null": return value === null;
      case "object": return isObject(value);
      case "array": return Array.isArray(value);
      case "integer": return typeof value === "number" && Number.isInteger(value);
      case "number": return typeof value === "number";
      default: return false;
    }
  };
  const resolve = (doc: string, ref: string): [string, Json] => {
    const [file, pointer] = ref.split("#");
    const target = file || doc;
    let node: Json = schemas[target];
    if (pointer) for (const part of pointer.replace(/^\//, "").split("/")) node = node[part.replace(/~1/g, "/").replace(/~0/g, "~")];
    return [target, node];
  };
  const check = (doc: string, schema: Dict, value: Json, path: string, errors: string[]): void => {
    const at = path || "/";
    if ("$ref" in schema) {
      const [target, node] = resolve(doc, schema.$ref);
      check(target, node, value, path, errors);
    }
    if ("const" in schema && !equal(value, schema.const)) errors.push(`${at}: const`);
    if ("enum" in schema && !schema.enum.some((item: Json) => equal(value, item))) errors.push(`${at}: enum`);
    if ("type" in schema) {
      const kinds: string[] = Array.isArray(schema.type) ? schema.type : [schema.type];
      if (!kinds.some((kind) => typeOk(kind, value))) {
        errors.push(`${at}: type`);
        return;
      }
    }
    if ("oneOf" in schema) {
      let hits = 0;
      for (const option of schema.oneOf) {
        const trial: string[] = [];
        check(doc, option, value, path, trial);
        if (trial.length === 0) hits++;
      }
      if (hits !== 1) errors.push(`${at}: oneOf`);
    }
    if (typeof value === "string") {
      const length = [...value].length;
      if ("minLength" in schema && length < schema.minLength) errors.push(`${at}: minLength`);
      if ("maxLength" in schema && length > schema.maxLength) errors.push(`${at}: maxLength`);
      if ("pattern" in schema && !pattern(schema.pattern).test(value)) errors.push(`${at}: pattern`);
      if (schema.format === "ip" && !validIp(value)) errors.push(`${at}: format`);
    }
    if (typeof value === "number") {
      if ("minimum" in schema && value < schema.minimum) errors.push(`${at}: minimum`);
      if ("maximum" in schema && value > schema.maximum) errors.push(`${at}: maximum`);
    }
    if (isObject(value)) {
      for (const key of schema.required ?? []) if (!has(value, key)) errors.push(`${path}/${key}: required`);
      const props: Dict = schema.properties ?? {};
      for (const key of Object.keys(value).sort()) {
        if (has(props, key)) check(doc, props[key], value[key], `${path}/${key}`, errors);
        else if (schema.additionalProperties === false) errors.push(`${path}/${key}: additionalProperties`);
      }
    }
    if (Array.isArray(value)) {
      if ("minItems" in schema && value.length < schema.minItems) errors.push(`${at}: minItems`);
      if ("maxItems" in schema && value.length > schema.maxItems) errors.push(`${at}: maxItems`);
      if (schema.uniqueItems && value.some((a, i) => value.some((b, j) => j > i && equal(a, b)))) errors.push(`${at}: uniqueItems`);
      if ("items" in schema) value.forEach((item, k) => check(doc, schema.items, item, `${path}/${k}`, errors));
    }
  };
  const validate = (name: string, instance: Json): string[] => {
    const errors: string[] = [];
    check(name, schemas[name], instance, "", errors);
    return errors;
  };

  // ---- the wire grammar
  const fieldOk = (kind: string, token: string): boolean => {
    const spec: Dict = grammar.types[kind];
    if (spec.max_bytes_from && token.length > pol(spec.max_bytes_from)) return false;
    if (spec.pattern && !pattern(spec.pattern).test(token)) return false;
    if (spec.format === "ip" && !validIp(token)) return false;
    if (spec.enum_from && !pol(spec.enum_from).includes(token)) return false;
    return true;
  };

  /** Parse one protocol line (the text before the LF) travelling in `direction` ("d2n" or "n2d"). Throws ProtocolError. */
  const parseLine = (line: string, direction: string): Parsed => {
    if (typeof line !== "string" || [...line].some((ch) => ch.charCodeAt(0) < 0x20 || ch.charCodeAt(0) > 0x7e)) throw new ProtocolError("bad_command");
    const cut = line.indexOf(" ");
    const verb = cut < 0 ? line : line.slice(0, cut);
    const hasSpace = cut >= 0;
    const rest = hasSpace ? line.slice(cut + 1) : "";
    const spec: Dict | undefined = Object.prototype.hasOwnProperty.call(grammar.verbs, verb) ? grammar.verbs[verb] : undefined;
    const limit: number = spec && spec.max ? pol(spec.max) : pol("protocol.line_max_bytes");
    if (line.length + 1 > limit) throw new ProtocolError("line_too_long");
    if (!spec || (spec.dir !== direction && spec.dir !== "both") || line === "" || (hasSpace && rest === "")) throw new ProtocolError("bad_command");
    const out: Parsed = { verb };
    if (spec.json) {
      if (!hasSpace) throw new ProtocolError("bad_command");
      let body: Json;
      try {
        body = parseJson(rest);
      } catch {
        throw new ProtocolError("bad_command");
      }
      if (!noFloats(body) || validate(spec.json, body).length > 0) throw new ProtocolError("bad_command");
      out.body = body;
      return out;
    }
    const tokens = hasSpace ? rest.split(" ") : [];
    if (tokens.some((token) => token === "")) throw new ProtocolError("bad_command");
    if (spec.repeat) {
      const rule = spec.repeat;
      if (tokens.length < rule.min || tokens.length > pol(rule.max_from) || !tokens.every((token) => fieldOk(rule.type, token))) throw new ProtocolError("bad_command");
      out.addresses = tokens;
      return out;
    }
    const fields: Dict[] = spec.fields ?? [];
    const optional: Dict[] = spec.optional ?? [];
    if (tokens.length < fields.length || tokens.length > fields.length + optional.length) throw new ProtocolError("bad_command");
    const rules = [...fields, ...optional];
    tokens.forEach((token, k) => {
      const rule = rules[k];
      if ("equals" in rule && token !== rule.equals) throw new ProtocolError(fieldOk(rule.type, token) ? rule.error_if_number : "bad_command");
      if (!fieldOk(rule.type, token)) throw new ProtocolError(rule.error ?? "bad_command");
      out[rule.name] = token;
    });
    return out;
  };

  /** The canonical line of a parsed message (the inverse of parseLine, which it is checked against). */
  const formatLine = (message: Parsed): string => {
    const spec: Dict = grammar.verbs[message.verb];
    let line: string;
    if (spec.json) line = `${message.verb} ${canonicalJson(message.body)}`;
    else if (spec.repeat) line = [message.verb, ...message.addresses].join(" ");
    else {
      const rules: Dict[] = [...(spec.fields ?? []), ...(spec.optional ?? [])];
      line = [message.verb, ...rules.filter((rule) => has(message, rule.name)).map((rule) => message[rule.name])].join(" ");
    }
    parseLine(line, spec.dir === "both" ? "d2n" : spec.dir);
    return line;
  };

  // ---- tokens
  const fail = (error: string): Verdict => ({ ok: false, error });

  const jwsParts = (token: Json, maxBytes: number) => {
    try {
      if (typeof token !== "string" || [...token].some((ch) => ch.charCodeAt(0) > 0x7f) || token.length > maxBytes) throw new Error();
      const parts = token.split(".");
      if (parts.length !== 3) throw new Error();
      // ignoreBOM keeps a leading U+FEFF in the text, so parseJson refuses it (Python and Go refuse it too; the default decoder drops it)
      const decoder = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });
      const header = parseJson(decoder.decode(b64uDecode(parts[0])));
      const claims = parseJson(decoder.decode(b64uDecode(parts[1])));
      const signature = parts[2] === "" ? new Uint8Array(0) : b64uDecode(parts[2]);
      if (!isObject(header) || !isObject(claims)) throw new Error();
      if (["crit", "b64", "jku", "x5u", "x5c"].some((name) => has(header, name))) throw new Error();
      if (!noFloats(claims)) throw new Error();
      return { header, claims, signature, input: `${parts[0]}.${parts[1]}` };
    } catch {
      throw new Reject("malformed_token");
    }
  };

  const jwkX = (value: Json): string => {
    if (!isObject(value) || value.kty !== "OKP" || value.crv !== "Ed25519" || has(value, "d") || typeof value.x !== "string" || value.x.length !== 43) {
      throw new Reject("malformed_token");
    }
    try {
      if (b64uDecode(value.x).length !== 32) throw new Error();
    } catch {
      throw new Reject("malformed_token");
    }
    return value.x;
  };

  const claimsOk = (claims: Dict, schema: string, ...ignore: string[]): boolean =>
    validate(schema, claims).every((error) => ignore.some((name) => error.startsWith(`/${name}:`)));

  const parseJwks = (doc: Json): Map<string, string> => {
    if (validate("jwks.schema.json", doc).length > 0) throw new Reject("bad_jwks");
    const keys = new Map<string, string>();
    for (const key of doc.keys) {
      if (keys.has(key.kid)) throw new Reject("bad_jwks");
      keys.set(key.kid, key.x);
    }
    return keys;
  };

  const parseNodeKeys = (doc: Json): Map<string, { node: string; x: string }> => {
    if (validate("node-keys.schema.json", doc).length > 0) throw new Reject("bad_node_keys");
    const keys = new Map<string, { node: string; x: string }>();
    for (const key of doc.keys) {
      if (keys.has(key.kid)) throw new Reject("bad_node_keys");
      keys.set(key.kid, { node: key.node, x: key.x });
    }
    return keys;
  };

  const signedByJwks = async (token: Json, keys: Map<string, string>, typ: string) => {
    const jws = jwsParts(token, pol("protocol.statement_line_max_bytes"));
    if (jws.header.alg !== "EdDSA") throw new Reject("bad_alg");
    const kid = jws.header.kid;
    if (typeof kid !== "string" || !kidRe.test(kid) || !keys.has(kid)) throw new Reject("unknown_kid");
    if (!(await ed25519Ok(keys.get(kid) as string, jws.signature, jws.input))) throw new Reject("bad_signature");
    if (jws.header.typ !== typ || jws.claims.typ !== typ) throw new Reject("wrong_type");
    return jws;
  };

  const run = async (body: () => Promise<Verdict>): Promise<Verdict> => {
    try {
      return await body();
    } catch (error) {
      if (error instanceof Reject) return fail(error.code);
      throw error;
    }
  };

  /** A device session as the node accepts it at HELLO and RENEW. Order of failure: malformed_token, bad_alg, unknown_kid, bad_signature, wrong_type,
   *  wrong_issuer, wrong_audience, bad_claims, bad_lifetime, not_yet_valid, expired. */
  const verifySession = (token: Json, o: { now: number; audience: string; keys: Map<string, string>; skew: number }): Promise<Verdict> => run(async () => {
    if (typeof token !== "string" || token.length > pol("protocol.jwt_max_bytes")) throw new Reject("malformed_token");
    const { claims } = await signedByJwks(token, o.keys, "device-session");
    if (claims.ver !== 2) throw new Reject("wrong_type");
    if (claims.iss !== pol("identity.issuer")) throw new Reject("wrong_issuer");
    if (claims.aud !== o.audience) throw new Reject("wrong_audience");
    if (!claimsOk(claims, "session-claims.schema.json", "aud")) throw new Reject("bad_claims");
    if (claims.exp - claims.iat !== pol("authorization.session_ttl_s")) throw new Reject("bad_lifetime");
    if (claims.iat > o.now + o.skew) throw new Reject("not_yet_valid");
    if (claims.exp <= o.now) throw new Reject("expired");
    return { ok: true, claims, jti: claims.jti };
  });

  /** The DPoP proof of PROOF. Order of failure: malformed_token, bad_alg, wrong_type, wrong_key, bad_signature, wrong_subject, wrong_audience,
   *  wrong_htm, wrong_htu, wrong_ath, wrong_nonce, bad_claims, not_yet_valid, stale_proof, replayed_jti. */
  const verifyProof = (proof: Json, o: { now: number; sessionToken: string; sessionClaims: Dict; nonce: string; htu: string; skew: number; seen: Set<string> }): Promise<Verdict> => run(async () => {
    if (typeof proof !== "string" || proof.length > pol("protocol.jwt_max_bytes")) throw new Reject("malformed_token");
    const jws = jwsParts(proof, pol("protocol.jwt_max_bytes"));
    if (jws.header.alg !== "EdDSA") throw new Reject("bad_alg");
    if (jws.header.typ !== "dpop+jwt") throw new Reject("wrong_type");
    const x = jwkX(jws.header.jwk);
    if (x !== o.sessionClaims.cnf.jwk.x) throw new Reject("wrong_key");
    if (!(await ed25519Ok(x, jws.signature, jws.input))) throw new Reject("bad_signature");
    const claims = jws.claims;
    if (claims.sub !== o.sessionClaims.sub) throw new Reject("wrong_subject");
    if (claims.aud !== pol("identity.aud_tunnel")) throw new Reject("wrong_audience");
    if (claims.htm !== pol("protocol.proof_htm")) throw new Reject("wrong_htm");
    if (claims.htu !== o.htu) throw new Reject("wrong_htu");
    if (claims.ath !== (await sha256B64(o.sessionToken))) throw new Reject("wrong_ath");
    if (claims.nonce !== o.nonce) throw new Reject("wrong_nonce");
    if (!claimsOk(claims, "proof-claims.schema.json", "htu")) throw new Reject("bad_claims");
    if (claims.iat > o.now + o.skew) throw new Reject("not_yet_valid");
    if (claims.iat + pol("authorization.proof_ttl_s") <= o.now) throw new Reject("stale_proof");
    if (o.seen.has(claims.jti)) throw new Reject("replayed_jti");
    return { ok: true, claims, jti: claims.jti };
  });

  /** A node's request authentication (header x-all-node-assertion). Order of failure: malformed_token, bad_alg, unknown_kid, bad_signature,
   *  wrong_type, wrong_audience, wrong_subject, wrong_htm, wrong_htu, bad_claims, bad_lifetime, not_yet_valid, expired, wrong_body_hash, replayed_jti. */
  const verifyNodeAssertion = (token: Json, o: { now: number; keys: Map<string, { node: string; x: string }>; method: string; url: string; body: Uint8Array; skew: number; seen: Set<string> }): Promise<Verdict> => run(async () => {
    const jws = jwsParts(token, pol("protocol.jwt_max_bytes"));
    if (jws.header.alg !== "EdDSA") throw new Reject("bad_alg");
    const kid = jws.header.kid;
    if (typeof kid !== "string" || !kidRe.test(kid) || !o.keys.has(kid)) throw new Reject("unknown_kid");
    const key = o.keys.get(kid) as { node: string; x: string };
    if (!(await ed25519Ok(key.x, jws.signature, jws.input))) throw new Reject("bad_signature");
    const claims = jws.claims;
    if (jws.header.typ !== "node-assertion" || claims.typ !== "node-assertion" || claims.ver !== 1) throw new Reject("wrong_type");
    if (claims.aud !== pol("identity.aud_node_assertion")) throw new Reject("wrong_audience");
    if (claims.sub !== key.node) throw new Reject("wrong_subject");
    if (claims.htm !== o.method) throw new Reject("wrong_htm");
    if (claims.htu !== o.url) throw new Reject("wrong_htu");
    if (!claimsOk(claims, "node-assertion-claims.schema.json", "htm", "htu", "aud", "sub")) throw new Reject("bad_claims");
    if (claims.exp - claims.iat !== pol("authorization.node_assertion_ttl_s")) throw new Reject("bad_lifetime");
    if (claims.iat > o.now + o.skew) throw new Reject("not_yet_valid");
    if (claims.exp <= o.now) throw new Reject("expired");
    if (claims.bh !== (await sha256B64(o.body))) throw new Reject("wrong_body_hash");
    if (o.seen.has(claims.jti)) throw new Reject("replayed_jti");
    return { ok: true, claims, jti: claims.jti };
  });

  /** The control plane's signed access statement as the device accepts it. Order of failure: malformed_token, bad_alg, unknown_kid, bad_signature,
   *  wrong_type, wrong_issuer, wrong_audience, wrong_subject, bad_claims, bad_lifetime, not_yet_valid, stale_seq. An expired statement still verifies. */
  const verifyStatement = (token: Json, o: { now: number; keys: Map<string, string>; deviceId: string; lastSeq: number }): Promise<Verdict> => run(async () => {
    const { claims } = await signedByJwks(token, o.keys, "device-access");
    if (claims.ver !== 1) throw new Reject("wrong_type");
    if (claims.iss !== pol("identity.issuer")) throw new Reject("wrong_issuer");
    if (claims.aud !== pol("identity.aud_access")) throw new Reject("wrong_audience");
    if (claims.sub !== o.deviceId) throw new Reject("wrong_subject");
    if (!claimsOk(claims, "statement-claims.schema.json", "aud", "sub") || has(claims, "paywall") !== (claims.mode === "paywall") ||
        (has(claims, "paused") && has(claims, "resumed"))) throw new Reject("bad_claims");
    const ttl = claims.exp - claims.iat;
    if (!(ttl > 0 && ttl <= pol(claims.mode === "paywall" ? "authorization.access_ttl_paywall_s" : "authorization.access_ttl_paid_s"))) throw new Reject("bad_lifetime");
    if (claims.iat > o.now + pol("authorization.access_future_slack_s")) throw new Reject("not_yet_valid");
    if (claims.seq < o.lastSeq) throw new Reject("stale_seq");
    return { ok: true, claims, jti: claims.jti };
  });

  /** Schema plus the rules a schema cannot say: events strictly increasing and after `since`, epoch not behind the last event, kill and kill_clear
   *  carry no device, every other event carries both device and label. */
  const checkFeed = (body: Json, since: number): string[] => {
    const errors = validate("feed-response.schema.json", body);
    if (errors.length > 0) return errors;
    let previous = since;
    body.events.forEach((event: Dict, k: number) => {
      if (event.epoch <= previous) errors.push(`/events/${k}: order`);
      previous = Math.max(previous, event.epoch);
      const global = event.type === "kill" || event.type === "kill_clear";
      if (global !== (event.device_id === null && event.label === null)) errors.push(`/events/${k}: scope`);
      if ((event.device_id === null) !== (event.label === null)) errors.push(`/events/${k}: scope`);
    });
    if (body.epoch < previous) errors.push("/epoch: behind events");
    return errors;
  };

  // ---- surface identity proof
  const surfaceKey = (secret: string): Uint8Array => {
    const raw = b64uDecode(secret);
    if (raw.length !== 32) throw new Error("secret");
    return raw;
  };
  const surfaceMac = (secret: string, nonce: string): Promise<string> => hmacB64(surfaceKey(secret), "all-surface-challenge-v1\n" + nonce);
  const surfaceProof = (secret: string, nonce: string, pid: number, port: number): Promise<string> =>
    hmacB64(surfaceKey(secret), `all-surface-proof-v1\n${nonce}\n${pid}\n${port}`);
  const verifySurfaceChallenge = async (secret: string, nonce: string, mac: Json): Promise<Verdict> => {
    try {
      if (typeof nonce !== "string" || !nonceRe.test(nonce) || typeof mac !== "string") return fail("bad_challenge");
      return sameText(await surfaceMac(secret, nonce), mac) ? { ok: true } : fail("bad_challenge");
    } catch {
      return fail("bad_challenge");
    }
  };
  const verifySurfaceProof = async (secret: string, nonce: string, pid: number, port: number, proof: Json): Promise<Verdict> => {
    try {
      if (typeof nonce !== "string" || !nonceRe.test(nonce) || typeof proof !== "string") return fail("bad_proof");
      return sameText(await surfaceProof(secret, nonce, pid, port), proof) ? { ok: true } : fail("bad_proof");
    } catch {
      return fail("bad_proof");
    }
  };
  const identityRequest = (host: string, port: number, nonce: string, mac: string): string =>
    `GET ${pol("surface.identity_path")} HTTP/1.1\r\nHost: ${host}:${port}\r\n${pol("surface.identity_challenge_header")}: ${nonce}\r\n` +
    `${pol("surface.identity_mac_header")}: ${mac}\r\nConnection: keep-alive\r\n\r\n`;

  // ---- node behaviour
  /** Does the recorded behaviour of ONE node obey the contract? Returns "" when it does, otherwise the first violation word. */
  const checkTranscript = async (doc: Dict): Promise<string> => {
    const ctx = doc.ctx;
    const keys = parseJwks(ctx.jwks);
    const skew: number = ctx.skew;
    type Conn = { phase: string; session: string; claims: Dict | null; sessionOk: boolean; kind: string; nonce: string; proof: string; authorized: boolean;
      reply: Dict | null; host: string; status: string; validUntil: number; superseded: boolean; sub: string };
    const conns = new Map<string, Conn>();
    const seen = new Set<string>();
    const streams = new Map<string, { secret: string; t: number; consumed: boolean }>();
    const secretsUsed = new Set<string>();
    const hellos = new Map<string, { ip: string; cls: string }[]>(); // per host: the peer_ip and class of each complete ClientHello still waiting for its OPEN
    let ended = false;
    let now = 0;

    for (const event of doc.events as Dict[]) {
      now = event.t;
      const kind: string = event.ev;
      let conn: Conn | undefined;
      if (typeof event.conn === "string" && ["recv", "send", "cp", "cp_reply"].includes(kind)) {
        if (!conns.has(event.conn)) {
          conns.set(event.conn, { phase: "new", session: "", claims: null, sessionOk: false, kind: "hello", nonce: "", proof: "none", authorized: false,
            reply: null, host: "", status: "", validUntil: 0, superseded: false, sub: "" });
        }
        conn = conns.get(event.conn);
      }
      if (kind === "client_hello") {
        if (event.complete === true) hellos.set(event.sni, [...(hellos.get(event.sni) ?? []), { ip: event.peer_ip, cls: event.class }]);
      } else if (kind === "recv" && conn) {
        let message: Parsed;
        try {
          message = parseLine(event.line, "d2n");
        } catch {
          continue;
        }
        const verb = message.verb;
        if ((verb === "HELLO" && conn.phase === "new") || (verb === "RENEW" && conn.phase === "ready")) {
          const result = await verifySession(message.session, { now, audience: pol("identity.aud_tunnel"), keys, skew });
          conn.sessionOk = result.ok && (verb === "HELLO" || (result.claims as Dict).sub === conn.sub);
          conn.session = message.session;
          conn.claims = result.ok ? (result.claims as Dict) : null;
          conn.kind = verb === "HELLO" ? "hello" : "renew";
          conn.nonce = "";
          conn.proof = "none";
          conn.authorized = false;
          conn.reply = null;
          if (verb === "HELLO") conn.phase = "hello";
        } else if (verb === "PROOF" && conn.sessionOk && conn.nonce !== "") {
          const result = await verifyProof(message.proof, { now, sessionToken: conn.session, sessionClaims: conn.claims as Dict, nonce: conn.nonce,
            htu: ctx.node_url, skew, seen });
          conn.proof = result.ok ? "ok" : result.error === "replayed_jti" ? "replayed" : "invalid";
          conn.authorized = false;
          conn.reply = null;
          if (result.ok && result.jti !== undefined) seen.add(result.jti);
        }
      } else if (kind === "cp" && conn) {
        const body = event.body;
        if (validate("authorize-request.schema.json", body).length > 0 || conn.claims === null || body.device_id !== conn.claims.sub ||
            body.session_jti !== conn.claims.jti || body.reason !== conn.kind || body.node !== ctx.node_id) return "bad_authorize_request";
        if (conn.proof === "ok") conn.authorized = true;
      } else if (kind === "cp_reply" && conn) {
        conn.reply = conn.authorized ? event : null;
      } else if (kind === "send" && conn) {
        let message: Parsed;
        try {
          message = parseLine(event.line, "n2d");
        } catch {
          return "bad_line";
        }
        if (message.verb === "CHALLENGE") {
          if (!conn.sessionOk || (conn.phase !== "hello" && conn.phase !== "ready")) return "challenge_for_invalid_session";
          conn.nonce = message.nonce;
        } else if (message.verb === "OK") {
          if (event.line !== "OK " + canonicalJson(message.body)) return "bad_line";
          if (conn.proof === "none") return "ok_without_proof";
          if (conn.proof === "replayed") return "replayed_proof_accepted";
          if (conn.proof !== "ok") return "ok_with_invalid_proof";
          if (!conn.authorized || conn.reply === null || conn.reply.status !== 200) return conn.kind === "renew" ? "renew_without_authorize" : "ok_without_authorize";
          const body = message.body;
          const answer = conn.reply.body;
          if (body.host !== answer.host) return "host_not_from_control_plane";
          if (body.status !== answer.status || body.valid_until !== answer.valid_until || !equal(body.policy, answer.policy) || body.node !== ctx.node_id) {
            return "ok_mismatch_control_plane";
          }
          conn.phase = "ready";
          conn.host = body.host;
          conn.status = body.status;
          conn.validUntil = body.valid_until;
          conn.sub = (conn.claims as Dict).sub;
          conn.proof = "none";
          conn.authorized = false;
          conn.reply = null;
          for (const other of conns.values()) if (other !== conn && other.phase === "ready" && other.sub === conn.sub) other.superseded = true;
        } else if (message.verb === "OPEN") {
          if (conn.phase !== "ready" || conn.status === "") return "open_before_ok";
          if (conn.status === "paused") return "open_when_paused";
          if (now >= conn.validUntil) return "open_after_valid_until";
          const pending = hellos.get(conn.host) ?? [];
          if (pending.length === 0) return [...hellos.values()].some((list) => list.length > 0) ? "open_wrong_host" : "open_without_client_hello";
          const waiting = pending.findIndex((hello) => hello.ip === message.peer_ip && hello.cls === message.class);
          if (waiting < 0) return "open_wrong_client";
          if (streams.has(message.stream_id) || secretsUsed.has(message.secret)) return "duplicate_stream";
          pending.splice(waiting, 1);
          streams.set(message.stream_id, { secret: message.secret, t: now, consumed: false });
          secretsUsed.add(message.secret);
        } else if (message.verb === "CLOSE") {
          conn.phase = "closed";
        }
      } else if (kind === "attach") {
        let message: Parsed;
        try {
          message = parseLine(event.line, "d2n");
        } catch {
          continue;
        }
        const known = streams.get(message.stream_id);
        const good = known !== undefined && sameText(known.secret, message.secret);
        const fresh = good && !known.consumed && now - known.t <= pol("protocol.attach_timeout_s");
        if (event.result === "ok") {
          if (known === undefined) return "attach_unknown_accepted";
          if (!good) return "attach_wrong_secret_accepted";
          if (known.consumed) return "attach_secret_reused";
          if (!fresh) return "attach_after_timeout";
          known.consumed = true;
        } else if (fresh) {
          return "attach_refused_good_secret";
        }
      } else if (kind === "end") {
        ended = true;
        for (const other of conns.values()) {
          if (other.phase === "ready" && other.superseded) return "replaced_not_closed";
          if (other.phase === "ready" && now > other.validUntil) return "no_close_at_valid_until";
        }
      }
    }
    return ended ? "" : "transcript_without_end";
  };

  return {
    pol, labelOk, fqdnOk, hostPattern, validate, parseLine, formatLine, verifySession, verifyProof, verifyNodeAssertion, verifyStatement, parseJwks,
    parseNodeKeys, checkFeed, surfaceMac, surfaceProof, verifySurfaceChallenge, verifySurfaceProof, identityRequest, checkTranscript, canonicalJson,
    labelRegexSource: labelRe.source,
  };
}

export type Contracts = ReturnType<typeof createContracts>;
export { Reject, b64uDecode, b64uEncode };
