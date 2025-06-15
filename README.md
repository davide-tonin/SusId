# SusId

SusId provides compact, self‑describing, UUID‑compatible identifiers that embed:

* **Timestamp** (48 bits)
* **Randomness** (up to 56 bits, depending on signature length)
* **TypeId** (8 bits; 0–254 for custom types, 255 = **untyped**)
* **SecretId** (8 bits)
* **Signature** (truncated SHA‑256; 1–4 bytes)

All encoded into 16 bytes, perfect for a standard `UUID` column.

---

## Features

* **Self‑validation**: Quick sanity‑check via a truncated SHA‑256 signature avoids unnecessary DB lookups on invalid IDs.
* **Decodable**: Extract timestamp, `typeId`, `secretId`, and signature without any external service.
* **Tunable trade‑off**: Dial signature length between 1 and 4 bytes. More signature bytes ⇆ less randomness.
* **Untyped ID**: Call `generate()` (no args) to produce an ID with `typeId = 255`.

---

## Getting Started

```java
Map<Integer,String> secrets = Map.of(
  0, "alpha-secret",
  1, "beta-secret"
);
Map<Integer,String> types = Map.of(
  10, "USER",
  20, "ORDER"
);

// Default: 2‑byte signature
SusId susId = new SusId(secrets, types);

UUID id1 = susId.generate(10);      // typeId=10
UUID id2 = susId.generate();        // typeId=255 (untyped)

SusIdInfo info1 = susId.decode(id1);
// info1.timestamp(), info1.typeId(), info1.typeDesc(), info1.secretId(), info1.valid()
```

### Custom Signature Length

```java
// 1‑byte signature (extra randomness)
SusId s1 = new SusId(secrets, types, 1);
// 4‑byte signature (stronger sanity check)
SusId s4 = new SusId(secrets, types, 4);
```

---

## TypeId = 255 (Untyped)

When you need an ID without assigning a specific domain type, use:

```java
UUID untyped = susId.generate(); // shorthand for generate(255)
```

In `SusIdInfo`, `typeId == 255` and `typeDesc == "Untyped"`.

---

## Secret Management

* **Static Secrets Only**: Do **not** rotate or change the `secrets` map on a live system. If you update secret values, existing IDs signed with the old secret will fail validation.
* **Multiple Secrets**: Store multiple entries (up to 256), each keyed by an integer `secretId`.

---

## Thread Safety & Performance

* `generate(...)`/\`\` are thread‑safe.
* Internally uses a `ThreadLocal<MessageDigest>` so each thread reuses its `SHA-256` instance.
* No intermediate allocations beyond the final 16‑byte buffer and small temp arrays.

---

## Testing

Included JUnit tests cover:

* Round‑trip generate + decode
* Invalid random or corrupted IDs
* Custom signature lengths (1–4)
* Map validation for out‑of‑range keys and sizes
* Performance benchmark (10k ops in <500ms)

---

## License

This project is licensed under the MIT License – see the [LICENSE](./LICENSE) file for details.