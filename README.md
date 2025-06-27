# SusId

### TL;DR – Why SusId?

It's an **optimization**.

* Let you say "this ID probably came from me" or "definitely not mine" without database lookup.
* Embeds a typeId, so you know what entity the ID was for.
* UUID-compatible — drop-in replacement for UUID columns
* Time-ordered — 'cause your indexes
* Tunable signature length

**It's not auth.**

I swear that if you use it to auth your api and I find out I'm gonna tell your mum.

---

## Structure

SusId is a structured identifier that embeds:

* `Timestamp` 6 bytes
* `Randomness` tunable, between 4 and 7 bytes
* `TypeId` 1 byte
* `SecretId` 1 byte
* `Signature` tunable, between 1 and 4 bytes

All encoded into 16 bytes, to fit in a standard `UUID` column.

---

## Features

* **Self‑validation**: Quick sanity‑check via a truncated SHA‑256 signature avoids unnecessary DB lookups on invalid IDs.
* **Decodable**: Extract `Timestamp`, `TypeId`, `SecretId`, and `Signature` without any external service.
* **Tunable trade‑off**: Tune signature length between 1 and 4 bytes. More signature bytes -> less randomness.

---

## Installations

You can pull SusId into your project via Maven or Gradle:

<details>
<summary>Maven</summary>

```xml
<dependency>
  <groupId>eu.davide</groupId>
  <artifactId>susid</artifactId>
  <version>1.0.0</version>
</dependency>
```

</details>

<details>
<summary>Gradle (Groovy)</summary>

```groovy
implementation 'eu.davide:susid:1.0.0'
```

</details>

<details>
<summary>Gradle (Kotlin)</summary>

```kotlin
implementation("eu.davide:susid:1.0.0")
```

</details>

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

* `generate(...)`/`decode(...)` are thread‑safe.
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

This project is licensed under the Apache License, Version 2.0 – see the [LICENSE](./LICENSE) file for details.