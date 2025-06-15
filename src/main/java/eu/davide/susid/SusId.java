/*
 * Copyright (c) 2025 Davide Tonin
 * Licensed under the Apache License, Version 2.0: https://opensource.org/license/apache-2-0
 */

package eu.davide.susid;

import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Map;
import java.util.UUID;

import static java.nio.charset.StandardCharsets.UTF_8;

/**
 * Generates and decodes compact, UUID-like identifiers with embedded timestamp, randomness,
 * type, and secret-based signature.
 */
public class SusId {
    static final int MAX_SECRETS     = 256;
    static final int MAX_TYPES       = 255;
    private static final int TIMESTAMP_BYTES = 6;
    private static final SecureRandom RAND   = new SecureRandom();

    private final Map<Integer,String> secrets;
    private final int[]               secretIds;
    private final Map<Integer,String> types;
    private final int                 signatureBytes;
    private final int                 randomBytes;

    /**
     * Result of decoding a SusId token.
     * @param valid     whether the signature is valid
     * @param timestamp extracted 48-bit timestamp (ms since epoch)
     * @param signature truncated signature bytes
     * @param typeId    type identifier (0–255, 255=untyped)
     * @param typeDesc  description of the type
     * @param secretId  secret identifier used
     */
    public record SusIdInfo(
            boolean valid,
            long timestamp,
            byte[] signature,
            int typeId,
            String typeDesc,
            int secretId
    ) {}

    /**
     * Defaults to a 2-byte signature.
     * @see #SusId(Map, Map, int)
     */
    public SusId(Map<Integer,String> secrets, Map<Integer,String> types) {
        this(secrets, types, 2);
    }

    /**
     * @param secrets        mapping of secretId to secret value (max 256 entries)
     * @param types          mapping of typeId to description (max 255 entries)
     * @param signatureBytes number of signature bytes (1–4; reduces randomness accordingly)
     * @throws IllegalArgumentException on invalid sizes or ranges
     */
    public SusId(Map<Integer,String> secrets, Map<Integer,String> types, int signatureBytes) {
        if (secrets.size() > MAX_SECRETS) throw new IllegalArgumentException("Too many secrets");
        if (types.size()   > MAX_TYPES ) throw new IllegalArgumentException("Too many types");
        secrets.keySet().forEach(id -> {
            if (id < 0 || id >= MAX_SECRETS) throw new IllegalArgumentException("Secret id OOB: " + id);
        });
        types.keySet().forEach(id -> {
            if (id < 0 || id >= MAX_TYPES) throw new IllegalArgumentException("Type id OOB: " + id);
        });
        if (signatureBytes < 1 || signatureBytes > 4) throw new IllegalArgumentException("Signature length must be 1–4");

        this.secrets        = Map.copyOf(secrets);
        this.types          = Map.copyOf(types);
        this.secretIds      = secrets.keySet().stream().mapToInt(i -> i).toArray();
        this.signatureBytes = signatureBytes;
        this.randomBytes    = 8 - signatureBytes;
    }

    /**
     * Generates a new untyped SusId (typeId=255).
     * @return new UUID identifier
     * @see #generate(int)
     */
    public UUID generate() {
        return generate(255);
    }

    /**
     * Generates a new SusId with given typeId.
     * @param typeId type identifier (0–254) or 255 for untyped
     * @return new UUID identifier
     * @throws IllegalArgumentException if typeId is unrecognized
     */
    public UUID generate(int typeId) {
        if (typeId != 255 && !types.containsKey(typeId))
            throw new IllegalArgumentException("Unknown type: " + typeId);

        long now = System.currentTimeMillis();
        byte[] id = new byte[16];

        // pack timestamp (6 bytes, big-endian)
        for (int i = 0; i < TIMESTAMP_BYTES; i++) {
            id[i] = (byte) (now >>> (8 * (TIMESTAMP_BYTES - 1 - i)));
        }

        // random bytes
        byte[] rnd = new byte[randomBytes];
        RAND.nextBytes(rnd);
        System.arraycopy(rnd, 0, id, TIMESTAMP_BYTES, randomBytes);

        // type and secret
        id[TIMESTAMP_BYTES + randomBytes]       = (byte) typeId;
        int secretId = secretIds[RAND.nextInt(secretIds.length)];
        id[TIMESTAMP_BYTES + randomBytes + 1]   = (byte) secretId;

        // signature over payload (timestamp+random+type+secret)
        int payloadLen = TIMESTAMP_BYTES + randomBytes + 2;
        byte[] payload = new byte[payloadLen];
        System.arraycopy(id, 0, payload, 0, payloadLen);
        byte[] sig = sign(payload, secretId);
        System.arraycopy(sig, 0, id, payloadLen, signatureBytes);

        // pack into UUID
        long msb = 0, lsb = 0;
        for (int i = 0; i < 8; i++)  msb = (msb << 8) | (id[i] & 0xFFL);
        for (int i = 8; i < 16; i++) lsb = (lsb << 8) | (id[i] & 0xFFL);
        return new UUID(msb, lsb);
    }

    /**
     * Decodes a SusId UUID into its components and verifies signature.
     * @param uuid identifier previously generated by this class
     * @return decoded info (valid=false if signature or secretId invalid)
     */
    public SusIdInfo decode(UUID uuid) {
        long msb = uuid.getMostSignificantBits(), lsb = uuid.getLeastSignificantBits();
        byte[] id = new byte[16];
        for (int i = 0; i < 8; i++)  id[i] = (byte) (msb >>> (8 * (7 - i)));
        for (int i = 8; i < 16; i++) id[i] = (byte) (lsb >>> (8 * (15 - i)));

        long ts = 0;
        for (int i = 0; i < TIMESTAMP_BYTES; i++)
            ts = (ts << 8) | (id[i] & 0xFFL);

        int typeId   = id[TIMESTAMP_BYTES + randomBytes] & 0xFF;
        int secretId = id[TIMESTAMP_BYTES + randomBytes + 1] & 0xFF;

        byte[] storedSig = new byte[signatureBytes];
        System.arraycopy(id, TIMESTAMP_BYTES + randomBytes + 2, storedSig, 0, signatureBytes);

        String typeDesc = (typeId == 255) ? "Untyped" : types.getOrDefault(typeId, "Unknown");

        if (!secrets.containsKey(secretId)) {
            return new SusIdInfo(false, ts, storedSig, typeId, typeDesc, secretId);
        }

        int payloadLen = TIMESTAMP_BYTES + randomBytes + 2;
        byte[] payload = new byte[payloadLen];
        System.arraycopy(id, 0, payload, 0, payloadLen);
        byte[] fullSig = sign(payload, secretId);

        boolean valid = true;
        for (int i = 0; i < signatureBytes; i++) {
            if (storedSig[i] != fullSig[i]) { valid = false; break; }
        }

        return new SusIdInfo(valid, ts, storedSig, typeId, typeDesc, secretId);
    }

    private static final ThreadLocal<MessageDigest> TL_MD =
            ThreadLocal.withInitial(() -> {
                try { return MessageDigest.getInstance("SHA-256"); }
                catch (Exception e) { throw new IllegalStateException(e); }
            });

    private byte[] sign(byte[] data, int secretId) {
        MessageDigest md = TL_MD.get();
        md.reset();
        md.update(secrets.get(secretId).getBytes(UTF_8));
        return md.digest(data);
    }
}