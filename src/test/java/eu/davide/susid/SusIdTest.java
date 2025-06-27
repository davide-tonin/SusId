package eu.davide.susid;

import static org.junit.jupiter.api.Assertions.*;
import java.time.Duration;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import eu.davide.susid.SusId.SusIdInfo;

public class SusIdTest {
    private static Map<Integer, String> secrets;
    private static Map<Integer, String> types;
    private static SusId susId;

    @BeforeAll
    static void setup() {
        // Use LinkedHashMap to keep deterministic key order
        secrets = new LinkedHashMap<>();
        secrets.put(0, "alpha");
        secrets.put(1, "beta");
        secrets.put(2, "gamma");

        types = new LinkedHashMap<>();
        types.put(10, "USER");
        types.put(20, "ORDER");

        susId = new SusId(secrets, types, 2);
    }

    @Test
    void testGenerateAndDecode_Valid() {
        // Verifies that generate + decode round-trip produces a valid SusIdInfo
        int typeId = 10;
        UUID uuid = susId.generate(typeId);
        assertNotNull(uuid, "Generated UUID should not be null");

        SusIdInfo info = susId.decode(uuid);
        assertTrue(info.valid(), "Decoded signature should be valid");
        assertEquals(typeId, info.typeId(), "Decoded typeId should match input");
        assertNotNull(info.signature(), "Signature bytes should not be null");
        assertEquals(2, info.signature().length, "Signature length should be 2 bytes");
        assertTrue(secrets.containsKey(info.secretId()), "Decoded secretId should exist in secrets map");
        assertTrue(info.timestamp() > 0, "Timestamp should be > 0");
    }

    @Test
    void testGenerate_UnknownType() {
        // Ensures generate() rejects unrecognized type IDs
        assertThrows(IllegalArgumentException.class, () -> susId.generate(99));
    }

    @Test
    void testSecretMapValidation_TooMany() {
        // Validates that constructor rejects more than MAX_SECRETS entries
        Map<Integer, String> badSecrets = new HashMap<>();
        for (int i = 0; i < SusId.MAX_SECRETS + 1; i++) {
            badSecrets.put(i, "s");
        }
        assertThrows(IllegalArgumentException.class,
                () -> new SusId(badSecrets, types, 2));
    }

    @Test
    void testSecretMapValidation_MaxAllowed() {
        // Ensures exactly MAX_SECRETS entries is valid
        Map<Integer, String> maxSecrets = new HashMap<>();
        for (int i = 0; i < SusId.MAX_SECRETS; i++) {
            maxSecrets.put(i, "s");
        }
        assertDoesNotThrow(() -> new SusId(maxSecrets, types, 2));
    }

    @Test
    void testTypeMapValidation_TooMany() {
        // Validates that constructor rejects more than MAX_TYPES entries
        Map<Integer, String> badTypes = new HashMap<>();
        for (int i = 0; i < SusId.MAX_TYPES + 1; i++) {
            badTypes.put(i, "t");
        }
        assertThrows(IllegalArgumentException.class,
                () -> new SusId(secrets, badTypes, 2));
    }

    @Test
    void testTypeMapValidation_MaxAllowed() {
        // Ensures exactly MAX_TYPES entries is valid
        Map<Integer, String> maxTypes = new HashMap<>();
        for (int i = 0; i < SusId.MAX_TYPES; i++) {
            maxTypes.put(i, "t");
        }
        assertDoesNotThrow(() -> new SusId(secrets, maxTypes, 2));
    }

    @Test
    void testTypeMapValidation_KeyOutOfRangeNegative() {
        // Validates that negative keys are rejected
        Map<Integer, String> badTypes = new HashMap<>(types);
        badTypes.put(-1, "neg");
        assertThrows(IllegalArgumentException.class,
                () -> new SusId(secrets, badTypes, 2));
    }

    @Test
    void testTypeMapValidation_KeyOutOfRangeOverflow() {
        // Validates that keys >= MAX_TYPES are rejected
        Map<Integer, String> badTypes = new HashMap<>(types);
        badTypes.put(256, "overflow");
        assertThrows(IllegalArgumentException.class,
                () -> new SusId(secrets, badTypes, 2));
    }

    @Test
    void testSecretMapValidation_KeyOutOfRangeNegative() {
        // Validates that negative secrets are rejected
        Map<Integer, String> badSecrets = new HashMap<>(secrets);
        badSecrets.put(-1, "neg");
        assertThrows(IllegalArgumentException.class,
                () -> new SusId(badSecrets, types, 2));
    }

    @Test
    void testSecretMapValidation_KeyOutOfRangeOverflow() {
        // Validates that secrets >= MAX_SECRETS are rejected
        Map<Integer, String> badSecrets = new HashMap<>(secrets);
        badSecrets.put(256, "overflow");
        assertThrows(IllegalArgumentException.class,
                () -> new SusId(badSecrets, types, 2));
    }

    @Test
    void testSignatureLength_Zero_Throws() {
        // Signature length < 1 should be rejected
        assertThrows(IllegalArgumentException.class,
                () -> new SusId(secrets, types, 0));
    }

    @Test
    void testSignatureLength_TooLarge_Throws() {
        // Signature length > 4 should be rejected
        assertThrows(IllegalArgumentException.class,
                () -> new SusId(secrets, types, 5));
    }

    @Test
    void testCustomSignatureLength_Min1() {
        // Validates minimum allowed signature length
        SusId s1 = new SusId(secrets, types, 1);
        UUID uuid = s1.generate(10);
        SusIdInfo info = s1.decode(uuid);
        assertTrue(info.valid());
        assertEquals(1, info.signature().length, "Signature length should be 1 byte");
    }

    @Test
    void testCustomSignatureLength_Max4() {
        // Validates maximum allowed signature length
        SusId s4 = new SusId(secrets, types, 4);
        UUID uuid = s4.generate(20);
        SusIdInfo info = s4.decode(uuid);
        assertTrue(info.valid());
        assertEquals(4, info.signature().length, "Signature length should be 4 bytes");
    }

    @Test
    void testDecode_RandomUuid_Invalid() {
        // Random UUIDs should almost never pass validation
        final int ITERATIONS = 1_000_000;
        final float VALID_THRESHOLD = 0.0001f; // max 0.01% false positives
        int validCount = 0;
        for (int i = 0; i < ITERATIONS; i++) {
            UUID random = UUID.randomUUID();
            if (susId.decode(random).valid()) validCount++;
        }
        float ratio = validCount / (float) ITERATIONS;
        assertTrue(ratio < VALID_THRESHOLD,
                String.format("Expected <%.2f%% valid, got %.5f%%", VALID_THRESHOLD * 100, ratio * 100));
    }

    @Test
    void testDecode_CorruptedSignature_Invalid() {
        // Corrupt one byte of a valid SusId and expect validation failure
        UUID uuid = susId.generate(10);
        byte[] bytes = asBytes(uuid);
        bytes[15] ^= (byte) 0xFF;
        UUID corrupted = uuidFromBytes(bytes);
        SusIdInfo info = susId.decode(corrupted);
        assertFalse(info.valid(), "Corrupted signature should not validate");
    }

    @Test
    void testDecode_FixtureAllZeros() {
        // Deterministic decode: all-zero UUID should parse consistently across languages
        UUID zero = new UUID(0L, 0L);
        SusIdInfo info = susId.decode(zero);
        assertEquals(0L, info.timestamp(), "Timestamp of all-zero UUID should be 0");
        assertEquals(0, info.typeId(), "TypeId of all-zero UUID should be 0");
        assertEquals("Unknown", info.typeDesc(), "Unknown type IDs should map to 'Unknown'");
        assertEquals(0, info.secretId(), "SecretId of all-zero UUID should be 0");
        assertArrayEquals(new byte[] {0,0}, info.signature(), "Signature bytes should be zeros");
        assertFalse(info.valid(), "All-zero UUID should not validate (signature mismatch)");
    }

    @Test
    void testPerformance_GenerateAndDecode() {
        // Basic performance sanity check: generate+decode 10k IDs under 500ms
        assertTimeoutPreemptively(Duration.ofMillis(500), () -> {
            for (int i = 0; i < 10000; i++) {
                UUID id = susId.generate(10);
                SusIdInfo info = susId.decode(id);
                assertTrue(info.valid(), "Generated ID should always validate");
            }
        });
    }

    @Test
    void testGenerateDecodeTimingMicros() {
        // Microbenchmark: assert avg < 10µs/op over 1M iterations
        final int ITERATIONS = 1_000_000;
        long start = System.nanoTime();
        for (int i = 0; i < ITERATIONS; i++) {
            UUID id = susId.generate(10);
            SusIdInfo info = susId.decode(id);
            if (!info.valid()) fail("Signature invalid on iteration " + i);
        }
        long elapsedNs = System.nanoTime() - start;
        double avgMicros = elapsedNs / 1_000.0 / ITERATIONS;
        System.out.printf("SusId generate+decode avg: %.2f µs over %,d iterations%n",
                avgMicros, ITERATIONS);
        assertTrue(avgMicros < 10,
                String.format("Too slow: %.2f µs/op (threshold 10 µs)", avgMicros));
    }

    // Helper methods for byte/UUID conversions
    private static byte[] asBytes(UUID uuid) {
        byte[] b = new byte[16];
        long msb = uuid.getMostSignificantBits(), lsb = uuid.getLeastSignificantBits();
        for (int i = 0; i < 8; i++) b[i] = (byte)(msb >>> (8*(7 - i)));
        for (int i = 8; i < 16; i++) b[i] = (byte)(lsb >>> (8*(15 - i)));
        return b;
    }

    private static UUID uuidFromBytes(byte[] b) {
        long msb = 0, lsb = 0;
        for (int i = 0; i < 8; i++)  msb = (msb << 8) | (b[i] & 0xFFL);
        for (int i = 8; i < 16; i++) lsb = (lsb << 8) | (b[i] & 0xFFL);
        return new UUID(msb, lsb);
    }
}
