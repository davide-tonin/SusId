package com.davidetonin.susid;

import static org.junit.jupiter.api.Assertions.*;
import java.time.Duration;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import com.davidetonin.susid.SusId.SusIdInfo;

public class SusIdTest {
    private static Map<Integer, String> secrets;
    private static Map<Integer, String> types;
    private static SusId susId;

    @BeforeAll
    static void setup() {
        secrets = new HashMap<>();
        secrets.put(0, "alpha");
        secrets.put(1, "beta");
        secrets.put(2, "gamma");

        types = new HashMap<>();
        types.put(10, "USER");
        types.put(20, "ORDER");

        susId = new SusId(secrets, types);
    }

    @Test
    void testGenerateAndDecode_Valid() {
        int typeId = 10;
        UUID uuid = susId.generate(typeId);
        assertNotNull(uuid);

        SusIdInfo info = susId.decode(uuid);
        assertTrue(info.valid());
        assertEquals(typeId, info.typeId());
        assertNotNull(info.signature());
        assertEquals(2, info.signature().length);
        assertTrue(secrets.containsKey(info.secretId()));
        assertTrue(info.timestamp() > 0);
    }

    @Test
    void testGenerate_UnknownType() {
        assertThrows(IllegalArgumentException.class, () -> susId.generate(99));
    }

    @Test
    void testSecretMapValidation_TooMany() {
        Map<Integer, String> badSecrets = new HashMap<>();
        for (int i = 0; i < SusId.MAX_SECRETS + 1; i++) {
            badSecrets.put(i, "s");
        }
        assertThrows(IllegalArgumentException.class, () -> new SusId(badSecrets, types));
    }

    @Test
    void testTypeMapValidation_TooMany() {
        Map<Integer, String> badTypes = new HashMap<>();
        for (int i = 0; i < SusId.MAX_TYPES + 1; i++) {
            badTypes.put(i, "t");
        }
        assertThrows(IllegalArgumentException.class, () -> new SusId(secrets, badTypes));
    }

    @Test
    void testTypeMapValidation_KeyOutOfRange() {
        Map<Integer, String> badTypes = new HashMap<>(types);
        badTypes.put(-1, "neg");
        assertThrows(IllegalArgumentException.class, () -> new SusId(secrets, badTypes));
    }

    @Test
    void testSecretMapValidation_KeyOutOfRange() {
        Map<Integer, String> badSecrets = new HashMap<>(secrets);
        badSecrets.put(256, "overflow");
        assertThrows(IllegalArgumentException.class, () -> new SusId(badSecrets, types));
    }

    @Test
    void testDecode_RandomUuid_Invalid() {
        UUID random = UUID.randomUUID();
        SusIdInfo info = susId.decode(random);
        assertFalse(info.valid());
    }

    @Test
    void testDecode_CorruptedSignature_Invalid() {
        UUID uuid = susId.generate(10);
        byte[] bytes = asBytes(uuid);
        bytes[15] ^= (byte)0xFF;
        UUID corrupted = uuidFromBytes(bytes);
        SusIdInfo info = susId.decode(corrupted);
        assertFalse(info.valid());
    }

    @Test
    void testPerformance_GenerateAndDecode() {
        assertTimeoutPreemptively(Duration.ofMillis(500), () -> {
            for (int i = 0; i < 10000; i++) {
                UUID id = susId.generate(10);
                SusIdInfo info = susId.decode(id);
                assertTrue(info.valid());
            }
        });
    }

    @Test
    void testCustomSignatureLength_Min1() {
        SusId s1 = new SusId(secrets, types, 1);
        UUID uuid = s1.generate(10);
        SusIdInfo info = s1.decode(uuid);
        assertTrue(info.valid());
        assertEquals(1, info.signature().length);
    }

    @Test
    void testCustomSignatureLength_Max4() {
        SusId s4 = new SusId(secrets, types, 4);
        UUID uuid = s4.generate(20);
        SusIdInfo info = s4.decode(uuid);
        assertTrue(info.valid());
        assertEquals(4, info.signature().length);
    }

    @Test
    void testGenerateAndDecode_Overload() {
        SusId s4 = new SusId(secrets, types, 4);
        UUID uuid = s4.generate();
        SusIdInfo info = s4.decode(uuid);
        assertTrue(info.valid());
        assertEquals(255, info.typeId());
    }

    @Test
    void testSignatureLength_Zero_Throws() {
        assertThrows(IllegalArgumentException.class, () -> new SusId(secrets, types, 0));
    }

    @Test
    void testSignatureLength_TooLarge_Throws() {
        assertThrows(IllegalArgumentException.class, () -> new SusId(secrets, types, 5));
    }

    // Helpers
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