/*
 * Telegram WebProxy - Java port of eooce/Telegram-webproxy (nodejs/index.js)
 * Embedded into NanoLimbo. Allows Telegram clients to reach MTProto DCs
 * via this server over WebSocket (t.me/webproxy?server=HOST&secret=SECRET).
 */
package ua.nanit.limbo.telegram;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Crypto and protocol primitives (frame codec, AES-CTR stream, HMAC tokens).
 */
public final class TgCrypto {

    private static final SecureRandom RNG = new SecureRandom();

    // ==================== UUID normalize ====================
    public static String normalizeSecret(String v) {
        String s = (v == null ? "" : v.trim().toLowerCase());
        if (s.matches("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")) {
            return s.replace("-", "");
        }
        return s;
    }

    // 32-hex, or dd/ee/ef + 32-hex (tagged)
    public static byte[] getKey(String v, boolean keepTag) {
        String s = (v == null ? "" : v.trim().toLowerCase());
        boolean tagged = s.length() == 34 && (s.startsWith("dd") || s.startsWith("ee") || s.startsWith("ef"));
        if (!tagged && s.length() != 32) throw new IllegalArgumentException("Invalid key");
        String hex = (keepTag && tagged) ? s : s.substring(s.length() - 32);
        return hexToBytes(hex);
    }

    public static byte[] hexToBytes(String hex) {
        byte[] out = new byte[hex.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(hex.substring(i * 2, i * 2 + 2), 16);
        }
        return out;
    }

    public static byte[] rand(int n) {
        byte[] b = new byte[n];
        RNG.nextBytes(b);
        return b;
    }

    // ==================== HMAC ====================
    public static byte[] hmacSha256(byte[] key, byte[]... parts) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            for (byte[] p : parts) mac.update(p);
            return mac.doFinal();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static byte[] sha256(byte[]... parts) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            for (byte[] p : parts) md.update(p);
            return md.digest();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    // BOOT derived from SECRET (same labels as node version)
    public static String deriveBoot(String secretRaw) {
        byte[] master = hmacSha256("tg-webproxy-master-v1".getBytes(StandardCharsets.UTF_8),
                secretRaw.trim().toLowerCase().getBytes(StandardCharsets.UTF_8));
        byte[] boot = hmacSha256("tg-webproxy-boot-v1".getBytes(StandardCharsets.UTF_8), master);
        return bytesToHex(boot);
    }

    public static String bytesToHex(byte[] b) {
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte x : b) sb.append(String.format("%02x", x));
        return sb.toString();
    }

    // ==================== Token (bootstrap / session) ====================
    // body = 4B exp + 12B nonce ; token = body + HMAC(boot, kind+"\n"+body)[0..16]
    public static byte[] tokenMac(byte[] bootKey, String kind, byte[] body) {
        byte[] prefix = (kind + "\n").getBytes(StandardCharsets.UTF_8);
        byte[] mac = hmacSha256(bootKey, prefix, body);
        byte[] out = new byte[16];
        System.arraycopy(mac, 0, out, 0, 16);
        return out;
    }

    public static String mkToken(byte[] bootKey, String kind, long expAtMillis) {
        byte[] body = new byte[16];
        int exp = (int) (Math.ceil(expAtMillis / 1000.0));
        body[0] = (byte) (exp >>> 24);
        body[1] = (byte) (exp >>> 16);
        body[2] = (byte) (exp >>> 8);
        body[3] = (byte) exp;
        System.arraycopy(rand(12), 0, body, 4, 12);
        byte[] token = new byte[32];
        System.arraycopy(body, 0, token, 0, 16);
        System.arraycopy(tokenMac(bootKey, kind, body), 0, token, 16, 16);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(token);
    }

    public static boolean verifyToken(String v, byte[] bootKey, String kind) {
        if (v == null || !v.matches("^[A-Za-z0-9_-]{43}$")) return false;
        byte[] token = Base64.getUrlDecoder().decode(v);
        if (token.length != 32) return false;
        long exp = ((token[0] & 0xFFL) << 24) | ((token[1] & 0xFFL) << 16)
                | ((token[2] & 0xFFL) << 8) | (token[3] & 0xFFL);
        if (exp * 1000L <= System.currentTimeMillis()) return false;
        byte[] body = new byte[16];
        System.arraycopy(token, 0, body, 0, 16);
        byte[] want = tokenMac(bootKey, kind, body);
        int diff = 0;
        for (int i = 0; i < 16; i++) diff |= token[16 + i] ^ want[i];
        return diff == 0;
    }

    // Bridge capability: HMAC(bridgeKey, "tdesktop-web-proxy-bridge-v1\n" + host)[0..24] b64url
    public static String mkCap(byte[] key, String host) {
        byte[] sig = hmacSha256(key,
                "tdesktop-web-proxy-bridge-v1\n".getBytes(StandardCharsets.UTF_8),
                host.toLowerCase().getBytes(StandardCharsets.UTF_8));
        byte[] cut = new byte[24];
        System.arraycopy(sig, 0, cut, 0, 24);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(cut);
    }

    // ==================== 64-byte fakeTLS head ====================
    public static class Head {
        public final int mode;    // 0xef / 0xee / 0xdd
        public final int target;  // dc index 0..4
        public final boolean media;

        Head(int mode, int target, boolean media) {
            this.mode = mode;
            this.target = target;
            this.media = media;
        }
    }

    public static Head headOf(byte[] head) {
        int tag = ((head[56] & 0xFF)) | ((head[57] & 0xFF) << 8)
                | ((head[58] & 0xFF) << 16) | ((head[59] & 0xFF) << 24);
        int mode;
        if (tag == 0xefefefef) mode = 0xef;
        else if (tag == 0xeeeeeeee) mode = 0xee;
        else if (tag == 0xdddddddd) mode = 0xdd;
        else throw new IllegalArgumentException("Invalid mode");
        int dc = (short) ((head[60] & 0xFF) | ((head[61] & 0xFF) << 8));
        int target = Math.abs(dc) - 1;
        if (target < 0 || target >= 5) throw new IllegalArgumentException("Invalid DC");
        return new Head(mode, target, dc < 0);
    }

    public static byte[] mkHead(int mode, int target, boolean media) {
        byte[] head = new byte[64];
        do {
            RNG.nextBytes(head);
        } while (head[0] == (byte) 0xef || isBadHead(head));
        head[56] = (byte) mode; head[57] = (byte) mode;
        head[58] = (byte) mode; head[59] = (byte) mode;
        int dc = (target + 1) * (media ? -1 : 1);
        head[60] = (byte) dc;
        head[61] = (byte) (dc >> 8);
        return head;
    }

    private static boolean isBadHead(byte[] h) {
        String s = new String(h, 0, 4, StandardCharsets.US_ASCII);
        if (s.equals("HEAD") || s.equals("POST") || s.equals("GET ") || s.equals("OPTI")) return true;
        return (h[4] | h[5] | h[6] | h[7]) == 0;
    }

    // ==================== AES-CTR continuous stream ====================
    public static class CtrStream {
        private final SecretKeySpec keySpec;
        private final String transformation;
        private final byte[] iv;      // 16-byte counter
        private byte[] tail = new byte[0];

        public CtrStream(byte[] key, byte[] ctr) {
            this.transformation = key.length == 32 ? "AES/CTR/NoPadding" : "AES/CTR/NoPadding";
            this.keySpec = new SecretKeySpec(key, "AES");
            this.iv = ctr.clone();
        }

        private static void step(byte[] ctr, int n) {
            long carry = n & 0xFFFFFFFFL;
            for (int i = ctr.length - 1; i >= 0 && carry > 0; i--) {
                long next = (ctr[i] & 0xFF) + (carry & 0xFF);
                ctr[i] = (byte) next;
                carry = (carry >>> 8) + (next >>> 8);
            }
        }

        public synchronized byte[] crypt(byte[] b) throws Exception {
            if (b.length == 0) return new byte[0];
            if (tail.length == 0 && b.length % 16 == 0) {
                Cipher c = Cipher.getInstance(transformation);
                c.init(Cipher.ENCRYPT_MODE, keySpec, new javax.crypto.spec.IvParameterSpec(iv));
                byte[] raw = c.doFinal(b);
                step(iv, b.length / 16);
                return raw;
            }
            if (b.length <= tail.length) {
                byte[] out = new byte[b.length];
                for (int i = 0; i < b.length; i++) out[i] = (byte) (b[i] ^ tail[i]);
                byte[] nt = new byte[tail.length - b.length];
                System.arraycopy(tail, b.length, nt, 0, nt.length);
                tail = nt;
                return out;
            }
            int skip = tail.length > 0 ? 16 - tail.length : 0;
            byte[] ctrCopy = iv.clone();
            if (skip > 0) {
                for (int i = ctrCopy.length - 1; i >= 0; i--) {
                    if (ctrCopy[i]-- != 0) break;
                }
            }
            int end = skip + b.length;
            byte[] block = new byte[((end + 15) / 16) * 16];
            System.arraycopy(b, 0, block, skip, b.length);
            Cipher c = Cipher.getInstance(transformation);
            c.init(Cipher.ENCRYPT_MODE, keySpec, new javax.crypto.spec.IvParameterSpec(ctrCopy));
            byte[] raw = c.doFinal(block);
            tail = new byte[raw.length - end];
            System.arraycopy(raw, end, tail, 0, tail.length);
            step(iv, block.length / 16 - (skip > 0 ? 1 : 0));
            byte[] out = new byte[b.length];
            System.arraycopy(raw, skip, out, 0, b.length);
            return out;
        }
    }

    public static byte[] cipherKey(byte[] head, byte[] secret, boolean reverse) {
        byte[] mat = new byte[48];
        System.arraycopy(head, 8, mat, 0, 48);
        if (reverse) {
            for (int i = 0, j = mat.length - 1; i < j; i++, j--) {
                byte t = mat[i]; mat[i] = mat[j]; mat[j] = t;
            }
        }
        byte[] first32 = new byte[32];
        System.arraycopy(mat, 0, first32, 0, 32);
        if (secret.length > 0) return sha256(first32, secret);
        return first32;
    }

    // wire head: encrypt 64B head with cipher(head, nil, false), first 56 bytes stay plaintext
    public static byte[][] wireHead(byte[] head) throws Exception {
        byte[] key = cipherKey(head, new byte[0], false);
        byte[] ctr = new byte[16];
        System.arraycopy(head, 8 + 32, ctr, 0, 16);
        CtrStream stream = new CtrStream(key, ctr);
        byte[] raw = stream.crypt(head);
        System.arraycopy(head, 0, raw, 0, 56);
        return new byte[][]{raw, key, ctr.clone()};
    }

    // ==================== Frame codec (type1B + sid3B + len4B + payload) ====================
    public static byte[] encFrame(int type, int sid, byte[] payload) {
        byte[] f = new byte[8 + payload.length];
        f[0] = (byte) type;
        f[1] = (byte) (sid >>> 16);
        f[2] = (byte) (sid >>> 8);
        f[3] = (byte) sid;
        int n = payload.length;
        f[4] = (byte) (n >>> 24);
        f[5] = (byte) (n >>> 16);
        f[6] = (byte) (n >>> 8);
        f[7] = (byte) n;
        System.arraycopy(payload, 0, f, 8, n);
        return f;
    }

    public static class Frame {
        public final int type;
        public final int sid;
        public final byte[] payload;

        Frame(int type, int sid, byte[] payload) {
            this.type = type;
            this.sid = sid;
            this.payload = payload;
        }
    }

    public static java.util.List<Frame> frames(byte[] b) {
        java.util.List<Frame> out = new java.util.ArrayList<>();
        int o = 0;
        while (b.length - o >= 8) {
            int type = b[o] & 0xFF;
            if (type != 1 && type != 2 && type != 3 && type != 4 && type != 17) {
                throw new IllegalArgumentException("Invalid frame type");
            }
            int sid = ((b[o + 1] & 0xFF) << 16) | ((b[o + 2] & 0xFF) << 8) | (b[o + 3] & 0xFF);
            int n = ((b[o + 4] & 0xFF) << 24) | ((b[o + 5] & 0xFF) << 16)
                    | ((b[o + 6] & 0xFF) << 8) | (b[o + 7] & 0xFF);
            if (n > 1024 * 1024) throw new IllegalArgumentException("Frame too large");
            int total = 8 + n;
            if (b.length - o < total) break;
            byte[] payload = new byte[n];
            System.arraycopy(b, o + 8, payload, 0, n);
            out.add(new Frame(type, sid, payload));
            o += total;
        }
        return out;
    }

    // ==================== Hello ====================
    public static void hello(byte[] body) {
        if (body.length != 9 || (body[0] & 0xFF) != 0x10 || body[1] != 0 || body[2] != 0
                || body[3] != 0 || ((body[4] & 0xFF) << 24 | (body[5] & 0xFF) << 16
                | (body[6] & 0xFF) << 8 | (body[7] & 0xFF)) != 1
                || body[8] != 1) {
            throw new IllegalArgumentException("Invalid hello");
        }
    }

    // ==================== MTProto packet parser ====================
    public static class PktParser {
        private final int mode;
        private ByteArrayOutputStream tail = new ByteArrayOutputStream();

        public PktParser(int mode) {
            this.mode = mode;
        }

        public java.util.List<byte[]> push(byte[] b) {
            byte[] all = tail.size() > 0 ? concat(tail.toByteArray(), b) : b;
            java.util.List<byte[]> pkts = new java.util.ArrayList<>();
            int o = 0;
            for (;;) {
                int avail = all.length - o;
                int hLen, pLen;
                if (mode == 0xef) {
                    if (avail < 1) break;
                    int words = all[o] & 0x7f;
                    if (words == 0x7f) {
                        if (avail < 4) break;
                        words = (all[o + 1] & 0xFF) | ((all[o + 2] & 0xFF) << 8) | ((all[o + 3] & 0xFF) << 16);
                        hLen = 4;
                    } else hLen = 1;
                    pLen = words * 4;
                } else {
                    if (avail < 4) break;
                    pLen = ((all[o] & 0xFF) | ((all[o + 1] & 0xFF) << 8)
                            | ((all[o + 2] & 0xFF) << 16) | ((all[o + 3] & 0xFF) << 24)) & 0x7fffffff;
                    hLen = 4;
                }
                if (pLen <= 0 || pLen > 8 * 1024 * 1024) throw new IllegalArgumentException("Invalid packet length");
                int total = hLen + pLen;
                if (avail < total) break;
                byte[] p = new byte[total];
                System.arraycopy(all, o, p, 0, total);
                pkts.add(p);
                o += total;
            }
            tail.reset();
            if (all.length - o > 0) tail.write(all, o, all.length - o);
            return pkts;
        }

        public void clear() {
            tail.reset();
        }
    }

    public static byte[] concat(byte[]... parts) {
        int n = 0;
        for (byte[] p : parts) n += p.length;
        byte[] out = new byte[n];
        int o = 0;
        for (byte[] p : parts) {
            System.arraycopy(p, 0, out, o, p.length);
            o += p.length;
        }
        return out;
    }

    // ==================== Window grant (4B big-endian) ====================
    public static int win(byte[] body) {
        if (body.length != 4) throw new IllegalArgumentException("Invalid window");
        int n = ((body[0] & 0xFF) << 24) | ((body[1] & 0xFF) << 16)
                | ((body[2] & 0xFF) << 8) | (body[3] & 0xFF);
        if (n == 0) throw new IllegalArgumentException("Zero window");
        return n;
    }

    private TgCrypto() {}
}
