/**
 * ***************************************************************************** Copyright 2006
 * European Community
 *
 * <p>Licensed under the EUPL, Version 1.1 or – as soon they will be approved by the European
 * Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except in
 * compliance with the Licence. You may obtain a copy of the Licence at:
 *
 * <p>https://joinup.ec.europa.eu/software/page/eupl
 *
 * <p>Unless required by applicable law or agreed to in writing, software distributed under the
 * Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 * ****************************************************************************
 */
package eu.cec.digit.circabc.repo.security.authentication;

import org.alfresco.repo.security.authentication.MD4PasswordEncoderImpl;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;

/**
 * Secure password encoder that uses PBKDF2-HMAC-SHA256 for all new password
 * hashing.
 *
 * <p>Backward-compatible: can still <em>verify</em> legacy hashes stored with
 * the {@code {SHA}}, {@code {MD5}} prefix format or the old Alfresco MD4
 * encoding, but {@link #encodePassword(String, Object)} now always produces a
 * PBKDF2 hash prefixed with {@code {PBKDF2}}.
 *
 * <p>This addresses OWASP A02:2021 (Cryptographic Failures) and
 * NIST SP 800-131A by replacing MD4/MD5/SHA-1 with PBKDF2-HMAC-SHA256
 * (600 000 iterations, 16-byte random salt, 256-bit derived key).
 */
public class CircabcPasswordEncoderImpl extends MD4PasswordEncoderImpl {

    /** PBKDF2 iteration count – OWASP 2023 recommendation for HMAC-SHA256. */
    private static final int PBKDF2_ITERATIONS = 600_000;

    /** Derived key length in bits. */
    private static final int PBKDF2_KEY_LENGTH = 256;

    /** Salt length in bytes. */
    private static final int SALT_LENGTH = 16;

    /** PBKDF2 algorithm available in JDK 8+. */
    private static final String PBKDF2_ALGORITHM = "PBKDF2WithHmacSHA256";

    /** Prefix used to identify PBKDF2-encoded passwords in the store. */
    private static final String PBKDF2_PREFIX = "{PBKDF2}";

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    public CircabcPasswordEncoderImpl() {
        super();
    }

    /**
     * Validates a raw password against a stored encoded password.
     *
     * <p>Supports the following formats for backward compatibility:
     * <ul>
     *   <li>{@code {PBKDF2}iterations:base64salt:base64hash} – PBKDF2 (preferred)</li>
     *   <li>{@code {SHA}base64} / {@code {MD5}base64} – legacy digest</li>
     *   <li>No prefix – legacy Alfresco MD4 encoding</li>
     * </ul>
     * Only PBKDF2 hashes are written by {@link #encodePassword(String, Object)}.
     */
    @Override
    public boolean isPasswordValid(String encPass, String rawPass, Object salt) {

        if (encPass == null || rawPass == null) {
            return false;
        }

        if (encPass.startsWith(PBKDF2_PREFIX)) {
            return verifyPbkdf2(encPass, rawPass);
        }

        // Legacy verification for existing stored hashes
        if (isAlgorithmPresent(encPass)) {
            String algorithm = getAlgorithm(encPass);
            if (algorithm.equals("SHA") || algorithm.equals("MD5")) {
                String pass2 = encodeLegacyPassword(algorithm, rawPass);
                return encPass.equals(pass2);
            } else {
                throw new IllegalArgumentException("Not supported algorithm : " + algorithm);
            }
        } else {
            // Fall back to Alfresco MD4 verification for very old hashes
            return super.isPasswordValid(encPass, rawPass, salt);
        }
    }

    /**
     * Encodes a password using PBKDF2-HMAC-SHA256 with a random per-hash salt.
     *
     * <p>The {@code salt} parameter is ignored because PBKDF2 generates its
     * own cryptographically-secure random salt internally.
     *
     * @param rawPass the plaintext password
     * @param salt    ignored (kept for API compatibility)
     * @return the PBKDF2 hash prefixed with {@code {PBKDF2}}
     */
    @Override
    public String encodePassword(String rawPass, Object salt) {
        byte[] saltBytes = new byte[SALT_LENGTH];
        SECURE_RANDOM.nextBytes(saltBytes);

        byte[] hash = pbkdf2(rawPass, saltBytes, PBKDF2_ITERATIONS);

        String saltBase64 = Base64.getEncoder().encodeToString(saltBytes);
        String hashBase64 = Base64.getEncoder().encodeToString(hash);

        return PBKDF2_PREFIX + PBKDF2_ITERATIONS + ":" + saltBase64 + ":" + hashBase64;
    }

    private String getAlgorithm(String encPass) {
        return encPass.substring(encPass.indexOf('{') + 1, encPass.indexOf('}'));
    }

    private boolean isAlgorithmPresent(String encPass) {
        return encPass.indexOf('{') == 0 && encPass.indexOf('}') > 0;
    }

    /**
     * Verifies a raw password against a stored PBKDF2 hash.
     *
     * <p>Format: {@code {PBKDF2}iterations:base64salt:base64hash}
     */
    private boolean verifyPbkdf2(String encPass, String rawPass) {
        String payload = encPass.substring(PBKDF2_PREFIX.length());
        String[] parts = payload.split(":");
        if (parts.length != 3) {
            return false;
        }

        int iterations;
        try {
            iterations = Integer.parseInt(parts[0]);
        } catch (NumberFormatException e) {
            return false;
        }

        byte[] saltBytes = Base64.getDecoder().decode(parts[1]);
        byte[] storedHash = Base64.getDecoder().decode(parts[2]);

        byte[] computedHash = pbkdf2(rawPass, saltBytes, iterations);

        return MessageDigest.isEqual(storedHash, computedHash);
    }

    /**
     * Derives a key using PBKDF2-HMAC-SHA256.
     */
    private byte[] pbkdf2(String password, byte[] salt, int iterations) {
        try {
            PBEKeySpec spec = new PBEKeySpec(
                    password.toCharArray(), salt, iterations, PBKDF2_KEY_LENGTH);
            SecretKeyFactory skf = SecretKeyFactory.getInstance(PBKDF2_ALGORITHM);
            return skf.generateSecret(spec).getEncoded();
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new IllegalStateException("PBKDF2 hashing failed", e);
        }
    }

    /**
     * Legacy digest encoding kept only for <em>verification</em> of old stored
     * hashes. Never used for new password encoding.
     */
    private String encodeLegacyPassword(String algorithm, String rawPass) {
        MessageDigest md;
        try {
            md = MessageDigest.getInstance(algorithm);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalArgumentException("No such algorithm : " + algorithm, e);
        }
        md.update(rawPass.getBytes(StandardCharsets.UTF_8));
        byte[] bytes = md.digest();

        String hash = Base64.getEncoder().encodeToString(bytes);
        return "{" + algorithm + "}" + hash;
    }
}
