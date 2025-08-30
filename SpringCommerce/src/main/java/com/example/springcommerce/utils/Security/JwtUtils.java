package com.example.springcommerce.utils.Security;

import com.example.springcommerce.utils.Security.Service.UserDetailsImpl;
import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SecurityException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.util.WebUtils;

import javax.crypto.SecretKey;
import java.security.Key;
import java.time.Duration;
import java.util.Date;

/**
 * Utility class for JWT (JSON Web Token) operations.
 *
 * WHY: JWTs are stateless tokens that contain user information and claims.
 * They eliminate the need for server-side session storage, making applications scalable.
 *
 * WHAT: This class handles JWT creation, validation, parsing, and cookie management.
 *
 * HOW: Uses JJWT library with HMAC-SHA algorithms for token signing and verification.
 *
 * INTERVIEW POINTS:
 * - JWT structure: Header.Payload.Signature (Base64 encoded)
 * - Stateless authentication vs session-based authentication
 * - Token expiration and security considerations
 * - Cookie security attributes (HttpOnly, Secure, SameSite)
 */
@Component
public class JwtUtils {

    private static final Logger logger = LoggerFactory.getLogger(JwtUtils.class);

    @Value("${spring.app.jwtSecret}")
    private String jwtSecret;

    @Value("${spring.app.jwtExpirationMs}")
    private int jwtExpirationMs;

    @Value("${spring.ecom.app.jwtCookieName}")
    private String jwtCookie;

    /**
     * Extracts JWT token from Authorization header.
     *
     * WHY: Standard way to send JWTs in HTTP requests is via Authorization header
     * with "Bearer " prefix as per RFC 6750.
     *
     * @param request HTTP request containing Authorization header
     * @return JWT token string or null if not found/invalid format
     */
    public String getJwtFromHeader(HttpServletRequest request) {
        String bearerToken = request.getHeader("Authorization");
        logger.debug("Processing Authorization header for JWT extraction");

        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer ")) {
            String token = bearerToken.substring(7).trim();
            return StringUtils.hasText(token) ? token : null;
        }

        return null;
    }

    /**
     * Generates a secure JWT cookie for user authentication.
     *
     * WHY: Cookies provide automatic inclusion in requests and can be secured
     * against XSS/CSRF attacks with proper attributes.
     *
     * SECURITY IMPROVEMENTS:
     * - HttpOnly: Prevents JavaScript access (XSS protection)
     * - Secure: Only sent over HTTPS
     * - SameSite: CSRF protection
     *
     * @param userPrincipal User details for token generation
     * @return Secure ResponseCookie containing JWT
     */
    public ResponseCookie generateJwtCookie(UserDetailsImpl userPrincipal) {
        if (userPrincipal == null || !StringUtils.hasText(userPrincipal.getUsername())) {
            throw new IllegalArgumentException("User principal cannot be null or empty");
        }

        String jwtToken = generateTokenFromUsername(userPrincipal.getUsername());

        return ResponseCookie.from(jwtCookie, jwtToken)
                .path("/")                    // Available to entire application
                .maxAge(Duration.ofDays(1))   // 24 hours expiration
                .httpOnly(true)               // XSS protection - CRITICAL FIX
                .secure(true)                 // HTTPS only - CRITICAL FIX
                .sameSite("Strict")           // CSRF protection - CRITICAL FIX
                .build();
    }

    /**
     * Creates a cookie to clear JWT token (for logout).
     *
     * WHY: Proper logout requires clearing the authentication token
     * from client storage.
     */
    public ResponseCookie getCleanJwtCookie() {
        return ResponseCookie.from(jwtCookie, "")
                .path("/")
                .maxAge(0)                    // Immediate expiration
                .httpOnly(true)
                .secure(true)
                .sameSite("Strict")
                .build();
    }

    /**
     * Generates JWT token from username with proper validation.
     *
     * WHY: This is the core method for creating authenticated sessions.
     *
     * HOW: Creates JWT with subject (username), issued time, expiration,
     * and signs with secret key using HMAC-SHA256.
     *
     * @param username User identifier for the token
     * @return Signed JWT token string
     * @throws IllegalArgumentException if username is invalid
     */
    public String generateTokenFromUsername(String username) {
        if (!StringUtils.hasText(username)) {
            throw new IllegalArgumentException("Username cannot be null or empty");
        }

        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + jwtExpirationMs);

        return Jwts.builder()
                .setSubject(username.trim())          // User identifier
                .setIssuedAt(now)                     // Token creation time
                .setExpiration(expiryDate)            // Token expiration
                .signWith(key(), SignatureAlgorithm.HS256)  // HMAC-SHA256 signature
                .compact();
    }

    /**
     * Extracts JWT token from HTTP cookies.
     *
     * WHY: Fallback mechanism when Authorization header is not used.
     * Useful for web applications using cookie-based authentication.
     */
    public String getJwtFromCookies(HttpServletRequest request) {
        if (request == null) {
            return null;
        }

        Cookie cookie = WebUtils.getCookie(request, jwtCookie);
        if (cookie != null && StringUtils.hasText(cookie.getValue())) {
            return cookie.getValue().trim();
        }

        return null;
    }

    /**
     * Generates cryptographic key for JWT signing.
     *
     * WHY: HMAC requires a secret key for creating and verifying signatures.
     * The key must be kept secret and be strong enough for security.
     *
     * INTERVIEW POINT: Symmetric vs Asymmetric signing
     * - HMAC (used here): Same key for signing and verification
     * - RSA/ECDSA: Public/private key pairs
     */
    private Key key() {
        return Keys.hmacShaKeyFor(Decoders.BASE64.decode(jwtSecret));
    }

    /**
     * Extracts username from JWT token with comprehensive validation.
     *
     * WHY: This method converts the token back to user identity
     * for authentication purposes.
     *
     * @param token JWT token to parse
     * @return Username from token subject
     * @throws RuntimeException if token is invalid
     */
    public String getUserNameFromJwtToken(String token) {
        if (!StringUtils.hasText(token)) {
            throw new IllegalArgumentException("JWT token cannot be null or empty");
        }

        try {
            Claims claims = Jwts.parser()
                    .verifyWith((SecretKey) key())
                    .build()
                    .parseSignedClaims(token.trim())
                    .getPayload();

            return claims.getSubject();
        } catch (Exception e) {
            logger.error("Failed to extract username from JWT: {}", e.getMessage());
            throw new RuntimeException("Invalid JWT token", e);
        }
    }

    /**
     * Validates JWT token with comprehensive error handling.
     *
     * WHY: Token validation is critical for security. Invalid tokens
     * must be rejected to prevent unauthorized access.
     *
     * WHAT: Checks token signature, expiration, format, and claims.
     *
     * HOW: Uses JJWT parser with secret key verification.
     *
     * INTERVIEW POINTS:
     * - Different types of JWT exceptions and their meanings
     * - Why we log errors but don't expose details to client
     * - Token replay attacks and mitigation
     *
     * @param authToken JWT token to validate
     * @return true if token is valid, false otherwise
     */
    public boolean validateJwtToken(String authToken) {
        if (!StringUtils.hasText(authToken)) {
            logger.warn("Empty or null JWT token provided for validation");
            return false;
        }

        try {
            // REMOVED: System.out.println - NEVER use in production!
            Jwts.parser()
                    .verifyWith((SecretKey) key())
                    .build()
                    .parseSignedClaims(authToken.trim());

            logger.debug("JWT token validation successful");
            return true;

        } catch (SecurityException ex) {
            logger.error("Invalid JWT signature: {}", ex.getMessage());
        } catch (MalformedJwtException ex) {
            logger.error("Invalid JWT format: {}", ex.getMessage());
        } catch (ExpiredJwtException ex) {
            logger.error("JWT token expired: {}", ex.getMessage());
        } catch (UnsupportedJwtException ex) {
            logger.error("Unsupported JWT token: {}", ex.getMessage());
        } catch (IllegalArgumentException ex) {
            logger.error("JWT claims string is empty: {}", ex.getMessage());
        } catch (Exception ex) {
            logger.error("Unexpected JWT validation error: {}", ex.getMessage());
        }

        return false;
    }
}
