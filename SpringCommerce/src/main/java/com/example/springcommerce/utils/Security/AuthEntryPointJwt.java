package com.example.springcommerce.utils.Security;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

/**
 * Custom authentication entry point for handling unauthorized access attempts.
 *
 * WHY: When a user tries to access a protected resource without proper
 * authentication, Spring Security needs to know how to respond.
 *
 * WHAT: This class handles authentication failures by returning a
 * structured JSON error response instead of redirecting to a login page.
 *
 * HOW: Implements AuthenticationEntryPoint interface and gets called
 * automatically by Spring Security when authentication fails.
 *
 * INTERVIEW POINTS:
 * - Difference between authentication and authorization failures
 * - Why JSON responses are preferred in REST APIs over redirects
 * - Security considerations in error messages (information disclosure)
 * - HTTP status codes and their meanings (401 vs 403)
 */
@Component
public class AuthEntryPointJwt implements AuthenticationEntryPoint {

    private static final Logger logger = LoggerFactory.getLogger(AuthEntryPointJwt.class);

    /**
     * Handles authentication failure by sending a structured JSON error response.
     *
     * WHY: REST APIs should return consistent, machine-readable error responses
     * rather than HTML pages or redirects.
     *
     * SECURITY CONSIDERATIONS:
     * - Don't expose internal error details to prevent information disclosure
     * - Log detailed errors for debugging but send generic messages to client
     * - Include correlation information for troubleshooting
     *
     * @param request HTTP request that failed authentication
     * @param response HTTP response to be sent to client
     * @param authException The authentication exception that occurred
     * @throws IOException if response writing fails
     * @throws ServletException if servlet processing fails
     */
    @Override
    public void commence(HttpServletRequest request,
                         HttpServletResponse response,
                         AuthenticationException authException)
            throws IOException, ServletException {

        String requestURI = request.getRequestURI();
        String clientIP = getClientIpAddress(request);

        // Log detailed error for security monitoring
        logger.error("Unauthorized access attempt - URI: {}, IP: {}, Error: {}",
                requestURI, clientIP, authException.getMessage());

        // Set response headers
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);

        // Create standardized error response
        final Map<String, Object> body = new HashMap<>();
        body.put("status", HttpServletResponse.SC_UNAUTHORIZED);
        body.put("error", "Unauthorized");

        // Generic message - don't expose internal details
        body.put("message", "Authentication required to access this resource");
        body.put("path", requestURI);
        body.put("timestamp", Instant.now().toString());

        // Add correlation ID for troubleshooting
        String correlationId = generateCorrelationId(request);
        body.put("correlationId", correlationId);

        // Log correlation ID for support tracking
        logger.info("Unauthorized access response sent with correlation ID: {}", correlationId);

        // Write JSON response
        final ObjectMapper mapper = new ObjectMapper();
        mapper.writeValue(response.getOutputStream(), body);
    }

    /**
     * Extracts the real client IP address from the request.
     *
     * WHY: Important for security logging and rate limiting.
     * Handles proxy headers to get the real client IP.
     *
     * @param request HTTP request
     * @return Client IP address
     */
    private String getClientIpAddress(HttpServletRequest request) {
        String xForwardedFor = request.getHeader("X-Forwarded-For");
        if (xForwardedFor != null && !xForwardedFor.isEmpty()) {
            // Take the first IP in the chain
            return xForwardedFor.split(",")[0].trim();
        }

        String xRealIP = request.getHeader("X-Real-IP");
        if (xRealIP != null && !xRealIP.isEmpty()) {
            return xRealIP;
        }

        return request.getRemoteAddr();
    }

    /**
     * Generates a unique correlation ID for request tracking.
     *
     * WHY: Helps in troubleshooting by correlating client requests
     * with server logs across multiple systems.
     *
     * @param request HTTP request
     * @return Unique correlation ID
     */
    private String generateCorrelationId(HttpServletRequest request) {
        // Check if correlation ID already exists in headers
        String existingId = request.getHeader("X-Correlation-ID");
        if (existingId != null && !existingId.isEmpty()) {
            return existingId;
        }

        // Generate new correlation ID
        return "AUTH-" + System.currentTimeMillis() + "-" +
                Integer.toHexString((int) (Math.random() * 0x10000));
    }
}
