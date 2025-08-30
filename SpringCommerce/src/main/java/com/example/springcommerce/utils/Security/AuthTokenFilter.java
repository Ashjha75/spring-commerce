package com.example.springcommerce.utils.Security;

import com.example.springcommerce.utils.Security.Service.UserDetailsServiceImpl;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * Authentication filter for processing JWT tokens on incoming requests.
 *
 * WHY: In stateless applications, every request must be authenticated
 * independently since there's no server-side session storage.
 *
 * WHAT: This filter intercepts HTTP requests, extracts JWT tokens,
 * validates them, and sets up Spring Security context for authorization.
 *
 * HOW: Extends OncePerRequestFilter to ensure single execution per request.
 * Runs before UsernamePasswordAuthenticationFilter in the filter chain.
 *
 * INTERVIEW POINTS:
 * - Spring Security Filter Chain order and importance
 * - OncePerRequestFilter vs regular Filter
 * - SecurityContext and SecurityContextHolder
 * - Stateless vs Stateful authentication
 */
@Component
public class AuthTokenFilter extends OncePerRequestFilter {

    private static final Logger logger = LoggerFactory.getLogger(AuthTokenFilter.class);

    @Autowired
    private JwtUtils jwtUtils;

    @Autowired
    private UserDetailsServiceImpl userDetailsService;

    /**
     * Core filter method that processes each HTTP request for JWT authentication.
     *
     * WHY: Every request in a stateless API needs authentication verification
     * since there's no session to maintain login state.
     *
     * PROCESS:
     * 1. Extract JWT from request (header or cookie)
     * 2. Validate token format and signature
     * 3. Extract username from valid token
     * 4. Load user details from database
     * 5. Create authentication object
     * 6. Set security context for this request
     *
     * @param request  HTTP request containing potential JWT token
     * @param response HTTP response object
     * @param filterChain Chain of filters to continue processing
     */
    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        String requestURI = request.getRequestURI();
        logger.debug("Processing authentication for request: {}", requestURI);

        try {
            String jwt = parseJwt(request);

            if (StringUtils.hasText(jwt) && jwtUtils.validateJwtToken(jwt)) {
                String username = jwtUtils.getUserNameFromJwtToken(jwt);
                logger.debug("Valid JWT found for user: {}", username);

                // Load user details from database
                UserDetails userDetails = userDetailsService.loadUserByUsername(username);

                // Create authentication token
                UsernamePasswordAuthenticationToken authentication =
                        new UsernamePasswordAuthenticationToken(
                                userDetails,
                                null,
                                userDetails.getAuthorities()
                        );

                // Set additional request details
                authentication.setDetails(
                        new WebAuthenticationDetailsSource().buildDetails(request)
                );

                // Set authentication in security context
                SecurityContextHolder.getContext().setAuthentication(authentication);

                logger.debug("User authenticated successfully with roles: {}",
                        userDetails.getAuthorities());

            } else {
                logger.debug("No valid JWT token found for request: {}", requestURI);
            }

        } catch (UsernameNotFoundException ex) {
            logger.warn("User not found during JWT authentication: {}", ex.getMessage());
            // Clear any partial authentication context
            SecurityContextHolder.clearContext();

        } catch (Exception ex) {
            logger.error("JWT authentication failed for request {}: {}",
                    requestURI, ex.getMessage());
            // Clear security context on any authentication error
            SecurityContextHolder.clearContext();
        }

        // Continue with the filter chain regardless of authentication result
        filterChain.doFilter(request, response);
    }

    /**
     * Extracts JWT token from HTTP request.
     *
     * WHY: JWTs can be sent via Authorization header (preferred) or cookies.
     * We need to check both locations for maximum compatibility.
     *
     * PRIORITY:
     * 1. Authorization header (Bearer token) - REST API standard
     * 2. HTTP cookies - Web application fallback
     *
     * @param request HTTP request to parse
     * @return JWT token string or null if not found
     */
    private String parseJwt(HttpServletRequest request) {
        if (request == null) {
            return null;
        }

        // Try Authorization header first (preferred method)
        String headerAuth = request.getHeader("Authorization");
        logger.debug("Checking Authorization header for JWT");

        // REMOVED: System.out.println - NEVER use in production!

        if (StringUtils.hasText(headerAuth) && headerAuth.startsWith("Bearer ")) {
            String token = headerAuth.substring(7).trim();
            if (StringUtils.hasText(token)) {
                logger.debug("JWT token found in Authorization header");
                return token;
            }
        }

        // Fallback to cookies
        String jwtFromCookies = jwtUtils.getJwtFromCookies(request);
        if (StringUtils.hasText(jwtFromCookies)) {
            logger.debug("JWT token found in cookies");
            return jwtFromCookies;
        }

        logger.debug("No JWT token found in request");
        return null;
    }
}
