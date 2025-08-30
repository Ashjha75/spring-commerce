package com.example.springcommerce.utils.utilityGroup;

import com.example.springcommerce.entity.userEntity;
import com.example.springcommerce.repository.userRepo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

/**
 * Utility class for retrieving current authenticated user information.
 *
 * WHY: Frequently needed functionality to get current user details
 * across different parts of the application.
 *
 * WHAT: Provides convenient methods to access current user's information
 * without repeating authentication logic everywhere.
 *
 * HOW: Uses Spring Security's SecurityContextHolder to get current
 * authentication and retrieves user from database.
 *
 * PERFORMANCE IMPROVEMENT: Single database call with caching to avoid
 * multiple queries for the same user in one request.
 *
 * INTERVIEW POINTS:
 * - SecurityContextHolder and thread-local storage
 * - Authentication vs Authorization
 * - Caching strategies in web applications
 * - Request-scoped beans and their lifecycle
 */
@Component
public class AuthUtil {

    private static final Logger logger = LoggerFactory.getLogger(AuthUtil.class);

    private final userRepo userRepository;

    // Thread-local cache to avoid multiple DB calls per request
    private final ThreadLocal<userEntity> userCache = new ThreadLocal<>();
    private final ThreadLocal<String> cachedUsername = new ThreadLocal<>();

    @Autowired
    public AuthUtil(userRepo userRepository) {
        this.userRepository = userRepository;
    }

    /**
     * Gets the current authenticated user with caching optimization.
     *
     * WHY: Multiple methods in this class need the same user entity.
     * Without caching, each method call results in a database query.
     *
     * HOW: Uses ThreadLocal to cache user per request thread.
     * Validates cache by comparing usernames to handle user switching.
     *
     * PERFORMANCE BENEFIT: Reduces database calls from N to 1 per request.
     *
     * @return Current authenticated user entity
     * @throws SecurityException if no authenticated user
     * @throws UsernameNotFoundException if user not found in database
     */
    private userEntity getCurrentUser() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        // Validate authentication state
        if (authentication == null || !authentication.isAuthenticated() ||
                "anonymousUser".equals(authentication.getName())) {
            logger.warn("No authenticated user found in security context");
            throw new SecurityException("No authenticated user found");
        }

        String currentUsername = authentication.getName();

        // Check if we have cached user for this username
        userEntity cachedUser = userCache.get();
        String lastCachedUsername = cachedUsername.get();

        if (cachedUser != null && currentUsername.equals(lastCachedUsername)) {
            logger.debug("Returning cached user: {}", currentUsername);
            return cachedUser;
        }

        // Cache miss or username changed - fetch from database
        logger.debug("Fetching user from database: {}", currentUsername);
        userEntity user = userRepository.findByUsername(currentUsername)
                .orElseThrow(() -> new UsernameNotFoundException(
                        "User not found: " + currentUsername));

        // Update cache
        userCache.set(user);
        cachedUsername.set(currentUsername);

        return user;
    }

    /**
     * Gets the email of the currently authenticated user.
     *
     * @return Current user's email address
     * @throws SecurityException if no authenticated user
     * @throws UsernameNotFoundException if user not found
     */
    public String loggedInEmail() {
        userEntity user = getCurrentUser();
        logger.debug("Retrieved email for user: {}", user.getUsername());
        return user.getEmail();
    }

    /**
     * Gets the complete user entity of the currently authenticated user.
     *
     * @return Current user entity with all details
     * @throws SecurityException if no authenticated user
     * @throws UsernameNotFoundException if user not found
     */
    public userEntity loggedInUser() {
        return getCurrentUser();
    }

    /**
     * Gets the user ID of the currently authenticated user.
     *
     * @return Current user's unique identifier
     * @throws SecurityException if no authenticated user
     * @throws UsernameNotFoundException if user not found
     */
    public Long loggedInUserId() {
        userEntity user = getCurrentUser();
        logger.debug("Retrieved user ID: {} for user: {}", user.getUserId(), user.getUsername());
        return user.getUserId();
    }

    /**
     * Clears the thread-local cache.
     *
     * WHY: Prevents memory leaks in thread pools and ensures fresh data
     * when user context changes within the same thread.
     *
     * WHEN TO CALL: After user logout, role changes, or at request end.
     */
    public void clearCache() {
        userCache.remove();
        cachedUsername.remove();
        logger.debug("Cleared user cache for current thread");
    }

    /**
     * Checks if a user is currently authenticated.
     *
     * @return true if user is authenticated, false otherwise
     */
    public boolean isUserAuthenticated() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        return authentication != null &&
                authentication.isAuthenticated() &&
                !"anonymousUser".equals(authentication.getName());
    }
}
