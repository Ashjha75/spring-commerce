package com.example.springcommerce.utils.Security.Service;

import com.example.springcommerce.entity.userEntity;
import com.example.springcommerce.repository.userRepo;
import jakarta.transaction.Transactional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

/**
 * Service implementation for loading user-specific data for authentication.
 *
 * WHY: Spring Security requires a UserDetailsService implementation to
 * load user information during authentication process.
 *
 * WHAT: Converts application user entities to Spring Security UserDetails
 * objects that contain authentication and authorization information.
 *
 * HOW: Implements UserDetailsService interface, loads user from database,
 * and wraps it in UserDetailsImpl for Spring Security compatibility.
 *
 * INTERVIEW POINTS:
 * - UserDetailsService vs UserDetails - interface vs implementation
 * - Why Spring Security needs this abstraction layer
 * - Transaction boundaries and their importance
 * - Database connection management in authentication
 */
@Service
public class UserDetailsServiceImpl implements UserDetailsService {

    private static final Logger logger = LoggerFactory.getLogger(UserDetailsServiceImpl.class);

    private final userRepo userRepository;

    /**
     * Constructor injection for repository dependency.
     *
     * WHY: Constructor injection is preferred over field injection
     * for better testability and immutability.
     */
    @Autowired
    public UserDetailsServiceImpl(userRepo userRepository) {
        this.userRepository = userRepository;
    }

    /**
     * Loads user details by username for Spring Security authentication.
     *
     * WHY: Spring Security calls this method during authentication to
     * retrieve user information and validate credentials.
     *
     * WHAT: Retrieves user from database and converts to UserDetails format
     * that includes username, password, authorities, and account status.
     *
     * HOW:
     * 1. Validate input username
     * 2. Query database for user
     * 3. Handle user not found scenario
     * 4. Convert user entity to UserDetails
     *
     * TRANSACTION: Read-only transaction for performance optimization
     * and to ensure consistent data read.
     *
     * @param username the username identifying the user whose data is required
     * @return UserDetails a fully populated user record (never null)
     * @throws UsernameNotFoundException if the user could not be found
     */
    @Override
    @Transactional(readOnly = true) // Read-only optimization
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        // Input validation
        if (!StringUtils.hasText(username)) {
            logger.warn("Attempted to load user with empty or null username");
            throw new UsernameNotFoundException("Username cannot be null or empty");
        }

        String trimmedUsername = username.trim();
        logger.debug("Loading user details for username: {}", trimmedUsername);

        // Query database for user
        userEntity user = userRepository.findByUsername(trimmedUsername)
                .orElseThrow(() -> {
                    logger.warn("User not found with username: {}", trimmedUsername);
                    return new UsernameNotFoundException("User not found with username: " + trimmedUsername);
                });

        logger.debug("Successfully loaded user: {} with {} authorities",
                user.getUsername(), user.getRoles().size());

        // Convert to Spring Security UserDetails
        return UserDetailsImpl.build(user);
    }
}
