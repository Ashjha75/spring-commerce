package com.example.springcommerce.utils.Security;

import com.example.springcommerce.utils.Security.Service.UserDetailsServiceImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.time.Duration;
import java.util.Arrays;

/**
 * Comprehensive Spring Security configuration for JWT-based authentication.
 * <p>
 * WHY: Centralized security configuration ensures consistent security policies
 * across the entire application and provides defense in depth.
 * <p>
 * WHAT: Configures authentication, authorization, session management,
 * CORS, security headers, and exception handling.
 * <p>
 * HOW: Uses Spring Security's builder pattern to configure security filters,
 * authentication providers, and security policies declaratively.
 * <p>
 * INTERVIEW POINTS:
 * - Spring Security architecture and filter chain
 * - Stateless vs stateful session management
 * - CORS and its security implications
 * - Security headers and their purposes
 * - Authentication vs Authorization
 */
@Configuration
@EnableWebSecurity
public class WebSecurityConfig {

    private final AuthEntryPointJwt unauthorizedHandler;
    private final UserDetailsServiceImpl userDetailsService;


    public WebSecurityConfig(AuthEntryPointJwt unauthorizedHandler, UserDetailsServiceImpl userDetailsService) {
        this.unauthorizedHandler = unauthorizedHandler;
        this.userDetailsService = userDetailsService;
    }

    /**
     * Creates JWT authentication filter bean.
     * <p>
     * WHY: Filter needs to be a Spring-managed bean for dependency injection
     * and proper lifecycle management.
     */
    @Bean
    public AuthTokenFilter authenticationJwtTokenFilter() {
        return new AuthTokenFilter();
    }

    /**
     * Configures DAO authentication provider with user details service and password encoder.
     * <p>
     * WHY: Spring Security needs to know how to authenticate users
     * (load user details and verify passwords).
     *
     * @return Configured authentication provider
     */
    @Bean
    public DaoAuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
        authProvider.setUserDetailsService(userDetailsService);
        authProvider.setPasswordEncoder(passwordEncoder());
        return authProvider;
    }

    /**
     * Password encoder bean using BCrypt hashing algorithm.
     * <p>
     * WHY: Passwords should never be stored in plain text.
     * BCrypt is a strong, adaptive hashing function designed for passwords.
     * <p>
     * INTERVIEW POINTS:
     * - Why BCrypt over MD5/SHA1
     * - Salt and its importance
     * - Adaptive hashing and work factors
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(12); // Strength parameter for security
    }

    /**
     * Authentication manager bean for programmatic authentication.
     *
     * @param authConfig Authentication configuration
     * @return AuthenticationManager instance
     */
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authConfig) throws Exception {
        return authConfig.getAuthenticationManager();
    }

    /**
     * CORS configuration for cross-origin requests.
     * <p>
     * WHY: Web applications often need to make requests from different domains.
     * CORS policy controls which origins can access the API.
     * <p>
     * SECURITY CONSIDERATIONS:
     * - Don't use wildcards (*) in production
     * - Specify exact allowed origins
     * - Limit allowed methods and headers
     *
     * @return CORS configuration source
     */
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();

        // Configure allowed origins - CHANGE IN PRODUCTION!
        configuration.setAllowedOriginPatterns(Arrays.asList("http://localhost:*", "https://yourdomain.com"));

        // Allowed HTTP methods
        configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS"));

        // Allowed headers
        configuration.setAllowedHeaders(Arrays.asList(
                "Authorization", "Content-Type", "X-Requested-With", "Accept",
                "Origin", "Access-Control-Request-Method", "Access-Control-Request-Headers"
        ));

        // Allow credentials (cookies, authorization headers)
        configuration.setAllowCredentials(true);

        // Preflight cache duration
        configuration.setMaxAge(Duration.ofHours(1));

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);

        return source;
    }

    /**
     * Main security filter chain configuration.
     * <p>
     * WHY: This is the heart of Spring Security configuration where
     * all security policies are defined and enforced.
     *
     * @param http HttpSecurity configuration object
     * @return Configured SecurityFilterChain
     */
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                // Disable CSRF for stateless API
                .csrf(csrf -> csrf.disable())

                // Enable CORS with our configuration
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))

                // Configure exception handling
                .exceptionHandling(exception ->
                        exception.authenticationEntryPoint(unauthorizedHandler))

                // Stateless session management for JWT
                .sessionManagement(session ->
                        session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))

                // Configure URL-based authorization
                .authorizeHttpRequests(auth -> auth
                        // Public endpoints
                        .requestMatchers("/api/auth/**").permitAll()
                        .requestMatchers("/api/public/**").permitAll()

                        // Documentation endpoints
                        .requestMatchers("/v3/api-docs/**").permitAll()
                        .requestMatchers("/swagger-ui/**").permitAll()
                        .requestMatchers("/swagger-resources/**").permitAll()

                        // Static resources
                        .requestMatchers("/images/**").permitAll()
                        .requestMatchers("/css/**", "/js/**", "/favicon.ico").permitAll()

                        // Health check endpoints
                        .requestMatchers("/actuator/health").permitAll()

                        // Error handling
                        .requestMatchers("/error").permitAll()

                        // All other requests require authentication
                        .anyRequest().authenticated()
                )

                // Security headers configuration
                .headers(headers -> headers
                        // Prevent clickjacking attacks
                        .frameOptions().deny()

                        // Prevent MIME type sniffing
                        .contentTypeOptions().and()

                        // HSTS for HTTPS enforcement
                        .httpStrictTransportSecurity(hstsConfig ->
                                hstsConfig
                                        .maxAgeInSeconds(31536000)     // 1 year
                                        .includeSubdomains(true)
                                        .preload(true)
                        )

                        // Content Security Policy
                        .contentSecurityPolicy("default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'")
                );

        // Set custom authentication provider
        http.authenticationProvider(authenticationProvider());

        // Add JWT filter before username/password authentication filter
        http.addFilterBefore(authenticationJwtTokenFilter(), UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    /**
     * Customize web security to ignore certain paths completely.
     * <p>
     * WHY: Some resources don't need any security processing at all
     * for performance reasons.
     */
    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        return (web -> web.ignoring().requestMatchers(
                "/v2/api-docs",
                "/configuration/ui",
                "/swagger-resources/**",
                "/configuration/security",
                "/swagger-ui.html",
                "/webjars/**",
                "/static/**"
        ));
    }
}
