package com.example.springcommerce.controller;

import com.example.springcommerce.entity.roleEntity;
import com.example.springcommerce.entity.userEntity;
import com.example.springcommerce.repository.RoleRepo;
import com.example.springcommerce.repository.userRepo;
import com.example.springcommerce.utils.Enums.AppRoles;
import com.example.springcommerce.utils.Security.DTO.MessageResponse;
import com.example.springcommerce.utils.Security.DTO.SignupRequest;
import com.example.springcommerce.utils.Security.DTO.UserInfoRequest;
import com.example.springcommerce.utils.Security.DTO.UserInfoResponse;
import com.example.springcommerce.utils.Security.JwtUtils;
import com.example.springcommerce.utils.Security.Service.UserDetailsImpl;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.*;
import java.util.stream.Collectors;

/**
 * Controller for handling authentication and user registration.
 */
@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final AuthenticationManager authenticationManager;

    @Autowired
    JwtUtils jwtUtils;

    @Autowired
    private userRepo userRepo;

    @Autowired
    private RoleRepo roleRepo;

    @Autowired
    private PasswordEncoder encoder;

    public AuthController(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }

    /**
     * Authenticates a user and returns a JWT token.
     *
     * @param userInfoRequest the user info request containing username and password
     * @return a ResponseEntity containing the user info response with JWT token
     */
    @PostMapping("/signin")
    public ResponseEntity<?> authenticateUser(@RequestBody UserInfoRequest userInfoRequest) {
        Authentication authentication;

        try {
            authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(userInfoRequest.getUsername(), userInfoRequest.getPassword())
            );
        } catch (AuthenticationException e) {
            Map<String, Object> map = new HashMap<>();
            map.put("message", "Invalid username or password");
            map.put("status", false);
            return new ResponseEntity<>(map, HttpStatus.NOT_FOUND);
        }

        SecurityContextHolder.getContext().setAuthentication(authentication);
        UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
        String jwt = jwtUtils.generateTokenFromUsername(userDetails);

        List<String> roles = userDetails.getAuthorities().stream()
                .map(item -> item.getAuthority())
                .collect(Collectors.toList());

        UserInfoResponse response = new UserInfoResponse(userDetails.getId(), jwt, userDetails.getUsername(), roles);

        return ResponseEntity.ok(response);
    }

    /**
     * Registers a new user.
     *
     * @param signupRequest the signup request containing user details
     * @return a ResponseEntity containing a message response
     */
    @PostMapping("/signup")
    public ResponseEntity<?> registerUser(@Valid @RequestBody SignupRequest signupRequest) {
        if (userRepo.existsByUsername(signupRequest.getUsername())) {
            return ResponseEntity.badRequest().body(new MessageResponse("Username is already taken!"));
        }
        if (userRepo.existsByEmail(signupRequest.getEmail())) {
            return ResponseEntity.badRequest().body(new MessageResponse("Email is already in use!"));
        }

        // Create new user account
        userEntity user = new userEntity(signupRequest.getUsername(), signupRequest.getEmail(), encoder.encode(signupRequest.getPassword()));
        Set<String> strRoles = signupRequest.getRole();
        Set<roleEntity> roles = new HashSet<>();

        if (strRoles == null) {
            roleEntity userRole = roleRepo.findByRoleName(AppRoles.ROLE_USER)
                    .orElseThrow(() -> new RuntimeException("Role is not found"));
            roles.add(userRole);
        } else {
            strRoles.forEach(role -> {
                switch (role) {
                    case "admin":
                        roleEntity adminRole = roleRepo.findByRoleName(AppRoles.ROLE_ADMIN)
                                .orElseThrow(() -> new RuntimeException("Role is not found"));
                        roles.add(adminRole);
                        break;

                    case "seller":
                        roleEntity sellerRole = roleRepo.findByRoleName(AppRoles.ROLE_SELLER)
                                .orElseThrow(() -> new RuntimeException("Role is not found"));
                        roles.add(sellerRole);
                        break;

                    default:
                        roleEntity userRole = roleRepo.findByRoleName(AppRoles.ROLE_USER)
                                .orElseThrow(() -> new RuntimeException("Role is not found"));
                        roles.add(userRole);
                        break;
                }
            });
        }
        user.setRoles(roles);
        userRepo.save(user);

        return ResponseEntity.ok(new MessageResponse("User registered successfully!"));
    }
}