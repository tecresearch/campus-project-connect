package com.cpc.config;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;

import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;

// This is a configuration class for the Spring Security configuration
@Configuration
// This annotation enables the Spring Security configuration defined in this class
@EnableWebSecurity
public class AppConfig {

    // This bean defines the SecurityFilterChain, which configures how HTTP security is handled in the application
    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        // Configure session management to be stateless, indicating that the application does not use HTTP sessions
        http.sessionManagement(Management -> Management.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                // Define authorization rules: requests to paths under "/api/**" must be authenticated
                .authorizeHttpRequests(Authorize -> Authorize.requestMatchers("/api/**").authenticated()
                        // All other requests are permitted without authentication
                        .anyRequest().permitAll())
                // Add a custom JWT token validator filter before the basic authentication filter in the security filter chain
                .addFilterBefore(new JwtTokenValidator(), BasicAuthenticationFilter.class)
                // Disable CSRF protection since it is not needed for stateless APIs
                .csrf(csrf -> csrf.disable())
                // Enable CORS with a custom configuration source
                .cors(cors -> cors.configurationSource(corsConfigrationSource()));

        // Build and return the configured SecurityFilterChain instance
        return http.build();
    }

    // This method defines a custom CORS configuration source to allow requests from specific origins
    private CorsConfigurationSource corsConfigrationSource() {

        // Return a new CORS configuration source, which is used to provide a CORS configuration dynamically
        return new CorsConfigurationSource() {
            @Override
            public CorsConfiguration getCorsConfiguration(HttpServletRequest request) {
                // Create a new CORS configuration object
                CorsConfiguration cfg = new CorsConfiguration();
                // Allow requests from these specific origins (localhost on different ports for local development)
                cfg.setAllowedOrigins(Arrays.asList(
                        "http://localhost:3000",
                        "http://localhost:5173",
                        "http://localhost:4200"
                ));

                // Allow all HTTP methods (GET, POST, PUT, DELETE, etc.)
                cfg.setAllowedMethods(Collections.singletonList("*"));
                // Allow credentials (cookies, authorization headers, etc.) to be sent in requests
                cfg.setAllowCredentials(true);
                // Allow all headers to be included in requests
                cfg.setAllowedHeaders(Collections.singletonList("*"));
                // Expose the "Authorization" header in responses so clients can read it
                cfg.setExposedHeaders(Arrays.asList("Authorization"));
                // Set the maximum age for the CORS configuration to be cached by clients, in seconds
                cfg.setMaxAge(3600L);

                // Return the configured CORS configuration
                return cfg;
            }
        };
    }

    // This bean defines a password encoder using the BCrypt hashing algorithm, used for encoding user passwords
    @Bean
    PasswordEncoder passwordEncoder() {
        // Return a new BCryptPasswordEncoder instance
        return new BCryptPasswordEncoder();
    }

}
