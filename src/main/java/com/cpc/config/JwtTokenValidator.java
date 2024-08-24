package com.cpc.config;

// Import necessary classes from the JJWT library and Jakarta Servlet API
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.util.List;

// This class defines a custom filter that validates JWT tokens in HTTP requests
public class JwtTokenValidator extends OncePerRequestFilter {

    // Override the doFilterInternal method to implement custom filtering logic
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        // Retrieve the JWT from the Authorization header of the request
        String jwt = request.getHeader(JwtConstant.JWT_HEADER);

        // Check if the JWT is present
        if (jwt != null) {
            // Remove the "Bearer " prefix from the JWT (assuming standard "Bearer" format)
            jwt = jwt.substring(7);
            try {
                // Generate a SecretKey for HMAC SHA using the secret key from JwtConstant
                SecretKey key = Keys.hmacShaKeyFor(JwtConstant.SECREATE_KEY.getBytes());

                // Parse the JWT claims using the JJWT library
                Claims claims = Jwts.parser()
                        .setSigningKey(key) // Set the secret key for verifying the JWT signature
                        .build()
                        .parseClaimsJws(jwt) // Parse the JWT to extract claims
                        .getBody();

                // Retrieve email and authorities (roles) from the JWT claims
                String email = String.valueOf(claims.get("email"));
                String authorities = String.valueOf(claims.get("authorities"));

                // Convert the comma-separated authorities string to a list of GrantedAuthority objects
                List<GrantedAuthority> auths = AuthorityUtils.commaSeparatedStringToAuthorityList(authorities);

                // Create an Authentication object with the email and authorities
                Authentication authentication = new UsernamePasswordAuthenticationToken(email, null, auths);

                // Set the authentication object in the SecurityContextHolder to mark the user as authenticated
                SecurityContextHolder.getContext().setAuthentication(authentication);
            } catch (Exception e) {
                // Handle any exceptions that occur during JWT parsing or validation
                // Log the exception (if logging is set up) and throw a BadCredentialsException
                throw new BadCredentialsException("Invalid token");
            }
        }

        // Continue the filter chain to allow the request to proceed to the next filter or endpoint
        filterChain.doFilter(request, response);
    }
}
