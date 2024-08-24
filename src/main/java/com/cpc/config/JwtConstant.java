package com.cpc.config;

// This class defines constants used for JWT authentication and authorization
public class JwtConstant {

    // Secret key used for signing and verifying JWTs
    // This should be a strong and unique secret key; it is critical for ensuring the security of JWT tokens
    public static final String SECREATE_KEY = "sdjifdsighuehfndujbdvf whf we wieorif euirhwfohgdiuhfhrtuiw";

    // The HTTP header key used to pass the JWT in HTTP requests
    // "Authorization" is the standard header used to pass authentication credentials in HTTP requests
    public static final String JWT_HEADER = "Authorization";
}
