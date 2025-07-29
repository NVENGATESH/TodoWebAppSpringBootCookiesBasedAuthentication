package com.nisahnth.ToDoListWebApp.security.jwt;

import com.nisahnth.ToDoListWebApp.security.services.UserDetailsImpl;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Component;
import org.springframework.web.util.WebUtils;

import javax.crypto.SecretKey;
import java.security.Key;
import java.util.Date;

@Component
public class JwtUtils {
    private static final Logger logger = LoggerFactory.getLogger(JwtUtils.class);

    @Value("${spring.app.jwtSecret}")
    private String jwtSecret;

    @Value("${spring.app.jwtExpirationMs}")
    private int jwtExpirationMs;

    @Value("${spring.app.jwtCookieName}")
    private String jwtCookie;

    public String getJwtFromCookies(HttpServletRequest request) {
        Cookie cookie = WebUtils.getCookie(request, jwtCookie);
        if (cookie != null) {
            return cookie.getValue();
        } else {
            return null;
        }
    }

    public ResponseCookie generateJwtCookie(UserDetailsImpl userPrincipal) {
        String jwt = generateTokenFromUsername(userPrincipal.getUsername());
        ResponseCookie cookie = ResponseCookie.from(jwtCookie, jwt)
                // .path("/api")
                // .maxAge(24 * 60 * 60)
                // .httpOnly(true)//browser to server send pannum true kudurha
                // .secure(true)
                // .build();
                  .path("/") // ✅ allow entire site
        .maxAge(24 * 60 * 60)
        .httpOnly(true)
        .secure(true) // ❗ must be true on HTTPS like Render
        .sameSite("None") // ✅ allow cross-site cookie from frontend
        .build();
        return cookie;
    }


//    ResponseCookie cookie = ResponseCookie.from("AUTH-TOKEN", token)
//            .httpOnly(true)
//            .secure(false) // change to true in HTTPS
//            .path("/")
//            .maxAge(24 * 60 * 60) // 1 day
//            .sameSite("Strict")
//            .build();

    public ResponseCookie getCleanJwtCookie() {
        ResponseCookie cookie = ResponseCookie.from(jwtCookie, null)
                // .path("/")
                // .maxAge(0) // delete cookie
                // .httpOnly(true)
                // .build();
                  .path("/")
        .maxAge(0)
        .httpOnly(true)
        .secure(true)
        .sameSite("None")
        .build();
        return cookie;
    }

//    @PostMapping("/logout")
//    public ResponseEntity<?> logout(HttpServletResponse response) {
//        ResponseCookie cookie = ResponseCookie.from("AUTH-TOKEN", "")
//                .httpOnly(true)
//                .secure(false)
//                .path("/")
//                .maxAge(0) // expire immediately
//                .build();
//
//        response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());
//        return ResponseEntity.ok(Map.of("message", "Logged out"));
//    }


    public String generateTokenFromUsername(String username) {
        return Jwts.builder()
                .subject(username)
                .issuedAt(new Date())
                .expiration(new Date((new Date()).getTime() + jwtExpirationMs))
                .signWith(key())
                .compact();
    }

    public String getUserNameFromJwtToken(String token) {
        return Jwts.parser()
                        .verifyWith((SecretKey) key())
                .build().parseSignedClaims(token)
                .getPayload().getSubject();
    }

    private Key key() {
        return Keys.hmacShaKeyFor(Decoders.BASE64.decode(jwtSecret));
    }

    public boolean validateJwtToken(String authToken) {
        try {
            System.out.println("Validate");
            Jwts.parser().verifyWith((SecretKey) key()).build().parseSignedClaims(authToken);
            return true;
        } catch (MalformedJwtException e) {
            logger.error("Invalid JWT token: {}", e.getMessage());
        } catch (ExpiredJwtException e) {
            logger.error("JWT token is expired: {}", e.getMessage());
        } catch (UnsupportedJwtException e) {
            logger.error("JWT token is unsupported: {}", e.getMessage());
        } catch (IllegalArgumentException e) {
            logger.error("JWT claims string is empty: {}", e.getMessage());
        }
        return false;
    }
}
