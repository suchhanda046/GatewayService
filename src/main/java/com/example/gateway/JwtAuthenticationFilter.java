package com.example.gateway;

import io.github.cdimascio.dotenv.Dotenv;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Parser;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.cloud.gateway.filter.factory.GatewayFilterFactory;
import org.springframework.http.HttpStatus;
import io.jsonwebtoken.Claims;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
@Component
public class JwtAuthenticationFilter extends AbstractGatewayFilterFactory<JwtAuthenticationFilter.Config> {
//    private final Key key;
    Dotenv dotenv = Dotenv.load();
    String jwtSecret =  dotenv.get("JWT_SECRET");
    private final SecretKey secretKey = Keys.hmacShaKeyFor(jwtSecret.getBytes());

    @Override
    public GatewayFilter apply(Config config) {

        return (exchange, chain) -> {
            String authHeader = exchange.getRequest().getHeaders().getFirst("Authorization");
            if (authHeader == null || !authHeader.startsWith("Bearer ")) {
                exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
                return exchange.getResponse().setComplete();
            }
            try{
                String token = authHeader.replace("Bearer ", "");
                Claims claims = validateSecretToken(token);
                String userId = claims.getSubject();
                exchange.getRequest().mutate().header("userId", userId).build();
            }catch (Exception e){
                exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            }

            return chain.filter(exchange);
        };
    }
    public static class Config {
        // You can add config properties here later if needed
    }
    public JwtAuthenticationFilter() {
        super(Config.class);
    }
    public Claims validateSecretToken(String token){
        JwtParser parse =  Jwts.parser().verifyWith(secretKey).build();
        return parse.parseSignedClaims(token).getPayload();
    }

}
