package web.mvc.jwt;

import io.jsonwebtoken.Jwts;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import web.mvc.domain.Member;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Date;

@Component
@Slf4j
public class JWTUtil {

    private SecretKey secretKey;

    public JWTUtil(@Value("${spring.jwt.secret}")String secret) {

        secretKey = new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), Jwts.SIG.HS256.key().build().getAlgorithm());
    }

    public String getUsername(String token) {
         log.info("getUsername(String token)  call");
        String re = Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload().get("username", String.class);
        log.info("getUsername(String token)  re = {}" ,re);
        return re;
    }

    public String getId(String token) {
        log.info("getId(String token)  call");
        String re = Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload().get("id", String.class);
        log.info("getIds(String token)  re = {}" ,re);
        return re;
    }

    public String getRole(String token) {
        log.info("getRole(String token)  call");
        String re = Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload().get("role", String.class);
        log.info("getRole(String token)  re = {} " , re);
        return re;
    }

    public Boolean isExpired(String token) {
        log.info("isExpired(String token)  call");
        boolean re = Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload().getExpiration().before(new Date());
        log.info("isExpired(String token)  re  = {}",re);
        return re;
    }

    //public String createJwt(String username, String role, Long expiredMs) {
    public String createJwt(Member member, String role, Long expiredMs) {
        log.info("createJwt  call");
        return Jwts.builder()
                .claim("username", member.getName()) //이름
                .claim("id", member.getId()) //아이디
                .claim("role", role)
                .issuedAt(new Date(System.currentTimeMillis())) //현재로그인된 시간
                .expiration(new Date(System.currentTimeMillis() + expiredMs))
                .signWith(secretKey)
                .compact();
    }
}