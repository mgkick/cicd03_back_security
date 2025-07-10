package web.mvc.jwt;

import com.google.gson.Gson;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import web.mvc.domain.Member;
import web.mvc.security.CustomMemberDetails;

import java.io.IOException;
import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

@Slf4j
public class LoginFilter extends UsernamePasswordAuthenticationFilter {
    private final AuthenticationManager authenticationManager;

    //JWTUtil 주입
    private final JWTUtil jwtUtil;

    public LoginFilter(AuthenticationManager authenticationManager , JWTUtil jwtUtil) {
        this.authenticationManager = authenticationManager;
        this.jwtUtil = jwtUtil;;
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {

				//클라이언트 요청에서 username, password 추출
        String username = super.obtainUsername(request); //id
        String password = obtainPassword(request);

         log.info("username {} " , username);
        log.info("password {} " , password);
        //스프링 시큐리티에서 username과 password를 검증하기 위해서는 token에 담아야 함
        UsernamePasswordAuthenticationToken authToken =
                new UsernamePasswordAuthenticationToken(username, password, null);

        //token에 담은 검증을 위한 AuthenticationManager로 전달
        Authentication authentication = authenticationManager.authenticate(authToken);

        log.info("authentication {} " , authentication);
        return authentication;
    }

    //로그인 성공시 실행하는 메소드 (여기서 JWT를 발급하면 됨)
    @Override
    protected void successfulAuthentication(HttpServletRequest request,
                                            HttpServletResponse response,
                                            FilterChain chain,
                                            Authentication authentication) throws  IOException{
        response.setContentType("text/html;charset=UTF-8");
       log.info("로그인 성공 ......");
        //UserDetailsS
        CustomMemberDetails customMemberDetails = (CustomMemberDetails) authentication.getPrincipal();

        String username = customMemberDetails.getUsername();//아이디

        Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
        Iterator<? extends GrantedAuthority> iterator = authorities.iterator();
        GrantedAuthority auth = iterator.next();
        String role = auth.getAuthority(); //ROLE_USER or ROLE_ADMIN

        //토큰생성과정...
        String token = jwtUtil.createJwt(
                customMemberDetails.getMember(), role, 1000L*60*10L);//1초*60*10 10분

        //응답할 헤더를 설정
        response.addHeader("Authorization", "Bearer " + token);

        Map<String, Object> map = new HashMap<>();
       Member   member= customMemberDetails.getMember();
        map.put("memberNo",member.getMemberNo() );
        map.put("id", member.getId());
        map.put("name", member.getName());
        map.put("address", member.getAddress());

        Gson gson= new Gson();
        String arr = gson.toJson(map);
        response.getWriter().print(arr);
    }
    //로그인 실패시 실행하는 메소드
    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response,
                                              AuthenticationException failed) throws IOException {

        response.setContentType("text/html;charset=UTF-8");

        log.info("로그인 실패... ......");
        //로그인 실패시 401 응답 코드 반환
        response.setStatus(401);

        Map<String, Object> map = new HashMap<>();
        map.put("errMsg","정보를 다시 확인해주세요.");
        Gson gson= new Gson();
        String arr = gson.toJson(map);
        response.getWriter().print(arr);
    }
}