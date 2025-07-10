package web.mvc.security;

import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import web.mvc.domain.Member;

import java.util.ArrayList;
import java.util.Collection;

@Slf4j
public class CustomMemberDetails implements UserDetails {

    @Getter
    private final Member member;

    public CustomMemberDetails(Member member){
        this.member= member;
        log.info("member ={}" , member);
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        log.info("getAuthorities .....");
        Collection<GrantedAuthority> collection = new ArrayList<>();

       /* collection.add(new GrantedAuthority() {
            @Override
            public String getAuthority() {
                return member.getRole();
            }
        });*/

        collection.add(()->member.getRole());

        return collection;
    }

    @Override
    public String getPassword() {
        log.info("getPassword .....");
        return member.getPwd();
    }

    @Override
    public String getUsername() {
        log.info("getUsername...");
        return member.getId(); //id
    }

    @Override
    public boolean isAccountNonExpired() {
        log.info("isAccountNonExpired...");
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        log.info("isAccountNonLocked...");
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        log.info("isCredentialsNonExpired...");
        return true;
    }

    @Override
    public boolean isEnabled() {
        log.info("isEnabled...");
        return true;
    }
}
