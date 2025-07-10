package web.mvc.security;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import web.mvc.domain.Member;
import web.mvc.repository.MemberRepository;

@Service //생성
@Slf4j
@RequiredArgsConstructor
public class CustomMemberDetailsService implements UserDetailsService {
    private final MemberRepository memberRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        log.info("username : {}" , username); //id
        //db에서 select..
       Member findMember =  memberRepository.findById(username);
       if(findMember!=null){
           log.info("찾았다....");
          return new CustomMemberDetails(findMember);
       }

        return null;
    }

}
