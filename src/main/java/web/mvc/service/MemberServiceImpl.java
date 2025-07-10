package web.mvc.service;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import web.mvc.domain.Member;
import web.mvc.exception.MemberAuthenticationException;
import web.mvc.repository.MemberRepository;

@Service
@Slf4j
public class MemberServiceImpl implements  MemberService{

    @Autowired
    private MemberRepository memberRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Transactional(readOnly = true)
    @Override
    public String duplicateCheck(String id) {
        Member member = memberRepository.duplicateCheck(id);
        System.out.println("member 정보 = " + member);
        
        if(member==null) return "사용가능합니다.";
        else return "중복입니다.";
        //return member;

    }


    @Transactional
    @Override
    public void signUp(Member member) {
       if(memberRepository.existsById(member.getId())){
           throw new MemberAuthenticationException("아이디중복입니다.","Duplicate ID");
       }

       //비번 암호화
       String encPwd =  passwordEncoder.encode(member.getPwd());
       member.setPwd(encPwd);

        //ROLE설정
        member.setRole("ROLE_USER");

         Member savedMember = memberRepository.save(member);
         log.info("saveMember = {}" , savedMember);

    }
}
