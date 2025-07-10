package web.mvc;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.annotation.Commit;
import org.springframework.transaction.annotation.Transactional;
import web.mvc.domain.Board;
import web.mvc.domain.Member;
import web.mvc.repository.BoardRepository;
import web.mvc.repository.MemberRepository;

@SpringBootTest
@Transactional
@Commit
class SpringSecurityJwtApplicationTests {
  @Autowired
  private MemberRepository memberRepository;

  @Autowired
  private BoardRepository boardRepository;
  @Autowired
  private PasswordEncoder passwordEncoder;



  /**
  * 관리자 등록
  * */
  @Test
  void memberInsert() {
      // admin 계정이 이미 존재하지 않으면
      if (!memberRepository.existsById("admin")) {
          String encPwd = passwordEncoder.encode("1234");
          
          memberRepository.save(Member.builder().id("admin").pwd(encPwd)
                  .role("ROLE_ADMIN").address("오리역").name("장희정").build());
      }

  }

  /**
   * 게시물 등록
   * */
   @Test
  void boardInsert() {
       String encPwd = passwordEncoder.encode("1234");
       if (!memberRepository.existsById("kosta")) {
           Member member = memberRepository.save(Member.builder().id("kosta").pwd(encPwd)
                   .role("ROLE_ADMIN").address("오리역").name("삼순이").build());

           boardRepository.save(Board.builder().title("test 첫번째").content("test1중입니다.").member(member).build());
           boardRepository.save(Board.builder().title("test 두번째").content("test2중입니다.").member(member).build());

       }
   }

}