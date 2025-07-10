package web.mvc.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import web.mvc.domain.Member;


public interface MemberRepository extends JpaRepository<Member, Long>{
   @Query("select m from Member m where m.id=?1") //JPQL문법
   Member duplicateCheck(String id);

   Boolean existsById(String id); //QueryMethod방식

   //username을 받아 DB 테이블에서 회원을 조회하는 메소드 작성
   Member findById(String id);////QueryMethod방식


}