package web.mvc.service;


import web.mvc.domain.Member;

public interface MemberService {

    String duplicateCheck(String id);

    /**
     * 가입
     * */
     void  signUp(Member member);



}
