package web.mvc.advice;


import org.springframework.http.ProblemDetail;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import web.mvc.exception.MemberAuthenticationException;

import java.time.LocalDateTime;

@RestControllerAdvice
public class DefaultExceptionAdvice {
    @ExceptionHandler({MemberAuthenticationException.class})
//    public ProblemDetail signInExceptionHandle(MemberAuthenticationException e){
//        ProblemDetail problemDetail = ProblemDetail.forStatus(e.getHttpStatus().value());
//
//        problemDetail.setTitle(e.getTitle());
//        problemDetail.setDetail(e.getMessage());
//        problemDetail.setProperty("timestamp", LocalDateTime.now());
//
//        return  problemDetail;
//    }

    public ResponseEntity<?> signInExceptionHandle(MemberAuthenticationException e){
        ProblemDetail problemDetail = ProblemDetail.forStatus(e.getHttpStatus().value());

        problemDetail.setTitle(e.getTitle());
        problemDetail.setDetail(e.getMessage());
        problemDetail.setProperty("timestamp", LocalDateTime.now());

        return  ResponseEntity.status(700).body("오류");
    }






}