package web.mvc.controller;

import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@Slf4j
public class TestController {


    @GetMapping("/test")
    public ResponseEntity<String> test() {
        return ResponseEntity
                .ok()
                .contentType(MediaType.valueOf("text/plain;charset=UTF-8"))  //
                .body("CI/CD GitHub Action - spring Security OK 연동하기! 연동연동   자바테스트 BACK FOR REACT성공!0711 1638 신난다");
    }
}
