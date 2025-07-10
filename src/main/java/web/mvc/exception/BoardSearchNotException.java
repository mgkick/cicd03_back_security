package web.mvc.exception;

import lombok.Getter;
import org.springframework.http.HttpStatus;

@Getter
public class BoardSearchNotException extends  RuntimeException{
    private String message;
    private HttpStatus httpStatus;
    private  String title;
    public BoardSearchNotException(String message, String title){
        this(message , title, HttpStatus.EXPECTATION_FAILED);//417
    }
    public BoardSearchNotException(String message, String title, HttpStatus httpStatus){
        this.message=message;
        this.title=title;
        this.httpStatus=httpStatus;
    }
}
