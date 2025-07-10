package web.mvc.dto;



import lombok.*;
import web.mvc.domain.Board;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class BoardRes {
    private Long id;//글번호
    private String title;//제목
    private String content;//내용
    private MemberRes member;//작성자
    private String regDate;//등록일

    public BoardRes(Board board) {
         id = board.getId();
         title=board.getTitle();
         content=board.getContent();
         regDate=board.getRegDate().toLocalDate().toString();
         member=new MemberRes(board.getMember().getMemberNo(),
                 board.getMember().getId() , board.getMember().getName());

    }

    /*public BoardRes toBoardRes(Board board){
       return BoardRes.builder()
               .id(board.getId())
               .title(board.getTitle())
               .content(board.getContent())
               .regDate(board.getRegDate().toString())
               .member(new MemberRes(board.getMember().getId() , board.getMember().getName()))
               .build();
   }*/
}
