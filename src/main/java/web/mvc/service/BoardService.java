package web.mvc.service;



import web.mvc.domain.Board;
import web.mvc.dto.BoardReq;
import web.mvc.dto.BoardRes;
import web.mvc.exception.BoardSearchNotException;
import web.mvc.exception.DMLException;

import java.util.List;

public interface BoardService {
    Board findBoard(Long id) throws BoardSearchNotException;

    List<BoardRes> findAllBoard()throws BoardSearchNotException ;
     Board addBoard(BoardReq board);

    Board updateBoard(Long id,BoardReq board)throws DMLException; ;

     String deleteBoard(Long id);
}
