package web.mvc.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import web.mvc.domain.Board;

import java.util.List;


public interface BoardRepository extends JpaRepository<Board, Long>{
   @Query("select distinct b from Board b join fetch b.member")
   //@Query("select  b from Board b join fetch b.member")
    List<Board> join();
}
