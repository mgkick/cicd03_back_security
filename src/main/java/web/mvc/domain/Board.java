package web.mvc.domain;

import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import java.time.LocalDateTime;

@AllArgsConstructor
@NoArgsConstructor
@Setter
@Getter
@ToString
@Entity //서버 실행시에 해당 객체로 테이블 매핑생성
@Builder
public class Board {
	@Id//pk를 해당 필드로 한다
	//@GeneratedValue(strategy = GenerationType.SEQUENCE ,generator = "board_id")
	///@SequenceGenerator(allocationSize = 1, sequenceName = "board_id" , name = "board_id")
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private Long id;//글번호
	
	private String title;//제목

	@Column(length =100)
	private String content;//내용


	@ManyToOne(fetch = FetchType.LAZY)
	@JoinColumn(name ="member_no")
	private Member member;//작성자

	@CreationTimestamp
	private LocalDateTime regDate;//등록일
	
	@UpdateTimestamp
	private LocalDateTime updateDate;//수정일
}


