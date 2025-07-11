package web.mvc;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.annotation.Commit;
import org.springframework.test.annotation.Rollback;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.dao.DataIntegrityViolationException;

import web.mvc.domain.Board;
import web.mvc.domain.Member;
import web.mvc.repository.BoardRepository;
import web.mvc.repository.MemberRepository;

import lombok.extern.slf4j.Slf4j;

import java.util.Arrays;
import java.util.List;

import static org.assertj.core.api.Assertions.*;

@SpringBootTest
@Transactional
@Slf4j
class SpringSecurityJwtApplicationTests {

    @Autowired
    private MemberRepository memberRepository;

    @Autowired
    private BoardRepository boardRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @BeforeEach
    void setUp() {
        log.info("=== 테스트 시작 ===");
    }

    /**
     * 관리자 등록 테스트
     */
    @Test
    @DisplayName("관리자 계정 등록")
    @Commit
    void memberInsert() {
        log.info("관리자 등록 테스트 시작");

        // admin 계정이 이미 존재하지 않으면
        if (!memberRepository.existsById("admin")) {
            String encPwd = passwordEncoder.encode("1234");

            Member adminMember = memberRepository.save(
                    Member.builder()
                            .id("admin")
                            .pwd(encPwd)
                            .role("ROLE_ADMIN")
                            .address("오리역")
                            .name("김문기")
                            .build()
            );

            assertThat(adminMember).isNotNull();
            assertThat(adminMember.getId()).isEqualTo("admin");
            assertThat(adminMember.getRole()).isEqualTo("ROLE_ADMIN");

            log.info("관리자 등록 성공 - ID: {}, 이름: {}", adminMember.getId(), adminMember.getName());
        } else {
            log.info("관리자 계정이 이미 존재합니다.");
        }
    }

    /**
     * 게시물 등록 테스트
     */
    @Test
    @DisplayName("게시물 등록")
    @Commit
    void boardInsert() {
        log.info("게시물 등록 테스트 시작");

        String encPwd = passwordEncoder.encode("1234");

        if (!memberRepository.existsById("kosta")) {
            Member member = memberRepository.save(
                    Member.builder()
                            .id("kosta")
                            .pwd(encPwd)
                            .role("ROLE_ADMIN")
                            .address("오리역")
                            .name("삼식이")
                            .build()
            );

            Board board1 = boardRepository.save(
                    Board.builder()
                            .title("test 첫번째")
                            .content("test1중입니다.")
                            .member(member)
                            .build()
            );

            Board board2 = boardRepository.save(
                    Board.builder()
                            .title("test 두번째")
                            .content("test2중입니다.")
                            .member(member)
                            .build()
            );

            assertThat(board1).isNotNull();
            assertThat(board2).isNotNull();
            assertThat(board1.getTitle()).isEqualTo("test 첫번째");
            assertThat(board2.getTitle()).isEqualTo("test 두번째");

            log.info("게시물 등록 성공 - 게시물 1: {}, 게시물 2: {}",
                    board1.getTitle(), board2.getTitle());
        } else {
            log.info("kosta 계정이 이미 존재합니다.");
        }
    }

    /**
     * 패스워드 암호화 테스트
     */
    @Test
    @DisplayName("암호화 test")
    void passwordTest() {
        log.info("패스워드 암호화 테스트 시작");

        String rawPassword = "8253jang"; // 평문

        // 비밀번호 인코딩
        String encodedPassword = passwordEncoder.encode(rawPassword); // 평문 -> 암호화
        log.info("encodedPassword = {}", encodedPassword);

        // 비밀번호 매칭 확인
        boolean isPasswordMatch = passwordEncoder.matches(rawPassword, encodedPassword);
        log.info("Password match : {}", isPasswordMatch);

        // 검증
        assertThat(encodedPassword).isNotNull();
        assertThat(encodedPassword).isNotEqualTo(rawPassword);
        assertThat(isPasswordMatch).isTrue();

        log.info("패스워드 암호화 테스트 완료");
    }

    /**
     * 사용자 등록 테스트 - 고유 ID 생성 방식
     */
    @Test
    @DisplayName("일반 사용자 계정 등록")
    @Commit
    void userRegistrationTest() {
        log.info("사용자 등록 테스트 시작");

        // Given: 유니크한 테스트 데이터 준비 (타임스탬프 기반)
        String timestamp = String.valueOf(System.currentTimeMillis());
        String userId = "testuser_" + timestamp;
        String rawPassword = "userpass123!";
        String userName = "김짱구";
        String userAddress = "서울시 서초구";
        String userRole = "ROLE_USER";

        // 기존 사용자 존재 여부 확인
        boolean userExists = memberRepository.existsById(userId);
        assertThat(userExists).isFalse();

        // When: 비밀번호 암호화 및 사용자 등록
        String encodedPassword = passwordEncoder.encode(rawPassword);
        log.info("사용자 비밀번호 암호화 완료: {}", encodedPassword.substring(0, 20) + "...");

        Member savedMember = memberRepository.save(
                Member.builder()
                        .id(userId)
                        .pwd(encodedPassword)
                        .role(userRole)
                        .address(userAddress)
                        .name(userName)
                        .build()
        );

        // Then: 등록 결과 검증
        assertThat(savedMember).isNotNull();
        assertThat(savedMember.getId()).isEqualTo(userId);
        assertThat(savedMember.getName()).isEqualTo(userName);
        assertThat(savedMember.getRole()).isEqualTo(userRole);
        assertThat(savedMember.getAddress()).isEqualTo(userAddress);

        // 비밀번호 매칭 검증
        boolean isPasswordMatch = passwordEncoder.matches(rawPassword, savedMember.getPwd());
        assertThat(isPasswordMatch).isTrue();

        // DB에서 실제 저장 확인 (직접 Member 객체 반환)
        Member foundMember = memberRepository.findById(userId);
        assertThat(foundMember).isNotNull();
        assertThat(foundMember.getName()).isEqualTo(userName);

        log.info("사용자 등록 성공 - ID: {}, 이름: {}, 권한: {}",
                savedMember.getId(), savedMember.getName(), savedMember.getRole());
    }

    /**
     * 사용자 등록 예외 처리 테스트
     */
    @Test
    @DisplayName("중복 ID 등록 시 예외 처리")
    @Rollback
    void duplicateUserRegistrationTest() {
        log.info("중복 ID 등록 예외 처리 테스트 시작");

        // Given: 고유한 ID로 첫 번째 사용자 생성 및 저장
        String baseId = "duplicate_test_" + System.currentTimeMillis();
        Member firstUser = createTestUser(baseId, "pass1!", "사용자1", "주소1");

        // When: 첫 번째 사용자 정상 등록
        Member savedUser = memberRepository.save(firstUser);
        assertThat(savedUser).isNotNull();
        assertThat(savedUser.getId()).isEqualTo(baseId);

        // Then: 동일한 ID로 두 번째 사용자 등록 시 예외 발생 확인
        Member duplicateUser = createTestUser(baseId, "pass2@", "사용자2", "주소2");

        assertThatThrownBy(() -> memberRepository.save(duplicateUser))
                .isInstanceOf(DataIntegrityViolationException.class);

        log.info("중복 ID 등록 예외 처리 테스트 완료 - ID: {}", baseId);
    }

    /**
     * 테스트용 Member 객체 생성 헬퍼 메서드
     */
    private Member createTestUser(String id, String password, String name, String address) {
        String encodedPassword = passwordEncoder.encode(password);

        return Member.builder()
                .id(id)
                .pwd(encodedPassword)
                .name(name)
                .address(address)
                .role("ROLE_USER")
                .build();
    }

    /**
     * 비밀번호 정책 검증 테스트
     */
    @Test
    @DisplayName("비밀번호 정책 검증")
    void passwordPolicyTest() {
        log.info("비밀번호 정책 검증 테스트 시작");

        // Given: 다양한 비밀번호 패턴
        List<String> passwords = Arrays.asList(
                "simple123!",      // 유효한 비밀번호
                "weakpass",        // 약한 비밀번호
                "VeryStrong123!@", // 강한 비밀번호
                "12345678"         // 숫자만 포함
        );

        // When & Then: 각 비밀번호 암호화 및 검증
        passwords.forEach(password -> {
            String encoded = passwordEncoder.encode(password);
            boolean matches = passwordEncoder.matches(password, encoded);

            assertThat(matches).isTrue();
            assertThat(encoded).isNotEqualTo(password);
            assertThat(encoded.length()).isGreaterThan(50); // BCrypt 길이 확인

            log.info("비밀번호 '{}' -> 암호화 길이: {}",
                    password.replaceAll(".", "*"), encoded.length());
        });

        log.info("비밀번호 정책 검증 테스트 완료");
    }

    /**
     * 권한별 사용자 등록 테스트
     */
    @Test
    @DisplayName("권한별 사용자 등록 테스트")
    @Commit
    void roleBasedUserRegistrationTest() {
        log.info("권한별 사용자 등록 테스트 시작");

        String timestamp = String.valueOf(System.currentTimeMillis());

        // ROLE_USER 등록
        Member userMember = memberRepository.save(
                Member.builder()
                        .id("user_" + timestamp)
                        .pwd(passwordEncoder.encode("userpass"))
                        .role("ROLE_USER")
                        .address("사용자 주소")
                        .name("일반사용자")
                        .build()
        );

        // ROLE_ADMIN 등록
        Member adminMember = memberRepository.save(
                Member.builder()
                        .id("admin_" + timestamp)
                        .pwd(passwordEncoder.encode("adminpass"))
                        .role("ROLE_ADMIN")
                        .address("관리자 주소")
                        .name("관리자")
                        .build()
        );

        // 검증
        assertThat(userMember.getRole()).isEqualTo("ROLE_USER");
        assertThat(adminMember.getRole()).isEqualTo("ROLE_ADMIN");

        log.info("권한별 사용자 등록 완료 - 사용자: {}, 관리자: {}",
                userMember.getId(), adminMember.getId());
    }

    /**
     * 사용자 정보 조회 테스트
     */
    @Test
    @DisplayName("사용자 정보 조회 테스트")
    @Commit
    void userFindTest() {
        log.info("사용자 정보 조회 테스트 시작");

        // Given: 테스트 사용자 생성
        String testUserId = "findtest_" + System.currentTimeMillis();
        Member testUser = memberRepository.save(
                createTestUser(testUserId, "testpass", "조회테스트", "테스트주소")
        );

        // When: 사용자 조회
        Member foundUser = memberRepository.findById(testUserId);

        // Then: 조회 결과 검증
        assertThat(foundUser).isNotNull();
        assertThat(foundUser.getId()).isEqualTo(testUserId);
        assertThat(foundUser.getName()).isEqualTo("조회테스트");
        assertThat(foundUser.getAddress()).isEqualTo("테스트주소");

        log.info("사용자 정보 조회 성공 - ID: {}, 이름: {}",
                foundUser.getId(), foundUser.getName());
    }
}