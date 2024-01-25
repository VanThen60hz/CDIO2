package com.example.be.controller;

import com.example.be.dto.JwtDTO;
import com.example.be.dto.PasswordChangeDTO;
import com.example.be.dto.SignInDTO;
import com.example.be.dto.TeacherCreateDTO;
import com.example.be.dto.request.SignUpRequest;
import com.example.be.entity.Account;
import com.example.be.entity.Teacher;
import com.example.be.jwt.JwtTokenProvider;
import com.example.be.security.UserPrinciple;
import com.example.be.service.IAccountService;
import com.example.be.service.ITeacherService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

@RequestMapping("/api/auth")
@CrossOrigin("*")
@RestController
public class LoginController {

    @Autowired
    private AuthenticationManager authenticationManager;
    @Autowired
    private JwtTokenProvider jwtTokenProvider;
    @Autowired
    private IAccountService iAccountService;
    @Autowired
    private PasswordEncoder passwordEncoder;
    @Autowired
    private ITeacherService iTeacherService;


    @PostMapping("/sign-in")
    public ResponseEntity<?> signIn(@RequestBody SignInDTO signInDTO) {
        try {
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(signInDTO.getUserName(), signInDTO.getPassword()));
            SecurityContextHolder.getContext().setAuthentication(authentication);
            UserPrinciple userPrinciple = (UserPrinciple) authentication.getPrincipal();
            String token = jwtTokenProvider.genarateToken(userPrinciple);
            Account account = iAccountService.findByUsername(userPrinciple.getUsername());

            System.out.println(authentication);
            System.out.println(account);
            System.out.println(token);
            System.out.println(userPrinciple.getAuthorities());

            if (account.getTeacher() != null) {
                return new ResponseEntity<>
                        (new JwtDTO(token, account.getTeacher().getName(), account.getTeacher().getAvatar(), userPrinciple.getAuthorities()), HttpStatus.OK);
            }
            if (account.getStudent() != null) {
                return new ResponseEntity<>
                        (new JwtDTO(token, account.getStudent().getName(), account.getStudent().getAvatar(), userPrinciple.getAuthorities()), HttpStatus.OK);
            }
            return new ResponseEntity<>
                    (new JwtDTO(token, "Admin", null, userPrinciple.getAuthorities()), HttpStatus.OK);
        } catch (AuthenticationException e) {
            return new ResponseEntity<>("Sai tên người dùng hoặc mật khẩu", HttpStatus.UNAUTHORIZED);
        }
    }

    @PostMapping("/sign-up-account")
    public ResponseEntity<?> signUpAccount(@RequestBody SignUpRequest signUpRequest) {
        if (iAccountService.existsByUsername(signUpRequest.getUserName())) {
            return new ResponseEntity<>("Tên người dùng đã tồn tại", HttpStatus.BAD_REQUEST);
        }
        Account account = new Account();
        account.setUsername(signUpRequest.getUserName());
        account.setPassword(passwordEncoder.encode(signUpRequest.getPassword()));
        iAccountService.saveAccount(account);

//        Teacher teacher = new Teacher();
//        teacher.setName(signUpRequest.getName());
//        teacher.setEmail(signUpRequest.getEmail());
//        teacher.setPhone(signUpRequest.getPhone());
//        teacher.setAddress(signUpRequest.getAddress());
//        teacher.setDateOfBirth(signUpRequest.getDateOfBirth());
//        teacher.setGender(signUpRequest.getGender());
//        teacher.setAvatar(signUpRequest.getAvatar());
////        teacher.setDegreeId(signUpRequest.getDegreeId());
////        teacher.setFacultyId(signUpRequest.getFacultyId());
//        teacher.setAccountId(account.getAccountId());
////        iTeacherService.createTeacher(teacher);
//        iTeacherService.saveTeacher(teacher);
//        iTeacherService.createTeacher(new Teacher(signUpRequest.getName(), signUpRequest.getEmail(), signUpRequest.getPhone(), signUpRequest.getAddress(), signUpRequest.getDateOfBirth(), signUpRequest.getGender(), signUpRequest.getAvatar(), signUpRequest.getDegreeId(), signUpRequest.getFacultyId(), account.getAccountId()));
        return new ResponseEntity<>("Đăng ký tài khoản thành công", HttpStatus.OK);
    }


    @PostMapping("/change-password")
    public ResponseEntity<?> changePassword(@RequestBody PasswordChangeDTO passwordChangeDTO) {
        UserPrinciple userPrinciple = (UserPrinciple) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        Account account = iAccountService.findByUsername(userPrinciple.getUsername());
        String oldPassword = passwordChangeDTO.getOldPassword();
        String newPassword = passwordChangeDTO.getNewPassword();
        String confirmPassword = passwordChangeDTO.getConfirmPassword();

        if (!passwordEncoder.matches(oldPassword, account.getPassword())) {
            return new ResponseEntity<>("Mật khẩu cũ không đúng", HttpStatus.BAD_REQUEST);
        }
        if (!confirmPassword.equalsIgnoreCase(newPassword)) {
            return new ResponseEntity<>("Mật khẩu mới và mật khẩu xác nhận không trùng khớp", HttpStatus.BAD_REQUEST);
        }

        String encodedPassword = passwordEncoder.encode(newPassword);
        account.setPassword(encodedPassword);
        iAccountService.changePassword(account);
        return new ResponseEntity<>("Đổi mật khẩu thành công", HttpStatus.OK);

    }

    @PreAuthorize("hasAnyRole('STUDENT', 'GROUP_LEADER','TEACHER')")
    @GetMapping("/user-info")
    public ResponseEntity<?> userInfo() {
        UserPrinciple userPrinciple = (UserPrinciple) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        Account account = iAccountService.findByUsername(userPrinciple.getUsername());
        if (account == null) {
            return new ResponseEntity<>("Người dùng không tồn tại", HttpStatus.BAD_REQUEST);
        }
        return new ResponseEntity<>(account, HttpStatus.OK);
    }
}