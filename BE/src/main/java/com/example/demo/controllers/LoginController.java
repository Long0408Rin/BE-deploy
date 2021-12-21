package com.example.demo.controllers;

import com.example.demo.config.JwtTokenProvider;
import com.example.demo.dto.LoginRequest;
import com.example.demo.dto.TokenDTO;
import com.example.demo.dto.UserDTO;
import com.example.demo.model.Cart;
import com.example.demo.model.Role;
import com.example.demo.model.User;
import com.example.demo.model.UserDetailsImpl;
import com.example.demo.repository.UserRepository;
import com.example.demo.service.CartService;
import com.example.demo.service.RoleService;
import com.example.demo.service.UserService;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdTokenVerifier;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.jackson2.JacksonFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;
import java.io.IOException;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

@Controller
@RestController
@CrossOrigin
@RequestMapping()
public class LoginController {
    public static String GOOGLE_CLIENT_ID = "164479982830-jt3um6q9oojd7c1n5j0mr5nf6klttbbd.apps.googleusercontent.com";
    public static String PASSWORD = "longRinPBL6";
    @Autowired
    private PasswordEncoder passwordEncoder;
    @Autowired
    AuthenticationManager authenticationManager;

    @Autowired
    private JavaMailSender javaMailSender;

    @Autowired
    private JwtTokenProvider tokenProvider;
    @Autowired
    UserService userService;

    @Autowired
    RoleService roleService;

    @Autowired
    UserRepository userRepository;

    @Autowired
    CartService cartService;

    private static String emailInput;
    public static String email;

    @PostMapping("/login")
    public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest loginRequest) {
        Authentication authentication;
        // Xác thực từ username và password.
        try {
            authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));
        }catch (Exception e){
//             (userService.findByUsername(loginRequest.getUsername()) != null)
                throw new BadCredentialsException("Tên đăng nhập hoặc mật khẩu không chính xác!", e);

        }
        // Nếu không xảy ra exception tức là thông tin hợp lệ
        // Set thông tin authentication vào Security Context
        SecurityContextHolder.getContext().setAuthentication(authentication);

        // Trả về jwt cho người dùng.
        String jwt = tokenProvider.generateJwtToken(authentication);
        UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
        List<String> roles = userDetails.getAuthorities().stream()
                .map(item -> item.getAuthority())
                .collect(Collectors.toList());

        return ResponseEntity.ok(new UserDTO(jwt,
                userDetails.getIdUser(),
                userDetails.getUsername(),
                userDetails.getFullName(),
                roles
        ));
    }

    @PostMapping("login-google")
    public ResponseEntity<?> authenticateByGoogleAccount(@RequestBody TokenDTO tokenDTO) throws IOException {
        final NetHttpTransport transport = new NetHttpTransport();
        final JacksonFactory jacksonFactory = new JacksonFactory();
        GoogleIdTokenVerifier.Builder verifier = new GoogleIdTokenVerifier.Builder(transport, jacksonFactory).setAudience(Collections.singletonList(GOOGLE_CLIENT_ID));
        final GoogleIdToken googleIdToken = GoogleIdToken.parse(verifier.getJsonFactory(), tokenDTO.getValue());
        final GoogleIdToken.Payload payload = googleIdToken.getPayload();
        User user;
        String userName = (String) payload.get("name");
        email = payload.getEmail();
        if (userRepository.existsByUsername(userName)) {
            user = userRepository.findByUsername(userName);
        } else {
            user = saveUser(userName);
        }
        UserDTO userDTO = login(user);
        return new ResponseEntity<>(userDTO, HttpStatus.OK);
    }


    @GetMapping("/send")
    public ResponseEntity<String> sendEmail(@RequestParam("to") String to) {
        User user = userRepository.findUserByEmail(to);
        if (user != null) {
            SimpleMailMessage msg = new SimpleMailMessage();
            msg.setTo(to);
            emailInput = to;
            msg.setSubject("Mã xác nhận đặt lại mật khẩu.");
            int randomCode = ((int) Math.floor(Math.random() * 8999) + 10000);
            msg.setText("Mã xác nhận của bạn là: " + randomCode);
            javaMailSender.send(msg);
            return new ResponseEntity<>(randomCode + "", HttpStatus.OK);
        }
        return new ResponseEntity<>(null, HttpStatus.OK);
    }

    @GetMapping("/resetPassWord")
    public ResponseEntity<Boolean> resetPassWord(@RequestParam("password") String password) {
        User user = userRepository.findUserByEmail(emailInput);
        if (user == null) {
            return new ResponseEntity<>(HttpStatus.NOT_FOUND);
        }
        user.setPassword(passwordEncoder.encode(password));
        userRepository.save(user);
        return new ResponseEntity<>(true, HttpStatus.OK);
    }

    @GetMapping("/find-by/{username}")
    public ResponseEntity<User> findByUser(@PathVariable("username") String userName) {
        User user = userRepository.findByUsername(userName);
        if (user == null) {
            return new ResponseEntity<>(HttpStatus.NOT_FOUND);
        }
        return new ResponseEntity<>(user, HttpStatus.OK);
    }

    //    @GetMapping("/save-user")
//    public ResponseEntity<Void> saveTimeRemaining(@RequestParam("userName") String userName, @RequestParam("time") String time){
//        User user = userRepository.findByUsername(userName);
//        if(user == null){
//            return new ResponseEntity<>(HttpStatus.NOT_FOUND);
//        }
//        user.setTimeRemaining(time);
//        userRepository.save(user);
//        return new ResponseEntity<>(HttpStatus.OK);
//    }
    private UserDTO login(User user) {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(user.getUsername(), PASSWORD)
        );
        SecurityContextHolder.getContext().setAuthentication(authentication);
        String jwt = tokenProvider.generateJwtToken(authentication);
        UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
        List<String> roles = userDetails.getAuthorities().stream()
                .map(item -> item.getAuthority())
                .collect(Collectors.toList());
        return new UserDTO(jwt, userDetails.getIdUser(), userDetails.getUsername(),
                userDetails.getFullName(),roles);
    }

    private User saveUser(String value) {
        User user = new User();
        Cart cart = new Cart();
        cartService.save(cart);
        user.setUsername(value);
        user.setEmail(email);
        user.setPassword(passwordEncoder.encode(PASSWORD));
        user.setFullName(value);
        Role rolUser = roleService.findById(2L);
        user.setRole(rolUser);
        user.setCart(cart);
        user.setStatus(true);
        return userRepository.save(user);
    }



}
