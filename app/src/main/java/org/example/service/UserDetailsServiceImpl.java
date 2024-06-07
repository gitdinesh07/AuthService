package org.example.service;

import org.example.entities.UserInfo;
import org.example.models.UserInfoDto;
import org.example.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Objects;
import java.util.UUID;

public class UserDetailsServiceImpl implements UserDetailsService {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        UserInfo user = userRepository.findByUsername(username);
        if(user == null)
            throw  new UsernameNotFoundException(username+" user not found.");

        return new CustomUserDetails(user);
    }

    public UserInfo checkIfUserAlreadyExist(UserInfoDto userInfoDto){
        return userRepository.findByUsername(userInfoDto.getUsername());
    }

    public String signupUser(UserInfoDto userInfoDto){
        if(Objects.nonNull(checkIfUserAlreadyExist(userInfoDto)))
            throw new RuntimeException("user already exist");

        //create new user
        userInfoDto.setUserId(UUID.randomUUID().toString());
        userInfoDto.setPassword(passwordEncoder.encode(userInfoDto.getPassword()));
        userRepository.save(userInfoDto);

        return userInfoDto.getUserId();
    }
}
