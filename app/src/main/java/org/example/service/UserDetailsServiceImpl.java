package org.example.service;

import lombok.AllArgsConstructor;
import lombok.Data;
import org.example.entities.UserInfo;
import org.example.models.UserInfoDto;
import org.example.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.HashSet;
import java.util.Objects;
import java.util.UUID;

@Component
@AllArgsConstructor
@Data
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
        //create new user
        UserInfo checkExist = checkIfUserAlreadyExist(userInfoDto);
        if(checkExist == null )
        {
            userInfoDto.setPassword(passwordEncoder.encode(userInfoDto.getPassword()));
            userInfoDto.setUserId(UUID.randomUUID().toString());
            userRepository.save(new UserInfo(userInfoDto.getUserId(), userInfoDto.getUsername(), userInfoDto.getPassword(), new HashSet<>()));
        }

        return userInfoDto.getUserId();
    }
}
