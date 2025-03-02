package com.emerson.identity.identity_service.services;

import com.emerson.identity.identity_service.entities.user.User;
import com.emerson.identity.identity_service.repositories.JpaUserDetailsRepository;
import com.emerson.identity.identity_service.security.NewUserDetails;
import com.emerson.identity.identity_service.security.UserSecurityDetails;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
@Slf4j
public class UserManagementServiceImp implements UserDetailsManager {

    private final JpaUserDetailsRepository jpaUserDetailsRepository;
    private final PasswordEncoder passwordEncoder;

    @Override
    public void createUser(UserDetails user){
        if(!(user instanceof NewUserDetails newUser)){
            throw new IllegalArgumentException("Invalid user details type");
        }
        User userToBeSaved = toUserObject(newUser);
        jpaUserDetailsRepository.save(userToBeSaved);
    }

    @Override
    public void updateUser(UserDetails user){

    }

    @Override
    public void deleteUser(String username){

    }

    @Override
    public void changePassword(String oldPassword, String newPassword){

    }

    @Override
    public boolean userExists(String email){
        return jpaUserDetailsRepository.existByEmail(email);
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException{
        return jpaUserDetailsRepository
                .findByEmail(username)
                .map(UserSecurityDetails::new)
                .orElseThrow(() -> new UsernameNotFoundException("email "+ username + " not found"));
    }

    private User toUserObject(NewUserDetails newUserDetails){
        return User.builder()
                .names(newUserDetails.getName())
                .lastNames(newUserDetails.getLastName())
                .email(newUserDetails.getUsername())
                .password(passwordEncoder.encode(newUserDetails.getPassword()))
                .build();
    }
}
