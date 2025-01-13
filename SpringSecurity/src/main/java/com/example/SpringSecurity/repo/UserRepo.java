package com.example.SpringSecurity.repo;

import com.example.SpringSecurity.model.Users;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface UserRepo extends JpaRepository<Users, Integer> {

   public Users findByUsername(String username);


}
