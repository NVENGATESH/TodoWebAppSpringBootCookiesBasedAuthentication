package com.nisahnth.ToDoListWebApp.repositories;

import com.nisahnth.ToDoListWebApp.model.AppRole;
import com.nisahnth.ToDoListWebApp.model.Role;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface RoleRepository extends JpaRepository<Role, Long> {


    Optional<Role>  findByRoleName(com.nisahnth.ToDoListWebApp.model.AppRole appRole);
}
