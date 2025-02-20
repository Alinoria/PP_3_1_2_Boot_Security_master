package ru.kata.spring.boot_security.demo.services;

import ru.kata.spring.boot_security.demo.models.Role;

import java.util.List;

public interface RoleService {
    List<Role> findAll();
    Role findByName(String name);
    Role findById(Long id);
    void createRole(Role role);
    void deleteById(Long id);
}
