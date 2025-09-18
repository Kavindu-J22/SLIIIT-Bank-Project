// src/main/java/com/bankingsystem/repository/AccountRepository.java
package com.bankingsystem.repository;

import com.bankingsystem.model.Account;
import com.bankingsystem.model.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface AccountRepository extends JpaRepository<Account, Long> {
    Optional<Account> findByAccountNumber(String accountNumber);
    List<Account> findByUser(User user);
}