// src/main/java/com/bankingsystem/repository/TransactionRepository.java
package com.bankingsystem.repository;

import com.bankingsystem.model.Account;
import com.bankingsystem.model.Transaction;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface TransactionRepository extends JpaRepository<Transaction, Long> {
    List<Transaction> findByFromAccountOrToAccount(Account fromAccount, Account toAccount);
}