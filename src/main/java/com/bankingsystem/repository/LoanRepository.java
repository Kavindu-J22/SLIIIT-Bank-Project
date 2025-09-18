// src/main/java/com/bankingsystem/repository/LoanRepository.java
package com.bankingsystem.repository;

import com.bankingsystem.model.Loan;
import com.bankingsystem.model.LoanStatus;
import com.bankingsystem.model.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface LoanRepository extends JpaRepository<Loan, Long> {
    List<Loan> findByApplicant(User applicant);
    List<Loan> findByStatus(LoanStatus status);
}