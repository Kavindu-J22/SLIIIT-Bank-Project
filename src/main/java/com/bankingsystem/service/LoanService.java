// src/main/java/com/bankingsystem/service/LoanService.java
package com.bankingsystem.service;

import com.bankingsystem.model.Loan;
import com.bankingsystem.model.LoanStatus;
import com.bankingsystem.model.User;
import com.bankingsystem.repository.LoanRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

@Service
public class LoanService {

    @Autowired
    private LoanRepository loanRepository;

    public Loan applyLoan(Loan loan, User applicant) {
        loan.setApplicant(applicant);
        loan.setStatus(LoanStatus.PENDING);
        return loanRepository.save(loan);
    }

    public void reviewLoan(Long loanId, User reviewer, LoanStatus status) {
        Loan loan = loanRepository.findById(loanId).orElseThrow(() -> new RuntimeException("Loan not found"));
        loan.setReviewer(reviewer);
        loan.setStatus(status);
        loanRepository.save(loan);
    }

    public void updateStatus(Long loanId, User approver, LoanStatus status) {
        Loan loan = loanRepository.findById(loanId).orElseThrow(() -> new RuntimeException("Loan not found"));
        loan.setApprover(approver);
        loan.setStatus(status);
        loanRepository.save(loan);
    }

    public List<Loan> findAll() {
        return loanRepository.findAll();
    }

    public Optional<Loan> findById(Long id) {
        return loanRepository.findById(id);
    }

    public List<Loan> findByApplicant(User applicant) {
        return loanRepository.findByApplicant(applicant);
    }

    public void deleteById(Long id) {
        loanRepository.deleteById(id);
    }
}