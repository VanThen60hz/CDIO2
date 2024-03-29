package com.example.be.service;


import com.example.be.entity.Account;



import javax.transaction.Transactional;


@Transactional
public interface IAccountService {

    Account findByUsername(String username);

    Account getAccountById(Integer idAccount);


    boolean existsByUsername(String username);

    void saveAccount(Account account);
  
    void changePassword(Account account);

    Account registerAccount(Account account);

}
