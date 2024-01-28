package com.example.be.dto.request;

import lombok.Value;

import java.io.Serializable;

/**
 * DTO for {@link com.example.be.entity.Account}
 */
@Value
public class AccountDto implements Serializable {
    Integer accountId;
    String username;
    String password;
}