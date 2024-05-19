﻿using Microsoft.AspNetCore.Mvc;
using SharedClassLibrary.Contracts;
using SharedClassLibrary.DTOs;

namespace IdentityEndpoints.Controllers
{
    [Route("api/[controller]")]
    [ApiController]

    public class AccountController(IUserAccount userAccount) : ControllerBase
    {
        [HttpPost("register")]
        public async Task<IActionResult> Register(UserDTO userDTO)
        {
            var response = await userAccount.CreateAccount(userDTO);
            return Ok(response);
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login(LoginDTO loginDTO)
        {
            var response = await userAccount.LoginAccount(loginDTO);
            return Ok(response);
        }

        [HttpPost("login-2FA")]
        public async Task<IActionResult> LoginAccountOTP(string code, string Email)
        {
            var response = await userAccount.LoginAccountOTP(code, Email);
            return Ok(response);
        }
    }
}
