using Microsoft.AspNetCore.Mvc;
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
        public async Task<IActionResult> LoginAccountOTP(LoginOTPDTO loginOTPDTO)
        {
            var response = await userAccount.LoginAccountOTP(loginOTPDTO);
            return Ok(response);
        }

        [HttpPost("refresh-token")]
        public async Task<IActionResult> RefreshToken(TokenDTO loginOTPDTO)
        {
            var response = await userAccount.RefreshToken(loginOTPDTO);
            return Ok(response);
        }

        [HttpPost("confirm")]
        public async Task<IActionResult> ConfirmEmail(ConfirmEmailDTO confirmEmailDTO)
        {
            var response = await userAccount.ConfirmEmail(confirmEmailDTO);
            return Ok(response);
        }
    }
}
