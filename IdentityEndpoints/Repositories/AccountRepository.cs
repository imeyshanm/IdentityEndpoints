using IdentityEndpoints.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;
using SharedClassLibrary.Contracts;
using SharedClassLibrary.DTOs;
using SharedClassLibrary.GenericModels;
using SharedClassLibrary.Services;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using static SharedClassLibrary.DTOs.ServiceResponses;

namespace IdentityEndpoints.Repositories
{
    public class AccountRepository(
        UserManager<ApplicationUser> userManager,
        SignInManager<ApplicationUser> signInManager,
        RoleManager<IdentityRole> roleManager,
       IEmailService _emailService,
       IConfiguration config) : IUserAccount
    {
        public async Task<ServiceResponses.GeneralResponse> CreateAccount(UserDTO userDTO)
        {
            if (userDTO is null) return new GeneralResponse(false, "Model is empty");
            var newUser = new ApplicationUser()
            {
                Name = userDTO.Name,
                Email = userDTO.Email,
                PasswordHash = userDTO.Password,
                UserName = userDTO.Email,
                TwoFactorEnabled = userDTO.TwoFactorEnabled,

            };
            var user = await userManager.FindByEmailAsync(newUser.Email);
            if (user is not null) return new GeneralResponse(false, "User registered already");

            var createUser = await userManager.CreateAsync(newUser!, userDTO.Password);
            if (!createUser.Succeeded) return new GeneralResponse(false, "Error occured.. please try again");

            //Assign Default Role : Admin to first registrar; rest is user
            var checkAdmin = await roleManager.FindByNameAsync("Admin");
            if (checkAdmin is null)
            {
                await roleManager.CreateAsync(new IdentityRole() { Name = "Admin" });
                await userManager.AddToRoleAsync(newUser, "Admin");
                return new GeneralResponse(true, "Account Created");
            }
            else
            {
                var checkUser = await roleManager.FindByNameAsync("User");
                if (checkUser is null)
                    await roleManager.CreateAsync(new IdentityRole() { Name = "User" });

                await userManager.AddToRoleAsync(newUser, "User");
                return new GeneralResponse(true, "Account Created");
            }
        }

        public async Task<ServiceResponses.LoginResponse> LoginAccount(LoginDTO loginDTO)
        {
            if (loginDTO == null)
                return new LoginResponse(false, null!, "Login container is empty");

            var getUser = await userManager.FindByEmailAsync(loginDTO.Email);
            if (getUser is null)
                return new LoginResponse(false, null!, "User not found");

            bool checkUserPasswords = await userManager.CheckPasswordAsync(getUser, loginDTO.Password);
            if (!checkUserPasswords)
                return new LoginResponse(false, null!, "Invalid email/password");

            var getUserRole = await userManager.GetRolesAsync(getUser);
            var userSession = new UserSession(getUser.Id, getUser.Name, getUser.Email, getUserRole.First());
            string token = GenerateToken(userSession);
            if (getUser.TwoFactorEnabled)
            {
                await signInManager.SignOutAsync();
                await signInManager.PasswordSignInAsync(getUser, loginDTO.Password, false, false);
                token = await userManager.GenerateTwoFactorTokenAsync(getUser, "Email");
                var message = new Message(new string[] { getUser.Email! }, "OTP Confrimation", token);
                _emailService.SendEmail(message);
                return new LoginResponse(false, null!, $"We have sent an OTO to your Email {getUser.Email} ");
            }

            return new LoginResponse(true, token!, "Login completed");
        }

        public async Task<LoginResponse> LoginAccountOTP(LoginOTPDTO loginOTPDTO)
        {
            var SignIn = await signInManager.TwoFactorSignInAsync("Email", loginOTPDTO.Code, false, false);
            if (SignIn.Succeeded)
            {
                var getUser = await userManager.FindByEmailAsync(loginOTPDTO.Email);
                if (getUser is null)
                    return new LoginResponse(false, null!, "User not found");

                //bool checkUserPasswords = await userManager.CheckPasswordAsync(getUser, getUser.p);
                //if (!checkUserPasswords)
                //    return new LoginResponse(false, null!, "Invalid email/password");

                var getUserRole = await userManager.GetRolesAsync(getUser);
                var userSession = new UserSession(getUser.Id, getUser.Name, getUser.Email, getUserRole.First());
                string token = GenerateToken(userSession);
                return new LoginResponse(true, token!, "Login completed");
            }
            else
            {
                return new LoginResponse(false, null!, "Invalid Code");

            }
        }

        private string GenerateToken(UserSession user)
        {
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(config["JWT:Key"]!));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);
            var userClaims = new[]
            {
                new Claim(ClaimTypes.NameIdentifier, user.Id),
                new Claim(ClaimTypes.Name, user.Name),
                new Claim(ClaimTypes.Email, user.Email),
                new Claim(ClaimTypes.Role, user.Role)
            };
            _ = int.TryParse(config["JWT:TokenValidityInMinutes"], out int tokenValidityInMinutes);

            var token = new JwtSecurityToken(
                issuer: config["Jwt:ValidIssuer"],
                audience: config["Jwt:ValidAudience"],
                claims: userClaims,
                expires: DateTime.Now.AddMinutes(tokenValidityInMinutes),
                signingCredentials: credentials
                );
            return new JwtSecurityTokenHandler().WriteToken(token);
        }
    }
}
