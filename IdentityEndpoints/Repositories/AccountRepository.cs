using IdentityEndpoints.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using SharedClassLibrary.Contracts;
using SharedClassLibrary.DTOs;
using SharedClassLibrary.GenericModels;
using SharedClassLibrary.Services;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
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
                EmailConfirmed = true

            };
            var user = await userManager.FindByEmailAsync(newUser.Email);
            if (user is not null) return new GeneralResponse(false, "User registered already");

            var createUser = await userManager.CreateAsync(newUser!, userDTO.Password);
            if (!createUser.Succeeded) return new GeneralResponse(false, $"Error occured {createUser} . please try again " );

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

        public async Task<ServiceResponses.TokenResponse> LoginAccount(LoginDTO loginDTO)
        {
            if (loginDTO == null)
                return new TokenResponse(false, null!,null!, "Login container is empty");

            var getUser = await userManager.FindByEmailAsync(loginDTO.Email);
            if (getUser is null)
                return new TokenResponse(false, null!, null!, "User not found");

            bool checkUserPasswords = await userManager.CheckPasswordAsync(getUser, loginDTO.Password);
            if (!checkUserPasswords)
                return new TokenResponse(false, null!, null!, "Invalid email/password");

            var getUserRole = await userManager.GetRolesAsync(getUser);
            var userSession = new UserSession(getUser.Id, getUser.Name, getUser.Email, getUserRole.First());
            string token = GenerateToken(userSession);

            var refreshToken = GenerateRefreshToken();

            _ = int.TryParse(config["JWT:RefreshTokenValidityInDays"], out int refreshTokenValidityInDays);
            _ = int.TryParse(config["JWT:TokenValidityInMinutes"], out int tokenValidityInMinutes);

            getUser.RefreshToken = refreshToken;
            getUser.TokenType = "Bearer";
            getUser.AccessTokenExpiryTime = DateTime.Now.AddMinutes(tokenValidityInMinutes);
            getUser.RefreshTokenExpiryTime = DateTime.Now.AddDays(refreshTokenValidityInDays);
            getUser.AccessToken = token;
            await userManager.UpdateAsync(getUser);


            if (getUser.TwoFactorEnabled)
            {
                await signInManager.SignOutAsync();
                await signInManager.PasswordSignInAsync(getUser, loginDTO.Password, true, false);
                var result = await signInManager.PasswordSignInAsync(getUser, loginDTO.Password, false, lockoutOnFailure: false);
                if (result.Succeeded)
                {

                }

                token = await userManager.GenerateTwoFactorTokenAsync(getUser, TokenOptions.DefaultEmailProvider);

                var message = new Message(new string[] { getUser.Email! }, "OTP Confrimation", token);
                _emailService.SendEmail(message);
                return new TokenResponse(false, null!,null!, $"We have sent an OTO to your Email {getUser.Email} ");
            }

            return new TokenResponse(true, token!, refreshToken, "Login completed");
        }

        public async Task<TokenResponse> LoginAccountOTP(LoginOTPDTO loginOTPDTO)
        {
            //var SignIn = await signInManager.TwoFactorSignInAsync("Email", loginOTPDTO.Code, false, false);
            var SignIn = await signInManager.TwoFactorSignInAsync(TokenOptions.DefaultEmailProvider, loginOTPDTO.Code, false, false);

            if (SignIn.Succeeded)
            {
                var getUser = await userManager.FindByEmailAsync(loginOTPDTO.Email);
                if (getUser is null)
                    return new TokenResponse(false, null!, "User not found");

                //var getUserRole = await userManager.GetRolesAsync(getUser);
                //var userSession = new UserSession(getUser.Id, getUser.Name, getUser.Email, getUserRole.First());
                //string token = GenerateToken(userSession);

                //var refreshToken = GenerateRefreshToken();

                //_ = int.TryParse(config["JWT:RefreshTokenValidityInDays"], out int refreshTokenValidityInDays);
                //_ = int.TryParse(config["JWT:TokenValidityInMinutes"], out int tokenValidityInMinutes);

                //getUser.RefreshToken = refreshToken;
                //getUser.TokenType = "Bearer";
                //getUser.AccessTokenExpiryTime = DateTime.Now.AddMinutes(tokenValidityInMinutes);
                //getUser.RefreshTokenExpiryTime = DateTime.Now.AddDays(refreshTokenValidityInDays);
                //getUser.AccessToken = token;

                //await userManager.UpdateAsync(getUser);

                return new TokenResponse(true, getUser.AccessToken!, getUser.RefreshToken!, "Login completed");
            }
            else
            {
                return new TokenResponse(false, null!,null!, "Invalid Code");

            }
        }



        public async Task<ServiceResponses.TokenResponse> RefreshToken(TokenDTO tokenDTO)
        {
            if (tokenDTO is null)
            {
                return new TokenResponse(false, null!, null!, "Invalid Invalid client request");
            }

            string? accessToken = tokenDTO.AccessToken;
            string? refreshToken = tokenDTO.RefreshToken;

            var principal = GetPrincipalFromExpiredToken(accessToken);
            if (principal == null)
            {
                return new TokenResponse(false, null!, null!, "Invalid access token or refresh token");
            }

#pragma warning disable CS8600 // Converting null literal or possible null value to non-nullable type.
#pragma warning disable CS8602 // Dereference of a possibly null reference.
            string username = principal.Identity.Name;
#pragma warning restore CS8602 // Dereference of a possibly null reference.
#pragma warning restore CS8600 // Converting null literal or possible null value to non-nullable type.

            var user = await userManager.FindByEmailAsync(username!);

            if (user == null || user.RefreshToken != refreshToken || user.RefreshTokenExpiryTime <= DateTime.Now)
            {
                return new TokenResponse(false,null!,null!, "Invalid access token or refresh token");
            }

            var getUserRole = await userManager.GetRolesAsync(user);
            var userSession = new UserSession(user.Id, user.Name, user.Email, getUserRole.First());

            var newAccessToken = GenerateToken(userSession);
            var newRefreshToken = user.RefreshToken;

            user.AccessToken = newAccessToken;
            await userManager.UpdateAsync(user);

            return new TokenResponse(true,accessToken = newAccessToken!,refreshToken = newRefreshToken!);

        }

        private string GenerateToken(UserSession user)
        {
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(config["JWT:Key"]!));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);
            var userClaims = new[]
            {
                new Claim(ClaimTypes.NameIdentifier, user.Id!),
                new Claim(ClaimTypes.Name, user.Name!),
                new Claim(ClaimTypes.Email, user.Email!),
                new Claim(ClaimTypes.Role, user.Role!)
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

        private ClaimsPrincipal? GetPrincipalFromExpiredToken(string? token)
        {
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(config["JWT:Key"]!));

            var tokenValidationParameters = new TokenValidationParameters
            {
                ValidateAudience = false,
                ValidateIssuer = false,
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = securityKey,
                ValidateLifetime = false
            };

            var tokenHandler = new JwtSecurityTokenHandler();
            var principal = tokenHandler.ValidateToken(token, tokenValidationParameters, out SecurityToken securityToken);
            if (securityToken is not JwtSecurityToken jwtSecurityToken || !jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase))
                throw new SecurityTokenException("Invalid token");

            return principal;

        }

        private static string GenerateRefreshToken()
        {
            var randomNumber = new byte[64];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(randomNumber);
            return Convert.ToBase64String(randomNumber);
        }

        public Task<GeneralResponse> ConfirmEmail(UserDTO userDTO)
        {
            throw new NotImplementedException();
        }
    }
}
