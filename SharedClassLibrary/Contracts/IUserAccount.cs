using SharedClassLibrary.DTOs;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using static SharedClassLibrary.DTOs.ServiceResponses;

namespace SharedClassLibrary.Contracts
{
    public interface IUserAccount
    {
        Task<GeneralResponse> CreateAccount(UserDTO userDTO);
        Task<TokenResponse> LoginAccount(LoginDTO loginDTO);

        Task<TokenResponse> LoginAccountOTP(LoginOTPDTO loginOTPDTO);
        Task<TokenResponse> RefreshToken(TokenDTO tokenDTO);

        Task<GeneralResponse> ConfirmEmail(UserDTO userDTO);


    }
}
