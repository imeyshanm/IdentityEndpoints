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
        Task<LoginResponse> LoginAccount(LoginDTO loginDTO);

        Task<LoginResponse> LoginAccountOTP(LoginOTPDTO loginOTPDTO);

    }
}
