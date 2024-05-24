using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SharedClassLibrary.DTOs
{
    public class ServiceResponses
    {
        public record class GeneralResponse(bool Flag, string Message);
        public record class LoginResponse(bool Flag, string Token=null!, string Message = null!);

        public record class TokenResponse(bool Flag, string accessToken = null!, string refreshToken = null!);
    }
}
