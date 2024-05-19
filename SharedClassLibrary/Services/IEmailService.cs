using SharedClassLibrary.GenericModels;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SharedClassLibrary.Services
{
    public interface IEmailService
    {
        void SendEmail(Message message);
    }
}
