using demoIdentityServer_Service.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace demoIdentityServer_Service.Services
{
    public interface IEmailService
    {
        void SendEmail(Message message);
    }
}
