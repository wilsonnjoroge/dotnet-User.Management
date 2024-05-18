

using User.Management.Service.Model;

namespace User.Management.Service.Services
{
    public interface IEmailService
    {
        void SendEmail(Message message);
    }
}
