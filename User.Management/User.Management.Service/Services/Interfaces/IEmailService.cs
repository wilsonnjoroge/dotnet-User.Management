using User.Management.Service.Model.MessageConfig;

namespace User.Management.Service.Services.Interfaces
{
    public interface IEmailService
    {
        void SendEmail(Message message);
    }
}
