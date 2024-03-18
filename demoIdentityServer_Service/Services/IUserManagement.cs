
using demoIdentityServer_Service.Models;
using demoIdentityServer_Service.Models.Authentication.SignUp;

namespace demoIdentityServer_Service.Services
{
    public interface IUserManagement
    {
        Task<ApiResponse<string>> CreateUserWithTokenAsync(RegisterUser registerUser);
        Task<ApiResponse<List<string>>> AssignRoleToUserAsync(IEnumerable<string> roles);
    }
}
