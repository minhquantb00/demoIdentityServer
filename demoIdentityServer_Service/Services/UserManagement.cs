using demoIdentityServer_Service.Models;
using demoIdentityServer_Service.Models.Authentication.SignUp;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Configuration;
using Microsoft.Win32;
using Org.BouncyCastle.Asn1.Ocsp;
using System;
using System.Collections.Generic;
using System.Data;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace demoIdentityServer_Service.Services
{
    public class UserManagement : IUserManagement
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IConfiguration _configuration;
        private readonly IEmailService _emailService;
        private readonly SignInManager<IdentityUser> _signInManager;
        public UserManagement(RoleManager<IdentityRole> roleManager, IConfiguration configuration, UserManager<IdentityUser> userManager, IEmailService emailService, SignInManager<IdentityUser> signInManager)
        {
            _roleManager = roleManager;
            _configuration = configuration;
            _userManager = userManager;
            _emailService = emailService;
            _signInManager = signInManager;
        }

        public Task<ApiResponse<List<string>>> AssignRoleToUserAsync(IEnumerable<string> roles)
        {
            throw new NotImplementedException();
        }

        public async Task<ApiResponse<string>> CreateUserWithTokenAsync(RegisterUser register)
        {
            var userExist = await _userManager.FindByEmailAsync(register.Email);
            if (userExist != null)
            {
                return new ApiResponse<string> { IsSuccess = false, StatusCode = 403, Message = "User already exist!", Response = null };
            }
            IdentityUser user = new()
            {
                Email = register.Email,
                SecurityStamp = Guid.NewGuid().ToString(),
                UserName = register.UserName,
                TwoFactorEnabled = true
            };
            if (await _roleManager.RoleExistsAsync(register.Role))
            {
                var result = await _userManager.CreateAsync(user, register.Password);
                if (!result.Succeeded)
                {
                    return new ApiResponse<string> { IsSuccess = false, Message = "User failed to create", StatusCode = 500, Response = null };
                }

                await _userManager.AddToRoleAsync(user, register.Role);
                var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);
                

                return new ApiResponse<string> { IsSuccess = true, Message = $"User created and email sent to {user.Email} successfully", StatusCode = 201, Response =  token};
            }
            else
            {
                return new ApiResponse<string> { IsSuccess = false, Message = "This role doesn't exist", StatusCode = 500, Response = null };
            }
        }
    }
}
