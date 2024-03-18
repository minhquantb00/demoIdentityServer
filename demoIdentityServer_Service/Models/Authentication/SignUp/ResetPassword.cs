using System.ComponentModel.DataAnnotations;

namespace demoIdentityServer.Models.Authentication.SignUp
{
    public class ResetPassword
    {
        [Required]
        public string? Password { get; set; } = string.Empty;
        [Compare("Password", ErrorMessage = "The password and confirmation password do not match")]
        public string? ConfirmPassword {  get; set; } = string.Empty;    
        public string? Email { get; set; } = string.Empty;
        public string? Token { get; set; } = string.Empty;
    }
}
