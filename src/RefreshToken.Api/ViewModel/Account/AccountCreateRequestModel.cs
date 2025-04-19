using System.ComponentModel.DataAnnotations;
using System.ComponentModel;

namespace RefreshToken.Api.ViewModel.Account
{
    public class AccountCreateRequestModel
    {
        [Required(ErrorMessage = "The {0} is required")]
        [EmailAddress(ErrorMessage = "The {0} is in a incorrect format")]
        public string? Email { get; set; }

        [Required(ErrorMessage = "The {0} is required")]
        [StringLength(100, ErrorMessage = "The {0} must have between {2} and {1} characters", MinimumLength = 6)]
        public string? Password { get; set; }

        [DisplayName("Confirm Password")]
        [Compare("Password", ErrorMessage = "The passwords doesn't match.")]
        public string? ConfirmPassword { get; set; }
    }
}
