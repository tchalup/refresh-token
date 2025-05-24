using System.ComponentModel.DataAnnotations;
using System.ComponentModel;

namespace RefreshToken.Api.ViewModel.Account
{
    /// <summary>
    /// Model for creating a new user account.
    /// </summary>
    public class AccountCreateRequestModel
    {
        /// <summary>
        /// The user's email address. This will also be used as the username.
        /// </summary>
        [Required(ErrorMessage = "The {0} is required")]
        [EmailAddress(ErrorMessage = "The {0} is in a incorrect format")]
        public string? Email { get; set; }

        /// <summary>
        /// The user's password. Must be between 6 and 100 characters.
        /// </summary>
        [Required(ErrorMessage = "The {0} is required")]
        [StringLength(100, ErrorMessage = "The {0} must have between {2} and {1} characters", MinimumLength = 6)]
        public string? Password { get; set; }

        /// <summary>
        /// Confirmation of the user's password. Must match the Password field.
        /// </summary>
        [DisplayName("Confirm Password")]
        [Compare("Password", ErrorMessage = "The passwords doesn't match.")]
        public string? ConfirmPassword { get; set; }
    }
}
