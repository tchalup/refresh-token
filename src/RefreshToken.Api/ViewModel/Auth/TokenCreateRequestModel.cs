using System.ComponentModel.DataAnnotations;

namespace RefreshToken.Api.ViewModel.Auth
{
    /// <summary>
    /// Model for requesting an authentication token.
    /// </summary>
    public class TokenCreateRequestModel
    {
        /// <summary>
        /// The user's email address.
        /// </summary>
        [Required(ErrorMessage = "The {0} is required")]
        [EmailAddress(ErrorMessage = "The {0} is in a incorrect format")]
        public string? Email { get; set; }

        /// <summary>
        /// The user's password.
        /// </summary>
        [Required(ErrorMessage = "The {0} is required")]
        [StringLength(100, ErrorMessage = "The {0} must have between {2} and {1} characters", MinimumLength = 6)]
        public string? Password { get; set; }
    }
}
