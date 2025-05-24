using System.ComponentModel.DataAnnotations;
using System.Text.Json.Serialization;

namespace RefreshToken.Api.ViewModel.Auth
{
    /// <summary>
    /// Model for requesting a new access token using a refresh token.
    /// </summary>
    public class RefreshTokenCreateRequestModel
    {
        /// <summary>
        /// The refresh token string.
        /// </summary>
        [Required]
        public string RefreshToken { get; set; }
    }
}
