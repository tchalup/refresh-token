using System.ComponentModel.DataAnnotations;
using System.Text.Json.Serialization;

namespace RefreshToken.Api.ViewModel.Auth
{
    public class RefreshTokenCreateRequestModel
    {
        [Required]
        public string RefreshToken { get; set; }
    }
}
