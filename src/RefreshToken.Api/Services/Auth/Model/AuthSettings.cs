namespace RefreshToken.Api.Services.Auth.Model
{
    public class AuthSettings
    {
        public string? Issuer { get; set; }
        public string? Audience { get; set; }
        public TokenModel? Token { get; set; }
        public TokenModel? RefreshToken { get; set; }
    }

    public class TokenModel
    {
        public int ExpiresInSeconds { get; set; }
    }
}
