namespace RefreshToken.Api.ViewModel.Auth
{
    public class TokenCreateResponseModel
    {
        public string? AccessToken { get; set; }
        public string? RefreshToken { get; set; }
        public int ExpiresInSeconds { get; set; }
    }
}
