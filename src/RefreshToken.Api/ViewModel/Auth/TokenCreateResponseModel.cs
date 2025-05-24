namespace RefreshToken.Api.ViewModel.Auth
{
    /// <summary>
    /// Model representing the response after successful token creation or refresh.
    /// </summary>
    public class TokenCreateResponseModel
    {
        /// <summary>
        /// The JWT access token.
        /// </summary>
        public string? AccessToken { get; set; }

        /// <summary>
        /// The JWT refresh token.
        /// </summary>
        public string? RefreshToken { get; set; }

        /// <summary>
        /// The lifetime of the access token in seconds.
        /// </summary>
        public int ExpiresInSeconds { get; set; }
    }
}
