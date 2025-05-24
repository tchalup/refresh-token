namespace RefreshToken.Api.Models.Constants
{
    public static class CustomClaimTypes
    {
        public const string LastRefreshToken = "LastRefreshToken";
        /// <summary>
        /// Claim indicating that the user must perform a full re-authentication.
        /// </summary>
        public const string ForceReAuthentication = "ForceReAuthentication";
    }
}
