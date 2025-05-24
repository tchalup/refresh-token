using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using RefreshToken.Api.ViewModel.Account;

namespace RefreshToken.Api.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class AccountController : ControllerBase
    {
        private readonly ILogger<AccountController> _logger;
        private readonly UserManager<IdentityUser> _userManager;

        public AccountController(ILogger<AccountController> logger, UserManager<IdentityUser> userManager)
        {
            _logger = logger;
            _userManager = userManager;
        }

        /// <summary>
        /// Registers a new user in the system.
        /// </summary>
        /// <param name="model">The user registration details including email and password.</param>
        /// <returns>An HTTP 200 OK response if registration is successful, otherwise a BadRequest with errors.</returns>
        /// <response code="200">User registered successfully.</response>
        /// <response code="400">Registration failed due to validation errors or other issues.</response>
        [HttpPost("register")] // Changed route from "" to "register"
        public async Task<IActionResult> RegisterUser(AccountCreateRequestModel model) // Renamed Index to RegisterUser
        {
            _logger.LogInformation("User registration endpoint accessed."); // Updated log message

            var user = new IdentityUser
            {
                UserName = model.Email,
                Email = model.Email,
                EmailConfirmed = true
            };

            var result = await _userManager.CreateAsync(user, model.Password);

            if (!result.Succeeded)
                return BadRequest(result.Errors);

            return Ok("User registered successfully."); // Simplified success message
        }
    }
}
