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

        [HttpPost("")]
        public async Task<IActionResult> Index(AccountCreateRequestModel model)
        {
            _logger.LogInformation("Account endpoint accessed.");

            var user = new IdentityUser
            {
                UserName = model.Email,
                Email = model.Email,
                EmailConfirmed = true
            };

            var result = await _userManager.CreateAsync(user, model.Password);

            if (!result.Succeeded)
                return BadRequest(result.Errors);

            return Ok("Success\nThis is an account endpoint.\nYou are authorized to access it.");
        }
    }
}
