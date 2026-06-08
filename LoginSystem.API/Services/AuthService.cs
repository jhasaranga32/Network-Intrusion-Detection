using LoginSystem.API.DTOs;
using LoginSystem.API.Helpers;
using LoginSystem.API.Models;
using LoginSystem.API.Repositories.Interfaces;
using LoginSystem.API.Services.Interfaces;

namespace LoginSystem.API.Services;

public class AuthService : IAuthService
{
    private readonly IUserRepository _userRepository;
    private readonly JwtService _jwtService;

    public AuthService(IUserRepository userRepository, JwtService jwtService)
    {
        _userRepository = userRepository;
        _jwtService = jwtService;
    }

    public async Task<AuthResponseDto> RegisterAsync(RegisterDto dto)
    {
        if (await _userRepository.ExistsByEmailAsync(dto.Email))
            throw new InvalidOperationException("Email is already registered.");

        if (await _userRepository.ExistsByUsernameAsync(dto.Username))
            throw new InvalidOperationException("Username is already taken.");

        var user = new User
        {
            Username = dto.Username,
            Email = dto.Email,
            PasswordHash = PasswordHasher.Hash(dto.Password),
            RefreshToken = _jwtService.GenerateRefreshToken(),
            RefreshTokenExpiry = _jwtService.GetRefreshTokenExpiry()
        };

        await _userRepository.CreateAsync(user);

        return BuildAuthResponse(user);
    }

    public async Task<AuthResponseDto> LoginAsync(LoginDto dto)
    {
        var user = await _userRepository.GetByEmailAsync(dto.Email)
            ?? throw new UnauthorizedAccessException("Invalid email or password.");

        if (!user.IsActive)
            throw new UnauthorizedAccessException("Account is deactivated.");

        if (!PasswordHasher.Verify(dto.Password, user.PasswordHash))
            throw new UnauthorizedAccessException("Invalid email or password.");

        user.RefreshToken = _jwtService.GenerateRefreshToken();
        user.RefreshTokenExpiry = _jwtService.GetRefreshTokenExpiry();
        await _userRepository.UpdateAsync(user);

        return BuildAuthResponse(user);
    }

    public async Task<AuthResponseDto> RefreshTokenAsync(string refreshToken)
    {
        var user = await _userRepository.GetByRefreshTokenAsync(refreshToken)
            ?? throw new UnauthorizedAccessException("Invalid refresh token.");

        if (user.RefreshTokenExpiry < DateTime.UtcNow)
            throw new UnauthorizedAccessException("Refresh token has expired.");

        user.RefreshToken = _jwtService.GenerateRefreshToken();
        user.RefreshTokenExpiry = _jwtService.GetRefreshTokenExpiry();
        await _userRepository.UpdateAsync(user);

        return BuildAuthResponse(user);
    }

    public async Task RevokeTokenAsync(int userId)
    {
        var user = await _userRepository.GetByIdAsync(userId)
            ?? throw new KeyNotFoundException("User not found.");

        user.RefreshToken = null;
        user.RefreshTokenExpiry = null;
        await _userRepository.UpdateAsync(user);
    }

    private AuthResponseDto BuildAuthResponse(User user) => new()
    {
        AccessToken = _jwtService.GenerateAccessToken(user),
        RefreshToken = user.RefreshToken!,
        ExpiresAt = _jwtService.GetAccessTokenExpiry(),
        User = new DTOs.UserDto
        {
            Id = user.Id,
            Username = user.Username,
            Email = user.Email,
            Role = user.Role,
            CreatedAt = user.CreatedAt,
            IsActive = user.IsActive
        }
    };
}
