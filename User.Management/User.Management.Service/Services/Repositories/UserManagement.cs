using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using User.Management.Data.Models;
using User.Management.Service.Model.UserManagementDTO;
using User.Management.Service.Models.Authentication.SignUp;
using User.Management.Service.Responses;
using User.Management.Service.Services.Interfaces;
using User.Management.Service.Services.Repositories;

namespace User.Management.Service.Services.Repositories;

public class UserManagement : IUserManagement
{
    private readonly UserManager<ApplicationUser> _userManager;

    public UserManagement(UserManager<ApplicationUser> userManager)
    {
        _userManager = userManager;
    }

    public async Task<ICollection<RegisterUserDTO>> GetAllUsersAsync()
    {
        var users = await _userManager.Users.ToListAsync();
        return users.Select(user => new RegisterUserDTO
        {
            Username = user.UserName,
            Email = user.Email,
        }).ToList();
    }

    public async Task<RegisterUserDTO> GetUserByNameAsync(string Username)
    {
        var user = await _userManager.FindByEmailAsync(Username);
        if (user == null) return null;

        return new RegisterUserDTO
        {
            Username = user.UserName,
            Email = user.Email,
        };
    }


    public async Task<bool> UserExistsAsync(string email)
    {
        // Check if user exists by email using UserManager
        var user = await _userManager.FindByEmailAsync(email);
        return user != null;
    }


    public async Task<Response> UpdateUserDetailsAsync(string email, string username)
    {
        if (username== null || string.IsNullOrEmpty(email))
        {
            return new Response
            {
                IsSuccess = false,
                Status = "400",
                Message = "Invalid user data."
            };
        }

        var userExists = await UserExistsAsync(email);
   
        if (!userExists)
        {
            return new Response
            {
                IsSuccess = false,
                Status = "404",
                Message = "User not found."
            };
        }

        var user = await _userManager.FindByEmailAsync(email);

        // Update fields if provided
        if (!string.IsNullOrEmpty(username))
        {
            user.UserName = username;
        } 

        // Update user details
        var updateResult = await _userManager.UpdateAsync(user);
        if (!updateResult.Succeeded)
        {
            return new Response
            {
                IsSuccess = false,
                Status = "500",
                Message = "Failed to update user details."
            };
        }

        return new Response
        {
            IsSuccess = true,
            Status = "200",
            Message = "Details updated successfully."
        };
    }


    public async Task<Response> DeleteUserByEmailAsync(string email) 
    {
        var user = await _userManager.FindByEmailAsync(email);
        if (user == null)
        {
            return new Response
            {
                IsSuccess = false,
                Status = "404",
                Message = "User not found."
            };
        }

        var result = await _userManager.DeleteAsync(user);
        if (!result.Succeeded)
        {
            return new Response
            {
                IsSuccess = false,
                Status = "500",
                Message = "Failed to delete user."
            };
        }

        return new Response
        {
            IsSuccess = true,
            Status = "200",
            Message = "User deleted successfully."
        };
    }



}


