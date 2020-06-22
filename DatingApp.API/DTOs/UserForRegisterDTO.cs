using System.ComponentModel.DataAnnotations;

namespace DatingApp.API.DTOs
{
    public class UserForRegisterDTO
    {
        [Required]
        public string UsernameDTO {get; set;}

        [Required]
        [StringLength(8, MinimumLength = 4 ,ErrorMessage = "You must specify password between 4 and 8 character")]
        public string PasswordDTO { get; set; }             
    }
}