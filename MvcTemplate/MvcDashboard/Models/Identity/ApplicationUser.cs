﻿using System;
using Microsoft.AspNetCore.Identity;

namespace MvcTemplate.Models.Identity
{
    public class ApplicationUser : IdentityUser
    {
        [PersonalData]
        public string FullName { get; set; }

        [PersonalData]
        public string JobDescription { get; set; }

        [PersonalData]
        public DateTime? BirthDate { get; set; }
    }
}
