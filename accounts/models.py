from django.db import models
from django.contrib.auth.models import BaseUserManager, AbstractBaseUser, PermissionsMixin
from django.utils import timezone

GENDER_TYPE = (
    ("Male", "Male"),
    ("Female", "Female"),
)

class MyUserManager(BaseUserManager):
    def _create_user(self, email, password, **extra_fields):
        """
        Creates and saves a User with the given email, and password.
        """
        if not email:
            raise ValueError("Users must have an email address")

        user = self.model(
            email=self.normalize_email(email),
            **extra_fields,
        )

        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_user(self, email=None, password=None, **extra_fields):
        extra_fields.setdefault("is_staff", False)
        extra_fields.setdefault("is_superuser", False)
        return self._create_user(email, password, **extra_fields)

    def create_superuser(self, email=None, password=None, **extra_fields):
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)
        extra_fields.setdefault("is_verified", True)
        return self._create_user(email, password, **extra_fields)

class User(AbstractBaseUser, PermissionsMixin):
    email = models.EmailField(
        verbose_name="Email",
        max_length=255,
        unique=True,
    )
    first_name = models.CharField(max_length=100, default="", blank=True)
    last_name = models.CharField(max_length=100, default="", blank=True)
    gender = models.CharField(choices=GENDER_TYPE, max_length=40, blank=True)
    phone_number=models.CharField(max_length=15 , blank=True)
    is_verified=models.BooleanField(default=False)
    otp=models.CharField(max_length=6, blank=True)
    otp_expiry = models.DateTimeField(null=True, blank=True)
    image = models.ImageField(upload_to='accounts/images/', default='images/default.png' , blank=True, null=True)

    is_active = models.BooleanField(default=True)
    is_superuser = models.BooleanField(default=False)
    is_staff = models.BooleanField(default=False)

    date_joined = models.DateTimeField(default=timezone.now)
    last_login = models.DateTimeField(blank=True, null=True)

    objects = MyUserManager()

    USERNAME_FIELD = "email"
    EMAIL_FIELD = "email"
    REQUIRED_FIELDS = []

    class Meta:
        verbose_name = "User"
        verbose_name_plural = "Users"

    def __str__(self):
        return f" {self.first_name} ({self.email})"

    def get_full_name(self):
        return f"{self.first_name} {self.last_name}"
    
    def get_short_name(self):
        return self.first_name or self.email.split("@")[0]
