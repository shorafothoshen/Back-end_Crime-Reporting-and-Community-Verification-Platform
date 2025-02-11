from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from .models import User

class UserModelAdmin(BaseUserAdmin):
    list_display = ('email', 'first_name', 'last_name','is_staff', 'is_superuser')
    list_filter = ('is_staff', 'is_superuser')
    
    fieldsets = (
        ("User Credentials", {"fields": ("email", "password")}),
        ('Personal info', {'fields': ('first_name', 'last_name', 'gender','phone_number','is_verified','otp','image')}),
        ('Permissions', {'fields': ('is_active', 'is_staff', 'is_superuser', 'groups', 'user_permissions')}),
        ('Important dates', {'fields': ('last_login', 'date_joined')}),
    )
    
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('email', 'first_name', 'last_name', 'gender','phone_number', 'password1', 'password2', 'is_active', 'is_staff', 'is_superuser'),
        }),
    )
    search_fields = ('email', 'first_name', 'last_name')
    ordering = ('email', 'id')
    filter_horizontal = ('groups', 'user_permissions')


admin.site.register(User, UserModelAdmin)
