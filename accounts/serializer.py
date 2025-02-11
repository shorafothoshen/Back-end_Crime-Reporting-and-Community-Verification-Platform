from rest_framework import serializers
from .models import User
from django.utils.encoding import smart_str,force_bytes
from django.utils.http import urlsafe_base64_decode,urlsafe_base64_encode
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.core.mail import EmailMultiAlternatives
from django.template.loader import render_to_string

class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(style={"input_type":"password"}, write_only=True, required=True)
    confirm_password = serializers.CharField(style={"input_type":"password"}, write_only=True, required=True)
    
    class Meta:
        model = User
        fields = ['first_name', 'last_name', 'email', 'gender','phone_number', 'password', 'confirm_password']
        
    def save(self):
        first_name = self.validated_data['first_name']
        last_name = self.validated_data['last_name']
        gender=self.validated_data["gender"]
        email = self.validated_data['email']
        phone_number=self.validated_data["phone_number"]
        password = self.validated_data['password']
        password2 = self.validated_data['confirm_password']
        
        if password != password2:
            raise serializers.ValidationError({'error' : "Password Doesn't Mactched"})
        if User.objects.filter(email=email).exists():
            raise serializers.ValidationError({'error' : "Email Already exists"})
        account = User(email=email, first_name = first_name, last_name = last_name,gender=gender ,phone_number=phone_number)
        account.set_password(password)
        account.save()
        return account
    
class LoginSerializer(serializers.ModelSerializer):
    email=serializers.EmailField(max_length=255,required=True)
    password = serializers.CharField(style={"input_type":"password"}, write_only=True, required=True)
    class Meta:
        model=User
        fields=["email","password"]

class UserProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model=User
        fields=['id','first_name', 'last_name', 'email', 'gender','phone_number',"image"]


class UserPasswordChangeSerializer(serializers.Serializer):
    password = serializers.CharField(style={"input_type":"password"}, write_only=True, required=True)
    confirm_password = serializers.CharField(style={"input_type":"password"}, write_only=True, required=True)
    class Meta:
        fields=["password","confirm_password"]
    
    def validate(self, attrs):
        password=attrs.get("password")
        confirm_password=attrs.get("confirm_password")
        user=self.context.get("user")
        if password != confirm_password:
            raise serializers.ValidationError({'error' : "Password Doesn't Mactched"})
        user.set_password(password)
        user.save()
        return attrs
    
class SendPasswordResetEmailSerializer(serializers.Serializer):
    email=serializers.EmailField(max_length=255,required=True)
    class Meta:
        fields=["email"]

    def validate(self, attrs):
        email=attrs.get("email")
        if User.objects.filter(email=email).exists():
            user=User.objects.get(email=email)
            uid=urlsafe_base64_encode(force_bytes(user.id))
            print("User UID:", uid)
            token=PasswordResetTokenGenerator().make_token(user)
            print("User Token: ", token)
            link="https://eradicat-crimes-b8w4.onrender.com/api/account/"+uid+"/"+token
            email_subject = "Change Password"
            email_body = render_to_string('registation_confirm_email.html', {'confirm_link' : link})
            email = EmailMultiAlternatives(email_subject , '', to=[user.email])
            email.attach_alternative(email_body, "text/html")
            email.send()
            return attrs
        else:
            raise ValueError("You are a Register User")
        
class UserPasswordResetSerializer(serializers.Serializer):
    password = serializers.CharField(style={"input_type":"password"}, write_only=True, required=True)
    confirm_password = serializers.CharField(style={"input_type":"password"}, write_only=True, required=True)
    class Meta:
        fields=["password","confirm_password"]
    
    def validate(self, attrs):
        password=attrs.get("password")
        confirm_password=attrs.get("confirm_password")
        uid=self.context.get("uid")
        token=self.context.get("token")
        if password != confirm_password:
            raise serializers.ValidationError({'error' : "Password Doesn't Mactched"})
        id=smart_str(urlsafe_base64_decode(uid))
        user=User.objects.get(id=id)
        if not PasswordResetTokenGenerator().check_token(user, token):
            raise serializers.ValidationError("Token is not Valid")
        user.set_password(password)
        user.save()
        return attrs