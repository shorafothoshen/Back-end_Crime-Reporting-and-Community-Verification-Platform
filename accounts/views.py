from rest_framework.response import Response
from rest_framework import status
from rest_framework.generics import CreateAPIView
from rest_framework.views import APIView
from rest_framework import viewsets
from . import models
from django.conf import settings
from twilio.rest import Client
from django.contrib.auth import get_user_model
from django.shortcuts import render
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.exceptions import TokenError
from allauth.socialaccount.models import SocialAccount,SocialToken
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes
from django.core.mail import EmailMultiAlternatives
from django.template.loader import render_to_string
from django.shortcuts import redirect
from .models import User
import json
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.decorators import login_required
from rest_framework.authentication import SessionAuthentication
from rest_framework.permissions import IsAuthenticated,AllowAny
from django.contrib.auth import authenticate,login,logout
from datetime import datetime, timedelta
from .serializer import RegisterSerializer,LoginSerializer,UserProfileSerializer,UserPasswordChangeSerializer,SendPasswordResetEmailSerializer,UserPasswordResetSerializer
# Create your views here.
User=get_user_model()
import random
def generate_otp():
    return str(random.randint(100000, 999999))

class UserRegisationView(CreateAPIView):
    queryset = models.User.objects.all()
    permission_classes = [AllowAny]
    serializer_class = RegisterSerializer

    def post(self, request, format=None):
        serializer = RegisterSerializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            user = serializer.save()
            refresh = RefreshToken.for_user(user)
            access_token = str(refresh.access_token)
            return Response({
                "registrationStatus": "success",
                "access_token": access_token,
                "refresh_token": str(refresh)
            }, status=status.HTTP_201_CREATED)
        return Response({"error": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)

class SendOTPView(APIView):
    def post(self, request):
        phone_number = request.data.get('phone_number')
        user, created = User.objects.get_or_create(phone_number=phone_number)
        otp = generate_otp()
        user.otp = otp
        token_generator = PasswordResetTokenGenerator()
        token = token_generator.make_token(user) 
        uid = urlsafe_base64_encode(force_bytes(user.pk))
        confirm_link = f"https://online-school-989z.onrender.com/api/account/active/{uid}/{token}"
        email_subject = "Confirm Your Email"
        email_body = render_to_string('registation_confirm_email.html', {'confirm_link': confirm_link})
        email = EmailMultiAlternatives(email_subject, '', to=[user.email])
        email.attach_alternative(email_body, "text/html")
        email.send()   
        send_sms(phone_number,otp)
        user.otp_expiry = datetime.now() + timedelta(minutes=5)  # 5 minutes validity
        user.save()

        return Response({"message": "OTP sent successfully"}, status=status.HTTP_200_OK)

def send_sms(phone_number, otp):
    client = Client(settings.ACCOUNT_SID, settings.AUTH_TOKEN)

    message = client.messages.create(
        body=f"Your OTP code is {otp}. Please do not share it.",
        from_='+8801581602809',
        to=phone_number
    )
    return message.sid


class VerifyOTPView(APIView):
    def post(self, request):
        phone_number = request.data.get('phone_number')
        otp = request.data.get('otp')
        user = User.objects.filter(phone_number=phone_number).first()

        if user and user.otp == otp and user.otp_expiry > datetime.now():
            user.is_verified = True
            user.save()
            return Response({"message": "OTP verified successfully"}, status=status.HTTP_200_OK)
        else:
            return Response({"error": "Invalid OTP or expired"}, status=status.HTTP_400_BAD_REQUEST)

def activate(request, uid64, token):
    try:
        uid = urlsafe_base64_decode(uid64).decode()
        user = User._default_manager.get(pk=uid)
    except(User.DoesNotExist):
        user = None 
    
    if user is not None and PasswordResetTokenGenerator.check_token(user, token):
        user.is_verified = True
        user.save()
        return redirect('verified_success')
    else:
        return redirect('verified_unsuccess')

class LoginAPIView(APIView):
    serializer_class = LoginSerializer
    permission_classes = [AllowAny]
    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            password = serializer.validated_data['password']
            user = authenticate(request, email=email, password=password)
            if user is not None:
                refresh = RefreshToken.for_user(user)
                access_token = str(refresh.access_token)
                login(request, user)

                role = 'user'
                if user.is_superuser or user.is_staff:
                    role = 'admin'
                elif not user.is_active:
                    return Response({
                        'error': "Your account is not active. Please activate your account before logging in."
                    }, status=status.HTTP_403_FORBIDDEN)

                return Response({
                    'access_token': access_token,
                    'refresh_token': str(refresh),
                    'user_id': user.id,
                    'role': role
                }, status=status.HTTP_200_OK)
            else:
                return Response({'error': {"non_field_errors": ["Email or Password is not valid"]}}, status=status.HTTP_401_UNAUTHORIZED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@login_required
def google_login_call(request):
    user=request.user
    
    socialAccounts=SocialAccount.objects.filter(user=user)
    print("Social Account for User:", socialAccounts)

    socialaccount=socialAccounts.first()
    if not socialaccount:
        print("No social Account for user:", user)
        return redirect('http://localhost:5173/login/callback/?error=NoSocialAccount')

    token=SocialToken.objects.filter(account=socialaccount,account_providers='google').first()
    if token:
        print("google token found:",token.token)
        refresh=RefreshToken.for_user(user)
        access_token=str(refresh.access_token)
        return redirect(f'http://localhost:5173/login/callback/?access_token={access_token}')
    else:
        print("No google token found for user: ", user)
        return redirect(f'http://localhost:5173/login/callback/?error=NoGoogleToken')

@csrf_exempt
def validate_google_token(request):
    if request.method=="POST":
        try:
            data=json.loads(request.body)
            google_access_token=data.get('access_token')
            print("google_access_token: ",google_access_token)

            if not google_access_token:
                return Response({'detail':"Access token is missing"},status=400)
            return Response({"valid":True})
        except json.JSONDecodeError:
            return Response({'Invalid Json'},status=400)
    return Response({'Method is not allowed'}, status=405)


class UserProfileApiView(viewsets.ModelViewSet):
    queryset = models.User.objects.all()
    serializer_class = UserProfileSerializer
    authentication_classes=[SessionAuthentication]

class UserPasswordChangeApiView(APIView):
    serializer_class =UserPasswordChangeSerializer
    permission_classes=[IsAuthenticated]
    def post(self, request,format=None):
        serializer=UserPasswordChangeSerializer(data=request.data, context={"user":request.user})
        if serializer.is_valid():
            return Response({"msg":"Successfully Change Your Password"},status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class SendPasswordResetEmailApiView(APIView):
    serializer_class=SendPasswordResetEmailSerializer
    def post(self, request,format=None):
        serializer=SendPasswordResetEmailSerializer(data=request.data)
        if serializer.is_valid():
            return Response({"msg":"Password Reset Link Send. Please Check Your Email"},status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class UserPasswordResetApiView(APIView):
    serializer_class=UserPasswordResetSerializer
    def post(self,request,uid, token,format=None):
        serializer=UserPasswordResetSerializer(data=request.data, context={"uid":uid,"token":token})
        if serializer.is_valid():
            return Response({"msg":"Password Reset Successfully"},status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class LogoutAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        try:
            refresh_token = request.data["refresh_token"]
            token = RefreshToken(refresh_token)
            token.blacklist()
            logout(request)
            return Response({"msg": "Successfully logged out"}, status=status.HTTP_200_OK)
        except TokenError:
            return Response({"error": "Invalid token"}, status=status.HTTP_400_BAD_REQUEST)
def successful(request):
    return render(request, 'successful.html')

def unsuccessful(request):
    return render(request, 'unsuccessful.html')
