from django.urls import path,include
from . import views
from rest_framework.routers import DefaultRouter
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView,TokenVerifyView
router=DefaultRouter()

router.register('profile', views.UserProfileApiView, basename='profile')

urlpatterns = [
    path("register/",views.UserRegisationView.as_view(),name="regiser"),
    path("login/",views.LoginAPIView.as_view(),name="login"),
    path("", include(router.urls)),
    path('social_account/',include('allauth.urls')),
    path('api/token/',TokenObtainPairView.as_view(),name="token_obtain_pair"),
    path('api/token/refresh/',TokenRefreshView.as_view(),name='token_refresh'),
    path('api/token/verify/', TokenVerifyView.as_view(), name='token_verify'),
    path('callback/',views.google_login_call,name='callback'),
    path('api/google/validate_token/',views.validate_google_token,name='validate_token'),
    path('active/<uid64>/<token>/', views.activate, name = 'activate'),
    path('successful-email-verified/', views.successful, name='verified_success'),
    path('unsuccessful-email-verified/',views.unsuccessful, name='verified_unsuccess'),
    # path('send-otp-varification/')
    path("changepassword/",views.UserPasswordChangeApiView.as_view(),name="changepassword"),
    path("send-reset-password-email/",views.SendPasswordResetEmailApiView.as_view(), name="sendresetpasswordemail"),
    path("reset-password/<uid>/<token>/",views.UserPasswordResetApiView.as_view(), name="resetPassword"),
    path("logout/",views.LogoutAPIView.as_view(),name="logout"),
]
