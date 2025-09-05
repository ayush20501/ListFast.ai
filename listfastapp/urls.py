from django.urls import path
from . import views

urlpatterns = [
    path('', views.IndexView.as_view(), name='index'),
    path('profile/', views.ProfileView.as_view(), name='profile'),
    path('profile/', views.ProfileAPIView.as_view(), name='profile-api'),  # Changed from 'api/profile/'
    path('ebay-login/', views.eBayLoginView.as_view(), name='ebay-login'),
    path('callback/', views.eBayCallbackView.as_view(), name='ebay-callback'),
    path('image-enhancement/', views.ImageEnhancementView.as_view(), name='image-enhancement'),
    path('display-profile/', views.DisplayProfileView.as_view(), name='display-profile'),
    path('ebay-auth/', views.eBayAuthView.as_view(), name='ebay-auth'),
    path('single-item-listing/', views.SingleItemListingView.as_view(), name='single-item-listing'),
    path('success/', views.SuccessView.as_view(), name='success'),
    path('services/', views.ServicesView.as_view(), name='services'),
    path('api/auth/login/', views.LoginView.as_view(), name='login'),
    path('logout/', views.LogoutView.as_view(), name='logout'),  # Changed from 'api/logout/'
    path('auth-status/', views.AuthStatusView.as_view(), name='auth-status'),  # Changed from 'api/auth-status/'
    path('publish-item/', views.PublishItemView.as_view(), name='publish-item'),  # Changed from 'api/publish-item/'
    path('total-listings/', views.TotalListingsView.as_view(), name='total-listings'),  # Changed from 'api/total-listings/'
    path('user-stats/', views.UserStatsView.as_view(), name='user-stats'),  # Changed from 'api/user-stats/'
    path('my-listings/', views.MyListingsView.as_view(), name='my-listings'),  # Changed from 'api/my-listings/'
    path('upload-profile-image/', views.UploadProfileImageView.as_view(), name='upload-profile-image'),  # Changed from 'api/upload-profile-image/'
    path('send-password-otp/', views.SendPasswordChangeOTPView.as_view(), name='send-password-otp'),  # Changed from 'api/send-password-otp/'
    path('change-password/', views.ChangePasswordView.as_view(), name='change-password'),  # Changed from 'api/change-password/'
    path('api/auth/signup/', views.SignupView.as_view(), name='signup'),  # Changed from 'api/signup/'
    path('api/auth/verify-otp/', views.VerifyOTPView.as_view(), name='verify-otp'),  # Changed from 'api/verify-otp/'
    path('api/auth/resend-otp/', views.ResendOTPView.as_view(), name='resend-otp'),  # Changed from 'api/resend-otp/'
    path('revoke-ebay-auth/', views.RevokeeBayAuthView.as_view(), name='revoke-ebay-auth'),  # Changed from 'api/revoke-ebay-auth/'
    path('format-description/', views.FormatDescriptionView.as_view(), name='format-description'),  # Changed from 'api/format-description/'
    path('enhance-image/', views.EnhanceImageView.as_view(), name='enhance-image'),  # Changed from 'api/enhance-image/'
]