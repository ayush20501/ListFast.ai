from django.urls import path
from . import views

urlpatterns = [
    path('', views.index_view, name='index'),
    path('profile/', views.profile_view, name='profile'),
    path('image-enhancement/', views.image_enhancement_view, name='image-enhancement'),
    path('display-profile/', views.display_profile_view, name='display-profile'),
    path('ebay-auth/', views.ebay_auth_view, name='ebay-auth'),
    path('success/', views.success_view, name='success'),
    path('services/', views.services_view, name='services'),
    path('callback/', views.ebay_callback_view, name='ebay-callback'),
    path('ebay-login/', views.ebay_login_view, name='ebay-login'),
    path('single-item-listing/', views.single_item_listing_view, name='single-item-listing'),
    path('multi-item-listing/', views.multi_item_listing_view, name='multi-item-listing'),
    path('bundle-item-listing/', views.bundle_listing_view, name='bundle-listing'),
    path('logout/', views.logout_view, name='logout'),


    path('api/login/', views.LoginAPIView.as_view(), name='login'),
    path('api/profile/', views.ProfileAPIView.as_view(), name='profile'),
    path('api/auth-status/', views.AuthStatusAPIView.as_view(), name='auth-status'),
    path('api/total-listings/', views.TotalListingsAPIView.as_view(), name='total-listings'),
    path('api/user-stats/', views.UserStatsAPIView.as_view(), name='user-stats'),
    path('api/my-listings/', views.MyListingsAPIView.as_view(), name='my-listings'),
    path('api/fetch-address-imageprofile/', views.FetchAddressImageProfileAPIView.as_view(), name='fetch-address-imageprofile'),
    path('api/upload-profile-image/', views.UploadProfileImageAPIView.as_view(), name='upload-profile-image'),
    path('api/send-password-otp/', views.SendPasswordChangeOTPAPIView.as_view(), name='send-password-otp'),
    path('api/change-password/', views.ChangePasswordAPIView.as_view(), name='change-password'),
    path('api/signup/', views.SignupAPIView.as_view(), name='signup'),
    path('api/verify-otp/', views.VerifyOTPAPIView.as_view(), name='verify-otp'),
    path('api/resend-otp/', views.ResendOTPAPIView.as_view(), name='resend-otp'),
    path('api/revoke-ebay-auth/', views.RevokeeBayAuthAPIView.as_view(), name='revoke-ebay-auth'),
    path('api/format-description/', views.FormatDescriptionAPIView.as_view(), name='format-description'),
    path('api/enhance-image/', views.EnhanceImageAPIView.as_view(), name='enhance-image'),
    path('api/single-item-listing/', views.SingleItemListingAPIView.as_view(), name='single-item-listing'),
    path('api/multipack-listing/', views.MultipackListingAPIView.as_view(), name='multipack-listing'),
    path('api/bundle-listing/', views.BundleListingAPIView.as_view(), name='bundle-listing'),

    path('<path:invalid_path>', views.custom_404_view, name='custom_404'),
]