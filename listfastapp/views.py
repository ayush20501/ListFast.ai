from decimal import Decimal
import io
import os
import random
import logging
from datetime import datetime, timedelta
from urllib.parse import quote
from PIL import Image, ImageDraw
from rest_framework.response import Response
import requests
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import User
from django.core.mail import EmailMultiAlternatives
from django.http import HttpResponseRedirect, JsonResponse, HttpResponse
from django.shortcuts import render, redirect
from django.urls import reverse
from django.utils import timezone
from rest_framework import status
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated
from rest_framework.serializers import Serializer, CharField, DecimalField, IntegerField, ChoiceField, ListField, URLField
from decouple import config
from .models import UserProfile, eBayToken, OTP, ListingCount, UserListing, TaskRecord, Plan, UserPlan, CreditPurchase, CreditPackage, RefundRequest, Order, NewsletterSubscriber, ContactFormSubmission
from .tasks import create_single_item_listing_task, create_multipack_listing_task, create_bundle_listing_task
from . import helpers
import uuid
from PIL import Image, ImageDraw, ImageFile
from django.contrib.auth.decorators import login_required
from django.db.models import F, Sum, ExpressionWrapper, DecimalField as ModelDecimalField
from django.utils.timezone import now
from django.contrib.auth import get_user_model
from django.db import transaction
import stripe


EBAY_ENV = config("EBAY_ENV", default="PRODUCTION")
BASE = config("EBAY_BASE")
AUTH = config("EBAY_AUTH")
TOKEN = config("EBAY_TOKEN_URL")
API = config("EBAY_API")
MARKETPLACE_ID = config("EBAY_MARKETPLACE_ID")
LANG = config("EBAY_LANG")
CLIENT_ID = config("EBAY_CLIENT_ID")
CLIENT_SECRET = config("EBAY_CLIENT_SECRET")
RU_NAME = config("EBAY_RU_NAME")

EMAIL_HOST = config("EMAIL_HOST")
EMAIL_USER = config("EMAIL_USER")
EMAIL_PASS = config("EMAIL_PASS")
EMAIL_PORT = config("EMAIL_PORT", cast=int)

OPENAI_API_KEY = config("OPENAI_API_KEY", default="")
IMGBB_API_KEY = config("IMGBB_API_KEY", default="")

REMBG_API_KEY = config("REMBG_API_KEY", default="")
REMBG_API_URL = config("REMBG_API_URL", default="")
SECRET_KEY = config("SECRET_KEY")
STRIPE_SECRET_KEY = config("STRIPE_SECRET_KEY", default="")
SITE_BASE_URL = config("SITE_BASE_URL", default="http://localhost:8000")
stripe.api_key = STRIPE_SECRET_KEY


SCOPES = " ".join([
    "https://api.ebay.com/oauth/api_scope",
    "https://api.ebay.com/oauth/api_scope/sell.inventory",
    "https://api.ebay.com/oauth/api_scope/sell.account",
])
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}
MAX_FILE_SIZE = 5 * 1024 * 1024
IMGBB_UPLOAD_URL = 'https://api.imgbb.com/1/upload'
SMALL_WORDS = {
    "a", "an", "the", "and", "or", "nor", "but", "for", "so", "yet",
    "at", "by", "in", "of", "on", "to", "up", "off", "as", "if",
    "per", "via", "vs", "vs."
}
MAX_LEN = 30

AWS_ACCESS_KEY = config("AWS_ACCESS_KEY")
AWS_SECRET_KEY = config("AWS_SECRET_KEY")
S3_BUCKET = config("S3_BUCKET")
AWS_REGION = config("AWS_REGION")

ImageFile.LOAD_TRUNCATED_IMAGES = True

# Serializers
class ProfileSerializer(Serializer):
    address_line1 = CharField(max_length=200, min_length=1)
    city = CharField(max_length=100, min_length=1)
    postal_code = CharField(max_length=20, min_length=1)
    country = CharField(max_length=2, default="GB")
    profile_pic_url = URLField(required=False, allow_blank=True)

class PriceSerializer(Serializer):
    value = DecimalField(max_digits=10, decimal_places=2, min_value=Decimal("0.01"))
    currency = ChoiceField(choices=["GBP", "USD", "EUR"])


class ListingSerializer(Serializer):
    raw_text = CharField(max_length=8000, min_length=1)
    images = ListField(child=URLField(), max_length=12, required=False)
    price = PriceSerializer() 
    quantity = IntegerField(min_value=1, max_value=999)
    condition = ChoiceField(choices=["NEW", "USED", "REFURBISHED"], required=False)


def index_view(request):
    return render(request, 'index.html')

@login_required
def profile_view(request):
    return render(request, 'profile.html')

@login_required
def image_enhancement_view(request):
    return render(request, 'image-enhancement.html')

@login_required
def display_profile_view(request):
    return render(request, 'display-profile.html')

@login_required
def ebay_auth_view(request):
    return render(request, 'ebay-auth.html')

@login_required
def single_item_listing_view(request):
    try:
        UserProfile.objects.get(user=request.user)
        has_profile = True
    except UserProfile.DoesNotExist:
            has_profile = False
        
    try:
        token = eBayToken.objects.get(user=request.user)
        has_ebay_auth = bool(token.refresh_token)
    except eBayToken.DoesNotExist:
        has_ebay_auth = False
    
    if not has_profile:
        return redirect('profile')
    
    if not has_ebay_auth:
        return redirect('ebay-auth')
    
    return render(request, 'single-item-listing.html')

@login_required
def success_view(request):
    return render(request, 'success.html')

@login_required
def single_listing_success_view(request):
    return render(request, 'single-listing-success.html')

@login_required
def services_view(request):
    return render(request, 'services.html')

def about_us(request):
    return render(request, 'about-us.html')

def blogs_resources(request):
    return render(request, 'blogs-resources.html')

def features(request):
    return render(request, 'features.html')

def contact(request):
    return render(request, 'contact.html')

def legal(request):
    return render(request, 'legal.html')

def faq(request):
    return redirect('pricing')
    
def pricing_view(request):
    plans = Plan.objects.filter(code__in=["FREE", "PRO", "BUSINESS"]).order_by("monthly_quota")
    context = {
        "plans": plans,
        "one_off": {
            "credits": 30,
            "price": 7.99,
        }
    }
    return render(request, 'pricing.html', context)

@login_required
def multi_item_listing_view(request):
    try:
        UserProfile.objects.get(user=request.user)
        has_profile = True
    except UserProfile.DoesNotExist:
        has_profile = False
        
    try:
        token = eBayToken.objects.get(user=request.user)
        has_ebay_auth = bool(token.refresh_token)
    except eBayToken.DoesNotExist:
        has_ebay_auth = False
    
    if not has_profile:
        return redirect('profile')
    
    if not has_ebay_auth:
        return redirect('ebay-auth')
    
    return render(request, 'multi-item-listing.html')

@login_required
def bundle_listing_view(request):
    try:
        UserProfile.objects.get(user=request.user)
        has_profile = True
    except UserProfile.DoesNotExist:
        has_profile = False
        
    try:
        token = eBayToken.objects.get(user=request.user)
        has_ebay_auth = bool(token.refresh_token)
    except eBayToken.DoesNotExist:
        has_ebay_auth = False
    
    if not has_profile:
        return redirect('profile')
    
    if not has_ebay_auth:
        return redirect('ebay-auth')
    
    return render(request, 'bundle-listing.html')

def custom_404_view(request, invalid_path):
    return render(request, '404.html', status=404)

def logout_view(request):
    logout(request) 
    return redirect('index') 

def ebay_callback_view(request):
    code = request.GET.get("code")
    if not code:
        return HttpResponse("Missing authorization code", status=400)

    try:
        r = requests.post(
            TOKEN,
            headers={
                "Authorization": helpers._b64_basic(),
                "Content-Type": "application/x-www-form-urlencoded",
            },
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": RU_NAME,
            },
        )
        r.raise_for_status()
        data = r.json()

        eBayToken.objects.update_or_create(
            user=request.user,
            defaults={
                "access_token": data["access_token"],
                "refresh_token": data.get("refresh_token"),
                "expires_at": helpers._now() + data["expires_in"],
                "updated_at": timezone.now(),
            },
        )
        return HttpResponseRedirect("/ebay-auth/?ebay_auth=success")

    except Exception as e:
        print(f"eBay auth error: {e}")
        return HttpResponseRedirect("/ebay-auth/?error=auth_failed")

def ebay_login_view(request):
    try:
        profile = request.user.userprofile
    except UserProfile.DoesNotExist:
        return JsonResponse({"error": "Please create your profile first"}, status=400)

    scope_enc = quote(SCOPES, safe="")
    ru_enc = quote(RU_NAME, safe="")

    url = (
        f"{AUTH}/oauth2/authorize"
        f"?client_id={CLIENT_ID}"
        f"&response_type=code"
        f"&redirect_uri={ru_enc}"
        f"&scope={scope_enc}"
        f"&state=xyz123"
    )

    if request.session.get("force_ebay_login"):
        url += "&prompt=login"

    print(url)
    return redirect(url)

class LoginAPIView(APIView):
    def post(self, request):
        email = request.data.get("email", "").strip().lower()
        password = request.data.get("password", "")
        if not email or not password:
            return Response({"error": "Email and password are required"}, status=400)
        user = authenticate(request, username=email, password=password)
        if not user:
            return Response({"error": "Invalid email or password"}, status=401)
        if not user.is_active:
            return Response({"error": "Account is inactive"}, status=403)
        login(request, user)
        
        return Response({
            "status": "success",
            "message": "Logged in successfully",
            "redirect": reverse('services')
        })


class ProfileAPIView(APIView):
    def get(self, request):
        try:
            profile = UserProfile.objects.get(user=request.user)
            return Response({
                "profile": {
                    "user_id": profile.user_id,
                    "address_line1": profile.address_line1,
                    "city": profile.city,
                    "postal_code": profile.postal_code,
                    "country": profile.country,
                    "profile_pic_url": profile.profile_pic_url,
                    "created_at": profile.created_at,
                    "updated_at": profile.updated_at
                }
            })
        except UserProfile.DoesNotExist:
            return Response({"profile": None})

    def post(self, request):
        serializer = ProfileSerializer(data=request.data)
        if not serializer.is_valid():
            return Response({"error": "Invalid profile data", "details": serializer.errors}, status=400)
        try:
            UserProfile.objects.update_or_create(
                user=request.user,
                defaults={
                    "address_line1": serializer.validated_data["address_line1"],
                    "city": serializer.validated_data["city"],
                    "postal_code": serializer.validated_data["postal_code"].upper(),
                    "country": serializer.validated_data["country"],
                    "profile_pic_url": serializer.validated_data.get("profile_pic_url")
                }
            )
            return Response({"status": "success", "message": "Profile created successfully"})
        except Exception as e:
            return Response({"error": "Failed to save profile"}, status=500)

class AuthStatusAPIView(APIView):
    def get(self, request):
        if not request.user.is_authenticated:
            return Response({
                "is_logged_in": False,
                "has_profile": False,
                "has_ebay_auth": False
            })
        try:
            profile = UserProfile.objects.get(user=request.user)
            has_profile = True
        except UserProfile.DoesNotExist:
            has_profile = False
        try:
            token = eBayToken.objects.get(user=request.user)
            has_ebay_auth = bool(token.refresh_token)
            access_exp_in = max(0, int(token.expires_at - helpers._now())) if token.access_token else 0
        except eBayToken.DoesNotExist:
            has_ebay_auth = False
            access_exp_in = 0
        return Response({
            "is_logged_in": True,
            "is_active": request.user.is_active,
            "email": request.user.email,
            "has_profile": has_profile,
            "has_ebay_auth": has_ebay_auth,
            "access_exp_in": access_exp_in
        })

class TotalListingsAPIView(APIView):
    def get(self, request):
        listing_count, _ = ListingCount.objects.get_or_create(id=1, defaults={"total_count": 0})
        return Response({"total_listings": listing_count.total_count})

class UserStatsAPIView(APIView):
    def get(self, request):
        try:
            UserProfile.objects.get(user=request.user)
        except UserProfile.DoesNotExist:
            return Response({"error": "Please create your profile first", "redirect": "profile"},status=status.HTTP_400_BAD_REQUEST)

        try:
            token = eBayToken.objects.get(user=request.user)
            if not token.refresh_token:
                return Response({"error": "Please authenticate with eBay first", "redirect": "ebay-auth"},status=status.HTTP_400_BAD_REQUEST)
        except eBayToken.DoesNotExist:
            return Response({"error": "Please authenticate with eBay first", "redirect": "ebay-auth"},status=status.HTTP_400_BAD_REQUEST)

        listings_qs = UserListing.objects.filter(user=request.user)
        total_listings = listings_qs.count()
        active_count = listings_qs.filter(status='ACTIVE').count()
        total_value_agg = listings_qs.aggregate(
            total=Sum(
                ExpressionWrapper(
                    (F('price_value') * F('quantity')),
                    output_field=ModelDecimalField(max_digits=18, decimal_places=2)
                )
            )
        )['total'] or 0
        usage = helpers._get_user_usage_snapshot(request.user)
        return Response({
            "total_listings": total_listings,
            "active_listings": active_count,
            "total_inventory_value": float(total_value_agg),
            "email": request.user.email,
            "usage": usage,
        })

class MyListingsAPIView(APIView):
    def get(self, request):
        page = int(request.query_params.get('page', 1))
        limit = 20
        offset = (page - 1) * limit
        listings = UserListing.objects.filter(user=request.user).order_by('-created_at')[offset:offset + limit]
        return Response({
            "listings": [{
                'listing_id': l.listing_id,
                'offer_id': l.offer_id,
                'sku': l.sku,
                'title': l.title,
                'price_value': float(l.price_value) if l.price_value else 0,
                'price_currency': l.price_currency,
                'quantity': l.quantity,
                'condition': l.condition,
                'category_name': l.category_name,
                'view_url': l.view_url,
                'status': l.status,
                'created_at': l.created_at.isoformat() if l.created_at else None
            } for l in listings],
            "page": page,
            "has_more": len(listings) == limit
        })

class FetchAddressImageProfileAPIView(APIView):
    def get(self, request):
        try:
            profile = UserProfile.objects.get(user=request.user)
            profile_data = {
                'address_line1': profile.address_line1,
                'city': profile.city,
                'postal_code': profile.postal_code,
                'country': profile.country
            }
            return Response(profile_data, status=status.HTTP_200_OK)
        except UserProfile.DoesNotExist:
            return Response({'error': 'User profile not found'},status=status.HTTP_404_NOT_FOUND)


class SendPasswordChangeOTPAPIView(APIView):
    def post(self, request):
        otp = str(random.randint(100000, 999999))
        expires_at = timezone.now() + timedelta(seconds=600)
        OTP.objects.filter(user=request.user).delete()
        OTP.objects.create(user=request.user, otp=otp, expires_at=expires_at)
        body = f"""
        <html>
            <body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 30px; text-align: center;">
                    <h1 style="color: white; margin: 0;">ListFast.ai</h1>
                </div>
                <div style="padding: 40px 30px; background: #f9f9f9;">
                    <h2 style="color: #333; margin-bottom: 20px;">Password Reset Request</h2>
                    <p style="color: #666; font-size: 16px; line-height: 1.6;">
                        Use the OTP below to reset your password:
                    </p>
                    <div style="background: white; padding: 30px; border-radius: 10px; text-align: center; margin: 30px 0;">
                        <div style="font-size: 32px; font-weight: bold; color: #667eea; letter-spacing: 8px; font-family: monospace;">
                            {otp}
                        </div>
                        <p style="color: #888; font-size: 14px; margin-top: 15px;">
                            This OTP is valid for 10 minutes.
                        </p>
                    </div>
                    <p style="color: #666; font-size: 14px;">
                        If you did not request this, contact <a href="mailto:rahul@listfast.ai">rahul@listfast.ai</a>.
                    </p>
                </div>
                <div style="background: #333; padding: 20px; text-align: center;">
                    <p style="color: #999; margin: 0; font-size: 12px;">
                        © 2025 ListFast.ai. All rights reserved.
                    </p>
                </div>
            </body>
        </html>
        """
        msg = EmailMultiAlternatives(
            subject="ListFast.ai Password Reset OTP",
            body="Your OTP is: " + otp,
            from_email=os.getenv("EMAIL_USER"),
            to=[request.user.email]
        )
        msg.attach_alternative(body, "text/html")
        try:
            msg.send()
            return Response({"status": "success", "message": "Verification code sent"})
        except Exception as e:
            return Response({"error": "Failed to send verification code"}, status=500)

class ChangePasswordAPIView(APIView):
    def post(self, request):
        otp = request.data.get("otp", "").strip()
        new_password = request.data.get("new_password", "").strip()
        if not otp or len(otp) != 6 or not otp.isdigit():
            return Response({"error": "Invalid 6-digit verification code"}, status=400)
        if len(new_password) < 6:
            return Response({"error": "Password must be at least 6 characters"}, status=400)
        try:
            otp_record = OTP.objects.get(user=request.user, otp=otp)
            if otp_record.expires_at < timezone.now():
                return Response({"error": "Verification code expired"}, status=400)
            request.user.set_password(new_password)
            request.user.save()
            OTP.objects.filter(user=request.user).delete()
            return Response({"status": "success", "message": "Password updated successfully"})
        except OTP.DoesNotExist:
            return Response({"error": "Invalid or expired verification code"}, status=400)

class SignupAPIView(APIView):
    def post(self, request):
        email = request.data.get("email", "").strip().lower()
        password = request.data.get("password", "")
        if not email or not password:
            return Response({"error": "Email and password are required"}, status=400)
        if len(password) < 6:
            return Response({"error": "Password must be at least 6 characters"}, status=400)
        if User.objects.filter(email=email).exists():
            return Response({"error": "User with this email already exists"}, status=400)
        otp = str(random.randint(100000, 999999))
        request.session['signup_data'] = {'email': email, 'password': password, 'otp': otp, 'timestamp': timezone.now().isoformat(), 'attempts': 0}
        body = f"""
        <html>
            <body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 30px; text-align: center;">
                    <h1 style="color: white; margin: 0;">ListFast.ai</h1>
                </div>
                <div style="padding: 40px 30px; background: #f9f9f9;">
                    <h2 style="color: #333; margin-bottom: 20px;">Welcome to ListFast.ai!</h2>
                    <p style="color: #666; font-size: 16px; line-height: 1.6;">
                        Use the verification code below to complete your registration:
                    </p>
                    <div style="background: white; padding: 30px; border-radius: 10px; text-align: center; margin: 30px 0;">
                        <div style="font-size: 32px; font-weight: bold; color: #667eea; letter-spacing: 8px; font-family: monospace;">
                            {otp}
                        </div>
                        <p style="color: #888; font-size: 14px; margin-top: 15px;">
                            This code will expire in 10 minutes
                        </p>
                    </div>
                    <p style="color: #666; font-size: 14px;">
                        If you didn't request this code, please ignore this email.
                    </p>
                </div>
                <div style="background: #333; padding: 20px; text-align: center;">
                    <p style="color: #999; margin: 0; font-size: 12px;">
                        © 2025 ListFast.ai. All rights reserved.
                    </p>
                </div>
            </body>
        </html>
        """
        msg = EmailMultiAlternatives(
            subject="ListFast.ai Verification Code",
            body="Your OTP is: " + otp,
            from_email=os.getenv("EMAIL_USER"),
            to=[email]
        )
        msg.attach_alternative(body, "text/html")
        try:
            msg.send()
            return Response({'message': 'Verification code sent to your email'})
        except Exception as e:
            print(f"[Registration] Error sending verification email: {str(e)}")
            return Response({"error": "Failed to send verification email. Please try again later."}, status=500)

class VerifyOTPAPIView(APIView):
    def post(self, request):
        email = request.data.get('email', '').strip().lower()
        submitted_otp = request.data.get('otp', '')
        signup_data = request.session.get('signup_data', {})
        if not email or not submitted_otp:
            return Response({'error': 'Email and OTP are required'}, status=400)
        if email != signup_data.get('email'):
            return Response({'error': 'No verification code found'}, status=400)
        if datetime.fromisoformat(signup_data['timestamp']) < timezone.now() - timedelta(minutes=10):
            request.session.pop('signup_data', None)
            return Response({'error': 'Verification code expired'}, status=400)
        if signup_data.get('attempts', 0) >= 5:
            request.session.pop('signup_data', None)
            return Response({'error': 'Too many incorrect attempts'}, status=400)
        if submitted_otp != signup_data['otp']:
            signup_data['attempts'] = signup_data.get('attempts', 0) + 1
            request.session['signup_data'] = signup_data
            return Response({'error': 'Invalid verification code'}, status=400)
        try:
            user = User.objects.create_user(
                username=email,
                email=email,
                password=signup_data['password']
            )
            user.is_active = True
            user.save()
            login(request, user)
            try:
                helpers._ensure_default_free_plan(user)
            except Exception:
                pass
            request.session.pop('signup_data', None)
            
            try:
                youtube_video_link = "https://www.youtube.com/watch?v=nN_qZ81V4y8" 
                
                subject = "Welcome to ListFast.ai 🎉"
                body_html = f"""
                <html>
                    <body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; background: #f9f9f9;">
                        <div style="width: 100%; overflow: hidden;">
                            <img src="https://i.ibb.co/XxYB2v7g/066f480f-54d1-23f3-bb62-83225a12a32f.jpg" 
                                 alt="Welcome to ListFast.ai" 
                                 style="width: 100%; max-width: 600px; height: auto; display: block;">
                        </div>
                        
                        
                        <div style="padding: 40px 30px; background: white;">
                            <h2 style="color: #333; font-size: 24px; margin-bottom: 20px;">
                                Welcome to ListFast.ai 🎉 — you're just one step away from creating your first lightning-fast eBay listing.
                            </h2>
                            
                            <p style="color: #666; font-size: 16px; line-height: 1.8; margin: 20px 0;">
                                To make sure your listings publish correctly, you'll need to set up <strong>eBay Business Policies</strong> (shipping, returns, and payment). Don't worry — it only takes a few minutes.
                            </p>
                            
                            <p style="color: #666; font-size: 16px; line-height: 1.8; margin: 20px 0;">
                                👉 We've created a simple video guide to walk you through it:
                            </p>
                            
                            <div style="text-align: center; margin: 30px 0;">
                                <a href="{youtube_video_link}" 
                                   style="display: inline-block; background: #FF0000; color: white; padding: 15px 30px; text-decoration: none; border-radius: 8px; font-weight: bold; font-size: 16px;">
                                    📺 Watch the setup video on YouTube
                                </a>
                            </div>
                            
                            <p style="color: #666; font-size: 16px; line-height: 1.8; margin: 20px 0;">
                                Once you're done, you'll be ready to:
                            </p>
                            
                            <div style="background: #f0f7ff; padding: 25px; border-radius: 10px; border-left: 4px solid #667eea; margin: 25px 0;">
                                <p style="margin: 0 0 12px 0; color: #333; font-size: 16px; line-height: 1.8;">
                                    🚀 <strong>Create listings in under 60 seconds</strong>
                                </p>
                                <p style="margin: 0 0 12px 0; color: #333; font-size: 16px; line-height: 1.8;">
                                    🖼️ <strong>Enhance product images automatically</strong>
                                </p>
                                <p style="margin: 0; color: #333; font-size: 16px; line-height: 1.8;">
                                    🔎 <strong>Publish eBay-compliant listings with AI-optimized titles & descriptions</strong>
                                </p>
                            </div>
                            
                            <hr style="border: none; border-top: 1px solid #e5e7eb; margin: 30px 0;">
                            
                            <p style="color: #666; font-size: 15px; line-height: 1.6; margin: 20px 0;">
                                If you need any help, reply to this email or reach us at 
                                <a href="mailto:rahul@listfast.ai" style="color: #667eea; text-decoration: none; font-weight: bold;">rahul@listfast.ai</a> 
                                — we're here for you.
                            </p>
                            
                            <p style="color: #666; font-size: 15px; line-height: 1.6; margin: 20px 0;">
                                <strong>Happy selling,</strong><br>
                                The ListFast.ai Team
                            </p>
                        </div>
                        
                        <!-- Footer -->
                        <div style="background: #333; padding: 20px; text-align: center;">
                            <p style="color: #999; margin: 0; font-size: 12px;">© 2025 ListFast.ai. All rights reserved.</p>
                        </div>
                    </body>
                </html>
                """
                
                msg = EmailMultiAlternatives(
                    subject=subject,
                    body="Welcome to ListFast.ai! You're just one step away from creating your first lightning-fast eBay listing.",
                    from_email=EMAIL_USER,
                    to=[email]
                )
                msg.attach_alternative(body_html, "text/html")
                msg.send()
                
                logging.info(f"Welcome email sent to {email}")
            except Exception as e:
                logging.error(f"Failed to send welcome email to {email}: {str(e)}")
            
            return Response({
                'message': 'Email verified successfully! Account created.',
                'user_id': user.id
            })
        except Exception as e:
            return Response({'error': 'Account creation failed'}, status=500)

class ResendOTPAPIView(APIView):
    def post(self, request):
        email = request.data.get('email', '').strip().lower()
        signup_data = request.session.get('signup_data', {})
        if email != signup_data.get('email'):
            return Response({'error': 'No pending verification for this email'}, status=400)
        if datetime.fromisoformat(signup_data['timestamp']) > timezone.now() - timedelta(minutes=1):
            return Response({'error': 'Please wait before requesting a new code'}, status=429)
        new_otp = str(random.randint(100000, 999999))
        signup_data.update({
            'otp': new_otp,
            'timestamp': timezone.now().isoformat(),
            'attempts': 0
        })
        request.session['signup_data'] = signup_data
        body = f"""
        <html>
            <body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 30px; text-align: center;">
                    <h1 style="color: white; margin: 0;">ListFast.ai</h1>
                </div>
                <div style="padding: 40px 30px; background: #f9f9f9;">
                    <h2 style="color: #333; margin-bottom: 20px;">Welcome to ListFast.ai!</h2>
                    <p style="color: #666; font-size: 16px; line-height: 1.6;">
                        Use the new verification code below to complete your registration:
                    </p>
                    <div style="background: white; padding: 30px; border-radius: 10px; text-align: center; margin: 30px 0;">
                        <div style="font-size: 32px; font-weight: bold; color: #667eea; letter-spacing: 8px; font-family: monospace;">
                            {new_otp}
                        </div>
                        <p style="color: #888; font-size: 14px; margin-top: 15px;">
                            This code will expire in 10 minutes
                        </p>
                    </div>
                    <p style="color: #666; font-size: 14px;">
                        If you didn't request this code, please ignore this email.
                    </p>
                </div>
                <div style="background: #333; padding: 20px; text-align: center;">
                    <p style="color: #999; margin: 0; font-size: 12px;">
                        © 2025 ListFast.ai. All rights reserved.
                    </p>
                </div>
            </body>
        </html>
        """
        msg = EmailMultiAlternatives(
            subject="ListFast.ai Verification Code",
            body="Your OTP is: " + new_otp,
            from_email=os.getenv("EMAIL_USER"),
            to=[email]
        )
        msg.attach_alternative(body, "text/html")
        try:
            msg.send()
            return Response({'message': 'New verification code sent'})
        except Exception:
            return Response({"error": "Failed to send verification email"}, status=500)

class RevokeeBayAuthAPIView(APIView):
    def post(self, request):
        print("Revoking eBay authentication")
        eBayToken.objects.filter(user=request.user).delete()
        request.session['force_ebay_login'] = True
        return Response({"status": "success", "message": "eBay authentication revoked"})

class FormatDescriptionAPIView(APIView):
    def post(self, request):
        text = request.data.get('text', '').strip()
        if not text:
            return Response({"error": "No text provided"}, status=400)
        try:
            prompt = (
                "Convert the following plain text into clean, well-structured HTML. "
                "Use ONLY <p>, <ul>, <li>, <strong>, <em>, <br> tags. "
                f"Plain text: {text}"
            )
            html_description = helpers.call_llm_text_simple(prompt, system_prompt="Return only HTML. No prose.")
            return Response({"html": html_description})
        except Exception as e:
            return Response({"error": f"Failed to format description: {str(e)}"}, status=500)

class EnhanceImageAPIView(APIView):
    def post(self, request):
        image_url = request.data.get("image_url", "").strip()
        title = request.data.get("title", "").strip() or None
        logo_url = request.data.get("logo_url", "").strip() or None
        remove_bg = bool(request.data.get("remove_bg", False))

        if not image_url:
            return Response({"error": "The field 'image_url' is required."}, status=400)

        try:
            unit = helpers.download_rgba(image_url)
            if remove_bg:
                unit = helpers.safe_remove_bg(unit)

            S = 1600 
            canvas = Image.new("RGBA", (S, S), (255, 255, 255, 255))
            draw = ImageDraw.Draw(canvas)

            banner_h = 0
            if title:
                banner_h = max(100, int(S * 0.16))
                draw.rectangle([0, 0, S, banner_h], fill=(255, 215, 0, 255))
                font = helpers.get_font_from_folder(title, int(S * 0.9), int(banner_h * 0.8), draw)
                tw, th = helpers.get_text_size(draw, title, font)
                tx, ty = (S - tw) // 2, (banner_h - th) // 2
                draw.text((tx, ty), title, font=font, fill=(0, 0, 0, 255))

            content_top = banner_h
            content_h = S - banner_h
            box_w = S - 2 * 48
            box_h = content_h - 2 * 48
            tile = helpers.fit_within(unit, box_w, box_h, margin_ratio=0.96)
            dx = (S - tile.size[0]) // 2
            dy = content_top + (content_h - tile.size[1]) // 2
            canvas.paste(tile, (dx, dy), tile)


            if logo_url:
                try:
                    logo = helpers.download_rgba(logo_url)
                    max_logo_w = int(S * 0.12)
                    logo.thumbnail((max_logo_w, max_logo_w), Image.LANCZOS)
                    lw, lh = logo.size
                    margin = int(S * 0.02)
                    x = S - lw - margin
                    y = S - lh - margin
                    canvas.paste(logo, (x, y), logo)
                except Exception:
                    return Response({"error": "Failed to process logo."}, status=400)

            buf = io.BytesIO()
            canvas.save(buf, format="PNG", optimize=True)
            buf.seek(0)
            response = HttpResponse(buf, content_type="image/png")
            response["Content-Disposition"] = f'inline; filename="enhanced_{random.randint(1000,9999)}.png"'
            return response

        except requests.exceptions.RequestException:
            return Response({"error": "Unable to download image."}, status=400)
        except OSError:
            return Response({"error": "Invalid image format."}, status=400)
        except Exception as e:
            return Response({"error": f"Unexpected server error: {str(e)}"}, status=500)

CATEGORY_PICK_SCHEMA = {
    "$schema": "http://json-schema.org/draft-07/schema#",
    "title": "CategoryPick",
    "type": "object",
    "required": ["choice"],
    "properties": {
        "choice": {
            "type": "object",
            "required": ["categoryId", "categoryName"],
            "properties": {
                "categoryId": {"type": "string"},
                "categoryName": {"type": "string"}
            },
            "additionalProperties": False
        },
        "ranking": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["categoryId", "score", "why"],
                "properties": {
                    "categoryId": {"type": "string"},
                    "score": {"type": "number", "minimum": 0, "maximum": 1},
                    "why": {"type": "string"}
                },
                "additionalProperties": False
            }
        },
        "notes": {"type": "string"}
    },
    "additionalProperties": False
}

class SingleItemListingAPIView(APIView):
    def post(self, request):
        if request.data.get("action", "publish") != "publish":
            return Response({"error": "Only 'publish' action is supported"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            UserProfile.objects.get(user=request.user)
        except UserProfile.DoesNotExist:
            return Response({"error": "Please create your profile first"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            token = eBayToken.objects.get(user=request.user)
            if not token.refresh_token:
                return Response({"error": "Please authenticate with eBay first"}, status=status.HTTP_400_BAD_REQUEST)
        except eBayToken.DoesNotExist:
            return Response({"error": "Please authenticate with eBay first"}, status=status.HTTP_400_BAD_REQUEST)

        allowed, reason = helpers._can_consume_listing(request.user)
        if not allowed:
            return Response({"error": reason, "redirect": "/pricing/"}, status=status.HTTP_402_PAYMENT_REQUIRED)

        payload = {
            "raw_text": request.data.get("raw_text", ""),
            "images": request.data.get("images", []),
            "price": request.data.get("price"),
            "quantity": request.data.get("quantity", 1),
            "condition": request.data.get("condition", "NEW"),
            "sku": request.data.get("sku"),
            "vat_rate": request.data.get("vat_rate", 0),
            "remove_bg": request.data.get("remove_bg", False),
        }

        task = create_single_item_listing_task.delay(request.user.id, payload)

        try:
            TaskRecord.objects.create(
                user=request.user,
                task_id=task.id,
                name="create_single_item_listing",
                status="PENDING",
                payload=payload,
            )
        except Exception:
            pass

        return Response({"task_id": task.id, "status": "queued", "redirect_url": f"/single-listing-success/?task_id={task.id}"}, status=status.HTTP_202_ACCEPTED)


class TaskStatusAPIView(APIView):
    def get(self, request):
        from celery.result import AsyncResult
        task_id = request.query_params.get("task_id")
        if not task_id:
            return Response({"error": "task_id is required"}, status=status.HTTP_400_BAD_REQUEST)
        rec = TaskRecord.objects.filter(task_id=task_id).first()
        if rec:
            data = {
                "task_id": task_id,
                "state": rec.status,
                "result": rec.result,
                "error": rec.error,
                "name": rec.name,
                "created_at": rec.created_at,
                "updated_at": rec.updated_at,
            }
            return Response(data)
        result = AsyncResult(task_id)
        data = {"task_id": task_id, "state": result.state}
        if result.state == "SUCCESS":
            data["result"] = result.result
        elif result.state == "FAILURE":
            data["error"] = str(result.result)
        return Response(data)


class MyTasksAPIView(APIView):
    def get(self, request):
        limit = int(request.query_params.get('limit', 20))
        qs = TaskRecord.objects.filter(user=request.user)[:limit]
        return Response({
            "tasks": [
                {
                    "task_id": t.task_id,
                    "name": t.name,
                    "state": t.status,
                    "created_at": t.created_at,
                    "updated_at": t.updated_at,
                }
                for t in qs
            ]
        })

class MultipackListingAPIView(APIView):
    def post(self, request):
        if request.data.get("action", "publish") != "publish":
            return Response({"error": "Only 'publish' action is supported"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            UserProfile.objects.get(user=request.user)
        except UserProfile.DoesNotExist:
            return Response({"error": "Please create your profile first"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            token = eBayToken.objects.get(user=request.user)
            if not token.refresh_token:
                return Response({"error": "Please authenticate with eBay first"}, status=status.HTTP_400_BAD_REQUEST)
        except eBayToken.DoesNotExist:
            return Response({"error": "Please authenticate with eBay first"}, status=status.HTTP_400_BAD_REQUEST)

        allowed, reason = helpers._can_consume_listing(request.user)
        if not allowed:
            return Response({"error": reason, "redirect": "/pricing/"}, status=status.HTTP_402_PAYMENT_REQUIRED)

        payload = {
            "raw_text": request.data.get("raw_text", ""),
            "images": request.data.get("images", []),
            "price": request.data.get("price"),
            "quantity": request.data.get("quantity", 1),
            "condition": request.data.get("condition", "NEW"),
            "sku": request.data.get("sku"),
            "vat_rate": request.data.get("vat_rate", 0),
            "remove_bg": request.data.get("remove_bg", request.data.get("remove_background", False)),
            "multipack_quantity": request.data.get("multipack_quantity", 2),
        }

        task = create_multipack_listing_task.delay(request.user.id, payload)

        try:
            TaskRecord.objects.create(
                user=request.user,
                task_id=task.id,
                name="create_multipack_listing",
                status="PENDING",
                payload=payload,
            )
        except Exception:
            pass

        return Response({"task_id": task.id, "status": "queued", "redirect_url": f"/single-listing-success/?task_id={task.id}"}, status=status.HTTP_202_ACCEPTED)

class BundleListingAPIView(APIView):
    def post(self, request):
        if request.data.get("action", "publish") != "publish":
            return Response({"error": "Only 'publish' action is supported"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            UserProfile.objects.get(user=request.user)
        except UserProfile.DoesNotExist:
            return Response({"error": "Please create your profile first"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            token = eBayToken.objects.get(user=request.user)
            if not token.refresh_token:
                return Response({"error": "Please authenticate with eBay first"}, status=status.HTTP_400_BAD_REQUEST)
        except eBayToken.DoesNotExist:
            return Response({"error": "Please authenticate with eBay first"}, status=status.HTTP_400_BAD_REQUEST)

        allowed, reason = helpers._can_consume_listing(request.user)
        if not allowed:
            return Response({"error": reason, "redirect": "/pricing/"}, status=status.HTTP_402_PAYMENT_REQUIRED)

        payload = {
            "raw_text": request.data.get("raw_text", ""),
            "images": request.data.get("images", []),
            "price": request.data.get("price"),
            "quantity": request.data.get("quantity", 1),
            "condition": request.data.get("condition", "NEW"),
            "sku": request.data.get("sku"),
            "vat_rate": request.data.get("vat_rate", 0),
            "remove_bg": request.data.get("remove_bg", request.data.get("remove_background", False)),
            "bundle_quantity": request.data.get("bundle_quantity", 2),
        }

        task = create_bundle_listing_task.delay(request.user.id, payload)

        try:
            TaskRecord.objects.create(
                user=request.user,
                task_id=task.id,
                name="create_bundle_listing",
                status="PENDING",
                payload=payload,
            )
        except Exception:
            pass

        return Response({"task_id": task.id, "status": "queued", "redirect_url": f"/single-listing-success/?task_id={task.id}"}, status=status.HTTP_202_ACCEPTED)


class UsageStatusAPIView(APIView):
    def get(self, request):
        return Response(helpers._get_user_usage_snapshot(request.user))

class UserPlanStatusAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        try:
            user_plan = UserPlan.objects.get(user=request.user)
            is_refundable = user_plan.listings_used == 0 and user_plan.plan.code != "FREE"
            
            pending_refund = RefundRequest.objects.filter(
                user=request.user,
                status="pending"
            ).first()
            
            completed_refund = RefundRequest.objects.filter(
                user=request.user,
                status="completed",
                processed_at__gte=now() - timedelta(days=7)
            ).first()
            
            return Response({
                "plan_name": user_plan.plan.name,
                "period_start": user_plan.current_period_start,
                "period_end": user_plan.current_period_end,
                "listings_used": user_plan.listings_used,
                "listings_quota": user_plan.plan.monthly_quota,
                "is_refundable": is_refundable,
                "has_pending_refund": pending_refund is not None,
                "refund_requested_at": pending_refund.created_at if pending_refund else None,
                "has_completed_refund": completed_refund is not None,
                "refund_completed_at": completed_refund.processed_at if completed_refund else None,
            })
        except UserPlan.DoesNotExist:
            return Response({"plan_name": "Free Plan"})


class RequestRefundAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        user = request.user

        try:
            user_plan = UserPlan.objects.get(user=user)
        except UserPlan.DoesNotExist:
            return Response({
                "error": "You don't have an active subscription plan."
            }, status=status.HTTP_400_BAD_REQUEST)

        if user_plan.plan.code not in ["PRO", "BUSINESS"]:
            return Response({
                "error": "Only Pro and Business plans are eligible for refunds."
            }, status=status.HTTP_400_BAD_REQUEST)

        if user_plan.listings_used > 0:
            return Response({
                "error": f"Refund not available. You have already used {user_plan.listings_used} listing(s) from your plan."
            }, status=status.HTTP_400_BAD_REQUEST)

        if not user_plan.stripe_subscription_id:
            return Response({
                "error": "No subscription found for refund."
            }, status=status.HTTP_400_BAD_REQUEST)

        try:
            subscription = stripe.Subscription.retrieve(user_plan.stripe_subscription_id)
            
            if subscription.status == "canceled":
                return Response({
                    "error": "This subscription has already been canceled."
                }, status=status.HTTP_400_BAD_REQUEST)

            refund_details = {
                "user_email": user.email,
                "user_id": user.id,
                "plan_name": user_plan.plan.name,
                "plan_code": user_plan.plan.code,
                "subscription_id": user_plan.stripe_subscription_id,
                "period_start": user_plan.current_period_start.strftime("%Y-%m-%d %H:%M:%S"),
                "period_end": user_plan.current_period_end.strftime("%Y-%m-%d %H:%M:%S"),
                "listings_used": user_plan.listings_used,
            }

            team_email = "rahul@listfast.ai"
            subject = f"Refund Request - {user.email} ({user_plan.plan.name})"
            
            body_html = f"""
            <html>
                <body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                    <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 30px; text-align: center;">
                        <h1 style="color: white; margin: 0;">ListFast.ai Refund Request</h1>
                    </div>
                    <div style="padding: 40px 30px; background: #f9f9f9;">
                        <h2 style="color: #333; margin-bottom: 20px;">New Refund Request</h2>
                        
                        <div style="background: white; padding: 20px; border-radius: 10px; margin: 20px 0;">
                            <h3 style="color: #667eea; margin-top: 0;">User Details</h3>
                            <table style="width: 100%; border-collapse: collapse;">
                                <tr>
                                    <td style="padding: 8px 0; color: #666; font-weight: bold;">Email:</td>
                                    <td style="padding: 8px 0; color: #333;">{refund_details['user_email']}</td>
                                </tr>
                                <tr>
                                    <td style="padding: 8px 0; color: #666; font-weight: bold;">User ID:</td>
                                    <td style="padding: 8px 0; color: #333;">{refund_details['user_id']}</td>
                                </tr>
                            </table>
                        </div>
                        
                        <div style="background: white; padding: 20px; border-radius: 10px; margin: 20px 0;">
                            <h3 style="color: #667eea; margin-top: 0;">Subscription Details</h3>
                            <table style="width: 100%; border-collapse: collapse;">
                                <tr>
                                    <td style="padding: 8px 0; color: #666; font-weight: bold;">Plan:</td>
                                    <td style="padding: 8px 0; color: #333;">{refund_details['plan_name']} ({refund_details['plan_code']})</td>
                                </tr>
                                <tr>
                                    <td style="padding: 8px 0; color: #666; font-weight: bold;">Subscription ID:</td>
                                    <td style="padding: 8px 0; color: #333; font-family: monospace; font-size: 12px;">{refund_details['subscription_id']}</td>
                                </tr>
                                <tr>
                                    <td style="padding: 8px 0; color: #666; font-weight: bold;">Period Start:</td>
                                    <td style="padding: 8px 0; color: #333;">{refund_details['period_start']}</td>
                                </tr>
                                <tr>
                                    <td style="padding: 8px 0; color: #666; font-weight: bold;">Period End:</td>
                                    <td style="padding: 8px 0; color: #333;">{refund_details['period_end']}</td>
                                </tr>
                                <tr>
                                    <td style="padding: 8px 0; color: #666; font-weight: bold;">Listings Used:</td>
                                    <td style="padding: 8px 0; color: #333;">{refund_details['listings_used']}</td>
                                </tr>
                            </table>
                        </div>
                        
                        <div style="background: #fff3cd; padding: 20px; border-radius: 10px; border-left: 4px solid #ffc107; margin: 20px 0;">
                            <p style="margin: 0; color: #856404; font-weight: bold;">
                                ⚠️ Action Required: Please review and process this refund request in Stripe.
                            </p>
                        </div>
                        
                        <p style="color: #666; font-size: 14px; margin-top: 30px;">
                            To process this refund, log in to your Stripe dashboard and issue the refund for subscription ID: <strong>{refund_details['subscription_id']}</strong>
                        </p>
                    </div>
                    <div style="background: #333; padding: 20px; text-align: center;">
                        <p style="color: #999; margin: 0; font-size: 12px;">
                            © 2025 ListFast.ai. All rights reserved.
                        </p>
                    </div>
                </body>
            </html>
            """
            
            body_text = f"""
            New Refund Request - ListFast.ai
            
            User Details:
            - Email: {refund_details['user_email']}
            - User ID: {refund_details['user_id']}
            
            Subscription Details:
            - Plan: {refund_details['plan_name']} ({refund_details['plan_code']})
            - Subscription ID: {refund_details['subscription_id']}
            - Period Start: {refund_details['period_start']}
            - Period End: {refund_details['period_end']}
            - Listings Used: {refund_details['listings_used']}
            
            Action Required: Please review and process this refund request in Stripe.
            """
            
            msg = EmailMultiAlternatives(
                subject=subject,
                body=body_text,
                from_email=EMAIL_USER,
                to=[team_email]
            )
            msg.attach_alternative(body_html, "text/html")
            
            try:
                msg.send()
                logging.info(f"Refund request email sent for user {user.email} (Plan: {user_plan.plan.code})")
            except Exception as email_error:
                logging.error(f"Failed to send refund request email: {str(email_error)}")
                return Response({
                    "error": "Failed to submit refund request. Please contact support at rahul@listfast.ai"
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

            user_subject = "Refund Request Received - ListFast.ai"
            user_body_html = f"""
            <html>
                <body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                    <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 30px; text-align: center;">
                        <h1 style="color: white; margin: 0;">ListFast.ai</h1>
                    </div>
                    <div style="padding: 40px 30px; background: #f9f9f9;">
                        <h2 style="color: #333; margin-bottom: 20px;">Refund Request Received</h2>
                        <p style="color: #666; font-size: 16px; line-height: 1.6;">
                            We have received your refund request for your <strong>{user_plan.plan.name}</strong> subscription.
                        </p>
                        <div style="background: white; padding: 30px; border-radius: 10px; margin: 30px 0;">
                            <p style="color: #666; font-size: 16px; line-height: 1.6; margin: 0;">
                                Our team will review your request and process it within <strong>2-3 business days</strong>. 
                                Once approved, the refund will be processed and you will receive it within 5-10 business days.
                            </p>
                        </div>
                        <p style="color: #666; font-size: 14px;">
                            If you have any questions, please contact us at <a href="mailto:rahul@listfast.ai">rahul@listfast.ai</a>.
                        </p>
                    </div>
                    <div style="background: #333; padding: 20px; text-align: center;">
                        <p style="color: #999; margin: 0; font-size: 12px;">
                            © 2025 ListFast.ai. All rights reserved.
                        </p>
                    </div>
                </body>
            </html>
            """
            
            user_msg = EmailMultiAlternatives(
                subject=user_subject,
                body=f"Your refund request for {user_plan.plan.name} has been received and will be processed within 2-3 business days.",
                from_email=EMAIL_USER,
                to=[user.email]
            )
            user_msg.attach_alternative(user_body_html, "text/html")
            
            try:
                user_msg.send()
            except Exception:
                pass 

            # Create refund request record
            RefundRequest.objects.create(
                user=user,
                subscription_id=user_plan.stripe_subscription_id,
                plan_name=user_plan.plan.name,
                amount=user_plan.plan.price_amount_gbp,
                status="pending"
            )

            return Response({
                "status": "success",
                "message": "Your refund request has been submitted successfully. Our team will review and process it within 2-3 business days. You will receive an email confirmation once processed."
            }, status=status.HTTP_200_OK)

        except Exception as e:
            logging.error(f"Error processing refund request for user {user.email}: {str(e)}")
            return Response({
                "error": "Failed to process refund request. Please contact support at rahul@listfast.ai"
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class CreateCheckoutSessionAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        kind = request.data.get("kind")
        user = request.user

        if kind == "subscription":
            plan_code = request.data.get("plan_code")
            try:
                up = UserPlan.objects.get(user=user)
                if up.current_period_start and up.current_period_start > now():
                    return Response({
                        "error": "Your current plan is not active yet. Please wait until it becomes active before purchasing another plan."},
                        status=400
                    )
            except UserPlan.DoesNotExist:
                pass
            try:
                plan = Plan.objects.get(code=plan_code)
                if not plan.stripe_price_id:
                    return Response({"error": "Plan not available for purchase"}, status=400)
            except Plan.DoesNotExist:
                return Response({"error": "Unknown plan"}, status=400)

            session = stripe.checkout.Session.create(
                mode="subscription",
                line_items=[{"price": plan.stripe_price_id, "quantity": 1}],
                success_url=f"{SITE_BASE_URL}/pricing/?success=1",
                cancel_url=f"{SITE_BASE_URL}/pricing/?canceled=1",
                metadata={
                    "user_id": str(user.id),
                    "kind": "subscription",
                    "plan_code": plan.code
                }
            )
            return Response({"checkout_url": session.url})

        elif kind == "credits":
            usage = helpers._get_user_usage_snapshot(user)
            if usage["remaining"] > 0:
                return Response({"error": "You can only purchase credits once you have used all your plan listings."}, status=400)
            
            try:
                package = CreditPackage.objects.get(is_active=True)
            except CreditPackage.DoesNotExist:
                return Response({"error": "No active credit package found"}, status=400)

            price_data = {
                "currency": "gbp",
                "unit_amount": int(package.price_gbp * 100),
                "product_data": {"name": package.name},
            }

            session = stripe.checkout.Session.create(
                mode="payment",
                line_items=[{"price_data": price_data, "quantity": 1}],
                success_url=f"{SITE_BASE_URL}/pricing/?success=1",
                cancel_url=f"{SITE_BASE_URL}/pricing/?canceled=1",
                metadata={
                    "user_id": str(user.id),
                    "kind": "credits",
                    "package_code": package.code,
                }
            )
            return Response({"checkout_url": session.url})

        else:
            return Response({"error": "Invalid kind"}, status=400)

class StripeWebhookAPIView(APIView):
    def post(self, request):
        payload = request.body
        sig_header = request.META.get("HTTP_STRIPE_SIGNATURE")
        endpoint_secret = config("STRIPE_WEBHOOK_SECRET")

        try:
            event = stripe.Webhook.construct_event(payload, sig_header, endpoint_secret)
        except stripe.SignatureVerificationError as e:
            logging.error(f"Stripe webhook signature verification failed: {e}")
            return Response(status=400)
        except Exception as e:
            logging.error(f"Error processing Stripe webhook: {e}")
            return Response(status=400)

        event_type = event["type"]
        logging.info(f"Processing Stripe webhook event: {event_type}")

        if event_type == "checkout.session.completed":
            session = event["data"]["object"]
            metadata = session.get("metadata", {})
            user_id = metadata.get("user_id")

            if not user_id:
                logging.error("user_id missing from Stripe checkout session metadata")
                return Response(status=400)

            try:
                user = get_user_model().objects.get(id=int(user_id))
            except get_user_model().DoesNotExist:
                logging.error(f"User with id={user_id} not found for completed checkout session")
                return Response(status=400)

            with transaction.atomic():
                if CreditPurchase.objects.filter(stripe_session_id=session.id).exists():
                    return Response({"message": "Webhook already processed"}, status=200)

                if session.get("mode") == "payment":
                    package_code = metadata.get("package_code")
                    try:
                        package = CreditPackage.objects.get(code=package_code)
                        CreditPurchase.objects.create(
                            user=user,
                            package=package,
                            credits_total=package.credits,
                            credits_used=0,
                            expires_at=now() + timedelta(days=30),
                            stripe_session_id=session.id,
                            status="completed",
                        )
                        logging.info(f"Credit purchase created for user {user.email}")
                    except CreditPackage.DoesNotExist:
                        logging.error(f"CreditPackage with code={package_code} not found.")
                        return Response(status=400)

                elif session.get("mode") == "subscription":
                    subscription_id = session.get("subscription")
                    if subscription_id:
                        subscription = stripe.Subscription.retrieve(subscription_id)
                        item = subscription["items"]["data"][0]
                        price_id = item["price"]["id"]
                        period_start = datetime.fromtimestamp(item["current_period_start"])
                        period_end = datetime.fromtimestamp(item["current_period_end"])

                        try:
                            plan = Plan.objects.get(stripe_price_id=price_id)
                            UserPlan.objects.update_or_create(
                                user=user,
                                defaults={
                                    "plan": plan,
                                    "current_period_start": period_start,
                                    "current_period_end": period_end,
                                    "listings_used": 0,
                                    "stripe_subscription_id": subscription_id,
                                }
                            )
                            logging.info(f"Subscription created for user {user.email} - Plan: {plan.name}")
                            
                            Order.objects.create(
                                user=user,
                                order_type="subscription",
                                stripe_session_id=session.id,
                                stripe_subscription_id=subscription_id,
                                amount=plan.price_amount_gbp,
                                currency="gbp",
                                description=f"{plan.name} Subscription",
                                status="completed"
                            )
                            
                            subject = f"Welcome to {plan.name} - ListFast.ai"
                            body_html = f"""
                            <html>
                                <body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                                    <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 30px; text-align: center;">
                                        <h1 style="color: white; margin: 0;">ListFast.ai</h1>
                                    </div>
                                    <div style="padding: 40px 30px; background: #f9f9f9;">
                                        <h2 style="color: #333; margin-bottom: 20px;">🎉 Welcome to {plan.name}!</h2>
                                        <p style="color: #666; font-size: 16px; line-height: 1.6;">
                                            Thank you for subscribing to <strong>{plan.name}</strong>! Your subscription is now active.
                                        </p>
                                        <div style="background: white; padding: 30px; border-radius: 10px; margin: 30px 0;">
                                            <h3 style="color: #667eea; margin-top: 0;">Subscription Details</h3>
                                            <table style="width: 100%; border-collapse: collapse;">
                                                <tr>
                                                    <td style="padding: 8px 0; color: #666; font-weight: bold;">Plan:</td>
                                                    <td style="padding: 8px 0; color: #333;">{plan.name}</td>
                                                </tr>
                                                <tr>
                                                    <td style="padding: 8px 0; color: #666; font-weight: bold;">Monthly Quota:</td>
                                                    <td style="padding: 8px 0; color: #333;">{plan.monthly_quota} listings</td>
                                                </tr>
                                                <tr>
                                                    <td style="padding: 8px 0; color: #666; font-weight: bold;">Billing Period:</td>
                                                    <td style="padding: 8px 0; color: #333;">{period_start.strftime("%b %d, %Y")} - {period_end.strftime("%b %d, %Y")}</td>
                                                </tr>
                                            </table>
                                        </div>
                                        <div style="background: #e0f2fe; padding: 20px; border-radius: 10px; border-left: 4px solid #0284c7; margin: 20px 0;">
                                            <p style="margin: 0; color: #075985; font-weight: bold;">
                                                🚀 Ready to get started? Head to your dashboard and create your first listing!
                                            </p>
                                        </div>
                                        <p style="color: #666; font-size: 14px;">
                                            If you have any questions, contact us at <a href="mailto:rahul@listfast.ai">rahul@listfast.ai</a>.
                                        </p>
                                    </div>
                                    <div style="background: #333; padding: 20px; text-align: center;">
                                        <p style="color: #999; margin: 0; font-size: 12px;">© 2025 ListFast.ai</p>
                                    </div>
                                </body>
                            </html>
                            """
                            
                            msg = EmailMultiAlternatives(
                                subject=subject,
                                body=f"Welcome to {plan.name}! Your subscription is now active with {plan.monthly_quota} listings per month.",
                                from_email=EMAIL_USER,
                                to=[user.email]
                            )
                            msg.attach_alternative(body_html, "text/html")
                            
                            try:
                                msg.send()
                                logging.info(f"Welcome subscription email sent to {user.email}")
                            except Exception:
                                pass
                                
                        except Plan.DoesNotExist:
                            logging.error(f"Plan with stripe_price_id={price_id} not found.")

        elif event_type == "invoice.payment_succeeded":
            invoice = event["data"]["object"]
            subscription_id = invoice.get("subscription")
            
            if subscription_id:
                try:
                    user_plan = UserPlan.objects.get(stripe_subscription_id=subscription_id)
                    
                    subscription = stripe.Subscription.retrieve(subscription_id)
                    item = subscription["items"]["data"][0]
                    period_start = datetime.fromtimestamp(item["current_period_start"])
                    period_end = datetime.fromtimestamp(item["current_period_end"])
                    
                    user_plan.current_period_start = period_start
                    user_plan.current_period_end = period_end
                    user_plan.listings_used = 0
                    user_plan.save()
                    
                    logging.info(f"Invoice paid for user {user_plan.user.email} - Period reset: {period_start} to {period_end}")
                    
                    amount_paid = invoice.get("amount_paid", 0) / 100
                    Order.objects.create(
                        user=user_plan.user,
                        order_type="subscription",
                        stripe_subscription_id=subscription_id,
                        stripe_invoice_id=invoice.get("id"),
                        amount=amount_paid,
                        currency=invoice.get("currency", "gbp"),
                        description=f"{user_plan.plan.name} Renewal",
                        status="completed"
                    )
                    
                    subject = "Payment Successful - ListFast.ai"
                    body_html = f"""
                    <html>
                        <body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                            <div style="background: linear-gradient(135deg, #10b981 0%, #059669 100%); padding: 30px; text-align: center;">
                                <h1 style="color: white; margin: 0;">✅ Payment Successful</h1>
                            </div>
                            <div style="padding: 40px 30px; background: #f9f9f9;">
                                <h2 style="color: #333;">Thank You for Your Payment!</h2>
                                <p style="color: #666; font-size: 16px; line-height: 1.6;">
                                    Your payment for <strong>{user_plan.plan.name}</strong> has been processed successfully.
                                </p>
                                <div style="background: white; padding: 30px; border-radius: 10px; margin: 30px 0;">
                                    <h3 style="color: #10b981; margin-top: 0;">Payment Details</h3>
                                    <table style="width: 100%; border-collapse: collapse;">
                                        <tr>
                                            <td style="padding: 8px 0; color: #666; font-weight: bold;">Amount Paid:</td>
                                            <td style="padding: 8px 0; color: #333;">£{amount_paid:.2f}</td>
                                        </tr>
                                        <tr>
                                            <td style="padding: 8px 0; color: #666; font-weight: bold;">Plan:</td>
                                            <td style="padding: 8px 0; color: #333;">{user_plan.plan.name}</td>
                                        </tr>
                                        <tr>
                                            <td style="padding: 8px 0; color: #666; font-weight: bold;">Billing Period:</td>
                                            <td style="padding: 8px 0; color: #333;">{period_start.strftime("%b %d, %Y")} - {period_end.strftime("%b %d, %Y")}</td>
                                        </tr>
                                        <tr>
                                            <td style="padding: 8px 0; color: #666; font-weight: bold;">Next Billing Date:</td>
                                            <td style="padding: 8px 0; color: #333;">{period_end.strftime("%b %d, %Y")}</td>
                                        </tr>
                                    </table>
                                </div>
                                <div style="background: #dbeafe; padding: 20px; border-radius: 10px; border-left: 4px solid #3b82f6; margin: 20px 0;">
                                    <p style="margin: 0; color: #1e40af; font-weight: bold;">
                                        🎉 Your listing quota has been reset to {user_plan.plan.monthly_quota} listings for this month!
                                    </p>
                                </div>
                                <p style="color: #666; font-size: 14px;">
                                    Questions? Contact us at <a href="mailto:rahul@listfast.ai">rahul@listfast.ai</a>.
                                </p>
                            </div>
                            <div style="background: #333; padding: 20px; text-align: center;">
                                <p style="color: #999; margin: 0; font-size: 12px;">© 2025 ListFast.ai</p>
                            </div>
                        </body>
                    </html>
                    """
                    
                    msg = EmailMultiAlternatives(
                        subject=subject,
                        body=f"Your payment of £{amount_paid:.2f} for {user_plan.plan.name} has been processed successfully.",
                        from_email=EMAIL_USER,
                        to=[user_plan.user.email]
                    )
                    msg.attach_alternative(body_html, "text/html")
                    
                    try:
                        msg.send()
                        logging.info(f"Payment success email sent to {user_plan.user.email}")
                    except Exception:
                        pass
                        
                except UserPlan.DoesNotExist:
                    logging.warning(f"UserPlan not found for subscription {subscription_id}")

        elif event_type == "invoice.payment_failed":
            invoice = event["data"]["object"]
            subscription_id = invoice.get("subscription")
            customer_email = invoice.get("customer_email")
            
            if subscription_id:
                try:
                    user_plan = UserPlan.objects.get(stripe_subscription_id=subscription_id)
                    user = user_plan.user
                    
                    subject = "Payment Failed - ListFast.ai Subscription"
                    body_html = f"""
                    <html>
                        <body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                            <div style="background: #dc3545; padding: 30px; text-align: center;">
                                <h1 style="color: white; margin: 0;">Payment Failed</h1>
                            </div>
                            <div style="padding: 40px 30px; background: #f9f9f9;">
                                <h2 style="color: #333;">Action Required</h2>
                                <p style="color: #666; font-size: 16px; line-height: 1.6;">
                                    We were unable to process your payment for your <strong>{user_plan.plan.name}</strong> subscription.
                                </p>
                                <div style="background: #fff3cd; padding: 20px; border-radius: 10px; border-left: 4px solid #ffc107; margin: 20px 0;">
                                    <p style="margin: 0; color: #856404;">
                                        Please update your payment method to avoid service interruption.
                                    </p>
                                </div>
                                <p style="color: #666; font-size: 14px;">
                                    If you have questions, contact us at <a href="mailto:rahul@listfast.ai">rahul@listfast.ai</a>.
                                </p>
                            </div>
                            <div style="background: #333; padding: 20px; text-align: center;">
                                <p style="color: #999; margin: 0; font-size: 12px;">© 2025 ListFast.ai</p>
                            </div>
                        </body>
                    </html>
                    """
                    
                    msg = EmailMultiAlternatives(
                        subject=subject,
                        body="Your payment for ListFast.ai subscription failed. Please update your payment method.",
                        from_email=EMAIL_USER,
                        to=[user.email]
                    )
                    msg.attach_alternative(body_html, "text/html")
                    
                    try:
                        msg.send()
                        logging.info(f"Payment failed email sent to {user.email}")
                    except Exception:
                        pass
                        
                    logging.warning(f"Payment failed for user {user.email} - Subscription: {subscription_id}")
                except UserPlan.DoesNotExist:
                    logging.warning(f"UserPlan not found for failed payment - Subscription: {subscription_id}")

        elif event_type == "customer.subscription.deleted":
            subscription = event["data"]["object"]
            subscription_id = subscription["id"]
            
            try:
                user_plan = UserPlan.objects.get(stripe_subscription_id=subscription_id)
                user = user_plan.user
                
                pending_refund = RefundRequest.objects.filter(
                    user=user,
                    subscription_id=subscription_id,
                    status="pending"
                ).first()
                
                has_refund = pending_refund is not None
                
                if pending_refund:
                    pending_refund.status = "completed"
                    pending_refund.processed_at = now()
                    pending_refund.save()
                    logging.info(f"Refund request marked as completed for user {user.email} - subscription canceled")
                
                free_plan, _ = Plan.objects.get_or_create(
                    code="FREE",
                    defaults={
                        "name": "Free",
                        "monthly_quota": 2,
                        "price_amount_gbp": 0,
                    }
                )
                
                period_start = now()
                period_end = period_start + timedelta(days=30)
                user_plan.plan = free_plan
                user_plan.current_period_start = period_start
                user_plan.current_period_end = period_end
                user_plan.listings_used = 0
                user_plan.stripe_subscription_id = None
                user_plan.save()
                
                logging.info(f"Subscription deleted - User {user.email} downgraded to FREE plan")
                
                if has_refund:
                    subject = "Refund Completed - ListFast.ai"
                    body_html = f"""
                    <html>
                        <body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                            <div style="background: linear-gradient(135deg, #10b981 0%, #059669 100%); padding: 30px; text-align: center;">
                                <h1 style="color: white; margin: 0;">✅ Refund Completed</h1>
                            </div>
                            <div style="padding: 40px 30px; background: #f9f9f9;">
                                <h2 style="color: #333;">Your Refund Has Been Processed</h2>
                                <p style="color: #666; font-size: 16px; line-height: 1.6;">
                                    Great news! We have completed the refund from our end.
                                </p>
                                <div style="background: white; padding: 30px; border-radius: 10px; margin: 30px 0; border-left: 4px solid #10b981;">
                                    <p style="color: #666; font-size: 16px; line-height: 1.6; margin: 0;">
                                        <strong style="color: #10b981;">✓ Refund processed successfully</strong><br>
                                        The refund may take <strong>1-2 business days</strong> to reflect in your bank account or card statement.
                                    </p>
                                </div>
                                <div style="background: #fef3c7; padding: 20px; border-radius: 10px; border-left: 4px solid #f59e0b; margin: 20px 0;">
                                    <p style="margin: 0; color: #92400e;">
                                        Your subscription has been canceled and you've been moved to the <strong>Free Plan</strong>. You can still create <strong>2 listings per month</strong>.
                                    </p>
                                </div>
                                <p style="color: #666; font-size: 14px;">
                                    Want to upgrade again? <a href="{SITE_BASE_URL}/pricing/" style="color: #10b981; text-decoration: none; font-weight: bold;">View our pricing</a>
                                </p>
                                <p style="color: #666; font-size: 14px;">
                                    Questions? Contact us at <a href="mailto:rahul@listfast.ai">rahul@listfast.ai</a>.
                                </p>
                            </div>
                            <div style="background: #333; padding: 20px; text-align: center;">
                                <p style="color: #999; margin: 0; font-size: 12px;">© 2025 ListFast.ai</p>
                            </div>
                        </body>
                    </html>
                    """
                else:
                    subject = "Subscription Canceled - ListFast.ai"
                    body_html = f"""
                    <html>
                        <body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                            <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 30px; text-align: center;">
                                <h1 style="color: white; margin: 0;">ListFast.ai</h1>
                            </div>
                            <div style="padding: 40px 30px; background: #f9f9f9;">
                                <h2 style="color: #333;">Subscription Canceled</h2>
                                <p style="color: #666; font-size: 16px; line-height: 1.6;">
                                    Your subscription has been canceled. You have been moved to the <strong>Free Plan</strong>.
                                </p>
                                <div style="background: white; padding: 20px; border-radius: 10px; margin: 20px 0;">
                                    <p style="color: #666; margin: 0;">
                                        You can still use <strong>2 listings per month</strong> on the Free plan.
                                    </p>
                                </div>
                                <p style="color: #666; font-size: 14px;">
                                    Want to upgrade again? Visit our <a href="{SITE_BASE_URL}/pricing/">pricing page</a>.
                                </p>
                            </div>
                            <div style="background: #333; padding: 20px; text-align: center;">
                                <p style="color: #999; margin: 0; font-size: 12px;">© 2025 ListFast.ai</p>
                            </div>
                        </body>
                    </html>
                    """
                
                msg = EmailMultiAlternatives(
                    subject=subject,
                    body="Your ListFast.ai subscription has been canceled. You've been moved to the Free plan.",
                    from_email=EMAIL_USER,
                    to=[user.email]
                )
                msg.attach_alternative(body_html, "text/html")
                
                try:
                    msg.send()
                except Exception:
                    pass
                    
            except UserPlan.DoesNotExist:
                logging.warning(f"UserPlan not found for deleted subscription: {subscription_id}")

        elif event_type == "customer.subscription.updated":
            subscription = event["data"]["object"]
            subscription_id = subscription["id"]
            
            try:
                user_plan = UserPlan.objects.get(stripe_subscription_id=subscription_id)
                item = subscription["items"]["data"][0]
                price_id = item["price"]["id"]
                period_start = datetime.fromtimestamp(item["current_period_start"])
                period_end = datetime.fromtimestamp(item["current_period_end"])
                
                try:
                    new_plan = Plan.objects.get(stripe_price_id=price_id)
                    if user_plan.plan != new_plan:
                        old_plan_name = user_plan.plan.name
                        user_plan.plan = new_plan
                        user_plan.current_period_start = period_start
                        user_plan.current_period_end = period_end
                        user_plan.save()
                        
                        logging.info(f"Plan updated for user {user_plan.user.email}: {old_plan_name} -> {new_plan.name}")
                        
                        is_upgrade = new_plan.monthly_quota > Plan.objects.get(name=old_plan_name).monthly_quota
                        subject = f"Plan {'Upgraded' if is_upgrade else 'Changed'} - ListFast.ai"
                        body_html = f"""
                        <html>
                            <body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                                <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 30px; text-align: center;">
                                    <h1 style="color: white; margin: 0;">{'🚀' if is_upgrade else '📋'} Plan {'Upgraded' if is_upgrade else 'Changed'}</h1>
                                </div>
                                <div style="padding: 40px 30px; background: #f9f9f9;">
                                    <h2 style="color: #333;">Your Plan Has Been {'Upgraded' if is_upgrade else 'Changed'}!</h2>
                                    <p style="color: #666; font-size: 16px; line-height: 1.6;">
                                        Your subscription has been {'upgraded' if is_upgrade else 'changed'} from <strong>{old_plan_name}</strong> to <strong>{new_plan.name}</strong>.
                                    </p>
                                    <div style="background: white; padding: 30px; border-radius: 10px; margin: 30px 0;">
                                        <h3 style="color: #667eea; margin-top: 0;">New Plan Details</h3>
                                        <table style="width: 100%; border-collapse: collapse;">
                                            <tr>
                                                <td style="padding: 8px 0; color: #666; font-weight: bold;">Previous Plan:</td>
                                                <td style="padding: 8px 0; color: #999; text-decoration: line-through;">{old_plan_name}</td>
                                            </tr>
                                            <tr>
                                                <td style="padding: 8px 0; color: #666; font-weight: bold;">Current Plan:</td>
                                                <td style="padding: 8px 0; color: #10b981; font-weight: bold;">{new_plan.name}</td>
                                            </tr>
                                            <tr>
                                                <td style="padding: 8px 0; color: #666; font-weight: bold;">Monthly Quota:</td>
                                                <td style="padding: 8px 0; color: #333;">{new_plan.monthly_quota} listings</td>
                                            </tr>
                                            <tr>
                                                <td style="padding: 8px 0; color: #666; font-weight: bold;">Billing Period:</td>
                                                <td style="padding: 8px 0; color: #333;">{period_start.strftime("%b %d, %Y")} - {period_end.strftime("%b %d, %Y")}</td>
                                            </tr>
                                        </table>
                                    </div>
                                    <div style="background: {'#dbeafe' if is_upgrade else '#fef3c7'}; padding: 20px; border-radius: 10px; border-left: 4px solid {'#3b82f6' if is_upgrade else '#f59e0b'}; margin: 20px 0;">
                                        <p style="margin: 0; color: {'#1e40af' if is_upgrade else '#92400e'}; font-weight: bold;">
                                            {'🎉 Enjoy your increased quota!' if is_upgrade else 'ℹ️ Your new plan is now active.'}
                                        </p>
                                    </div>
                                    <p style="color: #666; font-size: 14px;">
                                        Questions? Contact us at <a href="mailto:rahul@listfast.ai">rahul@listfast.ai</a>.
                                    </p>
                                </div>
                                <div style="background: #333; padding: 20px; text-align: center;">
                                    <p style="color: #999; margin: 0; font-size: 12px;">© 2025 ListFast.ai</p>
                                </div>
                            </body>
                        </html>
                        """
                        
                        msg = EmailMultiAlternatives(
                            subject=subject,
                            body=f"Your plan has been {'upgraded' if is_upgrade else 'changed'} from {old_plan_name} to {new_plan.name}.",
                            from_email=EMAIL_USER,
                            to=[user_plan.user.email]
                        )
                        msg.attach_alternative(body_html, "text/html")
                        
                        try:
                            msg.send()
                            logging.info(f"Plan change email sent to {user_plan.user.email}")
                        except Exception:
                            pass
                            
                except Plan.DoesNotExist:
                    logging.error(f"Plan not found for price_id: {price_id}")
                    
            except UserPlan.DoesNotExist:
                logging.warning(f"UserPlan not found for updated subscription: {subscription_id}")

        elif event_type == "charge.refunded":
            charge = event["data"]["object"]
            refund = charge.get("refunds", {}).get("data", [{}])[0]
            refund_amount = charge['amount_refunded'] / 100
            customer_email = charge.get("billing_details", {}).get("email") or charge.get("receipt_email")
            
            logging.info(f"Charge refunded: {charge['id']} - Amount: £{refund_amount}")
            
            if customer_email:
                subject = "Refund Initiated - ListFast.ai"
                body_html = f"""
                <html>
                    <body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                        <div style="background: linear-gradient(135deg, #10b981 0%, #059669 100%); padding: 30px; text-align: center;">
                            <h1 style="color: white; margin: 0;">💰 Refund Initiated</h1>
                        </div>
                        <div style="padding: 40px 30px; background: #f9f9f9;">
                            <h2 style="color: #333;">Refund in Progress</h2>
                            <p style="color: #666; font-size: 16px; line-height: 1.6;">
                                Your refund has been initiated by our team.
                            </p>
                            <div style="background: white; padding: 30px; border-radius: 10px; margin: 30px 0;">
                                <h3 style="color: #10b981; margin-top: 0;">Refund Details</h3>
                                <table style="width: 100%; border-collapse: collapse;">
                                    <tr>
                                        <td style="padding: 8px 0; color: #666; font-weight: bold;">Refund Amount:</td>
                                        <td style="padding: 8px 0; color: #10b981; font-weight: bold; font-size: 18px;">£{refund_amount:.2f}</td>
                                    </tr>
                                    <tr>
                                        <td style="padding: 8px 0; color: #666; font-weight: bold;">Status:</td>
                                        <td style="padding: 8px 0; color: #f59e0b;">Initiated</td>
                                    </tr>
                                </table>
                            </div>
                            <div style="background: #dbeafe; padding: 20px; border-radius: 10px; border-left: 4px solid #3b82f6; margin: 20px 0;">
                                <p style="margin: 0; color: #1e40af; font-weight: bold;">
                                    ℹ️ Your subscription will be canceled shortly and you'll receive a confirmation email once complete.
                                </p>
                            </div>
                            <p style="color: #666; font-size: 14px;">
                                Questions? Contact us at <a href="mailto:rahul@listfast.ai">rahul@listfast.ai</a>.
                            </p>
                        </div>
                        <div style="background: #333; padding: 20px; text-align: center;">
                            <p style="color: #999; margin: 0; font-size: 12px;">© 2025 ListFast.ai</p>
                        </div>
                    </body>
                </html>
                """
                
                msg = EmailMultiAlternatives(
                    subject=subject,
                    body=f"Your refund of £{refund_amount:.2f} has been processed and will appear in your account within 5-10 business days.",
                    from_email=EMAIL_USER,
                    to=[customer_email]
                )
                msg.attach_alternative(body_html, "text/html")
                
                try:
                    msg.send()
                    logging.info(f"Refund confirmation email sent to {customer_email}")
                except Exception as e:
                    logging.error(f"Failed to send refund email: {str(e)}")

        return Response({"received": True})

class OrderHistoryAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        orders = Order.objects.filter(user=request.user).order_by('-created_at')[:20]
        
        return Response({
            "orders": [{
                "id": order.id,
                "order_type": order.order_type,
                "amount": float(order.amount),
                "currency": order.currency.upper(),
                "description": order.description,
                "status": order.status,
                "created_at": order.created_at.isoformat(),
            } for order in orders]
        })


class SubscribeToMailchimpAPIView(APIView):
    def post(self, request):
        email = request.data.get("email", "").strip().lower()
        if not email:
            return Response({"error": "Email is required"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            subscriber, created = NewsletterSubscriber.objects.get_or_create(
                email=email,
                defaults={"is_active": True}
            )
            
            if not created:
                if not subscriber.is_active:
                    subscriber.is_active = True
                    subscriber.save()
                    logging.info(f"Newsletter subscription reactivated for: {email}")
                    return Response({"message": "Successfully resubscribed!"}, status=status.HTTP_200_OK)
                else:
                    return Response({"message": "You're already subscribed!"}, status=status.HTTP_200_OK)
            
            logging.info(f"New newsletter subscription from: {email}")
            return Response({"message": "Successfully subscribed!"}, status=status.HTTP_200_OK)
            
        except Exception as e:
            logging.error(f"Error subscribing {email} to newsletter: {str(e)}")
            return Response({"error": "Failed to subscribe. Please try again later."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class ContactFormAPIView(APIView):
    def post(self, request):
        name = request.data.get("name", "").strip()
        email = request.data.get("email", "").strip().lower()
        message = request.data.get("message", "").strip()
        
        if not name or not email or not message:
            return Response({"error": "All fields are required"}, status=status.HTTP_400_BAD_REQUEST)
        
        if len(message) < 10:
            return Response({"error": "Message must be at least 10 characters"}, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            user = request.user if request.user.is_authenticated else None
            
            contact_submission = ContactFormSubmission.objects.create(
                name=name,
                email=email,
                message=message,
                user=user
            )
            
            logging.info(f"Contact form submission saved with ID: {contact_submission.id}")
            
            team_subject = f"New Contact Form Submission from {name}"
            team_body_html = f"""
            <html>
                <body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                    <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 30px; text-align: center;">
                        <h1 style="color: white; margin: 0;">📬 New Contact Form Submission</h1>
                    </div>
                    <div style="padding: 40px 30px; background: #f9f9f9;">
                        <h2 style="color: #333; margin-bottom: 20px;">Contact Details</h2>
                        <div style="background: white; padding: 25px; border-radius: 10px; margin: 20px 0;">
                            <p style="margin: 10px 0; color: #666;"><strong style="color: #333;">Name:</strong> {name}</p>
                            <p style="margin: 10px 0; color: #666;"><strong style="color: #333;">Email:</strong> <a href="mailto:{email}" style="color: #667eea; text-decoration: none;">{email}</a></p>
                        </div>
                        <h3 style="color: #333; margin-top: 30px;">Message:</h3>
                        <div style="background: white; padding: 25px; border-radius: 10px; margin: 20px 0; border-left: 4px solid #667eea;">
                            <p style="color: #666; line-height: 1.6; white-space: pre-wrap;">{message}</p>
                        </div>
                        <div style="background: #dbeafe; padding: 20px; border-radius: 10px; border-left: 4px solid #3b82f6; margin: 20px 0;">
                            <p style="margin: 0; color: #1e40af; font-size: 14px;">
                                Please respond to this inquiry at your earliest convenience.
                            </p>
                        </div>
                    </div>
                    <div style="background: #333; padding: 20px; text-align: center;">
                        <p style="color: #999; margin: 0; font-size: 12px;">© 2025 ListFast.ai. All rights reserved.</p>
                    </div>
                </body>
            </html>
            """
            
            team_msg = EmailMultiAlternatives(
                subject=team_subject,
                body=f"New contact form submission from {name} ({email}): {message}",
                from_email=EMAIL_USER,
                to=["rahul@listfast.ai"]
            )
            team_msg.attach_alternative(team_body_html, "text/html")
            team_msg.send()
            
            user_subject = "Thank You for Contacting ListFast.ai"
            user_body_html = f"""
            <html>
                <body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                    <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 30px; text-align: center;">
                        <h1 style="color: white; margin: 0;">✅ Message Received!</h1>
                    </div>
                    <div style="padding: 40px 30px; background: #f9f9f9;">
                        <h2 style="color: #333; margin-bottom: 20px;">Hi {name},</h2>
                        <p style="color: #666; font-size: 16px; line-height: 1.6;">
                            Thank you for reaching out to ListFast.ai! We've received your message and our team will get back to you as soon as possible.
                        </p>
                        <div style="background: white; padding: 25px; border-radius: 10px; margin: 30px 0; border-left: 4px solid #10b981;">
                            <h3 style="color: #333; margin-top: 0;">Your Message:</h3>
                            <p style="color: #666; line-height: 1.6; white-space: pre-wrap;">{message}</p>
                        </div>
                        <div style="background: #dbeafe; padding: 20px; border-radius: 10px; border-left: 4px solid #3b82f6; margin: 20px 0;">
                            <p style="margin: 0; color: #1e40af; font-size: 14px;">
                                <strong>Expected Response Time:</strong> We typically respond within 24-48 hours during business days.
                            </p>
                        </div>
                        <p style="color: #666; font-size: 14px; margin-top: 30px;">
                            In the meantime, feel free to explore our <a href="{SITE_BASE_URL}/" style="color: #667eea; text-decoration: none; font-weight: bold;">platform</a> or check out our <a href="{SITE_BASE_URL}/faq/" style="color: #667eea; text-decoration: none; font-weight: bold;">FAQ</a> for instant answers.
                        </p>
                        <p style="color: #666; font-size: 14px;">
                            Best regards,<br>
                            <strong>The ListFast.ai Team</strong>
                        </p>
                    </div>
                    <div style="background: #333; padding: 20px; text-align: center;">
                        <p style="color: #999; margin: 0; font-size: 12px;">© 2025 ListFast.ai. All rights reserved.</p>
                    </div>
                </body>
            </html>
            """
            
            user_msg = EmailMultiAlternatives(
                subject=user_subject,
                body=f"Thank you for contacting ListFast.ai. We'll get back to you soon.",
                from_email=EMAIL_USER,
                to=[email]
            )
            user_msg.attach_alternative(user_body_html, "text/html")
            user_msg.send()
            
            logging.info(f"Contact form submission from {name} ({email})")
            return Response({"message": "Thank you! Your message has been sent successfully."}, status=status.HTTP_200_OK)
            
        except Exception as e:
            logging.error(f"Error processing contact form: {str(e)}")
            return Response({"error": "Failed to send message. Please try again later."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)