from decimal import Decimal
import io
import os

import random
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
from rest_framework.serializers import Serializer, CharField, DecimalField, IntegerField, ChoiceField, ListField, URLField
from decouple import config
from .models import UserProfile, eBayToken, OTP, ListingCount, UserListing, TaskRecord
from .tasks import create_single_item_listing_task, create_multipack_listing_task, create_bundle_listing_task
from . import helpers
from werkzeug.utils import secure_filename
import uuid
from typing import Any, Dict, Tuple, Optional
from PIL import Image, ImageDraw, ImageFont, ImageFile, ImageFilter
from rest_framework.permissions import IsAuthenticated
from rest_framework.authentication import SessionAuthentication
from django.contrib.auth.decorators import login_required
import numpy as np
from botocore.exceptions import ClientError
import boto3


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


# ----------------------------------Views----------------------------------

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
    print(request)
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
# ---------------------------------------APIViews---------------------------------------

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

        listings = UserListing.objects.filter(user=request.user)
        total_value = sum((l.price_value or 0) * (l.quantity or 0) for l in listings)
        active_count = listings.filter(status='ACTIVE').count()
        return Response({"total_listings": listings.count(),"active_listings": active_count,"total_inventory_value": float(total_value),"email": request.user.email})

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
                'country': profile.country,
                'profile_pic_url': profile.profile_pic_url
            }
            return Response(profile_data, status=status.HTTP_200_OK)
        except UserProfile.DoesNotExist:
            return Response({'error': 'User profile not found'},status=status.HTTP_404_NOT_FOUND)

class UploadProfileImageAPIView(APIView):
    def post(self, request):
        file = request.FILES.get("image")
        if not file:
            return Response({"error": "No image file provided"}, status=400)
        if getattr(file, "size", 0) > MAX_FILE_SIZE:
            return Response({"error": "File too large"}, status=400)

        output_path = None
        try:
            os.makedirs("media", exist_ok=True)
            output_path = f"media/single_{uuid.uuid4().hex}.jpg"

            with open(output_path, "wb") as out:
                for chunk in file.chunks():
                    out.write(chunk)

            processed_image_url = helpers.upload_to_s3(output_path)
            if not processed_image_url:
                return Response({"error": "Upload failed. Please try again later."},
                                status=status.HTTP_500_INTERNAL_SERVER_ERROR)

            if os.path.exists(output_path):
                os.remove(output_path)

            return Response({"status": "success", "image_url": processed_image_url})

        except Exception as e:
            try:
                if output_path and os.path.exists(output_path):
                    os.remove(output_path)
            except Exception:
                pass
            return Response({"error": f"Upload failed. Please try again later."},status=status.HTTP_500_INTERNAL_SERVER_ERROR)


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
        except Exception:
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
            request.session.pop('signup_data', None)
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

# --------------------------------------------------------------Multipack View--------------------------------------------------------------



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

# --------------------------------------------------------------Bundle View--------------------------------------------------------------

    
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
