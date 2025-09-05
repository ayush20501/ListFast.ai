import os
import base64
import time
import json
import re
import random
import hashlib
from datetime import datetime, timedelta
from urllib.parse import quote
from io import BytesIO
from pathlib import Path
from PIL import Image, ImageDraw, ImageFont
from rest_framework.response import Response
import requests
from django.conf import settings
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.core.mail import EmailMultiAlternatives
from django.http import HttpResponseRedirect, JsonResponse, HttpResponse
from django.shortcuts import render, redirect
from django.urls import reverse
from django.utils import timezone
from django.views import View
from rest_framework import status
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated
from rest_framework.serializers import Serializer, CharField, EmailField, DecimalField, IntegerField, ChoiceField, ListField, URLField
from decouple import config
from openai import OpenAI
from .models import UserProfile, eBayToken, OTP, ListingCount, UserListing
from django.core.files.storage import default_storage
from django.core.files.base import ContentFile
from werkzeug.utils import secure_filename
from django.contrib.auth.mixins import LoginRequiredMixin

# Configuration
DB_URL = config("DB_URL")

# eBay
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

# Email
EMAIL_HOST = config("EMAIL_HOST")
EMAIL_USER = config("EMAIL_USER")
EMAIL_PASS = config("EMAIL_PASS")
EMAIL_PORT = config("EMAIL_PORT", cast=int)

# External APIs
OPENAI_API_KEY = config("OPENAI_API_KEY", default="")
REMOVE_BG_API_KEY = config("REMOVE_BG_API_KEY", default="")
IMGBB_API_KEY = config("IMGBB_API_KEY", default="")

# Django
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

# Serializers
class ProfileSerializer(Serializer):
    address_line1 = CharField(max_length=200, min_length=1)
    city = CharField(max_length=100, min_length=1)
    postal_code = CharField(max_length=20, min_length=1)
    country = CharField(max_length=2, default="GB")
    profile_pic_url = URLField(required=False, allow_blank=True)

class PriceSerializer(Serializer):
    value = DecimalField(max_digits=10, decimal_places=2, min_value=0.01)
    currency = ChoiceField(choices=["GBP", "USD", "EUR"])


class ListingSerializer(Serializer):
    raw_text = CharField(max_length=8000, min_length=1)
    images = ListField(child=URLField(), max_length=12, required=False)
    price = PriceSerializer() 
    quantity = IntegerField(min_value=1, max_value=999)
    condition = ChoiceField(choices=["NEW", "USED", "REFURBISHED"], required=False)

# Helper Functions
def _b64_basic():
    return "Basic " + base64.b64encode(f"{CLIENT_ID}:{CLIENT_SECRET}".encode()).decode()

def _now():
    return time.time()

def clean_keywords(keywords):
    cleaned = []
    for kw in keywords:
        kw = kw.strip()
        if len(kw) > MAX_LEN:
            kw = kw[:MAX_LEN].rsplit(" ", 1)[0]
        cleaned.append(kw)
    return cleaned

def call_llm_json(system_prompt: str, user_prompt: str) -> dict:
    if not OPENAI_API_KEY:
        raise NotImplementedError("OPENAI_API_KEY not set")
    client = OpenAI(api_key=OPENAI_API_KEY)
    try:
        resp = client.chat.completions.create(
            model="gpt-4o-mini",
            response_format={"type": "json_object"},
            messages=[
                {"role": "system", "content": system_prompt + "\nReturn only JSON."},
                {"role": "user", "content": user_prompt + "\nReturn only JSON."},
            ],
            temperature=0.0,
        )
        return json.loads(resp.choices[0].message.content)
    except Exception as e:
        raise RuntimeError(f"LLM JSON call failed: {e}")

def call_llm_text_simple(user_prompt: str, system_prompt: str = None) -> str:
    if not OPENAI_API_KEY:
        raise NotImplementedError("OPENAI_API_KEY not set")
    client = OpenAI(api_key=OPENAI_API_KEY)
    messages = [{"role": "user", "content": user_prompt}]
    if system_prompt:
        messages.insert(0, {"role": "system", "content": system_prompt})
    resp = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=messages,
        temperature=0.2,
    )
    return resp.choices[0].message.content.strip()

def build_description_simple_from_raw(raw_text: str, html_mode: bool = True) -> dict:
    prompt = (
        "Return HTML only. Use ONLY <p>, <ul>, <li>, <br>, <strong>, <em> tags. "
        "No headings, tables, images, scripts. "
        f"Write eBay product description for: {raw_text}" if html_mode else
        f"Write plain text eBay product description for: {raw_text}"
    )
    try:
        out = call_llm_text_simple(prompt)[:6000].strip()
        return {"html": out, "text": _strip_html(out) if html_mode else out}
    except Exception:
        fallback = _clean_text(raw_text, limit=2000)
        return {"html": f"<p>{fallback}</p>" if html_mode else fallback, "text": fallback}

def _strip_html(s: str) -> str:
    s = re.sub(r"<br\s*/?>", "\n", s, flags=re.I)
    s = re.sub(r"</(p|li|h[1-6])>", "\n", s, flags=re.I)
    s = re.sub(r"<[^>]+>", "", s)
    return re.sub(r"\n{3,}", "\n\n", s).strip()

def _aspect_name(x):
    if isinstance(x, str):
        return x
    return x.get("aspectName") or x.get("localizedAspectName") or x.get("name") or (x.get("aspect") or {}).get("name")

def apply_aspect_constraints(filled: dict, aspects_raw: list):
    cmap = {a.get("localizedAspectName") or (a.get("aspect") or {}).get("name"): {
        "max_len": a.get("aspectConstraint", {}).get("aspectValueMaxLength"),
        "mode": a.get("aspectMode")
    } for a in aspects_raw or []}
    adjusted = {}
    for k, vals in filled.items():
        max_len = cmap.get(k, {}).get("max_len")
        mode = cmap.get(k, {}).get("mode")
        vlist = [str(v).strip()[:max_len] if mode == "FREE_TEXT" and isinstance(max_len, int) and max_len > 0 else str(v).strip() for v in vals or []]
        if vlist:
            adjusted[k] = vlist
    return adjusted

def _fallback_title(raw_text: str) -> str:
    t = re.sub(r"\s+", " ", raw_text.strip())
    return t[:80] or "Untitled Item"

def smart_titlecase(s: str) -> str:
    if not s:
        return s
    words = s.strip().split()
    out = []
    for i, w in enumerate(words):
        if re.search(r"[A-Z]{2,}", w) or re.search(r"\d[A-Za-z]|[A-Za-z]\d", w):
            out.append(w)
            continue
        def cap_core(token: str) -> str:
            if "'" in token:
                head, *rest = token.split("'")
                return head[:1].upper() + head[1:].lower() + "".join("'" + r.lower() for r in rest)
            return token[:1].upper() + token[1:].lower()
        def cap_compound(token: str) -> str:
            parts = re.split(r"(-|/)", token)
            return "".join(cap_core(p) if p not in ("-", "/") else p for p in parts)
        lower = w.lower()
        if 0 < i < len(words) - 1 and lower in SMALL_WORDS and not re.search(r"[:–—-]$", out[-1] if out else ""):
            out.append(lower)
        else:
            out.append(cap_compound(w))
    if out:
        out[0] = out[0][:1].upper() + out[0][1:]
        out[-1] = out[-1][:1].upper() + out[-1][1:]
    return " ".join(out)

def _clean_text(t: str, limit=6000) -> str:
    return re.sub(r"\s+", " ", t or "").strip()[:limit]

def _https_only(urls):
    return [u for u in urls or [] if isinstance(u, str) and u.startswith("https://")]

def _gen_sku(prefix="ITEM"):
    ts = str(int(time.time() * 1000))
    h = hashlib.sha1(ts.encode()).hexdigest()[:6].upper()
    return f"{prefix}-{ts[-6:]}-{h}"

def get_first_policy_id(kind: str, access: str, marketplace: str) -> str:
    url = f"{BASE}/sell/account/v1/{kind}_policy"
    headers = {
        "Authorization": f"Bearer {access}",
        "Accept-Language": LANG,
        "Content-Language": LANG,
        "X-EBAY-C-MARKETPLACE-ID": marketplace,
    }
    r = requests.get(url, headers=headers, params={"marketplace_id": marketplace})
    r.raise_for_status()
    list_key = f"{kind}Policies"
    items = r.json().get(list_key, [])
    if not items:
        raise RuntimeError(f"No {kind} policies found in {marketplace}.")
    return items[0][f"{kind}PolicyId"]

def get_or_create_location(access: str, marketplace: str, profile: UserProfile) -> str:
    url = f"{BASE}/sell/inventory/v1/location"
    headers = {
        "Authorization": f"Bearer {access}",
        "Accept-Language": LANG,
        "Content-Language": LANG,
        "X-EBAY-C-MARKETPLACE-ID": marketplace,
    }
    r = requests.get(url, headers=headers)
    r.raise_for_status()
    locs = r.json().get("locations", [])
    if locs:
        return locs[0]["merchantLocationKey"]
    merchant_location_key = "PRIMARY_LOCATION"
    create_url = f"{BASE}/sell/inventory/v1/location/{merchant_location_key}"
    payload = {
        "name": "Primary Warehouse",
        "location": {
            "address": {
                "addressLine1": profile.address_line1,
                "city": profile.city,
                "postalCode": profile.postal_code,
                "country": profile.country
            }
        },
        "locationType": "WAREHOUSE",
        "merchantLocationStatus": "ENABLED",
    }
    r = requests.post(create_url, headers=headers | {"Content-Type": "application/json"}, json=payload)
    r.raise_for_status()
    return merchant_location_key

def get_category_tree_id(access_token):
    r = requests.get(
        f"{API}/commerce/taxonomy/v1/get_default_category_tree_id",
        params={"marketplace_id": MARKETPLACE_ID},
        headers={"Authorization": f"Bearer {access_token}"},
    )
    r.raise_for_status()
    return r.json()["categoryTreeId"]

def suggest_leaf_category(tree_id: str, query: str, access_token):
    r = requests.get(
        f"{API}/commerce/taxonomy/v1/category_tree/{tree_id}/get_category_suggestions",
        params={"q": query},
        headers={"Authorization": f"Bearer {access_token}"},
    )
    r.raise_for_status()
    data = r.json() or {}
    suggestions = data.get("categorySuggestions") or []
    for node in suggestions:
        cat = node.get("category") or {}
        if node.get("categoryTreeNodeLevel", 0) > 0 and node.get("leafCategoryTreeNode", True):
            return cat["categoryId"], cat["categoryName"]
    if suggestions:
        cat = suggestions[0]["category"]
        return cat["categoryId"], cat["categoryName"]
    raise RuntimeError("No category suggestions found")

def browse_majority_category(query: str, access_token):
    from collections import Counter
    r = requests.get(
        f"{API}/buy/browse/v1/item_summary/search",
        params={"q": query, "limit": 50},
        headers={
            "Authorization": f"Bearer {access_token}",
            "X-EBAY-C-MARKETPLACE-ID": MARKETPLACE_ID,
        },
    )
    r.raise_for_status()
    items = (r.json() or {}).get("itemSummaries", []) or []
    cats = [it.get("categoryId") for it in items if it.get("categoryId")]
    if not cats:
        return None, None
    top_id, _ = Counter(cats).most_common(1)[0]
    return top_id, None

def get_required_and_recommended_aspects(tree_id: str, category_id: str, access_token):
    url = f"{API}/commerce/taxonomy/v1/category_tree/{tree_id}/get_item_aspects_for_category"
    r = requests.get(
        url,
        params={"category_id": category_id},
        headers={
            "Authorization": f"Bearer {access_token}",
            "Accept-Language": LANG,
            "X-EBAY-C-MARKETPLACE-ID": MARKETPLACE_ID,
        },
    )
    r.raise_for_status()
    aspects = r.json().get("aspects", [])
    required, recommended = [], []
    for a in aspects:
        name = a.get("localizedAspectName") or a.get("aspect", {}).get("name")
        cons = a.get("aspectConstraint", {})
        if not name:
            continue
        if cons.get("aspectRequired"):
            required.append({"aspect": {"name": name}})
        elif cons.get("aspectUsage") == "RECOMMENDED":
            recommended.append({"aspect": {"name": name}})
    return {"required": required, "recommended": recommended, "raw": aspects}

def ensure_access_token(user: User):
    try:
        token = eBayToken.objects.get(user=user)
        if token.access_token and _now() < token.expires_at - 60:
            return token.access_token
        if not token.refresh_token:
            raise RuntimeError("No refresh token. Please authenticate with eBay.")
        r = requests.post(
            TOKEN,
            headers={
                "Authorization": _b64_basic(),
                "Content-Type": "application/x-www-form-urlencoded",
            },
            data={
                "grant_type": "refresh_token",
                "refresh_token": token.refresh_token,
                "scope": SCOPES,
            },
        )
        r.raise_for_status()
        data = r.json()
        token.access_token = data["access_token"]
        token.refresh_token = data.get("refresh_token", token.refresh_token)
        token.expires_at = _now() + data["expires_in"]
        token.updated_at = timezone.now()
        token.save()
        return token.access_token
    except eBayToken.DoesNotExist:
        raise RuntimeError("No eBay tokens found. Please authenticate.")

def parse_ebay_error(response_text):
    try:
        error_data = json.loads(response_text)
        if 'errors' in error_data and error_data['errors']:
            first_error = error_data['errors'][0]
            error_id = first_error.get('errorId')
            message = first_error.get('message', '')
            if error_id == 25002:
                return "This item already exists in your eBay listings."
            elif error_id == 25001:
                return "Issue with product category. Try a different description."
            elif error_id == 25003:
                return "Issue with eBay selling policies. Check your account settings."
            elif 'listing policies' in message.lower():
                return "Missing required eBay selling policies."
            elif 'inventory item' in message.lower():
                return "Failed to create product listing."
            return message
        return f"eBay API error: {response_text}"
    except (json.JSONDecodeError, KeyError, TypeError):
        return f"Unknown eBay error: {response_text}"

# Views
class IndexView(View):
    def get(self, request):
        return render(request, 'index.html')

class ProfileView(APIView):
    def get(self, request):
        return render(request, 'profile.html')

    def post(self, request):
        try:
            serializer = ProfileSerializer(data=request.data)
            if not serializer.is_valid():
                return Response({"error": "Invalid profile data", "details": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)
            
            UserProfile.objects.update_or_create(
                user=request.user,
                defaults={
                    "address_line1": serializer.validated_data["address_line1"],
                    "city": serializer.validated_data["city"],
                    "postal_code": serializer.validated_data["postal_code"].upper(),
                    "country": serializer.validated_data["country"],
                    "profile_pic_url": serializer.validated_data.get("profile_pic_url", "")
                }
            )
            return Response({"status": "success", "message": "Profile saved successfully"}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"error": f"Failed to save profile: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class ImageEnhancementView(View):
    def get(self, request):
        return render(request, 'image-enhancement.html')

class DisplayProfileView(View):
    def get(self, request):
        return render(request, 'display-profile.html')

class eBayAuthView(View):
    def get(self, request):
        return render(request, 'ebay-auth.html')

class SingleItemListingView(View):
    def get(self, request):
        return render(request, 'single-item-listing.html')

class SuccessView(View):
    def get(self, request):
        return render(request, 'success.html')

class ServicesView(View):
    def get(self, request):
        return render(request, 'services.html')

class LoginView(APIView):
    def get(self, request):
        return render(request, 'index.html')

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
        
        try:
            UserProfile.objects.get(user=user)
            has_profile = True
        except UserProfile.DoesNotExist:
            has_profile = False
        
        try:
            token = eBayToken.objects.get(user=user)
            has_ebay_auth = bool(token.refresh_token)
        except eBayToken.DoesNotExist:
            has_ebay_auth = False
        if not has_profile:
            return Response({
                "status": "success",
                "message": "Logged in successfully, please create your profile",
                "redirect": reverse('profile')
            })
        if not has_ebay_auth:
            return Response({
                "status": "success",
                "message": "Logged in successfully, please authenticate with eBay",
                "redirect": reverse('ebay-auth')
            })
        
        return Response({
            "status": "success",
            "message": "Logged in successfully",
            "redirect": reverse('services')
        })

class LogoutView(APIView):
    def post(self, request):
        logout(request)
        return Response({"status": "success", "message": "Logged out successfully"})

class ProfileAPIView(APIView):
    permission_classes = [IsAuthenticated]

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

class eBayLoginView(LoginRequiredMixin, View):
    login_url = '/login/' 

    def get(self, request):
        try:
            profile = request.user.userprofile
        except UserProfile.DoesNotExist:
            return JsonResponse({"error": "Please create your profile first"}, status=400)

        scope_enc = quote(SCOPES, safe="")
        ru_enc = quote(RU_NAME, safe="")
        url = f"{AUTH}/oauth2/authorize?client_id={CLIENT_ID}&response_type=code&redirect_uri={ru_enc}&scope={scope_enc}&state=xyz123"

        if request.session.get("force_ebay_login"):
            url += "&prompt=login"

        return redirect(url)
        
class eBayCallbackView(LoginRequiredMixin, View):

    def get(self, request):
        code = request.GET.get("code")
        if not code:
            return HttpResponse("Missing authorization code", status=400)

        try:
            r = requests.post(
                TOKEN,
                headers={
                    "Authorization": _b64_basic(),
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                data={
                    "grant_type": "authorization_code",
                    "code": code,
                    "redirect_uri": RU_NAME
                },
            )
            r.raise_for_status()
            data = r.json()

            eBayToken.objects.update_or_create(
                user=request.user,
                defaults={
                    "access_token": data["access_token"],
                    "refresh_token": data.get("refresh_token"),
                    "expires_at": _now() + data["expires_in"],
                    "updated_at": timezone.now()
                }
            )
            return HttpResponseRedirect("/ebay-auth/?ebay_auth=success")

        except Exception as e:
            print(f"eBay auth error: {e}") 
            return HttpResponseRedirect("/ebay-auth/?error=auth_failed")

class AuthStatusView(APIView):
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
            access_exp_in = max(0, int(token.expires_at - _now())) if token.access_token else 0
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

class PublishItemView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        try:
            profile = UserProfile.objects.get(user=request.user)
        except UserProfile.DoesNotExist:
            return Response({"error": "Please create your profile first"}, status=400)
        try:
            token = eBayToken.objects.get(user=request.user)
            if not token.refresh_token:
                return Response({"error": "Please authenticate with eBay first"}, status=400)
        except eBayToken.DoesNotExist:
            return Response({"error": "Please authenticate with eBay first"}, status=400)
        serializer = ListingSerializer(data=request.data)
        if not serializer.is_valid():
            return Response({"error": "Invalid input", "details": serializer.errors}, status=400)
        raw_text_in = _clean_text(serializer.validated_data.get("raw_text"), limit=8000)
        images = _https_only(serializer.validated_data.get("images", []))
        marketplace_id = MARKETPLACE_ID
        price = serializer.validated_data["price"]
        quantity = serializer.validated_data["quantity"]
        condition = serializer.validated_data.get("condition", "NEW").upper()
        if not raw_text_in and not images:
            return Response({"error": "Raw text or images required"}, status=400)
        try:
            if not OPENAI_API_KEY:
                normalized_title = smart_titlecase(raw_text_in[:80]) or _fallback_title(raw_text_in)
                category_keywords = []
            else:
                system_prompt = (
                    "Extract concise keywords for eBay category selection and search. "
                    "Return STRICT JSON. Use ONLY facts from input. "
                    "Lowercase all keywords, no punctuation, no duplicates."
                )
                user_prompt = f"""MARKETPLACE: {marketplace_id}
RAW_TEXT:
{raw_text_in}
IMAGE_URLS (context only):
{chr(10).join(images) if images else "(none)"}
OUTPUT RULES:
- category_keywords: 1–5 short phrases (2–3 words) for product category.
- search_keywords: 3–12 search terms, lowercase, ≤ 30 chars.
- normalized_title: <=80 chars, clean, factual.
- brand: only if in RAW_TEXT.
- identifiers: only if present (isbn/ean/gtin/mpn)."""
                try:
                    s1 = call_llm_json(system_prompt, user_prompt)
                    s1["search_keywords"] = clean_keywords(s1.get("search_keywords", []))
                    normalized_title = s1.get("normalized_title") or _fallback_title(raw_text_in)
                    category_keywords = s1.get("category_keywords", [])
                except Exception as e:
                    normalized_title = smart_titlecase(raw_text_in[:80]) or _fallback_title(raw_text_in)
                    category_keywords = []
            access = ensure_access_token(request.user)
            tree_id = get_category_tree_id(access)
            query = (" ".join(category_keywords)).strip() or normalized_title
            try:
                cat_id, cat_name = suggest_leaf_category(tree_id, query, access)
            except Exception:
                cat_id, cat_name = browse_majority_category(query, access)
                if not cat_id:
                    return Response({"error": "No category found", "query": query}, status=404)
            aspects_info = get_required_and_recommended_aspects(tree_id, cat_id, access)
            req_names = [_aspect_name(x) for x in aspects_info.get("required", []) if _aspect_name(x)]
            rec_names = [_aspect_name(x) for x in aspects_info.get("recommended", []) if _aspect_name(x)]
            filled_aspects = {name: ["Unknown"] for name in req_names}
            if OPENAI_API_KEY and (req_names or rec_names):
                system_prompt2 = (
                    "Fill eBay item aspects from text/images. NEVER leave required aspects empty; "
                    "extract when explicit, infer when reasonable, otherwise use 'Does not apply'/'Unknown'."
                )
                user_prompt2 = f"""
INPUT TEXT:
{normalized_title}
RAW TEXT:
{raw_text_in}
ASPECTS:
- REQUIRED: {req_names}
- RECOMMENDED: {rec_names}
OUTPUT RULES:
{{
  "filled": {{"AspectName": ["value1","value2"]}},
  "missing_required": ["AspectName"],
  "notes": "optional"
}}
"""
                try:
                    s3 = call_llm_json(system_prompt2, user_prompt2)
                    allowed = set(req_names + rec_names)
                    for k, vals in (s3.get("filled") or {}).items():
                        if k in allowed and isinstance(vals, list):
                            clean_vals = list(dict.fromkeys([str(v).strip() for v in vals if str(v).strip()]))
                            if clean_vals:
                                filled_aspects[k] = clean_vals
                    filled_aspects = apply_aspect_constraints(filled_aspects, aspects_info.get("raw"))
                    if "Book Title" in filled_aspects:
                        filled_aspects["Book Title"] = [v[:65] for v in filled_aspects["Book Title"]]
                except Exception as e:
                    print(f"[AI Aspects Error] {e}")
            try:
                desc_bundle = build_description_simple_from_raw(raw_text_in, html_mode=True)
                description_text = desc_bundle["text"]
                description_html = desc_bundle["html"]
            except Exception as e:
                print(f"[AI Description Error] {e}")
                description_text = raw_text_in[:2000]
                description_html = f"<p>{description_text}</p>"
            lang = "en-GB" if marketplace_id == "EBAY_GB" else "en-US"
            headers = {
                "Authorization": f"Bearer {access}",
                "Content-Type": "application/json",
                "Content-Language": lang,
                "Accept-Language": lang,
                "X-EBAY-C-MARKETPLACE-ID": marketplace_id,
            }
            sku = _gen_sku("RAW")
            title = smart_titlecase(normalized_title)[:80]
            inv_url = f"{BASE}/sell/inventory/v1/inventory_item/{sku}"
            inv_payload = {
                "product": {
                    "title": title,
                    "description": description_text,
                    "aspects": filled_aspects,
                    "imageUrls": images
                },
                "condition": condition,
                "availability": {"shipToLocationAvailability": {"quantity": quantity}}
            }
            r = requests.put(inv_url, headers=headers, json=inv_payload)
            if r.status_code not in (200, 201, 204):
                return Response({"error": parse_ebay_error(r.text), "step": "inventory_item"}, status=400)
            try:
                fulfillment_policy_id = get_first_policy_id("fulfillment", access, marketplace_id)
                payment_policy_id = get_first_policy_id("payment", access, marketplace_id)
                return_policy_id = get_first_policy_id("return", access, marketplace_id)
            except RuntimeError as e:
                return Response({"error": f"Missing eBay policies: {str(e)}"}, status=400)
            merchant_location_key = get_or_create_location(access, marketplace_id, profile)
            offer_payload = {
                "sku": sku,
                "marketplaceId": marketplace_id,
                "format": "FIXED_PRICE",
                "availableQuantity": quantity,
                "categoryId": cat_id,
                "listingDescription": description_html,
                "pricingSummary": {"price": price},
                "listingPolicies": {
                    "fulfillmentPolicyId": fulfillment_policy_id,
                    "paymentPolicyId": payment_policy_id,
                    "returnPolicyId": return_policy_id
                },
                "merchantLocationKey": merchant_location_key
            }
            offer_url = f"{BASE}/sell/inventory/v1/offer"
            r = requests.post(offer_url, headers=headers, json=offer_payload)
            if r.status_code not in (200, 201):
                return Response({"error": parse_ebay_error(r.text), "step": "create_offer"}, status=400)
            offer_id = r.json().get("offerId")
            pub_url = f"{BASE}/sell/inventory/v1/offer/{offer_id}/publish"
            r = requests.post(pub_url, headers=headers)
            if r.status_code not in (200, 201):
                return Response({"error": parse_ebay_error(r.text), "step": "publish"}, status=400)
            pub = r.json()
            listing_id = pub.get("listingId") or (pub.get("listingIds") or [None])[0]
            view_url = f"https://www.ebay.co.uk/itm/{listing_id}" if marketplace_id == "EBAY_GB" else None
            listing_count, _ = ListingCount.objects.get_or_create(id=1, defaults={"total_count": 0})
            listing_count.total_count += 1
            listing_count.save()
            UserListing.objects.create(
                user=request.user,
                listing_id=listing_id,
                offer_id=offer_id,
                sku=sku,
                title=title,
                price_value=price["value"],
                price_currency=price["currency"],
                quantity=quantity,
                condition=condition,
                category_id=cat_id,
                category_name=cat_name,
                marketplace_id=marketplace_id,
                view_url=view_url
            )
            return Response({
                "status": "published",
                "offerId": offer_id,
                "listingId": listing_id,
                "viewItemUrl": view_url,
                "sku": sku,
                "marketplaceId": marketplace_id,
                "categoryId": cat_id,
                "categoryName": cat_name,
                "title": title,
                "aspects": filled_aspects
            })
        except requests.exceptions.RequestException as e:
            return Response({"error": f"Network error with eBay: {str(e)}"}, status=500)
        except RuntimeError as e:
            return Response({"error": str(e)}, status=400)
        except Exception as e:
            return Response({"error": f"Unexpected error: {str(e)}"}, status=500)

class TotalListingsView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        listing_count, _ = ListingCount.objects.get_or_create(id=1, defaults={"total_count": 0})
        return Response({"total_listings": listing_count.total_count})

class UserStatsView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        try:
            UserProfile.objects.get(user=request.user)
        except UserProfile.DoesNotExist:
            return Response(
                {"error": "Please create your profile first", "redirect": "/profile.html"},
                status=status.HTTP_400_BAD_REQUEST
            )

        try:
            token = eBayToken.objects.get(user=request.user)
            if not token.refresh_token:
                return Response(
                    {"error": "Please authenticate with eBay first", "redirect": "/ebay-auth.html"},
                    status=status.HTTP_400_BAD_REQUEST
                )
        except eBayToken.DoesNotExist:
            return Response(
                {"error": "Please authenticate with eBay first", "redirect": "/ebay-auth.html"},
                status=status.HTTP_400_BAD_REQUEST
            )

        listings = UserListing.objects.filter(user=request.user)
        total_value = sum((l.price_value or 0) * (l.quantity or 0) for l in listings)
        active_count = listings.filter(status='ACTIVE').count()
        return Response({
            "total_listings": listings.count(),
            "active_listings": active_count,
            "total_inventory_value": float(total_value),
            "email": request.user.email
        })

class MyListingsView(APIView):
    permission_classes = [IsAuthenticated]

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

class FetchAddressImageProfileView(APIView):
    permission_classes = [IsAuthenticated]

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
            return Response(
                {'error': 'User profile not found'},
                status=status.HTTP_404_NOT_FOUND
            )

class UploadProfileImageView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        file = request.FILES.get("image")
        if not file:
            return Response({"error": "No image file provided"}, status=400)
        if file.size > MAX_FILE_SIZE:
            return Response({"error": "File too large"}, status=400)
        try:
            encoded_image = base64.b64encode(file.read()).decode("utf-8")
            payload = {
                "key": IMGBB_API_KEY,
                "image": encoded_image,
                "name": secure_filename(file.name)
            }
            response = requests.post(IMGBB_UPLOAD_URL, data=payload)
            result = response.json()
            if result.get("success"):
                return Response({"status": "success", "image_url": result["data"]["url"]})
            return Response({"error": "Upload failed. Please try again later."}, status=500)
        except Exception as e:
            return Response({"error": "Upload failed. Please try again later."}, status=500)

class SendPasswordChangeOTPView(APIView):
    permission_classes = [IsAuthenticated]

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

class ChangePasswordView(APIView):
    permission_classes = [IsAuthenticated]

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

class SignupView(APIView):
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

class VerifyOTPView(APIView):
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

class ResendOTPView(APIView):
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

class RevokeeBayAuthView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        print("Revoking eBay authentication")
        eBayToken.objects.filter(user=request.user).delete()
        request.session['force_ebay_login'] = True
        return Response({"status": "success", "message": "eBay authentication revoked"})

class FormatDescriptionView(APIView):
    permission_classes = [IsAuthenticated]

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
            html_description = call_llm_text_simple(prompt, system_prompt="Return only HTML. No prose.")
            return Response({"html": html_description})
        except Exception as e:
            return Response({"error": f"Failed to format description: {str(e)}"}, status=500)

# class EnhanceImageView(APIView):
#     permission_classes = [IsAuthenticated]

#     def post(self, request):
#         image_url = request.data.get("image_url", "").strip()
#         title = request.data.get("title", "").strip() or None
#         logo_url = request.data.get("logo_url", "").strip() or None
#         remove_bg = request.data.get("remove_bg", False)
#         if not image_url:
#             return Response({"error": "image_url is required"}, status=400)
#         output_file = f"enhanced_{random.randint(1000, 9999)}.png"
#         try:
#             response = requests.get(image_url)
#             response.raise_for_status()
#             image = Image.open(BytesIO(response.content)).convert("RGBA")
#             if remove_bg and REMOVE_BG_API_KEY:
#                 try:
#                     img_byte_arr = BytesIO()
#                     image.save(img_byte_arr, format='PNG')
#                     response = requests.post(
#                         "https://api.remove.bg/v1.0/removebg",
#                         files={'image_file': img_byte_arr.getvalue()},
#                         headers={'X-Api-Key': REMOVE_BG_API_KEY}
#                     )
#                     response.raise_for_status()
#                     image_no_bg = Image.open(BytesIO(response.content)).convert("RGBA")
#                 except Exception as e:
#                     print(f"Background removal failed: {e}")
#                     image_no_bg = image
#             else:
#                 image_no_bg = image
#             tilt_angle = random.randint(-3, 3)
#             image_tilted = image_no_bg.rotate(tilt_angle, resample=Image.BICUBIC, expand=True, fillcolor=(0, 0, 0, 0))
#             banner_height = 120 if title else 0
#             canvas_size = max(image_tilted.width, image_tilted.height + banner_height)
#             canvas = Image.new("RGBA", (canvas_size, canvas_size), "WHITE")
#             paste_x = (canvas_size - image_tilted.width) // 2
#             paste_y = banner_height + (canvas_size - banner_height - image_tilted.height) // 2
#             canvas.paste(image_tilted, (paste_x, paste_y), image_tilted)
#             draw = ImageDraw.Draw(canvas)
#             if title:
#                 font_size = 150
#                 padding = 40
#                 try:
#                     font = ImageFont.truetype("Roboto-Bold.ttf", font_size)
#                 except IOError:
#                     font = ImageFont.load_default()
#                 while font_size > 10:
#                     bbox = draw.textbbox((0, 0), title, font=font)
#                     text_width = bbox[2] - bbox[0]
#                     if text_width <= canvas_size - padding:
#                         break
#                     font_size -= 10
#                     font = font.font_variant(size=font_size)
#                 bbox = draw.textbbox((0, 0), title, font=font)
#                 text_width = bbox[2] - bbox[0]
#                 text_height = bbox[3] - bbox[1]
#                 text_x = (canvas_size - text_width) // 2
#                 text_y = (banner_height - text_height) // 2
#                 draw.rectangle((0, 0, canvas_size, banner_height), fill="yellow")
#                 draw.text((text_x, text_y), title, fill="black", font=font)
#             if logo_url:
#                 try:
#                     logo_response = requests.get(logo_url)
#                     logo_response.raise_for_status()
#                     logo = Image.open(BytesIO(logo_response.content)).convert("RGBA")
#                     logo_width = canvas_size // 10
#                     logo_height = int((logo.height / logo.width) * logo_width)
#                     logo = logo.resize((logo_width, logo_height), Image.LANCZOS)
#                     logo_x = canvas_size - logo_width - 20
#                     logo_y = canvas_size - logo_height - 20
#                     canvas.paste(logo, (logo_x, logo_y), logo)
#                 except Exception as e:
#                     print(f"Failed to process logo: {e}")
#             output_path = default_storage.save(output_file, ContentFile(b""))
#             canvas.save(default_storage.path(output_path), "PNG")
#             response = HttpResponse(default_storage.open(output_path), content_type="image/png")
#             default_storage.delete(output_path)
#             return response
#         except requests.exceptions.RequestException as e:
#             return Response({"error": f"Failed to download image or logo: {e}"}, status=400)
#         except Exception as e:
#             return Response({"error": f"An unexpected error occurred: {e}"}, status=500)

class EnhanceImageView(APIView):
    permission_classes = [IsAuthenticated]

    def get_font(self, size):
        font_dir = os.path.join(settings.BASE_DIR, 'fonts')  
        font_path = os.path.join(font_dir, "arialbd.ttf")
        try:
            return ImageFont.truetype(font_path, size)
        except IOError as e:
            print(f"Failed to load Arial Bold font: {e}")
            return ImageFont.load_default()

    def post(self, request):
        image_url = request.data.get("image_url", "").strip()
        title = request.data.get("title", "").strip() or None
        logo_url = request.data.get("logo_url", "").strip() or None
        remove_bg = request.data.get("remove_bg", False)

        if not image_url:
            return Response({"error": "The field 'image_url' is required."}, status=400)

        output_file = f"enhanced_{random.randint(1000, 9999)}.png"

        try:
            response = requests.get(image_url)
            response.raise_for_status()
            image = Image.open(BytesIO(response.content)).convert("RGBA")

            if remove_bg and REMOVE_BG_API_KEY:
                try:
                    img_byte_arr = BytesIO()
                    image.save(img_byte_arr, format="PNG")
                    response = requests.post(
                        "https://api.remove.bg/v1.0/removebg",
                        files={"image_file": img_byte_arr.getvalue()},
                        headers={"X-Api-Key": REMOVE_BG_API_KEY},
                    )
                    response.raise_for_status()
                    image_no_bg = Image.open(BytesIO(response.content)).convert("RGBA")
                except Exception as e:
                    return Response({"error": f"Background removal failed. Please try again later."}, status=500)
            else:
                image_no_bg = image

            tilt_angle = random.randint(-3, 3)
            image_tilted = image_no_bg.rotate(
                tilt_angle,
                resample=Image.BICUBIC,
                expand=True,
                fillcolor=(0, 0, 0, 0),
            )

            banner_height = 120
            canvas_size = max(image_tilted.width, image_tilted.height + banner_height)
            canvas = Image.new("RGBA", (canvas_size, canvas_size), "WHITE")

            paste_x = (canvas_size - image_tilted.width) // 2
            paste_y = banner_height + (canvas_size - banner_height - image_tilted.height) // 2
            canvas.paste(image_tilted, (paste_x, paste_y), image_tilted)

            draw = ImageDraw.Draw(canvas)

            if title:
                padding = 60
                max_text_width = canvas_size - padding * 2
                font_size = 80
                font = self.get_font(font_size)

                if hasattr(font, "getbbox"):
                    bbox = font.getbbox(title)
                    text_width, text_height = bbox[2] - bbox[0], bbox[3] - bbox[1]
                else:
                    mask = font.getmask(title)
                    text_width, text_height = mask.size

                while text_width > max_text_width and font_size > 16:
                    font_size -= 4
                    font = self.get_font(font_size)
                    if hasattr(font, "getbbox"):
                        bbox = font.getbbox(title)
                        text_width, text_height = bbox[2] - bbox[0], bbox[3] - bbox[1]
                    else:
                        mask = font.getmask(title)
                        text_width, text_height = mask.size

                while text_height > banner_height - 20 and font_size > 16:
                    font_size -= 4
                    font = self.get_font(font_size)
                    if hasattr(font, "getbbox"):
                        bbox = font.getbbox(title)
                        text_width, text_height = bbox[2] - bbox[0], bbox[3] - bbox[1]
                    else:
                        mask = font.getmask(title)
                        text_width, text_height = mask.size

                draw.rectangle((0, 0, canvas_size, banner_height), fill="yellow")
                text_x = (canvas_size - text_width) // 2
                text_y = (banner_height - text_height) // 2
                draw.text((text_x, text_y), title, fill="black", font=font)

            if logo_url:
                try:
                    logo_response = requests.get(logo_url)
                    logo_response.raise_for_status()
                    logo = Image.open(BytesIO(logo_response.content)).convert("RGBA")
                    logo_width = canvas_size // 10
                    logo_height = int((logo.height / logo.width) * logo_width)
                    logo = logo.resize((logo_width, logo_height), Image.LANCZOS)
                    logo_x = canvas_size - logo_width - 20
                    logo_y = canvas_size - logo_height - 20
                    canvas.paste(logo, (logo_x, logo_y), logo)
                except Exception as e:
                    return Response({"error": f"Failed to process logo. Please try again later."}, status=400)

            output_path = default_storage.save(output_file, ContentFile(b""))
            canvas.save(default_storage.path(output_path), "PNG")
            response = HttpResponse(default_storage.open(output_path), content_type="image/png")
            default_storage.delete(output_path)
            return response

        except requests.exceptions.RequestException as e:
            return Response({"error": f"Unable to download image: {str(e)}"}, status=400)
        except OSError as e:
            return Response({"error": f"Invalid image format. Please try again with a different image."}, status=400)
        except Exception as e:
            return Response({"error": f"Unexpected server error. Please try again later."}, status=500)


class PreviewItemView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        print("PreviewItemView")
        try:
            profile = UserProfile.objects.get(user=request.user)
        except UserProfile.DoesNotExist:
            return Response({"error": "Please create your profile first"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            token = eBayToken.objects.get(user=request.user)
            if not token.refresh_token:
                return Response({"error": "Please authenticate with eBay first"}, status=status.HTTP_400_BAD_REQUEST)
        except eBayToken.DoesNotExist:
            return Response({"error": "Please authenticate with eBay first"}, status=status.HTTP_400_BAD_REQUEST)

        serializer = ListingSerializer(data=request.data)
        if not serializer.is_valid():
            return Response({"error": "Invalid input", "details": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)

        raw_text_in = _clean_text(serializer.validated_data.get("raw_text"), limit=8000)
        images = _https_only(serializer.validated_data.get("images", []))
        marketplace_id = MARKETPLACE_ID
        price = serializer.validated_data["price"]
        quantity = serializer.validated_data["quantity"]
        condition = serializer.validated_data.get("condition", "NEW").upper()

        if not raw_text_in and not images:
            return Response({"error": "Raw text or images required"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            if not OPENAI_API_KEY:
                normalized_title = smart_titlecase(raw_text_in[:80]) or _fallback_title(raw_text_in)
                category_keywords = []
                brand = None
            else:
                system_prompt = (
                    "Extract concise keywords for eBay category selection and search. "
                    "Return STRICT JSON per the schema. Use ONLY facts from input. "
                    "Do NOT invent identifiers; omit if absent. "
                    "Lowercase all keywords, no punctuation, no duplicates. "
                    "search_keywords must be ≤ 30 characters."
                )
                user_prompt = f"""MARKETPLACE: {marketplace_id}
RAW_TEXT:
{raw_text_in}
IMAGE_URLS (context only, do not copy text):
{chr(10).join(images) if images else "(none)"}
OUTPUT RULES:
- category_keywords: 1–5 short phrases (2–3 words) for product category.
- search_keywords: 3–12 search terms buyers would type (mix of unigrams/bigrams/trigrams), lowercase.
- normalized_title: <=80 chars, clean and factual (no emojis/promo).
- brand: only if explicitly in RAW_TEXT.
- identifiers: only if explicitly present (isbn/ean/gtin/mpn)."""
                try:
                    s1 = call_llm_json(system_prompt, user_prompt)
                    # Assuming serializer validates similar to KEYWORDS_SCHEMA
                    s1["search_keywords"] = clean_keywords(s1.get("search_keywords", []))
                    normalized_title = s1.get("normalized_title") or _fallback_title(raw_text_in)
                    category_keywords = s1.get("category_keywords", [])
                    brand = s1.get("brand")
                except Exception as e:
                    print(f"[AI Keywords Error] {e}")
                    normalized_title = smart_titlecase(raw_text_in[:80]) or _fallback_title(raw_text_in)
                    category_keywords = []
                    brand = None

            access = ensure_access_token(request.user)
            tree_id = get_category_tree_id(access)
            query = (" ".join(category_keywords)).strip() or normalized_title
            try:
                cat_id, cat_name = suggest_leaf_category(tree_id, query, access)
            except Exception:
                cat_id, cat_name = browse_majority_category(query, access)
                if not cat_id:
                    return Response({"error": "No category found", "query": query}, status=status.HTTP_404_NOT_FOUND)

            aspects_info = get_required_and_recommended_aspects(tree_id, cat_id, access)
            req_names = [_aspect_name(x) for x in aspects_info.get("required", []) if _aspect_name(x)]
            rec_names = [_aspect_name(x) for x in aspects_info.get("recommended", []) if _aspect_name(x)]

            filled_aspects = {name: ["Unknown"] for name in req_names}
            if OPENAI_API_KEY and (req_names or rec_names):
                system_prompt2 = (
                    "Fill eBay item aspects from provided text/images. NEVER leave required aspects empty; "
                    "extract when explicit, infer when reasonable, otherwise use 'Does not apply'/'Unknown'."
                )
                user_prompt2 = f"""
INPUT TEXT:
{normalized_title}
RAW TEXT:
{raw_text_in}
ASPECTS:
- REQUIRED: {req_names}
- RECOMMENDED: {rec_names}
OUTPUT RULES:
{{
  "filled": {{"AspectName": ["value1","value2"]}},
  "missing_required": ["AspectName"],
  "notes": "optional"
}}
"""
                try:
                    s3 = call_llm_json(system_prompt2, user_prompt2)
                    # Assuming serializer validates similar to ASPECTS_FILL_SCHEMA
                    allowed = set(req_names + rec_names)
                    for k, vals in (s3.get("filled") or {}).items():
                        if k in allowed and isinstance(vals, list):
                            clean_vals = list(dict.fromkeys([str(v).strip() for v in vals if str(v).strip()]))
                            if clean_vals:
                                filled_aspects[k] = clean_vals
                    filled_aspects = apply_aspect_constraints(filled_aspects, aspects_info.get("raw"))
                    if "Book Title" in filled_aspects:
                        filled_aspects["Book Title"] = [v[:65] for v in filled_aspects["Book Title"]]
                except Exception as e:
                    print(f"[AI Aspects Error] {e}")

            try:
                desc_bundle = build_description_simple_from_raw(raw_text_in, html_mode=True)
                description_text = desc_bundle["text"]
                description_html = desc_bundle["html"]
            except Exception as e:
                print(f"[AI Description Error] {e}")
                description_text = raw_text_in[:2000]
                description_html = f"<p>{description_text}</p>"

            title = smart_titlecase(normalized_title)[:80]
            return Response({
                "title": title,
                "description": {"text": description_text, "html": description_html, "used_html": True},
                "aspects": filled_aspects,
                "sku": _gen_sku("RAW"),
                "price": price,
                "quantity": quantity,
                "condition": condition,
                "category_id": cat_id,
                "category_name": cat_name,
                "marketplace_id": marketplace_id,
                "images": images
            })

        except requests.exceptions.RequestException as e:
            return Response({"error": f"Network error with eBay: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        except RuntimeError as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({"error": f"Unexpected error: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class PublishItemFromPreviewView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        try:
            profile = UserProfile.objects.get(user=request.user)
        except UserProfile.DoesNotExist:
            return Response({"error": "Please create your profile first"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            token = eBayToken.objects.get(user=request.user)
            if not token.refresh_token:
                return Response({"error": "Please authenticate with eBay first"}, status=status.HTTP_400_BAD_REQUEST)
        except eBayToken.DoesNotExist:
            return Response({"error": "Please authenticate with eBay first"}, status=status.HTTP_400_BAD_REQUEST)

        required_fields = ["title", "description", "aspects", "sku", "price", "quantity", "condition", "category_id", "marketplace_id", "images"]
        for field in required_fields:
            if field not in request.data:
                return Response({"error": f"Missing required field: {field}"}, status=status.HTTP_400_BAD_REQUEST)

        title = _clean_text(request.data.get("title"), limit=80)
        description = request.data.get("description", {})
        description_text = _clean_text(description.get("text"), limit=2000)
        description_html = description.get("html") if description.get("used_html") else f"<p>{description_text}</p>"
        aspects = request.data.get("aspects", {})
        sku = request.data.get("sku")
        price = request.data.get("price")
        quantity = int(request.data.get("quantity", 1))
        condition = request.data.get("condition").upper()
        category_id = request.data.get("category_id")
        marketplace_id = request.data.get("marketplace_id")
        images = _https_only(request.data.get("images"))

        if not title or not description_text or not images:
            return Response({"error": "Title, description, and at least one image URL are required"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            access = ensure_access_token(request.user)
            lang = "en-GB" if marketplace_id == "EBAY_GB" else "en-US"
            headers = {
                "Authorization": f"Bearer {access}",
                "Content-Type": "application/json",
                "Content-Language": lang,
                "Accept-Language": lang,
                "X-EBAY-C-MARKETPLACE-ID": marketplace_id,
            }
            inv_url = f"{BASE}/sell/inventory/v1/inventory_item/{sku}"
            inv_payload = {
                "product": {
                    "title": title,
                    "description": description_text,
                    "aspects": aspects,
                    "imageUrls": images
                },
                "condition": condition,
                "availability": {"shipToLocationAvailability": {"quantity": quantity}}
            }
            r = requests.put(inv_url, headers=headers, json=inv_payload, timeout=30)
            if r.status_code not in (200, 201, 204):
                return Response({"error": parse_ebay_error(r.text), "step": "inventory_item"}, status=status.HTTP_400_BAD_REQUEST)

            try:
                fulfillment_policy_id = get_first_policy_id("fulfillment", access, marketplace_id)
                payment_policy_id = get_first_policy_id("payment", access, marketplace_id)
                return_policy_id = get_first_policy_id("return", access, marketplace_id)
            except RuntimeError as e:
                return Response({"error": f"Missing eBay policies: {str(e)}. Please set up your selling policies."}, status=status.HTTP_400_BAD_REQUEST)

            merchant_location_key = get_or_create_location(access, marketplace_id, profile)
            offer_payload = {
                "sku": sku,
                "marketplaceId": marketplace_id,
                "format": "FIXED_PRICE",
                "availableQuantity": quantity,
                "categoryId": category_id,
                "listingDescription": description_html,
                "pricingSummary": {"price": price},
                "listingPolicies": {
                    "fulfillmentPolicyId": fulfillment_policy_id,
                    "paymentPolicyId": payment_policy_id,
                    "returnPolicyId": return_policy_id
                },
                "merchantLocationKey": merchant_location_key
            }
            offer_url = f"{BASE}/sell/inventory/v1/offer"
            r = requests.post(offer_url, headers=headers, json=offer_payload, timeout=30)
            if r.status_code not in (200, 201):
                return Response({"error": parse_ebay_error(r.text), "step": "create_offer"}, status=status.HTTP_400_BAD_REQUEST)

            offer_id = r.json().get("offerId")
            pub_url = f"{BASE}/sell/inventory/v1/offer/{offer_id}/publish"
            r = requests.post(pub_url, headers=headers, timeout=30)
            if r.status_code not in (200, 201):
                return Response({"error": parse_ebay_error(r.text), "step": "publish"}, status=status.HTTP_400_BAD_REQUEST)

            pub = r.json()
            listing_id = pub.get("listingId") or (pub.get("listingIds") or [None])[0]
            view_url = f"https://www.ebay.co.uk/itm/{listing_id}" if marketplace_id == "EBAY_GB" else None

            listing_count, _ = ListingCount.objects.get_or_create(id=1, defaults={"total_count": 0})
            listing_count.total_count += 1
            listing_count.save()

            UserListing.objects.create(
                user=request.user,
                listing_id=listing_id,
                offer_id=offer_id,
                sku=sku,
                title=title,
                price_value=price["value"],
                price_currency=price["currency"],
                quantity=quantity,
                condition=condition,
                category_id=category_id,
                category_name=request.data.get("category_name"),
                marketplace_id=marketplace_id,
                view_url=view_url
            )

            return Response({
                "status": "published",
                "offerId": offer_id,
                "listingId": listing_id,
                "viewItemUrl": view_url,
                "sku": sku,
                "marketplaceId": marketplace_id,
                "categoryId": category_id,
                "categoryName": request.data.get("category_name"),
                "title": title,
                "aspects": aspects
            })

        except requests.exceptions.RequestException as e:
            return Response({"error": f"Network error with eBay: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        except RuntimeError as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({"error": f"Unexpected error: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
