from decimal import Decimal
import io
import os
import base64
import time
import json
import re
import random
from datetime import datetime, timedelta
from urllib.parse import quote
from PIL import Image, ImageDraw, ImageFont
from rest_framework.response import Response
import requests
from django.conf import settings
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import User
from django.core.mail import EmailMultiAlternatives
from django.http import HttpResponseRedirect, JsonResponse, HttpResponse
from django.shortcuts import render, redirect
from django.urls import reverse
from django.utils import timezone
from django.views import View
from rest_framework import status
from rest_framework.views import APIView
from rest_framework.serializers import Serializer, CharField, DecimalField, IntegerField, ChoiceField, ListField, URLField
from decouple import config
from openai import OpenAI
from .models import UserProfile, eBayToken, OTP, ListingCount, UserListing
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
IMGBB_API_KEY = config("IMGBB_API_KEY", default="")

REMBG_API_KEY = config("REMBG_API_KEY", default="")
REMBG_API_URL = config("REMBG_API_URL", default="")
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


# ----------------------------------Helper Functions----------------------------------

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
            timeout=60.0,
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
        timeout=60.0,
    )
    return resp.choices[0].message.content.strip()

def pack_label(pack: dict) -> str:
    t = (pack or {}).get("type", "single")
    if t == "multipack":
        q = int((pack or {}).get("quantity") or 1)
        u = (pack or {}).get("unit") or ""
        return f"Pack of {q}" + (f" {u}" if u else "")
    if t == "bundle":
        comps = (pack or {}).get("components") or []
        if comps:
            return "Bundle (" + " + ".join(map(str, comps[:4])) + (", …" if len(comps) > 4 else "") + ")"
        size = (pack or {}).get("bundle_size")
        return f"Bundle ({size} pcs)" if size and size >= 2 else "Bundle"
    return ""  # single

def build_description_simple_from_raw(raw_text: str, *,html_mode: bool = True,pack_ctx: str = "",pack: Optional[dict] = None,s0: Optional[dict] = None,          # ← NEW: structured facts from vision (dict)
) -> Dict[str, str]:
    """
    Generate a short product description. If PACK CONTEXT is given, the LLM must reflect it.
    Also append a buyer-style 'Search keywords' section (SEO) at the end.
    Allowed HTML tags: <p>, <ul>, <li>, <br>, <strong>, <em>
    """
    packaging_note = pack_label(pack)
    ctx_block = f"PACK CONTEXT: {pack_ctx}\n" if pack_ctx else ""
    s0_json = json.dumps(s0, ensure_ascii=False) if s0 else ""

    # Shared guidance for using s0 JSON alongside raw_text
    guidance = (
        "Use the VISION EXTRACTION JSON for precise, structured facts (brand, identifiers, size/qty), "
        "and the PRODUCT TEXT for additional wording. Prefer JSON facts when they conflict. "
        "Do not invent data.\n"
    )

    if html_mode:
        # Ask for description + SEO list, restricted tags; include s0 JSON to ground facts
        prompt = (
            "Return HTML only. Use ONLY <p>, <ul>, <li>, <br>, <strong>, <em>. "
            "No headings, no tables, no images, no scripts.\n"
            + guidance
            + ctx_block +
            "Write an eBay product description for this item. "
            "If MULTIPACK, clearly state the pack size (e.g., 'Pack of 6') and describe what a buyer receives. "
            "If BUNDLE, include a concise 'What's included' bullet list.\n"
            "At the end, add a <p><strong>Search keywords</strong></p> followed by a <ul> with 6–12 buyer-style search terms. "
            "Rules for keywords: 3–12 search terms buyers would type (mix of unigrams/bigrams/trigrams), all lowercase; "
            "each ≤ 30 characters; include relevant pack/bundle phrasing when applicable.\n\n"
            f"VISION EXTRACTION (JSON):\n{s0_json}\n\n"
            f"PRODUCT TEXT:\n{str(raw_text)}"
        )
    else:
        # Plain text version; include s0 JSON and then a single 'Search keywords:' line
        prompt = (
            guidance
            + ctx_block +
            "Write a concise plain-text eBay product description (no bullets, no headings). "
            "Reflect the packaging context if any. "
            "After the description, add a line starting with 'Search keywords:' followed by 6–12 lowercase, comma-separated terms "
            "(each ≤ 30 characters).\n\n"
            f"VISION EXTRACTION (JSON):\n{s0_json}\n\n"
            f"PRODUCT TEXT:\n{str(raw_text)}"
        )

    try:
        out = call_llm_text_simple(prompt)
        out = out[:6000].strip()
        if html_mode:
            html_desc = out
            text_desc = _strip_html(html_desc)
            # Ensure pack note is present somewhere
            if packaging_note and packaging_note.lower() not in text_desc.lower():
                html_desc += f"<br><em>{packaging_note}</em>"
                text_desc = _strip_html(html_desc)
            return {"html": html_desc, "text": text_desc}
        else:
            # Plain text; append packaging note if missing
            if packaging_note and packaging_note.lower() not in out.lower():
                out = out + f"\n\n{packaging_note}"
            return {"html": out, "text": out}
    except Exception:
        # Safe fallback that still includes a placeholder keywords section
        fallback = _clean_text(raw_text, limit=2000)
        if html_mode:
            kw_stub = "<p><strong>Search keywords</strong></p><ul><li>product keyword</li><li>brand term</li></ul>"
            extra = f"<br><em>{packaging_note}</em>" if packaging_note else ""
            html_fallback = f"<p>{fallback}</p>{extra}{kw_stub}"
            return {"html": html_fallback, "text": _strip_html(html_fallback)}
        else:
            extra = f"\n\n{packaging_note}" if packaging_note else ""
            txt = f"{fallback}{extra}\n\nSearch keywords: product keyword, brand term"
            return {"html": txt, "text": txt}

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
    unique_id = str(uuid.uuid4())[:8].upper()
    return f"{prefix}-{ts[-6:]}-{unique_id}"

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

def upload_to_imgbb(image_path: str) -> str:
    if not IMGBB_API_KEY:
        raise RuntimeError("IMGBB_API_KEY is not set in the environment")
    with open(image_path, "rb") as file:
        files = {"image": (os.path.basename(image_path), file, "image/jpeg")}
        params = {"key": IMGBB_API_KEY}
        resp = requests.post("https://api.imgbb.com/1/upload", files=files, params=params)
    if resp.status_code != 200 or not resp.json().get("data", {}).get("url"):
        raise RuntimeError(f"ImgBB upload failed: {resp.status_code} {resp.text[:200]}")
    return resp.json()["data"]["url"]

def upload_to_s3(file_path):
    s3_client = boto3.client(
            's3',
            aws_access_key_id=AWS_ACCESS_KEY,
            aws_secret_access_key=AWS_SECRET_KEY,
            region_name=AWS_REGION
        )
    
    file_name = file_path.split('/')[-1]
    s3_key = f"images/{file_name}"  
    try:
        s3_client.upload_file(
            file_path,
            S3_BUCKET,
            s3_key,
            ExtraArgs={'ContentType': 'image/png'}
        )
        url = f"https://{S3_BUCKET}.s3.{AWS_REGION}.amazonaws.com/{s3_key}"
        return url
    except ClientError as e:
        print(f"Error: {e}")
        return None

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
                "Authorization": _b64_basic(),
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
                "expires_at": _now() + data["expires_in"],
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
            html_description = call_llm_text_simple(prompt, system_prompt="Return only HTML. No prose.")
            return Response({"html": html_description})
        except Exception as e:
            return Response({"error": f"Failed to format description: {str(e)}"}, status=500)



# --------------------------------------------------------------Enhance Image--------------------------------------------------------------

def download_rgba(url: str) -> Image.Image:
    r = requests.get(url)
    r.raise_for_status()
    return Image.open(io.BytesIO(r.content)).convert("RGBA")

def remove_bg_via_api(img: Image.Image, *, api_url: Optional[str] = None, api_key: Optional[str] = None) -> Image.Image:
    api_url = api_url or REMBG_API_URL
    api_key = api_key or REMBG_API_KEY
    if not api_key:
        return img

    buf = io.BytesIO()
    img.convert("RGBA").save(buf, format="PNG")
    buf.seek(0)
    headers = {"x-api-key": api_key}
    files = {"image": ("input.png", buf, "image/png")}

    try:
        resp = requests.post(api_url, headers=headers, files=files)
        if resp.status_code == 200:
            return Image.open(io.BytesIO(resp.content)).convert("RGBA")
        print(f"[rembg] Error {resp.status_code}: {resp.text[:200]}")
    except Exception as e:
        print(f"[rembg] Exception: {e}")
    return img

# def safe_remove_bg(img: Image.Image) -> Image.Image:
#     cut = remove_bg_via_api(img)
#     try:
#         white = Image.new("RGBA", cut.size, (255, 255, 255, 255))
#         return Image.alpha_composite(white, cut)
#     except Exception:
#         return img

def get_text_size(draw: ImageDraw.ImageDraw, text: str, font: ImageFont.FreeTypeFont) -> Tuple[int, int]:
    try:
        bbox = draw.textbbox((0, 0), text, font=font, align="center")
        return bbox[2] - bbox[0], bbox[3] - bbox[1]
    except AttributeError:
        return draw.textsize(text, font=font)

def get_font_from_folder(text: str, max_w: int, max_h: int, draw: ImageDraw.ImageDraw, min_size: int = 12) -> ImageFont.FreeTypeFont:
    font_folder = os.path.join(settings.BASE_DIR, "fonts")
    font_files = [f for f in os.listdir(font_folder) if f.endswith(('.ttf', '.otf'))]
    if not font_files:
        return ImageFont.load_default()

    for size in range(max_h, min_size - 1, -2):
        for font_file in font_files:
            try:
                font_path = os.path.join(font_folder, font_file)
                font = ImageFont.truetype(font_path, size)
                w, h = get_text_size(draw, text, font)
                if w <= max_w and h <= max_h:
                    return font
            except Exception:
                continue
    return ImageFont.load_default()

def fit_within(img: Image.Image, box_w: int, box_h: int, margin_ratio: float = 0.94) -> Image.Image:
    target_w = int(box_w * margin_ratio)
    target_h = int(box_h * margin_ratio)
    w, h = img.size
    scale = min(target_w / w, target_h / h)
    return img.resize((max(1, int(w * scale)), max(1, int(h * scale))), Image.LANCZOS)

def paste_with_shadow(canvas: Image.Image, tile: Image.Image, x: int, y: int, shadow_offset=(16, 16), blur=22):
    if tile.mode != "RGBA":
        tile = tile.convert("RGBA")
    try:
        alpha = tile.split()[3]
    except Exception:
        alpha = None
    if alpha is not None:
        shadow = Image.new("RGBA", tile.size, (0, 0, 0, 0))
        shadow.putalpha(alpha)
        shadow = shadow.filter(ImageFilter.GaussianBlur(blur))
        sx, sy = x + shadow_offset[0], y + shadow_offset[1]
        canvas.paste(shadow, (sx, sy), shadow)
    canvas.paste(tile, (x, y), tile)

class EnhanceImageAPIView(APIView):
    def post(self, request):
        image_url = request.data.get("image_url", "").strip()
        title = request.data.get("title", "").strip() or None
        logo_url = request.data.get("logo_url", "").strip() or None
        remove_bg = bool(request.data.get("remove_bg", False))

        if not image_url:
            return Response({"error": "The field 'image_url' is required."}, status=400)

        try:
            unit = download_rgba(image_url)
            if remove_bg:
                unit = safe_remove_bg(unit)

            S = 1600 
            canvas = Image.new("RGBA", (S, S), (255, 255, 255, 255))
            draw = ImageDraw.Draw(canvas)

            banner_h = 0
            if title:
                banner_h = max(100, int(S * 0.16))
                draw.rectangle([0, 0, S, banner_h], fill=(255, 215, 0, 255))
                font = get_font_from_folder(title, int(S * 0.9), int(banner_h * 0.8), draw)
                tw, th = get_text_size(draw, title, font)
                tx, ty = (S - tw) // 2, (banner_h - th) // 2
                draw.text((tx, ty), title, font=font, fill=(0, 0, 0, 255))

            content_top = banner_h
            content_h = S - banner_h
            box_w = S - 2 * 48
            box_h = content_h - 2 * 48
            tile = fit_within(unit, box_w, box_h, margin_ratio=0.96)
            dx = (S - tile.size[0]) // 2
            dy = content_top + (content_h - tile.size[1]) // 2
            canvas.paste(tile, (dx, dy), tile)


            if logo_url:
                try:
                    logo = download_rgba(logo_url)
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

# --------------------------------------------------------------Item View--------------------------------------------------------------

def fetch_image(url: str) -> Image.Image:
    r = requests.get(url)
    r.raise_for_status()
    return Image.open(io.BytesIO(r.content)).convert("RGBA")

def strip_background(img: Image.Image) -> Image.Image:
    if not REMBG_API_KEY:
        raise RuntimeError("REMBG_API_KEY is not set in the environment")
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    headers = {"x-api-key": REMBG_API_KEY}
    files = {"image": ("image.png", buf, "image/png")}
    resp = requests.post(REMBG_API_URL, headers=headers, files=files)
    if resp.status_code != 200 or not resp.content:
        raise RuntimeError(f"rembg API error: {resp.status_code} {resp.text[:200]}")
    return Image.open(io.BytesIO(resp.content)).convert("RGBA")

def safe_strip_background(img: Image.Image) -> Image.Image:
    try:
        cut = strip_background(img)
        white = Image.new("RGBA", cut.size, (255, 255, 255, 255))
        return Image.alpha_composite(white, cut)
    except Exception as e:
        print(f"[rembg] background removal failed, using original image: {e}")
        return img

def resize_to_fit(img: Image.Image, box_w: int, box_h: int, margin_ratio: float = 0.94) -> Image.Image:
    target_w = int(box_w * margin_ratio)
    target_h = int(box_h * margin_ratio)
    w, h = img.size
    scale = min(target_w / w, target_h / h)
    return img.resize((max(1, int(w * scale)), max(1, int(h * scale))), Image.LANCZOS)

def create_single_image(image_url: str, output_path: str = "single_item.jpg", output_size: int = 1600, padding: int = 28, do_remove_bg: bool = True, margin_ratio: float = 0.94):
    unit = fetch_image(image_url)
    if do_remove_bg:
        unit = safe_strip_background(unit)
    S = int(output_size)
    canvas = Image.new("RGBA", (S, S), (255, 255, 255, 255))
    cell_size = S - 2 * padding
    tile = resize_to_fit(unit, cell_size, cell_size, margin_ratio=margin_ratio)
    dx = (S - tile.size[0]) // 2
    dy = (S - tile.size[1]) // 2
    canvas.paste(tile, (dx, dy), tile if tile.mode == "RGBA" else None)
    print(f"[*] Saving -> {output_path}")
    canvas.convert("RGB").save(output_path, quality=95, optimize=True, subsampling=2)
    return output_path

# class SingleItemListingAPIView(APIView):
#     def post(self, request):
#         if request.data.get("action", "publish") != "publish":
#             return Response({"error": "Only 'publish' action is supported"}, status=status.HTTP_400_BAD_REQUEST)

#         try:
#             profile = UserProfile.objects.get(user=request.user)
#         except UserProfile.DoesNotExist:
#             return Response({"error": "Please create your profile first"}, status=status.HTTP_400_BAD_REQUEST)

#         try:
#             token = eBayToken.objects.get(user=request.user)
#             if not token.refresh_token:
#                 return Response({"error": "Please authenticate with eBay first"}, status=status.HTTP_400_BAD_REQUEST)
#         except eBayToken.DoesNotExist:
#             return Response({"error": "Please authenticate with eBay first"}, status=status.HTTP_400_BAD_REQUEST)
        
#         access = ensure_access_token(request.user)
        
#         raw_text_in = _clean_text(request.data.get("raw_text", ""), limit=8000)
#         images = _https_only(request.data.get("images", []))
#         marketplace_id = MARKETPLACE_ID
#         price = request.data.get("price")
#         quantity = int(request.data.get("quantity", 1))
#         condition = request.data.get("condition", "NEW").upper()
#         sku = request.data.get("sku") or _gen_sku("RAW")
#         remove_background = request.data.get("remove_bg", False)

#         if not raw_text_in and not images:
#             return Response({"error": "Raw text or images required"}, status=status.HTTP_400_BAD_REQUEST)

#         try:
#             output_path = f"media/single_{uuid.uuid4().hex}.jpg"
#             os.makedirs("media", exist_ok=True)
#             create_single_image(image_url=images[0], output_path=output_path, do_remove_bg=remove_background)
#             processed_image_url = upload_to_imgbb(output_path)
#             images[0] = processed_image_url
#             os.remove(output_path)
#         except Exception as e:
#             print(f"[Image Processing Error] {e}")
#             return Response({"error": f"Failed to process or upload image: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

#         system_prompt = (
#             "Extract concise keywords for eBay category selection and search. "
#             "Return STRICT JSON. Use ONLY facts from input. "
#             "Lowercase all keywords, no punctuation, no duplicates. "
#             "For normalized_title, describe ONE specific item, selecting the first mentioned variant for any attribute that defines a unique item (e.g., color, size, model)."
#         )
#         user_prompt = f"""MARKETPLACE: {marketplace_id}
#         RAW_TEXT:
#         {raw_text_in}
        
#         OUTPUT RULES:
#         - category_keywords: 1–5 short phrases (2–3 words) for product category.
#         - search_keywords: 3–12 search terms, lowercase, ≤ 30 chars.
#         - normalized_title: <=80 chars, clean, factual, describes ONE item.
#         - brand: only if in RAW_TEXT.
#         - identifiers: only if present (isbn/ean/gtin/mpn)."""
#         try:
#             s1 = call_llm_json(system_prompt, user_prompt)
#             s1["search_keywords"] = clean_keywords(s1.get("search_keywords", []))
#             normalized_title = s1.get("normalized_title") or _fallback_title(raw_text_in)
#             category_keywords = s1.get("category_keywords", [])
#             brand = s1.get("brand")
#         except Exception as e:
#             print(f"[AI Keywords Error] {e}")
#             normalized_title = smart_titlecase(raw_text_in[:80]) or _fallback_title(raw_text_in)
#             category_keywords = []
#             brand = None

#         access = ensure_access_token(request.user)
#         tree_id = get_category_tree_id(access)
#         query = (" ".join(category_keywords)).strip() or normalized_title
#         try:
#             cat_id, cat_name = suggest_leaf_category(tree_id, query, access)
#         except Exception:
#             cat_id, cat_name = browse_majority_category(query, access)
#             if not cat_id:
#                 return Response({"error": "No category found", "query": query}, status=status.HTTP_404_NOT_FOUND)

#         aspects_info = get_required_and_recommended_aspects(tree_id, cat_id, access)
#         req_names = [_aspect_name(x) for x in aspects_info.get("required", []) if _aspect_name(x)]
#         rec_names = [_aspect_name(x) for x in aspects_info.get("recommended", []) if _aspect_name(x)]
#         filled_aspects = {name: ["Does not apply"] for name in req_names}

#         single_value_aspects = [
#             _aspect_name(aspect) for aspect in aspects_info.get("raw", [])
#             if _aspect_name(aspect) and aspect.get("aspectConstraint", {}).get("aspectMode") in ["FREE_TEXT", "SELECTION_ONLY"]
#         ]

#         if req_names or rec_names:
#             system_prompt2 = (
#                 "Fill eBay item aspects from text/images. NEVER leave required aspects empty; "
#                 "extract when explicit, infer when reasonable, otherwise use 'Does not apply'. "
#                 "For aspects that define unique item variations (e.g., color, size, model), select ONLY the first value mentioned in the text to describe a single item."
#             )
#             user_prompt2 = f"""
#             INPUT TEXT:
#             {normalized_title}
#             RAW TEXT:
#             {raw_text_in}
#             ASPECTS:
#             - REQUIRED: {req_names}
#             - RECOMMENDED: {rec_names}
#             OUTPUT RULES:
#             {{
#             "filled": {{"AspectName": ["value1"]}},
#             "missing_required": ["AspectName"],
#             "notes": "optional"
#             }}
#             """
#             try:
#                 s3 = call_llm_json(system_prompt2, user_prompt2)
#                 allowed = set(req_names + rec_names)
#                 for k, vals in (s3.get("filled") or {}).items():
#                     if k in allowed and isinstance(vals, list):
#                         clean_vals = list(dict.fromkeys([str(v).strip() for v in vals if str(v).strip()]))
#                         if k in single_value_aspects and clean_vals:
#                             clean_vals = [clean_vals[0]]
#                         if clean_vals:
#                             filled_aspects[k] = clean_vals
#                 filled_aspects = apply_aspect_constraints(filled_aspects, aspects_info.get("raw"))
#                 if "Book Title" in filled_aspects:
#                     filled_aspects["Book Title"] = [v[:65] for v in filled_aspects["Book Title"]]
#             except Exception as e:
#                 print(f"[AI Aspects Error] {e}")

#         try:
#             desc_bundle = build_description_simple_from_raw(raw_text_in, html_mode=True)
#             description_text = desc_bundle["text"]
#             description_html = desc_bundle["html"]
#         except Exception as e:
#             print(f"[AI Description Error] {e}")
#             description_text = raw_text_in[:2000]
#             description_html = f"<p>{description_text}</p>"

#         title = smart_titlecase(normalized_title)[:80]
#         category_id = cat_id
#         category_name = cat_name
#         aspects = filled_aspects

#         try:
#             lang = "en-GB" if marketplace_id == "EBAY_GB" else "en-US"
#             headers = {
#                 "Authorization": f"Bearer {access}",
#                 "Content-Type": "application/json",
#                 "Content-Language": lang,
#                 "Accept-Language": lang,
#                 "X-EBAY-C-MARKETPLACE-ID": marketplace_id,
#             }

#             max_attempts = 3
#             for _ in range(max_attempts):
#                 check_url = f"{BASE}/sell/inventory/v1/inventory_item/{sku}"
#                 r = requests.get(check_url, headers=headers)
#                 if r.status_code != 200:
#                     break
#                 sku = _gen_sku("RAW")
#             else:
#                 return Response({"error": "Failed to generate unique SKU"}, status=status.HTTP_400_BAD_REQUEST)

#             inv_url = f"{BASE}/sell/inventory/v1/inventory_item/{sku}"
#             inv_payload = {
#                 "product": {
#                     "title": title,
#                     "description": description_text,
#                     "aspects": aspects,
#                     "imageUrls": images
#                 },
#                 "condition": condition,
#                 "availability": {"shipToLocationAvailability": {"quantity": quantity}}
#             }
#             r = requests.put(inv_url, headers=headers, json=inv_payload)
#             if r.status_code not in (200, 201, 204):
#                 return Response({"error": parse_ebay_error(r.text), "step": "inventory_item"}, status=status.HTTP_400_BAD_REQUEST)

#             try:
#                 fulfillment_policy_id = get_first_policy_id("fulfillment", access, marketplace_id)
#                 payment_policy_id = get_first_policy_id("payment", access, marketplace_id)
#                 return_policy_id = get_first_policy_id("return", access, marketplace_id)
#             except RuntimeError as e:
#                 return Response({"error": f"Missing eBay policies: {str(e)}"}, status=status.HTTP_400_BAD_REQUEST)

#             merchant_location_key = get_or_create_location(access, marketplace_id, profile)
#             offer_payload = {
#                 "sku": sku,
#                 "marketplaceId": marketplace_id,
#                 "format": "FIXED_PRICE",
#                 "availableQuantity": quantity,
#                 "categoryId": category_id,
#                 "listingDescription": description_html,
#                 "pricingSummary": {
#                     "price": {
#                         "value": str(price["value"]),
#                         "currency": price["currency"]
#                     }
#                 },
#                 "listingPolicies": {
#                     "fulfillmentPolicyId": fulfillment_policy_id,
#                     "paymentPolicyId": payment_policy_id,
#                     "returnPolicyId": return_policy_id
#                 },
#                 "merchantLocationKey": merchant_location_key
#             }
#             offer_url = f"{BASE}/sell/inventory/v1/offer"
#             r = requests.post(offer_url, headers=headers, json=offer_payload)
#             if r.status_code not in (200, 201):
#                 return Response({"error": parse_ebay_error(r.text), "step": "create_offer"}, status=status.HTTP_400_BAD_REQUEST)

#             offer_id = r.json().get("offerId")
#             pub_url = f"{BASE}/sell/inventory/v1/offer/{offer_id}/publish"
#             r = requests.post(pub_url, headers=headers)
#             if r.status_code not in (200, 201):
#                 return Response({"error": parse_ebay_error(r.text), "step": "publish"}, status=status.HTTP_400_BAD_REQUEST)

#             pub = r.json()
#             listing_id = pub.get("listingId") or (pub.get("listingIds") or [None])[0]
#             view_url = f"https://www.ebay.co.uk/itm/{listing_id}" if marketplace_id == "EBAY_GB" else None

#             listing_count, _ = ListingCount.objects.get_or_create(id=1, defaults={"total_count": 0})
#             listing_count.total_count += 1
#             listing_count.save()

#             UserListing.objects.create(
#                 user=request.user,
#                 listing_id=listing_id,
#                 offer_id=offer_id,
#                 sku=sku,
#                 title=title,
#                 price_value=price["value"],
#                 price_currency=price["currency"],
#                 quantity=quantity,
#                 condition=condition,
#                 category_id=category_id,
#                 category_name=category_name,
#                 marketplace_id=marketplace_id,
#                 view_url=view_url,
#                 listing_type="Single"
#             )

#             return Response({
#                 "status": "published",
#                 "offerId": offer_id,
#                 "listingId": listing_id,
#                 "viewItemUrl": view_url,
#                 "sku": sku,
#                 "marketplaceId": marketplace_id,
#                 "categoryId": category_id,
#                 "categoryName": category_name,
#                 "title": title,
#                 "aspects": aspects
#             })

#         except requests.exceptions.RequestException as e:
#             return Response({"error": f"Network error with eBay: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
#         except RuntimeError as e:
#             return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)
#         except Exception as e:
#             return Response({"error": f"Unexpected error: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

def build_pack_context(body: dict) -> tuple[dict, str]:
    mode = (body.get("image_mode") or "").strip().lower()
    def to_int(x, default=0):
        try:
            return int(x)
        except Exception:
            return default
    pack = {"type": "single"}
    ctx = "SINGLE ITEM"

    if mode == "multipack":
        qty = max(to_int(body.get("pack_size"), 1), 1)
        unit = (body.get("unit") or body.get("pack_unit") or "").strip()
        pack = {"type": "multipack", "quantity": qty, "unit": unit}
        ctx = f"MULTIPACK: Pack of {qty}" + (f" {unit}" if unit else "")

    elif mode == "bundle":
        size = max(to_int(body.get("bundle_size"), 0), 0)
        components = body.get("bundle_components") or []
        pack = {"type": "bundle", "bundle_size": size, "components": components}
        if components:
            ctx = "BUNDLE: " + " + ".join(map(str, components))
        elif size >= 2:
            ctx = f"BUNDLE: {size} items"
        else:
            ctx = "BUNDLE"

    return pack, ctx

def call_llm_json_vision(system_prompt: str, text_prompt: str, image_urls: list[str]) -> dict:
    if not OPENAI_API_KEY:
        raise NotImplementedError("OPENAI_API_KEY not set; vision LLM features disabled.")
    client = OpenAI(api_key=OPENAI_API_KEY)
    user_content = [{"type": "text", "text": (text_prompt or "").strip()}]
    for u in (image_urls or [])[:8]: 
        if isinstance(u, str) and u.startswith("http"):
            user_content.append({"type": "image_url", "image_url": {"url": u}})
    print("Calling Vision API")
    resp = client.chat.completions.create(
        model="gpt-4o-mini",
        response_format={"type": "json_object"},
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_content},
        ],
        temperature=0.2,
        timeout=60.0,
    )
    print(resp)
    txt = (resp.choices[0].message.content or "").strip()
    try:
        return json.loads(txt)
    except Exception:
        m = re.search(r'\{.*\}', txt, re.DOTALL)
        return json.loads(m.group(0)) if m else {"_raw": txt}

def extract_product_from_images_gpt4o(image_urls: list[str], marketplace_id: str, pack_ctx: str = "") -> dict:
    sys_prompt = (
        "You are a product extraction assistant for creating eBay listings from images only. "
        "Look carefully at the packaging, labels, and any visible text to extract FACTS only. "
        "Return a JSON object with these keys exactly: "
        "normalized_title, raw_text, category_keywords, search_keywords, brand, identifiers, notes. "
        "Rules: "
        "• The title must be ≤80 chars, factual, no emojis or promo. "
        "• Lowercase all keywords, 3–5 category_keywords, 3–12 search_keywords; each search keyword ≤30 chars. "
        "• Only include brand if clearly visible. "
        "• identifiers object may include isbn, ean, gtin, or mpn if visible; otherwise omit. "
        "• Do NOT invent data; if unsure, leave fields empty or omit. "
    )
    text_prompt = f"""MARKETPLACE: {marketplace_id}
    PACK CONTEXT: {pack_ctx or "SINGLE ITEM"}

    Return a JSON object only.
    """
    print("Before Vision LLM Call")
    result = call_llm_json_vision(sys_prompt, text_prompt, image_urls)
    print("After Vision LLM Call")
    result["search_keywords"] = clean_keywords(result.get("search_keywords", []))
    result["category_keywords"] = clean_keywords(result.get("category_keywords", []))[:5]
    return result

def build_aspect_catalog(aspects_info):
    cat = {}
    for a in aspects_info.get("raw", []):
        name = a.get("localizedAspectName")
        if not name:
            continue
        c = a.get("aspectConstraint", {}) or {}
        if c.get("aspectUsage") == "NOT_RECOMMENDED":
            continue
        appl = set(c.get("aspectApplicableTo") or ["PRODUCT"])
        if "PRODUCT" not in appl:
            continue

        mode = c.get("aspectMode", "FREE_TEXT")
        cardinality = c.get("itemToAspectCardinality", "SINGLE")
        vals = {v.get("localizedValue") for v in (a.get("aspectValues") or []) if v.get("localizedValue")}
        cat[name] = {
            "mode": mode,
            "cardinality": cardinality,
            "values": vals if mode == "SELECTION_ONLY" else set()
        }
    return cat

def coerce_aspects_fill(s3: dict) -> dict:
    notes = s3.get("notes")
    if isinstance(notes, dict):
        s3.setdefault("filled", {})
        for k, v in notes.items():
            if isinstance(v, list) and k not in s3["filled"]:
                s3["filled"][k] = [str(x) for x in v]
        s3["notes"] = "; ".join(
            f"{k}: {', '.join(map(str, v if isinstance(v, list) else [v]))}"
            for k, v in notes.items()
        )
    return s3

def aspect_length_limits(aspects_info: dict,
                         default_free_text: int = 65,
                         default_selection: int = 65) -> dict:
    limits: dict[str, int] = {}

    def _get_name_from_any(node: Dict[str, Any], hint: Optional[str] = None) -> Optional[str]:
        for key in ("aspectName", "localizedAspectName", "name", "localizedName"):
            val = node.get(key)
            if isinstance(val, str) and val.strip():
                return val.strip()
        a = node.get("aspect")
        if isinstance(a, str) and a.strip():
            return a.strip()
        if isinstance(a, dict):
            for key in ("aspectName", "localizedAspectName", "name", "localizedName"):
                val = a.get(key)
                if isinstance(val, str) and val.strip():
                    return val.strip()
        return hint.strip() if isinstance(hint, str) and hint.strip() else None

    def _harvest_node(node: Dict[str, Any], name_hint: Optional[str] = None):
        nm = _get_name_from_any(node, hint=name_hint)
        if not isinstance(nm, str) or not nm:
            return

        cons = (node.get("constraints") or node.get("aspectConstraints") or {})
        L = (cons.get("aspectMaxLength")
             or cons.get("maxLength")
             or node.get("aspectMaxLength"))
        if isinstance(L, int) and L > 0:
            limits[nm] = L
            return

        mode = (cons.get("aspectMode") or cons.get("mode") or "").lower()
        if "free" in mode:
            limits.setdefault(nm, default_free_text)
        elif "select" in mode:
            options = node.get("values") or node.get("aspectValues") or []
            if isinstance(options, list) and options:
                try:
                    longest = max(
                        len(str(o.get("value") if isinstance(o, dict) else o))
                        for o in options
                    )
                    limits[nm] = min(max(longest, 32), default_selection)
                except Exception:
                    limits.setdefault(nm, default_selection)
            else:
                limits.setdefault(nm, default_selection)
        else:
            limits.setdefault(nm, default_free_text)

    ai = aspects_info or {}

    by_name = ((ai.get("meta") or {}).get("by_name")) or {}
    if isinstance(by_name, dict):
        for nm, node in by_name.items():
            if isinstance(node, dict):
                _harvest_node(node, name_hint=nm if isinstance(nm, str) else None)

    for key in ("required", "recommended", "optional", "aspects"):
        arr = ai.get(key)
        if isinstance(arr, list):
            for entry in arr:
                if isinstance(entry, dict):
                    _harvest_node(entry)

    limits.setdefault("Main Purpose", 65)
    limits.setdefault("Brand", 65)
    limits.setdefault("MPN", 65)
    limits.setdefault("Ingredients", 65)
    limits.setdefault("Active Ingredients", 65)

    return limits
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
def _compress_listy(text: str, max_len: int) -> str:
    s = re.sub(r"\s*\([^)]*\)", "", str(text)).strip()
    parts = [p.strip() for p in re.split(r",|;|/|•|\u2022|\s-\s", s) if p.strip()]
    if not parts:
        return _smart_truncate(s, max_len)

    kept = []
    for p in parts:
        candidate = ", ".join(kept + [p]) if kept else p
        if len(candidate) <= max_len:
            kept.append(p)
        else:
            break

    if kept:
        return ", ".join(kept)
    return _smart_truncate(s, max_len)

def _compress_claim_text(s: str) -> str:
    x = str(s).strip()
    repl = [
        (" and ", " & "),
        (" – ", " - "), ("—", "-"),
        ("  ", " "),
        ("supports normal ", ""), ("contributes to ", ""), ("function of the ", ""), ("function of ", ""),
    ]
    for a, b in repl:
        x = x.replace(a, b)
    x = re.sub(r"\s+", " ", x).strip()
    x = re.sub(r"^(Supports?|Contributes to)\s+", "", x, flags=re.IGNORECASE)
    return x.rstrip(" ,;:.")

def _smart_truncate(text: str, max_len: int) -> str:
    s = str(text).strip()
    if len(s) <= max_len:
        return s
    cut = s[:max_len]
    space = cut.rfind(" ")
    if space >= 40:
        cut = cut[:space]
    return cut.rstrip(" ,;:.-")

def _shrink_for_limit(aspect_name: str, value: str, max_len: int) -> str:
    if not isinstance(max_len, int) or max_len <= 0:
        return str(value)
    s = str(value).strip()
    if len(s) <= max_len:
        return s

    nm = (aspect_name or "").lower()
    if any(k in nm for k in ("ingredient", "feature", "material", "component", "contents", "included")):
        s = _compress_listy(s, max_len)
    elif any(k in nm for k in ("purpose", "benefit", "direction", "dosage", "indication", "description")):
        s = _compress_claim_text(s)
        if len(s) > max_len:
            s = _smart_truncate(s, max_len)
    else:
        s = _smart_truncate(s, max_len)
    return s

def sanitize_filled(filled_in: dict, catalog: dict) -> dict:
    out = {}
    for name, vals in (filled_in or {}).items():
        if name not in catalog:
            continue

        if not isinstance(vals, (list, tuple)):
            vals = [vals]
        vals = [str(v).strip() for v in vals if isinstance(v, (str, int, float)) and str(v).strip()]
        if not vals:
            continue

        spec = catalog[name]
        mode = spec["mode"]
        card = spec["cardinality"]

        if mode == "SELECTION_ONLY":
            whitelist = spec["values"]
            vals = [v for v in vals if v in whitelist]
            if not vals:
                continue

        if card == "SINGLE":
            vals = vals[:1]

        seen = set()
        uniq = []
        for v in vals:
            if v not in seen:
                uniq.append(v)
                seen.add(v)

        if uniq:
            out[name] = uniq
    return out

def _cat_path(node: dict) -> str:
    anc = node.get("categoryTreeNodeAncestors") or []
    names = [a.get("categoryName") for a in anc if a.get("categoryName")]
    names.append(node.get("category", {}).get("categoryName"))
    return " > ".join([n for n in names if n])

def _summarize_suggestions(suggestions: list[dict], limit: int = 12) -> list[dict]:
    out = []
    for n in suggestions[:limit]:
        c = n.get("category") or {}
        out.append({
            "id": str(c.get("categoryId")),
            "name": c.get("categoryName"),
            "path": _cat_path(n),
            "leaf": bool(n.get("leafCategoryTreeNode") is True),
            "level": int(n.get("categoryTreeNodeLevel") or 0),
        })
    return out

from jsonschema import validate
def pick_category_with_llm(tree_id: str, query: str, normalized_title: str, raw_text: str,access):
    print("before access")
    # access = ensure_access_token()
    print("after access")
    r = requests.get(
        f"{API}/commerce/taxonomy/v1/category_tree/{tree_id}/get_category_suggestions",
        params={"q": query},
        headers={"Authorization": f"Bearer {access}"}
    )
    print("after request")
    r.raise_for_status()
    suggestions = (r.json() or {}).get("categorySuggestions") or []
    if not suggestions:
        raise RuntimeError("No category suggestions found")

    sugg = _summarize_suggestions(suggestions, limit=12)
    text = (raw_text or "")[:1500]

    system_prompt = (
        "You are an assistant that chooses the BEST eBay UK (EBAY_GB) leaf category "
        "for a product, given its title/description and eBay's own suggestions. "
        "Rules:\n"
        "1) Prefer a LEAF category. If multiple leaves fit, choose the most specific (deepest level).\n"
        "2) The pick MUST come from the provided suggestions (do not invent IDs).\n"
        "3) Match on domain cues in title/description (product type, audience, format), not just keywords.\n"
        "4) If the text is clearly educational/revision/GCSE etc., bias toward textbooks/education within Books.\n"
        "5) Return JSON only."
    )

    opts_lines = []
    for i, s in enumerate(sugg, 1):
        leaf_flag = "leaf" if s["leaf"] else "non-leaf"
        opts_lines.append(f"{i}. [{s['id']}] {s['path']}  ({leaf_flag}, level {s['level']})")
    options_block = "\n".join(opts_lines)

    user_prompt = f"""
    TITLE:
    {normalized_title}

    DESCRIPTION (truncated):
    {text}

    SUGGESTIONS (choose exactly one from these):
    {options_block}

    OUTPUT JSON:
    {{
      "choice": {{"categoryId":"<id from list>", "categoryName":"<name>"}},
      "ranking": [{{"categoryId":"<id>", "score":0.00, "why":"brief"}}],
      "notes": "optional"
    }}
    """

    result = call_llm_json(system_prompt, user_prompt)
    validate(instance=result, schema=CATEGORY_PICK_SCHEMA)

    by_id = {s["id"]: s for s in sugg}
    choice = result["choice"]
    cid = str(choice["categoryId"])
    picked = by_id.get(cid)

    if not picked:
        leaves = [s for s in sugg if s["leaf"]]
        leaves.sort(key=lambda s: s["level"], reverse=True)
        picked = leaves[0] if leaves else sugg[0]
        choice = {"categoryId": picked["id"], "categoryName": picked["name"]}

    if not picked["leaf"]:
        leaves = [s for s in sugg if s["leaf"]]
        if leaves:
            leaves.sort(key=lambda s: s["level"], reverse=True)
            picked = leaves[0]
            choice = {"categoryId": picked["id"], "categoryName": picked["name"]}

    return choice["categoryId"], choice["categoryName"], result.get("ranking"), result.get("notes")

def prepare_listing_components(*,images,raw_text_in,marketplace_id,pack_ctx,pack,access,use_llm_category=True,max_optional_aspects=2):
    print("Starting prepare_listing_components")
    print(f"Input - images: {images}, marketplace_id: {marketplace_id}, pack_ctx: {pack_ctx}, pack: {pack}")

    print("Extracting product from images")
    s0 = extract_product_from_images_gpt4o(images, marketplace_id, pack_ctx)
    print("Getting product from images")
    s0_text = s0.get("raw_text", "") or ""
    s0_json = json.dumps(s0, ensure_ascii=False)
    print(f"s0 result: {s0_json}")

    print("Preparing LLM call for keywords and title")
    system_prompt = (
        "You extract concise keywords for eBay category selection and search. "
        "Return STRICT JSON per the schema. Use ONLY facts present in the input. "
        "Do NOT invent identifiers; if absent, omit the field. "
        "Lowercase all keywords. No punctuation, no duplicates."
        "search_keywords must be less than 30 characters"
    )
    user_prompt = f"""MARKETPLACE: {marketplace_id}

RAW_TEXT:
{raw_text_in}

RAW_TEXT_FROM_IMAGES:
{s0_text}

VISION EXTRACTION (structured facts):
{s0_json}

PACK CONTEXT:
{pack_ctx}

TITLE RULES:
- If MULTIPACK: include "Pack of <quantity>" in normalized_title.
- If BUNDLE: include the word "Bundle" and name key components like "Textbook + Workbook".
- If SINGLE: do not add "Pack" or "Bundle".
- Keep ≤ 80 chars, no emojis or promo.

OUTPUT RULES:
- category_keywords: 3-5 short phrases (2-3 words) that best describe the product category.
- search_keywords: 3-12 search terms buyers would type (mix of unigrams/bigrams/trigrams), all lowercase.
- All search_keywords must be ≤ 30 characters.
- normalized_title: ≤80 chars, clean and factual (no emojis/promo).
- if it is a multipack or bundle include that in the title.
- brand: only if explicitly present in RAW_TEXT.
- identifiers: only if explicitly present (isbn/ean/gtin/mpn)."""
    print("Calling LLM for keywords and title")
    s1 = call_llm_json(system_prompt, user_prompt)
    print(f"s1 result: {s1}")

    s1["search_keywords"] = clean_keywords(s1.get("search_keywords", []))
    normalized_title = s1.get("normalized_title") or _fallback_title(raw_text_in)
    category_keywords = s1.get("category_keywords") or []
    print(f"Cleaned search keywords: {s1['search_keywords']}")
    print(f"Normalized title: {normalized_title}")
    print(f"Category keywords: {category_keywords}")

    print("Fetching category tree ID")
    tree_id = get_category_tree_id(access)
    print(f"Tree ID: {tree_id}")
    query = (" ".join(category_keywords)).strip() or normalized_title
    print(f"Category query: {query}")

    try:
        if use_llm_category:
            print("Using LLM for category selection")
            cat_id, cat_name, ranking, notes = pick_category_with_llm(
                tree_id=tree_id,
                query=query,
                normalized_title=normalized_title,
                raw_text=raw_text_in,
                access=access,
            )
            print(f"LLM category - ID: {cat_id}, Name: {cat_name}, Ranking: {ranking}, Notes: {notes}")
        else:
            raise RuntimeError("LLM category selection disabled")
    except Exception as e:
        print(f"LLM category selection failed: {str(e)}")
        try:
            print("Falling back to suggest_leaf_category")
            cat_id, cat_name = suggest_leaf_category(tree_id, query)
            print(f"Suggested category - ID: {cat_id}, Name: {cat_name}")
        except Exception as e:
            print(f"suggest_leaf_category failed: {str(e)}")
            cat_id, cat_name = browse_majority_category(query)
            print(f"Browse majority category - ID: {cat_id}, Name: {cat_name}")
            if not cat_id:
                print(f"No category found for query: {query}")
                raise RuntimeError(f"No category found from taxonomy or browse for query='{query}'")
            
    print("Fetching aspects info")
    aspects_info = get_required_and_recommended_aspects(tree_id, cat_id, access)
    print(f"Aspects info: {aspects_info}")

    print("Building aspect catalog")
    catalog = build_aspect_catalog(aspects_info)
    # print(f"Catalog: {catalog}")

    req_in = aspects_info.get("required", [])
    rec_in = aspects_info.get("recommended", [])
    req_names = [n for n in (_aspect_name(x) for x in req_in) if n]
    rec_names = [n for n in (_aspect_name(x) for x in rec_in) if n]
    all_names = set(catalog.keys())
    optional_names = sorted(all_names - set(req_names) - set(rec_names))
    shown_optional = optional_names[:max_optional_aspects]
    print(f"Required aspects: {req_names}")
    print(f"Recommended aspects: {rec_names}")
    # print(f"Optional aspects: {shown_optional}")

    print("Preparing LLM call for aspects")
    system_prompt2 = (
        "You fill eBay item aspects from provided text/images.\n"
        "Rules:\n"
        "• NEVER leave required aspects empty; if not available, use 'Does not apply' or 'Unknown' ONLY for required.\n"
        "• Fill optional aspects only when explicit or very likely. Respect cardinality exactly.\n"
        "• Multipack/bundle: multiply quantitative values by pack size (e.g., total weight/tablets). "
        "  For bundles, choose one most relevant/latest value per aspect.\n"
        "• LENGTH LIMITS: Obey aspectMaxLength. If unknown, keep EVERY free-text aspect ≤ 65 chars.\n"
        "• 'Ingredients': ≤ 65 chars, 3–4 key items, concise names.\n"
        "• If too long, shorten conservatively; if needed, truncate at a word boundary.\n"
        "• UK English; no emojis/marketing. For selection-only aspects, output one allowed option.\n"
        "• Include units only if the aspect expects them.\n"
    )
    user_prompt2 = f"""
INPUT TEXT:
{normalized_title}

RAW TEXT:
{raw_text_in}

RAW TEXT_FROM_IMAGES:
{s0_text}

VISION EXTRACTION (structured facts):
{s0_json}

PACK CONTEXT:
{pack_ctx}

ASPECTS:
- REQUIRED: {req_names}
- RECOMMENDED: {rec_names}
- OPTIONAL (you may fill when confident): {shown_optional}

OUTPUT RULES:
{{
  "filled": {{"AspectName": ["value1","value2"]}},
  "missing_required": ["AspectName"],
  "notes": "optional"
}}
"""
    print("Calling LLM for aspects")
    s2 = call_llm_json(system_prompt2, user_prompt2)
    print(f"s2 result: {s2}")

    s2 = coerce_aspects_fill(s2)
    limits = aspect_length_limits(aspects_info)
    filled = s2.get("filled") or {}
    print(f"Filled aspects before limits: {filled}")

    for aspect_name, values in list(filled.items()):
        max_len = limits.get(aspect_name)
        if max_len:
            filled[aspect_name] = [_shrink_for_limit(aspect_name, v, max_len) for v in (values or [])]
    print(f"Filled aspects after limits: {filled}")

    filled_all = sanitize_filled(filled, catalog)
    missing_required = [n for n in req_names if not filled_all.get(n)]
    print(f"Sanitized filled aspects: {filled_all}")
    print(f"Missing required aspects: {missing_required}")

    print("Building description")
    try:
        desc_bundle = build_description_simple_from_raw(
            raw_text_in, html_mode=True, pack_ctx=pack_ctx, pack=pack, s0=s0
        )
        description_html = desc_bundle["html"]
        print(f"Description HTML: {description_html}")
    except Exception as e:
        print(f"Description build failed: {str(e)}")
        description_html = f"<p>{(raw_text_in or '')[:2000]}</p>"
        print(f"Fallback description: {description_html}")

    print("Formatting final title")
    title = smart_titlecase(normalized_title)[:80]
    print(f"Final title: {title}")

    result = {
        "title": title,
        "description_html": description_html,
        "aspects": filled_all,
        "category_id": cat_id,
        "category_name": cat_name,
        "normalized_title": normalized_title,
        "missing_required": missing_required,
        "notes": s2.get("notes", "")
    }
    print(f"Returning result: {result}")
    return result

class SingleItemListingAPIView(APIView):
    def post(self, request):
        if request.data.get("action", "publish") != "publish":
            return Response({"error": "Only 'publish' action is supported"}, status=status.HTTP_400_BAD_REQUEST)
        
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

        access = ensure_access_token(request.user)
        raw_text_in = _clean_text(request.data.get("raw_text", ""), limit=8000)
        images = _https_only(request.data.get("images", []))
        print("images", images)
        marketplace_id = MARKETPLACE_ID
        price = request.data.get("price")
        quantity = int(request.data.get("quantity", 1))
        condition = request.data.get("condition", "NEW").upper()
        sku = request.data.get("sku") or _gen_sku("RAW")
        random_number = random.randint(100, 999)
        sku = f"{sku}-{random_number}"
        print("sku",sku)
        vat_rate = float(request.data.get("vat_rate", 0))
        remove_background = request.data.get("remove_bg", False)
        try:
            output_path = f"media/single_{uuid.uuid4().hex}.jpg"
            os.makedirs("media", exist_ok=True)
            create_single_image(image_url=images[0], output_path=output_path, do_remove_bg=remove_background)

            file_name = f"listings/{uuid.uuid4().hex}.jpg"
            processed_image_url = upload_to_s3(output_path)

            images[0] = processed_image_url
            if os.path.exists(output_path):
                print(f"Removing {output_path}")
                os.remove(output_path)
            else:
                print(f"File not found: {output_path}")
    
        except Exception as e:
            return Response({"error": f"Failed to process or upload image: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        print(processed_image_url)

        pack = {"type": "single"}
        pack_ctx = "SINGLE ITEM"
        
        prep = prepare_listing_components(
            images=images,
            raw_text_in=raw_text_in,
            marketplace_id=marketplace_id,
            pack_ctx=pack_ctx,
            pack=pack,
            access=access,
        )

        title = prep["title"]
        description_html = prep["description_html"]
        aspects = prep["aspects"]
        category_id = prep["category_id"]
        category_name = prep["category_name"]

        lang = "en-GB" if marketplace_id == "EBAY_GB" else "en-US"
        headers = {
            "Authorization": f"Bearer {access}",
            "Content-Type": "application/json",
            "Content-Language": lang,
            "Accept-Language": lang,
            "X-EBAY-C-MARKETPLACE-ID": marketplace_id,
        }

        check_url = f"{BASE}/sell/inventory/v1/inventory_item/{sku}"
        r = requests.get(check_url, headers=headers)
        if r.status_code == 200:
            return Response({"error": "SKU already exists"}, status=status.HTTP_400_BAD_REQUEST)

        inv_url = f"{BASE}/sell/inventory/v1/inventory_item/{sku}"
        inv_payload = {
            "product": {
                "title": title,
                "description": description_html,
                "aspects": aspects,
                "imageUrls": images
            },
            "condition": condition,
            "availability": {"shipToLocationAvailability": {"quantity": quantity}},
            "tax": {"vatPercentage": vat_rate} if vat_rate > 0 else {}
        }
        r = requests.put(inv_url, headers=headers, json=inv_payload)
        if r.status_code not in (200, 201, 204):
            return Response({"error": parse_ebay_error(r.text), "step": "inventory_item"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            fulfillment_policy_id = get_first_policy_id("fulfillment", access, marketplace_id)
            payment_policy_id = get_first_policy_id("payment", access, marketplace_id)
            return_policy_id = get_first_policy_id("return", access, marketplace_id)
        except RuntimeError as e:
            return Response({"error": f"Missing eBay policies: {str(e)}"}, status=status.HTTP_400_BAD_REQUEST)

        merchant_location_key = get_or_create_location(access, marketplace_id, profile)
        offer_payload = {
            "sku": sku,
            "marketplaceId": marketplace_id,
            "format": "FIXED_PRICE",
            "availableQuantity": quantity,
            "categoryId": category_id,
            "listingDescription": description_html,
            "pricingSummary": {
                "price": {
                    "value": str(price["value"]),
                    "currency": price["currency"]
                }
            },
            "listingPolicies": {
                "fulfillmentPolicyId": fulfillment_policy_id,
                "paymentPolicyId": payment_policy_id,
                "returnPolicyId": return_policy_id
            },
            "merchantLocationKey": merchant_location_key,
            "tax": {"vatPercentage": vat_rate} if vat_rate > 0 else {}
        }
        offer_url = f"{BASE}/sell/inventory/v1/offer"
        r = requests.post(offer_url, headers=headers, json=offer_payload)
        if r.status_code not in (200, 201):
            return Response({"error": parse_ebay_error(r.text), "step": "create_offer"}, status=status.HTTP_400_BAD_REQUEST)

        offer_id = r.json().get("offerId")
        pub_url = f"{BASE}/sell/inventory/v1/offer/{offer_id}/publish"
        r = requests.post(pub_url, headers=headers)
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
            category_name=category_name,
            marketplace_id=marketplace_id,
            view_url=view_url,
            listing_type="Single"
        )

        return Response({
            "status": "published",
            "offerId": offer_id,
            "listingId": listing_id,
            "viewItemUrl": view_url,
            "sku": sku,
            "marketplaceId": marketplace_id,
            "categoryId": category_id,
            "categoryName": category_name,
            "title": title,
            "aspects": aspects
        })

# --------------------------------------------------------------Multipack View--------------------------------------------------------------

def _gen_sku_multi(prefix="MULTI"):
    ts = str(int(time.time() * 1000))
    unique_id = str(uuid.uuid4())[:8].upper()
    return f"{prefix}-{ts[-6:]}-{unique_id}"

def download_rgba(url: str) -> Image.Image:
    r = requests.get(url)
    r.raise_for_status()
    return Image.open(io.BytesIO(r.content)).convert("RGBA")

def remove_bg_via_rembg(img: Image.Image) -> Image.Image:
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    headers = {"x-api-key": REMBG_API_KEY}
    files = {"image": ("image.png", buf, "image/png")}
    resp = requests.post(REMBG_API_URL, headers=headers, files=files)
    if resp.status_code != 200 or not resp.content:
        raise RuntimeError(f"rembg API error: {resp.status_code} {resp.text[:200]}")
    return Image.open(io.BytesIO(resp.content)).convert("RGBA")

def is_white_background(img: Image.Image,border_frac: float = 0.01,v_thresh: float = 0.92,chroma_thresh: float = 0.12,min_ratio: float = 0.85,std_thresh: float = 18.0):
    arr = np.asarray(img.convert("RGB"), dtype=np.float32) / 255.0
    h, w, _ = arr.shape
    b = max(1, int(min(h, w) * border_frac))

    mask = np.zeros((h, w), dtype=bool)
    mask[:b, :] = True
    mask[-b:, :] = True
    mask[:, :b] = True
    mask[:, -b:] = True

    border = arr[mask]
    mx = border.max(axis=1)
    mn = border.min(axis=1)
    bright = mx >= v_thresh
    low_chroma = (mx - mn) <= chroma_thresh
    whiteish = bright & low_chroma
    ratio = float(whiteish.mean())
    border_std = float(np.mean(border.std(axis=0) * 255.0))

    return (ratio >= min_ratio and border_std <= std_thresh)


def crop_to_subject_white_bg(img: Image.Image,v_thresh: float = 0.5,chroma_thresh: float = 0.12,margin: float = 0.04,min_fg_ratio: float = 0.02,use_edge_help: bool = True) -> Image.Image:
    arr = np.asarray(img.convert("RGB"), dtype=np.float32) / 255.0
    mx = arr.max(axis=2)
    mn = arr.min(axis=2)
    whiteish = (mx >= v_thresh) & ((mx - mn) <= chroma_thresh)
    fg = ~whiteish

    if use_edge_help:
        gray = (0.299 * arr[..., 0] + 0.587 * arr[..., 1] + 0.114 * arr[..., 2])
        gx = np.abs(np.diff(gray, axis=1, prepend=gray[:, :1]))
        gy = np.abs(np.diff(gray, axis=0, prepend=gray[:1, :]))
        edge = (gx + gy) * 255.0
        edge_mask = edge > 20
        fg = fg | edge_mask

    m = Image.fromarray(np.uint8(fg) * 255, mode="L")
    m = m.filter(ImageFilter.MinFilter(3))
    m = m.filter(ImageFilter.MaxFilter(5))

    bbox = m.getbbox()
    if not bbox:
        return img

    x0, y0, x1, y1 = bbox
    h, w = arr.shape[:2]
    area = (x1 - x0) * (y1 - y0)
    if area < min_fg_ratio * (w * h):
        return img

    dx = int((x1 - x0) * margin)
    dy = int((y1 - y0) * margin)
    x0 = max(0, x0 - dx)
    y0 = max(0, y0 - dy)
    x1 = min(w, x1 + dx)
    y1 = min(h, y1 + dy)

    return img.crop((x0, y0, x1, y1))
    
def safe_remove_bg(img: Image.Image) -> Image.Image:
    is_white = is_white_background(img)
    if is_white:
        cut = crop_to_subject_white_bg(img)
        try:
            white = Image.new("RGBA", cut.size, (255, 255, 255, 255))
            return Image.alpha_composite(white, cut)
        except Exception:
            return img
    else:
        cut = remove_bg_via_api(img)
        try:
            white = Image.new("RGBA", cut.size, (255, 255, 255, 255))
            return Image.alpha_composite(white, cut)
        except Exception:
            return img

def fit_within(img: Image.Image, box_w: int, box_h: int, margin_ratio: float = 0.94) -> Image.Image:
    target_w = int(box_w * margin_ratio)
    target_h = int(box_h * margin_ratio)
    w, h = img.size
    scale = min(target_w / w, target_h / h)
    return img.resize((max(1, int(w * scale)), max(1, int(h * scale))), Image.LANCZOS)

def grid_spec(pack_size: int):
    n = max(2, min(6, int(pack_size)))
    if n <= 3:
        rows, cols = 1, n
        cells = [(0, c) for c in range(n)]
    elif n == 4:
        rows, cols = 2, 2
        cells = [(0, 0), (0, 1), (1, 0), (1, 1)]
    elif n == 5:
        rows, cols = 2, 3
        cells = [(0, 0), (0, 1), (0, 2), (1, 0.5), (1, 1.5)]
    else:
        rows, cols = 2, 3
        cells = [(0, 0), (0, 1), (0, 2), (1, 0), (1, 1), (1, 2)]
    return rows, cols, cells

def compose_multipack(image_url: str, pack_size: int = 4, output_path: str = "multipack.jpg", output_size: int = 1600, padding: int = 28, do_remove_bg: bool = True, margin_ratio: float = 0.94):
    assert 2 <= pack_size <= 6, "pack_size must be between 2 and 6"
    unit = download_rgba(image_url)
    if do_remove_bg:
        unit = safe_remove_bg(unit)
    S = int(output_size)
    canvas = Image.new("RGBA", (S, S), (255, 255, 255, 255))
    rows, cols, cells = grid_spec(pack_size)
    cell_w = (S - (cols + 1) * padding) // cols
    cell_h = (S - (rows + 1) * padding) // rows
    cell_size = min(cell_w, cell_h)
    grid_w = cols * cell_size + (cols + 1) * padding
    grid_h = rows * cell_size + (rows + 1) * padding
    grid_left = (S - grid_w) // 2
    grid_top = (S - grid_h) // 2
    for idx, (r, c) in enumerate(cells, 1):
        x0 = grid_left + padding + float(c) * (cell_size + padding)
        y0 = grid_top + padding + int(r) * (cell_size + padding)
        tile = fit_within(unit, cell_size, cell_size, margin_ratio=margin_ratio)
        dx = int(round(x0 + (cell_size - tile.size[0]) / 2.0))
        dy = int(round(y0 + (cell_size - tile.size[1]) / 2.0))
        canvas.paste(tile, (dx, dy), tile if tile.mode == "RGBA" else None)
        if idx >= pack_size:
            break
    canvas.convert("RGB").save(output_path, quality=95, optimize=True, subsampling=2)
    return output_path

class MultipackListingAPIView(APIView):
    def post(self, request):
        if request.data.get("action", "publish") != "publish":
            return Response({"error": "Invalid action. Only 'publish' is supported"}, status=status.HTTP_400_BAD_REQUEST)

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

        access = ensure_access_token(request.user)
        raw_text_in = _clean_text(request.data.get("raw_text"), limit=8000)
        images = _https_only(request.data.get("images", []))
        marketplace_id = MARKETPLACE_ID
        price = request.data["price"]
        quantity = request.data["quantity"]
        condition = request.data.get("condition", "NEW").upper()
        vat_rate = float(request.data.get("vat_rate", 0))
        sku = request.data.get("sku") or _gen_sku_multi("MULTI")
        random_number = random.randint(100, 999)
        sku = f"{sku}-{random_number}"
        print("sku",sku)
        remove_background = request.data.get("remove_background", False)
        multipack_quantity = request.data.get("multipack_quantity", 2)

        pack_ctx = {'type': 'multipack', 'quantity': multipack_quantity, 'unit': ''}
        pack = f"MULTIPACK: Pack of {multipack_quantity}"

        if multipack_quantity < 1 or multipack_quantity > 6:
            return Response({"error": "Multipack quantity must be between 1 and 6"}, status=status.HTTP_400_BAD_REQUEST)

        if multipack_quantity > 1 and images:
            try:
                output_path = f"media/multipack_{uuid.uuid4().hex}.jpg"
                os.makedirs("media", exist_ok=True)
                compose_multipack(
                    image_url=images[0],
                    pack_size=multipack_quantity,
                    output_path=output_path,
                    do_remove_bg=remove_background
                )
                processed_image_url = upload_to_s3(output_path)
                images[0] = processed_image_url
                os.remove(output_path)
            except Exception as e:
                return Response({"error": f"Failed to process or upload multipack image: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        prep = prepare_listing_components(
            images=images,
            raw_text_in=raw_text_in,
            marketplace_id=marketplace_id,
            pack_ctx=pack_ctx,
            pack=pack,
            access=access,
        )

        title = prep["title"]
        description_html = prep["description_html"]
        aspects = prep["aspects"]
        category_id = prep["category_id"]
        category_name = prep["category_name"]

        try:
            lang = "en-GB" if marketplace_id == "EBAY_GB" else "en-US"
            headers = {
                "Authorization": f"Bearer {access}",
                "Content-Type": "application/json",
                "Content-Language": lang,
                "Accept-Language": lang,
                "X-EBAY-C-MARKETPLACE-ID": marketplace_id,
            }

            check_url = f"{BASE}/sell/inventory/v1/inventory_item/{sku}"
            r = requests.get(check_url, headers=headers)
            if r.status_code == 200:
                return Response({"error": "SKU already exists"}, status=status.HTTP_400_BAD_REQUEST)

            inv_url = f"{BASE}/sell/inventory/v1/inventory_item/{sku}"
            inv_payload = {
                "product": {
                    "title": title,
                    "description": description_html,
                    "aspects": aspects,
                    "imageUrls": images
                },
                "condition": condition,
                "availability": {"shipToLocationAvailability": {"quantity": quantity}},
                "tax": {"vatPercentage": vat_rate} if vat_rate > 0 else {}
            }
            r = requests.put(inv_url, headers=headers, json=inv_payload)
            if r.status_code not in (200, 201, 204):
                return Response({"error": parse_ebay_error(r.text), "step": "inventory_item"}, status=status.HTTP_400_BAD_REQUEST)

            try:
                fulfillment_policy_id = get_first_policy_id("fulfillment", access, marketplace_id)
                payment_policy_id = get_first_policy_id("payment", access, marketplace_id)
                return_policy_id = get_first_policy_id("return", access, marketplace_id)
            except RuntimeError as e:
                return Response({"error": f"Missing eBay policies: {str(e)}"}, status=status.HTTP_400_BAD_REQUEST)

            merchant_location_key = get_or_create_location(access, marketplace_id, profile)
            offer_payload = {
                "sku": sku,
                "marketplaceId": marketplace_id,
                "format": "FIXED_PRICE",
                "availableQuantity": quantity,
                "categoryId": category_id,
                "listingDescription": description_html,
                "pricingSummary": {
                    "price": {
                        "value": str(price["value"]),
                        "currency": price["currency"]
                    }
                },
                "listingPolicies": {
                    "fulfillmentPolicyId": fulfillment_policy_id,
                    "paymentPolicyId": payment_policy_id,
                    "returnPolicyId": return_policy_id
                },
                "merchantLocationKey": merchant_location_key,
                "tax": {"vatPercentage": vat_rate} if vat_rate > 0 else {}
            }
            offer_url = f"{BASE}/sell/inventory/v1/offer"
            r = requests.post(offer_url, headers=headers, json=offer_payload)
            if r.status_code not in (200, 201):
                return Response({"error": parse_ebay_error(r.text), "step": "create_offer"}, status=status.HTTP_400_BAD_REQUEST)

            offer_id = r.json().get("offerId")
            pub_url = f"{BASE}/sell/inventory/v1/offer/{offer_id}/publish"
            r = requests.post(pub_url, headers=headers)
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
                category_name=category_name,
                marketplace_id=marketplace_id,
                view_url=view_url,
                vat_rate=vat_rate,
                listing_type='Multi'
            )

            return Response({
                "status": "published",
                "offerId": offer_id,
                "listingId": listing_id,
                "viewItemUrl": view_url,
                "sku": sku,
                "marketplaceId": marketplace_id,
                "categoryId": category_id,
                "categoryName": category_name,
                "title": title,
                "aspects": aspects,
                "vat_rate": vat_rate,
            })
        except requests.exceptions.RequestException as e:
            return Response({"error": f"Network error with eBay: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        except RuntimeError as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({"error": f"Unexpected error: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

# --------------------------------------------------------------Bundle View--------------------------------------------------------------

def fetch_image_rgba(url: str) -> Image.Image:
    r = requests.get(url)
    r.raise_for_status()
    return Image.open(io.BytesIO(r.content)).convert("RGBA")


def remove_bg_api(img: Image.Image) -> Image.Image:
    if not REMBG_API_KEY:
        raise RuntimeError("REMBG_API_KEY is not set in the environment")
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    headers = {"x-api-key": REMBG_API_KEY}
    files = {"image": ("image.png", buf, "image/png")}
    resp = requests.post(REMBG_API_URL, headers=headers, files=files)
    if resp.status_code != 200 or not resp.content:
        raise RuntimeError(f"rembg API error: {resp.status_code} {resp.text[:200]}")
    return Image.open(io.BytesIO(resp.content)).convert("RGBA")


def remove_bg_safe(img: Image.Image) -> Image.Image:
    try:
        cut = remove_bg_api(img)
        white = Image.new("RGBA", cut.size, (255, 255, 255, 255))
        return Image.alpha_composite(white, cut)
    except Exception as e:
        print(f"[rembg] background removal failed, using original image: {e}")
        return img


def resize_to_fit(img: Image.Image, box_w: int, box_h: int, margin_ratio: float = 0.94) -> Image.Image:
    target_w = int(box_w * margin_ratio)
    target_h = int(box_h * margin_ratio)
    w, h = img.size
    scale = min(target_w / w, target_h / h)
    return img.resize((max(1, int(w * scale)), max(1, int(h * scale))), Image.LANCZOS)


def make_grid_layout(n: int) -> tuple[int, int, list[tuple[float, float]]]:
    n = max(2, min(6, int(n)))
    if n == 2:
        rows, cols = 1, 2
        cells = [(0, 0.0), (0, 1.0)]
    elif n == 3:
        rows, cols = 1, 3
        cells = [(0, 0.0), (0, 1.0), (0, 2.0)]
    elif n == 4:
        rows, cols = 2, 2
        cells = [(0, 0.0), (0, 1.0), (1, 0.0), (1, 1.0)]
    elif n == 5:
        rows, cols = 2, 3
        cells = [(0, 0.0), (0, 1.0), (0, 2.0), (1, 0.5), (1, 1.5)]
    else:  # 6
        rows, cols = 2, 3
        cells = [(0, 0.0), (0, 1.0), (0, 2.0), (1, 0.0), (1, 1.0), (1, 2.0)]
    return rows, cols, cells


def compose_bundle(
    image_urls: list[str],
    output_path: str = "bundle.jpg",
    output_size: int = 1600,
    padding: int = 0,
    do_remove_bg: bool = True,
    margin_ratio: float = 0.94,
):
    assert 2 <= len(image_urls) <= 6, "Provide 2 to 6 item URLs."
    items: list[Image.Image] = []
    for i, url in enumerate(image_urls, 1):
        print(f"[*] Downloading item {i}…")
        img = fetch_image_rgba(url)
        if do_remove_bg:
            img = remove_bg_safe(img)
        items.append(img)

    S = int(output_size)
    canvas = Image.new("RGBA", (S, S), (255, 255, 255, 255))

    rows, cols, cells = make_grid_layout(len(items))
    cell_w = (S - (cols + 1) * padding) // cols
    cell_h = (S - (rows + 1) * padding) // rows
    cell_size = min(cell_w, cell_h)

    grid_w = cols * cell_size + (cols + 1) * padding
    grid_h = rows * cell_size + (rows + 1) * padding
    grid_left = (S - grid_w) // 2
    grid_top = (S - grid_h) // 2

    for img, (r, c) in zip(items, cells):
        x0 = grid_left + padding + float(c) * (cell_size + padding)
        y0 = grid_top + padding + int(r) * (cell_size + padding)
        tile = resize_to_fit(img, cell_size, cell_size, margin_ratio=margin_ratio)
        dx = int(round(x0 + (cell_size - tile.size[0]) / 2.0))
        dy = int(round(y0 + (cell_size - tile.size[1]) / 2.0))
        canvas.paste(tile, (dx, dy), tile if tile.mode == "RGBA" else None)

    print(f"[*] Saving -> {output_path}")
    canvas.convert("RGB").save(output_path, quality=95, optimize=True, subsampling=2)
    
class BundleListingAPIView(APIView):
    def post(self, request):
        print("Starting BundleListingAPIView.post")
        try:
            print("Fetching user profile")
            profile = UserProfile.objects.get(user=request.user)
        except UserProfile.DoesNotExist:
            print("User profile not found")
            return Response({"error": "Please create your profile first"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            print("Fetching eBay token")
            token = eBayToken.objects.get(user=request.user)
            if not token.refresh_token:
                print("eBay token refresh_token missing")
                return Response({"error": "Please authenticate with eBay first"}, status=status.HTTP_400_BAD_REQUEST)
        except eBayToken.DoesNotExist:
            print("eBay token not found")
            return Response({"error": "Please authenticate with eBay first"}, status=status.HTTP_400_BAD_REQUEST)

        print("Ensuring access token")
        access = ensure_access_token(request.user)
        print(f"Access token: {access}")
        raw_text_in = _clean_text(request.data.get("raw_text"), limit=8000)
        print(f"Raw text: {raw_text_in}")
        images = _https_only(request.data.get("images", []))
        print(f"Images: {images}")
        marketplace_id = MARKETPLACE_ID
        print(f"Marketplace ID: {marketplace_id}")
        price = request.data.get("price")
        print(f"Price: {price}")
        quantity = int(request.data.get("quantity", 1))
        print(f"Quantity: {quantity}")
        condition = request.data.get("condition", "NEW").upper()
        print(f"Condition: {condition}")
        vat_rate = float(request.data.get("vat_rate", 0))
        print(f"VAT rate: {vat_rate}")
        sku = request.data.get("sku") or _gen_sku_multi("BUNDLE")
        print(f"SKU: {sku}")
        remove_background = request.data.get("remove_background", False)
        print(f"Remove background: {remove_background}")
        bundle_quantity = int(request.data.get("bundle_quantity", 2))
        print(f"Bundle quantity: {bundle_quantity}")

        pack_ctx = {'type': 'bundle', 'bundle_size': bundle_quantity, 'components': []}
        pack = f"BUNDLE: {bundle_quantity} items"
        print(f"Pack: {pack}")
        print(f"Pack context: {pack_ctx}")

        if bundle_quantity < 2 or bundle_quantity > 6:
            print(f"Invalid bundle quantity: {bundle_quantity}")
            return Response({"error": "Bundle quantity must be between 2 and 6"}, status=status.HTTP_400_BAD_REQUEST)

        if len(images) < bundle_quantity:
            print(f"Insufficient images: {len(images)} for bundle quantity {bundle_quantity}")
            return Response({"error": f"Bundle listings require at least {bundle_quantity} images"}, status=status.HTTP_400_BAD_REQUEST)

        if remove_background:
            try:
                print("Processing bundle image")
                output_path = f"media/bundle_{uuid.uuid4().hex}.jpg"
                print(f"Output path: {output_path}")
                os.makedirs("media", exist_ok=True)
                compose_bundle(
                    image_urls=images[:bundle_quantity],
                    output_path=output_path,
                    output_size=1600,
                    padding=0,
                    do_remove_bg=True,
                    margin_ratio=0.94
                )
                print("Uploading to imgbb")
                processed_image_url = upload_to_s3(output_path)
                print(f"Processed image URL: {processed_image_url}")
                images = [processed_image_url] + images[bundle_quantity:]
                print(f"Updated images: {images}")
                os.remove(output_path)
                print(f"Removed temporary file: {output_path}")
            except Exception as e:
                print(f"Image processing error: {str(e)}")
                return Response({"error": f"Failed to process or upload bundle image: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        print("Preparing listing components")
        prep = prepare_listing_components(
            images=images,
            raw_text_in=raw_text_in,
            marketplace_id=marketplace_id,
            pack_ctx=pack_ctx,
            pack=pack,
            access=access,
        )
        print(f"Prep result: {prep}")

        title = prep["title"]
        description_html = prep["description_html"]
        aspects = prep["aspects"]
        category_id = prep["category_id"]
        category_name = prep["category_name"]
        print(f"Title: {title}")
        print(f"Description HTML: {description_html}")
        print(f"Aspects: {aspects}")
        print(f"Category ID: {category_id}")
        print(f"Category Name: {category_name}")

        try:
            lang = "en-GB" if marketplace_id == "EBAY_GB" else "en-US"
            print(f"Language: {lang}")
            headers = {
                "Authorization": f"Bearer {access}",
                "Content-Type": "application/json",
                "Content-Language": lang,
                "Accept-Language": lang,
                "X-EBAY-C-MARKETPLACE-ID": marketplace_id,
            }
            print(f"Headers: {headers}")

            print(f"Checking SKU: {sku}")
            check_url = f"{BASE}/sell/inventory/v1/inventory_item/{sku}"
            r = requests.get(check_url, headers=headers)
            print(f"SKU check response: {r.status_code}")
            if r.status_code == 200:
                print(f"SKU already exists: {sku}")
                return Response({"error": "SKU already exists"}, status=status.HTTP_400_BAD_REQUEST)

            print("Creating inventory item")
            inv_url = f"{BASE}/sell/inventory/v1/inventory_item/{sku}"
            inv_payload = {
                "product": {
                    "title": title,
                    "description": description_html,
                    "aspects": aspects,
                    "imageUrls": images
                },
                "condition": condition,
                "availability": {"shipToLocationAvailability": {"quantity": quantity}},
                "tax": {"vatPercentage": vat_rate} if vat_rate > 0 else {}
            }
            print(f"Inventory payload: {inv_payload}")
            r = requests.put(inv_url, headers=headers, json=inv_payload)
            print(f"Inventory response: {r.status_code}")
            if r.status_code not in (200, 201, 204):
                print(f"Inventory error: {parse_ebay_error(r.text)}")
                return Response({"error": parse_ebay_error(r.text), "step": "inventory_item"}, status=status.HTTP_400_BAD_REQUEST)

            print("Fetching policy IDs")
            try:
                fulfillment_policy_id = get_first_policy_id("fulfillment", access, marketplace_id)
                payment_policy_id = get_first_policy_id("payment", access, marketplace_id)
                return_policy_id = get_first_policy_id("return", access, marketplace_id)
                print(f"Fulfillment policy ID: {fulfillment_policy_id}")
                print(f"Payment policy ID: {payment_policy_id}")
                print(f"Return policy ID: {return_policy_id}")
            except RuntimeError as e:
                print(f"Policy error: {str(e)}")
                return Response({"error": f"Missing eBay policies: {str(e)}"}, status=status.HTTP_400_BAD_REQUEST)

            print("Getting or creating merchant location")
            merchant_location_key = get_or_create_location(access, marketplace_id, profile)
            print(f"Merchant location key: {merchant_location_key}")
            offer_payload = {
                "sku": sku,
                "marketplaceId": marketplace_id,
                "format": "FIXED_PRICE",
                "availableQuantity": quantity,
                "categoryId": category_id,
                "listingDescription": description_html,
                "pricingSummary": {
                    "price": {
                        "value": str(price["value"]),
                        "currency": price["currency"]
                    }
                },
                "listingPolicies": {
                    "fulfillmentPolicyId": fulfillment_policy_id,
                    "paymentPolicyId": payment_policy_id,
                    "returnPolicyId": return_policy_id
                },
                "merchantLocationKey": merchant_location_key,
                "tax": {"vatPercentage": vat_rate} if vat_rate > 0 else {}
            }
            print(f"Offer payload: {offer_payload}")
            offer_url = f"{BASE}/sell/inventory/v1/offer"
            r = requests.post(offer_url, headers=headers, json=offer_payload)
            print(f"Offer response: {r.status_code}")
            if r.status_code not in (200, 201):
                print(f"Offer error: {parse_ebay_error(r.text)}")
                return Response({"error": parse_ebay_error(r.text), "step": "create_offer"}, status=status.HTTP_400_BAD_REQUEST)

            offer_id = r.json().get("offerId")
            print(f"Offer ID: {offer_id}")
            pub_url = f"{BASE}/sell/inventory/v1/offer/{offer_id}/publish"
            r = requests.post(pub_url, headers=headers)
            print(f"Publish response: {r.status_code}")
            if r.status_code not in (200, 201):
                print(f"Publish error: {parse_ebay_error(r.text)}")
                return Response({"error": parse_ebay_error(r.text), "step": "publish"}, status=status.HTTP_400_BAD_REQUEST)

            pub = r.json()
            print(f"Publish response JSON: {pub}")
            listing_id = pub.get("listingId") or (pub.get("listingIds") or [None])[0]
            print(f"Listing ID: {listing_id}")
            view_url = f"https://www.ebay.co.uk/itm/{listing_id}" if marketplace_id == "EBAY_GB" else None
            print(f"View URL: {view_url}")
            listing_count, _ = ListingCount.objects.get_or_create(id=1, defaults={"total_count": 0})
            listing_count.total_count += 1
            listing_count.save()
            print(f"Updated listing count: {listing_count.total_count}")

            print("Creating UserListing")
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
                category_name=category_name,
                marketplace_id=marketplace_id,
                view_url=view_url,
                vat_rate=vat_rate,
                listing_type='Bundle',
            )
            print("UserListing created")

            print("Preparing response")
            return Response({
                "status": "published",
                "offerId": offer_id,
                "listingId": listing_id,
                "viewItemUrl": view_url,
                "sku": sku,
                "marketplaceId": marketplace_id,
                "categoryId": category_id,
                "categoryName": category_name,
                "title": title,
                "aspects": aspects,
                "vat_rate": vat_rate,
                "bundle_quantity": bundle_quantity
            })
        except requests.exceptions.RequestException as e:
            print(f"Network error: {str(e)}")
            return Response({"error": f"Network error with eBay: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        except RuntimeError as e:
            print(f"Runtime error: {str(e)}")
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            print(f"Unexpected error: {str(e)}")
            return Response({"error": f"Unexpected error: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
