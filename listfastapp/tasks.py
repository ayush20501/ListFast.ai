import os
import random
import uuid
from typing import Any, Dict

import requests
from celery import shared_task
from django.utils import timezone

from . import helpers
from .models import ListingCount, UserListing, UserProfile, eBayToken, TaskRecord
from decouple import config


@shared_task(bind=True, autoretry_for=(requests.exceptions.RequestException,), retry_backoff=True, retry_kwargs={"max_retries": 3})
def create_single_item_listing_task(self, user_id: int, payload: Dict[str, Any]) -> Dict[str, Any]:
    from django.contrib.auth import get_user_model

    User = get_user_model()
    user = User.objects.get(id=user_id)

    record = TaskRecord.objects.filter(task_id=self.request.id).first()
    if record:
        record.status = 'STARTED'
        record.save(update_fields=['status', 'updated_at'])

    def finish(status: str, result: Dict[str, Any] | None = None, error: str | None = None):
        if record:
            record.status = status
            if result is not None:
                record.result = result
            if error is not None:
                record.error = error
            record.save()

    try:
        UserProfile.objects.get(user=user)
    except UserProfile.DoesNotExist:
        finish('FAILURE', error="Please create your profile first")
        return {"error": "Please create your profile first"}

    try:
        token = eBayToken.objects.get(user=user)
        if not token.refresh_token:
            finish('FAILURE', error="Please authenticate with eBay first")
            return {"error": "Please authenticate with eBay first"}
    except eBayToken.DoesNotExist:
        finish('FAILURE', error="Please authenticate with eBay first")
        return {"error": "Please authenticate with eBay first"}

    access = helpers.ensure_access_token(user)

    raw_text_in = helpers._clean_text(payload.get("raw_text", ""), limit=8000)
    images = helpers._https_only(payload.get("images", []))
    marketplace_id = config("EBAY_MARKETPLACE_ID", default=os.getenv("EBAY_MARKETPLACE_ID"))
    base = config("EBAY_BASE", default=os.getenv("EBAY_BASE"))

    price = payload.get("price")
    quantity = int(payload.get("quantity", 1))
    condition = payload.get("condition", "NEW").upper()
    sku = payload.get("sku") or helpers._gen_sku("RAW")
    random_number = random.randint(100, 999)
    sku = f"{sku}-{random_number}"
    vat_rate = float(payload.get("vat_rate", 0))
    remove_background = payload.get("remove_bg", False)

    try:
        output_path = f"media/single_{uuid.uuid4().hex}.jpg"
        os.makedirs("media", exist_ok=True)
        helpers.create_single_image(image_url=images[0], output_path=output_path, do_remove_bg=remove_background)
        processed_image_url = helpers.upload_to_s3(output_path)
        images[0] = processed_image_url
        if os.path.exists(output_path):
            os.remove(output_path)
    except Exception as e:
        finish('FAILURE', error=f"Failed to process or upload image: {str(e)}")
        return {"error": f"Failed to process or upload image: {str(e)}"}

    pack = {"type": "single"}
    pack_ctx = "SINGLE ITEM"

    prep = helpers.prepare_listing_components(
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

    check_url = f"{base}/sell/inventory/v1/inventory_item/{sku}"
    r = requests.get(check_url, headers=headers)
    if r.status_code == 200:
        finish('FAILURE', error="SKU already exists")
        return {"error": "SKU already exists"}

    inv_url = f"{base}/sell/inventory/v1/inventory_item/{sku}"
    inv_payload = {
        "product": {
            "title": title,
            "description": description_html,
            "aspects": aspects,
            "imageUrls": images,
        },
        "condition": condition,
        "availability": {"shipToLocationAvailability": {"quantity": quantity}},
        "tax": {"vatPercentage": vat_rate} if vat_rate > 0 else {},
    }
    r = requests.put(inv_url, headers=headers, json=inv_payload)
    if r.status_code not in (200, 201, 204):
        err = helpers.parse_ebay_error(r.text)
        finish('FAILURE', error=err)
        return {"error": err, "step": "inventory_item"}

    try:
        fulfillment_policy_id = helpers.get_first_policy_id("fulfillment", access, marketplace_id)
        payment_policy_id = helpers.get_first_policy_id("payment", access, marketplace_id)
        return_policy_id = helpers.get_first_policy_id("return", access, marketplace_id)
    except RuntimeError as e:
        finish('FAILURE', error=f"Missing eBay policies: {str(e)}")
        return {"error": f"Missing eBay policies: {str(e)}"}

    merchant_location_key = helpers.get_or_create_location(access, marketplace_id, UserProfile.objects.get(user=user))
    offer_payload = {
        "sku": sku,
        "marketplaceId": marketplace_id,
        "format": "FIXED_PRICE",
        "availableQuantity": quantity,
        "categoryId": category_id,
        "listingDescription": description_html,
        "pricingSummary": {
            "price": {"value": str(price["value"]), "currency": price["currency"]}
        },
        "listingPolicies": {
            "fulfillmentPolicyId": fulfillment_policy_id,
            "paymentPolicyId": payment_policy_id,
            "returnPolicyId": return_policy_id,
        },
        "merchantLocationKey": merchant_location_key,
        "tax": {"vatPercentage": vat_rate} if vat_rate > 0 else {},
    }
    offer_url = f"{base}/sell/inventory/v1/offer"
    r = requests.post(offer_url, headers=headers, json=offer_payload)
    if r.status_code not in (200, 201):
        err = helpers.parse_ebay_error(r.text)
        finish('FAILURE', error=err)
        return {"error": err, "step": "create_offer"}

    offer_id = r.json().get("offerId")
    pub_url = f"{base}/sell/inventory/v1/offer/{offer_id}/publish"
    r = requests.post(pub_url, headers=headers)
    if r.status_code not in (200, 201):
        err = helpers.parse_ebay_error(r.text)
        finish('FAILURE', error=err)
        return {"error": err, "step": "publish"}

    pub = r.json()
    listing_id = pub.get("listingId") or (pub.get("listingIds") or [None])[0]
    view_url = f"https://www.ebay.co.uk/itm/{listing_id}" if marketplace_id == "EBAY_GB" else None

    listing_count, _ = ListingCount.objects.get_or_create(id=1, defaults={"total_count": 0})
    listing_count.total_count += 1
    listing_count.save()

    UserListing.objects.create(
        user=user,
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
        listing_type="Single",
    )

    result = {
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
    }
    finish('SUCCESS', result=result)
    return result




@shared_task(bind=True, autoretry_for=(requests.exceptions.RequestException,), retry_backoff=True, retry_kwargs={"max_retries": 3})
def create_multipack_listing_task(self, user_id: int, payload: Dict[str, Any]) -> Dict[str, Any]:
    from django.contrib.auth import get_user_model

    User = get_user_model()
    user = User.objects.get(id=user_id)

    record = TaskRecord.objects.filter(task_id=self.request.id).first()
    if record:
        record.status = 'STARTED'
        record.save(update_fields=['status', 'updated_at'])

    def finish(status: str, result: Dict[str, Any] | None = None, error: str | None = None):
        if record:
            record.status = status
            if result is not None:
                record.result = result
            if error is not None:
                record.error = error
            record.save()

    try:
        profile = UserProfile.objects.get(user=user)
    except UserProfile.DoesNotExist:
        finish('FAILURE', error="Please create your profile first")
        return {"error": "Please create your profile first"}

    try:
        token = eBayToken.objects.get(user=user)
        if not token.refresh_token:
            finish('FAILURE', error="Please authenticate with eBay first")
            return {"error": "Please authenticate with eBay first"}
    except eBayToken.DoesNotExist:
        finish('FAILURE', error="Please authenticate with eBay first")
        return {"error": "Please authenticate with eBay first"}

    access = helpers.ensure_access_token(user)

    raw_text_in = helpers._clean_text(payload.get("raw_text", ""), limit=8000)
    images = helpers._https_only(payload.get("images", []))
    marketplace_id = config("EBAY_MARKETPLACE_ID", default=os.getenv("EBAY_MARKETPLACE_ID"))
    base = config("EBAY_BASE", default=os.getenv("EBAY_BASE"))

    price = payload.get("price")
    quantity = int(payload.get("quantity", 1))
    condition = payload.get("condition", "NEW").upper()
    sku = payload.get("sku") or helpers._gen_sku_multi("MULTI")
    random_number = random.randint(100, 999)
    sku = f"{sku}-{random_number}"
    vat_rate = float(payload.get("vat_rate", 0))
    remove_background = bool(payload.get("remove_bg", payload.get("remove_background", False)))
    multipack_quantity = int(payload.get("multipack_quantity", 2))

    if multipack_quantity < 1 or multipack_quantity > 6:
        finish('FAILURE', error="Multipack quantity must be between 1 and 6")
        return {"error": "Multipack quantity must be between 1 and 6"}

    if multipack_quantity > 1 and images:
        try:
            output_path = f"media/multipack_{uuid.uuid4().hex}.jpg"
            os.makedirs("media", exist_ok=True)
            helpers.compose_multipack(
                image_url=images[0],
                pack_size=multipack_quantity,
                output_path=output_path,
                do_remove_bg=remove_background,
            )
            processed_image_url = helpers.upload_to_s3(output_path)
            images[0] = processed_image_url
        finally:
            try:
                if output_path and os.path.exists(output_path):
                    os.remove(output_path)
            except Exception:
                pass

    pack_ctx = {'type': 'multipack', 'quantity': multipack_quantity, 'unit': ''}
    pack = f"MULTIPACK: Pack of {multipack_quantity}"

    prep = helpers.prepare_listing_components(
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

    check_url = f"{base}/sell/inventory/v1/inventory_item/{sku}"
    r = requests.get(check_url, headers=headers)
    if r.status_code == 200:
        finish('FAILURE', error="SKU already exists")
        return {"error": "SKU already exists"}

    inv_url = f"{base}/sell/inventory/v1/inventory_item/{sku}"
    inv_payload = {
        "product": {
            "title": title,
            "description": description_html,
            "aspects": aspects,
            "imageUrls": images,
        },
        "condition": condition,
        "availability": {"shipToLocationAvailability": {"quantity": quantity}},
        "tax": {"vatPercentage": vat_rate} if vat_rate > 0 else {},
    }
    r = requests.put(inv_url, headers=headers, json=inv_payload)
    if r.status_code not in (200, 201, 204):
        err = helpers.parse_ebay_error(r.text)
        finish('FAILURE', error=err)
        return {"error": err, "step": "inventory_item"}

    try:
        fulfillment_policy_id = helpers.get_first_policy_id("fulfillment", access, marketplace_id)
        payment_policy_id = helpers.get_first_policy_id("payment", access, marketplace_id)
        return_policy_id = helpers.get_first_policy_id("return", access, marketplace_id)
    except RuntimeError as e:
        finish('FAILURE', error=f"Missing eBay policies: {str(e)}")
        return {"error": f"Missing eBay policies: {str(e)}"}

    merchant_location_key = helpers.get_or_create_location(access, marketplace_id, profile)
    offer_payload = {
        "sku": sku,
        "marketplaceId": marketplace_id,
        "format": "FIXED_PRICE",
        "availableQuantity": quantity,
        "categoryId": category_id,
        "listingDescription": description_html,
        "pricingSummary": {
            "price": {"value": str(price["value"]), "currency": price["currency"]}
        },
        "listingPolicies": {
            "fulfillmentPolicyId": fulfillment_policy_id,
            "paymentPolicyId": payment_policy_id,
            "returnPolicyId": return_policy_id,
        },
        "merchantLocationKey": merchant_location_key,
        "tax": {"vatPercentage": vat_rate} if vat_rate > 0 else {},
    }
    offer_url = f"{base}/sell/inventory/v1/offer"
    r = requests.post(offer_url, headers=headers, json=offer_payload)
    if r.status_code not in (200, 201):
        err = helpers.parse_ebay_error(r.text)
        finish('FAILURE', error=err)
        return {"error": err, "step": "create_offer"}

    offer_id = r.json().get("offerId")
    pub_url = f"{base}/sell/inventory/v1/offer/{offer_id}/publish"
    r = requests.post(pub_url, headers=headers)
    if r.status_code not in (200, 201):
        err = helpers.parse_ebay_error(r.text)
        finish('FAILURE', error=err)
        return {"error": err, "step": "publish"}

    pub = r.json()
    listing_id = pub.get("listingId") or (pub.get("listingIds") or [None])[0]
    view_url = f"https://www.ebay.co.uk/itm/{listing_id}" if marketplace_id == "EBAY_GB" else None

    listing_count, _ = ListingCount.objects.get_or_create(id=1, defaults={"total_count": 0})
    listing_count.total_count += 1
    listing_count.save()

    UserListing.objects.create(
        user=user,
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
        listing_type='Multi',
    )

    result = {
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
        "multipack_quantity": multipack_quantity,
    }
    finish('SUCCESS', result=result)
    return result


@shared_task(bind=True, autoretry_for=(requests.exceptions.RequestException,), retry_backoff=True, retry_kwargs={"max_retries": 3})
def create_bundle_listing_task(self, user_id: int, payload: Dict[str, Any]) -> Dict[str, Any]:
    from django.contrib.auth import get_user_model

    User = get_user_model()
    user = User.objects.get(id=user_id)

    record = TaskRecord.objects.filter(task_id=self.request.id).first()
    if record:
        record.status = 'STARTED'
        record.save(update_fields=['status', 'updated_at'])

    def finish(status: str, result: Dict[str, Any] | None = None, error: str | None = None):
        if record:
            record.status = status
            if result is not None:
                record.result = result
            if error is not None:
                record.error = error
            record.save()

    try:
        profile = UserProfile.objects.get(user=user)
    except UserProfile.DoesNotExist:
        finish('FAILURE', error="Please create your profile first")
        return {"error": "Please create your profile first"}

    try:
        token = eBayToken.objects.get(user=user)
        if not token.refresh_token:
            finish('FAILURE', error="Please authenticate with eBay first")
            return {"error": "Please authenticate with eBay first"}
    except eBayToken.DoesNotExist:
        finish('FAILURE', error="Please authenticate with eBay first")
        return {"error": "Please authenticate with eBay first"}

    access = helpers.ensure_access_token(user)

    raw_text_in = helpers._clean_text(payload.get("raw_text", ""), limit=8000)
    images = helpers._https_only(payload.get("images", []))
    marketplace_id = config("EBAY_MARKETPLACE_ID", default=os.getenv("EBAY_MARKETPLACE_ID"))
    base = config("EBAY_BASE", default=os.getenv("EBAY_BASE"))

    price = payload.get("price")
    quantity = int(payload.get("quantity", 1))
    condition = payload.get("condition", "NEW").upper()
    sku = payload.get("sku") or helpers._gen_sku_multi("BUNDLE")
    random_number = random.randint(100, 999)
    sku = f"{sku}-{random_number}"
    vat_rate = float(payload.get("vat_rate", 0))
    remove_background = bool(payload.get("remove_bg", payload.get("remove_background", False)))
    bundle_quantity = int(payload.get("bundle_quantity", 2))

    if bundle_quantity < 2 or bundle_quantity > 6:
        finish('FAILURE', error="Bundle quantity must be between 2 and 6")
        return {"error": "Bundle quantity must be between 2 and 6"}

    if len(images) < bundle_quantity:
        finish('FAILURE', error=f"Bundle listings require at least {bundle_quantity} images")
        return {"error": f"Bundle listings require at least {bundle_quantity} images"}

    if remove_background:
        try:
            output_path = f"media/bundle_{uuid.uuid4().hex}.jpg"
            os.makedirs("media", exist_ok=True)
            helpers.compose_bundle(
                image_urls=images[:bundle_quantity],
                output_path=output_path,
                output_size=1600,
                padding=0,
                do_remove_bg=True,
                margin_ratio=0.94,
            )
            processed_image_url = helpers.upload_to_s3(output_path)
            images = [processed_image_url] + images[bundle_quantity:]
        finally:
            try:
                if output_path and os.path.exists(output_path):
                    os.remove(output_path)
            except Exception:
                pass

    pack_ctx = {'type': 'bundle', 'bundle_size': bundle_quantity, 'components': []}
    pack = f"BUNDLE: {bundle_quantity} items"

    prep = helpers.prepare_listing_components(
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

    check_url = f"{base}/sell/inventory/v1/inventory_item/{sku}"
    r = requests.get(check_url, headers=headers)
    if r.status_code == 200:
        finish('FAILURE', error="SKU already exists")
        return {"error": "SKU already exists"}

    inv_url = f"{base}/sell/inventory/v1/inventory_item/{sku}"
    inv_payload = {
        "product": {
            "title": title,
            "description": description_html,
            "aspects": aspects,
            "imageUrls": images,
        },
        "condition": condition,
        "availability": {"shipToLocationAvailability": {"quantity": quantity}},
        "tax": {"vatPercentage": vat_rate} if vat_rate > 0 else {},
    }
    r = requests.put(inv_url, headers=headers, json=inv_payload)
    if r.status_code not in (200, 201, 204):
        err = helpers.parse_ebay_error(r.text)
        finish('FAILURE', error=err)
        return {"error": err, "step": "inventory_item"}

    try:
        fulfillment_policy_id = helpers.get_first_policy_id("fulfillment", access, marketplace_id)
        payment_policy_id = helpers.get_first_policy_id("payment", access, marketplace_id)
        return_policy_id = helpers.get_first_policy_id("return", access, marketplace_id)
    except RuntimeError as e:
        finish('FAILURE', error=f"Missing eBay policies: {str(e)}")
        return {"error": f"Missing eBay policies: {str(e)}"}

    merchant_location_key = helpers.get_or_create_location(access, marketplace_id, profile)
    offer_payload = {
        "sku": sku,
        "marketplaceId": marketplace_id,
        "format": "FIXED_PRICE",
        "availableQuantity": quantity,
        "categoryId": category_id,
        "listingDescription": description_html,
        "pricingSummary": {
            "price": {"value": str(price["value"]), "currency": price["currency"]}
        },
        "listingPolicies": {
            "fulfillmentPolicyId": fulfillment_policy_id,
            "paymentPolicyId": payment_policy_id,
            "returnPolicyId": return_policy_id,
        },
        "merchantLocationKey": merchant_location_key,
        "tax": {"vatPercentage": vat_rate} if vat_rate > 0 else {},
    }
    offer_url = f"{base}/sell/inventory/v1/offer"
    r = requests.post(offer_url, headers=headers, json=offer_payload)
    if r.status_code not in (200, 201):
        err = helpers.parse_ebay_error(r.text)
        finish('FAILURE', error=err)
        return {"error": err, "step": "create_offer"}

    offer_id = r.json().get("offerId")
    pub_url = f"{base}/sell/inventory/v1/offer/{offer_id}/publish"
    r = requests.post(pub_url, headers=headers)
    if r.status_code not in (200, 201):
        err = helpers.parse_ebay_error(r.text)
        finish('FAILURE', error=err)
        return {"error": err, "step": "publish"}

    pub = r.json()
    listing_id = pub.get("listingId") or (pub.get("listingIds") or [None])[0]
    view_url = f"https://www.ebay.co.uk/itm/{listing_id}" if marketplace_id == "EBAY_GB" else None

    listing_count, _ = ListingCount.objects.get_or_create(id=1, defaults={"total_count": 0})
    listing_count.total_count += 1
    listing_count.save()

    UserListing.objects.create(
        user=user,
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

    result = {
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
        "bundle_quantity": bundle_quantity,
    }
    finish('SUCCESS', result=result)
    return result