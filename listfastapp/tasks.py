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
from .helpers import *

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
            if status == 'FAILURE' and error is not None:
                from django.core.mail import EmailMultiAlternatives
                from os import getenv
                
                subject = "ListFast.ai - Single Item Listing Failed"
                body = f"""
                <html>
                    <body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                        <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 30px; text-align: center;">
                            <h1 style="color: white; margin: 0;">ListFast.ai</h1>
                        </div>
                        <div style="padding: 40px 30px; background: #f9f9f9;">
                            <h2 style="color: #333; margin-bottom: 20px;">Single Item Listing Failed</h2>
                            <p style="color: #666; font-size: 16px; line-height: 1.6;">
                                We're sorry, but your single item listing could not be completed due to the following error:
                            </p>
                            <div style="background: white; padding: 20px; border-radius: 10px; margin: 20px 0; border-left: 4px solid #e74c3c;">
                                <p style="color: #e74c3c; font-size: 14px; margin: 0;">
                                    {error}
                                </p>
                            </div>
                            <p style="color: #666; font-size: 16px; line-height: 1.6;">
                                Please try again or contact support if the issue persists.
                            </p>
                            <a href="mailto:support@listfast.ai" style="display: inline-block; background: #667eea; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; margin-top: 20px;">
                                Contact Support
                            </a>
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
                    subject=subject,
                    body=f"Your single item listing failed due to: {error}",
                    from_email=getenv("EMAIL_USER"),
                    to=[user.email]
                )
                msg.attach_alternative(body, "text/html")
                try:
                    msg.send()
                except Exception as e:
                    print(f"Failed to send notification email: {str(e)}")

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

    
    # try:
    #     processed_images, img_errors = helpers.process_all_images(images, remove_background)
    #     images[:] = processed_images  # mutate original list in place if you like
    #     if img_errors:
    #         app.logger.warning("Some images failed to process: %s", img_errors)
    # except Exception as e:
    #     finish('FAILURE', error=f"Failed to process or upload images: {e}")
    #     return {"error": f"Failed to process or upload images: {e}"}

    
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
    
    try:
        consume_listing_success(user)
    except Exception:
        pass
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

    # pack_ctx = {'type': 'multipack', 'quantity': multipack_quantity, 'unit': ''}
    # pack = f"MULTIPACK: Pack of {multipack_quantity}"

    # def make_pack_info(multipack_quantity):
    try:
        qty = int(multipack_quantity or 1)
    except (TypeError, ValueError):
        qty = 1

    if qty >= 2:
        pack_info = {"type": "multipack", "quantity": qty, "unit": ""}
        pack_note = f"Pack of {qty}"  # for UI only, don't pass as `pack`
    else:
        pack_info = {"type": "single"}
        pack_note = ""

    # return pack_info, pack_note

    # Usage
    # pack_info, pack_note = make_pack_info(multipack_quantity)
    pack_ctx = pack_info              # dict
    pack = dict(pack_info)            # also a dict, no strings here


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
    try:
        
        consume_listing_success(user)
    except Exception:
        pass
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

    # pack_ctx = {'type': 'bundle', 'bundle_size': bundle_quantity, 'components': []}
    # pack = f"BUNDLE: {bundle_quantity} items"

    # Normalize quantity
    try:
        qty = int(bundle_quantity) if bundle_quantity is not None else 0
    except (TypeError, ValueError):
        qty = 0
    if qty < 0:
        qty = 0
    
    # Normalize components (not used in bundle task, set to empty list)
    components_norm = []
    
    # Use dicts for both pack_ctx and pack (avoid the '.get' on a string crash)
    pack_ctx = {
        "type": "bundle",
        "bundle_size": qty,
        "quantity": qty,       # helpful standard key if other code expects it
        "components": components_norm,
    }
    pack = dict(pack_ctx)      # NOT a string
    



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
    try:
        
        consume_listing_success(user)
    except Exception:
        pass
    return result


@shared_task(bind=True, autoretry_for=(Exception,), retry_backoff=True, retry_kwargs={"max_retries": 3})
def send_verification_email_task(self, email: str, otp: str):
    """Send OTP verification email for signup"""
    from django.core.mail import EmailMultiAlternatives
    from os import getenv
    
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
        from_email=getenv("EMAIL_USER"),
        to=[email]
    )
    msg.attach_alternative(body, "text/html")
    msg.send()


@shared_task(bind=True, autoretry_for=(Exception,), retry_backoff=True, retry_kwargs={"max_retries": 3})
def send_welcome_email_task(self, email: str):
    """Send welcome email after successful registration"""
    from django.core.mail import EmailMultiAlternatives
    from os import getenv
    import logging
    
    youtube_video_link = "https://www.youtube.com/watch?v=nN_qZ81V4y8"
    EMAIL_USER = getenv("EMAIL_USER")
    
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


@shared_task(bind=True, autoretry_for=(Exception,), retry_backoff=True, retry_kwargs={"max_retries": 3})
def send_password_reset_email_task(self, email: str, otp: str):
    """Send password reset OTP email"""
    from django.core.mail import EmailMultiAlternatives
    from os import getenv
    
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
        from_email=getenv("EMAIL_USER"),
        to=[email]
    )
    msg.attach_alternative(body, "text/html")
    msg.send()


@shared_task(bind=True, autoretry_for=(Exception,), retry_backoff=True, retry_kwargs={"max_retries": 3})
def send_refund_request_emails_task(self, user_email: str, user_name: str, plan_name: str, plan_code: str, amount: float, reason: str):
    """Send refund request notification to team and confirmation to user"""
    from django.core.mail import EmailMultiAlternatives
    from os import getenv
    import logging
    
    EMAIL_USER = getenv("EMAIL_USER")
    team_email = getenv("TEAM_EMAIL", "rahul@listfast.ai")

    subject = f"🔔 Refund Request from {user_name} ({user_email})"
    body_text = f"""
    Refund Request Details:
    
    User: {user_name}
    Email: {user_email}
    Plan: {plan_name} ({plan_code})
    Amount: £{amount:.2f}
    Reason: {reason}
    
    Action Required: Please review and process this refund request in Stripe.
    """
    
    body_html = f"""
    <html>
        <body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
            <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 30px; text-align: center;">
                <h1 style="color: white; margin: 0;">ListFast.ai - Refund Request</h1>
            </div>
            <div style="padding: 40px 30px; background: #f9f9f9;">
                <h2 style="color: #333; margin-bottom: 20px;">New Refund Request</h2>
                <div style="background: white; padding: 20px; border-radius: 10px; margin: 20px 0;">
                    <p style="margin: 10px 0;"><strong>User:</strong> {user_name}</p>
                    <p style="margin: 10px 0;"><strong>Email:</strong> {user_email}</p>
                    <p style="margin: 10px 0;"><strong>Plan:</strong> {plan_name} ({plan_code})</p>
                    <p style="margin: 10px 0;"><strong>Amount:</strong> £{amount:.2f}</p>
                    <p style="margin: 10px 0;"><strong>Reason:</strong> {reason}</p>
                </div>
                <p style="color: #e74c3c; font-weight: bold;">
                    ⚠️ Action Required: Please review and process this refund request in Stripe.
                </p>
            </div>
        </body>
    </html>
    """
    
    msg = EmailMultiAlternatives(
        subject=subject,
        body=body_text,
        from_email=EMAIL_USER,
        to=[team_email]
    )
    msg.attach_alternative(body_html, "text/html")
    msg.send()
    
    logging.info(f"Refund request email sent to team for user {user_email} (Plan: {plan_code})")

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
                    We have received your refund request for your <strong>{plan_name}</strong> subscription.
                </p>
                <div style="background: white; padding: 20px; border-radius: 10px; margin: 20px 0;">
                    <p style="margin: 10px 0; color: #333;"><strong>Amount:</strong> £{amount:.2f}</p>
                    <p style="margin: 10px 0; color: #333;"><strong>Expected Processing Time:</strong> 2-3 business days</p>
                </div>
                <p style="color: #666; font-size: 16px; line-height: 1.6;">
                    Our team will review your request and process the refund accordingly. You'll receive a confirmation email once completed.
                </p>
                <p style="color: #666; font-size: 14px; margin-top: 30px;">
                    If you have any questions, contact us at <a href="mailto:rahul@listfast.ai" style="color: #667eea;">rahul@listfast.ai</a>
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
        body=f"Your refund request for {plan_name} has been received and will be processed within 2-3 business days.",
        from_email=EMAIL_USER,
        to=[user_email]
    )
    user_msg.attach_alternative(user_body_html, "text/html")
    user_msg.send()


@shared_task(bind=True, autoretry_for=(Exception,), retry_backoff=True, retry_kwargs={"max_retries": 3})
def send_payment_success_email_task(self, user_email: str, plan_name: str, amount_paid: float, monthly_quota: int):
    """Send payment success confirmation email"""
    from django.core.mail import EmailMultiAlternatives
    from os import getenv
    import logging
    
    EMAIL_USER = getenv("EMAIL_USER")
    SITE_BASE_URL = getenv("SITE_BASE_URL", "https://listfast.ai")
    
    subject = f"Payment Confirmed - {plan_name} - ListFast.ai"
    body_html = f"""
    <html>
        <body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
            <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 30px; text-align: center;">
                <h1 style="color: white; margin: 0;">ListFast.ai</h1>
            </div>
            <div style="padding: 40px 30px; background: #f9f9f9;">
                <h2 style="color: #333; margin-bottom: 20px;">✅ Payment Successful</h2>
                <p style="color: #666; font-size: 16px; line-height: 1.6;">
                    Your payment has been processed successfully!
                </p>
                <div style="background: white; padding: 30px; border-radius: 10px; margin: 30px 0; border-left: 4px solid #10b981;">
                    <p style="margin: 10px 0; color: #333; font-size: 18px;"><strong>Plan:</strong> {plan_name}</p>
                    <p style="margin: 10px 0; color: #333; font-size: 18px;"><strong>Amount Paid:</strong> £{amount_paid:.2f}</p>
                    <p style="margin: 10px 0; color: #10b981; font-size: 20px; font-weight: bold;">
                        📊 Monthly Quota: {monthly_quota} listings
                    </p>
                </div>
                <div style="background: #dbeafe; padding: 20px; border-radius: 10px; border-left: 4px solid #3b82f6; margin: 20px 0;">
                    <p style="margin: 0; color: #1e40af; font-size: 14px;">
                        🎉 You now have access to {monthly_quota} listings for this month!
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
        body=f"Your payment of £{amount_paid:.2f} for {plan_name} has been processed successfully.",
        from_email=EMAIL_USER,
        to=[user_email]
    )
    msg.attach_alternative(body_html, "text/html")
    msg.send()
    
    logging.info(f"Payment success email sent to {user_email}")


@shared_task(bind=True, autoretry_for=(Exception,), retry_backoff=True, retry_kwargs={"max_retries": 3})
def send_payment_failed_email_task(self, user_email: str):
    """Send payment failure notification email"""
    from django.core.mail import EmailMultiAlternatives
    from os import getenv
    import logging
    
    EMAIL_USER = getenv("EMAIL_USER")
    SITE_BASE_URL = getenv("SITE_BASE_URL", "https://listfast.ai")
    
    subject = "Payment Failed - ListFast.ai"
    body_html = f"""
    <html>
        <body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
            <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 30px; text-align: center;">
                <h1 style="color: white; margin: 0;">ListFast.ai</h1>
            </div>
            <div style="padding: 40px 30px; background: #f9f9f9;">
                <h2 style="color: #333; margin-bottom: 20px;">⚠️ Payment Failed</h2>
                <p style="color: #666; font-size: 16px; line-height: 1.6;">
                    We were unable to process your payment for your ListFast.ai subscription.
                </p>
                <div style="background: #fee; padding: 20px; border-radius: 10px; border-left: 4px solid #e74c3c; margin: 20px 0;">
                    <p style="margin: 0; color: #c0392b; font-size: 14px;">
                        Please update your payment method to continue using your subscription.
                    </p>
                </div>
                <div style="text-align: center; margin: 30px 0;">
                    <a href="{SITE_BASE_URL}/pricing/" style="display: inline-block; background: #667eea; color: white; padding: 15px 30px; text-decoration: none; border-radius: 8px; font-weight: bold;">
                        Update Payment Method
                    </a>
                </div>
                <p style="color: #666; font-size: 14px;">
                    Need help? Contact us at <a href="mailto:rahul@listfast.ai">rahul@listfast.ai</a>
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
        to=[user_email]
    )
    msg.attach_alternative(body_html, "text/html")
    msg.send()
    
    logging.info(f"Payment failed email sent to {user_email}")


@shared_task(bind=True, autoretry_for=(Exception,), retry_backoff=True, retry_kwargs={"max_retries": 3})
def send_subscription_canceled_email_task(self, user_email: str):
    """Send subscription cancellation confirmation email"""
    from django.core.mail import EmailMultiAlternatives
    from os import getenv
    import logging
    
    EMAIL_USER = getenv("EMAIL_USER")
    SITE_BASE_URL = getenv("SITE_BASE_URL", "https://listfast.ai")
    
    subject = "Subscription Canceled - ListFast.ai"
    body_html = f"""
    <html>
        <body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
            <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 30px; text-align: center;">
                <h1 style="color: white; margin: 0;">ListFast.ai</h1>
            </div>
            <div style="padding: 40px 30px; background: #f9f9f9;">
                <h2 style="color: #333; margin-bottom: 20px;">Subscription Canceled</h2>
                <p style="color: #666; font-size: 16px; line-height: 1.6;">
                    Your ListFast.ai subscription has been canceled. You've been moved to the Free plan.
                </p>
                <div style="background: #fff3cd; padding: 20px; border-radius: 10px; border-left: 4px solid #ffc107; margin: 20px 0;">
                    <p style="margin: 0; color: #856404; font-size: 14px;">
                        You can reactivate your subscription anytime from your account settings.
                    </p>
                </div>
                <div style="text-align: center; margin: 30px 0;">
                    <a href="{SITE_BASE_URL}/pricing/" style="display: inline-block; background: #667eea; color: white; padding: 15px 30px; text-decoration: none; border-radius: 8px; font-weight: bold;">
                        View Plans
                    </a>
                </div>
                <p style="color: #666; font-size: 14px;">
                    Questions? Contact us at <a href="mailto:rahul@listfast.ai">rahul@listfast.ai</a>
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
        to=[user_email]
    )
    msg.attach_alternative(body_html, "text/html")
    msg.send()
    
    logging.info(f"Subscription canceled email sent to {user_email}")


@shared_task(bind=True, autoretry_for=(Exception,), retry_backoff=True, retry_kwargs={"max_retries": 3})
def send_plan_change_email_task(self, user_email: str, old_plan_name: str, new_plan_name: str, is_upgrade: bool):
    """Send plan upgrade/downgrade confirmation email"""
    from django.core.mail import EmailMultiAlternatives
    from os import getenv
    import logging
    
    EMAIL_USER = getenv("EMAIL_USER")
    
    change_type = "upgraded" if is_upgrade else "changed"
    emoji = "🎉" if is_upgrade else "ℹ️"
    
    subject = f"Plan {change_type.title()} - ListFast.ai"
    body_html = f"""
    <html>
        <body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
            <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 30px; text-align: center;">
                <h1 style="color: white; margin: 0;">ListFast.ai</h1>
            </div>
            <div style="padding: 40px 30px; background: #f9f9f9;">
                <h2 style="color: #333; margin-bottom: 20px;">{emoji} Plan {change_type.title()}</h2>
                <p style="color: #666; font-size: 16px; line-height: 1.6;">
                    Your plan has been {change_type} from <strong>{old_plan_name}</strong> to <strong>{new_plan_name}</strong>.
                </p>
                <div style="background: white; padding: 20px; border-radius: 10px; margin: 20px 0;">
                    <p style="margin: 10px 0; color: #333;"><strong>Previous Plan:</strong> {old_plan_name}</p>
                    <p style="margin: 10px 0; color: #10b981; font-weight: bold;"><strong>New Plan:</strong> {new_plan_name}</p>
                </div>
                <p style="color: #666; font-size: 14px;">
                    Questions? Contact us at <a href="mailto:rahul@listfast.ai">rahul@listfast.ai</a>
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
        body=f"Your plan has been {change_type} from {old_plan_name} to {new_plan_name}.",
        from_email=EMAIL_USER,
        to=[user_email]
    )
    msg.attach_alternative(body_html, "text/html")
    msg.send()
    
    logging.info(f"Plan change email sent to {user_email}")


@shared_task(bind=True, autoretry_for=(Exception,), retry_backoff=True, retry_kwargs={"max_retries": 3})
def send_refund_processed_email_task(self, user_email: str, refund_amount: float):
    """Send refund processed confirmation email"""
    from django.core.mail import EmailMultiAlternatives
    from os import getenv
    import logging
    
    EMAIL_USER = getenv("EMAIL_USER")
    
    subject = "Refund Processed - ListFast.ai"
    body_html = f"""
    <html>
        <body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
            <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 30px; text-align: center;">
                <h1 style="color: white; margin: 0;">ListFast.ai</h1>
            </div>
            <div style="padding: 40px 30px; background: #f9f9f9;">
                <h2 style="color: #333; margin-bottom: 20px;">✅ Refund Processed</h2>
                <p style="color: #666; font-size: 16px; line-height: 1.6;">
                    Your refund has been processed successfully.
                </p>
                <div style="background: white; padding: 30px; border-radius: 10px; margin: 30px 0; border-left: 4px solid #10b981;">
                    <p style="margin: 0; color: #333; font-size: 20px; font-weight: bold;">
                        Refund Amount: £{refund_amount:.2f}
                    </p>
                </div>
                <div style="background: #dbeafe; padding: 20px; border-radius: 10px; border-left: 4px solid #3b82f6; margin: 20px 0;">
                    <p style="margin: 0; color: #1e40af; font-size: 14px;">
                        The refund will appear in your account within 5-10 business days.
                    </p>
                </div>
                <p style="color: #666; font-size: 14px;">
                    Questions? Contact us at <a href="mailto:rahul@listfast.ai">rahul@listfast.ai</a>
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
        to=[user_email]
    )
    msg.attach_alternative(body_html, "text/html")
    msg.send()
    
    logging.info(f"Refund processed email sent to {user_email}")


@shared_task(bind=True, autoretry_for=(Exception,), retry_backoff=True, retry_kwargs={"max_retries": 3})
def send_contact_form_emails_task(self, name: str, email: str, message: str):
    """Send contact form emails to team and user"""
    from django.core.mail import EmailMultiAlternatives
    from os import getenv
    import logging
    
    EMAIL_USER = getenv("EMAIL_USER")
    team_email = getenv("TEAM_EMAIL", "rahul@listfast.ai")
    SITE_BASE_URL = getenv("SITE_BASE_URL", "https://listfast.ai")
    
    team_subject = f"New Contact Form Submission from {name}"
    team_body_html = f"""
    <html>
        <body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
            <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 30px; text-align: center;">
                <h1 style="color: white; margin: 0;">ListFast.ai - New Contact</h1>
            </div>
            <div style="padding: 40px 30px; background: #f9f9f9;">
                <h2 style="color: #333; margin-bottom: 20px;">📧 New Contact Form Submission</h2>
                <div style="background: white; padding: 20px; border-radius: 10px; margin: 20px 0;">
                    <p style="margin: 10px 0;"><strong>Name:</strong> {name}</p>
                    <p style="margin: 10px 0;"><strong>Email:</strong> <a href="mailto:{email}">{email}</a></p>
                    <p style="margin: 10px 0;"><strong>Message:</strong></p>
                    <p style="margin: 10px 0; padding: 15px; background: #f9f9f9; border-radius: 5px;">{message}</p>
                </div>
                <div style="background: #dbeafe; padding: 20px; border-radius: 10px; border-left: 4px solid #3b82f6; margin: 20px 0;">
                    <p style="margin: 0; color: #1e40af; font-size: 14px;">
                        <strong>Expected Response Time:</strong> We typically respond within 24-48 hours during business days.
                    </p>
                </div>
            </div>
        </body>
    </html>
    """
    
    team_msg = EmailMultiAlternatives(
        subject=team_subject,
        body=f"New contact form submission from {name} ({email}): {message}",
        from_email=EMAIL_USER,
        to=[team_email],
        reply_to=[email]
    )
    team_msg.attach_alternative(team_body_html, "text/html")
    team_msg.send()
    
    user_subject = "We Received Your Message - ListFast.ai"
    user_body_html = f"""
    <html>
        <body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
            <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 30px; text-align: center;">
                <h1 style="color: white; margin: 0;">ListFast.ai</h1>
            </div>
            <div style="padding: 40px 30px; background: #f9f9f9;">
                <h2 style="color: #333; margin-bottom: 20px;">Thank You for Contacting Us!</h2>
                <p style="color: #666; font-size: 16px; line-height: 1.6;">
                    Hi <strong>{name}</strong>,
                </p>
                <p style="color: #666; font-size: 16px; line-height: 1.6;">
                    We've received your message and our team will get back to you as soon as possible.
                </p>
                <div style="background: white; padding: 20px; border-radius: 10px; margin: 20px 0; border-left: 4px solid #667eea;">
                    <p style="margin: 0 0 10px 0; color: #999; font-size: 12px;">Your Message:</p>
                    <p style="margin: 0; color: #333;">{message}</p>
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
    
    logging.info(f"Contact form emails sent for submission from {name} ({email})")


@shared_task(bind=True, autoretry_for=(Exception,), retry_backoff=True, retry_kwargs={"max_retries": 3})
def send_subscription_welcome_email_task(self, user_email: str, plan_name: str, monthly_quota: int):
    """Send welcome email for new subscription"""
    from django.core.mail import EmailMultiAlternatives
    from os import getenv
    import logging
    
    EMAIL_USER = getenv("EMAIL_USER")
    SITE_BASE_URL = getenv("SITE_BASE_URL", "https://listfast.ai")
    
    subject = f"Welcome to {plan_name} - ListFast.ai"
    body_html = f"""
    <html>
        <body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
            <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 30px; text-align: center;">
                <h1 style="color: white; margin: 0;">ListFast.ai</h1>
            </div>
            <div style="padding: 40px 30px; background: #f9f9f9;">
                <h2 style="color: #333; margin-bottom: 20px;">🎉 Welcome to {plan_name}!</h2>
                <p style="color: #666; font-size: 16px; line-height: 1.6;">
                    Thank you for subscribing to <strong>{plan_name}</strong>. Your subscription is now active!
                </p>
                <div style="background: white; padding: 30px; border-radius: 10px; margin: 30px 0; border-left: 4px solid #10b981;">
                    <p style="margin: 0; color: #333; font-size: 20px; font-weight: bold;">
                        📊 Monthly Quota: {monthly_quota} listings
                    </p>
                </div>
                <div style="background: #f0f7ff; padding: 25px; border-radius: 10px; border-left: 4px solid #667eea; margin: 25px 0;">
                    <p style="margin: 0 0 12px 0; color: #333; font-size: 16px;">
                        🚀 <strong>Start creating listings now!</strong>
                    </p>
                    <p style="margin: 0; color: #666; font-size: 14px;">
                        Log in to your dashboard and create professional eBay listings in under 60 seconds.
                    </p>
                </div>
                <div style="text-align: center; margin: 30px 0;">
                    <a href="{SITE_BASE_URL}/" style="display: inline-block; background: #667eea; color: white; padding: 15px 30px; text-decoration: none; border-radius: 8px; font-weight: bold;">
                        Go to Dashboard
                    </a>
                </div>
                <p style="color: #666; font-size: 14px;">
                    Questions? Contact us at <a href="mailto:rahul@listfast.ai">rahul@listfast.ai</a>
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
        body=f"Welcome to {plan_name}! Your subscription is now active with {monthly_quota} listings per month.",
        from_email=EMAIL_USER,
        to=[user_email]
    )
    msg.attach_alternative(body_html, "text/html")
    msg.send()
    
    logging.info(f"Subscription welcome email sent to {user_email}")