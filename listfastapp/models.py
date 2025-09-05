from django.db import models
from django.contrib.auth.models import User
from django.core.validators import MinLengthValidator, RegexValidator


class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, primary_key=True)
    address_line1 = models.CharField(max_length=200, validators=[MinLengthValidator(1)])
    city = models.CharField(max_length=100, validators=[MinLengthValidator(1)])
    postal_code = models.CharField(max_length=20, validators=[MinLengthValidator(1)])
    country = models.CharField(max_length=2, default='GB')
    profile_pic_url = models.URLField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"Profile of {self.user.username}"


class eBayToken(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, primary_key=True)
    access_token = models.TextField(blank=True, null=True)
    refresh_token = models.TextField(blank=True, null=True)
    expires_at = models.FloatField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"eBayToken for {self.user.username}"


class OTP(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    otp = models.CharField(max_length=6, validators=[RegexValidator(r'^\d{6}$')])
    expires_at = models.DateTimeField()
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"OTP {self.otp} for {self.user.username}"


class ListingCount(models.Model):
    total_count = models.IntegerField(default=0)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"Total Listings: {self.total_count}"


class UserListing(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    listing_id = models.CharField(max_length=50)
    offer_id = models.CharField(max_length=50, blank=True, null=True)
    sku = models.CharField(max_length=50, blank=True, null=True)
    title = models.CharField(max_length=80)
    price_value = models.DecimalField(max_digits=10, decimal_places=2, blank=True, null=True)
    price_currency = models.CharField(max_length=3, default='GBP')
    quantity = models.IntegerField(blank=True, null=True)
    condition = models.CharField(max_length=20, blank=True, null=True)
    category_id = models.CharField(max_length=50, blank=True, null=True)
    category_name = models.CharField(max_length=255, blank=True, null=True)
    marketplace_id = models.CharField(max_length=50, blank=True, null=True)
    view_url = models.URLField(blank=True, null=True)
    status = models.CharField(max_length=20, default='ACTIVE')
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ('user', 'listing_id')

    def __str__(self):
        return f"{self.title} ({self.listing_id})"
