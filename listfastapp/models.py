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
    LISTING_TYPE_CHOICES = [
        ('Single', 'Single'),
        ('Multi', 'Multi'),
        ('Bundle', 'Bundle'),
    ]
    
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
    vat_rate = models.FloatField(default=0, blank=True, null=True)
    listing_type = models.CharField(max_length=20, choices=LISTING_TYPE_CHOICES, default='Single')

    class Meta:
        unique_together = ('user', 'listing_id')

    def __str__(self):
        return f"{self.title} ({self.listing_id})"


class TaskRecord(models.Model):
    STATUS_CHOICES = [
        ('PENDING', 'PENDING'),
        ('STARTED', 'STARTED'),
        ('SUCCESS', 'SUCCESS'),
        ('FAILURE', 'FAILURE'),
        ('RETRY', 'RETRY'),
        ('REVOKED', 'REVOKED'),
    ]

    user = models.ForeignKey(User, on_delete=models.CASCADE)
    task_id = models.CharField(max_length=100, unique=True)
    name = models.CharField(max_length=100)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='PENDING')
    payload = models.JSONField(blank=True, null=True)
    result = models.JSONField(blank=True, null=True)
    error = models.TextField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"Task {self.name} [{self.task_id}] - {self.status}"


# ---------------- Billing/Usage -----------------

class Plan(models.Model):
    code = models.CharField(max_length=30, unique=True)
    name = models.CharField(max_length=60)
    monthly_quota = models.IntegerField(default=0)
    stripe_price_id = models.CharField(max_length=100, blank=True, null=True)
    price_amount_gbp = models.DecimalField(max_digits=8, decimal_places=2, default=0)

    def __str__(self):
        return f"{self.name} ({self.code})"


class UserPlan(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, primary_key=True)
    plan = models.ForeignKey(Plan, on_delete=models.PROTECT)
    current_period_start = models.DateTimeField()
    current_period_end = models.DateTimeField()
    listings_used = models.IntegerField(default=0)
    stripe_subscription_id = models.CharField(max_length=100, blank=True, null=True)

    def __str__(self):
        return f"{self.user.email} -> {self.plan.code}"


class CreditPackage(models.Model):
    code = models.CharField(max_length=30, unique=True)
    name = models.CharField(max_length=100)
    credits = models.IntegerField()
    price_gbp = models.DecimalField(max_digits=8, decimal_places=2)
    is_active = models.BooleanField(default=True)
    stripe_product_id = models.CharField(max_length=100, blank=True, null=True)
    stripe_price_id = models.CharField(max_length=100, blank=True, null=True)

    def __str__(self):
        return f"{self.name} ({self.credits} credits for £{self.price_gbp})"


class CreditPurchase(models.Model):
    STATUS_CHOICES = [
        ("pending", "pending"),
        ("completed", "completed"),
        ("refunded", "refunded"),
        ("canceled", "canceled"),
    ]

    user = models.ForeignKey(User, on_delete=models.CASCADE)
    package = models.ForeignKey(CreditPackage, on_delete=models.PROTECT, null=True, blank=True)
    credits_total = models.IntegerField(default=0)
    credits_used = models.IntegerField(default=0)
    expires_at = models.DateTimeField()
    stripe_session_id = models.CharField(max_length=255, blank=True, null=True, unique=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default="pending")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return f"Credits {self.credits_total - self.credits_used}/{self.credits_total} for {self.user.email}"


class RefundRequest(models.Model):
    STATUS_CHOICES = [
        ("pending", "pending"),
        ("approved", "approved"),
        ("rejected", "rejected"),
        ("completed", "completed"),
    ]

    user = models.ForeignKey(User, on_delete=models.CASCADE)
    subscription_id = models.CharField(max_length=255)
    plan_name = models.CharField(max_length=100)
    amount = models.DecimalField(max_digits=10, decimal_places=2, default=0)
    reason = models.TextField(blank=True, null=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default="pending")
    created_at = models.DateTimeField(auto_now_add=True)
    processed_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return f"Refund Request - {self.user.email} ({self.status})"


class Order(models.Model):
    ORDER_TYPE_CHOICES = [
        ("subscription", "subscription"),
        ("credits", "credits"),
    ]
    
    STATUS_CHOICES = [
        ("pending", "pending"),
        ("completed", "completed"),
        ("refunded", "refunded"),
        ("failed", "failed"),
    ]

    user = models.ForeignKey(User, on_delete=models.CASCADE)
    order_type = models.CharField(max_length=20, choices=ORDER_TYPE_CHOICES)
    stripe_session_id = models.CharField(max_length=255, unique=True, null=True, blank=True)
    stripe_subscription_id = models.CharField(max_length=255, null=True, blank=True)
    stripe_invoice_id = models.CharField(max_length=255, null=True, blank=True)
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    currency = models.CharField(max_length=3, default="gbp")
    description = models.CharField(max_length=255)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default="pending")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return f"Order #{self.id} - {self.user.email} - {self.description}"


class NewsletterSubscriber(models.Model):
    email = models.EmailField(unique=True)
    subscribed_at = models.DateTimeField(auto_now_add=True)
    is_active = models.BooleanField(default=True)
    
    class Meta:
        ordering = ["-subscribed_at"]
    
    def __str__(self):
        return f"{self.email} - {'Active' if self.is_active else 'Unsubscribed'}"


class ContactFormSubmission(models.Model):
    name = models.CharField(max_length=200)
    email = models.EmailField()
    message = models.TextField()
    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return f"Contact from {self.name} ({self.email})"