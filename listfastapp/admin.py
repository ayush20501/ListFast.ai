from django.contrib import admin
from .models import *


admin.site.register(UserProfile)
admin.site.register(eBayToken)
admin.site.register(OTP)
admin.site.register(ListingCount)
admin.site.register(UserListing)
admin.site.register(TaskRecord)
admin.site.register(Plan)
admin.site.register(UserPlan)
admin.site.register(CreditPurchase)
admin.site.register(CreditPackage)
admin.site.register(Order)
admin.site.register(RefundRequest)
admin.site.register(NewsletterSubscriber)