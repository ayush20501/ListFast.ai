from django.contrib import admin
from .models import UserProfile, eBayToken, OTP, ListingCount, UserListing


admin.site.register(UserProfile)
admin.site.register(eBayToken)
admin.site.register(OTP)
admin.site.register(ListingCount)
admin.site.register(UserListing)
