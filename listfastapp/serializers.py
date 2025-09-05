from rest_framework.serializers import Serializer, CharField, EmailField, DecimalField, IntegerField, ChoiceField, ListField, URLField


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
