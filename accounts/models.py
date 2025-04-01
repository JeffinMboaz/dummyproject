from django.db import models
from django.utils import timezone
from django.contrib.auth.models import User
from django.contrib.auth.hashers import make_password, check_password
import os


# Vendor Model
class Vendor(models.Model):
    username = models.CharField(max_length=150, unique=True)
    password = models.CharField(max_length=255)  # Hashed password
    email = models.EmailField(unique=True)
    first_name = models.CharField(max_length=150)
    second_name = models.CharField(max_length=150)
    phone_no = models.CharField(max_length=15)
    date_created = models.DateTimeField(default=timezone.now)
    address = models.TextField()
    company = models.CharField(max_length=150)

    def set_password(self, raw_password):
        self.password = make_password(raw_password)

    def check_password(self, raw_password):
        return check_password(raw_password, self.password)

    def __str__(self):
        return self.username

    class Meta:
        verbose_name = "Registered Vendor"
        verbose_name_plural = "Registered Vendors"
        
# Create_Tour_Package for vendor
class Create_Tour_Package(models.Model):
    vendor = models.ForeignKey(Vendor, on_delete=models.CASCADE)
    package_title = models.CharField(max_length=200)
    destination = models.CharField(max_length=200)
    place_image = models.URLField()  # For image URL (copy image address)
    price = models.DecimalField(max_digits=10, decimal_places=2)
    description = models.TextField()
    duration = models.IntegerField(help_text="Duration in days")
    start_date = models.DateField()
    end_date = models.DateField()
    top_package = models.BooleanField(default=False)
    budget_friendly = models.BooleanField(default=False)
    created_date = models.DateTimeField(auto_now_add=True)
    auto_expire = models.BooleanField(default=True)
    booking_count= models.IntegerField(default=0)
    approved = models.BooleanField(default=False)  # Admin approval

    def __str__(self):
        return self.package_title

    class Meta:
        verbose_name = "Tour package"
        verbose_name_plural = "Tour packages"


class Manage_Bills(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    package = models.ForeignKey(Create_Tour_Package, on_delete=models.CASCADE, related_name="bookings")
    date_booked = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.user.username} - {self.package.package_title}"
