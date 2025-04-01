from django.contrib import admin

# Register your models here.

from django.contrib import admin,messages
from .models import Vendor,Create_Tour_Package


class VendorAdmin(admin.ModelAdmin):
    list_display = ('username', 'email', 'first_name', 'second_name', 'phone_no', 'company', 'date_created')
    search_fields = ('username', 'email', 'first_name', 'second_name', 'company')
    list_filter = ('company', 'date_created')

    # Optional - make password read-only in the admin
    readonly_fields = ('password',)

admin.site.register(Vendor, VendorAdmin)

class TourPackageAdmin(admin.ModelAdmin):
    list_display = ['package_title', 'vendor', 'destination', 'price', 'approved', 'start_date', 'end_date']
    list_filter = ['approved', 'start_date']
    search_fields = ['package_title', 'destination']
    list_editable = ['approved']  # Admin can approve


    def save_model(self, request, obj, form, change):
        super().save_model(request, obj, form, change)
        if obj.approved:
            self.message_user(request, f"Package '{obj.package_title}' approved and now visible to users.", messages.SUCCESS)





admin.site.register(Create_Tour_Package, TourPackageAdmin)