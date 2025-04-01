from django.urls import path
from . import views

urlpatterns = [
    path('', views.home, name='home'),
    path('user_reg/', views.user_reg, name='user_reg'),
    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),
    path('travel_plan/', views.travel_plan, name='travel_plan'),
    #
    # path('booked_packages/', views.booked_packages, name='booked_packages'),

    path('vendor_reg/', views.vendor_register, name='vendor_reg'),
    path('vendor_login/', views.vendor_login, name='vendor_login'),
    path('add_package/', views.add_package, name='add_package'),
    path('vendor_logout/', views.vendor_logout, name='vendor_logout'),

    path('ven_login/', views.ven_login, name='ven_login'),
    path('ven_addpackage/', views.ven_addpackage, name='ven_addpackage'),
    path('ven_user_login/', views.ven_user_login, name='ven_user_login'),
    path('uv_login/', views.uv_login, name='uv_login'),


    path('vendor/create_package/', views.create_package, name='create_package'),
    path('success/',views.success,name='success'),
    path('non_expired_package/', views.non_expired_package, name='non_expired_package'),
    
    path('return_to_vendor_dashboard/',views.return_to_vendor_dashboard,name='return_to_vendor_dashboard'),
    path('vendor/published_package/',views.published_package,name='published_package'),

    path('return_to_user_dashboard/',views.return_to_user_dashboard,name='return_to_user_dashboard'),

    path('delete_package/<int:package_id>/', views.delete_package, name='delete_package'),
    path('edit_package/<int:package_id>/', views.edit_package, name='edit_package'),

    path('package_details/<int:package_id>/',views.package_details,name='package_details'),

    path('confirm_payment/<int:package_id>/', views.confirm_payment, name='confirm_payment'),

    path('user_bookings/', views.user_bookings, name='user_bookings'),


]









