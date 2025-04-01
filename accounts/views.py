from django.contrib.auth import authenticate, login as auth_login, logout as auth_logout
from django.shortcuts import render, redirect
from django.contrib import messages
from .models import Vendor,Create_Tour_Package,Manage_Bills
from .forms import (UserRegForm, VendorRegistrationForm,VendorLoginForm,CreatedPackageForm)
from django.utils import timezone
from django.shortcuts import render, get_object_or_404, redirect
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.decorators import login_required

# Home Page
def home(request):
    return render(request, 'homepage.html')

# User registration
def user_reg(request):
    if request.method == 'POST':
        form = UserRegForm(request.POST)
        if form.is_valid():
            form.save()
            messages.success(request, "Registration Successful! Please login.")
            return redirect('login')
        else:
            messages.error(request, "Registration failed. Check the form.")
    else:
        form = UserRegForm()
    return render(request, 'user_reg.html', {'uform': form})

# User login
def login_view(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        user = authenticate(request, username=username, password=password)

        if user is not None:
            if user.is_superuser:
                messages.error(request, "Admin cannot log in from user login page.")
                return redirect('login')  # Redirect back to login page
            else:
                auth_login(request, user)
                messages.success(request, "Login Successful!")
                return redirect('travel_plan')
        else:
            messages.error(request, "Invalid Username or Password!")
            return redirect('login')  # Redirect back to login

    return render(request, 'login.html')


# User dashboard
@csrf_exempt
def travel_plan(request):
    if request.user.is_authenticated:

        return redirect('non_expired_package')
    else:
        messages.error(request, "Please login to access Travel Plan.")
        return redirect('login')

# User logout
def logout_view(request):
    auth_logout(request)
    messages.success(request, "Logged out successfully.")
    return redirect('home')


# Vendor Registration
def vendor_register(request):
    if request.method == 'POST':
        form = VendorRegistrationForm(request.POST)
        if form.is_valid():
            vendor = form.save(commit=False)
            vendor.set_password(form.cleaned_data['password'])  # Hash password
            vendor.save()
            messages.success(request, "Vendor registered successfully! Please log in.")
            return redirect('vendor_login')
    else:
        form = VendorRegistrationForm()
    return render(request, 'vendor_reg.html', {'form': form})

# Vendor Login
def vendor_login(request):
    if request.method == 'POST':
        form = VendorLoginForm(request.POST)
        if form.is_valid():
            username = form.cleaned_data['username']
            password = form.cleaned_data['password']
            try:
                vendor = Vendor.objects.get(username=username)
                if vendor.check_password(password):
                    request.session['vendor_id'] = vendor.id
                    return redirect('ven_addpackage')
                else:
                    messages.error(request, "Invalid password")
            except Vendor.DoesNotExist:
                messages.error(request, "Vendor not found")
    else:
        form = VendorLoginForm()
    return render(request, 'vendor_login.html', {'form': form})

# Vendor Logout
def vendor_logout(request):
    request.session.flush()
    messages.success(request, "Logged out successfully!")
    return redirect('home')

# Add Package (Vendor Only)
def add_package(request):
    if not request.session.get('vendor_id'):
        messages.error(request, "Please login first.")
        return redirect('vendor_login')


    return render(request, 'addpackage.html')

# Vendor login page
def ven_login(request):
    return render(request, 'vendor_login.html')

# Vendor Add Package Page
def ven_addpackage(request):
    vendor_id = request.session.get('vendor_id')
    if not vendor_id:
        messages.error(request, "Please login first.")
        return redirect('vendor_login')

    vendor = Vendor.objects.get(id=vendor_id)
    return render(request, 'addpackage.html', {'vendor': vendor})

# Combined User/Vendor login POST handler
def ven_user_login(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')

        # User Authentication
        user = authenticate(request, username=username, password=password)
        if user is not None:
            auth_login(request, user)
            messages.success(request, "User Login Successful!")
            return redirect('travel_plan')

        # Vendor Authentication
        try:
            vendor = Vendor.objects.get(username=username)
            if vendor.check_password(password):
                request.session['vendor_id'] = vendor.id
                messages.success(request, "Vendor Login Successful!")
                return redirect('ven_addpackage')
            else:
                messages.error(request, "Invalid Password for Vendor!")
        except Vendor.DoesNotExist:
            messages.error(request, "Invalid Credentials!")

    return render(request, 'user_vendor_login.html')

# ✅ FIXED: Combined User/Vendor login page render
def uv_login(request):
    return render(request, 'user_vendor_login.html')

# For vendors to create new package and submit it for admin approval
def create_package(request):
    if request.method == 'POST':
        form = CreatedPackageForm(request.POST)
        if form.is_valid():
            package = form.save(commit=False)
            # Assuming you set vendor_id in session after login
            vendor = Vendor.objects.get(id=request.session['vendor_id'])
            package.vendor = vendor
            package.save()
            return redirect('success')
    else:
        form = CreatedPackageForm()
    return render(request, 'vendor/create_package.html', {'form': form})

# page show succesful package creation
def success(request):
    return render(request, 'success.html')  # Simple page saying "Package submitted, pending admin approval"

# Approved package display in userpage and auto expire package
@csrf_exempt
def non_expired_package(request):
    today = timezone.now().date()
    packages = Create_Tour_Package.objects.filter(
        approved=True,
        auto_expire=True,
        start_date__gt=today  # Auto-expiry logic: Show only non-expired packages
    )

    return render(request, 'travel_plan.html',
           context = {
            'first_name': request.user.first_name,
            'last_name': request.user.last_name,
            'packages': packages
                 },)

def return_to_vendor_dashboard(request):
    return render(request, 'addpackage.html')

@csrf_exempt
def return_to_user_dashboard(request):
    return redirect( 'travel_plan')
#
# def published_package(request):
#     return render(request, 'vendor/published_package.html')

#
def published_package(request):
    packages = Create_Tour_Package.objects.all()
    return render(request, 'vendor/published_package.html', {'packages': packages})

#
def delete_package(request, package_id):
    package = get_object_or_404(Create_Tour_Package, id=package_id)

    package.delete()
    return redirect('published_package')

#
def edit_package(request, package_id):
    package = get_object_or_404(Create_Tour_Package, id=package_id)
    if request.method == "POST":
        package.package_title = request.POST.get('package_title')
        package.destination = request.POST.get('destination')
        package.price = request.POST.get('price')
        package.description = request.POST.get('description')
        package.duration = request.POST.get('duration')

        package.save()
        return redirect('published_package')
    return render(request, 'vendor/edit_package.html', {'package': package})
#
def package_details (request,package_id):
    package = get_object_or_404(Create_Tour_Package, id=package_id)
    return render(request, 'user/package_details.html',{'package':package})
#

def confirm_payment(request, package_id):
    package = get_object_or_404(Create_Tour_Package, id=package_id)

    # Increase package booking count
    package.booking_count+= 1
    package.save()

    # Record confirmed booking
    Manage_Bills.objects.create(user=request.user, package=package)

    return render(request, 'user/payment_page.html', {'package': package})




# User Dashboard - Show booked packages
def user_bookings(request):
    bookings = Manage_Bills.objects.filter(user=request.user)
    return render(request, "user/booked_packages.html", {"bookings": bookings})  # ✅ Correct

# # Booked packages page
# def booked_packages(request):
#     return render(request, 'bookings.html')
