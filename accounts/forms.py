
from django.contrib.auth.models import User
from django import forms
from .models import Vendor,Create_Tour_Package




class VendorRegistrationForm(forms.ModelForm):
    password = forms.CharField(widget=forms.PasswordInput)

    class Meta:
        model = Vendor
        fields = [ 'first_name', 'second_name','email', 'phone_no','company', 'address','username','password',]

class VendorLoginForm(forms.Form):
    username = forms.CharField(max_length=150)
    password = forms.CharField(widget=forms.PasswordInput)

class UserRegForm(forms.Form):
    first_name = forms.CharField(max_length=100, label="First Name")
    second_name = forms.CharField(max_length=100, label="Second Name")
    email = forms.EmailField(max_length=100, label="Email")
    user_name = forms.CharField(max_length=100, label="Username")
    password = forms.CharField(widget=forms.PasswordInput(), label="Password")
    confirm_password = forms.CharField(widget=forms.PasswordInput(), label="Confirm Password")

    def clean(self):
        cleaned_data = super().clean()

        first_name = cleaned_data.get('first_name')
        second_name = cleaned_data.get('second_name')
        email = cleaned_data.get('email')
        user_name = cleaned_data.get('user_name')
        password = cleaned_data.get('password')
        confirm_password = cleaned_data.get('confirm_password')

        if user_name and User.objects.filter(username=user_name).exists():
            self.add_error('user_name', "Username is already taken! Choose another username.")

        if email and User.objects.filter(email=email).exists():
            self.add_error('email', "Email is already registered.")

        if password and confirm_password and password != confirm_password:
            self.add_error('confirm_password', "Passwords do not match.")

        if not first_name or first_name.strip() == "":
            self.add_error('first_name', "First name cannot be empty or whitespace.")

        if not second_name or second_name.strip() == "":
            self.add_error('second_name', "Second name cannot be empty or whitespace.")

        return cleaned_data


    def save(self):
        cleaned_data = self.cleaned_data
        user = User.objects.create_user(
            username=cleaned_data['user_name'],
            email=cleaned_data['email'],
            password=cleaned_data['password'],
            first_name=cleaned_data['first_name'],
            last_name=cleaned_data['second_name']
        )
        return user

class CreatedPackageForm(forms.ModelForm):
    class Meta:
        model = Create_Tour_Package
        fields = [
                  'package_title', 'destination', 'place_image',
                  'price', 'description','duration', 'start_date',
                  'end_date', 'top_package', 'budget_friendly',
                  'auto_expire'
                  ]

