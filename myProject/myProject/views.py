from django.shortcuts import render, redirect,HttpResponse
from django.contrib.auth import authenticate, login, logout
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from myApp.models import *
from django.core.mail import send_mail, BadHeaderError
from django.template.loader import render_to_string
from django.db.models.query_utils import Q
from django.utils.http import urlsafe_base64_encode
from django.contrib.auth.tokens import default_token_generator
from django.utils.encoding import force_bytes
from django.contrib.auth.forms import PasswordResetForm
from myProject.forms import *
import uuid
from django.conf import settings
from django.core.mail import send_mail


def signupPage(request):
    if request.method == 'POST':
        username = request.POST['username']
        email = request.POST['email']
        confirm_password = request.POST['confirm-password']
        password = request.POST['password']
        confirm_password = request.POST['confirm-password']
        user_type = request.POST.get('user_type')

        if password == confirm_password:
            if Custom_User.objects.filter(username=username).exists():
                messages.error(request, 'Username already taken.')
                return redirect('signupPage')
            elif Custom_User.objects.filter(email=email).exists():
                messages.error(request, 'Email already registered.')
                return redirect('signupPage')
            else:
                user = Custom_User.objects.create_user(
                username=username,
                email=email,
                password=password,
                user_type=user_type,
                )
                user.save()
                
                auth_token = str(uuid.uuid4())
                user.auth_token = auth_token
                
                print("Token Generated")
                user.save()  
                send_mail_after_registration(email , auth_token)
                return redirect('send_token')
                
        else:
            messages.error(request, 'Passwords do not match.')
            return redirect('signupPage')

    return render(request, 'signupPage.html')

# Signin View
def signInPage(request):
    if request.method == 'POST':
        email = request.POST['email']
        password = request.POST['password']

        try:
            user = Custom_User.objects.get(email=email)
            user = authenticate(request, username=user.username, password=password)

            if user is not None:
                login(request, user)
                messages.success(request, f'Welcome, {user.username}!')
                return redirect('homePage') 
            else:
                messages.error(request, 'Invalid credentials, please try again.')
                return redirect('signInPage')

        except Custom_User.DoesNotExist:
            messages.error(request, 'No user with this email exists.')
            return redirect('signInPage')

    return render(request, 'signInPage.html')


# Signout View
def logoutPage(request):
    logout(request)
    messages.success(request, 'You have been logged out.')
    return redirect('signInPage')


@login_required
def homePage(request):
    
    return render(request,"homePage.html")


def send_token(request):
    
    return render(request,"send_token.html")

def successPage(request):
    
    return render(request,"successPage.html")

def error_page(request):
    return  render(request , 'error.html')



def verify(request,auth_token):
    
    print("Mail Verified")
    try:
        user_obj = Custom_User.objects.filter(auth_token = auth_token).first()

        if user_obj:
            if user_obj.is_verified:
                messages.success(request, 'Your account is already verified.')
                return redirect('signInPage')
            user_obj.is_verified = True
            user_obj.save()
            messages.success(request, 'Your account has been verified.')
            return redirect('signInPage')
        else:
            return redirect('signInPage')
    except Exception as e:
        print(e)
        return redirect('/')


def send_mail_after_registration(email,token):
    print("Mail Sent")
    subject = 'Your accounts need to be verified'
    message = f'Hi paste the link to verify your account http://127.0.0.1:8000/verify/{token}'
    email_from = settings.EMAIL_HOST_USER
    recipient_list = [email]
    send_mail(subject, message , email_from ,recipient_list )
