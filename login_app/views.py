from django.shortcuts import render, redirect
from .models import User
from django.contrib import messages
import bcrypt

# Create your views here.
def index(request):
    context = {
        'allUsers': User.objects.all()
    }
    return render(request, "index.html", context)

def register(request):
    password = request.POST['password']
    pw_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    print('hash', User.objects.all())
    User.objects.create(
        first_name = request.POST['first_name'],
        last_name = request.POST['last_name'],
        email = request.POST['email'],
        password = pw_hash,
    )
    errors = User.objects.my_validator(request.POST)
    c = User.objects.last()
    if len(errors) > 0:
        for key, value in errors.items():
            messages.error(request, value)
        c.delete()
        return redirect ('/')
    # request.session['email']
    return redirect('/success')

def login(request):
    user = User.objects.filter(email = request.POST['login_email'])
    if user:
        logged_user = user[0]
        if bcrypt.checkpw(request.POST['login_pw'].encode(), logged_user.password.encode()):
            request.session['userid'] = logged_user.id
            return redirect('/success')
        else:
            # errors = {}
            # errors['incorrect_login'] = "Incorrect email or password"
            messages.error(request, "Incorrect email or password")
        return redirect('/')
    return redirect('/')
    

def success(request):
    context = {
        'user': User.objects.first()
    }
    request.session['email'] = User.objects.first().email
    print(User.objects.first().email)
    return render(request, "success.html", context)

def logout(request):
    pass