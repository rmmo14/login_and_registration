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
    if request.method == "GET":
        return redirect('/')
    errors = User.objects.my_validator(request.POST)
    c = User.objects.last()
    if len(errors) > 0:
        for key, value in errors.items():
            messages.error(request, value)
        c.delete()
        return redirect ('/')
    else:
        password = request.POST['password']
        pw_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
        print('hash', User.objects.all())
        new_user = User.objects.create(
            first_name = request.POST['first_name'],
            last_name = request.POST['last_name'],
            email = request.POST['email'],
            password = pw_hash,
        )
        request.session['user_id'] = new_user.id
        return redirect('/success')

def login(request):
    if request.method == "GET":
        return redirect('/')
    user = User.objects.filter(email = request.POST['email'])
    print('email', user[0].email)
    if user:
        logged_user = user[0]
        if bcrypt.checkpw(request.POST['login_pw'].encode(), logged_user.password.encode()):
            request.session['user_id'] = logged_user.id
            return redirect('/success')
        else:
            messages.error(request, "Incorrect email or password")
        return redirect('/')    

def success(request):
    if 'user_id' not in request.session:
        print("not in session")
        return redirect('/')
    user = User.objects.get(id = request.session['user_id'])
    context = {
        'user': user
    }
    request.session['email'] = user.email
    print(user.email)
    return render(request, "success.html", context)

def logout(request):
    request.session.clear()
    return redirect('/')