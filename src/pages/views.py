import logging
from django.contrib.auth.decorators import login_required
from django.shortcuts import render, redirect
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.cache import never_cache
from django.contrib.auth.models import User
from django.db import transaction
from .models import Account

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

fh = logging.FileHandler('transactions.log')
fh.setLevel(logging.INFO)

formatter = logging.Formatter('%(asctime)s - %(message)s')
fh.setFormatter(formatter)
logger.addHandler(fh)


@transaction.atomic
@csrf_exempt
@never_cache
def transferView(request):
	
	if request.method == 'POST':
		to_user = User.objects.get(username=request.POST['to'])
		from_user = User.objects.get(username=request.user)
		amount = int(request.POST['amount'])
		to_acc = Account.objects.get(user=to_user)
		from_acc = Account.objects.get(user=from_user)

		if amount <= 0 or (amount > from_acc.balance) or to_acc == from_acc:
			return redirect('/')
		
		
		from_acc.balance -= amount
		to_acc.balance += amount
		logger.info(f'Sent {amount} from {from_user} to {to_user} from IP: {request.META["REMOTE_ADDR"]}')

		from_acc.save()
		to_acc.save()
	    
	return redirect('/')


@login_required
def homePageView(request):
	accounts = Account.objects.exclude(user_id=request.user.id)
	return render(request, 'pages/index.html', {'accounts': accounts})


# User login spam fix, rate limited to 3 per hour
# Note, this does not ratelimit other pages like admin login
from django_ratelimit.decorators import ratelimit
from django.contrib.auth import authenticate, login
from django.contrib.auth.forms import AuthenticationForm
from django.utils import timezone


@never_cache # dont cache login page for next users
@transaction.atomic
@ratelimit(key='ip', rate='3/h', method='POST', block=True) # ratelimit logins
def loginView(request):
	print("entering login view")
	if request.method == 'POST':
		username = request.POST.get('username')
		password = request.POST.get('password')
		user = authenticate(request, username=username, password=password)
	
		if user is not None and user.is_active:
			user.last_login = timezone.now()
			user.save()

			login(request, user)
			return redirect('/')
	return render(request, 'pages/login.html', {'form': AuthenticationForm()})
