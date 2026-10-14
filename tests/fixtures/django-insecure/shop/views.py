import pickle
import subprocess

import yaml
from django.db import connection
from django.http import HttpResponse
from django.views.decorators.csrf import csrf_exempt

from .models import User


@csrf_exempt
def webhook(request):
    payload = pickle.loads(request.body)
    return HttpResponse(str(payload))


def search(request):
    name = request.GET["name"]
    with connection.cursor() as cursor:
        cursor.execute(f"SELECT * FROM shop_user WHERE name = '{name}'")
    users = User.objects.raw("SELECT * FROM shop_user WHERE name = '%s'" % name)
    return HttpResponse(len(list(users)))


def run(request):
    result = eval(request.GET["expr"])
    subprocess.run(f"convert {request.GET['file']} out.png", shell=True)
    config = yaml.load(request.body)
    return HttpResponse(f"{result} {config}")
