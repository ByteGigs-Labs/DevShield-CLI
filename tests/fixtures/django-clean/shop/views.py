from django.db import connection
from django.http import HttpResponse


def search(request):
    with connection.cursor() as cursor:
        cursor.execute("SELECT * FROM shop_user WHERE name = %s", [request.GET["name"]])
    return HttpResponse("ok")
