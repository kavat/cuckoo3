from django.urls import path, register_converter

from cuckoo.web import converters
from . import views

urlpatterns = [
    path("", views.Logs.as_view(), name="Logs/index"),
    path("get_logs", views.LogsData.as_view())
]
