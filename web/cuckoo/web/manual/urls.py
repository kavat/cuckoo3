from django.urls import path, register_converter

from cuckoo.web import converters
from . import views

urlpatterns = [
    path("", views.Manual.as_view(), name="Manual/index"),
]
