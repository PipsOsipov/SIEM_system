from django.urls import path
from . import views

urlpatterns = [
    path('', views.all_logs, name='all_logs'),
]