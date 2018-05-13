# Hacked from django.contrib.auth.urls

from . import views
from django.urls import path

app_name = 'authfib'

urlpatterns = [
    path('login/', views.login, name='login'),
    path('logout/', views.logout, name='logout'),
    path('profile/', views.profile, name='profile'),
    path('callback/', views.callback, name='callback'),

]
