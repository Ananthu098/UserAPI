from django.urls import path
from .views import RegisterView, LoginView,EmailCheckView,ResetView


urlpatterns=[
    path('register',RegisterView.as_view()),
    path('login',LoginView.as_view()),
    path('pswdemail',EmailCheckView.as_view()),
    path('resetpwd',ResetView.as_view()),


]