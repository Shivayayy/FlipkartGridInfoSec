from django.urls import path
from .views.userSignUp import UserSignUpView
from .views.userLogin import UserLoginView

urlpatterns = [
    path('signup/', UserSignUpView.as_view(), name='user-signup'),
    path('login/', UserLoginView.as_view(), name='user-login'),
]
