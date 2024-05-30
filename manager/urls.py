from django.urls import path

from . import views

app_name = 'manager'

urlpatterns = [
    path('', views.IndexPage.as_view(), name='index_page'),
    path('login/', views.LoginPage.as_view(), name='login_page'),
    path('logout/', views.logout_action, name='logout'),
    path('dashboard/', views.DashboardPage.as_view(), name='dashboard_page'),
    path('devices/<int:pk>/', views.DevicePage.as_view(), name='device_page'),
]