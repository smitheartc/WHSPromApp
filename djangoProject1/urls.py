"""djangoProject1 URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/4.0/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path, include, re_path, URLPattern
from django.views.decorators.csrf import csrf_exempt
from django.views.generic import TemplateView
from django.contrib.auth.views import LogoutView

from promapp import views

urlpatterns = [
    path('admin/', admin.site.urls),
    path('do_thing/', views.run_del),
    path('adminonly/', views.admin_only),
    path('images/<str:image>', views.images),
    path('createticket/', views.get_ticket_view),
    path('navbar/', views.navbar),
    path('footer/', views.footer),
    path('styles/<str:style>', views.styles),
    path('scripts/<str:script>', views.scripts),
    path('', views.index), #TemplateView.as_view(template_name="login.html")),
    path('logout', views.logout),
    path('login/', csrf_exempt(views.login)),
    path('login/<str:callback>/', csrf_exempt(views.login)),
    path('oauth2callback/', views.oauth2callback),
    path('wisdonly/', views.wisd_only),
    path('database/', views.database_lookup),
    path('database/<str:var>/', views.database_lookup),
    path('student/<str:student>/', views.student_view),
    path('ticketexists/', views.ticket_exists),
    path('ticketsuccess/', views.ticket_success),
    path('success/', views.success),
    path('checkin/<str:student_email>/<str:redirect_thing>/', views.checkin),
    path('wylieapp/<str:student_email>/<str:redirect_thing>/', views.wylieapp),
    path('del/<str:student_email>/', views.deleteThing),
    path('recshirt/<str:student_email>/<str:redirect_thing>/', views.recshirt),
    path('date/<str:email>/<str:key>/', views.date_creation),
    path('dateapprove/<str:email>/<str:key>/', views.date_approve),
    path('comebacklater/', views.comebacklater)

]
