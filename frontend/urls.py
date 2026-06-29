from django.urls import path
from frontend import views

urlpatterns = [
    path("", views.index, name="index"),
    path("resolver/", views.resolver_dashboard, name="resolver-dashboard"),
    path("resolver.html", views.resolver_dashboard, name="resolver-dashboard-html"),
    path("search/", views.search, name="search"),
    path("search.html", views.search, name="search-html"),
]
