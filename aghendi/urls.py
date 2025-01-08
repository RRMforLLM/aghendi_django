from django.urls import path
from . import views

urlpatterns = [
    path("", views.index, name="index"),

    path("login/", views.login, name="login"),
    path("signup/", views.signup, name="signup"),
    path("logout/", views.logout_view, name="logout"),
    
    path("create_agenda/", views.create_agenda, name="create_agenda"),
    path("join_agenda/", views.join_agenda, name="join_agenda"),
    
    path('agenda/<int:agenda_id>/', views.view_agenda, name='view_agenda'),
    path('agenda/<int:agenda_id>/calendar/', views.calendar_view, name='calendar_view'),
    path('agenda/<int:agenda_id>/delete/', views.delete_agenda, name='delete_agenda'),
    path('agenda/<int:agenda_id>/add_editor/', views.add_editor, name='add_editor'),
    path('agenda/<int:agenda_id>/remove_editor/<int:user_id>/', views.remove_editor, name='remove_editor'),
    path('agenda/<int:agenda_id>/remove_member/<int:user_id>/', views.remove_member, name='remove_member'),
    path('agenda/<int:agenda_id>/leave/', views.leave_agenda, name='leave_agenda'),
    
    path('agenda/<int:agenda_id>/create_section/', views.create_section, name='create_section'),
    path('agenda/<int:agenda_id>/section/<int:section_id>/delete/', views.delete_section, name='delete_section'),
    
    path('agenda/<int:agenda_id>/section/<int:section_id>/add_element/', views.add_element, name='add_element'),
    path('agenda/<int:agenda_id>/section/<int:section_id>/element/<int:element_id>/', views.element_detail, name='element_detail'),
    path('agenda/<int:agenda_id>/section/<int:section_id>/element/<int:element_id>/flag/', views.flag_element, name='flag_element'),
    path('agenda/<int:agenda_id>/section/<int:section_id>/element/<int:element_id>/edit/', views.edit_element, name='edit_element'),
    path('agenda/<int:agenda_id>/section/<int:section_id>/element/<int:element_id>/delete/', views.delete_element, name='delete_element'),
    path('agenda/<int:agenda_id>/section/<int:section_id>/element/<int:element_id>/comments/', views.element_comments, name='element_comments'),
    path('agenda/<int:agenda_id>/section/<int:section_id>/element/<int:element_id>/comment/<int:comment_id>/delete/', views.delete_comment, name='delete_comment'),
]

from django.contrib.auth import views as auth_views

urlpatterns += [
    path('password_reset/', views.password_reset_request, name='password_reset_request'),
    path('password_reset/confirm/<uidb64>/<token>/', views.password_reset_confirm, name='password_reset_confirm'),
    path('password_reset/complete/',
        auth_views.PasswordResetCompleteView.as_view(
            template_name='aghendi/password_reset_complete.html'
        ),
        name='password_reset_complete'),
]