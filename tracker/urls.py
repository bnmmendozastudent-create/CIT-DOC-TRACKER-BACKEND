from django.urls import path
from . import views

urlpatterns = [
    path('register/',            views.register,         name='register'),
    path('me/',                  views.me,               name='me'),
    path('users/',               views.user_list,        name='user-list'),
    path('dashboard/',           views.dashboard_stats,  name='dashboard'),
    path('documents/',           views.document_list,    name='document-list'),
    path('documents/<int:pk>/',  views.document_detail,  name='document-detail'),
    path('documents/<int:pk>/qr/', views.generate_qr,   name='generate-qr'),
    path('documents/<int:pk>/attachments/', views.document_attachment_upload, name='document-attachment-upload'),
    path('documents/<int:pk>/attachments/<int:attachment_pk>/download/', views.document_attachment_download, name='document-attachment-download'),
    path('documents/<int:pk>/unlock/', views.document_unlock, name='document-unlock'),
    path('documents/<int:pk>/key/', views.document_key_debug, name='document-key-debug'),
]